//! Catch-up sweep: find allowlisted databases the shadow uploader is
//! behind on, so it can bootstrap or re-publish them.
//!
//! The sweep is a paged metadata query over `database_artifact LEFT JOIN
//! sql_store_manifest`, filtered to a provided set of allowlisted spaces.
//! It reports three kinds of lag per hit: no frontier (the database has
//! never been published, so bootstrap), the cid moved (a new snapshot is
//! due), or the revision moved past `last_seq` (a segment is due).
//!
//! The sweep touches only metadata columns. `database_artifact.payload`
//! is never read here; the bootstrap module reads payload later, one
//! database at a time, when the uploader actually needs the bytes.
//!
//! The sweep is designed to run hourly and once at boot. Pagination is
//! driven by a single `(space, name)` keyset cursor so the sweep is O(1)
//! memory in the database count. The caller supplies the page size and
//! paces the calls.
//!
//! The LEFT JOIN relies on `sql_store_manifest` having at most one row
//! per `(space, db_id)`: the primary key is exactly that pair, so no row
//! is multiplied and no stale lineage row can mask lag.
//!
//! TC-1491.

use std::collections::BTreeSet;

use sea_orm::{ConnectionTrait, FromQueryResult, Statement};

/// Why the uploader needs to look at this database again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lag {
    /// No `sql_store_manifest` row exists yet: the database has never
    /// been published. The uploader bootstraps it.
    NoFrontier,
    /// The manifest's `base_checkpoint_cid` no longer equals the
    /// artifact's `checkpoint_content_hash`: Postgres checkpointed. The
    /// uploader publishes a new snapshot.
    CidMoved,
    /// Same cid, but the manifest's `last_seq` is behind the artifact's
    /// revision: the uploader publishes a segment.
    RevisionBehind,
}

/// One database the sweep reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub space: String,
    pub db_id: String,
    pub lag: Lag,
}

/// A page of hits plus the keyset cursor the sweep moved past when it
/// produced them. `(space, db_id)` in lexicographic order so the sweep is
/// driven by one unique composite key with a stable tiebreaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub hits: Vec<Hit>,
    /// `None` when the sweep has walked past the last database. Otherwise
    /// the last key the sweep touched; the next call passes it as
    /// `after_cursor`.
    pub next_cursor: Option<(String, String)>,
}

#[derive(Debug, FromQueryResult)]
struct Row {
    space: String,
    name: String,
    revision: i64,
    checkpoint_content_hash: String,
    frontier_last_seq: Option<i64>,
    frontier_cid: Option<String>,
}

/// Run one page of the sweep, starting after `after_cursor`. Returns at
/// most `page_size` hits. An empty allowlist returns the empty page with
/// no cursor; the caller does not run a query.
///
/// The query is hand-built so it stays portable across SQLite, PostgreSQL
/// and MySQL without sea-orm's `IN` binder (which some backends surface
/// differently) and without a tuple keyset predicate (which MySQL cannot
/// index). The predicate is a two-part `(space > ?) OR (space = ? AND
/// name > ?)` so the backend can walk the `database_artifact` primary
/// key in order.
pub async fn sweep_page<C: ConnectionTrait>(
    conn: &C,
    spaces: &BTreeSet<String>,
    after_cursor: Option<&(String, String)>,
    page_size: u64,
) -> Result<Page, sea_orm::DbErr> {
    if spaces.is_empty() {
        return Ok(Page {
            hits: Vec::new(),
            next_cursor: None,
        });
    }

    let backend = conn.get_database_backend();
    let placeholders: Vec<String> = (0..spaces.len())
        .map(|i| placeholder(backend, i + 1))
        .collect();
    let in_clause = placeholders.join(", ");

    // Values the statement binds. Order mirrors the appearance in `sql`.
    let mut values: Vec<sea_orm::Value> = Vec::new();
    for s in spaces.iter() {
        values.push(sea_orm::Value::from(s.clone()));
    }

    let mut after_predicate = String::new();
    if let Some((space, name)) = after_cursor {
        let p_space_gt = placeholder(backend, values.len() + 1);
        values.push(sea_orm::Value::from(space.clone()));
        let p_space_eq = placeholder(backend, values.len() + 1);
        values.push(sea_orm::Value::from(space.clone()));
        let p_name_gt = placeholder(backend, values.len() + 1);
        values.push(sea_orm::Value::from(name.clone()));
        after_predicate = format!(
            " AND (a.space > {p_space_gt} OR (a.space = {p_space_eq} AND a.name > {p_name_gt}))"
        );
    }

    let sql = format!(
        "SELECT a.space AS space, a.name AS name, a.revision AS revision, \
                a.checkpoint_content_hash AS checkpoint_content_hash, \
                m.last_seq AS frontier_last_seq, \
                m.base_checkpoint_cid AS frontier_cid \
         FROM database_artifact a \
         LEFT JOIN sql_store_manifest m \
           ON m.space = a.space AND m.db_id = a.name \
         WHERE a.service = 'sql' AND a.space IN ({in_clause}){after_predicate} \
         ORDER BY a.space ASC, a.name ASC \
         LIMIT {page_size}"
    );
    let stmt = Statement::from_sql_and_values(backend, &sql, values);
    let rows = Row::find_by_statement(stmt).all(conn).await?;

    let mut hits = Vec::with_capacity(rows.len());
    let mut last_cursor = None;
    let count = rows.len() as u64;
    for row in rows {
        last_cursor = Some((row.space.clone(), row.name.clone()));
        let lag = match (row.frontier_last_seq, row.frontier_cid) {
            (None, _) | (_, None) => Lag::NoFrontier,
            (Some(_), Some(cid)) if cid != row.checkpoint_content_hash => Lag::CidMoved,
            (Some(last_seq), Some(_)) if last_seq < row.revision => Lag::RevisionBehind,
            _ => continue,
        };
        hits.push(Hit {
            space: row.space,
            db_id: row.name,
            lag,
        });
    }

    let next_cursor = if count < page_size { None } else { last_cursor };
    Ok(Page { hits, next_cursor })
}

/// Backend-specific placeholder: `$n` for PostgreSQL, `?` for SQLite and
/// MySQL. `n` is 1-indexed.
fn placeholder(backend: sea_orm::DbBackend, n: usize) -> String {
    match backend {
        sea_orm::DbBackend::Postgres => format!("${n}"),
        sea_orm::DbBackend::MySql | sea_orm::DbBackend::Sqlite => "?".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_artifacts::{
        ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    };
    use crate::migrations::Migrator;
    use crate::sea_orm::{ConnectOptions, Database};
    use crate::sea_orm_migration::MigratorTrait;
    use crate::sql::store::manifest::{DbSqlManifest, Publish, PublishKind, SqlManifest};
    use crate::sql::store::{DbRef, Lineage, ObjectKey, PublishId};
    use bytes::Bytes;
    use std::sync::Arc;

    async fn harness() -> (
        Arc<SeaOrmDatabaseArtifactRepository>,
        DbSqlManifest,
        sea_orm::DatabaseConnection,
    ) {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone()));
        let manifest = DbSqlManifest::new(db.clone());
        (repo, manifest, db)
    }

    #[tokio::test]
    async fn sweep_reports_no_hits_when_allowlist_is_empty() {
        let (_, _, db) = harness().await;
        let page = sweep_page(&db, &BTreeSet::new(), None, 100).await.unwrap();
        assert!(page.hits.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn sweep_reports_no_frontier_for_an_artifact_without_a_manifest_row() {
        let (repo, _manifest, db) = harness().await;
        repo.save(
            "sql",
            "space-a",
            "main",
            Bytes::from_static(&[1u8; 16]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let mut spaces = BTreeSet::new();
        spaces.insert("space-a".into());
        let page = sweep_page(&db, &spaces, None, 100).await.unwrap();
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].lag, Lag::NoFrontier);
        assert_eq!(page.hits[0].space, "space-a");
        assert_eq!(page.hits[0].db_id, "main");
    }

    #[tokio::test]
    async fn sweep_skips_spaces_outside_the_allowlist() {
        let (repo, _, db) = harness().await;
        repo.save(
            "sql",
            "space-a",
            "main",
            Bytes::from_static(&[1u8; 16]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        repo.save(
            "sql",
            "space-b",
            "main",
            Bytes::from_static(&[2u8; 16]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let mut spaces = BTreeSet::new();
        spaces.insert("space-a".into());
        let page = sweep_page(&db, &spaces, None, 100).await.unwrap();
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].space, "space-a");
    }

    #[tokio::test]
    async fn sweep_reports_revision_behind_when_frontier_last_seq_lags() {
        let (repo, manifest, db) = harness().await;
        let saved = repo
            .save(
                "sql",
                "space-a",
                "main",
                Bytes::from_static(&[1u8; 16]),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let key = ObjectKey::snapshot(
            &DbRef {
                space: "space-a",
                db_id: "main",
            },
            &Lineage::random(),
            0,
            &crate::sql::store::object::sha256(b"x"),
        )
        .unwrap();
        manifest
            .record_object(
                &DbRef {
                    space: "space-a",
                    db_id: "main",
                },
                &crate::sql::store::manifest::ObjectRecord {
                    key: key.clone(),
                    format: "sqlite-v1".into(),
                    bytes: 16,
                    created_at: "2026-11-22T00:00:00.000000Z".into(),
                },
            )
            .await
            .unwrap();
        manifest
            .publish_cas(
                &DbRef {
                    space: "space-a",
                    db_id: "main",
                },
                None,
                Publish {
                    kind: PublishKind::Snapshot,
                    object: key,
                    base_checkpoint_cid: saved.checkpoint_content_hash.clone(),
                    frontier_bytes: 16,
                    publish_id: PublishId::random(),
                    now: "2026-11-22T00:00:00.000000Z".into(),
                },
            )
            .await
            .unwrap();
        let _ = repo
            .save_delta(
                "sql",
                "space-a",
                "main",
                Bytes::from_static(&[2u8; 4]),
                ArtifactExpectation::Derived {
                    revision: saved.revision,
                    checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
                },
            )
            .await
            .unwrap();

        let mut spaces = BTreeSet::new();
        spaces.insert("space-a".into());
        let page = sweep_page(&db, &spaces, None, 100).await.unwrap();
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].lag, Lag::RevisionBehind);
    }

    #[tokio::test]
    async fn sweep_paginates_by_cursor_and_terminates() {
        let (repo, _, db) = harness().await;
        for name in ["a", "b", "c"] {
            repo.save(
                "sql",
                "space-a",
                name,
                Bytes::from_static(&[1u8; 16]),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        }
        let mut spaces = BTreeSet::new();
        spaces.insert("space-a".into());

        let page1 = sweep_page(&db, &spaces, None, 2).await.unwrap();
        assert_eq!(page1.hits.len(), 2);
        let cursor = page1.next_cursor.unwrap();
        let page2 = sweep_page(&db, &spaces, Some(&cursor), 2).await.unwrap();
        assert_eq!(page2.hits.len(), 1);
        assert!(page2.next_cursor.is_none(), "terminates on short page");
    }
}
