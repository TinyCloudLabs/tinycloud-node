//! The durable lag scan (TC-1491 P1): which databases of an allowlisted
//! space have an artifact head the published frontier does not match.
//!
//! Notices are lossy (a crash, a full channel, a node that never saw the
//! save); the scan is what makes the uploader converge anyway. It runs once
//! at startup (that is how bootstrap begins) and then periodically.
//!
//! One keyset-paginated statement per page: `database_artifact` left-joined
//! to `sql_store_manifest` on `(space, name = db_id)`, filtered to rows whose
//! revision or checkpoint differs from the frontier, ordered by name after a
//! cursor. No `IN (...)` list; runs on PostgreSQL and SQLite.

use sea_orm::{
    sea_query::{Alias, Cond, Expr, JoinType, Order, Query},
    ConnectionTrait, DbErr,
};

use super::machine::Head;
use crate::models::{database_artifact as artifact, sql_store_manifest as manifest};
use crate::sql::store::manifest::Frontier;

/// The artifact service the SQL service saves under.
const SERVICE: &str = "sql";

/// One database whose artifact head differs from its frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub db_id: String,
    pub head: Head,
    /// The published frontier, if any.
    pub have: Option<Frontier>,
}

impl Drift {
    /// PG is below the frontier: a lower revision, or the frontier's own
    /// revision with another checkpoint (contract 11.7).
    pub fn regressed(&self) -> bool {
        self.have.as_ref().is_some_and(|f| {
            let last = i64::try_from(f.last_seq).unwrap_or(i64::MAX);
            self.head.revision < last
                || (self.head.revision == last && self.head.cid != f.base_checkpoint_cid)
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("lag scan query failed: {0}")]
    Db(#[from] DbErr),
    #[error("lag scan read an invalid manifest row: {0}")]
    Manifest(#[from] crate::sql::store::SqlStoreError),
}

const M_COLUMNS: [(manifest::Column, &str); 11] = [
    (manifest::Column::Space, "m_space"),
    (manifest::Column::Lineage, "m_lineage"),
    (manifest::Column::Epoch, "m_epoch"),
    (manifest::Column::Revision, "m_revision"),
    (manifest::Column::BaseSnapshotKey, "m_base_snapshot_key"),
    (manifest::Column::BaseSeq, "m_base_seq"),
    (manifest::Column::BaseCheckpointCid, "m_base_checkpoint_cid"),
    (manifest::Column::LastSeq, "m_last_seq"),
    (manifest::Column::PublishId, "m_publish_id"),
    (manifest::Column::PublishedAt, "m_published_at"),
    (manifest::Column::FrontierBytes, "m_frontier_bytes"),
];

/// Up to `limit` drifted databases of `space` whose name sorts after `after`.
/// A page shorter than `limit` does not mean the end: rows in sync are
/// filtered out, so the caller pages until the page is empty.
pub async fn scan_page<C: ConnectionTrait>(
    conn: &C,
    space: &str,
    after: &str,
    limit: u64,
) -> Result<Vec<Drift>, ScanError> {
    let a = |c: artifact::Column| Expr::col((artifact::Entity, c));
    let m = |c: manifest::Column| Expr::col((manifest::Entity, c));
    let mut q = Query::select();
    q.expr_as(a(artifact::Column::Name), Alias::new("name"))
        .expr_as(a(artifact::Column::Revision), Alias::new("revision"))
        .expr_as(
            a(artifact::Column::CheckpointContentHash),
            Alias::new("cid"),
        );
    for (column, alias) in M_COLUMNS {
        q.expr_as(m(column), Alias::new(alias));
    }
    q.from(artifact::Entity)
        .join(
            JoinType::LeftJoin,
            manifest::Entity,
            Cond::all()
                .add(
                    Expr::col((manifest::Entity, manifest::Column::Space))
                        .equals((artifact::Entity, artifact::Column::Space)),
                )
                .add(
                    Expr::col((manifest::Entity, manifest::Column::DbId))
                        .equals((artifact::Entity, artifact::Column::Name)),
                ),
        )
        .and_where(a(artifact::Column::Service).eq(SERVICE))
        .and_where(a(artifact::Column::Space).eq(space))
        .and_where(a(artifact::Column::Name).gt(after))
        .cond_where(
            Cond::any()
                .add(m(manifest::Column::Space).is_null())
                .add(a(artifact::Column::Revision).ne(m(manifest::Column::LastSeq)))
                .add(
                    a(artifact::Column::CheckpointContentHash)
                        .ne(m(manifest::Column::BaseCheckpointCid)),
                ),
        )
        .order_by((artifact::Entity, artifact::Column::Name), Order::Asc)
        .limit(limit);
    let rows = conn
        .query_all(conn.get_database_backend().build(&q))
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let db_id: String = row.try_get("", "name")?;
        let head = Head {
            revision: row.try_get("", "revision")?,
            cid: row.try_get("", "cid")?,
        };
        let have = match row.try_get::<Option<String>>("", "m_space")? {
            None => None,
            Some(m_space) => Some(Frontier::from_model(manifest::Model {
                space: m_space,
                db_id: db_id.clone(),
                lineage: row.try_get("", "m_lineage")?,
                epoch: row.try_get("", "m_epoch")?,
                revision: row.try_get("", "m_revision")?,
                base_snapshot_key: row.try_get("", "m_base_snapshot_key")?,
                base_seq: row.try_get("", "m_base_seq")?,
                base_checkpoint_cid: row.try_get("", "m_base_checkpoint_cid")?,
                last_seq: row.try_get("", "m_last_seq")?,
                publish_id: row.try_get("", "m_publish_id")?,
                published_at: row.try_get("", "m_published_at")?,
                frontier_bytes: row.try_get("", "m_frontier_bytes")?,
            })?),
        };
        out.push(Drift { db_id, head, have });
    }
    Ok(out)
}

/// Every drifted database of `space`, `page` rows per statement.
pub async fn scan_space<C: ConnectionTrait>(
    conn: &C,
    space: &str,
    page: u64,
) -> Result<Vec<Drift>, ScanError> {
    let mut all = Vec::new();
    let mut after = String::new();
    loop {
        let rows = scan_page(conn, space, &after, page.max(1)).await?;
        let Some(last) = rows.last() else {
            return Ok(all);
        };
        after = last.db_id.clone();
        all.extend(rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_artifacts::{ArtifactExpectation, DatabaseArtifactRepository};
    use crate::sql::store::key::{DbRef, Lineage, ObjectKey, PublishId};
    use crate::sql::store::manifest::{
        DbSqlManifest, ObjectRecord, PublishChain, PublishOutcome, SqlManifest,
    };
    use crate::sql::store::object::sha256;
    use crate::sql::store::shadow::source::tests::{repository, saved, SPACE};

    async fn publish_at(m: &DbSqlManifest, db: &str, at: u64, cid: &str) -> Frontier {
        let dbref = DbRef {
            space: SPACE,
            db_id: db,
        };
        let key =
            ObjectKey::snapshot(&dbref, &Lineage::random(), at, &sha256(db.as_bytes())).unwrap();
        let PublishOutcome::Published(f) = m
            .publish_chain(
                &dbref,
                None,
                PublishChain {
                    objects: vec![ObjectRecord {
                        key,
                        format: "sqlite-v1".into(),
                        bytes: 1,
                        created_at: "2026-10-21T00:00:00Z".into(),
                    }],
                    base_checkpoint_cid: cid.into(),
                    publish_id: PublishId::random(),
                    now: "2026-10-21T00:00:00Z".into(),
                },
            )
            .await
            .unwrap()
        else {
            panic!("publish lost");
        };
        f
    }

    #[tokio::test]
    async fn the_scan_returns_only_drifted_databases_of_the_space_in_pages() {
        let (conn, repo) = repository().await;
        let manifest = DbSqlManifest::new(conn.clone());
        // a: no frontier. b: in sync. c: behind. d: regressed. e: same
        // revision, another checkpoint.
        let a = saved(&repo, "a", b"a", &[]).await;
        let b = saved(&repo, "b", b"b", &[b"w"]).await;
        publish_at(&manifest, "b", 2, &b.checkpoint_content_hash).await;
        let c = saved(&repo, "c", b"c", &[b"w", b"ww"]).await;
        let c_have = publish_at(&manifest, "c", 1, &c.checkpoint_content_hash).await;
        let d = saved(&repo, "d", b"d", &[]).await;
        publish_at(&manifest, "d", 5, &d.checkpoint_content_hash).await;
        let e = saved(&repo, "e", b"e", &[]).await;
        publish_at(&manifest, "e", 1, "another-checkpoint").await;
        // Other spaces and services are never scanned.
        repo.save(
            "sql",
            "tinycloud:pkh:eip155:1:0xCd://default",
            "z",
            bytes::Bytes::from_static(b"z"),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        repo.save(
            "duckdb",
            SPACE,
            "y",
            bytes::Bytes::from_static(b"y"),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();

        let drift = scan_space(&conn, SPACE, 1).await.unwrap();
        let names: Vec<_> = drift.iter().map(|d| d.db_id.as_str()).collect();
        assert_eq!(names, ["a", "c", "d", "e"]);
        assert_eq!(
            drift[0],
            Drift {
                db_id: "a".into(),
                head: Head {
                    revision: a.revision,
                    cid: a.checkpoint_content_hash,
                },
                have: None,
            }
        );
        assert_eq!(drift[1].have.as_ref(), Some(&c_have));
        assert_eq!(drift[1].head.revision, 3);
        assert!(!drift[0].regressed() && !drift[1].regressed());
        assert!(drift[2].regressed(), "revision 1 below last_seq 5");
        assert!(drift[3].regressed(), "same revision, another checkpoint");
        // One page with room for everything gives the same answer.
        assert_eq!(scan_space(&conn, SPACE, 100).await.unwrap(), drift);
        let _ = e;
    }
}
