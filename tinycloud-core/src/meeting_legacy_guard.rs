//! Generation-checked per-space preservation barrier for legacy meeting artifacts.
//!
//! The write-first UPSERT takes a PostgreSQL row lock or SQLite writer lock.
//! Callers must hold the transaction through the protected KV mutation's commit.
use crate::models::meeting_legacy_write_guard::{Column, Entity};
use sea_orm::{
    sea_query::{Expr, OnConflict, Query},
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, QueryFilter,
};
use tinycloud_auth::resource::SpaceId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FreezeStatus {
    pub frozen: bool,
    pub generation: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum FreezeError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("legacy_freeze_generation_conflict")]
    GenerationConflict,
    #[error("legacy_freeze_invalid_expected_generation")]
    InvalidExpectedGeneration,
}

pub fn protects(path: &str) -> bool {
    let Some(tail) = path.strip_prefix("xyz.tinycloud.tinychat/connectors/") else {
        return false;
    };
    let Some((source, artifact)) = tail.split_once('/') else {
        return false;
    };
    matches!(
        source,
        "fireflies" | "google-meet" | "tinycloud-transcriber"
    ) && ["transcript/", "meeting/", "archive-copy/transcript/"]
        .iter()
        .any(|prefix| artifact.starts_with(prefix))
}

/// A missing row is writable; a failed database read is never treated as writable.
pub async fn status<C: ConnectionTrait>(conn: &C, space: &SpaceId) -> Result<FreezeStatus, DbErr> {
    Ok(Entity::find_by_id(space.to_string())
        .one(conn)
        .await?
        .map(|row| FreezeStatus {
            frozen: row.frozen,
            generation: row.generation,
        })
        .unwrap_or_default())
}

async fn lock(tx: &DatabaseTransaction, space: &SpaceId) -> Result<FreezeStatus, DbErr> {
    let statement = Query::insert()
        .into_table(Entity)
        .columns([Column::Space, Column::Frozen, Column::Generation])
        .values_panic([space.to_string().into(), false.into(), 0_i64.into()])
        .on_conflict(
            OnConflict::column(Column::Space)
                // Writers must never reset an existing flag or generation.
                .update_column(Column::Space)
                .to_owned(),
        )
        .to_owned();
    tx.execute(tx.get_database_backend().build(&statement))
        .await?;
    Entity::find_by_id(space.to_string())
        .one(tx)
        .await?
        .map(|row| FreezeStatus {
            frozen: row.frozen,
            generation: row.generation,
        })
        .ok_or_else(|| DbErr::Custom("legacy meeting write guard disappeared while locked".into()))
}

pub(crate) async fn lock_writer(tx: &DatabaseTransaction, space: &SpaceId) -> Result<bool, DbErr> {
    Ok(lock(tx, space).await?.frozen)
}

pub(crate) async fn transition(
    tx: &DatabaseTransaction,
    space: &SpaceId,
    frozen: bool,
    expected: i64,
) -> Result<FreezeStatus, FreezeError> {
    let next = expected
        .checked_add(1)
        .filter(|_| expected >= 0)
        .ok_or(FreezeError::InvalidExpectedGeneration)?;
    let current = lock(tx, space).await?;
    // Only the immediately following matching transition is an idempotent retry.
    if current.frozen == frozen && current.generation == next {
        return Ok(current);
    }
    if current.frozen == frozen || current.generation != expected {
        return Err(FreezeError::GenerationConflict);
    }
    let updated = Entity::update_many()
        .col_expr(Column::Frozen, Expr::value(frozen))
        .col_expr(Column::Generation, Expr::value(next))
        .filter(Column::Space.eq(space.to_string()))
        .exec(tx)
        .await?;
    if updated.rows_affected != 1 {
        return Err(
            DbErr::Custom("legacy meeting write guard disappeared while locked".into()).into(),
        );
    }
    Ok(FreezeStatus {
        frozen,
        generation: next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection, TransactionTrait};
    use sea_orm_migration::{MigrationTrait, SchemaManager};
    use std::time::Duration;
    use tinycloud_auth::{resolver::DID_METHODS, ssi::jwk::JWK};

    fn space(name: &str) -> SpaceId {
        SpaceId::new(
            DID_METHODS
                .generate(&JWK::generate_ed25519().unwrap(), "key")
                .unwrap(),
            name.parse().unwrap(),
        )
    }

    #[test]
    fn legacy_freeze_scope_excludes_credentials_cursors_snapshots_and_neighbours() {
        for source in ["fireflies", "google-meet", "tinycloud-transcriber"] {
            let prefix = format!("xyz.tinycloud.tinychat/connectors/{source}");
            for artifact in ["transcript/id", "meeting/id", "archive-copy/transcript/id"] {
                assert!(protects(&format!("{prefix}/{artifact}")));
            }
            for neighbour in [
                "drive-page-token",
                "credentials",
                "snapshot/id/revision",
                "transcript-old/id",
                "archive-copy/other/id",
                "meeting-state",
            ] {
                assert!(!protects(&format!("{prefix}/{neighbour}")), "{neighbour}");
            }
        }
        assert!(!protects(
            "xyz.tinycloud.tinychat/connectors/other/transcript/id"
        ));
        assert!(!protects("xyz.tinycloud.tinychat/chat/thread"));
    }

    async fn migrate(conn: &DatabaseConnection) {
        crate::migrations::m20260915_000000_meeting_legacy_write_guard::Migration
            .up(&SchemaManager::new(conn))
            .await
            .unwrap();
    }

    async fn ordering_and_persistence(first: DatabaseConnection, second: DatabaseConnection) {
        migrate(&first).await;
        let target = space("legacy-freeze-order");
        let other = space("legacy-freeze-other");
        assert!(!status(&first, &target).await.unwrap().frozen);
        let writer = first.begin().await.unwrap();
        assert!(!lock_writer(&writer, &target).await.unwrap());
        // This models work done after the guard, in the same KV transaction.
        writer
            .execute_unprepared("CREATE TABLE guard_ordering_probe(value INTEGER)")
            .await
            .unwrap();
        writer
            .execute_unprepared("INSERT INTO guard_ordering_probe VALUES (1)")
            .await
            .unwrap();
        let freeze_conn = second.clone();
        let freeze_space = target.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut freezing = tokio::spawn(async move {
            let tx = freeze_conn.begin().await.unwrap();
            started_tx.send(()).unwrap();
            transition(&tx, &freeze_space, true, 0).await.unwrap();
            // A completed freeze must observe the preceding writer's commit.
            let probe = tx
                .query_one(sea_orm::Statement::from_string(
                    tx.get_database_backend(),
                    "SELECT value FROM guard_ordering_probe".to_string(),
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(probe.try_get::<i32>("", "value").unwrap(), 1);
            tx.commit().await.unwrap();
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut freezing)
                .await
                .is_err(),
            "freeze acknowledged before earlier write committed"
        );
        writer.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), freezing)
            .await
            .unwrap()
            .unwrap();
        assert!(status(&first, &target).await.unwrap().frozen);
        assert!(!status(&first, &other).await.unwrap().frozen);
        let after = first.begin().await.unwrap();
        assert!(lock_writer(&after, &target).await.unwrap());
        after.commit().await.unwrap();
        assert!(
            status(&second, &target).await.unwrap().frozen,
            "writer UPSERT reset frozen flag"
        );
        let repeat = second.begin().await.unwrap();
        transition(&repeat, &target, true, 0).await.unwrap();
        repeat.commit().await.unwrap();
        assert!(status(&first, &target).await.unwrap().frozen);
        for (frozen, expected, generation) in
            [(false, 1, 2), (false, 1, 2), (true, 2, 3), (true, 2, 3)]
        {
            let tx = first.begin().await.unwrap();
            assert_eq!(
                transition(&tx, &target, frozen, expected).await.unwrap(),
                FreezeStatus { frozen, generation }
            );
            tx.commit().await.unwrap();
        }
        // Neither an old release nor an old freeze can affect a new cycle.
        for (frozen, expected) in [(false, 1), (true, 0), (true, 3), (false, 0), (true, 4)] {
            let tx = second.begin().await.unwrap();
            assert!(matches!(
                transition(&tx, &target, frozen, expected).await,
                Err(FreezeError::GenerationConflict)
            ));
            tx.rollback().await.unwrap();
        }
        for expected in [-1, i64::MAX] {
            let tx = second.begin().await.unwrap();
            assert!(matches!(
                transition(&tx, &target, false, expected).await,
                Err(FreezeError::InvalidExpectedGeneration)
            ));
            tx.rollback().await.unwrap();
        }
        assert_eq!(
            status(&first, &target).await.unwrap(),
            FreezeStatus {
                frozen: true,
                generation: 3
            }
        );
    }

    #[tokio::test]
    async fn legacy_freeze_sqlite_serializes_independent_connections_and_persists() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("guard.sqlite").display()
        );
        let connect = || Database::connect(ConnectOptions::new(url.clone()));
        let first = connect().await.unwrap();
        let second = connect().await.unwrap();
        ordering_and_persistence(first.clone(), second.clone()).await;
        first.close().await.unwrap();
        second.close().await.unwrap();
        let reopened = connect().await.unwrap();
        assert!(Entity::find().one(&reopened).await.unwrap().unwrap().frozen);
    }

    #[tokio::test]
    async fn postgres_legacy_freeze_serializes_independent_connections_and_persists() {
        let Some(url) = crate::test_support::postgres_test_url(
            "postgres_legacy_freeze_serializes_independent_connections_and_persists",
        ) else {
            return;
        };
        let admin = Database::connect(url.clone()).await.unwrap();
        let schema = format!(
            "legacy_freeze_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let connect = || {
            let mut options = ConnectOptions::new(url.clone());
            options.set_schema_search_path(schema.clone());
            Database::connect(options)
        };
        let first = connect().await.unwrap();
        let second = connect().await.unwrap();
        ordering_and_persistence(first.clone(), second.clone()).await;
        first.close().await.unwrap();
        second.close().await.unwrap();
        let reopened = connect().await.unwrap();
        assert!(Entity::find().one(&reopened).await.unwrap().unwrap().frozen);
        reopened.close().await.unwrap();
        admin
            .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn legacy_freeze_database_failures_are_not_writable_status() {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        let target = space("legacy-freeze-failed-db");
        assert!(status(&conn, &target).await.is_err());
        let tx = conn.begin().await.unwrap();
        assert!(lock_writer(&tx, &target).await.is_err());
        tx.rollback().await.unwrap();
        let tx = conn.begin().await.unwrap();
        assert!(transition(&tx, &target, true, 0).await.is_err());
    }
}
