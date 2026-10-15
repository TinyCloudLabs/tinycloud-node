//! Byte-ordered key range seek for quiet-prefix kv/sync polls on PostgreSQL.
//! SQLite's `(space, key)` primary key already has byte ordering.

use sea_orm_migration::prelude::*;
#[cfg(feature = "postgres")]
use sea_orm_migration::SchemaManagerConnection;

pub(crate) const NAME: &str = "m20261015_010000_current_kv_prefix_index";

/// A dedicated connection holds the session advisory lock and has no
/// statement timeout. Try the lock without waiting in a PostgreSQL query:
/// CONCURRENTLY waits for old transactions, including a blocked lock query,
/// so a blocking advisory lock can deadlock two simultaneous node startups.
/// Closing the connection releases the lock and discards session settings.
#[cfg(feature = "postgres")]
async fn postgres_index(manager: &SchemaManager<'_>, create: bool) -> Result<(), DbErr> {
    let SchemaManagerConnection::Connection(db) = manager.get_connection() else {
        return Err(DbErr::Custom(
            "concurrent current_kv index requires a connection outside a transaction".into(),
        ));
    };
    let mut connection = db
        .get_postgres_connection_pool()
        .acquire()
        .await
        .map_err(|error| DbErr::Conn(sea_orm::RuntimeErr::SqlxError(error)))?;
    let result = async {
        sea_orm::sqlx::query("SET statement_timeout = 0")
            .execute(&mut *connection)
            .await?;
        loop {
            let locked: bool = sea_orm::sqlx::query_scalar("SELECT pg_try_advisory_lock(737, 1)")
                .fetch_one(&mut *connection)
                .await?;
            if locked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if create {
            let valid: Option<bool> = sea_orm::sqlx::query_scalar(
                "SELECT indisvalid FROM pg_index \
                 WHERE indexrelid = to_regclass('idx_current_kv_space_key_c')",
            )
            .fetch_optional(&mut *connection)
            .await?;
            // A cancelled concurrent build leaves an invalid index behind;
            // IF NOT EXISTS alone would otherwise skip it forever.
            if valid == Some(false) {
                sea_orm::sqlx::query("DROP INDEX CONCURRENTLY idx_current_kv_space_key_c")
                    .execute(&mut *connection)
                    .await?;
            }
            sea_orm::sqlx::query(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_current_kv_space_key_c \
                 ON current_kv (space, key COLLATE \"C\")",
            )
            .execute(&mut *connection)
            .await?;
        } else {
            sea_orm::sqlx::query("DROP INDEX CONCURRENTLY IF EXISTS idx_current_kv_space_key_c")
                .execute(&mut *connection)
                .await?;
        }
        Ok::<(), sea_orm::sqlx::Error>(())
    }
    .await;
    let close = connection.close().await;
    result.map_err(|error| DbErr::Exec(sea_orm::RuntimeErr::SqlxError(error)))?;
    close.map_err(|error| DbErr::Conn(sea_orm::RuntimeErr::SqlxError(error)))
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        #[cfg(feature = "postgres")]
        if manager.get_database_backend() == sea_orm::DbBackend::Postgres {
            postgres_index(manager, true).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        #[cfg(feature = "postgres")]
        if manager.get_database_backend() == sea_orm::DbBackend::Postgres {
            postgres_index(manager, false).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Statement, TransactionTrait};

    #[tokio::test]
    async fn postgres_index_build_does_not_block_a_second_writer() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_index_build_does_not_block_a_second_writer",
        )
        .await
        else {
            return;
        };
        let db = &schema.conn;
        db.execute_unprepared("DROP INDEX idx_current_kv_space_key_c")
            .await
            .unwrap();
        let first = db.begin().await.unwrap();
        first
            .execute(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) \
                 VALUES ('space-a', 'busy/first', decode(repeat('ab', 34), 'hex'), 10, \
                 decode(repeat('ab', 34), 'hex'), 0, decode(repeat('ab', 34), 'hex'), '{}', false)",
            ))
            .await
            .unwrap();

        let build_db = db.clone();
        let build = tokio::spawn(async move { Migration.up(&SchemaManager::new(&build_db)).await });
        let waiting = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let row = db
                    .query_one(Statement::from_string(
                        sea_orm::DbBackend::Postgres,
                        "SELECT 1 AS active FROM pg_stat_activity \
                         WHERE query LIKE 'CREATE INDEX%idx_current_kv_space_key_c%' \
                         AND state = 'active' AND pid <> pg_backend_pid()",
                    ))
                    .await
                    .unwrap();
                if row.is_some() || build.is_finished() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(waiting.is_ok(), "index build never started");

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            db.execute(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) \
                 VALUES ('space-a', 'busy/second', decode(repeat('ab', 34), 'hex'), 11, \
                 decode(repeat('ab', 34), 'hex'), 0, decode(repeat('ab', 34), 'hex'), '{}', false)",
            )),
        )
        .await;
        first.rollback().await.unwrap();
        build.await.unwrap().unwrap();
        assert!(
            matches!(second, Ok(Ok(_))),
            "index build blocked a writer: {second:?}"
        );
    }

    #[tokio::test]
    async fn postgres_concurrent_index_down_and_up_restore_history() {
        use sea_orm_migration::MigratorTrait;

        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_concurrent_index_down_and_up_restore_history",
        )
        .await
        else {
            return;
        };
        let db = &schema.conn;
        let migrations = crate::migrations::Migrator::migrations();
        let index = migrations
            .iter()
            .position(|migration| migration.name() == NAME)
            .unwrap();
        let steps = (migrations.len() - index) as u32;
        crate::migrations::Migrator::down(db, Some(steps))
            .await
            .unwrap();
        let absent = db
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "SELECT 1 FROM pg_index WHERE indexrelid = to_regclass('idx_current_kv_space_key_c')",
            ))
            .await
            .unwrap();
        assert!(absent.is_none());
        crate::migrations::Migrator::up(db, Some(steps))
            .await
            .unwrap();
        let valid: bool = db
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "SELECT indisvalid AS valid FROM pg_index \
                 WHERE indexrelid = to_regclass('idx_current_kv_space_key_c')",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "valid")
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn postgres_two_nodes_can_finish_the_same_concurrent_index_migration() {
        use sea_orm_migration::MigratorTrait;

        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_two_nodes_can_finish_the_same_concurrent_index_migration",
        )
        .await
        else {
            return;
        };
        let db = &schema.conn;
        crate::migrations::Migrator::down(db, Some(1))
            .await
            .unwrap();
        db.execute(Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) \
             SELECT 'space-a', 'busy/' || lpad(n::text, 6, '0'), \
             decode(repeat('ab', 34), 'hex'), n, decode(repeat('ab', 34), 'hex'), 0, \
             decode(repeat('ab', 34), 'hex'), '{}', false FROM generate_series(1, 100000) n",
        ))
        .await
        .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let run = || {
            let db = db.clone();
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                crate::migrations::Migrator::up(&db, None).await
            }
        };
        let (first, second) = tokio::join!(run(), run());
        assert!(first.is_ok(), "first node migration: {first:?}");
        assert!(second.is_ok(), "second node migration: {second:?}");
    }
    #[tokio::test]
    async fn postgres_retry_replaces_an_invalid_concurrent_index() {
        use sea_orm_migration::MigratorTrait;

        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_retry_replaces_an_invalid_concurrent_index",
        )
        .await
        else {
            return;
        };
        let db = &schema.conn;
        crate::migrations::Migrator::down(db, Some(1))
            .await
            .unwrap();
        db.execute_unprepared(
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) \
             SELECT 'space-a', 'busy/' || n::text, decode(repeat('ab', 34), 'hex'), n, \
             decode(repeat('ab', 34), 'hex'), 0, decode(repeat('ab', 34), 'hex'), '{}', false \
             FROM generate_series(1, 2) n",
        )
        .await
        .unwrap();
        // A failed concurrent uniqueness check leaves an INVALID catalog entry
        // with the same name as the desired index.
        let failed = db
            .execute_unprepared(
                "CREATE UNIQUE INDEX CONCURRENTLY idx_current_kv_space_key_c \
                 ON current_kv (space)",
            )
            .await;
        assert!(failed.is_err(), "duplicate spaces must fail the build");
        let invalid: bool = db
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "SELECT NOT indisvalid AS invalid FROM pg_index \
                 WHERE indexrelid = to_regclass('idx_current_kv_space_key_c')",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "invalid")
            .unwrap();
        assert!(invalid);
        let history = db
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                format!("SELECT 1 FROM seaql_migrations WHERE version = '{NAME}'"),
            ))
            .await
            .unwrap();
        assert!(history.is_none(), "failed build must not be marked applied");

        crate::migrations::Migrator::up(db, Some(1)).await.unwrap();
        let ddl: String = db
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "SELECT pg_get_indexdef(indexrelid) AS ddl FROM pg_index \
                 WHERE indexrelid = to_regclass('idx_current_kv_space_key_c') \
                 AND indisvalid",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "ddl")
            .unwrap();
        assert!(ddl.contains("(space, key COLLATE \"C\")"), "{ddl}");
    }
}
