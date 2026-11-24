use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        let conn = manager.get_connection();
        let previous: String = conn
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SHOW lock_timeout".to_string(),
            ))
            .await?
            .ok_or_else(|| DbErr::Migration("missing lock timeout".into()))?
            .try_get("", "lock_timeout")?;
        conn.execute_unprepared("SET LOCAL lock_timeout = '500ms'")
            .await?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("../database_artifacts/part_lifecycle.sql"))
            .await?;
        conn.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT set_config('lock_timeout', $1, true)",
            [previous.into()],
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        Err(DbErr::Migration(
            "artifact part lifecycle is forward-only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::migrations::Migrator;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use sea_orm_migration::MigratorTrait;

    async fn one(db: &sea_orm::DatabaseConnection, sql: &str) -> i64 {
        db.query_one(Statement::from_string(DbBackend::Postgres, sql))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap()
    }

    /// TC-3755 rollback: deleting a migration's `seaql_migrations` row leaves
    /// its schema in place, so going forward again runs `up` on a schema it
    /// already changed. The two forward-only artifact migrations must tolerate
    /// that (and leave the final function bodies in place).
    #[tokio::test]
    async fn postgres_artifact_wal_and_lifecycle_up_again_after_deregister() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_artifact_wal_and_lifecycle_up_again_after_deregister",
        )
        .await
        else {
            return;
        };
        let db = &fixture.conn;
        let deregister = "DELETE FROM seaql_migrations WHERE version IN \
            ('m20261113_020000_artifact_chunk_wal', 'm20261113_030000_artifact_part_lifecycle')";
        let registered = "SELECT COUNT(*) AS n FROM seaql_migrations WHERE version IN \
            ('m20261113_020000_artifact_chunk_wal', 'm20261113_030000_artifact_part_lifecycle')";
        assert_eq!(one(db, registered).await, 2);
        db.execute(Statement::from_string(DbBackend::Postgres, deregister))
            .await
            .unwrap();
        assert_eq!(one(db, registered).await, 0);

        Migrator::up(db, None).await.unwrap();

        assert_eq!(one(db, registered).await, 2);
        // One of each object, and the lifecycle version of the reserve function (the
        // WAL migration's body, which has no lock timeout, must not be the survivor).
        assert_eq!(
            one(db, "SELECT COUNT(*) AS n FROM pg_constraint WHERE conname = 'artifact_part_replaced_delta_fk' \
                 AND conrelid = 'artifact_part'::regclass")
                .await,
            1
        );
        assert_eq!(
            one(db, "SELECT COUNT(*) AS n FROM pg_indexes WHERE indexname = 'artifact_part_reap_database' \
                 AND schemaname = current_schema()")
                .await,
            1
        );
        assert_eq!(
            one(
                db,
                "SELECT COUNT(*) AS n FROM pg_proc WHERE proname = 'artifact_reserve_part' \
                 AND pronamespace = current_schema()::regnamespace AND 'lock_timeout=50ms' = ANY(proconfig)"
            )
            .await,
            1
        );
    }
}
