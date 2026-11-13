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
