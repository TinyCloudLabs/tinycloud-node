use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

use crate::models::delegation;

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn drop_index_if_exists(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let backend = manager.get_database_backend();
    let sql = match backend {
        DbBackend::MySql => "DROP INDEX IF EXISTS idx_delegation_delegator ON delegation",
        DbBackend::Postgres | DbBackend::Sqlite => "DROP INDEX IF EXISTS idx_delegation_delegator",
    };
    manager
        .get_connection()
        .execute(Statement::from_string(backend, sql.to_string()))
        .await?;
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_index_if_exists(manager).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .col(delegation::Column::Delegator)
                    .col(delegation::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_index_if_exists(manager).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .col(delegation::Column::Delegator)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
