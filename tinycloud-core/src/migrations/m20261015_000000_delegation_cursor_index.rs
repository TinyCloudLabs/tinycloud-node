use sea_orm_migration::prelude::*;

use crate::models::delegation;

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn drop_index_if_exists(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    if manager
        .has_index("delegation", "idx_delegation_delegator")
        .await?
    {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .to_owned(),
            )
            .await?;
    }
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
