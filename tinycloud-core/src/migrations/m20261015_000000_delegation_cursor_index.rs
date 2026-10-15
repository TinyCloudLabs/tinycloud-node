use sea_orm_migration::prelude::*;

use crate::models::delegation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .to_owned(),
            )
            .await?;
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
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .to_owned(),
            )
            .await?;
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
