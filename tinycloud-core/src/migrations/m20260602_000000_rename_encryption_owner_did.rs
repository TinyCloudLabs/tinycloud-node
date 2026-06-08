use sea_orm_migration::prelude::*;

use crate::models::encryption_network;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(encryption_network::Entity)
                    .rename_column(
                        Alias::new("principal"),
                        encryption_network::Column::OwnerDid,
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(encryption_network::Entity)
                    .rename_column(
                        encryption_network::Column::OwnerDid,
                        Alias::new("principal"),
                    )
                    .to_owned(),
            )
            .await
    }
}
