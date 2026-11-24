use crate::models::resource_retirement_snapshot;
use sea_orm::Schema;
use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Schema::new(manager.get_database_backend())
                    .create_table_from_entity(resource_retirement_snapshot::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("resource_retirement_snapshot_network_idx")
                    .table(resource_retirement_snapshot::Entity)
                    .col(resource_retirement_snapshot::Column::HmacKeyId)
                    .col(resource_retirement_snapshot::Column::NetworkHmac)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Custom(
            "retirement provenance cannot be rolled back".into(),
        ))
    }
}
