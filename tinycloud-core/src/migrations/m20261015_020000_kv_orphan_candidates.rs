use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::models::kv_orphan_candidate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(kv_orphan_candidate::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_kv_orphan_candidate_age")
                    .table(kv_orphan_candidate::Entity)
                    .col(kv_orphan_candidate::Column::CreatedAt)
                    .col(kv_orphan_candidate::Column::Space)
                    .col(kv_orphan_candidate::Column::Value)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(kv_orphan_candidate::Entity).to_owned())
            .await
    }
}
