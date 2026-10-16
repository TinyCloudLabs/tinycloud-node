use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::models::{kv_blob_generation, kv_orphan_attempt, kv_orphan_candidate};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(kv_blob_generation::Entity))
            .await?;
        for table in ["kv_write", "current_kv"] {
            // A fresh install builds the initial table from today's entity,
            // while an upgraded schema still has the pre-generation column set.
            if !manager.has_column(table, "generation").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new(table))
                            .add_column(
                                ColumnDef::new(Alias::new("generation"))
                                    .big_integer()
                                    .not_null()
                                    .default(0),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        }
        manager
            .create_table(schema.create_table_from_entity(kv_orphan_candidate::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(kv_orphan_attempt::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_kv_orphan_candidate_deleting")
                    .table(kv_orphan_candidate::Entity)
                    .col(kv_orphan_candidate::Column::DeletingAt)
                    .col(kv_orphan_candidate::Column::Space)
                    .col(kv_orphan_candidate::Column::Value)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_kv_orphan_attempt_age")
                    .table(kv_orphan_attempt::Entity)
                    .col(kv_orphan_attempt::Column::CreatedAt)
                    .col(kv_orphan_attempt::Column::Space)
                    .col(kv_orphan_attempt::Column::Value)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_kv_orphan_attempt_retry")
                    .table(kv_orphan_attempt::Entity)
                    .col(kv_orphan_attempt::Column::RetryAfter)
                    .col(kv_orphan_attempt::Column::CreatedAt)
                    .col(kv_orphan_attempt::Column::Space)
                    .col(kv_orphan_attempt::Column::Value)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["current_kv", "kv_write"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new("generation"))
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_table(Table::drop().table(kv_orphan_attempt::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(kv_orphan_candidate::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(kv_blob_generation::Entity).to_owned())
            .await
    }
}
