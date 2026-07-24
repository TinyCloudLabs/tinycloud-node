use sea_orm_migration::prelude::*;

use crate::models::invocation_replay;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(invocation_replay::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(invocation_replay::Column::ContentHash)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(invocation_replay::Column::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_invocation_replay_expires_at")
                    .table(invocation_replay::Entity)
                    .col(invocation_replay::Column::ExpiresAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(invocation_replay::Entity).to_owned())
            .await
    }
}
