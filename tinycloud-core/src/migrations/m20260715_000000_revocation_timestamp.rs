use sea_orm_migration::prelude::*;

use crate::models::revocation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(revocation::Entity)
                    .add_column(
                        ColumnDef::new(revocation::Column::RevokedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(revocation::Entity)
                    .drop_column(revocation::Column::RevokedAt)
                    .to_owned(),
            )
            .await
    }
}
