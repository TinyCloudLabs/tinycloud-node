use sea_orm_migration::prelude::*;

use crate::models::database_identity_fence;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(database_identity_fence::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(database_identity_fence::Column::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(database_identity_fence::Column::Enabled)
                            .boolean()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(database_identity_fence::Entity)
                    .to_owned(),
            )
            .await
    }
}
