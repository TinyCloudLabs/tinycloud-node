use sea_orm_migration::prelude::*;

use crate::models::database_artifact;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(database_artifact::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(database_artifact::Column::Service)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::Space)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::Name)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::Revision)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::ContentHash)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::Payload)
                            .blob()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::SizeBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::Backend)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::StorageMode)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_artifact::Column::UpdatedAt)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(database_artifact::Column::Service)
                            .col(database_artifact::Column::Space)
                            .col(database_artifact::Column::Name),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(database_artifact::Entity).to_owned())
            .await
    }
}
