use sea_orm_migration::prelude::*;

use crate::models::{database_alias, database_legacy_artifact};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(database_legacy_artifact::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(database_legacy_artifact::Column::Service)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_legacy_artifact::Column::Space)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_legacy_artifact::Column::PhysicalName)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(database_legacy_artifact::Column::Service)
                            .col(database_legacy_artifact::Column::Space)
                            .col(database_legacy_artifact::Column::PhysicalName),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(database_alias::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(database_alias::Column::Service)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_alias::Column::Space)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(database_alias::Column::LogicalName)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(database_alias::Column::Path).string())
                    .col(
                        ColumnDef::new(database_alias::Column::PhysicalName)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(database_alias::Column::Service)
                            .col(database_alias::Column::Space)
                            .col(database_alias::Column::LogicalName),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .name("database_alias_physical_unique")
                            .col(database_alias::Column::Service)
                            .col(database_alias::Column::Space)
                            .col(database_alias::Column::PhysicalName),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(database_alias::Entity).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(database_legacy_artifact::Entity)
                    .to_owned(),
            )
            .await
    }
}
