//! TC-887 S1: tables for the at-rest key hierarchy and its escrow. Empty
//! until a node is configured to provision at-rest keys.

use sea_orm_migration::prelude::*;

use crate::models::{at_rest_escrow, at_rest_key, space_data_key};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(at_rest_key::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(at_rest_key::Column::Generation)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(at_rest_key::Column::ArkId).blob().not_null())
                    .col(
                        ColumnDef::new(at_rest_key::Column::WLabel)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(at_rest_key::Column::Sealed)
                            .blob()
                            .not_null(),
                    )
                    .col(ColumnDef::new(at_rest_key::Column::Chain).blob())
                    .col(
                        ColumnDef::new(at_rest_key::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(at_rest_escrow::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(at_rest_escrow::Column::Efp)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(at_rest_escrow::Column::Generation)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(at_rest_escrow::Column::Bundle)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(at_rest_escrow::Column::Active)
                            .boolean()
                            .not_null(),
                    )
                    .col(ColumnDef::new(at_rest_escrow::Column::Record).text())
                    .col(
                        ColumnDef::new(at_rest_escrow::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(space_data_key::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(space_data_key::Column::Space)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(space_data_key::Column::DekId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(space_data_key::Column::Generation)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(space_data_key::Column::Wrapped)
                            .blob()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(space_data_key::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(space_data_key::Column::Space)
                            .col(space_data_key::Column::DekId),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(space_data_key::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(at_rest_escrow::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(at_rest_key::Entity).to_owned())
            .await
    }
}
