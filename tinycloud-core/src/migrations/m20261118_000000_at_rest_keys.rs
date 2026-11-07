//! TC-887 S1: tables for the at-rest key hierarchy and its escrow. Empty
//! until a node is configured to provision at-rest keys.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, EntityTrait, PaginatorTrait};

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
        // At most one active bundle per generation. MySQL has no partial
        // indexes (sea-query would emit a plain unique index, which would
        // forbid keeping old bundles); there, the row lock taken by
        // `AtRestStore::activate_escrow` alone serializes activations.
        if manager.get_database_backend() != DatabaseBackend::MySql {
            manager
                .create_index(
                    Index::create()
                        .name("at_rest_escrow_one_active")
                        .table(at_rest_escrow::Entity)
                        .col(at_rest_escrow::Column::Generation)
                        .unique()
                        .if_not_exists()
                        .and_where(Expr::col(at_rest_escrow::Column::Active).eq(true))
                        .to_owned(),
                )
                .await?;
        }
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

    /// Refuses while any key row exists: dropping them would leave sealed
    /// data depending on the mirror alone, or on nothing.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let rows = at_rest_key::Entity::find().count(db).await?
            + at_rest_escrow::Entity::find().count(db).await?
            + space_data_key::Entity::find().count(db).await?;
        if rows > 0 {
            return Err(DbErr::Migration(
                "refusing to drop the at-rest key tables: they hold keys that exist nowhere else"
                    .into(),
            ));
        }
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
