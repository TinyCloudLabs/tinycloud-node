//! TC-887: how each stored part of a `database_artifact` row is encoded, and
//! the row's manifest tag. Encoding `NULL` is legacy plaintext, so every
//! existing row reads as before; `1` is TCE1 (`docs/at-rest/INTERFACES.md`
//! §5). `manifest` is `NULL` on every existing row and on rows mode `off`
//! writes (§8).

use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;

use crate::models::database_artifact;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            ColumnDef::new(database_artifact::Column::PayloadEncoding)
                .small_integer()
                .null()
                .to_owned(),
            ColumnDef::new(database_artifact::Column::DeltaEncoding)
                .small_integer()
                .null()
                .to_owned(),
            ColumnDef::new(database_artifact::Column::Manifest)
                .blob()
                .null()
                .to_owned(),
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(database_artifact::Entity)
                        .add_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Match the runbook rollback preflight before dropping any metadata.
        let protected_data = manager
            .get_connection()
            .query_one(Statement::from_string(
                manager.get_database_backend(),
                r#"SELECT 1
WHERE EXISTS (SELECT 1 FROM at_rest_key)
   OR EXISTS (SELECT 1 FROM at_rest_escrow)
   OR EXISTS (SELECT 1 FROM space_data_key)
   OR EXISTS (
       SELECT 1 FROM database_artifact
       WHERE payload_encoding IS NOT NULL
          OR delta_encoding IS NOT NULL
          OR manifest IS NOT NULL
   )"#,
            ))
            .await?
            .is_some();
        if protected_data {
            return Err(DbErr::Migration(
                "refusing to drop artifact encoding metadata while at-rest keys or non-plaintext artifact metadata exist"
                    .into(),
            ));
        }

        for column in [
            database_artifact::Column::Manifest,
            database_artifact::Column::DeltaEncoding,
            database_artifact::Column::PayloadEncoding,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(database_artifact::Entity)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
