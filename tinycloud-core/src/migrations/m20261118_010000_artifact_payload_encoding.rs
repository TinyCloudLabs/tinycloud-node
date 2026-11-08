//! TC-887: how each stored part of a `database_artifact` row is encoded.
//! `NULL` is legacy plaintext, so every existing row reads as before;
//! `1` is TCE1 (`docs/at-rest/INTERFACES.md` §5).

use sea_orm_migration::prelude::*;

use crate::models::database_artifact;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            database_artifact::Column::PayloadEncoding,
            database_artifact::Column::DeltaEncoding,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(database_artifact::Entity)
                        .add_column(ColumnDef::new(column).small_integer().null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
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
