use sea_orm_migration::prelude::*;

use crate::models::database_artifact;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            ColumnDef::new(database_artifact::Column::CheckpointSizeBytes)
                .big_integer()
                .not_null()
                .default(0)
                .to_owned(),
            ColumnDef::new(database_artifact::Column::CheckpointContentHash)
                .string()
                .not_null()
                .default("")
                .to_owned(),
            ColumnDef::new(database_artifact::Column::DeltaPayload)
                .blob()
                .null()
                .to_owned(),
            ColumnDef::new(database_artifact::Column::DeltaContentHash)
                .string()
                .null()
                .to_owned(),
            ColumnDef::new(database_artifact::Column::DeltaSizeBytes)
                .big_integer()
                .not_null()
                .default(0)
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

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE database_artifact
                 SET checkpoint_size_bytes = size_bytes,
                     checkpoint_content_hash = content_hash",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            database_artifact::Column::DeltaSizeBytes,
            database_artifact::Column::DeltaContentHash,
            database_artifact::Column::DeltaPayload,
            database_artifact::Column::CheckpointContentHash,
            database_artifact::Column::CheckpointSizeBytes,
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
