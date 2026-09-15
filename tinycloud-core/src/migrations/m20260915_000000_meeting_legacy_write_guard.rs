use crate::models::meeting_legacy_write_guard;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(meeting_legacy_write_guard::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(meeting_legacy_write_guard::Column::Space)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(meeting_legacy_write_guard::Column::Frozen)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(meeting_legacy_write_guard::Column::Generation)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Dropping the generation would permit stale releases after a rollback.
        Err(DbErr::Custom(
            "legacy meeting guard rollback requires an explicit recovery plan".into(),
        ))
    }
}
