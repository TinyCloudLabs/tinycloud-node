//! Schema only. Startup backfills legacy policies transactionally; the
//! read-only count gate must run before this migration is released.
use crate::policy_witness::{Column, Entity};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Entity)
                    .if_not_exists()
                    .col(ColumnDef::new(Column::PolicyCid).string().not_null())
                    .col(ColumnDef::new(Column::RootCid).string().not_null())
                    .col(ColumnDef::new(Column::CapabilityIndex).integer().not_null())
                    .col(ColumnDef::new(Column::Version).integer().not_null())
                    .col(ColumnDef::new(Column::RegisteredAt).string().not_null())
                    .col(ColumnDef::new(Column::WitnessBytes).blob().not_null())
                    .col(ColumnDef::new(Column::WitnessDigestHex).string().not_null())
                    .primary_key(
                        Index::create()
                            .col(Column::PolicyCid)
                            .col(Column::RootCid)
                            .col(Column::CapabilityIndex),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Entity).to_owned())
            .await
    }
}
