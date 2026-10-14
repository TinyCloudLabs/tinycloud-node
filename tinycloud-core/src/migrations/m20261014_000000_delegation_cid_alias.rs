use sea_orm_migration::prelude::*;

use crate::models::{delegation, delegation_cid_alias};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut id = ColumnDef::new(delegation_cid_alias::Column::Id);
        let mut canonical = ColumnDef::new(delegation_cid_alias::Column::Canonical);
        if manager.get_database_backend() == sea_orm::DbBackend::MySql {
            // Encoded multihashes have variable length; MySQL's bare BINARY
            // defaults to one byte, and fixed-width BINARY would pad the ID.
            id.var_binary(255);
            canonical.var_binary(255);
        } else {
            id.binary();
            canonical.binary();
        }
        manager
            .create_table(
                Table::create()
                    .table(delegation_cid_alias::Entity)
                    .if_not_exists()
                    .col(id.not_null().primary_key())
                    .col(canonical.not_null())
                    .col(
                        ColumnDef::new(delegation_cid_alias::Column::Encrypted)
                            .boolean()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                delegation_cid_alias::Entity,
                                delegation_cid_alias::Column::Id,
                            )
                            .to(delegation::Entity, delegation::Column::Id),
                    )
                    // Canonical identities may have no separately persisted
                    // serialization, so only the exact ID has a foreign key.
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_cid_alias_canonical")
                    .table(delegation_cid_alias::Entity)
                    .col(delegation_cid_alias::Column::Canonical)
                    .col(delegation_cid_alias::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_cid_alias_encrypted")
                    .table(delegation_cid_alias::Entity)
                    .col(delegation_cid_alias::Column::Encrypted)
                    .col(delegation_cid_alias::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_cid_alias_canonical")
                    .table(delegation_cid_alias::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_cid_alias_encrypted")
                    .table(delegation_cid_alias::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(delegation_cid_alias::Entity).to_owned())
            .await
    }
}
