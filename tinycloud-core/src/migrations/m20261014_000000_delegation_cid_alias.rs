use sea_orm_migration::prelude::*;

use crate::models::{delegation, delegation_cid_alias};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(delegation_cid_alias::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(delegation_cid_alias::Column::Id)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(delegation_cid_alias::Column::Canonical)
                            .binary()
                            .not_null(),
                    )
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
