//! `delegation_cid_alias_rule`: which revision of the canonical-identity rule
//! the stored `delegation_cid_alias.canonical` values follow (TC-4366).
//!
//! One new table with no foreign key and no index on any existing table. The
//! boot step `delegation_cid_alias::recompute` brings every UCAN alias to the
//! current rule, in the boot transaction, and records the revision here; a
//! later boot finds it and reads nothing.
//!
//! `up` also empties the table, so applying this migration again (after a
//! rollback deleted its `seaql_migrations` row) recomputes the aliases that
//! an older image wrote meanwhile. `down` drops the table; the recomputed
//! aliases stay, and an older image reads them unchanged.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum DelegationCidAliasRule {
    Table,
    Revision,
    AppliedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DelegationCidAliasRule::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DelegationCidAliasRule::Revision)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DelegationCidAliasRule::AppliedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(DelegationCidAliasRule::Table)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(DelegationCidAliasRule::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
