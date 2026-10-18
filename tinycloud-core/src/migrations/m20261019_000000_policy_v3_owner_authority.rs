//! TC-1423: record which delegations a Policy/v3 owner held as authority.
//!
//! Two new, empty tables and one index; no ALTER of `policy_v3_registration`
//! and no foreign keys (as in m20261018), so the migration is O(1) and an
//! older binary simply ignores the tables. Existing registrations are
//! classified lazily on first use, or by the node's opt-in sweep.
//!
//! Rollback: run `down` (two `DROP TABLE`s), then deploy the previous binary.
//! The applied-at time of this migration is the default legacy cutover; after
//! a rollback and re-upgrade, set `policy_v3.legacy_cutover` to the first
//! deploy time.

use sea_orm_migration::prelude::*;

use crate::models::{policy_v3_owner_authority, policy_v3_owner_binding};

#[derive(DeriveMigrationName)]
pub struct Migration;

const AUTHORITY_BY_DELEGATION_INDEX: &str = "idx_policy_v3_owner_authority_delegation";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(policy_v3_owner_binding::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(policy_v3_owner_binding::Column::PolicyCid)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(policy_v3_owner_binding::Column::State)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(policy_v3_owner_binding::Column::AuthorityExpiresAt)
                            .string(),
                    )
                    .col(ColumnDef::new(policy_v3_owner_binding::Column::UnknownReason).string())
                    .col(
                        ColumnDef::new(policy_v3_owner_binding::Column::ClassifierVersion)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(policy_v3_owner_binding::Column::RegisteredMode)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(policy_v3_owner_binding::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        let mut delegation_id = ColumnDef::new(policy_v3_owner_authority::Column::DelegationId);
        if manager.get_database_backend() == sea_orm::DbBackend::MySql {
            // As in m20261014: MySQL's bare BINARY is one byte and fixed-width
            // BINARY would pad the multihash.
            delegation_id.var_binary(255);
        } else {
            delegation_id.binary();
        }
        manager
            .create_table(
                Table::create()
                    .table(policy_v3_owner_authority::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(policy_v3_owner_authority::Column::PolicyCid)
                            .string()
                            .not_null(),
                    )
                    .col(delegation_id.not_null())
                    .col(
                        ColumnDef::new(policy_v3_owner_authority::Column::Depth)
                            .integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(policy_v3_owner_authority::Column::PolicyCid)
                            .col(policy_v3_owner_authority::Column::DelegationId),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(AUTHORITY_BY_DELEGATION_INDEX)
                    .table(policy_v3_owner_authority::Entity)
                    .col(policy_v3_owner_authority::Column::DelegationId)
                    .col(policy_v3_owner_authority::Column::PolicyCid)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Dropping a table drops its indexes on every supported backend.
        manager
            .drop_table(
                Table::drop()
                    .table(policy_v3_owner_authority::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(policy_v3_owner_binding::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
