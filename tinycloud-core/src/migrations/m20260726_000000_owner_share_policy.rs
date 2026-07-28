//! Additive persistence for production owner-rooted v2 share policies.

use sea_orm_migration::prelude::*;

use crate::models::owner_share_policy;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(owner_share_policy::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(owner_share_policy::Column::PolicyCid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::RegistrationCid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::OwnerDelegationCid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::EnforcementDelegationCid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::PolicyBytes)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::PolicyDigest)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::MatcherDigest)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::ContentSourceDigest)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::OwnerDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::ShareKeyDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::EnforcerDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::NodeAudience)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::TargetOrigin)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::SpaceId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::ResourceKind)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::ResourcePath)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::Actions)
                            .json()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::RegisteredAt)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(owner_share_policy::Column::ExpiresAt)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(owner_share_policy::Column::RevokedAt).string())
                    .primary_key(Index::create().col(owner_share_policy::Column::PolicyCid))
                    .to_owned(),
            )
            .await?;

        for (name, column) in [
            (
                "idx_owner_share_policy_registration_cid",
                owner_share_policy::Column::RegistrationCid,
            ),
            (
                "idx_owner_share_policy_owner_delegation_cid",
                owner_share_policy::Column::OwnerDelegationCid,
            ),
            (
                "idx_owner_share_policy_enforcement_delegation_cid",
                owner_share_policy::Column::EnforcementDelegationCid,
            ),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(owner_share_policy::Entity)
                        .col(column)
                        .unique()
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(owner_share_policy::Entity).to_owned())
            .await
    }
}
