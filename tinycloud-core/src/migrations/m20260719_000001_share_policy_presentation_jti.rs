//! N4-owned replay-control table for the #117 policy-session establishment
//! transaction. See [`crate::models::share_policy_presentation_jti`].

use sea_orm_migration::prelude::*;

use crate::models::share_policy_presentation_jti;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(share_policy_presentation_jti::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(share_policy_presentation_jti::Column::PresentationJti)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(share_policy_presentation_jti::Column::Nonce)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(share_policy_presentation_jti::Column::PolicyCid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(share_policy_presentation_jti::Column::SessionHandle)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(share_policy_presentation_jti::Column::IssuedAt)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(share_policy_presentation_jti::Column::ExpiresAt)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create().col(share_policy_presentation_jti::Column::PresentationJti),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_share_policy_presentation_jti_nonce")
                    .table(share_policy_presentation_jti::Entity)
                    .col(share_policy_presentation_jti::Column::Nonce)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(share_policy_presentation_jti::Entity)
                    .to_owned(),
            )
            .await
    }
}
