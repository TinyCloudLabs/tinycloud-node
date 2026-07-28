//! Persist the encrypted share-key-to-enforcer artifact for live revocation checks.

use sea_orm_migration::prelude::*;

use crate::models::owner_share_policy;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(owner_share_policy::Entity)
                    .add_column(
                        ColumnDef::new(owner_share_policy::Column::EnforcementDelegationBytes)
                            .binary()
                            .not_null()
                            .default(Vec::<u8>::new()),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(owner_share_policy::Entity)
                    .drop_column(owner_share_policy::Column::EnforcementDelegationBytes)
                    .to_owned(),
            )
            .await
    }
}
