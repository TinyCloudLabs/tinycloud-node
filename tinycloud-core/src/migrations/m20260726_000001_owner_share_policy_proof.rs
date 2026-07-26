//! Add the durable share-key policy signature used by the v2 data plane.

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
                        ColumnDef::new(owner_share_policy::Column::PolicyProof)
                            .string()
                            .not_null()
                            .default(""),
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
                    .drop_column(owner_share_policy::Column::PolicyProof)
                    .to_owned(),
            )
            .await
    }
}
