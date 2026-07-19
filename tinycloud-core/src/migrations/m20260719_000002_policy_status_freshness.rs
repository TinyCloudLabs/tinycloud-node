use sea_orm_migration::prelude::*;

use crate::models::policy_delegation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(policy_delegation::Entity)
                    .add_column(
                        ColumnDef::new(policy_delegation::Column::StatusFreshUntil)
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(policy_delegation::Entity)
                    .drop_column(policy_delegation::Column::StatusFreshUntil)
                    .to_owned(),
            )
            .await
    }
}
