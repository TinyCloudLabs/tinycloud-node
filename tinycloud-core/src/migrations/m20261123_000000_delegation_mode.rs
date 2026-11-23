use sea_orm_migration::prelude::*;

use crate::models::{delegation, delegation_mode};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let mut delegation_id = ColumnDef::new(delegation_mode::Column::DelegationId);
        let mut mode = ColumnDef::new(delegation_mode::Column::Mode);
        if backend == sea_orm::DbBackend::MySql {
            delegation_id.var_binary(255);
            mode.string_len(16);
        } else {
            delegation_id.binary();
            mode.text();
        }
        manager
            .create_table(
                Table::create()
                    .table(delegation_mode::Entity)
                    .if_not_exists()
                    .col(delegation_id.not_null().primary_key())
                    .col(
                        mode.not_null()
                            .check(Expr::cust("mode IN ('attenuable', 'terminal', 'invalid')")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                delegation_mode::Entity,
                                delegation_mode::Column::DelegationId,
                            )
                            .to(delegation::Entity, delegation::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(delegation_mode::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
