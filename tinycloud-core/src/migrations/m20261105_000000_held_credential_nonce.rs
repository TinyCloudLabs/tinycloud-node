//! TC-1452: `held_credential_nonce` table. A presentation for a held credential
//! spends its nonce by deleting the row whose audience, nonce and account all
//! match, so a nonce is single use and bound to the account it was minted for.

use sea_orm_migration::prelude::*;

use crate::models::held_credential_nonce;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(held_credential_nonce::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(held_credential_nonce::Column::Audience)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(held_credential_nonce::Column::Nonce)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(held_credential_nonce::Column::Account)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(held_credential_nonce::Column::Audience)
                            .col(held_credential_nonce::Column::Nonce),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(held_credential_nonce::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
