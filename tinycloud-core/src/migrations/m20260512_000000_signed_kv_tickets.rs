use sea_orm_migration::prelude::*;

use crate::models::signed_kv_ticket;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(signed_kv_ticket::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::Id)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::IssuerDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::SubjectDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::SpaceId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::Path)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::Service)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::Ability)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::ExpiresAt)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::InvocationExpiresAt)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::ParentExpiresAt)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::ContentHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::Etag)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(signed_kv_ticket::Column::ParentCidsJson)
                            .string()
                            .null(),
                    )
                    .primary_key(Index::create().col(signed_kv_ticket::Column::Id))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(signed_kv_ticket::Entity).to_owned())
            .await
    }
}
