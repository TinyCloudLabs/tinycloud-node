use crate::models::space_purge_shared_residue;
use sea_orm::Schema;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut table = Schema::new(manager.get_database_backend())
            .create_table_from_entity(space_purge_shared_residue::Entity);
        table.check(
            Expr::col(space_purge_shared_residue::Column::RecordKind).is_in([
                "invocation",
                "delegation",
                "revocation",
            ]),
        );
        manager
            .create_table(table.if_not_exists().to_owned())
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("space_purge_residue_record")
                    .table(space_purge_shared_residue::Entity)
                    .col(space_purge_shared_residue::Column::RecordKind)
                    .col(space_purge_shared_residue::Column::RecordId)
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Custom(
            "space purge residue records cannot be rolled back".into(),
        ))
    }
}
