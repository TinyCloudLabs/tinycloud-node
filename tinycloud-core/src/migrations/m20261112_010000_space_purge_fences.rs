use crate::models::space_purge_fence;
use sea_orm::Schema;
use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut table = Schema::new(manager.get_database_backend())
            .create_table_from_entity(space_purge_fence::Entity);
        table.check(Expr::col(space_purge_fence::Column::Generation).gte(0));
        manager.create_table(table.if_not_exists().to_owned()).await
    }
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Custom(
            "space purge fences cannot be rolled back".into(),
        ))
    }
}
