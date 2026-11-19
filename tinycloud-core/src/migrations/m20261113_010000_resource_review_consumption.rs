use crate::models::resource_review_consumption;
use sea_orm::Schema;
use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Schema::new(manager.get_database_backend())
                    .create_table_from_entity(resource_review_consumption::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Custom(
            "consumed review authority cannot be rolled back".into(),
        ))
    }
}
