use crate::models::{space_purge_ledger_copy, space_purge_prefix_repair};
use sea_orm::Schema;
use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(
                schema
                    .create_table_from_entity(space_purge_ledger_copy::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        let mut repair = schema.create_table_from_entity(space_purge_prefix_repair::Entity);
        repair.check(
            Expr::col(space_purge_prefix_repair::Column::Phase).is_in(["pending", "complete"]),
        );
        repair.check(Expr::col(space_purge_prefix_repair::Column::AttemptCount).gte(0));
        manager
            .create_table(repair.if_not_exists().to_owned())
            .await?;
        // Only pending repairs conflict: a newly observed restored prefix gets
        // a NEW repair job, never a downgrade of an earlier completed repair.
        manager.get_connection().execute_unprepared("CREATE UNIQUE INDEX IF NOT EXISTS space_purge_prefix_repair_exact ON space_purge_prefix_repair (object_key,store_kind,prefix_hmac) WHERE phase='pending'").await?;
        Ok(())
    }
    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Custom(
            "authenticated purge evidence cannot be rolled back".into(),
        ))
    }
}
