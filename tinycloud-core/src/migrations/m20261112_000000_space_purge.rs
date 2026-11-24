use crate::models::{
    space_purge_job, space_purge_nonce, space_purge_request, space_purge_tombstone,
    space_retirement,
};
use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        let mut job = schema.create_table_from_entity(space_purge_job::Entity);
        job.check(
            Expr::col(space_purge_job::Column::Phase)
                .is_in(["drain", "database", "access", "objects", "complete"]),
        );
        job.check(Expr::col(space_purge_job::Column::FenceGeneration).gte(1));
        // Completion removes the raw identity in the same transaction as the tombstone.
        job.check(Expr::cust(
            "(phase = 'complete' AND space IS NULL) OR (phase <> 'complete' AND space IS NOT NULL)",
        ));
        manager.create_table(job.if_not_exists().to_owned()).await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(space_retirement::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(space_purge_tombstone::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(space_purge_nonce::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(space_purge_request::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        if manager.get_database_backend() == DbBackend::MySql {
            // Completed jobs have NULL space, preserving the same active-only invariant.
            manager
                .create_index(
                    Index::create()
                        .name("space_purge_one_active")
                        .table(space_purge_job::Entity)
                        .col(space_purge_job::Column::Space)
                        .unique()
                        .to_owned(),
                )
                .await?;
        } else {
            manager.get_connection().execute_unprepared("CREATE UNIQUE INDEX IF NOT EXISTS space_purge_one_active ON space_purge_job (space) WHERE phase <> 'complete'").await?;
        }
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("space_purge_ready")
                    .table(space_purge_job::Entity)
                    .col(space_purge_job::Column::Phase)
                    .col(space_purge_job::Column::NextAttemptAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Removing a permanent fence can resurrect deleted data after a restore.
        Err(DbErr::Custom(
            "space purge records cannot be rolled back".into(),
        ))
    }
}
