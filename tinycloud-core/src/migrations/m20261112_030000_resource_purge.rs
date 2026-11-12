use crate::models::{resource_purge_job, resource_purge_tombstone};
use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        let mut job = schema.create_table_from_entity(resource_purge_job::Entity);
        job.check(
            Expr::col(resource_purge_job::Column::Phase)
                .is_in(["drain", "database", "access", "objects", "complete"]),
        );
        job.check(Expr::col(resource_purge_job::Column::FenceGeneration).gte(1));
        // Completion removes the raw identity in the same transaction as the tombstone.
        job.check(Expr::cust(
            "(phase = 'complete' AND resource IS NULL) OR (phase <> 'complete' AND resource IS NOT NULL)",
        ));
        manager.create_table(job.if_not_exists().to_owned()).await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(resource_purge_tombstone::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        if manager.get_database_backend() == DbBackend::MySql {
            // Completed jobs have NULL resource, preserving the same active-only invariant.
            manager
                .create_index(
                    Index::create()
                        .name("resource_purge_one_active")
                        .table(resource_purge_job::Entity)
                        .col(resource_purge_job::Column::Resource)
                        .unique()
                        .to_owned(),
                )
                .await?;
        } else {
            manager.get_connection().execute_unprepared("CREATE UNIQUE INDEX IF NOT EXISTS resource_purge_one_active ON resource_purge_job (resource) WHERE phase <> 'complete'").await?;
        }
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("resource_purge_ready")
                    .table(resource_purge_job::Entity)
                    .col(resource_purge_job::Column::Phase)
                    .col(resource_purge_job::Column::NextAttemptAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Removing a permanent fence can resurrect deleted data after a restore.
        Err(DbErr::Custom(
            "resource purge records cannot be rolled back".into(),
        ))
    }
}
