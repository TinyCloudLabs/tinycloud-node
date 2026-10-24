use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::models::{kv_blob_generation, kv_orphan_attempt, kv_orphan_candidate};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Re-runnable: every table and index is created if absent and the
    /// `generation` columns are added only where missing, so applying the
    /// migration again over existing tables (and their rows) changes nothing.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(
                schema
                    .create_table_from_entity(kv_blob_generation::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for table in ["kv_write", "current_kv"] {
            // A fresh install builds the initial table from today's entity,
            // while an upgraded schema still has the pre-generation column set.
            if !manager.has_column(table, "generation").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new(table))
                            .add_column(
                                ColumnDef::new(Alias::new("generation"))
                                    .big_integer()
                                    .not_null()
                                    .default(0),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        }
        manager
            .create_table(
                schema
                    .create_table_from_entity(kv_orphan_candidate::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(kv_orphan_attempt::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_kv_orphan_candidate_deleting")
                    .table(kv_orphan_candidate::Entity)
                    .col(kv_orphan_candidate::Column::DeletingAt)
                    .col(kv_orphan_candidate::Column::Space)
                    .col(kv_orphan_candidate::Column::Value)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_kv_orphan_attempt_age")
                    .table(kv_orphan_attempt::Entity)
                    .col(kv_orphan_attempt::Column::CreatedAt)
                    .col(kv_orphan_attempt::Column::Space)
                    .col(kv_orphan_attempt::Column::Value)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_kv_orphan_attempt_retry")
                    .table(kv_orphan_attempt::Entity)
                    .col(kv_orphan_attempt::Column::RetryAfter)
                    .col(kv_orphan_attempt::Column::CreatedAt)
                    .col(kv_orphan_attempt::Column::Space)
                    .col(kv_orphan_attempt::Column::Value)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["current_kv", "kv_write"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new("generation"))
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_table(Table::drop().table(kv_orphan_attempt::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(kv_orphan_candidate::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(kv_blob_generation::Entity).to_owned())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::migrations::Migrator;
    use crate::types::SpaceIdWrap;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, EntityTrait, Statement,
    };
    use sea_orm_migration::MigratorTrait;
    use time::OffsetDateTime;
    use tinycloud_auth::{resolver::DID_METHODS, resource::SpaceId, ssi::jwk::JWK};

    const VERSION: &str = "m20261023_010000_kv_orphan_candidates";

    async fn seed(db: &DatabaseConnection) {
        let did = DID_METHODS
            .generate(&JWK::generate_ed25519().unwrap(), "key")
            .unwrap();
        let space = SpaceIdWrap(SpaceId::new(did, "files".parse().unwrap()));
        let value = hash(b"rerun");
        let now = OffsetDateTime::now_utc();
        kv_blob_generation::ActiveModel {
            space: Set(space.clone()),
            value: Set(value),
            generation: Set(3),
        }
        .insert(db)
        .await
        .unwrap();
        kv_orphan_candidate::ActiveModel {
            space: Set(space.clone()),
            value: Set(value),
            generation: Set(3),
            created_at: Set(now),
            deleting_at: Set(None),
            deletion_bytes: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        kv_orphan_attempt::ActiveModel {
            space: Set(space),
            value: Set(value),
            attempt_id: Set("attempt".to_owned()),
            generation: Set(3),
            created_at: Set(now),
            retry_after: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn counts(db: &DatabaseConnection) -> (usize, usize, usize) {
        (
            kv_blob_generation::Entity::find()
                .all(db)
                .await
                .unwrap()
                .len(),
            kv_orphan_candidate::Entity::find()
                .all(db)
                .await
                .unwrap()
                .len(),
            kv_orphan_attempt::Entity::find()
                .all(db)
                .await
                .unwrap()
                .len(),
        )
    }

    /// Applying the migration again over its own tables, with rows in them,
    /// changes nothing, whether directly or through the migrator after its
    /// history row is deleted.
    async fn assert_rerunnable(db: &DatabaseConnection) {
        seed(db).await;
        let backend = db.get_database_backend();
        Migration.up(&SchemaManager::new(db)).await.unwrap();
        assert_eq!(counts(db).await, (1, 1, 1));

        db.execute(Statement::from_string(
            backend,
            format!("DELETE FROM seaql_migrations WHERE version = '{VERSION}'"),
        ))
        .await
        .unwrap();
        Migrator::up(db, None).await.unwrap();
        assert_eq!(counts(db).await, (1, 1, 1));
        let history = db
            .query_one(Statement::from_string(
                backend,
                format!("SELECT version FROM seaql_migrations WHERE version = '{VERSION}'"),
            ))
            .await
            .unwrap();
        assert!(history.is_some(), "the history row is recorded again");
    }

    #[tokio::test]
    async fn sqlite_migration_reruns_over_populated_tables() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_owned()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_rerunnable(&db).await;
    }

    #[tokio::test]
    async fn postgres_migration_reruns_over_populated_tables() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_migration_reruns_over_populated_tables",
        )
        .await
        else {
            return;
        };
        assert_rerunnable(&fixture.conn).await;
    }
}
