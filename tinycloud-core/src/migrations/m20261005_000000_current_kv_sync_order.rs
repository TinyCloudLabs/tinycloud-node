//! TC-732: the `tinycloud.kv/sync` feed index.
//!
//! The change feed reads `current_kv` rows of one space in
//! `(seq, epoch, epoch_seq, key)` order, strictly after a cursor position.
//! `current_kv` is keyed `(space, key)`, so without this index every poll
//! sorts the space's whole key set. No column changes and no backfill: a
//! tombstone written after this release carries its delete's own position in
//! the existing `(seq, epoch, epoch_seq)` columns, and a pre-migration
//! tombstone keeps its deleted write's position, which is below every
//! bootstrap floor a client can hold.
//!
//! Names are raw identifiers on purpose: the live `current_kv` entity is
//! what `m20260724_010000_current_kv` builds from, so this migration must not
//! depend on it.

use sea_orm_migration::prelude::*;

pub(crate) const INDEX_NAME: &str = "idx_current_kv_space_order";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX_NAME)
                    .table(Alias::new("current_kv"))
                    .col(Alias::new("space"))
                    .col(Alias::new("seq"))
                    .col(Alias::new("epoch"))
                    .col(Alias::new("epoch_seq"))
                    .col(Alias::new("key"))
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(INDEX_NAME)
                    .table(Alias::new("current_kv"))
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};
    use sea_orm_migration::MigratorTrait;

    async fn index_exists(db: &DatabaseConnection) -> bool {
        db.query_one(Statement::from_sql_and_values(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
            [INDEX_NAME.into()],
        ))
        .await
        .unwrap()
        .is_some()
    }

    async fn current_kv_rows(db: &DatabaseConnection) -> i64 {
        db.query_one(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM current_kv",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap()
    }

    #[tokio::test]
    async fn fresh_install_creates_the_feed_index() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert!(index_exists(&db).await);
    }

    /// A node upgraded from the previous release: every earlier migration has
    /// run and `current_kv` already holds rows, including a tombstone. The
    /// migration adds only the index and leaves the rows untouched; `down`
    /// removes exactly the index.
    #[tokio::test]
    async fn pre_migration_database_gains_only_the_index() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        let previous = Migrator::migrations().len() as u32 - 1;
        Migrator::up(&db, Some(previous)).await.unwrap();
        assert!(!index_exists(&db).await);
        db.execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys = OFF",
        ))
        .await
        .unwrap();
        for (key, deleted) in [("notes/a", false), ("notes/b", true)] {
            db.execute(Statement::from_sql_and_values(
                sea_orm::DatabaseBackend::Sqlite,
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) \
                 VALUES ('tinycloud:key:z:default', ?, x'1e20', 1, x'1e20', 0, x'1e20', '{}', ?)",
                [key.into(), deleted.into()],
            ))
            .await
            .unwrap();
        }

        Migrator::up(&db, None).await.unwrap();
        assert!(index_exists(&db).await);
        assert_eq!(current_kv_rows(&db).await, 2);

        Migrator::down(&db, Some(1)).await.unwrap();
        assert!(!index_exists(&db).await);
        assert_eq!(current_kv_rows(&db).await, 2);
    }
}
