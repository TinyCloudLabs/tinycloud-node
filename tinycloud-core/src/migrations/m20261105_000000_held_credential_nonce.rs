//! TC-1452: `held_credential_nonce` table. A presentation for a held credential
//! spends its nonce by deleting the row whose audience, nonce and account all
//! match, so a nonce is single use and bound to the account it was minted for.
//! Every consume first prunes rows with `expires_at <= now`, so `expires_at` is
//! indexed to keep that prune from scanning the table.

use sea_orm_migration::prelude::*;

use crate::models::held_credential_nonce;

const EXPIRES_AT_INDEX: &str = "idx_held_credential_nonce_expires_at";

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
                    .col(
                        ColumnDef::new(held_credential_nonce::Column::ExpiresAt)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(held_credential_nonce::Column::Audience)
                            .col(held_credential_nonce::Column::Nonce),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(EXPIRES_AT_INDEX)
                    .table(held_credential_nonce::Entity)
                    .col(held_credential_nonce::Column::ExpiresAt)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(EXPIRES_AT_INDEX)
                    .table(held_credential_nonce::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::PostgresTestSchema;
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};

    /// Columns of the expires_at index on SQLite, in key order. Empty when absent.
    async fn sqlite_index_columns(db: &DatabaseConnection) -> Vec<String> {
        db.query_all(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA index_info('{EXPIRES_AT_INDEX}')"),
        ))
        .await
        .unwrap()
        .iter()
        .map(|row| row.try_get("", "name").unwrap())
        .collect()
    }

    async fn sqlite_table_exists(db: &DatabaseConnection) -> bool {
        db.query_one(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'held_credential_nonce'"
                .to_string(),
        ))
        .await
        .unwrap()
        .is_some()
    }

    /// Definition of the expires_at index on Postgres, or `None` when absent.
    async fn postgres_index_def(db: &DatabaseConnection) -> Option<String> {
        db.query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT indexdef FROM pg_indexes \
                 WHERE schemaname = current_schema() AND indexname = '{EXPIRES_AT_INDEX}'"
            ),
        ))
        .await
        .unwrap()
        .map(|row| row.try_get("", "indexdef").unwrap())
    }

    async fn postgres_table_exists(db: &DatabaseConnection) -> bool {
        db.query_one(Statement::from_string(
            DbBackend::Postgres,
            "SELECT to_regclass('held_credential_nonce') IS NOT NULL AS present".to_string(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "present")
        .unwrap()
    }

    #[tokio::test]
    async fn sqlite_expires_at_index_follows_up_and_down() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("nonce.db").display()
        );
        let db = Database::connect(url).await.unwrap();
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();
        assert_eq!(sqlite_index_columns(&db).await, ["expires_at"]);

        Migration.down(&manager).await.unwrap();
        assert!(sqlite_index_columns(&db).await.is_empty());
        assert!(!sqlite_table_exists(&db).await);

        Migration.up(&manager).await.unwrap();
        assert_eq!(sqlite_index_columns(&db).await, ["expires_at"]);
    }

    #[tokio::test]
    async fn postgres_expires_at_index_follows_up_and_down() {
        // The state a node upgrading to this migration boots with: this migration
        // and everything after it still unapplied.
        let this = crate::migrations::Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == Migration.name())
            .unwrap() as u32;
        let Some(fixture) = PostgresTestSchema::migrated_through(
            "postgres_expires_at_index_follows_up_and_down",
            Some(this),
        )
        .await
        else {
            return;
        };
        let db = &fixture.conn;
        let manager = SchemaManager::new(db);
        assert!(postgres_index_def(db).await.is_none());

        Migration.up(&manager).await.unwrap();
        let def = postgres_index_def(db).await.expect("index created by up");
        assert!(def.ends_with("(expires_at)"), "{def}");

        Migration.down(&manager).await.unwrap();
        assert!(postgres_index_def(db).await.is_none());
        assert!(!postgres_table_exists(db).await);

        Migration.up(&manager).await.unwrap();
        let def = postgres_index_def(db).await.expect("index recreated by up");
        assert!(def.ends_with("(expires_at)"), "{def}");
    }
}
