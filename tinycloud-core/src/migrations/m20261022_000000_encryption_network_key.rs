//! Schema for named encryption keys: one row per key under an encryption
//! network, and the nullable key path on audit rows. Nothing reads or writes
//! these yet.

use sea_orm_migration::prelude::*;

use crate::models::{encryption_audit, encryption_network_key};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(encryption_network_key::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(encryption_network_key::Column::NetworkId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::KeyPath)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::Kind)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::State)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::PublicKey)
                            .blob()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::SealedSeed)
                            .blob()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::KeyVersion)
                            .big_integer()
                            .not_null()
                            .default(1),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::CreatedAt)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(encryption_network_key::Column::UpdatedAt)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(encryption_network_key::Column::NetworkId)
                            .col(encryption_network_key::Column::KeyPath),
                    )
                    .to_owned(),
            )
            .await?;

        // Re-running this migration after its `seaql_migrations` row was removed
        // (without `down`) must not fail on the column that already exists.
        if !manager.has_column("encryption_audit", "key_path").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(encryption_audit::Entity)
                        .add_column(
                            ColumnDef::new(encryption_audit::Column::KeyPath)
                                .string()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(encryption_audit::Entity)
                    .drop_column(encryption_audit::Column::KeyPath)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(encryption_network_key::Entity)
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, DbBackend, EntityTrait, Statement,
    };
    use sea_orm_migration::MigratorTrait;

    async fn fresh_db() -> DatabaseConnection {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("migrate");
        db
    }

    fn key_row(network_id: &str, key_path: &str) -> encryption_network_key::ActiveModel {
        encryption_network_key::ActiveModel {
            network_id: Set(network_id.to_string()),
            key_path: Set(key_path.to_string()),
            kind: Set("deterministic".to_string()),
            state: Set("active".to_string()),
            public_key: Set(vec![7u8; 32]),
            sealed_seed: Set(None),
            key_version: Set(1),
            created_at: Set("2026-10-22T00:00:00Z".to_string()),
            updated_at: Set("2026-10-22T00:00:00Z".to_string()),
        }
    }

    #[tokio::test]
    async fn applies_on_fresh_sqlite_is_idempotent_and_reapplies_after_down() {
        let db = fresh_db().await;
        Migrator::up(&db, None).await.expect("second up is a no-op");
        Migrator::down(&db, Some(1)).await.expect("down");
        Migrator::up(&db, None).await.expect("up after down");
        key_row("net", "docs/app-one/key")
            .insert(&db)
            .await
            .expect("insert after reapply");
    }

    #[tokio::test]
    async fn key_row_round_trips_with_null_sealed_seed() {
        let db = fresh_db().await;
        key_row("net", "docs/app-one/key")
            .insert(&db)
            .await
            .expect("insert");
        let row = encryption_network_key::Entity::find_by_id((
            "net".to_string(),
            "docs/app-one/key".to_string(),
        ))
        .one(&db)
        .await
        .expect("query")
        .expect("row present");
        assert_eq!(row.kind, "deterministic");
        assert_eq!(row.state, "active");
        assert_eq!(row.public_key, vec![7u8; 32]);
        assert_eq!(row.sealed_seed, None);
        assert_eq!(row.key_version, 1);
    }

    #[tokio::test]
    async fn duplicate_network_and_key_path_is_rejected_but_other_network_is_not() {
        let db = fresh_db().await;
        key_row("net", "k").insert(&db).await.expect("first insert");
        let mut duplicate = key_row("net", "k");
        duplicate.state = Set("blocked".to_string());
        assert!(duplicate.insert(&db).await.is_err());
        let kept = encryption_network_key::Entity::find_by_id(("net".to_string(), "k".to_string()))
            .one(&db)
            .await
            .expect("query")
            .expect("row present");
        assert_eq!(kept.state, "active");
        key_row("other", "k")
            .insert(&db)
            .await
            .expect("same path under another network");
    }

    #[tokio::test]
    async fn key_version_defaults_to_one_when_omitted() {
        let db = fresh_db().await;
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO encryption_network_key (network_id, key_path, kind, state, public_key, created_at, updated_at) \
             VALUES ('net', 'k', 'deterministic', 'active', X'07', '2026-10-22T00:00:00Z', '2026-10-22T00:00:00Z')"
                .to_string(),
        ))
        .await
        .expect("insert without key_version");
        let row = encryption_network_key::Entity::find_by_id(("net".to_string(), "k".to_string()))
            .one(&db)
            .await
            .expect("query")
            .expect("row present");
        assert_eq!(row.key_version, 1);
    }

    #[tokio::test]
    async fn audit_insert_without_key_path_still_works() {
        let db = fresh_db().await;
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO encryption_audit (request_hash, requester, network_id, node_id, outcome, decided_at) \
             VALUES ('h1', 'did:key:z6MkRequester', 'default', 'did:key:z6MkNode', 'allowed', '2026-10-22T00:00:00Z')"
                .to_string(),
        ))
        .await
        .expect("insert audit row without key_path");
        let row = encryption_audit::Entity::find_by_id("h1".to_string())
            .one(&db)
            .await
            .expect("query")
            .expect("row present");
        assert_eq!(row.key_path, None);
    }

    /// Removes only the migration record, as the rollback instruction does, then
    /// re-runs migrations without `down` and checks the schema accepts new rows.
    async fn assert_reapplies_after_record_removed(db: &DatabaseConnection) {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "DELETE FROM seaql_migrations WHERE version = 'm20261022_000000_encryption_network_key'"
                .to_string(),
        ))
        .await
        .expect("remove migration record");
        Migrator::up(db, None).await.expect("re-apply without down");
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "INSERT INTO encryption_audit (request_hash, requester, network_id, node_id, outcome, decided_at) \
             VALUES ('h2', 'did:key:z6MkRequester', 'default', 'did:key:z6MkNode', 'allowed', '2026-10-22T00:00:00Z')"
                .to_string(),
        ))
        .await
        .expect("audit insert without key_path after re-apply");
        key_row("net", "docs/app-one/key")
            .insert(db)
            .await
            .expect("key row insert after re-apply");
    }

    #[tokio::test]
    async fn reapplies_after_migration_record_is_removed_without_down() {
        let db = fresh_db().await;
        assert_reapplies_after_record_removed(&db).await;
    }

    #[tokio::test]
    async fn postgres_reapplies_after_migration_record_is_removed_without_down() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_reapplies_after_migration_record_is_removed_without_down",
        )
        .await
        else {
            return;
        };
        assert_reapplies_after_record_removed(&fixture.conn).await;
    }

    #[tokio::test]
    async fn up_is_a_no_op_when_table_and_column_already_exist() {
        let db = fresh_db().await;
        key_row("net", "docs/app-one/key")
            .insert(&db)
            .await
            .expect("insert key row");
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO encryption_audit (request_hash, requester, network_id, node_id, outcome, decided_at, key_path) \
             VALUES ('h3', 'did:key:z6MkRequester', 'default', 'did:key:z6MkNode', 'allowed', '2026-10-22T00:00:00Z', 'docs/app-one/key')"
                .to_string(),
        ))
        .await
        .expect("insert audit row with key_path");

        let manager = SchemaManager::new(&db);
        Migration
            .up(&manager)
            .await
            .expect("up is a no-op over existing table and column");

        let key = encryption_network_key::Entity::find_by_id((
            "net".to_string(),
            "docs/app-one/key".to_string(),
        ))
        .one(&db)
        .await
        .expect("query")
        .expect("key row survives");
        assert_eq!(key.kind, "deterministic");
        let audit = encryption_audit::Entity::find_by_id("h3".to_string())
            .one(&db)
            .await
            .expect("query")
            .expect("audit row survives");
        assert_eq!(audit.key_path, Some("docs/app-one/key".to_string()));
    }
}
