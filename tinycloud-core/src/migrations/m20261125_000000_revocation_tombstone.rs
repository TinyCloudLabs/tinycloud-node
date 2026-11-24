//! `revocation_tombstone`: what a space purge remembers of a revoked
//! delegation after it deletes the `revocation` row (TC-4092).
//!
//! One new, empty table with no foreign key, no index on any existing table
//! and no backfill: purges that ran before this migration have already lost
//! their revocation rows and are not recovered. Re-run is a no-op
//! (IF NOT EXISTS). The four columns hold one opaque content hash and times;
//! there is no DID, space or resource column (see the model).
//!
//! `down` drops the table. Rolling back reopens the gap: a purge run by the
//! previous image deletes revocations without a tombstone.

use sea_orm_migration::prelude::*;

use crate::models::revocation_tombstone as tombstone;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(tombstone_table(manager.get_database_backend()))
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(tombstone::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

/// Public so tests can render the DDL for every backend.
pub fn tombstone_table(backend: sea_orm::DbBackend) -> TableCreateStatement {
    use tombstone::Column as C;
    let mut canonical = ColumnDef::new(C::DelegationCanonical);
    if backend == sea_orm::DbBackend::MySql {
        canonical.var_binary(255);
    } else {
        canonical.binary();
    }
    Table::create()
        .table(tombstone::Entity)
        .if_not_exists()
        .col(canonical.not_null().primary_key())
        .col(ColumnDef::new(C::DelegationExpiry).timestamp_with_time_zone())
        .col(ColumnDef::new(C::RevokedAt).timestamp_with_time_zone())
        .col(
            ColumnDef::new(C::RecordedAt)
                .timestamp_with_time_zone()
                .not_null(),
        )
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
    use sea_orm_migration::MigratorTrait;

    async fn sqlite() -> sea_orm::DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        Database::connect(options).await.unwrap()
    }

    async fn columns(conn: &sea_orm::DatabaseConnection) -> Vec<String> {
        conn.query_all(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT name FROM pragma_table_info('revocation_tombstone') ORDER BY cid".to_string(),
        ))
        .await
        .unwrap()
        .iter()
        .map(|row| row.try_get::<String>("", "name").unwrap())
        .collect()
    }

    #[tokio::test]
    async fn up_twice_is_a_no_op_and_down_drops_the_table() {
        let conn = sqlite().await;
        Migrator::up(&conn, None).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        // The migration alone, re-run, is a no-op (IF NOT EXISTS).
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        // Exactly these four columns: no DID, space or resource, ever. The
        // purge table inventory relies on it.
        assert_eq!(
            columns(&conn).await,
            [
                "delegation_canonical",
                "delegation_expiry",
                "revoked_at",
                "recorded_at"
            ]
        );
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        assert!(columns(&conn).await.is_empty());
        // Down is idempotent (IF EXISTS), and up recreates the table.
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        assert_eq!(columns(&conn).await.len(), 4);
    }

    #[test]
    fn every_backend_creates_the_table_if_absent() {
        for backend in [DbBackend::Postgres, DbBackend::Sqlite, DbBackend::MySql] {
            let ddl = match backend {
                DbBackend::Postgres => tombstone_table(backend)
                    .to_string(sea_orm_migration::sea_query::PostgresQueryBuilder),
                DbBackend::Sqlite => tombstone_table(backend)
                    .to_string(sea_orm_migration::sea_query::SqliteQueryBuilder),
                DbBackend::MySql => tombstone_table(backend)
                    .to_string(sea_orm_migration::sea_query::MysqlQueryBuilder),
            };
            assert!(ddl.contains("IF NOT EXISTS"), "{ddl}");
            assert!(ddl.contains("PRIMARY KEY"), "{ddl}");
        }
    }
}
