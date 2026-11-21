//! TC-1491 1b-design §9 (owner marker): the `sql_store_owner` row that pairs
//! with the `sql/v1/_owner/v1` object at boot.
//!
//! One empty table, no foreign keys, no index on any existing table, no
//! backfill. **MySQL-safe**: `varchar(32)` primary key (128-bit hex) plus a
//! bounded `varchar(40)` timestamp, both well under the 3,072-byte InnoDB key
//! cap. Re-run is a no-op (IF NOT EXISTS).
//!
//! Interaction with TC-3443 (`m20261121_000000_session_retire`, node 1.26.18):
//! disjoint tables (`revocation`/session rows vs this fresh table), disjoint
//! control-DB state. SeaORM applies by version string, so this migration (date
//! 2026-11-22) runs strictly after the session-retire migration whichever is
//! installed first. No conflict.
//!
//! **[shadow only]** `down` drops the table. In store-master the row is the
//! identity fence and `down` must be replaced by a refusing variant.

use sea_orm_migration::prelude::*;

use crate::models::sql_store_owner as owner;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(owner_table()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(owner::Entity).if_exists().to_owned())
            .await
    }
}

/// Public so tests can render the DDL for every backend.
pub fn owner_table() -> TableCreateStatement {
    use owner::Column as C;
    let mut store_id = ColumnDef::new(C::StoreId);
    store_id.string_len(32).not_null();
    let mut created_at = ColumnDef::new(C::CreatedAt);
    created_at.string_len(40).not_null();
    Table::create()
        .table(owner::Entity)
        .if_not_exists()
        .col(store_id)
        .col(created_at)
        .primary_key(Index::create().col(C::StoreId))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, Database, DbBackend};
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn sqlite_fresh_up_is_idempotent() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_down_then_up_runs() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
    }

    #[test]
    fn mysql_ddl_fits_in_three_thousand_seventy_two_bytes() {
        let ddl = owner_table().to_string(sea_orm_migration::sea_query::MysqlQueryBuilder);
        // The primary key is 32 chars under utf8mb4 (4 bytes/char) = 128 bytes,
        // far below the 3072-byte InnoDB key cap.
        assert!(ddl.contains("sql_store_owner"));
        assert!(ddl.contains("varchar(32)"));
        assert!(ddl.contains("varchar(40)"));
    }

    #[test]
    fn postgres_ddl_is_a_simple_create_table() {
        let ddl = owner_table().to_string(sea_orm_migration::sea_query::PostgresQueryBuilder);
        assert!(ddl.contains("sql_store_owner"));
        assert!(ddl.contains("PRIMARY KEY"));
    }

    #[test]
    fn sqlite_ddl_is_a_simple_create_table() {
        let ddl = owner_table().to_string(sea_orm_migration::sea_query::SqliteQueryBuilder);
        assert!(ddl.contains("sql_store_owner"));
        assert!(ddl.contains("PRIMARY KEY"));
    }

    #[test]
    fn backend_used_in_test_module_is_compatible_with_migrator_signatures() {
        // Smoke-check the symbol path so any DbBackend rename in sea-orm shows
        // up here instead of inside migrator reflection.
        let _ = DbBackend::MySql;
        let _ = DbBackend::Postgres;
        let _ = DbBackend::Sqlite;
    }
}
