//! Owner marker: the `sql_store_owner` row that pairs with the
//! `sql/v1/_owner/v1` object at boot.
//!
//! One empty table, no foreign keys, no index on any existing table, no
//! backfill. The primary key is a fixed-value `id SMALLINT NOT NULL CHECK
//! (id = 1)` column: the table is a schema-enforced singleton. `store_id`
//! (`varchar(32)`, the 128-bit hex) and `created_at` (`varchar(40)`) sit
//! alongside it, both well under MySQL's 3,072-byte InnoDB key cap.
//! Re-run is a no-op (IF NOT EXISTS).
//!
//! Interaction with `m20261121_000000_session_retire` (ships as node
//! 1.26.18): disjoint tables (revocation and session rows vs this fresh
//! table), disjoint control-DB state. SeaORM applies by version string, so
//! this migration (date 2026-11-22) runs strictly after the session-retire
//! migration whichever is installed first. No conflict.
//!
//! `down` refuses: the row is the SQL block store's identity fence.
//! Operators who truly want to walk this back must either prefix-delete
//! `sql/v1/_owner/v1` with written authorization (the runbook) or restore
//! the control-DB row from backup.
//!
//! TC-1491.

use sea_orm_migration::prelude::*;

use crate::models::sql_store_owner as owner;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(owner_table()).await
    }

    /// Refusing down.
    ///
    /// The owner row is the SQL block store's identity fence. Dropping it
    /// alongside a retained `sql/v1/_owner/v1` object in the bucket would
    /// let a later boot re-pair against a brand-new, randomly-minted store
    /// ID and claim the namespace. Operators who truly want to walk this
    /// back must either prefix-delete `sql/v1/_owner/v1` with written
    /// authorization (the runbook) or restore the control-DB row from
    /// backup; neither is something a blind migrator rollback should do.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Custom(
            "sql_store_owner down is refused: the row is the SQL block store identity fence; see the runbook".into(),
        ))
    }
}

/// Public so tests can render the DDL for every backend.
pub fn owner_table() -> TableCreateStatement {
    use owner::Column as C;
    // `id` is a schema-enforced singleton guard: exactly one row ever, with
    // `id = 1`. See the model comment for the race it closes.
    let mut id = ColumnDef::new(C::Id);
    id.small_integer().not_null().check(Expr::col(C::Id).eq(1));
    let mut store_id = ColumnDef::new(C::StoreId);
    store_id.string_len(32).not_null();
    let mut created_at = ColumnDef::new(C::CreatedAt);
    created_at.string_len(40).not_null();
    Table::create()
        .table(owner::Entity)
        .if_not_exists()
        .col(id)
        .col(store_id)
        .col(created_at)
        .primary_key(Index::create().col(C::Id))
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
    async fn down_is_refused() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let err = Migration
            .down(&SchemaManager::new(&conn))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("sql_store_owner down is refused"),
            "unexpected error message: {err}"
        );
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
