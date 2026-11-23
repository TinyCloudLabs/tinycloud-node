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

    /// Refusing down when the identity fence is populated.
    ///
    /// The owner row is the SQL block store's identity fence. Dropping it
    /// alongside a retained `sql/v1/_owner/v1` object in the bucket would
    /// let a later boot re-pair against a brand-new, randomly-minted store
    /// ID and claim the namespace. Operators who truly want to walk this
    /// back must either prefix-delete `sql/v1/_owner/v1` with written
    /// authorization (the runbook) or restore the control-DB row from
    /// backup; neither is something a blind migrator rollback should do.
    ///
    /// An empty table has no identity to protect, so an empty-table down
    /// drops the table normally. This lets a global `Migrator::down()`
    /// sweep on an unenabled node succeed (there is no fence yet to break),
    /// which keeps CI sweeps happy and matches the actual security
    /// concern.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use crate::models::sql_store_owner as owner;
        use sea_orm::EntityTrait;
        let conn = manager.get_connection();
        let rows = owner::Entity::find().all(conn).await?;
        if !rows.is_empty() {
            return Err(DbErr::Custom(
                "sql_store_owner down is refused while the identity fence is populated: see the runbook".into(),
            ));
        }
        manager
            .drop_table(Table::drop().table(owner::Entity).if_exists().to_owned())
            .await
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
    use sea_orm::{ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn down_on_empty_table_drops_normally() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        // No owner row written: down drops the table so a global
        // Migrator::down sweep succeeds on an unenabled node.
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
    }

    #[tokio::test]
    async fn down_refuses_while_fence_is_populated() {
        use crate::sql::store::shadow::owner::{insert_or_load_owner_row, StoreId};
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        // Establish the identity fence.
        insert_or_load_owner_row(&conn, &StoreId::random())
            .await
            .unwrap();
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
}
