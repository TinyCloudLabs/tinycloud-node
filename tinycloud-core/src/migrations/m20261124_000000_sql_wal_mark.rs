//! WAL marks: the `sql_wal_mark` table the SQL block store's incremental WAL
//! objects (`wal-delta-v1`) are carved with (contract 4.5).
//!
//! One new, empty table. No foreign key, no index on any existing table, no
//! backfill: databases saved before this migration have no marks, and the
//! uploader keeps publishing cumulative `wal-cum-v1` segments for them until
//! their next `save_delta` writes one. Re-run is a no-op (IF NOT EXISTS).
//!
//! The primary key is `(service, space, name, revision)`: three
//! `varchar(255)` plus a `bigint` is 3,068 bytes under utf8mb4, under
//! MySQL's 3,072-byte InnoDB key cap (the `database_artifact` key is the
//! first three of them).
//!
//! `down` drops the table. Marks are derived data: without them the uploader
//! falls back to cumulative segments.
//!
//! TC-1491.

use sea_orm_migration::prelude::*;

use crate::models::sql_wal_mark as mark;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(mark_table()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(mark::Entity).if_exists().to_owned())
            .await
    }
}

/// Public so tests can render the DDL for every backend.
pub fn mark_table() -> TableCreateStatement {
    use mark::Column as C;
    let key = |column| {
        let mut def = ColumnDef::new(column);
        def.string_len(255).not_null();
        def
    };
    let mut revision = ColumnDef::new(C::Revision);
    revision.big_integer().not_null();
    let mut cid = ColumnDef::new(C::CheckpointContentHash);
    cid.string_len(255).not_null();
    let mut wal_end = ColumnDef::new(C::WalEndBytes);
    wal_end.big_integer().not_null();
    let mut prefix = ColumnDef::new(C::WalPrefixSha256);
    prefix.string_len(64).not_null();
    Table::create()
        .table(mark::Entity)
        .if_not_exists()
        .col(key(C::Service))
        .col(key(C::Space))
        .col(key(C::Name))
        .col(revision)
        .col(cid)
        .col(wal_end)
        .col(prefix)
        .primary_key(
            Index::create()
                .col(C::Service)
                .col(C::Space)
                .col(C::Name)
                .col(C::Revision),
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

    async fn table_exists(conn: &sea_orm::DatabaseConnection) -> bool {
        conn.query_one(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sql_wal_mark'"
                .to_string(),
        ))
        .await
        .unwrap()
        .is_some()
    }

    #[tokio::test]
    async fn up_is_idempotent_and_down_drops_the_table() {
        let conn = sqlite().await;
        Migrator::up(&conn, None).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        assert!(table_exists(&conn).await);
        // A second `up` of this migration alone is a no-op (IF NOT EXISTS).
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        assert!(!table_exists(&conn).await);
        // Down is idempotent too (IF EXISTS), and up recreates the table.
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        assert!(table_exists(&conn).await);
    }

    #[test]
    fn mysql_ddl_keeps_the_key_under_the_innodb_cap() {
        let ddl = mark_table().to_string(sea_orm_migration::sea_query::MysqlQueryBuilder);
        assert!(ddl.contains("IF NOT EXISTS `sql_wal_mark`"), "{ddl}");
        // 3 x varchar(255) x 4 bytes + one bigint = 3,068 bytes <= 3,072.
        assert_eq!(ddl.matches("varchar(255)").count(), 4, "{ddl}");
        assert!(ddl.contains("varchar(64)"), "{ddl}");
        assert!(
            ddl.contains("PRIMARY KEY (`service`, `space`, `name`, `revision`)"),
            "{ddl}"
        );
    }

    #[test]
    fn postgres_and_sqlite_ddl_create_the_table_if_absent() {
        for ddl in [
            mark_table().to_string(sea_orm_migration::sea_query::PostgresQueryBuilder),
            mark_table().to_string(sea_orm_migration::sea_query::SqliteQueryBuilder),
        ] {
            assert!(ddl.contains("IF NOT EXISTS \"sql_wal_mark\""), "{ddl}");
            assert!(ddl.contains("PRIMARY KEY"), "{ddl}");
        }
    }
}
