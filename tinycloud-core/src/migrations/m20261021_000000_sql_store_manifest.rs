//! TC-1491: `sql_store_manifest` and `sql_store_object`, the advisory
//! bookkeeping of the SQL block-store shadow upload.
//!
//! Only two empty tables. No foreign keys, no index on any existing table, no
//! backfill: nothing here locks or scans a populated table inside the boot
//! transaction. Tables are created whether or not `[sql_store]` is enabled; with
//! it off nothing reads or writes them.
//!
//! MySQL: `.string()` is `varchar(255)` and an InnoDB key is capped at 3072
//! bytes, so the object key's fields are bounded columns and the full key is a
//! `text` column outside every index. The widest primary key is 2,512 bytes
//! under utf8mb4.
//!
//! `down` drops both tables. That is only safe while the manifest is advisory
//! (shadow phase); it must be made to refuse before any database becomes
//! store-master.

use sea_orm_migration::prelude::*;

use crate::models::{sql_store_manifest as manifest, sql_store_object as object};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(manifest_table()).await?;
        manager.create_table(object_table()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(object::Entity).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(manifest::Entity).if_exists().to_owned())
            .await
    }
}

fn str_col<T: IntoIden>(name: T, len: u32) -> ColumnDef {
    let mut col = ColumnDef::new(name);
    col.string_len(len).not_null();
    col
}

fn int_col<T: IntoIden>(name: T) -> ColumnDef {
    let mut col = ColumnDef::new(name);
    col.big_integer().not_null();
    col
}

fn text_col<T: IntoIden>(name: T) -> ColumnDef {
    let mut col = ColumnDef::new(name);
    col.text().not_null();
    col
}

/// Public so tests can render the DDL for every backend.
pub fn manifest_table() -> TableCreateStatement {
    use manifest::Column as C;
    Table::create()
        .table(manifest::Entity)
        .if_not_exists()
        .col(str_col(C::Space, 255))
        .col(str_col(C::DbId, 255))
        .col(str_col(C::Lineage, 32))
        .col(int_col(C::Epoch))
        .col(int_col(C::Revision))
        .col(text_col(C::BaseSnapshotKey))
        .col(int_col(C::BaseSeq))
        .col(str_col(C::BaseCheckpointCid, 255))
        .col(int_col(C::LastSeq))
        .col(str_col(C::PublishId, 32))
        .col(str_col(C::PublishedAt, 64))
        .col(int_col(C::FrontierBytes))
        .primary_key(Index::create().col(C::Space).col(C::DbId))
        .to_owned()
}

pub fn object_table() -> TableCreateStatement {
    use object::Column as C;
    Table::create()
        .table(object::Entity)
        .if_not_exists()
        .col(str_col(C::Space, 255))
        .col(str_col(C::DbId, 255))
        .col(str_col(C::Lineage, 32))
        .col(str_col(C::Kind, 16))
        .col(int_col(C::BaseSeq))
        .col(int_col(C::FromSeq))
        .col(int_col(C::ToSeq))
        .col(str_col(C::ContentHash, 64))
        .col(str_col(C::Format, 16))
        .col(text_col(C::Key))
        .col(int_col(C::Bytes))
        .col(str_col(C::State, 16))
        .col(str_col(C::CreatedAt, 64))
        .primary_key(
            Index::create()
                .col(C::Space)
                .col(C::DbId)
                .col(C::Lineage)
                .col(C::Kind)
                .col(C::BaseSeq)
                .col(C::FromSeq)
                .col(C::ToSeq)
                .col(C::ContentHash),
        )
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::test_support::PostgresTestSchema;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
    use sea_orm_migration::MigratorTrait;

    const VERSION: &str = "m20261021_000000_sql_store_manifest";

    async fn sqlite() -> sea_orm::DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        Database::connect(options).await.unwrap()
    }

    async fn table_exists(
        conn: &sea_orm::DatabaseConnection,
        backend: DbBackend,
        name: &str,
    ) -> bool {
        let sql = match backend {
            DbBackend::Sqlite => format!("SELECT name FROM sqlite_master WHERE type='table' AND name='{name}'"),
            _ => format!("SELECT table_name FROM information_schema.tables WHERE table_name='{name}' AND table_schema = current_schema()"),
        };
        !conn
            .query_all(Statement::from_string(backend, sql))
            .await
            .unwrap()
            .is_empty()
    }

    async fn recorded(conn: &sea_orm::DatabaseConnection, backend: DbBackend) -> bool {
        !conn
            .query_all(Statement::from_string(
                backend,
                format!("SELECT version FROM seaql_migrations WHERE version = '{VERSION}'"),
            ))
            .await
            .unwrap()
            .is_empty()
    }

    async fn up_down_cycle(conn: sea_orm::DatabaseConnection, backend: DbBackend) {
        Migrator::up(&conn, None).await.unwrap();
        assert!(recorded(&conn, backend).await);
        for table in ["sql_store_manifest", "sql_store_object"] {
            assert!(table_exists(&conn, backend, table).await, "{table}");
        }
        // Re-run is a no-op.
        Migrator::up(&conn, None).await.unwrap();
        // The migration itself is idempotent on existing tables (an operator
        // pre-created them, or the version row was deleted for a downgrade).
        conn.execute(Statement::from_string(
            backend,
            format!("DELETE FROM seaql_migrations WHERE version = '{VERSION}'"),
        ))
        .await
        .unwrap();
        assert!(!recorded(&conn, backend).await);
        Migrator::up(&conn, None).await.unwrap();
        assert!(recorded(&conn, backend).await);
        // Rows survive a re-run.
        conn.execute(Statement::from_string(
            backend,
            "INSERT INTO sql_store_manifest VALUES ('s','d','l',0,0,'k',0,'c',0,'p','t',0)"
                .to_string(),
        ))
        .await
        .unwrap();
        conn.execute(Statement::from_string(
            backend,
            format!("DELETE FROM seaql_migrations WHERE version = '{VERSION}'"),
        ))
        .await
        .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let rows = conn
            .query_all(Statement::from_string(
                backend,
                "SELECT space FROM sql_store_manifest".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        // down drops both; up recreates them.
        Migrator::down(&conn, Some(1)).await.unwrap();
        for table in ["sql_store_manifest", "sql_store_object"] {
            assert!(!table_exists(&conn, backend, table).await, "{table}");
        }
        Migrator::up(&conn, None).await.unwrap();
        assert!(table_exists(&conn, backend, "sql_store_object").await);
    }

    #[tokio::test]
    async fn sqlite_fresh_rerun_and_down() {
        up_down_cycle(sqlite().await, DbBackend::Sqlite).await;
    }

    #[tokio::test]
    async fn sqlite_upgrade_from_the_previous_release_line() {
        let conn = sqlite().await;
        let before = (Migrator::migrations().len() - 1) as u32;
        Migrator::up(&conn, Some(before)).await.unwrap();
        assert!(!table_exists(&conn, DbBackend::Sqlite, "sql_store_manifest").await);
        Migrator::up(&conn, None).await.unwrap();
        assert!(table_exists(&conn, DbBackend::Sqlite, "sql_store_manifest").await);
        assert!(Migrator::migrations()
            .last()
            .is_some_and(|m| m.name() == VERSION));
    }

    #[tokio::test]
    async fn postgres_fresh_rerun_and_down() {
        let Some(fixture) = PostgresTestSchema::migrated_through(
            "postgres_sql_store_migration",
            Some((Migrator::migrations().len() - 1) as u32),
        )
        .await
        else {
            return;
        };
        up_down_cycle(fixture.connect(2).await, DbBackend::Postgres).await;
    }

    /// MySQL has no test harness in this repo, so assert the DDL sea-query
    /// emits for it: bounded `varchar`/`bigint` primary-key columns, `text`
    /// for the unindexed key, and a key width within InnoDB's 3072 bytes.
    #[test]
    fn mysql_ddl_fits_innodb_key_limits() {
        use sea_orm::sea_query::MysqlQueryBuilder;
        let manifest = manifest_table().to_string(MysqlQueryBuilder);
        let object = object_table().to_string(MysqlQueryBuilder);
        for ddl in [&manifest, &object] {
            assert!(ddl.starts_with("CREATE TABLE IF NOT EXISTS"), "{ddl}");
            assert!(!ddl.contains("FOREIGN KEY"), "{ddl}");
        }
        assert!(
            manifest.contains("`base_snapshot_key` text NOT NULL"),
            "{manifest}"
        );
        assert!(object.contains("`key` text NOT NULL"), "{object}");
        assert!(object.contains("`space` varchar(255) NOT NULL"), "{object}");
        assert!(
            object.contains("`content_hash` varchar(64) NOT NULL"),
            "{object}"
        );

        // Sum the widths of the primary-key columns (utf8mb4: 4 bytes/char,
        // bigint: 8) from the generated statement itself.
        fn pk_bytes(ddl: &str) -> usize {
            let pk = ddl
                .split("PRIMARY KEY (")
                .nth(1)
                .and_then(|rest| rest.split(')').next())
                .expect("a primary key");
            pk.split(',')
                .map(|col| {
                    let name = col.trim().trim_matches('`');
                    let def = ddl
                        .split(&format!("`{name}` "))
                        .nth(1)
                        .expect("pk column defined")
                        .split(',')
                        .next()
                        .unwrap();
                    if let Some(len) = def.strip_prefix("varchar(") {
                        len.split(')').next().unwrap().parse::<usize>().unwrap() * 4
                    } else if def.starts_with("bigint") {
                        8
                    } else {
                        panic!("unbounded primary-key column {name}: {def}");
                    }
                })
                .sum()
        }
        assert_eq!(pk_bytes(&object), 2512, "{object}");
        assert!(pk_bytes(&object) <= 3072);
        assert!(pk_bytes(&manifest) <= 3072);
    }
}
