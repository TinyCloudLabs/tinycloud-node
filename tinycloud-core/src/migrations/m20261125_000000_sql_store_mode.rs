//! Mode record: the `sql_store_mode` table that says, per SQL database,
//! whether Postgres or the SQL block store is master (TC-1491 P4.1, design
//! section 4, contract 4.6).
//!
//! One new, empty table. No foreign key, no index on any existing table, no
//! backfill: an absent row means `pg_master`, so the migration is inert.
//! Re-run is a no-op (IF NOT EXISTS). The primary key is `(space, db_id)`:
//! two `varchar(255)` are 2,040 bytes under utf8mb4, under MySQL's
//! 3,072-byte InnoDB key cap.
//!
//! `down` drops the table only while every row is `pg_master` or `shadow`
//! (both advisory: Postgres is master) at epoch 0. It refuses while any row
//! is in another mode, because then the row is the only record that the
//! store, not Postgres, holds the newest data (contract section 7). It also
//! refuses while any row has an epoch above 0, even a `pg_master` one after
//! a copy-back: dropping it would let the next insert restart that database
//! at epoch 0, and the epoch must never be reset. Rolling back past this
//! migration also needs `DELETE FROM seaql_migrations WHERE version =
//! 'm20261125_000000_sql_store_mode'`: older binaries refuse to start with
//! an applied migration they do not ship.
//!
//! TC-1491.

use sea_orm_migration::prelude::*;

use crate::models::sql_store_mode as mode;

/// The modes in which the row is advisory and `down` may drop it.
const ADVISORY_MODES: [&str; 2] = ["pg_master", "shadow"];

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(mode_table()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
        if manager.has_table("sql_store_mode").await? {
            let kept = mode::Entity::find()
                .filter(
                    Condition::any()
                        .add(mode::Column::Mode.is_not_in(ADVISORY_MODES))
                        .add(mode::Column::Epoch.gt(0)),
                )
                .one(manager.get_connection())
                .await?;
            if kept.is_some() {
                return Err(DbErr::Custom(
                    "sql_store_mode down is refused while a database is past shadow or has an epoch above 0: see the runbook".into(),
                ));
            }
        }
        manager
            .drop_table(Table::drop().table(mode::Entity).if_exists().to_owned())
            .await
    }
}

/// Public so tests can render the DDL for every backend.
pub fn mode_table() -> TableCreateStatement {
    use mode::Column as C;
    let text = |column, len| {
        let mut def = ColumnDef::new(column);
        def.string_len(len);
        def
    };
    let mut space = text(C::Space, 255);
    space.not_null();
    let mut db_id = text(C::DbId, 255);
    db_id.not_null();
    let mut mode_col = text(C::Mode, 16);
    mode_col.not_null();
    let mut epoch = ColumnDef::new(C::Epoch);
    epoch.big_integer().not_null();
    let mut owner_node = text(C::OwnerNode, 255);
    owner_node.null();
    let mut lease_holder = text(C::LeaseHolder, 255);
    lease_holder.null();
    let mut lease_expires_at = text(C::LeaseExpiresAt, 64);
    lease_expires_at.null();
    let mut changed_at = text(C::ModeChangedAt, 64);
    changed_at.not_null();
    let mut cutover_revision = ColumnDef::new(C::CutoverRevision);
    cutover_revision.big_integer().null();
    Table::create()
        .table(mode::Entity)
        .if_not_exists()
        .col(space)
        .col(db_id)
        .col(mode_col)
        .col(epoch)
        .col(owner_node)
        .col(lease_holder)
        .col(lease_expires_at)
        .col(changed_at)
        .col(cutover_revision)
        .primary_key(Index::create().col(C::Space).col(C::DbId))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::sql::store::mode::{transition_row, Expected, StoreMode};
    use crate::sql::store::DbRef;
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
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sql_store_mode'"
                .to_string(),
        ))
        .await
        .unwrap()
        .is_some()
    }

    const DB: DbRef<'static> = DbRef {
        space: "tinycloud:pkh:eip155:1:0xabc:default",
        db_id: "main",
    };

    #[tokio::test]
    async fn up_is_idempotent_and_down_drops_an_advisory_table() {
        let conn = sqlite().await;
        Migrator::up(&conn, None).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        assert!(table_exists(&conn).await);
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        // A shadow row is advisory: down still drops the table.
        transition_row(&conn, &DB, None, StoreMode::Shadow, None)
            .await
            .unwrap();
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        assert!(!table_exists(&conn).await);
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        assert!(table_exists(&conn).await);
    }

    #[tokio::test]
    async fn down_refuses_while_a_database_is_past_shadow() {
        let conn = sqlite().await;
        Migrator::up(&conn, None).await.unwrap();
        let epoch = transition_row(&conn, &DB, None, StoreMode::Shadow, None)
            .await
            .unwrap();
        let shadow = Expected {
            mode: StoreMode::Shadow,
            epoch,
        };
        transition_row(&conn, &DB, Some(shadow), StoreMode::CuttingOver, None)
            .await
            .unwrap();
        let err = Migration
            .down(&SchemaManager::new(&conn))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("sql_store_mode down is refused"),
            "{err}"
        );
        assert!(table_exists(&conn).await);
    }

    /// After a cutover and a copy-back the row is `pg_master` again but at
    /// epoch 1. Dropping it would restart the database at epoch 0.
    #[tokio::test]
    async fn down_refuses_a_pg_master_row_whose_epoch_moved() {
        use StoreMode::*;
        let conn = sqlite().await;
        Migrator::up(&conn, None).await.unwrap();
        let mut at = Expected {
            mode: Shadow,
            epoch: transition_row(&conn, &DB, None, Shadow, None)
                .await
                .unwrap(),
        };
        for (to, owner) in [
            (CuttingOver, None),
            (StoreMaster, Some("node-a")),
            (CopyingBack, None),
            (PgMaster, None),
        ] {
            let epoch = transition_row(&conn, &DB, Some(at), to, owner)
                .await
                .unwrap();
            at = Expected { mode: to, epoch };
        }
        assert_eq!(
            at,
            Expected {
                mode: PgMaster,
                epoch: 1
            }
        );
        let err = Migration
            .down(&SchemaManager::new(&conn))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("sql_store_mode down is refused"),
            "{err}"
        );
        assert!(table_exists(&conn).await);
    }

    #[test]
    fn mysql_ddl_keeps_the_key_under_the_innodb_cap() {
        let ddl = mode_table().to_string(sea_orm_migration::sea_query::MysqlQueryBuilder);
        assert!(ddl.contains("IF NOT EXISTS `sql_store_mode`"), "{ddl}");
        assert!(ddl.contains("`space` varchar(255) NOT NULL"), "{ddl}");
        assert!(ddl.contains("`db_id` varchar(255) NOT NULL"), "{ddl}");
        assert!(ddl.contains("`mode` varchar(16) NOT NULL"), "{ddl}");
        // 2 x varchar(255) x 4 bytes = 2,040 bytes <= 3,072.
        assert!(ddl.contains("PRIMARY KEY (`space`, `db_id`)"), "{ddl}");
        assert!(!ddl.contains("FOREIGN KEY"), "{ddl}");
    }

    #[test]
    fn postgres_and_sqlite_ddl_create_the_table_if_absent() {
        for ddl in [
            mode_table().to_string(sea_orm_migration::sea_query::PostgresQueryBuilder),
            mode_table().to_string(sea_orm_migration::sea_query::SqliteQueryBuilder),
        ] {
            assert!(ddl.contains("IF NOT EXISTS \"sql_store_mode\""), "{ddl}");
            assert!(ddl.contains("PRIMARY KEY (\"space\", \"db_id\")"), "{ddl}");
        }
    }
}
