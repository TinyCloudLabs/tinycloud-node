use sea_orm_migration::prelude::*;

/// TC-3443: sign-out retires a session key.
///
/// `delegation.first_seen_at` is when this node first stored a delegation.
/// It is NULL for rows stored before this migration, which count as seen
/// before any retire. `session_retire` holds each retired session key until
/// `expires_at`, after which the row is ignored and pruned.
///
/// `up` is idempotent (TC-3755). Each step skips what already exists, so a
/// node can migrate again after this migration's `seaql_migrations` row was
/// deleted with its schema left in place. That is the deregister-only
/// rollback to 1.26.17: an operator role can't drop these tables, because
/// they are owned by the node's own database role.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Delegation {
    Table,
    FirstSeenAt,
}

#[derive(DeriveIden)]
enum SessionRetire {
    Table,
    Did,
    RetiredAt,
    ExpiresAt,
}

const EXPIRES_AT_INDEX: &str = "idx_session_retire_expires_at";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("delegation", "first_seen_at").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Delegation::Table)
                        .add_column(
                            ColumnDef::new(Delegation::FirstSeenAt)
                                .timestamp_with_time_zone()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        manager
            .create_table(
                Table::create()
                    .table(SessionRetire::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SessionRetire::Did)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SessionRetire::RetiredAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SessionRetire::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        if manager
            .has_index("session_retire", EXPIRES_AT_INDEX)
            .await?
        {
            return Ok(());
        }
        manager
            .create_index(
                Index::create()
                    .name(EXPIRES_AT_INDEX)
                    .table(SessionRetire::Table)
                    .col(SessionRetire::ExpiresAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SessionRetire::Table).to_owned())
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Delegation::Table)
                    .drop_column(Delegation::FirstSeenAt)
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::migrations::Migrator;
    use sea_orm::{
        ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement, TransactionTrait,
    };
    use sea_orm_migration::{MigrationName, MigratorTrait};

    async fn columns(db: &DatabaseConnection, table: &str) -> Vec<String> {
        let sql = match db.get_database_backend() {
            DbBackend::Postgres => format!(
                "SELECT column_name AS name FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = '{table}'"
            ),
            _ => format!("SELECT name FROM pragma_table_info('{table}')"),
        };
        db.query_all(Statement::from_string(db.get_database_backend(), sql))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "name").unwrap())
            .collect()
    }

    async fn assert_applied(db: &DatabaseConnection, applied: bool) {
        assert_eq!(
            columns(db, "delegation")
                .await
                .contains(&"first_seen_at".to_owned()),
            applied
        );
        let mut retire = columns(db, "session_retire").await;
        retire.sort();
        let expected: Vec<String> = if applied {
            vec!["did".into(), "expires_at".into(), "retired_at".into()]
        } else {
            Vec::new()
        };
        assert_eq!(retire, expected);
    }

    /// Up, down, then up again: `down` removes the column and the table, and
    /// a second `up` restores both. Rows in `session_retire` round-trip.
    async fn assert_up_down_up(db: &DatabaseConnection, forward_only_tail: usize) {
        let backend = db.get_database_backend();
        assert_applied(db, true).await;
        let insert = "INSERT INTO session_retire (did, retired_at, expires_at) \
             VALUES ('did:key:z6Mkretired', '2026-11-21T00:00:00Z', '2026-12-21T00:00:00Z')";
        db.execute(Statement::from_string(backend, insert))
            .await
            .unwrap();

        // test-ruling: TC-1491 m20261121_000000_session_retire.rs
        // assert_up_down_up rolls back every migration from
        // m20261121_000000_session_retire onward (count computed from
        // Migrator::migrations()) instead of a fixed 1; its applied/
        // unapplied assertions stay unchanged (2026-11-21).
        let steps = Migrator::migrations()
            .iter()
            .rev()
            .position(|m| m.name() == super::Migration.name())
            .map(|i| (i + 1 - forward_only_tail) as u32)
            .expect("session_retire migration is registered");
        Migrator::down(db, Some(steps)).await.unwrap();
        assert_applied(db, false).await;

        Migrator::up(db, None).await.unwrap();
        assert_applied(db, true).await;
        // The table was dropped with its rows, and takes new ones.
        let txn = db.begin().await.unwrap();
        assert_eq!(count(&txn).await, 0);
        txn.execute(Statement::from_string(backend, insert))
            .await
            .unwrap();
        assert_eq!(count(&txn).await, 1);
        txn.rollback().await.unwrap();
    }

    async fn count(txn: &sea_orm::DatabaseTransaction) -> i64 {
        txn.query_one(Statement::from_string(
            txn.get_database_backend(),
            "SELECT COUNT(*) AS n FROM session_retire",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
    }

    #[tokio::test]
    async fn sqlite_session_retire_up_down_up() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_up_down_up(&db, 0).await;
    }

    #[tokio::test]
    async fn postgres_session_retire_up_down_up() {
        // The last two migrations (m20261113_020000_artifact_chunk_wal,
        // m20261113_030000_artifact_part_lifecycle) are forward-only on
        // PostgreSQL: `down` refuses them. The schema is migrated without
        // them, so the roll-back covers only what is applied after
        // session_retire, and `assert_up_down_up`'s final `up` applies them.
        // The next migration that is forward-only on PostgreSQL and listed
        // after session_retire must raise this count (TC-2917).
        const FORWARD_ONLY_TAIL: usize = 2;
        let Some(fixture) = crate::test_support::PostgresTestSchema::migrated_through(
            "postgres_session_retire_up_down_up",
            Some((Migrator::migrations().len() - FORWARD_ONLY_TAIL) as u32),
        )
        .await
        else {
            return;
        };
        assert_up_down_up(&fixture.conn, FORWARD_ONLY_TAIL).await;
    }

    // test-ruling: TC-3755 new tests only (Naomi GO 2026-11-22 04:23Z);
    // the existing tests above are unchanged.
    /// Deregister-only rollback, then forward again. Deleting the 1.26.18
    /// migrations' `seaql_migrations` rows leaves their schema and rows in
    /// place, and is what lets 1.26.17 boot. Running `up` a second time must
    /// then succeed and keep the retired sessions.
    async fn assert_up_again_after_deregister(db: &DatabaseConnection) {
        let backend = db.get_database_backend();
        assert_applied(db, true).await;
        for sql in [
            "INSERT INTO session_retire (did, retired_at, expires_at) \
             VALUES ('did:key:z6Mkretired', '2026-11-21T00:00:00Z', '2026-12-21T00:00:00Z')",
            "DELETE FROM seaql_migrations WHERE version IN \
             ('m20261121_000000_session_retire', 'm20261122_000000_sql_store_owner')",
        ] {
            db.execute(Statement::from_string(backend, sql))
                .await
                .unwrap();
        }
        assert_eq!(registered(db).await, 0);

        Migrator::up(db, None).await.unwrap();

        assert_eq!(registered(db).await, 2);
        assert_applied(db, true).await;
        let txn = db.begin().await.unwrap();
        assert_eq!(count(&txn).await, 1, "retired sessions survive");
        txn.rollback().await.unwrap();
    }

    async fn registered(db: &DatabaseConnection) -> i64 {
        db.query_one(Statement::from_string(
            db.get_database_backend(),
            "SELECT COUNT(*) AS n FROM seaql_migrations WHERE version IN \
             ('m20261121_000000_session_retire', 'm20261122_000000_sql_store_owner')",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
    }

    #[tokio::test]
    async fn sqlite_session_retire_up_again_after_deregister() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_up_again_after_deregister(&db).await;
    }

    #[tokio::test]
    async fn postgres_session_retire_up_again_after_deregister() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_session_retire_up_again_after_deregister",
        )
        .await
        else {
            return;
        };
        assert_up_again_after_deregister(&fixture.conn).await;
    }
}
