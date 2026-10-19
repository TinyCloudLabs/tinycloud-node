//! TC-1274: `current_kv (space, deleted, (key COLLATE "C"))` for the KV list
//! range select. `kv_prefix_condition` compares `key COLLATE "C"` so prefix
//! membership is byte order whatever the column's collation is, and
//! `idx_current_kv_space_deleted_key` is built in the column's own collation.
//! On a database whose collation is not `C` (production's is `en_US.UTF-8`)
//! the key bounds therefore cannot be index conditions: the scan reads every
//! live key of the space and filters. This index matches the `COLLATE "C"`
//! expression, so the planner seeks on the bounds. The old index stays for
//! point lookups. No query changes: the planner matches the expression.
//!
//! **The index is performance-only.** The node boots and serves without it
//! (KV lists are slower), so this migration never locks `current_kv` for a
//! build and never fails boot because the index is missing or broken. On
//! PostgreSQL, `up` reads `pg_index` for the index's exact name and:
//!
//! 1. valid, ready and live, with the right shape: does nothing;
//! 2. missing and `current_kv` empty (a fresh or test database): creates it,
//!    which is instant on an empty table;
//! 3. missing and `current_kv` not empty: does **not** create it (a plain
//!    `CREATE INDEX` takes a SHARE lock that blocks every KV write until the
//!    boot transaction ends) and logs `current_kv_c_index_missing`;
//! 4. right shape but invalid, not ready or not live (a failed or running
//!    `CREATE INDEX CONCURRENTLY`): logs `current_kv_c_index_invalid`;
//! 5. this name with another shape (or not an index on `current_kv`): logs
//!    `current_kv_c_index_wrong_shape` at error level.
//!
//! In every case the migration is recorded as applied, so an index an operator
//! builds later is simply used by the planner. Operators build it online
//! before deploy, outside any transaction, with the statement and recovery
//! steps in `docs/releasing.md`. The warnings are constant text: production
//! logs are public (TC-961), so no key, space or value is ever logged.
//!
//! SQLite and MySQL: nothing to do. SQLite's `BINARY` collation is byte order,
//! so `idx_current_kv_space_deleted_key` already seeks on the bounds. MySQL has
//! no `COLLATE "C"` to match; the migration leaves it as it is.

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX: &str = "idx_current_kv_space_deleted_key_c";
const DEFINITION: &str = r#"(space, deleted, (key COLLATE "C"))"#;

/// Longest the build on an empty table waits for a lock. The migration
/// transaction's own `lock_timeout` is 30 s; a `CREATE INDEX` that waits queues
/// every later KV writer behind it, so this is kept short and a timeout skips
/// the index instead of failing boot.
const CREATE_LOCK_TIMEOUT: &str = "2s";

const EVENT_MISSING: &str = "current_kv_c_index_missing";
const EVENT_INVALID: &str = "current_kv_c_index_invalid";
const EVENT_WRONG_SHAPE: &str = "current_kv_c_index_wrong_shape";

const MISSING_MESSAGE: &str = "idx_current_kv_space_deleted_key_c is missing; the node keeps \
serving and KV list requests are slower until an operator builds it with CREATE INDEX CONCURRENTLY \
(docs/releasing.md, section idx_current_kv_space_deleted_key_c)";
const INVALID_MESSAGE: &str = "idx_current_kv_space_deleted_key_c is invalid or still being \
built; the node keeps serving and KV list requests are slower. If no CREATE INDEX CONCURRENTLY is \
running, run DROP INDEX CONCURRENTLY idx_current_kv_space_deleted_key_c; and then the CREATE INDEX \
CONCURRENTLY in docs/releasing.md, section idx_current_kv_space_deleted_key_c";
const WRONG_SHAPE_MESSAGE: &str = "idx_current_kv_space_deleted_key_c exists with the wrong \
definition and is not used for KV lists; the node keeps serving and KV list requests are slower. \
Run DROP INDEX CONCURRENTLY idx_current_kv_space_deleted_key_c; and then the CREATE INDEX \
CONCURRENTLY in docs/releasing.md, section idx_current_kv_space_deleted_key_c";

/// The DDL `up` runs when the index is absent and `current_kv` is empty
/// (PostgreSQL only).
fn create_index_sql() -> String {
    format!("CREATE INDEX IF NOT EXISTS {INDEX} ON current_kv {DEFINITION}")
}

/// The statement an operator runs, in autocommit, before the node deploy.
#[cfg(test)]
fn operator_create_index_sql() -> String {
    format!("CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX} ON current_kv {DEFINITION}")
}

/// What the current schema holds under [`INDEX`]'s name.
#[derive(Debug, PartialEq, Eq)]
enum IndexState {
    /// No relation has that name.
    Missing,
    /// A valid, ready and live plain btree index of the right shape.
    Valid,
    /// The right shape, but not valid, ready and live.
    Invalid,
    /// Anything else with that name.
    WrongShape,
}

/// Classify [`INDEX`] on PostgreSQL.
///
/// PostgreSQL stores `(key COLLATE "C")` on a bare column not as an index
/// expression but as the column `key` with the `C` collation of `pg_catalog`
/// recorded in `indcollation`, so that is the shape checked: columns
/// `space, deleted, key`, the third in collation `pg_catalog.C`, default
/// operator classes, ascending, the first two columns in their own columns'
/// collations (a query compares `space` in the column's collation, so an
/// index in another one cannot serve `space = $1`), no expressions, predicate or included
/// columns. An index on `key` in the database collation (the existing
/// `idx_current_kv_space_deleted_key`), on `COLLATE "POSIX"`, on another
/// expression, with a predicate, or with extra columns is not this index, and
/// the planner cannot use it for the byte-order bounds.
async fn postgres_index_state(manager: &SchemaManager<'_>) -> Result<IndexState, DbErr> {
    let row = manager
        .get_connection()
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT c.relkind::text AS kind,
                    COALESCE(i.indrelid = 'current_kv'::regclass, false) AS on_table,
                    COALESCE(i.indisvalid AND i.indisready AND i.indislive, false) AS usable,
                    am.amname::text AS method,
                    i.indpred IS NULL AND i.indexprs IS NULL
                        AND i.indnatts = i.indnkeyatts AS plain,
                    array_to_string(ARRAY(
                        SELECT a.attname::text
                        FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                        LEFT JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                        ORDER BY k.ord), ',') AS columns,
                    (SELECT n.nspname::text || '.' || co.collname::text
                     FROM unnest(i.indcollation::oid[]) WITH ORDINALITY AS k(coll, ord)
                     JOIN pg_collation co ON co.oid = k.coll
                     JOIN pg_namespace n ON n.oid = co.collnamespace
                     WHERE k.ord = 3) AS key_collation,
                    COALESCE((SELECT bool_and(oc.opcdefault)
                              FROM unnest(i.indclass::oid[]) AS k(opclass)
                              JOIN pg_opclass oc ON oc.oid = k.opclass), false) AS default_opclasses,
                    array_to_string(i.indoption::int2[], ',') AS options,
                    COALESCE((SELECT bool_and(k.coll = a.attcollation)
                              FROM unnest(i.indcollation::oid[]) WITH ORDINALITY AS k(coll, ord)
                              JOIN unnest(i.indkey::int2[]) WITH ORDINALITY AS kk(attnum, ord)
                                ON kk.ord = k.ord
                              JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = kk.attnum
                              WHERE k.ord IN (1, 2)), false) AS lead_collations_match_the_columns
             FROM pg_class c
             LEFT JOIN pg_index i ON i.indexrelid = c.oid
             LEFT JOIN pg_am am ON am.oid = c.relam
             WHERE c.relname = $1
               AND c.relnamespace = (SELECT relnamespace FROM pg_class
                                     WHERE oid = 'current_kv'::regclass)",
            [INDEX.into()],
        ))
        .await?;
    let Some(row) = row else {
        return Ok(IndexState::Missing);
    };
    let kind: String = row.try_get("", "kind")?;
    let on_table: bool = row.try_get("", "on_table")?;
    let usable: bool = row.try_get("", "usable")?;
    let method: Option<String> = row.try_get("", "method")?;
    let plain: Option<bool> = row.try_get("", "plain")?;
    let columns: Option<String> = row.try_get("", "columns")?;
    let key_collation: Option<String> = row.try_get("", "key_collation")?;
    let default_opclasses: bool = row.try_get("", "default_opclasses")?;
    let options: Option<String> = row.try_get("", "options")?;
    let lead_collations_match_the_columns: bool =
        row.try_get("", "lead_collations_match_the_columns")?;
    let shaped = kind == "i"
        && on_table
        && method.as_deref() == Some("btree")
        && plain == Some(true)
        && columns.as_deref() == Some("space,deleted,key")
        && key_collation.as_deref() == Some("pg_catalog.C")
        && default_opclasses
        && options.as_deref() == Some("0,0,0")
        && lead_collations_match_the_columns;
    Ok(match (shaped, usable) {
        (true, true) => IndexState::Valid,
        (true, false) => IndexState::Invalid,
        (false, _) => IndexState::WrongShape,
    })
}

/// Whether `current_kv` has any row. An `EXISTS` probe stops at the first
/// row and takes only an ACCESS SHARE lock, which no writer conflicts with.
async fn current_kv_is_empty(manager: &SchemaManager<'_>) -> Result<bool, DbErr> {
    let row = manager
        .get_connection()
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            "SELECT EXISTS (SELECT 1 FROM current_kv) AS present".to_string(),
        ))
        .await?
        .ok_or_else(|| DbErr::Migration("current_kv probe returned no row".to_string()))?;
    Ok(!row.try_get::<bool>("", "present")?)
}

/// Build the index on the empty `current_kv`. The build runs in a savepoint
/// with a short `lock_timeout`, so a writer that appears between the probe and
/// the build, or a role that may not create indexes on the table, leaves the
/// transaction usable: `Ok(false)` means "skipped", never a failed boot.
async fn try_create_on_empty_table(manager: &SchemaManager<'_>) -> Result<bool, DbErr> {
    const SAVEPOINT: &str = "current_kv_c_index";
    let conn = manager.get_connection();
    let outer_timeout: String = conn
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            "SELECT current_setting('lock_timeout') AS value".to_string(),
        ))
        .await?
        .ok_or_else(|| DbErr::Migration("lock_timeout probe returned no row".to_string()))?
        .try_get("", "value")?;
    conn.execute_unprepared(&format!("SAVEPOINT {SAVEPOINT}"))
        .await?;
    let built = async {
        conn.execute_unprepared(&format!("SET LOCAL lock_timeout = '{CREATE_LOCK_TIMEOUT}'"))
            .await?;
        conn.execute_unprepared(&create_index_sql()).await
    }
    .await;
    if built.is_err() {
        conn.execute_unprepared(&format!("ROLLBACK TO SAVEPOINT {SAVEPOINT}"))
            .await?;
    }
    conn.execute_unprepared(&format!("RELEASE SAVEPOINT {SAVEPOINT}"))
        .await?;
    if built.is_ok() {
        // `SET LOCAL` outlives the released savepoint: give the migration
        // transaction its own timeout back.
        conn.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT set_config('lock_timeout', $1, true)",
            [outer_timeout.into()],
        ))
        .await?;
    }
    Ok(built.is_ok())
}

/// Why the index was not built: constant values only.
const REASON_TABLE_NOT_EMPTY: &str = "table_not_empty";
const REASON_BUILD_FAILED: &str = "build_failed";

fn warn_missing(reason: &'static str) {
    tracing::warn!(
        event = EVENT_MISSING,
        index = INDEX,
        reason,
        "{MISSING_MESSAGE}"
    );
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        match postgres_index_state(manager).await? {
            IndexState::Valid => {}
            IndexState::Invalid => {
                tracing::warn!(event = EVENT_INVALID, index = INDEX, "{INVALID_MESSAGE}");
            }
            IndexState::WrongShape => {
                tracing::error!(
                    event = EVENT_WRONG_SHAPE,
                    index = INDEX,
                    "{WRONG_SHAPE_MESSAGE}"
                );
            }
            IndexState::Missing => {
                if !current_kv_is_empty(manager).await? {
                    warn_missing(REASON_TABLE_NOT_EMPTY);
                } else if !try_create_on_empty_table(manager).await? {
                    warn_missing(REASON_BUILD_FAILED);
                }
            }
        }
        Ok(())
    }

    /// Keeps the index. It may be operator-built, and the previous release
    /// runs the same range select, so it still benefits. Drop it by hand with
    /// `DROP INDEX CONCURRENTLY` if it is ever unwanted.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::test_support::events::{capture_events, CapturedEvent};
    use crate::test_support::PostgresTestDatabase;
    use sea_orm::{ConnectionTrait, Database, DbBackend, DbConn, Statement, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use std::time::Duration;

    /// A key the logs must never show.
    const KEY_CANARY: &str = "secret-key-canary";

    fn steps_before_this() -> u32 {
        Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == Migration.name())
            .unwrap() as u32
    }

    /// A database as of the previous release, in a database of its own: some
    /// tests here run `CREATE INDEX CONCURRENTLY`, which waits for every open
    /// transaction of its database (`PostgresTestDatabase`).
    async fn before_this(test: &str) -> Option<PostgresTestDatabase> {
        PostgresTestDatabase::migrated_through(test, Some(steps_before_this())).await
    }

    #[tokio::test]
    async fn sqlite_migration_is_a_no_op() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let names: Vec<String> = db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA index_list('current_kv')".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get("", "name").unwrap())
            .collect();
        assert!(names.contains(&"idx_current_kv_space_deleted_key".to_string()));
        assert!(!names.iter().any(|name| name == INDEX), "{names:?}");
    }

    /// `(oid, indisvalid)` of `INDEX` on `current_kv`, or `None` if absent.
    async fn postgres_index(db: &DbConn) -> Option<(u32, bool)> {
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT c.oid::int8 AS oid, i.indisvalid AS valid
                     FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                     WHERE i.indrelid = 'current_kv'::regclass AND c.relname = '{INDEX}'"
                ),
            ))
            .await
            .unwrap()?;
        Some((
            row.try_get::<i64>("", "oid").unwrap() as u32,
            row.try_get("", "valid").unwrap(),
        ))
    }

    /// The production entry point: one outer transaction (TC-1054).
    async fn boot(db: &DbConn) -> Result<(), DbErr> {
        crate::db::migrate(&db.clone().into()).await
    }

    /// `boot`, giving up after `limit`. The timer starts when the future is
    /// first polled: pass this to `events_of`, which polls it only once it
    /// holds the capture lock, so waiting for another test's capture does not
    /// count against `limit`.
    async fn boot_within(
        db: &DbConn,
        limit: Duration,
    ) -> Result<Result<(), DbErr>, tokio::time::error::Elapsed> {
        tokio::time::timeout(limit, boot(db)).await
    }

    /// `up` alone, in a transaction under the boot's 30 s `lock_timeout`.
    /// Returns the `lock_timeout` in force when `up` returned.
    async fn run_up(db: &DbConn) -> String {
        let transaction = db.begin().await.unwrap();
        transaction
            .execute_unprepared("SET LOCAL lock_timeout = '30s'")
            .await
            .unwrap();
        Migration
            .up(&SchemaManager::new(&transaction))
            .await
            .unwrap();
        let timeout = transaction
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT current_setting('lock_timeout') AS value".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "value")
            .unwrap();
        transaction.commit().await.unwrap();
        timeout
    }

    async fn events_of<F: std::future::Future>(run: F) -> (F::Output, Vec<CapturedEvent>) {
        capture_events("current_kv_c_index_", run).await
    }

    async fn recorded(db: &DbConn) -> i64 {
        db.query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT COUNT(*) AS n FROM seaql_migrations WHERE version = '{}'",
                Migration.name()
            ),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
    }

    /// One live key, so `current_kv` is not empty. Foreign keys are off for
    /// the table: the rows they point at are not what is tested.
    async fn insert_a_key(db: &DbConn) {
        db.execute_unprepared("ALTER TABLE current_kv DISABLE TRIGGER ALL")
            .await
            .unwrap();
        db.execute_unprepared(&format!(
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, \
             metadata, deleted) VALUES ('tinycloud:key:z:default', '{KEY_CANARY}', '\\x1e20', 1, \
             '\\x1e20', 0, '\\x1e20', '{{}}', false)"
        ))
        .await
        .unwrap();
    }

    /// A transaction mid-write on `current_kv`, as `transact` is when it
    /// upserts. `ROW EXCLUSIVE` conflicts with the `SHARE` lock a `CREATE
    /// INDEX` takes, so anything that tried to build would queue behind it.
    async fn open_writer(db: &DbConn) -> sea_orm::DatabaseTransaction {
        let writer = db.begin().await.unwrap();
        writer
            .execute_unprepared("LOCK TABLE current_kv IN ROW EXCLUSIVE MODE")
            .await
            .unwrap();
        writer
    }

    /// The one `missing` warning, with the constant reason it was not built.
    fn assert_missing(events: &[CapturedEvent], reason: &str, label: &str) {
        assert_only(
            events,
            EVENT_MISSING,
            tracing::Level::WARN,
            MISSING_MESSAGE,
            label,
        );
        assert!(
            events[0].fields.contains(&format!("reason=\"{reason}\"")),
            "{label}: {:?}",
            events[0]
        );
    }

    fn assert_only(
        events: &[CapturedEvent],
        name: &str,
        level: tracing::Level,
        message: &str,
        label: &str,
    ) {
        assert_eq!(events.len(), 1, "{label}: {events:?}");
        let event = &events[0];
        assert_eq!(event.event, name, "{label}");
        assert_eq!(event.level, level, "{label}");
        assert_eq!(event.message, message, "{label}");
        assert!(
            !event.message.contains(KEY_CANARY) && !event.fields.contains(KEY_CANARY),
            "{label}: {event:?}"
        );
    }

    /// Branch 2 (fresh database): the index is built, instantly, silently.
    #[tokio::test]
    async fn postgres_fresh_database_gets_the_index() {
        let Some(fixture) =
            PostgresTestDatabase::migrated_through("postgres_fresh_database_gets_the_index", None)
                .await
        else {
            return;
        };
        assert!(postgres_index(&fixture.conn).await.unwrap().1);
    }

    /// Branch 2: missing and `current_kv` empty. Created; no warning; the
    /// boot transaction's own `lock_timeout` is back afterwards.
    #[tokio::test]
    async fn postgres_missing_index_on_an_empty_table_is_created() {
        let Some(fixture) =
            before_this("postgres_missing_index_on_an_empty_table_is_created").await
        else {
            return;
        };
        let db = &fixture.conn;
        assert_eq!(postgres_index(db).await, None);

        let (timeout, events) = events_of(run_up(db)).await;

        assert!(postgres_index(db).await.unwrap().1);
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(timeout, "30s");
    }

    /// Branch 2, but a writer holds `current_kv` between the probe and the
    /// build (or the role may not build): the build gives up after
    /// `CREATE_LOCK_TIMEOUT`, the transaction stays usable, the node boots
    /// with one `missing` warning and the migration is recorded.
    #[tokio::test]
    async fn postgres_failed_build_on_an_empty_table_warns_and_boots() {
        let Some(fixture) =
            before_this("postgres_failed_build_on_an_empty_table_warns_and_boots").await
        else {
            return;
        };
        let db = &fixture.conn;
        let writer = open_writer(db).await;
        let migrator = fixture.connect(1).await;

        // `up` alone: the transaction is usable after the failed build and
        // has the boot's `lock_timeout` back.
        let ((timeout, up_waited), events) = events_of(async {
            let started = std::time::Instant::now();
            (run_up(&migrator).await, started.elapsed())
        })
        .await;
        assert_eq!(timeout, "30s");
        assert!(up_waited < Duration::from_secs(10), "{up_waited:?}");
        assert_eq!(postgres_index(db).await, None);
        assert_missing(&events, REASON_BUILD_FAILED, "up");

        // The real boot: continues, records the migration.
        let (booted, events) = events_of(boot_within(&migrator, Duration::from_secs(20))).await;
        writer.rollback().await.unwrap();
        booted.expect("boot hung on the build").unwrap();
        assert_eq!(postgres_index(db).await, None);
        assert_eq!(recorded(db).await, 1);
        assert_missing(&events, REASON_BUILD_FAILED, "boot");
    }

    /// Branch 3: missing and `current_kv` not empty. No `CREATE INDEX`, so no
    /// lock on `current_kv` (a writer mid-transaction does not hold the boot
    /// up), no index, one `missing` warning with constant text, the node
    /// boots and the migration is recorded. The operator's build afterwards
    /// is a valid index of the right shape, and a restart is quiet.
    #[tokio::test]
    async fn postgres_missing_index_on_a_non_empty_table_is_skipped_with_a_warning() {
        let Some(fixture) =
            before_this("postgres_missing_index_on_a_non_empty_table_is_skipped_with_a_warning")
                .await
        else {
            return;
        };
        let db = &fixture.conn;
        insert_a_key(db).await;
        let writer = open_writer(db).await;
        let migrator = fixture.connect(1).await;

        let (booted, events) = events_of(boot_within(&migrator, Duration::from_secs(5))).await;
        writer.rollback().await.unwrap();

        booted
            .expect("boot waited behind an open current_kv write: it took a lock")
            .unwrap();
        assert_eq!(postgres_index(db).await, None, "the index was built");
        assert_eq!(recorded(db).await, 1);
        assert_missing(&events, REASON_TABLE_NOT_EMPTY, "non-empty");

        // Later, the operator builds it with the documented statement.
        db.execute_unprepared(&operator_create_index_sql())
            .await
            .unwrap();
        let (oid, valid) = postgres_index(db).await.unwrap();
        assert!(valid);
        let (_, events) = events_of(async {
            boot(db).await.unwrap();
            run_up(db).await;
        })
        .await;
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(postgres_index(db).await, Some((oid, true)));
    }

    /// Branch 1: the operator built the index online with the documented
    /// statement. Booting keeps that index (same OID), says nothing, and does
    /// not lock `current_kv` against writers.
    #[tokio::test]
    async fn postgres_valid_index_is_kept_without_a_warning_or_a_lock() {
        let Some(fixture) =
            before_this("postgres_valid_index_is_kept_without_a_warning_or_a_lock").await
        else {
            return;
        };
        let db = &fixture.conn;
        insert_a_key(db).await;
        db.execute_unprepared(&operator_create_index_sql())
            .await
            .unwrap();
        let (oid, valid) = postgres_index(db).await.unwrap();
        assert!(valid);
        let writer = open_writer(db).await;
        let migrator = fixture.connect(1).await;

        let (booted, events) = events_of(boot_within(&migrator, Duration::from_secs(5))).await;
        writer.rollback().await.unwrap();

        booted
            .expect("boot waited behind an open current_kv write")
            .unwrap();
        assert_eq!(postgres_index(db).await, Some((oid, true)));
        assert_eq!(recorded(db).await, 1);
        assert!(events.is_empty(), "{events:?}");
    }

    /// Branch 4: the right shape but not valid, ready and live (what a failed
    /// `CREATE INDEX CONCURRENTLY` leaves). One `invalid` warning; the index
    /// is neither dropped nor rebuilt, boot continues, the migration is
    /// recorded. Empty or not, the table is not built on.
    #[tokio::test]
    async fn postgres_invalid_index_warns_and_boots() {
        let Some(fixture) = before_this("postgres_invalid_index_warns_and_boots").await else {
            return;
        };
        let db = &fixture.conn;
        for (flag, populated) in [
            ("indisvalid", false),
            ("indisready", false),
            ("indislive", false),
            ("indisvalid", true),
        ] {
            let label = format!("{flag} populated {populated}");
            if populated {
                insert_a_key(db).await;
            }
            db.execute_unprepared(&format!("DROP INDEX IF EXISTS {INDEX}"))
                .await
                .unwrap();
            db.execute_unprepared(&format!("CREATE INDEX {INDEX} ON current_kv {DEFINITION}"))
                .await
                .unwrap();
            // What a failed CONCURRENTLY build leaves behind. Needs a
            // superuser, as the CI and local test roles are.
            db.execute_unprepared(&format!(
                "UPDATE pg_index SET {flag} = false WHERE indexrelid = '{INDEX}'::regclass"
            ))
            .await
            .unwrap();
            let oid = postgres_index(db).await.unwrap().0;

            let (_, events) = events_of(run_up(db)).await;

            assert_only(
                &events,
                EVENT_INVALID,
                tracing::Level::WARN,
                INVALID_MESSAGE,
                &label,
            );
            assert_eq!(postgres_index(db).await.unwrap().0, oid, "{label}: rebuilt");
        }

        // Through the real boot, recorded as applied.
        let (booted, events) = events_of(boot(db)).await;
        booted.unwrap();
        assert_eq!(recorded(db).await, 1);
        assert_eq!(events.len(), 1, "{events:?}");
    }

    /// Remove whatever holds `INDEX`'s name (an index or a table) and `other_kv`.
    async fn clear_index_name(db: &DbConn) {
        db.execute_unprepared(&format!(
            "DO $$
             DECLARE kind \"char\";
             BEGIN
                 SELECT relkind INTO kind FROM pg_class
                 WHERE relname = '{INDEX}'
                   AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema());
                 IF kind = 'i' THEN DROP INDEX {INDEX}; ELSIF kind = 'r' THEN DROP TABLE {INDEX}; END IF;
                 DROP TABLE IF EXISTS other_kv;
             END $$"
        ))
        .await
        .unwrap();
    }

    /// Branch 4 as it happens: the operator's `CREATE INDEX CONCURRENTLY` is
    /// still running (held in its first wait by an open write), so the index
    /// is not valid yet. The node boots with one `invalid` warning, without
    /// waiting for the build and without disturbing it; the build then
    /// finishes valid. This database is this test's own: the build waits for
    /// every open transaction of its database.
    #[tokio::test]
    async fn postgres_index_build_in_progress_warns_and_boots() {
        let Some(fixture) = before_this("postgres_index_build_in_progress_warns_and_boots").await
        else {
            return;
        };
        let db = &fixture.conn;
        insert_a_key(db).await;
        let writer = open_writer(db).await;
        let builder = fixture.connect(1).await;
        let build = tokio::spawn(async move {
            builder
                .execute_unprepared(&operator_create_index_sql())
                .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while postgres_index(db).await.is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "build never started"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!postgres_index(db).await.unwrap().1, "mid-build is invalid");
        let migrator = fixture.connect(1).await;

        let (booted, events) = events_of(boot_within(&migrator, Duration::from_secs(5))).await;
        writer.rollback().await.unwrap();
        build.await.unwrap().unwrap();

        booted.expect("boot waited for the build").unwrap();
        assert_only(
            &events,
            EVENT_INVALID,
            tracing::Level::WARN,
            INVALID_MESSAGE,
            "build in progress",
        );
        assert_eq!(recorded(db).await, 1);
        assert!(postgres_index(db).await.unwrap().1, "build finished valid");
    }

    /// Branch 5: this name, another definition (or another kind of relation,
    /// or another table). One error-level `wrong_shape` event; the object is
    /// left alone, boot continues.
    #[tokio::test]
    async fn postgres_wrong_shape_under_the_index_name_warns_loudly_and_boots() {
        let Some(fixture) =
            before_this("postgres_wrong_shape_under_the_index_name_warns_loudly_and_boots").await
        else {
            return;
        };
        let db = &fixture.conn;
        for (setup, populated) in [
            // The existing index's shape: the database collation, not "C".
            (
                format!("CREATE INDEX {INDEX} ON current_kv (space, deleted, key)"),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, deleted, (key COLLATE "POSIX"))"#
                ),
                false,
            ),
            // A collation on a leading column other than the column's own: a
            // query compares `space` in the column's collation, so the
            // planner cannot match this index for `space = $1`.
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv ((space COLLATE "C"), deleted, (key COLLATE "C"))"#
                ),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv ((space COLLATE "POSIX"), deleted, (key COLLATE "C"))"#
                ),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, deleted, (lower(key) COLLATE "C"))"#
                ),
                false,
            ),
            (
                format!(r#"CREATE INDEX {INDEX} ON current_kv (space, (key COLLATE "C"))"#),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, (key COLLATE "C"), deleted)"#
                ),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, deleted, (key COLLATE "C") DESC)"#
                ),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, deleted, (key COLLATE "C") varchar_pattern_ops)"#
                ),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, deleted, (key COLLATE "C")) INCLUDE (seq)"#
                ),
                false,
            ),
            (
                format!(
                    r#"CREATE INDEX {INDEX} ON current_kv (space, deleted, (key COLLATE "C")) WHERE deleted = false"#
                ),
                false,
            ),
            // Non-empty table too: still no build.
            (
                format!("CREATE INDEX {INDEX} ON current_kv (space, deleted, key)"),
                true,
            ),
            // Another table's index of this name.
            (
                format!(
                    r#"CREATE TABLE other_kv (space text, deleted boolean, key varchar);
                       CREATE INDEX {INDEX} ON other_kv (space, deleted, (key COLLATE "C"))"#
                ),
                false,
            ),
            // Not an index.
            (format!("CREATE TABLE {INDEX} (id int)"), false),
        ] {
            if populated {
                insert_a_key(db).await;
            }
            clear_index_name(db).await;
            db.execute_unprepared(&setup).await.unwrap();

            let (_, events) = events_of(run_up(db)).await;

            assert_only(
                &events,
                EVENT_WRONG_SHAPE,
                tracing::Level::ERROR,
                WRONG_SHAPE_MESSAGE,
                &setup,
            );
        }

        // Through the real boot, recorded as applied.
        let (booted, events) = events_of(boot(db)).await;
        booted.unwrap();
        assert_eq!(recorded(db).await, 1);
        assert_eq!(events.len(), 1, "{events:?}");
    }

    /// A different name is a different index: `up` looks only at its own
    /// name, whatever else is on `current_kv` (existing indexes of any shape,
    /// even this very definition under another name).
    #[tokio::test]
    async fn postgres_other_indexes_are_ignored() {
        let Some(fixture) = before_this("postgres_other_indexes_are_ignored").await else {
            return;
        };
        let db = &fixture.conn;
        for statement in [
            "CREATE INDEX idx_tc1274_other_collation ON current_kv (space, deleted, key)",
            r#"CREATE INDEX idx_tc1274_other_name ON current_kv (space, deleted, (key COLLATE "C"))"#,
        ] {
            db.execute_unprepared(statement).await.unwrap();
        }
        let others = || async {
            db.query_all(Statement::from_string(
                DbBackend::Postgres,
                "SELECT c.relname::text AS name, c.oid::int8 AS oid FROM pg_class c \
                 WHERE c.relname LIKE 'idx_tc1274_other_%' ORDER BY 1"
                    .to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.try_get::<String>("", "name").unwrap(),
                    row.try_get::<i64>("", "oid").unwrap(),
                )
            })
            .collect::<Vec<_>>()
        };
        let before = others().await;
        assert_eq!(before.len(), 2);

        // Empty table: this index is still built.
        let (_, events) = events_of(run_up(db)).await;
        assert!(postgres_index(db).await.unwrap().1);
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(others().await, before);

        // Non-empty table without it: still the `missing` warning.
        db.execute_unprepared(&format!("DROP INDEX {INDEX}"))
            .await
            .unwrap();
        insert_a_key(db).await;
        let (_, events) = events_of(run_up(db)).await;
        assert_eq!(postgres_index(db).await, None);
        assert_missing(&events, REASON_TABLE_NOT_EMPTY, "other indexes");
        assert_eq!(others().await, before);
    }
}
