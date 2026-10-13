//! Connection-loss recovery for the node's shared database pool (TC-951).
//!
//! The Postgres pool no longer pings an idle connection before handing it
//! out: the database is a WAN round trip away, and that ping doubled the
//! cost of nearly every statement. A connection that the server, a proxy or
//! the network dropped while it sat idle therefore fails on its first use
//! instead of being replaced at acquire. Two mechanisms make that safe:
//!
//! - [`RecoveringConnection`] retries a statement exactly once when it fails
//!   with a connection-class error, but only when a second execution cannot
//!   change the outcome: `BEGIN` (it failed, so no statement of the
//!   transaction ran) and read-only statements. Everything else, including
//!   every write and `COMMIT`, returns the error unchanged. Statements inside
//!   a transaction are never retried: they run on the
//!   [`DatabaseTransaction`]'s own connection, which this type never wraps.
//! - [`PoolRecovery`] remembers when a connection loss was last observed.
//!   The pool's `before_acquire` hook pings only the idle connections that
//!   were released at or before that instant, so after one detected loss
//!   every connection that might be dead is checked before reuse, while the
//!   steady state costs no extra round trip.
//!
//! sqlx pings a connection when it is released to the pool and closes it if
//! that ping fails, so a connection is known to be live when it enters the
//! idle queue; it can only go stale while it sits there.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use sea_orm::{
    error::{RuntimeErr, SqlxError},
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    ExecResult, IsolationLevel, QueryResult, Statement, TransactionError, TransactionTrait,
};

use crate::telemetry::{observe_db_connection_event, DbConnectionEvent};

/// The node's pooled database connection.
///
/// It delegates every operation to the wrapped sea-orm connection and
/// applies the connection-loss policy described in the [module docs](self).
/// It deliberately does not `Deref` to [`DatabaseConnection`]: every
/// production statement on the shared pool goes through this type, and the
/// compiler finds any code that would bypass it.
#[derive(Clone, Debug)]
pub struct RecoveringConnection {
    conn: DatabaseConnection,
    recovery: Option<Arc<PoolRecovery>>,
}

impl RecoveringConnection {
    /// Wrap a connection whose pool has no [`PoolRecovery`] hook. Statements
    /// still get the retry policy; the pool's own acquire checks (sqlx's
    /// default pre-acquire ping on MySQL, a local file on SQLite) cover the
    /// rest.
    pub fn new(conn: DatabaseConnection) -> Self {
        Self {
            conn,
            recovery: None,
        }
    }

    /// Wrap a connection whose pool was built with
    /// [`PoolRecovery::install`] on the same `recovery`.
    pub fn with_recovery(conn: DatabaseConnection, recovery: Arc<PoolRecovery>) -> Self {
        Self {
            conn,
            recovery: Some(recovery),
        }
    }

    /// The pool's recovery state, when it has one.
    pub fn recovery(&self) -> Option<&Arc<PoolRecovery>> {
        self.recovery.as_ref()
    }

    /// The underlying sea-orm connection.
    ///
    /// This bypasses the connection-loss policy. Use it only where an API
    /// accepts nothing else and a lost connection needs no recovery: running
    /// migrations at boot (`sea-orm-migration` only accepts the raw
    /// connection, and a failure aborts startup), reading the sqlx pool's
    /// size and probing acquire latency for telemetry, and closing the pool.
    pub fn sea_orm_connection(&self) -> &DatabaseConnection {
        &self.conn
    }

    /// Record an observed connection loss.
    fn lost(&self, operation: &'static str, error: &DbErr, retrying: bool) {
        if let Some(recovery) = &self.recovery {
            recovery.mark_lost();
            if retrying {
                recovery.retries.fetch_add(1, Ordering::Relaxed);
            }
        }
        observe_db_connection_event(DbConnectionEvent::Lost);
        if retrying {
            observe_db_connection_event(DbConnectionEvent::Retried);
        }
        // Never the statement text or its values (TC-961).
        tracing::warn!(
            operation,
            error_class = connection_error_class(error).unwrap_or("other"),
            retrying,
            "database connection lost"
        );
    }

    /// Run `attempt` and, if it fails with a connection-class error, run it
    /// once more when `retryable`.
    async fn run<T, F, Fut>(
        &self,
        operation: &'static str,
        retryable: bool,
        attempt: F,
    ) -> Result<T, DbErr>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, DbErr>>,
    {
        match attempt().await {
            Err(error) if is_connection_error(&error) => {
                self.lost(operation, &error, retryable);
                if retryable {
                    self.retried(operation, attempt().await)
                } else {
                    Err(error)
                }
            }
            result => result,
        }
    }

    /// [`Self::run`] for a statement that each attempt consumes. Only a
    /// read-only statement is retryable, and only it is cloned, once.
    async fn run_statement<T, F, Fut>(
        &self,
        operation: &'static str,
        stmt: Statement,
        attempt: F,
    ) -> Result<T, DbErr>
    where
        F: Fn(Statement) -> Fut,
        Fut: Future<Output = Result<T, DbErr>>,
    {
        let retry = is_read_only_statement(&stmt.sql).then(|| stmt.clone());
        match attempt(stmt).await {
            Err(error) if is_connection_error(&error) => {
                self.lost(operation, &error, retry.is_some());
                match retry {
                    Some(stmt) => self.retried(operation, attempt(stmt).await),
                    None => Err(error),
                }
            }
            result => result,
        }
    }

    /// The outcome of the one retry. It is never retried again, but a
    /// connection lost again is still recorded.
    fn retried<T>(&self, operation: &'static str, result: Result<T, DbErr>) -> Result<T, DbErr> {
        if let Err(error) = &result {
            if is_connection_error(error) {
                self.lost(operation, error, false);
            }
        }
        result
    }
}

impl From<DatabaseConnection> for RecoveringConnection {
    fn from(conn: DatabaseConnection) -> Self {
        Self::new(conn)
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for RecoveringConnection {
    fn get_database_backend(&self) -> DatabaseBackend {
        self.conn.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.run_statement("execute", stmt, |stmt| self.conn.execute(stmt))
            .await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.run("execute", is_read_only_statement(sql), || {
            self.conn.execute_unprepared(sql)
        })
        .await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.run_statement("query", stmt, |stmt| self.conn.query_one(stmt))
            .await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.run_statement("query", stmt, |stmt| self.conn.query_all(stmt))
            .await
    }

    fn support_returning(&self) -> bool {
        self.conn.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.conn.is_mock_connection()
    }
}

#[async_trait::async_trait]
impl TransactionTrait for RecoveringConnection {
    /// `BEGIN` is retried once on a connection-class error: it failed, so no
    /// statement of the transaction ran.
    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        self.run("begin", true, || self.conn.begin()).await
    }

    async fn begin_with_config(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<DatabaseTransaction, DbErr> {
        self.run("begin", true, || {
            self.conn.begin_with_config(isolation_level, access_mode)
        })
        .await
    }

    /// sea-orm's `transaction`, on top of the retried [`Self::begin`]. The
    /// callback runs exactly once.
    async fn transaction<F, T, E>(&self, callback: F) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        let transaction = self.begin().await.map_err(TransactionError::Connection)?;
        run_transaction(transaction, callback).await
    }

    async fn transaction_with_config<F, T, E>(
        &self,
        callback: F,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        let transaction = self
            .begin_with_config(isolation_level, access_mode)
            .await
            .map_err(TransactionError::Connection)?;
        run_transaction(transaction, callback).await
    }
}

/// sea-orm's `DatabaseTransaction::run` (crate-private there): commit when
/// the callback succeeds, roll back when it fails, and report a failed
/// commit or rollback as a connection error.
async fn run_transaction<F, T, E>(
    transaction: DatabaseTransaction,
    callback: F,
) -> Result<T, TransactionError<E>>
where
    F: for<'c> FnOnce(
            &'c DatabaseTransaction,
        ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
        + Send,
    T: Send,
    E: std::fmt::Display + std::fmt::Debug + Send,
{
    let result = callback(&transaction)
        .await
        .map_err(TransactionError::Transaction);
    if result.is_ok() {
        transaction
            .commit()
            .await
            .map_err(TransactionError::Connection)?;
    } else {
        transaction
            .rollback()
            .await
            .map_err(TransactionError::Connection)?;
    }
    result
}

/// Pool-wide record of the last observed connection loss (TC-951).
///
/// A pool built with [`PoolRecovery::install`] pings an idle connection
/// before handing it out only if the connection was released to the pool at
/// or before the last loss that [`RecoveringConnection`] observed. A failed
/// ping makes sqlx close that connection and move on to the next idle one,
/// or open a new one. With no loss, no connection is ever pinged.
#[derive(Debug)]
pub struct PoolRecovery {
    origin: Instant,
    /// Nanoseconds after `origin` of the last observed loss, plus one; zero
    /// means no loss has been observed.
    lost_at: AtomicU64,
    losses: AtomicU64,
    retries: AtomicU64,
    revalidations: AtomicU64,
    revalidation_failures: AtomicU64,
}

/// Counters a [`PoolRecovery`] has accumulated since it was created.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolRecoveryStats {
    /// Statements or `BEGIN`s that failed with a connection-class error.
    pub losses: u64,
    /// Of those, the ones that were retried.
    pub retries: u64,
    /// Idle connections pinged by the acquire hook.
    pub revalidations: u64,
    /// Of those, the ones whose ping failed and that were closed.
    pub revalidation_failures: u64,
}

impl Default for PoolRecovery {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            lost_at: AtomicU64::new(0),
            losses: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            revalidations: AtomicU64::new(0),
            revalidation_failures: AtomicU64::new(0),
        }
    }
}

impl PoolRecovery {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record that a connection of this pool was found dead now.
    pub fn mark_lost(&self) {
        self.losses.fetch_add(1, Ordering::Relaxed);
        let now = u64::try_from(self.origin.elapsed().as_nanos())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        self.lost_at.fetch_max(now, Ordering::AcqRel);
    }

    /// Whether a connection that has been idle for `idle_for` was released
    /// at or before the last observed loss, and so may be dead.
    pub fn needs_revalidation(&self, idle_for: Duration) -> bool {
        let lost_at = self.lost_at.load(Ordering::Acquire);
        if lost_at == 0 {
            return false;
        }
        let lost_at = Duration::from_nanos(lost_at - 1);
        match self.origin.elapsed().checked_sub(idle_for) {
            Some(released_at) => released_at <= lost_at,
            // Released before this pool's recovery state existed.
            None => true,
        }
    }

    pub fn stats(&self) -> PoolRecoveryStats {
        PoolRecoveryStats {
            losses: self.losses.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            revalidations: self.revalidations.load(Ordering::Relaxed),
            revalidation_failures: self.revalidation_failures.load(Ordering::Relaxed),
        }
    }

    /// Add the re-validation hook to a Postgres pool's options. The options
    /// must keep `test_before_acquire(false)`; this hook replaces that
    /// unconditional ping.
    #[cfg(feature = "postgres")]
    pub fn install(
        self: &Arc<Self>,
        options: sea_orm::sqlx::pool::PoolOptions<sea_orm::sqlx::Postgres>,
    ) -> sea_orm::sqlx::pool::PoolOptions<sea_orm::sqlx::Postgres> {
        use sea_orm::sqlx::Connection;

        let recovery = Arc::clone(self);
        options.before_acquire(move |conn, meta| {
            if !recovery.needs_revalidation(meta.idle_for) {
                return Box::pin(KeepConnection);
            }
            let recovery = Arc::clone(&recovery);
            Box::pin(async move {
                recovery.revalidations.fetch_add(1, Ordering::Relaxed);
                observe_db_connection_event(DbConnectionEvent::Revalidated);
                match conn.ping().await {
                    Ok(()) => Ok(true),
                    Err(error) => {
                        // sqlx closes the connection and tries the next one.
                        recovery
                            .revalidation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        observe_db_connection_event(DbConnectionEvent::RevalidationFailed);
                        Err(error)
                    }
                }
            })
        })
    }
}

/// The acquire hook's verdict for a connection that needs no check. It is
/// zero-sized, so the steady-state hook boxes it without allocating.
#[cfg(feature = "postgres")]
struct KeepConnection;

#[cfg(feature = "postgres")]
impl Future for KeepConnection {
    type Output = Result<bool, sea_orm::sqlx::Error>;

    fn poll(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(Ok(true))
    }
}

/// Whether `error` means the connection it ran on is gone, so the statement
/// may never have reached the server or its result was lost.
///
/// Pool exhaustion (`PoolTimedOut`) and a closed pool (`PoolClosed`, which
/// sea-orm reports as `ConnectionAcquire(ConnectionClosed)`) are not: a
/// retry cannot help, and neither are serialization failures and deadlocks
/// (40001, 40P01), which the routes already answer with 503.
pub fn is_connection_error(error: &DbErr) -> bool {
    connection_error_class(error).is_some()
}

fn connection_error_class(error: &DbErr) -> Option<&'static str> {
    let (DbErr::Conn(RuntimeErr::SqlxError(error))
    | DbErr::Exec(RuntimeErr::SqlxError(error))
    | DbErr::Query(RuntimeErr::SqlxError(error))) = error
    else {
        return None;
    };
    match error {
        SqlxError::Io(_) => Some("io"),
        SqlxError::Tls(_) => Some("tls"),
        SqlxError::Protocol(_) => Some("protocol"),
        SqlxError::WorkerCrashed => Some("worker_crashed"),
        SqlxError::Database(error) => match error.code().as_deref() {
            // admin_shutdown, crash_shutdown, cannot_connect_now
            Some("57P01") => Some("sqlstate_57P01"),
            Some("57P02") => Some("sqlstate_57P02"),
            Some("57P03") => Some("sqlstate_57P03"),
            // Class 08: connection exception.
            Some(code) if code.starts_with("08") => Some("sqlstate_08"),
            _ => None,
        },
        _ => None,
    }
}

/// Keywords that make a statement unsafe to run twice, wherever they occur.
const WRITE_KEYWORDS: [&str; 5] = ["INSERT", "UPDATE", "DELETE", "MERGE", "INTO"];

/// Whether running `sql` a second time cannot change the database.
///
/// True only for a statement whose first keyword is `SELECT` or `WITH` and
/// that contains none of `INSERT`, `UPDATE`, `DELETE`, `MERGE` or `INTO` as
/// a whole word anywhere (case-insensitive). The scan ignores quoting, so a
/// literal or identifier spelled like one of those words makes a read
/// non-retryable; a false match can only ever prevent a retry. `INTO`
/// catches `SELECT ... INTO`, which creates a table.
pub fn is_read_only_statement(sql: &str) -> bool {
    let mut words = sql
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty());
    let Some(first) = words.next() else {
        return false;
    };
    // The first word must also be the statement's first token: `(SELECT`
    // or a leading comment is not classified.
    if !sql.trim_start().starts_with(first) {
        return false;
    }
    if !(first.eq_ignore_ascii_case("SELECT") || first.eq_ignore_ascii_case("WITH")) {
        return false;
    }
    !words.any(|word| {
        WRITE_KEYWORDS
            .iter()
            .any(|keyword| word.eq_ignore_ascii_case(keyword))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash::hash,
        migrations::Migrator,
        models::{actor, delegation, invocation_replay},
    };
    use sea_orm::{
        error::ConnAcquireErr,
        sea_query::{OnConflict, Query},
        ActiveModelTrait,
        ActiveValue::Set,
        ColumnTrait, Database, DbBackend, EntityTrait, PaginatorTrait, QueryFilter, QueryTrait,
    };
    use sea_orm_migration::MigratorTrait;
    use std::{borrow::Cow, error::Error as StdError, fmt, io};

    #[derive(Debug)]
    struct FakeDatabaseError(&'static str);

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "database error {}", self.0)
        }
    }

    impl StdError for FakeDatabaseError {}

    impl sea_orm::sqlx::error::DatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            "fake"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.0))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sea_orm::sqlx::error::ErrorKind {
            sea_orm::sqlx::error::ErrorKind::Other
        }
    }

    fn sqlstate(code: &'static str) -> SqlxError {
        SqlxError::Database(Box::new(FakeDatabaseError(code)))
    }

    /// Every way sea-orm wraps an sqlx error.
    fn wrapped(make: impl Fn() -> SqlxError) -> [DbErr; 3] {
        [
            DbErr::Conn(RuntimeErr::SqlxError(make())),
            DbErr::Exec(RuntimeErr::SqlxError(make())),
            DbErr::Query(RuntimeErr::SqlxError(make())),
        ]
    }

    #[test]
    fn connection_class_errors_are_recognized_in_every_wrapper() {
        let positives: [fn() -> SqlxError; 10] = [
            || SqlxError::Io(io::Error::from(io::ErrorKind::ConnectionReset)),
            || SqlxError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)),
            || SqlxError::Io(io::Error::from(io::ErrorKind::BrokenPipe)),
            || SqlxError::Tls("tls session closed".into()),
            || SqlxError::Protocol("unexpected message".into()),
            || SqlxError::WorkerCrashed,
            || sqlstate("57P01"),
            || sqlstate("57P02"),
            || sqlstate("57P03"),
            || sqlstate("08006"),
        ];
        for make in positives {
            for error in wrapped(make) {
                assert!(is_connection_error(&error), "{error:?}");
            }
        }
        for code in ["08000", "08003", "08001", "08P01"] {
            assert!(is_connection_error(&DbErr::Query(RuntimeErr::SqlxError(
                sqlstate(code)
            ))));
        }
    }

    #[test]
    fn other_errors_are_not_connection_errors() {
        let negatives: [fn() -> SqlxError; 9] = [
            || SqlxError::PoolTimedOut,
            || SqlxError::PoolClosed,
            || SqlxError::RowNotFound,
            || SqlxError::ColumnNotFound("c".into()),
            || sqlstate("40001"),
            || sqlstate("40P01"),
            || sqlstate("23505"),
            || sqlstate("57014"),
            || sqlstate("42P01"),
        ];
        for make in negatives {
            for error in wrapped(make) {
                assert!(!is_connection_error(&error), "{error:?}");
            }
        }
        for error in [
            // sea-orm's mapping of `PoolTimedOut` and `PoolClosed` at acquire.
            DbErr::ConnectionAcquire(ConnAcquireErr::Timeout),
            DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed),
            DbErr::Exec(RuntimeErr::Internal("io".into())),
            DbErr::Custom("connection reset".into()),
            DbErr::RecordNotFound("row".into()),
        ] {
            assert!(!is_connection_error(&error), "{error:?}");
        }
    }

    fn closure_edges_statement() -> &'static str {
        // `auth_graph::load_closure_edges`, as sea-query renders it for Postgres.
        r#"WITH RECURSIVE "authorization_edges" ("child", "parent") AS (SELECT "child", "parent" FROM "parent_delegations" WHERE "child" IN ($1, $2) UNION SELECT "parent_delegations"."child", "parent_delegations"."parent" FROM "parent_delegations" INNER JOIN "authorization_edges" ON "parent_delegations"."child" = "authorization_edges"."parent") SELECT "authorization_edges"."child", "authorization_edges"."parent" FROM "authorization_edges" LIMIT $3"#
    }

    #[test]
    fn only_reads_are_classified_read_only() {
        let select = delegation::Entity::find()
            .filter(delegation::Column::Delegator.eq("did:key:z"))
            .build(DbBackend::Postgres)
            .sql;
        assert!(select.starts_with("SELECT"), "{select}");
        let replay_insert = Query::insert()
            .into_table(invocation_replay::Entity)
            .columns([
                invocation_replay::Column::ContentHash,
                invocation_replay::Column::ExpiresAt,
            ])
            .values_panic([
                hash(b"replay").into(),
                time::OffsetDateTime::UNIX_EPOCH.into(),
            ])
            .on_conflict(
                OnConflict::column(invocation_replay::Column::ContentHash)
                    .do_nothing()
                    .to_owned(),
            )
            .to_owned();
        let replay_insert = DbBackend::Postgres.build(&replay_insert).sql;
        assert!(replay_insert.contains("ON CONFLICT"), "{replay_insert}");

        for read in [
            select.as_str(),
            closure_edges_statement(),
            "select 1",
            "  SELECT \"kv_delete\".\"key\" FROM \"kv_delete\"",
            "SELECT \"updated_at\", \"deleted\" FROM \"t\"",
            "WITH x AS (SELECT 1) SELECT * FROM x",
        ] {
            assert!(is_read_only_statement(read), "{read}");
        }
        for not_read in [
            replay_insert.as_str(),
            // The read-audit batch: a data-modifying CTE.
            r#"WITH "batch" ("id", "invoker") AS (VALUES ($1, $2)) INSERT INTO "invocation" ("id", "invoker") SELECT "id", "invoker" FROM "batch" ON CONFLICT DO NOTHING"#,
            r#"WITH "moved" AS (DELETE FROM "a" RETURNING *) SELECT * FROM "moved""#,
            "with u as (update t set x = 1 returning x) select x from u",
            "WITH m AS (SELECT 1) MERGE INTO t USING m ON true WHEN MATCHED THEN DO NOTHING",
            "SELECT * INTO new_table FROM t",
            "SELECT 1; DELETE FROM t",
            "SELECT * FROM t FOR UPDATE",
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1",
            "DELETE FROM t",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SET search_path = x",
            "(SELECT 1)",
            "/* SELECT */ DELETE FROM t",
            "",
            "   ",
        ] {
            assert!(!is_read_only_statement(not_read), "{not_read}");
        }
    }

    #[test]
    fn revalidation_covers_only_connections_released_before_a_loss() {
        let recovery = PoolRecovery::new();
        assert!(!recovery.needs_revalidation(Duration::from_secs(3600)));
        std::thread::sleep(Duration::from_millis(20));
        recovery.mark_lost();
        // Idle since before the loss: may be dead.
        assert!(recovery.needs_revalidation(Duration::from_millis(10)));
        // Released before this recovery state existed.
        assert!(recovery.needs_revalidation(Duration::from_secs(3600)));
        std::thread::sleep(Duration::from_millis(20));
        // Released after the loss: it passed sqlx's release ping since.
        assert!(!recovery.needs_revalidation(Duration::from_millis(5)));
        assert!(!recovery.needs_revalidation(Duration::ZERO));
        assert_eq!(recovery.stats().losses, 1);
    }

    async fn sqlite() -> RecoveringConnection {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        RecoveringConnection::new(conn)
    }

    #[tokio::test]
    async fn transaction_commits_on_ok_and_rolls_back_on_err_like_sea_orm() {
        let conn = sqlite().await;
        let committed = conn
            .transaction::<_, (), DbErr>(|txn| {
                Box::pin(async move {
                    actor::ActiveModel {
                        id: Set("did:key:committed".into()),
                    }
                    .insert(txn)
                    .await?;
                    Ok(())
                })
            })
            .await;
        assert!(committed.is_ok());
        let rolled_back = conn
            .transaction::<_, (), DbErr>(|txn| {
                Box::pin(async move {
                    actor::ActiveModel {
                        id: Set("did:key:rolled-back".into()),
                    }
                    .insert(txn)
                    .await?;
                    Err(DbErr::Custom("callback failed".into()))
                })
            })
            .await;
        assert!(matches!(
            rolled_back,
            Err(TransactionError::Transaction(DbErr::Custom(ref message))) if message == "callback failed"
        ));
        let ids: Vec<String> = actor::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|actor| actor.id)
            .collect();
        assert_eq!(ids, vec!["did:key:committed".to_string()]);
        assert_eq!(actor::Entity::find().count(&conn).await.unwrap(), 1);
    }
}
