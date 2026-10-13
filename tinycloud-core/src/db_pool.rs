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
//!   The pool's `before_acquire` hook pings an idle connection only if it
//!   was released at or before that instant, or has sat idle for at least
//!   [`IDLE_REVALIDATE_AFTER`]. Every acquisition after the first observed
//!   loss is therefore checked, and so is every connection an idle reaper
//!   (`idle_session_timeout`, a NAT or load balancer) may have closed, while
//!   a pool in normal use costs no extra round trip.
//!
//! What this does not cover: statements that had already acquired a dead
//! connection when the first loss was observed (a concurrent wave right
//! after a failover) each meet that connection. The reads and `BEGIN`s
//! among them are retried once on a checked connection; each write among
//! them fails. A reaper faster than [`IDLE_REVALIDATE_AFTER`] is covered
//! only by the loss rule: the first statement on each reaped connection
//! fails, and is retried if it is a read or `BEGIN`.
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

/// How long a pooled connection may sit idle before the acquire hook
/// checks it regardless of losses: idle reapers (PostgreSQL's
/// `idle_session_timeout`, NAT and load-balancer timeouts) close
/// connections without any statement observing it. In normal use the
/// webhook dispatcher's 1 Hz poll and request traffic rotate through the
/// FIFO idle queue, so a connection is reused within seconds and this
/// never fires.
pub const IDLE_REVALIDATE_AFTER: Duration = Duration::from_secs(60);

/// Pool-wide record of the last observed connection loss (TC-951).
///
/// A pool built with [`PoolRecovery::install`] pings an idle connection
/// before handing it out only if the connection was released to the pool at
/// or before the last loss that [`RecoveringConnection`] observed, or has
/// been idle for at least the idle threshold ([`IDLE_REVALIDATE_AFTER`]). A
/// failed ping makes sqlx close that connection and open a new one in its
/// place.
#[derive(Debug)]
pub struct PoolRecovery {
    origin: Instant,
    idle_revalidate_after: Duration,
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
            idle_revalidate_after: IDLE_REVALIDATE_AFTER,
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

    /// A recovery state with a different idle threshold than
    /// [`IDLE_REVALIDATE_AFTER`]. Tests only: they cannot wait a minute.
    pub fn with_idle_revalidation(idle_revalidate_after: Duration) -> Arc<Self> {
        Arc::new(Self {
            idle_revalidate_after,
            ..Self::default()
        })
    }

    /// Record that a connection of this pool was found dead now.
    pub fn mark_lost(&self) {
        self.losses.fetch_add(1, Ordering::Relaxed);
        let now = u64::try_from(self.origin.elapsed().as_nanos())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        self.lost_at.fetch_max(now, Ordering::AcqRel);
    }

    /// Whether a connection that has been idle for `idle_for` may be dead:
    /// it was released at or before the last observed loss, or it has been
    /// idle long enough for an idle reaper to have closed it.
    pub fn needs_revalidation(&self, idle_for: Duration) -> bool {
        if idle_for >= self.idle_revalidate_after {
            return true;
        }
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
                        // sqlx closes the connection and opens a new one in its place.
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
            // The server ended this session (PostgreSQL 16 errcodes):
            // 57P01 admin_shutdown, 57P02 crash_shutdown, 57P03
            // cannot_connect_now, 57P04 database_dropped, 57P05
            // idle_session_timeout, and 25P03
            // idle_in_transaction_session_timeout. Not 57014
            // (query_canceled) or 57000: the session survives those.
            Some("57P01") => Some("sqlstate_57P01"),
            Some("57P02") => Some("sqlstate_57P02"),
            Some("57P03") => Some("sqlstate_57P03"),
            Some("57P04") => Some("sqlstate_57P04"),
            Some("57P05") => Some("sqlstate_57P05"),
            Some("25P03") => Some("sqlstate_25P03"),
            // Class 08: connection exception.
            Some(code) if code.starts_with("08") => Some("sqlstate_08"),
            _ => None,
        },
        _ => None,
    }
}

/// Keywords that make a statement unsafe to run twice, wherever they occur
/// as a bare word.
const WRITE_KEYWORDS: [&str; 5] = ["INSERT", "UPDATE", "DELETE", "MERGE", "INTO"];

/// The only bare words a read-only statement may put directly before `(`:
/// SQL keywords that open a subquery, a list or a grouping, and the pure
/// built-in aggregates and functions the node's generated SQL uses. A call
/// of anything else (`nextval`, `setval`, `pg_advisory_lock`,
/// `pg_terminate_backend`, `set_config`, `lo_*`, a user-defined function)
/// may have side effects, so it makes the statement non-retryable.
const CALL_ALLOWLIST: [&str; 36] = [
    // keywords
    "SELECT",
    "FROM",
    "WHERE",
    "AND",
    "OR",
    "NOT",
    "IN",
    "EXISTS",
    "ANY",
    "ALL",
    "SOME",
    "AS",
    "ON",
    "USING",
    "JOIN",
    "UNION",
    "INTERSECT",
    "EXCEPT",
    "VALUES",
    "BY",
    "HAVING",
    "LIMIT",
    "OFFSET",
    "WHEN",
    "THEN",
    "ELSE",
    "IS",
    "LIKE",
    // pure built-ins
    "COUNT",
    "MAX",
    "MIN",
    "SUM",
    "AVG",
    "COALESCE",
    "LOWER",
    "UPPER",
];

#[derive(Debug, PartialEq, Eq)]
enum Token<'a> {
    /// An unquoted word: a keyword, an identifier, a number or `$n`.
    Word(&'a str),
    /// A double-quoted identifier.
    Quoted,
    Punct(u8),
}

/// Split `sql` into tokens, or `None` for an unterminated quoted
/// identifier. The caller has already rejected string literals, comments
/// and non-ASCII text.
fn tokens(sql: &str) -> Option<Vec<Token<'_>>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte.is_ascii_whitespace() {
            i += 1;
        } else if byte == b'"' {
            i += 1;
            loop {
                match bytes.get(i) {
                    None => return None,
                    Some(b'"') if bytes.get(i + 1) == Some(&b'"') => i += 2,
                    Some(b'"') => break,
                    Some(_) => i += 1,
                }
            }
            i += 1;
            tokens.push(Token::Quoted);
        } else if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            tokens.push(Token::Word(&sql[start..i]));
        } else {
            tokens.push(Token::Punct(byte));
            i += 1;
        }
    }
    Some(tokens)
}

/// Whether running `sql` a second time cannot change the database.
///
/// Deliberately conservative: anything it cannot prove harmless is "no",
/// and a wrong "no" only costs a retry. True only when all of these hold:
///
/// - the text is ASCII, with no `;` (anywhere, even in a literal), no
///   comment (`--`, `/*`), no string literal or dollar quote (`'`, `$` not
///   followed by a digit), no `&` (`U&"..."` identifiers), no `\` and no
///   `::` cast, which could run a user-defined cast;
/// - the first token is `SELECT` or `WITH`;
/// - no bare `INSERT`, `UPDATE` (also `FOR UPDATE`), `DELETE`, `MERGE` or
///   `INTO` (`SELECT ... INTO` creates a table);
/// - every `(` follows punctuation, a word in [`CALL_ALLOWLIST`] that is not
///   qualified (`schema.count(` is a different function), or a quoted
///   identifier right after `WITH` or `WITH RECURSIVE` (a CTE's column
///   list). A quoted name anywhere else before `(` may be a call.
///   Whitespace between a name and `(` changes nothing.
pub fn is_read_only_statement(sql: &str) -> bool {
    if !sql.is_ascii()
        || sql.contains([';', '\'', '&', '\\'])
        || sql.contains("--")
        || sql.contains("/*")
        || sql.contains("::")
    {
        return false;
    }
    let bytes = sql.as_bytes();
    if bytes
        .iter()
        .enumerate()
        .any(|(i, b)| *b == b'$' && !bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
    {
        return false;
    }
    let Some(tokens) = tokens(sql) else {
        return false;
    };
    let is_word = |token: Option<&Token<'_>>, keyword: &str| matches!(token, Some(Token::Word(word)) if word.eq_ignore_ascii_case(keyword));
    if !(is_word(tokens.first(), "SELECT") || is_word(tokens.first(), "WITH")) {
        return false;
    }
    for (i, token) in tokens.iter().enumerate() {
        match token {
            Token::Word(word)
                if WRITE_KEYWORDS
                    .iter()
                    .any(|keyword| word.eq_ignore_ascii_case(keyword)) =>
            {
                return false;
            }
            Token::Punct(b'(') => {
                let before = i.checked_sub(1).map(|j| &tokens[j]);
                let before_that = i.checked_sub(2).map(|j| &tokens[j]);
                let allowed = match before {
                    None | Some(Token::Punct(b'.')) => false,
                    Some(Token::Punct(_)) => true,
                    Some(Token::Word(word)) => {
                        !matches!(before_that, Some(Token::Punct(b'.')))
                            && CALL_ALLOWLIST
                                .iter()
                                .any(|allowed| word.eq_ignore_ascii_case(allowed))
                    }
                    Some(Token::Quoted) => {
                        is_word(before_that, "WITH") || is_word(before_that, "RECURSIVE")
                    }
                };
                if !allowed {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
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
        let positives: [fn() -> SqlxError; 13] = [
            || SqlxError::Io(io::Error::from(io::ErrorKind::ConnectionReset)),
            || SqlxError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)),
            || SqlxError::Io(io::Error::from(io::ErrorKind::BrokenPipe)),
            || SqlxError::Tls("tls session closed".into()),
            || SqlxError::Protocol("unexpected message".into()),
            || SqlxError::WorkerCrashed,
            || sqlstate("57P01"),
            || sqlstate("57P02"),
            || sqlstate("57P03"),
            || sqlstate("57P04"),
            || sqlstate("57P05"),
            || sqlstate("25P03"),
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

    /// Calls that may have side effects, and every way to hide one, are
    /// never classified read-only (Astra's review of TC-951).
    #[test]
    fn side_effects_and_hidden_calls_are_not_read_only() {
        for unsafe_sql in [
            // Volatile and side-effecting functions, bare or bound.
            "SELECT nextval('s')",
            "SELECT nextval($1)",
            "SELECT setval($1, $2)",
            "SELECT currval($1)",
            "SELECT pg_advisory_lock($1)",
            "SELECT pg_advisory_xact_lock($1)",
            "SELECT pg_terminate_backend($1)",
            "SELECT set_config($1, $2, $3)",
            "SELECT lo_create($1)",
            "SELECT lo_unlink($1)",
            "SELECT my_function($1)",
            "SELECT \"t\".\"c\" FROM \"t\" WHERE \"t\".\"c\" = touch($1)",
            "WITH x AS (SELECT nextval($1)) SELECT * FROM x",
            // Whitespace between the name and `(`.
            "SELECT nextval ($1)",
            "SELECT nextval\n($1)",
            "SELECT nextval\t\r\n  ($1)",
            // Qualified calls: an allowlisted basename is a different function.
            "SELECT evil.count($1)",
            "SELECT pg_catalog.count(*) FROM t",
            "SELECT \"evil\".\"count\"(*) FROM t",
            "SELECT \"evil\".count(*) FROM t",
            // Quoted and escaped names before `(`.
            "SELECT \"count\"(*) FROM t",
            "SELECT \"nextval\"($1)",
            "SELECT \"nextval\" ($1)",
            "SELECT U&\"nextval\"($1)",
            "SELECT u&\"\\006Eextval\"($1)",
            "SELECT 1, \"f\"($1) AS x",
            // Comments, which must never be stripped before classifying.
            "SELECT nextval/*x*/($1)",
            "SELECT 1 -- harmless",
            "SELECT /* */ 1",
            // Multiple statements, a `;` in a literal included.
            "SELECT 1; TRUNCATE TABLE t",
            "SELECT 1;",
            "SELECT 'a;b'",
            // Writes, locks, table creation.
            "SELECT * INTO new_table FROM t",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR NO KEY UPDATE",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            // Casts, literals, dollar quotes, non-ASCII.
            "SELECT $1::regclass",
            "SELECT $tag$x$tag$",
            "SELECT E'\\x'",
            "SELECT nеxtval($1)",
            // Not a statement we classify.
            "TRUNCATE TABLE t",
            "VALUES (1)",
            "(SELECT 1)",
            "SELECT \"unterminated",
        ] {
            assert!(!is_read_only_statement(unsafe_sql), "{unsafe_sql}");
        }
        for read in [
            "SELECT COUNT(*) FROM t WHERE c IN ($1, $2)",
            "SELECT count (*) FROM t",
            "SELECT MAX(\"t\".\"seq\") AS \"m\" FROM \"t\" WHERE NOT EXISTS (SELECT $1)",
            "SELECT coalesce(\"a\", $1) FROM \"t\" WHERE \"b\" = ANY($2)",
            "WITH \"x\" (\"a\") AS (SELECT $1) SELECT \"a\" FROM \"x\"",
        ] {
            assert!(is_read_only_statement(read), "{read}");
        }
    }

    /// Every autocommit statement PostgreSQL logged for sign-in, KV put,
    /// KV get and SQL in the TC-946 lab (texts with `$n`, no values). Each
    /// read must stay retryable, so the allowlist cannot silently switch
    /// recovery off on the hot paths, and each write must not.
    #[test]
    fn logged_autocommit_statements_keep_their_classification() {
        let corpus = include_str!("../tests/fixtures/postgres-autocommit-statements.txt");
        let (mut reads, mut writes) = (0, 0);
        for statement in corpus.lines().filter(|line| !line.trim().is_empty()) {
            let words = statement
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>();
            let writes_rows = words.iter().any(|word| {
                ["INSERT", "UPDATE", "DELETE"]
                    .iter()
                    .any(|keyword| word.eq_ignore_ascii_case(keyword))
            });
            let read = matches!(words.first(), Some(&"SELECT") | Some(&"WITH")) && !writes_rows;
            assert_eq!(is_read_only_statement(statement), read, "{statement}");
            if read {
                reads += 1;
            } else {
                writes += 1;
            }
        }
        assert_eq!((reads, writes), (20, 12));
    }

    #[test]
    fn long_idle_connections_are_revalidated_without_a_loss() {
        let recovery = PoolRecovery::new();
        assert!(!recovery.needs_revalidation(IDLE_REVALIDATE_AFTER - Duration::from_millis(1)));
        assert!(recovery.needs_revalidation(IDLE_REVALIDATE_AFTER));
        let fast = PoolRecovery::with_idle_revalidation(Duration::from_millis(500));
        assert!(!fast.needs_revalidation(Duration::from_millis(499)));
        assert!(fast.needs_revalidation(Duration::from_millis(500)));
        assert_eq!(fast.stats(), PoolRecoveryStats::default());
    }

    #[test]
    fn revalidation_covers_only_connections_released_before_a_loss() {
        // The loss rule alone: no idle threshold.
        let recovery = PoolRecovery::with_idle_revalidation(Duration::MAX);
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
