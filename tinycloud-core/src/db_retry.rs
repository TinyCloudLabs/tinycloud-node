//! The one owner that retries a database operation (TC-2610).
//!
//! [`retry_owner`] runs one cancel-safe database operation (a transaction from
//! `BEGIN` to `COMMIT`, or an authorization read) and, when it failed with a
//! lost connection, runs it once more. Statements, `BEGIN`s and `COMMIT`s are
//! never retried on their own: an operation has one owner, one retry and one
//! bounded budget.
//!
//! The retry happens only when all of these hold:
//! 1. the failure is `connection_lost` or `io` ([`failure_kind`]);
//! 2. the write tracker proves nothing can have committed
//!    ([`Replay::Never`]), or the attempt is one autocommit idempotent
//!    statement ([`Replay::IdempotentStatement`]) that began no explicit
//!    transaction, so a lost `COMMIT` is never replayed;
//! 3. a [`RetryPolicy`] is configured and the budget has room for the backoff
//!    and a second attempt;
//! 4. the request deadline has not cut or latched the request and leaves room;
//! 5. no [`OverloadSignal`] is active.
//!
//! `request_timeout`, `pool_timeout`, `pool_closed`, `statement_timeout`,
//! serialization failures, uncertain commits and every other failure are
//! returned as they are.

use std::{
    future::Future,
    ops::RangeInclusive,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
};

use rand::Rng;
use sea_orm::DbErr;
use tokio::time::Instant;

use crate::{
    db_pool::{connection_error_class, WriteState, WRITE_MAY_HAVE_APPLIED},
    failure_diagnostic::{failure_kind, KIND_CONNECTION_LOST, KIND_IO},
    request_cancel::{self, RequestCancel},
    telemetry::{observe_db_connection_event, DbConnectionEvent},
};

/// How long every retry is suppressed after an overload signal.
pub const OVERLOAD_SUPPRESS: Duration = Duration::from_secs(30);

/// The budget of one operation: attempt 1, the backoff and attempt 2.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// The absolute bound from the owner's start. A retry starts only if
    /// `budget - elapsed - delay >= min_attempt`, and runs for at most the
    /// remainder.
    pub budget: Duration,
    /// The jittered backoff before the retry, in milliseconds.
    pub delay_ms: RangeInclusive<u64>,
    /// The least time worth giving a second attempt.
    pub min_attempt: Duration,
}

impl RetryPolicy {
    pub fn new(budget: Duration) -> Self {
        Self {
            budget,
            delay_ms: 100..=300,
            min_attempt: Duration::from_secs(1),
        }
    }
}

/// What the owner may assume about running the operation twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// A second run is only safe if nothing can have committed.
    Never,
    /// The attempt is ONE autocommit statement, with no explicit `BEGIN` or
    /// `COMMIT`, whose every write is a fixed-key `INSERT .. ON CONFLICT DO
    /// NOTHING` and whose result does not depend on whether it already ran.
    IdempotentStatement,
}

tokio::task_local! {
    /// Set while a [`retry_owner`] runs (attempts and backoff).
    static OWNER: ();
}

/// A path that continues after its caller's future is dropped refuses to
/// run inside a retry attempt: the owner's budget could not stop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachedInRetryAttempt(pub &'static str);

impl std::fmt::Display for DetachedInRetryAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} cannot run inside a database retry attempt", self.0)
    }
}

/// Call before spawning work that outlives the calling future.
pub fn refuse_in_retry_attempt(site: &'static str) -> Result<(), DetachedInRetryAttempt> {
    if OWNER.try_with(|_| ()).is_ok() {
        Err(DetachedInRetryAttempt(site))
    } else {
        Ok(())
    }
}

/// Source of milliseconds for the [`OverloadSignal`].
pub trait Clock: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
}

/// Milliseconds on tokio's clock, so paused time applies in tests.
pub struct TokioClock;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

impl Clock for TokioClock {
    fn now_ms(&self) -> u64 {
        EPOCH.elapsed().as_millis() as u64
    }
}

#[derive(Debug)]
struct OverloadState {
    until_ms: u64,
    active: bool,
}

/// What a [`OverloadSignal::stamp`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stamped {
    /// A new suppression period began (one start line, one watcher).
    Started,
    /// An active period was extended.
    Extended,
}

/// What the end watcher does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherStep {
    SleepFor(Duration),
    Done,
}

/// A process-wide marker: a request timeout, pool timeout or statement
/// timeout suppresses every retry for [`OVERLOAD_SUPPRESS`].
///
/// All transitions run under one mutex, so the expiry decision in
/// [`Self::watcher_step`] and a concurrent [`Self::stamp_at`] are ordered: a
/// stamp either extends the window before the watcher decides, or begins a new
/// period after the watcher ended the old one. One start line, one end line and
/// one watcher per period.
pub struct OverloadSignal {
    state: Mutex<OverloadState>,
    /// `until_ms`, written only under `state`, so it only grows.
    mirror: AtomicU64,
    clock: Box<dyn Clock>,
    suppress_ms: u64,
    starts: AtomicU64,
    ends: AtomicU64,
}

impl OverloadSignal {
    pub fn new(clock: impl Clock, suppress: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(OverloadState {
                until_ms: 0,
                active: false,
            }),
            mirror: AtomicU64::new(0),
            clock: Box::new(clock),
            suppress_ms: suppress.as_millis() as u64,
            starts: AtomicU64::new(0),
            ends: AtomicU64::new(0),
        })
    }

    /// Whether retries are suppressed now. Lock-free.
    pub fn is_suppressing(&self) -> bool {
        self.is_suppressing_at(self.clock.now_ms())
    }

    pub fn is_suppressing_at(&self, now_ms: u64) -> bool {
        now_ms < self.mirror.load(Ordering::Acquire)
    }

    /// Periods begun and ended so far.
    pub fn periods(&self) -> (u64, u64) {
        (
            self.starts.load(Ordering::SeqCst),
            self.ends.load(Ordering::SeqCst),
        )
    }

    /// The window end, for tests.
    pub fn until_ms(&self) -> u64 {
        self.state.lock().expect("overload state").until_ms
    }

    /// Apply a stamp at `now_ms`. Logs the start line on a new period.
    pub fn stamp_at(&self, class: &'static str, now_ms: u64) -> Stamped {
        let mut state = self.state.lock().expect("overload state");
        state.until_ms = state.until_ms.max(now_ms.saturating_add(self.suppress_ms));
        self.mirror.store(state.until_ms, Ordering::Release);
        if state.active {
            return Stamped::Extended;
        }
        state.active = true;
        self.starts.fetch_add(1, Ordering::SeqCst);
        tracing::warn!(
            error_class = class,
            suppress_ms = self.suppress_ms,
            "retries suppressed after a database overload signal"
        );
        Stamped::Started
    }

    /// One decision of the end watcher. Logs the end line when the window
    /// has passed.
    pub fn watcher_step(&self, now_ms: u64) -> WatcherStep {
        let mut state = self.state.lock().expect("overload state");
        if now_ms >= state.until_ms {
            state.active = false;
            self.ends.fetch_add(1, Ordering::SeqCst);
            tracing::info!(
                suppress_ms = self.suppress_ms,
                "retries resumed after a database overload signal"
            );
            return WatcherStep::Done;
        }
        WatcherStep::SleepFor(Duration::from_millis(state.until_ms - now_ms))
    }

    /// Stamp now and, on a new period, spawn its end watcher.
    pub fn stamp(self: &Arc<Self>, class: &'static str) {
        if self.stamp_at(class, self.clock.now_ms()) != Stamped::Started {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // No runtime to run a watcher: end the period at once rather
            // than leave it open with nobody to close it.
            let _ = self.watcher_step(u64::MAX);
            return;
        };
        let signal = Arc::clone(self);
        runtime.spawn(async move {
            while let WatcherStep::SleepFor(wait) = signal.watcher_step(signal.clock.now_ms()) {
                tokio::time::sleep(wait).await;
            }
        });
    }
}

#[cfg(not(test))]
static OVERLOAD: LazyLock<Arc<OverloadSignal>> =
    LazyLock::new(|| OverloadSignal::new(TokioClock, OVERLOAD_SUPPRESS));

tokio::task_local! {
    /// A test's own signal, so a timeout in one test never suppresses the
    /// retries another test expects.
    static ISOLATED: Arc<OverloadSignal>;
}

/// The signal in force: the process-wide one, or a test's own.
pub fn overload() -> Arc<OverloadSignal> {
    ISOLATED
        .try_with(Arc::clone)
        .unwrap_or_else(|_| process_signal())
}

#[cfg(not(test))]
fn process_signal() -> Arc<OverloadSignal> {
    Arc::clone(&OVERLOAD)
}

/// The unit tests of this crate share one process: a timeout in one must
/// not suppress the retries another expects, so outside an isolated scope
/// they get a signal nothing else sees.
#[cfg(test)]
fn process_signal() -> Arc<OverloadSignal> {
    OverloadSignal::new(TokioClock, OVERLOAD_SUPPRESS)
}

/// Run `future` with a fresh signal of its own instead of the process-wide
/// one. For tests that need retries while other tests time requests out.
#[cfg(any(test, feature = "test-util"))]
pub async fn isolate_overload<F: Future>(future: F) -> F::Output {
    ISOLATED
        .scope(OverloadSignal::new(TokioClock, OVERLOAD_SUPPRESS), future)
        .await
}

/// Run `future` with `signal` (built with a test [`Clock`]) instead of the
/// process-wide one.
#[cfg(any(test, feature = "test-util"))]
pub async fn with_overload_signal<F: Future>(signal: Arc<OverloadSignal>, future: F) -> F::Output {
    ISOLATED.scope(signal, future).await
}

/// Run `future` under `signal`: how a task spawned by an operation carries
/// the overload signal in force at its spawn.
pub(crate) async fn within_overload<F: Future>(
    signal: Arc<OverloadSignal>,
    future: F,
) -> F::Output {
    ISOLATED.scope(signal, future).await
}

/// Stamp the signal in force (a request timeout, pool timeout or statement
/// timeout was observed).
pub fn stamp_overload(class: &'static str) {
    overload().stamp(class);
}

/// Stamp the signal for a database failure that means the database is
/// slow: `pool_timeout` or `statement_timeout`.
pub fn note_failure(error: &DbErr) {
    note_failure_in(&overload(), error);
}

fn note_failure_in(signal: &Arc<OverloadSignal>, error: &DbErr) {
    let kind = failure_kind(error);
    if matches!(kind, "pool_timeout" | "statement_timeout") {
        signal.stamp(kind);
    }
}

/// Whether the request deadline leaves room for `need` more.
fn deadline_allows(context: Option<&RequestCancel>, need: Duration) -> bool {
    match context {
        None => true,
        Some(context) => {
            context.is_open()
                && context
                    .deadline()
                    .checked_duration_since(Instant::now())
                    .is_some_and(|left| left > need)
        }
    }
}

/// Run `attempt` (one cancel-safe database operation) and, if it qualifies,
/// once more. Returns the last result and whether a write may have applied
/// ([`classify_failure`](crate::db_pool::classify_failure)).
///
/// `attempt` may run twice: no external effect (object store, email, hook
/// delivery, network call) may run inside it. A nested owner runs its attempt
/// once under the outer owner, which alone decides.
pub async fn retry_owner<T, E, F, Fut>(
    operation: &'static str,
    policy: Option<RetryPolicy>,
    replay: Replay,
    attempt: F,
    db_error: impl Fn(&E) -> Option<&DbErr>,
) -> (Result<T, E>, bool)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    retry_owner_in(&overload(), operation, policy, replay, attempt, db_error).await
}

pub(crate) async fn retry_owner_in<T, E, F, Fut>(
    overload: &Arc<OverloadSignal>,
    operation: &'static str,
    policy: Option<RetryPolicy>,
    replay: Replay,
    mut attempt: F,
    db_error: impl Fn(&E) -> Option<&DbErr>,
) -> (Result<T, E>, bool)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    if OWNER.try_with(|_| ()).is_ok() {
        let result = attempt().await;
        let applied = WRITE_MAY_HAVE_APPLIED
            .try_with(|state| state.applied())
            .unwrap_or(false);
        return (result, applied);
    }
    OWNER
        .scope((), async {
            let started = Instant::now();
            let first_state = Arc::new(WriteState::default());
            let result = WRITE_MAY_HAVE_APPLIED
                .scope(Arc::clone(&first_state), attempt())
                .await;
            let first_applied = first_state.applied();

            let error_class = match &result {
                Err(error) => db_error(error).and_then(|error| {
                    note_failure_in(overload, error);
                    matches!(failure_kind(error), KIND_CONNECTION_LOST | KIND_IO)
                        .then(|| connection_error_class(error).unwrap_or("other"))
                }),
                Ok(_) => None,
            };
            let Some(error_class) = error_class else {
                return (result, first_applied);
            };
            let replayable = match replay {
                Replay::Never => !first_applied,
                Replay::IdempotentStatement => !first_state.explicit_transaction(),
            };
            let Some(policy) = policy.filter(|_| replayable) else {
                return (result, first_applied);
            };
            if overload.is_suppressing() {
                observe_db_connection_event(DbConnectionEvent::OperationRetrySkippedOverload);
                tracing::warn!(
                    operation,
                    error_class,
                    "not retrying operation: retries are suppressed after a database overload signal"
                );
                return (result, first_applied);
            }
            let delay = Duration::from_millis(rand::thread_rng().gen_range(policy.delay_ms.clone()));
            let remaining = policy
                .budget
                .checked_sub(started.elapsed() + delay)
                .filter(|remaining| *remaining >= policy.min_attempt);
            let Some(remaining) = remaining else {
                observe_db_connection_event(DbConnectionEvent::OperationRetrySkippedSlow);
                tracing::warn!(
                    operation,
                    error_class,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    retry_window_ms = policy.budget.as_millis() as u64,
                    "not retrying operation: its first run took longer than the retry window to fail"
                );
                return (result, first_applied);
            };
            let context = request_cancel::current();
            if !deadline_allows(context.as_deref(), delay + remaining) {
                observe_db_connection_event(DbConnectionEvent::OperationRetrySkippedDeadline);
                tracing::warn!(
                    operation,
                    error_class,
                    "not retrying operation: the request deadline leaves no room"
                );
                return (result, first_applied);
            }
            observe_db_connection_event(DbConnectionEvent::OperationRetried);
            // Never the statement text or its values (TC-961).
            tracing::warn!(
                operation,
                error_class,
                "retrying operation after a lost database connection"
            );
            tokio::time::sleep(delay).await;
            if !deadline_allows(context.as_deref(), remaining) {
                observe_db_connection_event(DbConnectionEvent::OperationRetrySkippedDeadline);
                tracing::warn!(
                    operation,
                    error_class,
                    "not retrying operation: the request deadline leaves no room"
                );
                return (result, first_applied);
            }
            let second_state = Arc::new(WriteState::default());
            let second = tokio::time::timeout(
                remaining,
                WRITE_MAY_HAVE_APPLIED.scope(Arc::clone(&second_state), attempt()),
            )
            .await;
            match second {
                Ok(second) => {
                    if second.is_ok() {
                        observe_db_connection_event(DbConnectionEvent::OperationRetrySucceeded);
                        tracing::info!(operation, "operation succeeded on its retry");
                    } else if let Err(error) = &second {
                        if let Some(error) = db_error(error) {
                            note_failure_in(overload, error);
                        }
                    }
                    (second, second_state.applied())
                }
                Err(_) => {
                    // The attempt's future is dropped. A statement already
                    // on the wire is recorded by the in-flight guard.
                    observe_db_connection_event(DbConnectionEvent::OperationRetryBudgetExpired);
                    tracing::warn!(
                        operation,
                        error_class,
                        retry_window_ms = policy.budget.as_millis() as u64,
                        "retry attempt stopped: the operation budget expired"
                    );
                    (result, first_applied || second_state.applied())
                }
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_pool::{note_transaction_began, note_write_outcome_for_tests};
    use sea_orm::error::{ConnAcquireErr, RuntimeErr, SqlxError};
    use std::{
        io,
        sync::atomic::{AtomicBool, AtomicUsize},
    };

    #[derive(Clone, Default)]
    struct ManualClock(Arc<AtomicU64>);

    impl ManualClock {
        fn set(&self, ms: u64) {
            self.0.store(ms, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn lost() -> DbErr {
        DbErr::Query(RuntimeErr::SqlxError(SqlxError::Io(io::Error::from(
            io::ErrorKind::ConnectionReset,
        ))))
    }

    fn lost_conn() -> DbErr {
        DbErr::Conn(RuntimeErr::SqlxError(SqlxError::WorkerCrashed))
    }

    fn policy() -> Option<RetryPolicy> {
        Some(RetryPolicy::new(Duration::from_secs(10)))
    }

    fn quiet() -> Arc<OverloadSignal> {
        OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS)
    }

    async fn run(
        replay: Replay,
        policy: Option<RetryPolicy>,
        attempts: &AtomicUsize,
        body: impl Fn(usize) -> Result<(), DbErr>,
    ) -> (Result<(), DbErr>, bool) {
        let body = &body;
        retry_owner_in(
            &quiet(),
            "test",
            policy,
            replay,
            || {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                // The body runs when the attempt is polled, inside the
                // tracker scope, like a real operation.
                async move { body(n) }
            },
            |error: &DbErr| Some(error),
        )
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn lost_connection_before_any_write_is_retried_once() {
        for error in [lost as fn() -> DbErr, lost_conn] {
            let attempts = AtomicUsize::new(0);
            let (result, applied) = run(Replay::Never, policy(), &attempts, |n| {
                if n == 0 {
                    Err(error())
                } else {
                    Ok(())
                }
            })
            .await;
            assert!(result.is_ok());
            assert!(!applied);
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_failure_is_returned_with_no_third_run() {
        let attempts = AtomicUsize::new(0);
        let (result, _) = run(Replay::Never, policy(), &attempts, |_| Err(lost())).await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_retried_once_a_write_may_have_applied() {
        enum Applied {
            TransactionBegan,
            WriteAcknowledged,
            WriteLostItsConnection,
            CommitLost,
        }
        for how in [
            Applied::TransactionBegan,
            Applied::WriteAcknowledged,
            Applied::WriteLostItsConnection,
            Applied::CommitLost,
        ] {
            let attempts = AtomicUsize::new(0);
            let (result, applied) = run(Replay::Never, policy(), &attempts, |_| {
                match how {
                    Applied::TransactionBegan | Applied::CommitLost => note_transaction_began(),
                    Applied::WriteAcknowledged => {
                        note_write_outcome_for_tests(&Ok::<(), DbErr>(()))
                    }
                    Applied::WriteLostItsConnection => {
                        note_write_outcome_for_tests(&Err::<(), _>(lost()))
                    }
                }
                Err(lost())
            })
            .await;
            assert!(result.is_err());
            assert!(applied);
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
    }

    #[derive(Debug)]
    struct ServerError(&'static str);

    impl std::fmt::Display for ServerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "server error {}", self.0)
        }
    }

    impl std::error::Error for ServerError {}

    impl sea_orm::sqlx::error::DatabaseError for ServerError {
        fn message(&self) -> &str {
            "server error"
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(std::borrow::Cow::Borrowed(self.0))
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sea_orm::sqlx::error::ErrorKind {
            sea_orm::sqlx::error::ErrorKind::Other
        }
    }

    /// A statement timeout (57014), a serialization failure (40001), a
    /// deadlock (40P01) and a unique violation (23505) are the server's
    /// answers, not lost connections: under an enabled policy each runs once
    /// and is returned, and nothing is reported as possibly applied.
    #[tokio::test(start_paused = true)]
    async fn server_refusals_are_not_retried_under_an_enabled_policy() {
        assert!(policy().is_some(), "the policy and its budget are on");
        for code in ["57014", "40001", "40P01", "23505"] {
            for wrap in [
                (|e| DbErr::Query(RuntimeErr::SqlxError(e))) as fn(SqlxError) -> DbErr,
                |e| DbErr::Exec(RuntimeErr::SqlxError(e)),
            ] {
                let attempts = AtomicUsize::new(0);
                let (result, applied) = run(Replay::Never, policy(), &attempts, |_| {
                    Err(wrap(SqlxError::Database(Box::new(ServerError(code)))))
                })
                .await;
                assert!(result.is_err(), "{code}");
                assert!(!applied, "{code}");
                assert_eq!(attempts.load(Ordering::SeqCst), 1, "{code}: no retry");
                // The idempotent path does not retry them either.
                let attempts = AtomicUsize::new(0);
                let (result, _) = run(Replay::IdempotentStatement, policy(), &attempts, |_| {
                    Err(wrap(SqlxError::Database(Box::new(ServerError(code)))))
                })
                .await;
                assert!(result.is_err(), "{code}");
                assert_eq!(attempts.load(Ordering::SeqCst), 1, "{code}: idempotent");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn only_lost_connections_are_retried() {
        let failures: Vec<fn() -> DbErr> = vec![
            || DbErr::ConnectionAcquire(ConnAcquireErr::Timeout),
            || DbErr::Conn(RuntimeErr::SqlxError(SqlxError::PoolTimedOut)),
            || DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed),
            || DbErr::Conn(RuntimeErr::SqlxError(SqlxError::PoolClosed)),
            || DbErr::RecordNotFound("row".into()),
            || DbErr::Custom("other".into()),
        ];
        for failure in failures {
            let attempts = AtomicUsize::new(0);
            let (result, applied) =
                run(Replay::Never, policy(), &attempts, |_| Err(failure())).await;
            assert!(result.is_err());
            assert!(!applied);
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
        // A failure that is not a database error at all.
        let attempts = AtomicUsize::new(0);
        let (result, _) = retry_owner_in(
            &quiet(),
            "test",
            policy(),
            Replay::Never,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>("lock wait") }
            },
            |_: &&str| None,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_policy_nothing_is_retried() {
        let attempts = AtomicUsize::new(0);
        let (result, _) = run(Replay::Never, None, &attempts, |_| Err(lost())).await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_run_that_used_the_budget_is_not_retried() {
        let attempts = AtomicUsize::new(0);
        let policy = RetryPolicy::new(Duration::from_secs(10));
        for (first_run, expected) in [
            (Duration::ZERO, 2),
            (Duration::from_secs(5), 2),
            (Duration::from_secs(9), 1),
        ] {
            attempts.store(0, Ordering::SeqCst);
            let (result, _) = retry_owner_in(
                &quiet(),
                "test",
                Some(policy.clone()),
                Replay::Never,
                || {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if n == 0 {
                            tokio::time::sleep(first_run).await;
                            Err(lost())
                        } else {
                            Ok(())
                        }
                    }
                },
                |error: &DbErr| Some(error),
            )
            .await;
            assert_eq!(result.is_ok(), expected == 2, "{first_run:?}");
            assert_eq!(attempts.load(Ordering::SeqCst), expected, "{first_run:?}");
        }
    }

    /// Attempt 2 that outlasts the remaining budget is dropped: its later
    /// statements never run, attempt 1's error is returned, no third run, and
    /// a write it had on the wire is reported as possibly applied.
    #[tokio::test(start_paused = true)]
    async fn a_retry_that_outlasts_the_budget_is_stopped() {
        for write_in_flight in [false, true] {
            let attempts = AtomicUsize::new(0);
            let after_pause = AtomicBool::new(false);
            let (result, applied) = retry_owner_in(
                &quiet(),
                "test",
                policy(),
                Replay::Never,
                || {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    let after_pause = &after_pause;
                    async move {
                        if n == 0 {
                            return Err(lost());
                        }
                        let guard = write_in_flight.then(crate::db_pool::arm_in_flight_write);
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        after_pause.store(true, Ordering::SeqCst);
                        drop(guard);
                        Ok(())
                    }
                },
                |error: &DbErr| Some(error),
            )
            .await;
            assert!(matches!(result, Err(DbErr::Query(_))), "attempt 1's error");
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
            assert!(!after_pause.load(Ordering::SeqCst), "the attempt stopped");
            assert_eq!(applied, write_in_flight);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_cut_or_latched_request_is_not_retried_and_a_cut_during_backoff_skips_attempt_2() {
        let attempts = AtomicUsize::new(0);
        let context = RequestCancel::new(Duration::from_secs(60));
        request_cancel::within(Some(context.clone()), async {
            assert!(context.latch());
            let (result, _) = run(Replay::Never, policy(), &attempts, |_| Err(lost())).await;
            assert!(result.is_err());
        })
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "latched");

        attempts.store(0, Ordering::SeqCst);
        let context = RequestCancel::new(Duration::from_secs(60));
        request_cancel::within(Some(context.clone()), async {
            assert!(context.cut());
            let (result, _) = run(Replay::Never, policy(), &attempts, |_| Err(lost())).await;
            assert!(result.is_err());
        })
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "cut");

        // Cut while the owner sleeps its backoff: attempt 2 never starts.
        attempts.store(0, Ordering::SeqCst);
        let context = RequestCancel::new(Duration::from_secs(60));
        let cutter = context.clone();
        request_cancel::within(Some(context), async {
            let owner = run(Replay::Never, policy(), &attempts, |_| Err(lost()));
            let cut = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert!(cutter.cut());
            };
            let ((result, _), ()) = tokio::join!(owner, cut);
            assert!(result.is_err());
        })
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "cut during backoff");

        // Deadline too close for the backoff plus the bounded attempt.
        attempts.store(0, Ordering::SeqCst);
        let context = RequestCancel::new(Duration::from_secs(5));
        request_cancel::within(Some(context), async {
            let (result, _) = run(Replay::Never, policy(), &attempts, |_| Err(lost())).await;
            assert!(result.is_err());
        })
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "no room");

        // A background task has no deadline: the budget alone bounds it.
        attempts.store(0, Ordering::SeqCst);
        let (result, _) = run(Replay::Never, policy(), &attempts, |n| {
            if n == 0 {
                Err(lost())
            } else {
                Ok(())
            }
        })
        .await;
        assert!(result.is_ok());
    }

    /// One retry in total across outer and inner owners.
    #[tokio::test(start_paused = true)]
    async fn nested_owners_share_one_retry() {
        let outer = AtomicUsize::new(0);
        let inner = AtomicUsize::new(0);
        let signal = quiet();
        let (result, _) = retry_owner_in(
            &signal,
            "outer",
            policy(),
            Replay::Never,
            || {
                outer.fetch_add(1, Ordering::SeqCst);
                let signal = &signal;
                let inner = &inner;
                async move {
                    let (result, _) = retry_owner_in(
                        signal,
                        "inner",
                        policy(),
                        Replay::Never,
                        || {
                            inner.fetch_add(1, Ordering::SeqCst);
                            async { Err::<(), _>(lost()) }
                        },
                        |error: &DbErr| Some(error),
                    )
                    .await;
                    result
                }
            },
            |error: &DbErr| Some(error),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(outer.load(Ordering::SeqCst), 2);
        assert_eq!(
            inner.load(Ordering::SeqCst),
            2,
            "one retry in total: the inner ran once per outer run, never retried alone"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idempotent_statement_replays_an_applied_autocommit_write_only() {
        let attempts = AtomicUsize::new(0);
        let (result, _) = run(Replay::IdempotentStatement, policy(), &attempts, |n| {
            if n == 0 {
                note_write_outcome_for_tests(&Err::<(), _>(lost()));
                Err(lost())
            } else {
                Ok(())
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // Not for other failures.
        attempts.store(0, Ordering::SeqCst);
        let (result, _) = run(Replay::IdempotentStatement, policy(), &attempts, |_| {
            Err(DbErr::ConnectionAcquire(ConnAcquireErr::Timeout))
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// A lost `COMMIT` is never replayed, even on the idempotent path.
    #[tokio::test(start_paused = true)]
    async fn idempotent_statement_never_replays_a_lost_commit() {
        let attempts = AtomicUsize::new(0);
        let (result, applied) = run(Replay::IdempotentStatement, policy(), &attempts, |_| {
            note_transaction_began();
            Err(lost())
        })
        .await;
        assert!(result.is_err());
        assert!(applied);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_are_suppressed_while_an_overload_signal_is_active() {
        let clock = ManualClock::default();
        let signal = OverloadSignal::new(clock.clone(), OVERLOAD_SUPPRESS);
        clock.set(1_000);
        signal.stamp("request_timeout");
        let attempts = AtomicUsize::new(0);
        // Inside the window: not retried.
        clock.set(1_000 + 29_999);
        let (result, _) = run_with(&signal, Replay::Never, &attempts).await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        // The same error after the window is retried.
        attempts.store(0, Ordering::SeqCst);
        clock.set(1_000 + 30_000);
        let (result, _) = run_with(&signal, Replay::Never, &attempts).await;
        assert!(result.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // The owner itself stamps on a timeout it sees.
        let attempts = AtomicUsize::new(0);
        let fresh = OverloadSignal::new(clock.clone(), OVERLOAD_SUPPRESS);
        let (_, _) = retry_owner_in(
            &fresh,
            "test",
            policy(),
            Replay::Never,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(DbErr::ConnectionAcquire(ConnAcquireErr::Timeout)) }
            },
            |error: &DbErr| Some(error),
        )
        .await;
        assert!(fresh.is_suppressing());
        let idempotent = AtomicUsize::new(0);
        let (result, _) = run_with(&fresh, Replay::IdempotentStatement, &idempotent).await;
        assert!(result.is_err());
        assert_eq!(idempotent.load(Ordering::SeqCst), 1);
    }

    async fn run_with(
        signal: &Arc<OverloadSignal>,
        replay: Replay,
        attempts: &AtomicUsize,
    ) -> (Result<(), DbErr>, bool) {
        retry_owner_in(
            signal,
            "test",
            policy(),
            replay,
            || {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(lost())
                    } else {
                        Ok(())
                    }
                }
            },
            |error: &DbErr| Some(error),
        )
        .await
    }

    #[test]
    fn stamping_extends_a_window_and_never_shortens_it() {
        let signal = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
        assert_eq!(signal.stamp_at("request_timeout", 5_000), Stamped::Started);
        assert_eq!(signal.stamp_at("pool_timeout", 3_000), Stamped::Extended);
        assert_eq!(signal.until_ms(), 35_000, "an older stamp does not shorten");
        assert_eq!(signal.stamp_at("pool_timeout", 9_000), Stamped::Extended);
        assert_eq!(signal.until_ms(), 39_000);
        assert!(signal.is_suppressing_at(38_999));
        assert!(!signal.is_suppressing_at(39_000));
        assert_eq!(signal.periods(), (1, 0));
    }

    #[test]
    fn extend_then_step_is_one_period() {
        let signal = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
        signal.stamp_at("request_timeout", 0);
        assert_eq!(
            signal.watcher_step(29_900),
            WatcherStep::SleepFor(Duration::from_millis(100))
        );
        assert_eq!(signal.stamp_at("pool_timeout", 29_900), Stamped::Extended);
        assert_eq!(
            signal.watcher_step(30_000),
            WatcherStep::SleepFor(Duration::from_millis(29_900))
        );
        assert_eq!(signal.watcher_step(59_900), WatcherStep::Done);
        assert_eq!(signal.periods(), (1, 1));
    }

    #[test]
    fn step_then_stamp_is_two_periods_never_overlapping() {
        let signal = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
        signal.stamp_at("request_timeout", 0);
        assert_eq!(signal.watcher_step(30_000), WatcherStep::Done);
        assert_eq!(signal.periods(), (1, 1));
        assert_eq!(signal.stamp_at("request_timeout", 30_000), Stamped::Started);
        assert_eq!(signal.periods(), (2, 1));
        assert_eq!(signal.watcher_step(60_000), WatcherStep::Done);
        assert_eq!(signal.periods(), (2, 2));
    }

    #[test]
    fn expiry_versus_stamp_has_one_start_per_period_in_both_orders() {
        // Stamp lands before the watcher's decision: the window moves, the
        // watcher keeps sleeping, no second start.
        let a = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
        a.stamp_at("request_timeout", 0);
        assert_eq!(a.stamp_at("request_timeout", 30_000), Stamped::Extended);
        assert!(matches!(a.watcher_step(30_000), WatcherStep::SleepFor(_)));
        assert_eq!(a.periods(), (1, 0));
        // Watcher decides first: the stamp opens a second period.
        let b = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
        b.stamp_at("request_timeout", 0);
        assert_eq!(b.watcher_step(30_000), WatcherStep::Done);
        assert_eq!(b.stamp_at("request_timeout", 30_000), Stamped::Started);
        assert_eq!(b.periods(), (2, 1));
    }

    #[test]
    fn every_stamp_order_leaves_the_latest_window() {
        let times = [5_000u64, 3_000, 9_000, 7_000];
        let mut order = [0usize, 1, 2, 3];
        let mut seen = 0;
        permute(&mut order, 0, &mut |order| {
            let signal = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
            for &i in order {
                signal.stamp_at("request_timeout", times[i]);
            }
            assert_eq!(signal.until_ms(), 9_000 + 30_000, "{order:?}");
            assert!(signal.is_suppressing_at(38_999));
            assert!(!signal.is_suppressing_at(39_000));
            assert_eq!(signal.periods(), (1, 0));
            seen += 1;
        });
        assert_eq!(seen, 24);
    }

    fn permute(order: &mut [usize; 4], k: usize, visit: &mut impl FnMut(&[usize; 4])) {
        if k == order.len() {
            visit(order);
            return;
        }
        for i in k..order.len() {
            order.swap(k, i);
            permute(order, k + 1, visit);
            order.swap(k, i);
        }
    }

    #[test]
    fn concurrent_stamps_leave_the_latest_window_and_one_start() {
        let signal = OverloadSignal::new(ManualClock::default(), OVERLOAD_SUPPRESS);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = [5_000u64, 3_000, 9_000, 7_000, 1_000, 8_000, 2_000, 6_000]
            .into_iter()
            .map(|at| {
                let (signal, barrier) = (Arc::clone(&signal), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    signal.stamp_at("request_timeout", at)
                })
            })
            .collect();
        let started = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|stamped| *stamped == Stamped::Started)
            .count();
        assert_eq!(started, 1);
        assert_eq!(signal.until_ms(), 9_000 + 30_000);
        assert_eq!(signal.periods(), (1, 0));
    }

    /// The spawned watcher logs the end of an idle period exactly once.
    #[tokio::test(start_paused = true)]
    async fn the_end_watcher_closes_the_period_even_when_idle() {
        let signal = OverloadSignal::new(TokioClock, OVERLOAD_SUPPRESS);
        signal.stamp("request_timeout");
        assert_eq!(signal.periods(), (1, 0));
        tokio::time::sleep(Duration::from_secs(10)).await;
        signal.stamp("pool_timeout");
        assert_eq!(signal.periods(), (1, 0), "an extension is no new start");
        tokio::time::sleep(Duration::from_secs(29)).await;
        assert_eq!(signal.periods(), (1, 0), "still inside the extended window");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(signal.periods(), (1, 1));
        assert!(!signal.is_suppressing());
    }

    #[tokio::test]
    async fn detached_paths_are_refused_inside_a_retry_attempt() {
        assert_eq!(refuse_in_retry_attempt("site"), Ok(()));
        let spawned = AtomicUsize::new(0);
        let attempts = AtomicUsize::new(0);
        let (result, _) = retry_owner_in(
            &quiet(),
            "test",
            policy(),
            Replay::Never,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                let spawned = &spawned;
                async move {
                    refuse_in_retry_attempt("run_locked")
                        .map_err(|e| DbErr::Custom(e.to_string()))?;
                    spawned.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), DbErr>(())
                }
            },
            |error: &DbErr| Some(error),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(spawned.load(Ordering::SeqCst), 0, "nothing was spawned");
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "and it is not retried");
    }
}
