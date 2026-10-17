//! Request-local, data-free timing at SQL and pool acquisition boundaries.
//!
//! A scope installs its context for each poll, not for the lifetime of a future,
//! so unrelated tasks and migrated futures cannot inherit another request's
//! counters. Drivers with worker threads must explicitly propagate [`current`]
//! and [`enter`] at their command boundary. Detached cleanup and pool connection
//! initialization/health checks are deliberately not request SQL. The paired
//! PostgreSQL/SQLite driver patches cover raw transaction controls even when
//! SeaORM calls their transaction managers directly.

use std::cell::RefCell;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use pin_project::pin_project;

thread_local! {
    static CURRENT: RefCell<Option<Arc<Metrics>>> = const { RefCell::new(None) };
}

/// Data-free counters shared only by work belonging to one request.
#[derive(Default)]
pub struct Metrics {
    pool_wait_ns: AtomicU64,
    query_time_ns: AtomicU64,
    query_count: AtomicU64,
}

/// Numeric request totals. Durations are nanoseconds, never inferred aggregates.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Actual acquisition elapsed time, including failed/cancelled waits and setup.
    pub pool_wait_ns: u64,
    /// Driver execution elapsed time; excludes acquisition, not database CPU time.
    pub query_time_ns: u64,
    /// Execution attempts, including failed attempts and awaited transaction controls.
    pub query_count: u64,
}

impl Metrics {
    /// Add completed numeric work; shared batches are non-additive across requests.
    pub fn accumulate(&self, snapshot: Snapshot) {
        self.pool_wait_ns
            .fetch_add(snapshot.pool_wait_ns, Ordering::Relaxed);
        self.query_time_ns
            .fetch_add(snapshot.query_time_ns, Ordering::Relaxed);
        self.query_count
            .fetch_add(snapshot.query_count, Ordering::Relaxed);
    }

    /// Read the current counters; completed worker commands publish before reply.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            pool_wait_ns: self.pool_wait_ns.load(Ordering::Relaxed),
            query_time_ns: self.query_time_ns.load(Ordering::Relaxed),
            query_count: self.query_count.load(Ordering::Relaxed),
        }
    }
}

/// Return the context installed for the currently executing poll or worker command.
pub fn current() -> Option<Arc<Metrics>> {
    CURRENT.with(|current| current.borrow().clone())
}

/// A synchronous context guard. It must be dropped on the thread that entered it.
pub struct EnterGuard {
    previous: Option<Arc<Metrics>>,
    _not_send: PhantomData<Rc<()>>,
}

/// Install a context until the returned guard drops. Never hold it across await.
pub fn enter(metrics: Option<Arc<Metrics>>) -> EnterGuard {
    let previous = CURRENT.with(|current| current.replace(metrics));
    EnterGuard {
        previous,
        _not_send: PhantomData,
    }
}

impl Drop for EnterGuard {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
    }
}

/// A future which restores thread-local state after every individual poll.
#[pin_project]
pub struct Scope<F> {
    metrics: Option<Arc<Metrics>>,
    #[pin]
    future: F,
}

/// Attribute work polled by `future` to `metrics`, without allocating a pinned box.
pub fn scope<F: Future>(metrics: Arc<Metrics>, future: F) -> Scope<F> {
    Scope {
        metrics: Some(metrics),
        future,
    }
}

pub(crate) fn unscoped<F: Future>(future: F) -> Scope<F> {
    Scope {
        metrics: None,
        future,
    }
}

impl<F: Future> Future for Scope<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let _guard = enter(this.metrics.clone());
        this.future.poll(cx)
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Records exactly one attempted query when dropped, including failure/cancellation.
///
/// The captured context never changes. Pausing excludes result formatting between
/// separate synchronous database calls without turning them into extra queries.
pub struct QueryTimer {
    metrics: Option<Arc<Metrics>>,
    started: Option<Instant>,
    elapsed: Duration,
}

impl QueryTimer {
    /// Capture the current context and begin measuring execution.
    pub fn new() -> Self {
        let metrics = current();
        let started = metrics.as_ref().map(|_| Instant::now());
        Self {
            metrics,
            started,
            elapsed: Duration::ZERO,
        }
    }

    /// Stop measuring until resumed; repeated pauses are harmless.
    pub fn pause(&mut self) {
        if let Some(started) = self.started.take() {
            self.elapsed = self.elapsed.saturating_add(started.elapsed());
        }
    }

    /// Resume measuring using the originally captured context, if any.
    pub fn resume(&mut self) {
        if self.metrics.is_some() && self.started.is_none() {
            self.started = Some(Instant::now());
        }
    }
}

impl Default for QueryTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for QueryTimer {
    fn drop(&mut self) {
        self.pause();
        if let Some(metrics) = &self.metrics {
            metrics
                .query_time_ns
                .fetch_add(nanos(self.elapsed), Ordering::Relaxed);
            metrics.query_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Measures a real pool acquisition, including errors and cancelled waits.
pub struct PoolTimer {
    captured: Option<(Arc<Metrics>, Instant)>,
}

impl PoolTimer {
    /// Capture the request before any acquisition validation or waiting.
    pub fn new() -> Self {
        Self {
            captured: current().map(|metrics| (metrics, Instant::now())),
        }
    }
}

impl Default for PoolTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PoolTimer {
    fn drop(&mut self) {
        if let Some((metrics, started)) = &self.captured {
            metrics
                .pool_wait_ns
                .fetch_add(nanos(started.elapsed()), Ordering::Relaxed);
        }
    }
}
