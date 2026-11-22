//! The uploader's run loop: per-DB in-flight serialisation and the
//! timer tick that drives `publish_cycle` across the dirty set.
//!
//! One run loop per node. It owns:
//!
//! - A `DashMap<(space, db_id), Mutex<DbState>>` of per-database state.
//!   The `Mutex` is the `in_flight` primitive from 1b-design §2: at most
//!   one cycle per database runs at a time, and a duplicate cycle in
//!   the same process is impossible.
//! - A node-wide semaphore bounding the number of cycles in flight
//!   across all databases (default 8).
//! - A node-wide PG semaphore bounding the manifest's Postgres
//!   concurrency (default 2 per `pg_concurrency`).
//! - A timer that wakes every `tick` and evaluates `UploadPolicy::due`
//!   per dirty DB.
//!
//! The loop is intentionally thin: it decides which DBs are due, takes
//! the per-DB lock, and hands one `Cycle` to `publish_cycle`. The
//! backoff and breaker land as a sibling module; the planner + spool
//! produce the `Cycle`; this module stitches them together.
//!
//! Not in this commit: the Rocket fairing glue, the capture-hook ingress
//! that marks a DB dirty, the real spool, and the backoff/breaker. Each
//! lands in its own commit on the same branch.
//!
//! TC-1491.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{Mutex, Semaphore};

use super::state::DbState;

/// How the run loop names a database it is driving. Owned strings, so
/// the map can live past the borrow of any one request.
pub type DbKey = (String, String);

/// What `select_due` returns: the keys of databases the uploader should
/// try to publish on this tick.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DueSet {
    pub keys: Vec<DbKey>,
}

/// The policy the run loop reads to decide which DBs are due. Mirrors
/// `UploadPolicy::due` from `shadow::state` but is kept as a thin
/// closure here so tests can substitute a deterministic predicate.
pub trait IsDue: Send + Sync {
    fn is_due(&self, state: &DbState, now: Instant) -> bool;
}

impl<F: Fn(&DbState, Instant) -> bool + Send + Sync> IsDue for F {
    fn is_due(&self, state: &DbState, now: Instant) -> bool {
        (self)(state, now)
    }
}

/// The run loop's shared state: the per-DB map, the node-wide and
/// Postgres semaphores, and the allowlist.
pub struct RunState {
    pub states: DashMap<DbKey, Mutex<DbState>>,
    pub node_concurrency: Semaphore,
    pub pg_concurrency: Semaphore,
    pub allowlist: BTreeSet<String>,
}

impl RunState {
    pub fn new(
        node_concurrency: usize,
        pg_concurrency: usize,
        allowlist: BTreeSet<String>,
    ) -> Self {
        Self {
            states: DashMap::new(),
            node_concurrency: Semaphore::new(node_concurrency),
            pg_concurrency: Semaphore::new(pg_concurrency),
            allowlist,
        }
    }

    /// Insert or update the state for one database. Used by the capture
    /// hook's ingress (upcoming commit) and the catch-up sweep's
    /// needs_bootstrap marks.
    pub async fn upsert<F>(&self, key: DbKey, apply: F)
    where
        F: FnOnce(&mut DbState),
    {
        let entry = self
            .states
            .entry(key)
            .or_insert_with(|| Mutex::new(DbState::default()));
        let mut st = entry.lock().await;
        apply(&mut st);
    }
}

/// Scan every tracked database, read each state under the per-DB lock
/// (non-blocking: skip if a cycle is already in flight), and return the
/// due set. The caller then picks up each due key, re-takes the lock,
/// builds a `Cycle` from the state, and runs `publish_cycle`.
///
/// The non-blocking `try_lock` is what keeps the run loop from fighting
/// a per-DB in-flight cycle for its own lock. If a database is in
/// flight, this tick skips it; the next tick re-evaluates.
pub fn select_due<P: IsDue>(state: &RunState, policy: &P, now: Instant) -> DueSet {
    let mut keys = Vec::new();
    for entry in state.states.iter() {
        if !state.allowlist.contains(&entry.key().0) {
            continue;
        }
        let Ok(st) = entry.value().try_lock() else {
            continue;
        };
        if policy.is_due(&st, now) {
            keys.push(entry.key().clone());
        }
    }
    DueSet { keys }
}

/// Node-concurrency wrapper around one cycle's `publish_cycle` call.
/// Acquires both the node-wide and the Postgres semaphore (in that
/// order, to avoid the PG pool starving the node pool). Drops both
/// permits on return.
pub async fn run_cycle<F, O>(state: &Arc<RunState>, cycle: F) -> O
where
    F: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = O> + Send>>,
{
    let _node = state
        .node_concurrency
        .acquire()
        .await
        .expect("node semaphore never closes");
    let _pg = state
        .pg_concurrency
        .acquire()
        .await
        .expect("pg semaphore never closes");
    cycle().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn allowed(space: &str) -> BTreeSet<String> {
        [space.to_string()].into_iter().collect()
    }

    #[tokio::test]
    async fn select_due_returns_only_allowlisted_due_databases() {
        let state = RunState::new(8, 2, allowed("space-a"));
        state
            .upsert(("space-a".into(), "a".into()), |st| {
                st.first_dirty_at = Some(Instant::now())
            })
            .await;
        state
            .upsert(("space-a".into(), "b".into()), |st| {
                st.first_dirty_at = None
            })
            .await;
        state
            .upsert(("space-b".into(), "c".into()), |st| {
                st.first_dirty_at = Some(Instant::now())
            })
            .await;

        let policy = |st: &DbState, _now: Instant| st.first_dirty_at.is_some();
        let due = select_due(&state, &policy, Instant::now());
        assert_eq!(due.keys.len(), 1);
        assert_eq!(due.keys[0].0, "space-a");
        assert_eq!(due.keys[0].1, "a");
    }

    #[tokio::test]
    async fn select_due_skips_databases_whose_lock_is_held() {
        let state = RunState::new(8, 2, allowed("space-a"));
        state
            .upsert(("space-a".into(), "a".into()), |st| {
                st.first_dirty_at = Some(Instant::now())
            })
            .await;
        let entry = state.states.get(&("space-a".into(), "a".into())).unwrap();
        let held = entry.value().try_lock().ok();
        assert!(held.is_some(), "setup: the lock should be free");
        let _held = held.unwrap();
        let policy = |_: &DbState, _now: Instant| true;
        let due = select_due(&state, &policy, Instant::now());
        assert!(due.keys.is_empty(), "the held DB must not be due");
    }

    #[tokio::test]
    async fn run_cycle_bounds_node_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let state = Arc::new(RunState::new(2, 10, allowed("space-a")));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let state = state.clone();
            let in_flight = in_flight.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                run_cycle(&state, move || {
                    Box::pin(async move {
                        let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    })
                })
                .await
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "node concurrency cap violated: peak={}",
            peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn run_cycle_bounds_pg_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Node concurrency high, PG cap low: PG cap must bind.
        let state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        let pg_in_flight = Arc::new(AtomicUsize::new(0));
        let pg_peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let state = state.clone();
            let pg_in_flight = pg_in_flight.clone();
            let pg_peak = pg_peak.clone();
            handles.push(tokio::spawn(async move {
                run_cycle(&state, move || {
                    Box::pin(async move {
                        let n = pg_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        pg_peak.fetch_max(n, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        pg_in_flight.fetch_sub(1, Ordering::SeqCst);
                    })
                })
                .await
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            pg_peak.load(Ordering::SeqCst) <= 2,
            "pg concurrency cap violated: peak={}",
            pg_peak.load(Ordering::SeqCst)
        );
    }
}
