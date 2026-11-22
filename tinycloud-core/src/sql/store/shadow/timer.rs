//! The uploader's timer tick.
//!
//! Ties the pieces that landed earlier on this branch into the one loop
//! the node actually runs: every `tick_interval` (default 1 s), select
//! the due set, respect the breaker, and spawn a bounded set of cycles
//! against the per-DB in-flight locks.
//!
//! The timer is a free-standing async function so it can be driven from
//! the node's runtime fairing (`tinycloud-node-server::sql_store`) or
//! from a test harness that supplies deterministic time via a fake
//! clock. The function returns when its caller drops the shutdown
//! receiver; the shutdown drain is the `shadow::drain` policy on top.
//!
//! One tick:
//! 1. Evaluate the circuit breaker at `now`. On `Open`, skip this tick.
//! 2. `select_due(state, policy, now)` scans the tracked DBs under
//!    non-blocking locks and returns the due set.
//! 3. For each key in the due set: acquire the per-DB Mutex (async;
//!    this is where the uploader serialises with itself), check the
//!    per-DB backoff with `ready(now)`, build a `Cycle`, run it through
//!    `run_cycle`, and record the result on the state.
//! 4. On `HalfOpen`, allow exactly one cycle this tick (the probe).
//!
//! What this commit does NOT yet have:
//! - The actual `Cycle` builder (needs the spool + capture body and
//!   the manifest's current frontier, both of which arrive in the
//!   follow-up wiring commit).
//! - The real store/manifest clients: tests pass fakes.
//!
//! TC-1491.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::backoff::{Breaker, BreakerPolicy, BreakerState};
use super::runloop::{DbKey, IsDue, RunState};
use super::state::DbState;

/// Parameters the timer reads on each tick.
#[derive(Debug, Clone, Copy)]
pub struct TimerPolicy {
    /// How often the tick wakes up.
    pub tick_interval: Duration,
    /// Per-tick node-wide publish-cycle budget. The shared semaphores
    /// in [`RunState`] enforce the hard cap; this budget is the soft
    /// cap for one tick, to avoid a thundering herd.
    pub per_tick_budget: usize,
    pub breaker: BreakerPolicy,
}

impl Default for TimerPolicy {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(1),
            per_tick_budget: 8,
            breaker: BreakerPolicy::default(),
        }
    }
}

/// What a single cycle attempt reports back to the timer. The timer
/// feeds this into the per-DB backoff and the node-wide breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleResult {
    /// The publish cycle succeeded end to end.
    Ok,
    /// Infrastructure error: store down, manifest down, control DB
    /// down. Feeds the node-wide breaker because it is likely to
    /// affect every DB.
    InfraErr,
    /// Per-DB policy error: Key / Conflict / Invalid /
    /// ObjectNotUploaded. Does NOT feed the node-wide breaker — one
    /// tenant's poisoned DB would otherwise re-trip the breaker every
    /// `open_for` indefinitely, starving every other DB.
    PolicyErr,
    /// A cycle was skipped because the per-DB backoff still holds.
    Backoff,
}

/// What the timer does per due DB. Injected so tests can run the whole
/// loop against a deterministic fake that does not touch a real store.
pub trait CycleRunner: Send + Sync {
    fn run(&self, key: DbKey, state: &DbState) -> CycleResult;
}

impl<F> CycleRunner for F
where
    F: Fn(DbKey, &DbState) -> CycleResult + Send + Sync,
{
    fn run(&self, key: DbKey, state: &DbState) -> CycleResult {
        (self)(key, state)
    }
}

/// One tick of the loop. Returns the number of cycles that ran (success
/// or error), not counting backoff skips. The caller holds the
/// breaker, cursor and policy across ticks.
///
/// The due set is filtered on the per-DB backoff BEFORE the per-tick
/// limit is applied, so backed-off DBs cannot burn the budget. The
/// start cursor rotates across ticks (round-robin fairness), so one
/// DB at the head of the DashMap's hash order cannot monopolise the
/// HalfOpen probe or the budget.
pub async fn tick<P: IsDue, R: CycleRunner>(
    state: &Arc<RunState>,
    policy: &P,
    timer: &TimerPolicy,
    breaker: &mut Breaker,
    cursor: &mut usize,
    runner: &R,
    now: Instant,
) -> usize {
    match breaker.evaluate(&timer.breaker, now) {
        BreakerState::Open { .. } => return 0,
        BreakerState::HalfOpen | BreakerState::Closed => {}
    }
    let half_open = matches!(
        breaker.evaluate(&timer.breaker, now),
        BreakerState::HalfOpen
    );
    let limit = if half_open { 1 } else { timer.per_tick_budget };

    let due = super::runloop::select_due(state, policy, now);

    // Filter on per-DB backoff BEFORE taking the limit, so a backed-off
    // DB does not consume this tick's budget. We take the per-DB lock
    // with `try_lock` so a cycle that is already running (held by a
    // worker from an earlier tick) is skipped silently; it cannot be
    // due again until the holder releases the lock.
    let mut ready: Vec<DbKey> = Vec::with_capacity(due.keys.len());
    for key in &due.keys {
        let Some(entry) = state.states.get(key) else {
            continue;
        };
        let Ok(st_guard) = entry.value().try_lock() else {
            continue;
        };
        if st_guard.backoff.ready(now) {
            ready.push(key.clone());
        }
    }
    if ready.is_empty() {
        return 0;
    }
    // Rotate the start index round-robin so the DB at hash position 0
    // does not always get the HalfOpen probe. Position cycles modulo
    // ready.len() across ticks.
    let n = ready.len();
    let start = (*cursor) % n;
    *cursor = start.wrapping_add(1);
    let ordered: Vec<DbKey> = ready.iter().cycle().skip(start).take(n).cloned().collect();

    let mut ran = 0usize;
    for key in ordered.into_iter().take(limit) {
        let Some(entry) = state.states.get(&key) else {
            continue;
        };
        // Lock again: we dropped the guard above to collect keys without
        // holding RefMuts across code we might extend later.
        let Ok(st_guard) = entry.value().try_lock() else {
            continue;
        };
        let result = runner.run(key.clone(), &st_guard);
        match result {
            CycleResult::Ok => {
                breaker.record_success();
                ran += 1;
            }
            CycleResult::InfraErr => {
                breaker.record_failure(&timer.breaker, now);
                ran += 1;
            }
            CycleResult::PolicyErr => {
                // Per-DB policy errors (Key / Conflict / Invalid /
                // ObjectNotUploaded) are NOT fed to the node-wide
                // breaker. A single poisoned tenant DB must not pause
                // every other DB's uploader every 30 s indefinitely.
                // The per-DB backoff still records the failure through
                // the runner.
                ran += 1;
            }
            CycleResult::Backoff => {}
        }
    }
    ran
}

/// Drive the timer until `shutdown` fires. One `tick_interval` sleep
/// between ticks.
pub async fn run_until_shutdown<P: IsDue, R: CycleRunner>(
    state: Arc<RunState>,
    policy: Arc<P>,
    timer: TimerPolicy,
    mut breaker: Breaker,
    runner: Arc<R>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut cursor = 0usize;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(timer.tick_interval) => {
                tick(
                    &state,
                    &*policy,
                    &timer,
                    &mut breaker,
                    &mut cursor,
                    &*runner,
                    Instant::now(),
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn allowed(space: &str) -> BTreeSet<String> {
        [space.to_string()].into_iter().collect()
    }

    fn always_due(_st: &DbState, _now: Instant) -> bool {
        true
    }

    struct CountingRunner(Arc<AtomicUsize>, CycleResult);
    impl CycleRunner for CountingRunner {
        fn run(&self, _k: DbKey, _s: &DbState) -> CycleResult {
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1
        }
    }

    #[tokio::test]
    async fn tick_runs_every_due_db_up_to_the_per_tick_budget() {
        let state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        for name in ["a", "b", "c", "d"] {
            state
                .upsert(("space-a".into(), name.into()), |st| {
                    st.first_dirty_at = Some(Instant::now());
                })
                .await;
        }
        let runs = Arc::new(AtomicUsize::new(0));
        let runner = CountingRunner(runs.clone(), CycleResult::Ok);
        let mut breaker = Breaker::default();
        let mut cursor = 0usize;
        let timer = TimerPolicy {
            tick_interval: Duration::from_millis(1),
            per_tick_budget: 2,
            breaker: BreakerPolicy::default(),
        };
        let ran = tick(
            &state,
            &always_due,
            &timer,
            &mut breaker,
            &mut cursor,
            &runner,
            Instant::now(),
        )
        .await;
        assert_eq!(ran, 2, "per_tick_budget caps work");
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn open_breaker_skips_the_tick() {
        let state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        state
            .upsert(("space-a".into(), "a".into()), |st| {
                st.first_dirty_at = Some(Instant::now());
            })
            .await;
        let runs = Arc::new(AtomicUsize::new(0));
        let runner = CountingRunner(runs.clone(), CycleResult::Ok);
        let policy = BreakerPolicy {
            threshold: 1,
            open_for: Duration::from_secs(10),
        };
        let mut breaker = Breaker::default();
        let mut cursor = 0usize;
        let t0 = Instant::now();
        breaker.record_failure(&policy, t0);
        let timer = TimerPolicy {
            tick_interval: Duration::from_millis(1),
            per_tick_budget: 8,
            breaker: policy,
        };
        let ran = tick(
            &state,
            &always_due,
            &timer,
            &mut breaker,
            &mut cursor,
            &runner,
            t0,
        )
        .await;
        assert_eq!(ran, 0);
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn half_open_runs_exactly_one_cycle_as_a_probe() {
        let state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        for name in ["a", "b", "c"] {
            state
                .upsert(("space-a".into(), name.into()), |st| {
                    st.first_dirty_at = Some(Instant::now());
                })
                .await;
        }
        let runs = Arc::new(AtomicUsize::new(0));
        let runner = CountingRunner(runs.clone(), CycleResult::Ok);
        let policy = BreakerPolicy {
            threshold: 1,
            open_for: Duration::from_millis(1),
        };
        let mut breaker = Breaker::default();
        let mut cursor = 0usize;
        let t0 = Instant::now();
        breaker.record_failure(&policy, t0);
        let t1 = t0 + Duration::from_millis(2);
        let timer = TimerPolicy {
            tick_interval: Duration::from_millis(1),
            per_tick_budget: 8,
            breaker: policy,
        };
        let ran = tick(
            &state,
            &always_due,
            &timer,
            &mut breaker,
            &mut cursor,
            &runner,
            t1,
        )
        .await;
        assert_eq!(ran, 1, "half-open allows exactly one probe");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cycle_failures_are_fed_into_the_breaker() {
        let state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        for name in ["a", "b", "c", "d", "e"] {
            state
                .upsert(("space-a".into(), name.into()), |st| {
                    st.first_dirty_at = Some(Instant::now());
                })
                .await;
        }
        let runs = Arc::new(AtomicUsize::new(0));
        let runner = CountingRunner(runs.clone(), CycleResult::InfraErr);
        let policy = BreakerPolicy {
            threshold: 3,
            open_for: Duration::from_secs(60),
        };
        let mut breaker = Breaker::default();
        let mut cursor = 0usize;
        let t0 = Instant::now();
        let timer = TimerPolicy {
            tick_interval: Duration::from_millis(1),
            per_tick_budget: 8,
            breaker: policy,
        };
        let _ = tick(
            &state,
            &always_due,
            &timer,
            &mut breaker,
            &mut cursor,
            &runner,
            t0,
        )
        .await;
        // Five failed cycles in one tick: breaker should have opened at
        // the third, but subsequent cycles in the same tick still run
        // because the breaker is evaluated once per tick.
        assert!(breaker.opened_at.is_some(), "breaker opened on failures");
    }
}
