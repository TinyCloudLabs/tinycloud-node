//! Limits on the links fetches that delivery authorizations make.
//!
//! The links API limits reads per client address (120 a minute, contract
//! section 4.9) and the node reads from one address, so one authenticated
//! invoker sending valid-looking link ids could use that allowance up and turn
//! every sender's delivery into `503 delivery-links-unavailable`. Before a
//! request reaches the fetch (and before the body is opened) it passes two
//! limits:
//!
//! - a token bucket per authenticated invoker (a burst of five, refilled at the
//!   configured rate), and
//! - one node-wide cap on fetches in any 60 seconds, configured below the API's
//!   allowance.
//!
//! Only requests that reach the fetch step are counted; a request refused
//! earlier (bad digest, a link the grammar refuses, a replay) costs nothing.
//! The set of tracked invokers is bounded: idle ones are dropped, and when the
//! set is still full a new invoker is counted against the node-wide cap only.
//!
//! A refusal is counted (`tinycloud_delivery_rate_limited_total`, one bounded
//! label `scope`) and reported by one aggregated log line per scope per
//! minute: fixed fields only, never an invoker, a link or a key.

use crate::prometheus::observe_delivery_rate_limited;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

pub const DEFAULT_PER_INVOKER_PER_MINUTE: u32 = 20;
pub const DEFAULT_GLOBAL_PER_MINUTE: u32 = 90;
/// The node-wide cap stays below the API's per-address read allowance.
pub const MAX_GLOBAL_PER_MINUTE: u32 = 110;
const BURST: u32 = 5;
const MAX_TRACKED_INVOKERS: usize = 4096;
const WINDOW: Duration = Duration::from_secs(60);
/// The window of the aggregated log line.
pub const REPORT_WINDOW_SECS: u64 = 60;

/// The configuration rule: both limits are at least one, the node-wide cap at
/// most [`MAX_GLOBAL_PER_MINUTE`].
pub fn validate_limits(
    per_invoker_per_minute: u32,
    global_per_minute: u32,
) -> Result<(), &'static str> {
    if per_invoker_per_minute == 0 || global_per_minute == 0 {
        return Err("share email links fetch limits must be at least 1 a minute");
    }
    if global_per_minute > MAX_GLOBAL_PER_MINUTE {
        return Err("share email links_fetch_global_per_minute must be at most 110");
    }
    Ok(())
}

/// Which limit refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Invoker,
    Global,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoker => "invoker",
            Self::Global => "global",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Invoker => 0,
            Self::Global => 1,
        }
    }
}

/// A refusal: the limit that held and the seconds to wait (at least one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    pub scope: Scope,
    pub retry_after_secs: u64,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

struct Limits {
    per_minute: u32,
    burst: u32,
    global_per_minute: u32,
}

#[derive(Default)]
struct State {
    invokers: HashMap<String, Bucket>,
    /// When each fetch in the last 60 seconds was admitted, oldest first.
    global: VecDeque<Instant>,
    /// Refusals since the last report, by scope.
    refused: [u64; 2],
}

pub struct FetchLimiter {
    limits: Mutex<Limits>,
    state: Mutex<State>,
    observe: Arc<dyn Fn(Scope) + Send + Sync>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl FetchLimiter {
    pub fn new(per_invoker_per_minute: u32, global_per_minute: u32) -> Self {
        Self::with_observer(
            per_invoker_per_minute,
            global_per_minute,
            Arc::new(|scope| observe_delivery_rate_limited(scope.as_str())),
        )
    }

    /// As [`Self::new`], with the function called once per refusal.
    pub fn with_observer(
        per_invoker_per_minute: u32,
        global_per_minute: u32,
        observe: Arc<dyn Fn(Scope) + Send + Sync>,
    ) -> Self {
        let per_minute = per_invoker_per_minute.max(1);
        Self {
            limits: Mutex::new(Limits {
                per_minute,
                burst: BURST.min(per_minute),
                global_per_minute: global_per_minute.clamp(1, MAX_GLOBAL_PER_MINUTE),
            }),
            state: Mutex::new(State::default()),
            observe,
        }
    }

    /// Replace the limits and forget every count. Tests only.
    #[cfg(test)]
    pub(crate) fn set_limits(&self, per_minute: u32, burst: u32, global_per_minute: u32) {
        *locked(&self.limits) = Limits {
            per_minute,
            burst,
            global_per_minute,
        };
        *locked(&self.state) = State::default();
    }

    /// How many invokers have a bucket. Tests only.
    #[cfg(test)]
    pub(crate) fn tracked_invokers(&self) -> usize {
        locked(&self.state).invokers.len()
    }

    /// Admit or refuse one fetch for `invoker` at `now`. A refusal consumes
    /// nothing from either limit.
    pub fn check(&self, invoker: &str, now: Instant) -> Result<(), Refused> {
        let (per_minute, burst, global_limit) = {
            let limits = locked(&self.limits);
            (
                f64::from(limits.per_minute),
                f64::from(limits.burst),
                limits.global_per_minute as usize,
            )
        };
        let rate = per_minute / 60.0;
        let mut state = locked(&self.state);
        let state = &mut *state;
        while state
            .global
            .front()
            .is_some_and(|admitted| now.saturating_duration_since(*admitted) >= WINDOW)
        {
            state.global.pop_front();
        }

        // The invoker's bucket, refilled to `now`. At the cap on tracked
        // invokers an unknown one is not tracked and only the node-wide cap
        // applies to it.
        let refill = |bucket: &mut Bucket| {
            let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
            bucket.updated = now;
        };
        if !state.invokers.contains_key(invoker) && state.invokers.len() >= MAX_TRACKED_INVOKERS {
            state.invokers.retain(|_, bucket| {
                let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
                bucket.tokens + elapsed * rate < burst
            });
        }
        let tracked =
            state.invokers.contains_key(invoker) || state.invokers.len() < MAX_TRACKED_INVOKERS;
        if tracked {
            let bucket = state.invokers.entry(invoker.to_owned()).or_insert(Bucket {
                tokens: burst,
                updated: now,
            });
            refill(bucket);
            if bucket.tokens < 1.0 {
                let wait = ((1.0 - bucket.tokens) / rate).ceil().max(1.0) as u64;
                return Err(self.refuse(state, Scope::Invoker, wait));
            }
        }
        if state.global.len() >= global_limit {
            let oldest = state.global.front().copied().unwrap_or(now);
            let wait = WINDOW
                .saturating_sub(now.saturating_duration_since(oldest))
                .as_secs_f64()
                .ceil()
                .max(1.0) as u64;
            return Err(self.refuse(state, Scope::Global, wait));
        }
        if tracked {
            if let Some(bucket) = state.invokers.get_mut(invoker) {
                bucket.tokens -= 1.0;
            }
        }
        state.global.push_back(now);
        Ok(())
    }

    fn refuse(&self, state: &mut State, scope: Scope, retry_after_secs: u64) -> Refused {
        state.refused[scope.index()] += 1;
        (self.observe)(scope);
        Refused {
            scope,
            retry_after_secs,
        }
    }

    /// Refusals since the last call, by scope, and reset. Only a scope with at
    /// least one refusal is returned.
    pub fn take_refusals(&self) -> Vec<(Scope, u64)> {
        let mut state = locked(&self.state);
        [Scope::Invoker, Scope::Global]
            .into_iter()
            .filter_map(|scope| {
                let count = std::mem::take(&mut state.refused[scope.index()]);
                (count > 0).then_some((scope, count))
            })
            .collect()
    }

    /// Emit the aggregated line for the refusals since the last report: one
    /// per scope with at least one refusal, fixed fields only.
    pub fn report(&self) -> Vec<(Scope, u64)> {
        let refusals = self.take_refusals();
        for (scope, count) in &refusals {
            tracing::warn!(
                event = "delivery_rate_limited",
                scope = scope.as_str(),
                count = *count,
                window_s = REPORT_WINDOW_SECS,
                "delivery authorizations refused by the rate limit"
            );
        }
        refusals
    }
}

impl Default for FetchLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_PER_INVOKER_PER_MINUTE, DEFAULT_GLOBAL_PER_MINUTE)
    }
}

/// Report once every 60 seconds until `stop` resolves.
pub async fn run_report(limiter: Arc<FetchLimiter>, stop: impl Future<Output = ()>) {
    let period = Duration::from_secs(REPORT_WINDOW_SECS);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                limiter.report();
            }
            _ = &mut stop => break,
        }
    }
}

#[cfg(test)]
mod tests;
