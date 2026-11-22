//! Per-database backoff and a node-wide circuit breaker.
//!
//! Backoff: on a failed publish cycle (store down, manifest down, CAS
//! lost without a path forward), the per-DB backoff doubles from 1 s to
//! a 60 s ceiling, with ±20% jitter. A successful cycle resets it.
//!
//! Breaker: when N consecutive failures across DBs exceed a threshold
//! (default 5), the node-wide breaker opens and pauses new cycles for
//! 30 s. The breaker exits via a half-open probe (one DB) and closes
//! on the probe's success.
//!
//! Both pieces are pure policy: no clock, no sleep, no randomness other
//! than a seeded `rand::rngs::SmallRng` for the jitter. The caller
//! supplies `now: Instant` and the loop hooks the result into `tokio::
//! time::sleep_until`. Tests pass a deterministic seed.
//!
//! TC-1491.

use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Per-DB backoff state. Owned by the uploader's per-DB `DbState`
/// alongside the pending capture.
#[derive(Debug, Clone)]
pub struct Backoff {
    /// When the uploader is permitted to try again. `None` on a fresh
    /// state, or after a successful cycle.
    pub next_try: Option<Instant>,
    /// Consecutive failure count. Doubles the base delay, capped at the
    /// policy's `max`.
    pub consecutive: u32,
    rng: StdRng,
}

impl Backoff {
    /// A fresh backoff: never failed yet.
    pub fn new(seed: u64) -> Self {
        Self {
            next_try: None,
            consecutive: 0,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// The caller may try again if the deadline has passed (or there
    /// has never been a failure).
    pub fn ready(&self, now: Instant) -> bool {
        self.next_try.is_none_or(|t| now >= t)
    }

    /// Record a failure and schedule the next retry.
    pub fn record_failure(&mut self, policy: &BackoffPolicy, now: Instant) {
        self.consecutive = self.consecutive.saturating_add(1);
        let base = policy.base.as_millis() as u64;
        let max = policy.max.as_millis() as u64;
        let exp = base
            .checked_shl(self.consecutive.saturating_sub(1).min(32))
            .unwrap_or(max);
        let delay_ms = exp.min(max);
        let jitter_pct = policy.jitter_pct as i64;
        // Jitter in [-jitter_pct%, +jitter_pct%].
        let jitter_range = (delay_ms as i64 * jitter_pct) / 100;
        let jitter = if jitter_range == 0 {
            0
        } else {
            self.rng.gen_range(-jitter_range..=jitter_range)
        };
        let final_ms = (delay_ms as i64 + jitter).max(0) as u64;
        self.next_try = Some(now + Duration::from_millis(final_ms));
    }

    /// Reset after a successful cycle.
    pub fn record_success(&mut self) {
        self.next_try = None;
        self.consecutive = 0;
    }
}

/// Fixed parameters the backoff reads.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub max: Duration,
    /// ±jitter as an integer percent (default 20).
    pub jitter_pct: u8,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            jitter_pct: 20,
        }
    }
}

/// Node-wide circuit breaker. Opens after N consecutive failures across
/// any DBs; new cycles pause for `open_for`. The half-open probe runs
/// exactly one DB.
#[derive(Debug, Clone, Default)]
pub struct Breaker {
    pub consecutive: u32,
    pub opened_at: Option<Instant>,
    pub half_open: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct BreakerPolicy {
    pub threshold: u32,
    pub open_for: Duration,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            open_for: Duration::from_secs(30),
        }
    }
}

/// What the breaker says to do on this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Open. The caller skips new cycles until `open_until`.
    Open { open_until: Instant },
    /// Half-open: exactly one cycle may run as a probe. Success closes
    /// the breaker; failure re-opens it.
    HalfOpen,
    /// Closed. Normal operation.
    Closed,
}

impl Breaker {
    /// Record a failure. Trips open on the Nth consecutive failure.
    pub fn record_failure(&mut self, policy: &BreakerPolicy, now: Instant) {
        self.consecutive = self.consecutive.saturating_add(1);
        if self.consecutive >= policy.threshold && self.opened_at.is_none() {
            self.opened_at = Some(now);
            self.half_open = false;
        } else if self.half_open {
            // A half-open probe failed: re-open the breaker.
            self.opened_at = Some(now);
            self.half_open = false;
        }
    }

    /// Record a success. Half-open closes the breaker; closed resets
    /// the counter.
    pub fn record_success(&mut self) {
        self.consecutive = 0;
        self.opened_at = None;
        self.half_open = false;
    }

    /// Evaluate the breaker at `now`. Transitions Open → HalfOpen once
    /// `open_for` has elapsed. The caller runs at most one cycle while
    /// HalfOpen.
    pub fn evaluate(&mut self, policy: &BreakerPolicy, now: Instant) -> BreakerState {
        match self.opened_at {
            None => BreakerState::Closed,
            Some(t) if now >= t + policy.open_for => {
                self.half_open = true;
                BreakerState::HalfOpen
            }
            Some(t) => BreakerState::Open {
                open_until: t + policy.open_for,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_base_to_max() {
        let mut b = Backoff::new(42);
        let policy = BackoffPolicy {
            base: Duration::from_millis(100),
            max: Duration::from_millis(1000),
            jitter_pct: 0,
        };
        let now = Instant::now();
        for (i, expect_ms) in [100u128, 200, 400, 800, 1000, 1000].iter().enumerate() {
            b.record_failure(&policy, now);
            let delay = b.next_try.unwrap() - now;
            assert_eq!(
                delay.as_millis(),
                *expect_ms,
                "failure {i}: expected {expect_ms} ms delay, got {}",
                delay.as_millis()
            );
        }
    }

    #[test]
    fn backoff_jitter_stays_within_percent_bound() {
        let mut b = Backoff::new(42);
        let policy = BackoffPolicy {
            base: Duration::from_millis(1000),
            max: Duration::from_millis(60_000),
            jitter_pct: 20,
        };
        let now = Instant::now();
        b.record_failure(&policy, now);
        let delay = b.next_try.unwrap() - now;
        // Base 1000 ms ±20% => [800 ms, 1200 ms].
        assert!(
            delay.as_millis() >= 800 && delay.as_millis() <= 1200,
            "jittered delay out of ±20% bound: {} ms",
            delay.as_millis()
        );
    }

    #[test]
    fn backoff_record_success_clears_the_count_and_deadline() {
        let mut b = Backoff::new(42);
        b.record_failure(&BackoffPolicy::default(), Instant::now());
        b.record_success();
        assert_eq!(b.consecutive, 0);
        assert!(b.next_try.is_none());
        assert!(b.ready(Instant::now()));
    }

    #[test]
    fn breaker_opens_after_the_threshold_and_half_opens_after_the_window() {
        let mut br = Breaker::default();
        let policy = BreakerPolicy {
            threshold: 3,
            open_for: Duration::from_millis(100),
        };
        let t0 = Instant::now();
        for _ in 0..3 {
            br.record_failure(&policy, t0);
        }
        // Freshly opened: evaluate reports Open.
        match br.evaluate(&policy, t0) {
            BreakerState::Open { .. } => {}
            other => panic!("expected Open, got {other:?}"),
        }
        // After the window: half-open.
        let t1 = t0 + Duration::from_millis(101);
        assert_eq!(br.evaluate(&policy, t1), BreakerState::HalfOpen);
    }

    #[test]
    fn breaker_half_open_closes_on_success() {
        let mut br = Breaker::default();
        let policy = BreakerPolicy {
            threshold: 2,
            open_for: Duration::from_millis(1),
        };
        let t0 = Instant::now();
        br.record_failure(&policy, t0);
        br.record_failure(&policy, t0);
        let t1 = t0 + Duration::from_millis(2);
        assert_eq!(br.evaluate(&policy, t1), BreakerState::HalfOpen);
        br.record_success();
        assert_eq!(br.evaluate(&policy, t1), BreakerState::Closed);
    }

    #[test]
    fn breaker_half_open_reopens_on_failure() {
        let mut br = Breaker::default();
        let policy = BreakerPolicy {
            threshold: 2,
            open_for: Duration::from_millis(1),
        };
        let t0 = Instant::now();
        br.record_failure(&policy, t0);
        br.record_failure(&policy, t0);
        let t1 = t0 + Duration::from_millis(2);
        assert_eq!(br.evaluate(&policy, t1), BreakerState::HalfOpen);
        br.record_failure(&policy, t1);
        match br.evaluate(&policy, t1) {
            BreakerState::Open { .. } => {}
            other => panic!("expected Open after half-open failure, got {other:?}"),
        }
    }

    #[test]
    fn breaker_closed_is_the_default_state() {
        let mut br = Breaker::default();
        assert_eq!(
            br.evaluate(&BreakerPolicy::default(), Instant::now()),
            BreakerState::Closed
        );
    }
}
