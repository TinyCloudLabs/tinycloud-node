//! Pure reconnect/backoff decision logic for the tunnel client, kept free of
//! any actual networking so it can be exhaustively unit tested.
//!
//! The tunnel connection loop (`tunnel::connection`) asks this module what
//! to do after each connect attempt outcome (a WS close code, an ack, or a
//! transport-level error) and applies the resulting [`ReconnectAction`]
//! without embedding this policy inline in async I/O code.
use std::time::Duration;

use super::protocol::{CLOSE_STALE_SEQUENCE, CLOSE_SUPERSEDED};

/// How far to jump the local sequence counter when recovering from a
/// stale-sequence (4409) close. Mirrors `link::commands::SEQUENCE_RESYNC_JUMP`
/// — the link service does not expose its stored sequence via
/// `GET /v1/names/:name`, so an exact resync isn't possible; jumping forward
/// and retrying is the documented recovery path (see
/// `docs/specs/node-control-plane-v1.md` §3.9).
pub const SEQUENCE_RESYNC_JUMP: u64 = 100;

/// Base delay for the first backoff retry.
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// Upper bound on backoff delay (before jitter), so a long outage doesn't
/// push the retry interval out indefinitely.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// The outcome of one connect+auth attempt, as observed by the connection
/// loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The relay acked the auth frame; the tunnel is live.
    Ack,
    /// The relay closed with a specific close code (e.g. 4409, 4410, or any
    /// other 4xxx auth-rejection code).
    Closed(u16),
    /// The connection failed before any close code was observed (DNS
    /// failure, TCP refused, TLS error, timeout, ...).
    TransportError,
}

/// What the connection loop should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectAction {
    /// Reset backoff state; the tunnel is live and should serve requests
    /// until the connection drops.
    Serve,
    /// Bump the local sequence forward by `SEQUENCE_RESYNC_JUMP` and retry
    /// the connection immediately (no backoff delay) — the local sequence
    /// has fallen behind the relay's stored record.
    ResyncAndRetry { jump: u64 },
    /// Another connection for this name has taken over. Stop the tunnel
    /// task entirely; do not reconnect-fight with the socket that superseded
    /// us.
    Stop,
    /// Wait `delay` (already jittered) before retrying with a fresh
    /// sequence.
    Backoff { delay: Duration },
}

/// Tracks backoff state across repeated connection attempts. `attempt` is
/// the number of consecutive non-`Ack` outcomes since the last successful
/// `Ack` (or since the loop started).
#[derive(Debug, Default, Clone, Copy)]
pub struct BackoffState {
    attempt: u32,
}

impl BackoffState {
    pub fn new() -> Self {
        Self { attempt: 0 }
    }

    /// Reset backoff after a successful auth — the next failure starts from
    /// the base delay again rather than continuing to escalate.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Decide what to do given the outcome of the most recent attempt.
    /// `jitter` is a caller-supplied value in `[0.0, 1.0)` (from `rand`) so
    /// this function stays deterministic and unit-testable.
    pub fn next_action(&mut self, outcome: AttemptOutcome, jitter: f64) -> ReconnectAction {
        match outcome {
            AttemptOutcome::Ack => {
                self.reset();
                ReconnectAction::Serve
            }
            AttemptOutcome::Closed(CLOSE_SUPERSEDED) => ReconnectAction::Stop,
            AttemptOutcome::Closed(CLOSE_STALE_SEQUENCE) => ReconnectAction::ResyncAndRetry {
                jump: SEQUENCE_RESYNC_JUMP,
            },
            AttemptOutcome::Closed(_) | AttemptOutcome::TransportError => {
                let delay = self.backoff_delay(jitter);
                self.attempt = self.attempt.saturating_add(1);
                ReconnectAction::Backoff { delay }
            }
        }
    }

    /// Exponential backoff with jitter, capped at `BACKOFF_CAP`.
    /// `jitter` in `[0.0, 1.0)` scales the delay by `[0.5, 1.0)` so
    /// simultaneous reconnects (e.g. many nodes recovering from a relay
    /// restart at once) don't all retry in lockstep.
    fn backoff_delay(&self, jitter: f64) -> Duration {
        let exp = self.attempt.min(10); // 2^10 * base is already >> cap
        let unjittered = BACKOFF_BASE.saturating_mul(1u32 << exp).min(BACKOFF_CAP);
        let factor = 0.5 + (jitter.clamp(0.0, 1.0) * 0.5);
        unjittered.mul_f64(factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_resets_backoff_and_serves() {
        let mut state = BackoffState::new();
        state.attempt = 5;
        let action = state.next_action(AttemptOutcome::Ack, 0.0);
        assert_eq!(action, ReconnectAction::Serve);
        assert_eq!(state.attempt, 0);
    }

    #[test]
    fn stale_sequence_close_resyncs_without_backoff() {
        let mut state = BackoffState::new();
        let action = state.next_action(AttemptOutcome::Closed(CLOSE_STALE_SEQUENCE), 0.0);
        assert_eq!(
            action,
            ReconnectAction::ResyncAndRetry {
                jump: SEQUENCE_RESYNC_JUMP
            }
        );
        // A resync-and-retry is not itself a backoff escalation.
        assert_eq!(state.attempt, 0);
    }

    #[test]
    fn superseded_close_stops_and_does_not_reconnect() {
        let mut state = BackoffState::new();
        let action = state.next_action(AttemptOutcome::Closed(CLOSE_SUPERSEDED), 0.0);
        assert_eq!(action, ReconnectAction::Stop);
    }

    #[test]
    fn other_close_codes_apply_backoff() {
        let mut state = BackoffState::new();
        let action = state.next_action(AttemptOutcome::Closed(4400), 0.0);
        match action {
            ReconnectAction::Backoff { delay } => {
                assert!(delay >= BACKOFF_BASE.mul_f64(0.5));
            }
            other => panic!("expected Backoff, got {other:?}"),
        }
        assert_eq!(state.attempt, 1);
    }

    #[test]
    fn transport_error_applies_backoff() {
        let mut state = BackoffState::new();
        let action = state.next_action(AttemptOutcome::TransportError, 0.0);
        assert!(matches!(action, ReconnectAction::Backoff { .. }));
        assert_eq!(state.attempt, 1);
    }

    #[test]
    fn backoff_escalates_and_caps() {
        let mut state = BackoffState::new();
        let mut delays = Vec::new();
        for _ in 0..15 {
            match state.next_action(AttemptOutcome::TransportError, 0.0) {
                ReconnectAction::Backoff { delay } => delays.push(delay),
                other => panic!("expected Backoff, got {other:?}"),
            }
        }
        // Monotonically non-decreasing until the cap.
        for pair in delays.windows(2) {
            assert!(pair[1] >= pair[0]);
        }
        // Never exceeds the cap (jitter only ever scales it down to half).
        for delay in &delays {
            assert!(*delay <= BACKOFF_CAP);
        }
        // Eventually reaches the cap.
        assert!(delays.last().unwrap().as_secs_f64() >= BACKOFF_CAP.as_secs_f64() * 0.5);
    }

    #[test]
    fn jitter_scales_delay_between_half_and_full() {
        let mut low = BackoffState::new();
        low.attempt = 3;
        let mut high = BackoffState::new();
        high.attempt = 3;

        let low_delay = match low.next_action(AttemptOutcome::TransportError, 0.0) {
            ReconnectAction::Backoff { delay } => delay,
            _ => panic!("expected backoff"),
        };
        let high_delay = match high.next_action(AttemptOutcome::TransportError, 0.999) {
            ReconnectAction::Backoff { delay } => delay,
            _ => panic!("expected backoff"),
        };
        assert!(high_delay > low_delay);
    }
}
