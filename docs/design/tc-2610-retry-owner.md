# One retry owner for database operations

Status: accepted design. Base: main 64e85090.

## Current behaviour

Several retry layers apply to one request:

| Layer | Where | Retries |
|---|---|---|
| statement | `db_pool.rs` `run`/`run_statement` (≈180-255) | reads, `BEGIN`, once |
| idempotent write | `db_pool.rs` `execute_idempotent` | one asserted-idempotent statement, once |
| `BEGIN` as retryable | `db_pool.rs` `begin*` (≈595-640), `begin_preparatory`, `begin_bulk_read` | `BEGIN`, once |
| operation | `db_pool.rs` `track_writes_retrying` (≈958-1006) | whole `/delegate`, `/invoke` authorize, once |
| local loop | `db.rs` ≈2552-2593 and ≈2612-2660 | preparatory registration, `BEGIN`, freeze lock, once each |

One operation can run through the statement and operation layers (and the local loops) with no shared
budget. The design gives every operation one owner, one retry and one bounded budget, and adds no load
while the database is slow.

## Rule

An operation is retried only when all hold:

1. The failure is a lost connection: `failure_kind` is `connection_lost` or `io` (TC-128 categories, unchanged).
2. The write tracker proves nothing can have committed (`WRITE_MAY_HAVE_APPLIED` is false). A lost `COMMIT`
   is covered: the transaction began, so the flag is set. Exception: `Replay::IdempotentStatement` (below).
3. The retry count is unspent (one retry per operation) and the operation budget has room (see Budget).
4. The request deadline allows it (checked twice, see Deadline).
5. No overload signal is active (see Overload suppression).

Never retried, whatever the tracker says: `request_timeout` (the future is cancelled, nothing runs),
`pool_timeout`, `pool_closed`, `statement_timeout`, `serialization`, uncertain `COMMIT`, `other`.
The client sees them as today; `classify_failure` and the 503 mapping are untouched.

### Budget: one absolute bound over attempt 1 + backoff + attempt 2

`RetryPolicy { budget: Duration, delay_ms }`; `budget` is `database.retry_window_ms` (default 10 s), renamed in
code, same config key. `RecoveringConnection::retry_policy() -> Option<RetryPolicy>`; a pool with no configured
value returns `None`, and `retry_owner(None, ..)` runs the attempt once, no retry (so `RecoveringConnection::new`
does not retry, and today's `None never skips` is gone).

`t0` = owner start. After attempt 1 fails with a retryable error, with `delay` drawn from 100-300 ms:

- `remaining = budget - (now - t0) - delay`. If `remaining < MIN_RETRY = 1 s`, skip (`skipped_budget`; this
  subsumes today's slow-first-run skip: a run that took a keepalive/`TCP_USER_TIMEOUT` expiry eats the budget).
- Sleep `delay`, then run attempt 2 inside `tokio::time::timeout(remaining, attempt())`.
- Attempt 1 itself is not cancelled by the owner (a write in flight is not interrupted; it is bounded by the
  statement timeout, TCP user timeout and the request deadline as today).

On expiry of attempt 2 (`budget_expired`, logged and counted): its future is dropped. A write it had in flight is
already recorded by the `InFlightWrite` guard, so the returned flag is attempt 2's tracker state (conservative:
may-have-applied if a write was on the wire). The returned error is attempt 1's error (the owner cannot build
an `E`), so the client sees the original connection-class failure, classified by `classify_failure` with that
flag. It is not retried again. A `ctx = None` background task has the same bound: it is the budget, not the
deadline, that stops it.

### Deadline

State source: `request_cancel::current() -> Option<Arc<RequestCancel>>` (task-local, installed by
`request_cancel::within`); `retry_owner` reads it itself, no new parameter. Check `deadline_allows(ctx, now, need)`:

- `ctx` is `None` (background task, no request): allowed; time is bounded by `budget` alone.
- `ctx.is_open()` is false (cut, or latched): not retried. A cut request is already answered `request_timeout`.
  Latched means a data write began; the tracker is authoritative for safety, but we do not retry across a
  latch, so a retry never extends a request the deadline can no longer cut.
- `ctx.deadline() - now <= need`: not retried (room for the backoff plus the bounded second attempt).

Checked (a) before the backoff sleep, with `need = delay + remaining`, and (b) immediately after the sleep,
before attempt 2 starts, with `need = remaining`; both read `is_open()` again so a cut during the sleep skips
attempt 2. The sleep needs no extra cancellation: the handler future is dropped when the deadline cuts it.
Skips are logged and counted as `skipped_deadline`.

## Overload suppression

While the database is slow, retries must not add load. Owner-observable signal: a process-wide `OverloadSignal` (one `AtomicU64` of the last-seen instant, in
`db_pool.rs`, next to `PoolRecovery`) stamped when any of these is observed anywhere in the process:

- a request is cut by its deadline (`RequestCancel::cut` returning true: `request_timeout`),
- `failure_kind` is `pool_timeout` or `statement_timeout` (stamped where `lost()` is called today, and by the
  owner when it sees one in a result).

Decision (Naomi, option 1): any of the three stamps the marker, and while it is active ALL retries are
suppressed for `OVERLOAD_SUPPRESS = 30 s` (every `retry_owner`, including `IdempotentStatement`; run-once,
`skipped_overload` counted). Process-wide. The signal reflects timeouts already observed, so it takes effect
from the first one.

Mechanics. One small `std::sync::Mutex<OverloadState { until_ms: u64, active: bool }>` is the only writer of
the state; every transition is decided and applied under it, so transitions are linearizable. The two atomics
of the earlier draft are gone. A `Clock` trait (`fn now_ms(&self) -> u64`; production reads `Instant`, tests
use a manual clock) supplies time; the transition functions take `now_ms` as an argument.

- `stamp(class, now)` (rare: only on a timeout): lock; `until_ms = max(until_ms, now + 30 s)` (an older stamp
  can never shorten a newer window); if `!active` set `active = true`, log the start line (still under the lock,
  so lines are ordered) and mark "spawn watcher"; publish `until_ms` to a read mirror `AtomicU64`
  (`store` under the lock, so the mirror only ever increases); unlock; spawn the watcher if marked.
  A stamp while `active` only extends `until_ms`: no start line, no second watcher.
- `is_suppressing(now)` (hot path, lock-free): `now < mirror`. The mirror is written only under the lock, so a
  reader sees a value that was true at some instant; at worst it lags one concurrent stamp, never past an
  expired window.
- `watcher_step(now)`, the end watcher's only action: lock; if `now >= until_ms` then `active = false`, log the
  end line (under the lock) and return `Done`; else return `SleepFor(until_ms - now)`. The expiry decision and
  `active = false` are one critical section. A concurrent stamp therefore lands either before it (it extends
  `until_ms`, the watcher gets `SleepFor` and loops) or after it (`active` is already false, so that stamp starts
  a new period with its own start line and a new watcher). No interleaving yields a second start line or a
  second watcher within one period, and none leaves `active = true` with no watcher.
- Invariant: per period exactly one start line, one end line, one live watcher; across a run
  `starts == ends` or `starts == ends + 1` (a period still open). The watcher is one task per period
  (`loop { match step(now) { SleepFor(d) => sleep(d), Done => break } }`) and logs the end even when idle.

Logging (`tracing::warn!` start, `tracing::info!` end), fields only `error_class` (`request_timeout`,
`pool_timeout` or `statement_timeout`, the triggering class of the first stamp) and `suppress_ms`
(the window, 30000): "retries suppressed after a database overload signal" / "retries resumed". No request,
space, statement or error text (TC-961).

Fallback if Naomi's choice is revisited: delete `OverloadSignal` (~40 lines, three stamp sites, one check).

## API (in `db_pool.rs`)

```rust
pub struct RetryPolicy { budget: Duration, delay_ms: RangeInclusive<u64> } // 100..=300
impl RecoveringConnection { pub fn retry_policy(&self) -> Option<RetryPolicy> }

pub enum Replay {
    Never,
    /// Attempt is ONE autocommit statement, no explicit BEGIN/COMMIT, whose every write is a fixed-key
    /// INSERT ... ON CONFLICT DO NOTHING and whose result does not depend on whether it already ran.
    IdempotentStatement,
}

pub async fn retry_owner<T, E, F, Fut>(
    operation: &'static str,
    policy: Option<RetryPolicy>,
    replay: Replay,
    attempt: F,                       // FnMut() -> Fut: ONE database operation or transaction
    db_error: impl Fn(&E) -> Option<&DbErr>,
) -> (Result<T, E>, bool)            // result, write_may_have_applied (same shape as today)
```

`retry_owner` generalises `track_writes_retrying` and is the only retrier. It never reuses the failed
connection (pool release ping + `PoolRecovery` revalidation, unchanged), sleeps a jittered 100-300 ms, and keeps
the existing `OperationRetried` / `OperationRetrySucceeded` / `OperationRetrySkippedSlow` counters.

### Replay::IdempotentStatement and COMMIT

The tracker is a boolean that any read-write `BEGIN` sets, so it cannot distinguish an idempotent statement
from an uncertain `COMMIT`. Resolution: `IdempotentStatement` is valid only for a single autocommit statement.
The owner enforces it with a second task-local flag `COMMIT_UNKNOWN`, set by `begin*` on any explicit
transaction (the same place `note_write_may_have_applied` is called today). If `COMMIT_UNKNOWN` is set during an
`IdempotentStatement` attempt, the owner refuses to retry (as `Replay::Never` would), so an explicit transaction
inside an idempotent attempt, including one whose `COMMIT`
is lost, is never replayed. Condition 2 is relaxed only for an autocommit write that lost its connection.
Only user: `read_audit.rs:643`.

### Nested owners and the budget

The owner installs a task-local marker for its whole run. A `retry_owner` entered while it is set runs its
attempt once under the outer tracker and never retries; the outer owner decides. Total retries across outer
and inner calls is therefore at most one. Nested use is a guard against accidental stacking, not a feature:
an inner owner has no retry of its own.

### Cancellation boundary: cancel-safe attempts only

Dropping attempt 2 on budget expiry only helps if the attempt owns no work that outlives its future. The
production path that does is `SqlService::run_locked` (`sql/service.rs`), which runs its operation on a
`tokio::spawn`ed task that continues if the awaiting future is dropped (TC-1274, by design: hydration, the
actor statement and the durable save must finish). Selected guarantee:
**prohibit wrapping detached or non-cancellable paths; a retry attempt is cancel-safe by construction.**

- Cancel-safe means: when its future is dropped, no task, statement chain or lock of the attempt keeps running
  on the node. (The server may still finish one statement already on the wire; that is not new: sqlx pings
  the connection back to the pool after it finishes. `InFlightWrite` records it, so the owner returns the
  flag as may-have-applied and the client gets `outcome_unknown`, never a safe retry.)
- Wrapped today: `tinycloud.delegate(..)` and `invoke_admitted(..)` (authorization reads, `begin`, writes
  and `commit` on the caller's task, no spawn), read-audit batches, and the two webhook dispatcher reads.
  `/invoke` SQL execution, `persist_write`, `run_locked` and the KV write path are NOT wrapped and keep
  `track_writes` only.
- Structural check, so a later change cannot silently break it: a task-local marker is set while a
  `retry_owner` runs. `run_locked` calls `db_retry::refuse_in_retry_attempt(site)` first. Inside a retry
  owner it returns an error (`SqlError::Internal`, class `other`, not retryable); outside, it is a no-op.
  Wrapping a detached path is rejected at the first call.
- Attempt 1 is subject to the same rule, so both attempts have identical semantics.

Tests: (a) attempt 2 hangs past the remaining budget (tokio paused time): `retry_owner` returns attempt 1's error,
and a second statement the attempt would have issued after the pause never executes (counter stays 0), proving
the future stopped; with an `InFlightWrite` armed in attempt 2 the returned flag is true. (b) `retry_owner`
around a closure that calls `refuse_in_retry_attempt` (as `run_locked` does) gets the refusal error and
does not spawn (no task running afterwards, checked via a drop-guard counter), and is not retried.

### Attempt scope: DB operation only

`attempt` is the database operation or transaction (`begin_*` through `commit()` and the reads feeding it), not
the HTTP handler. It may run twice, so NO external effect may run inside it: no object-store or block-store
write, no email, no webhook or hook delivery, no network call, no log line that downstream treats as an event.
Effects run after `retry_owner` returns `Ok`, or are recorded in the transaction (outbox / lease row) and sent
after commit. The routes call sites (`routes/mod.rs` ≈758 and ≈4401) already wrap `tinycloud.delegate(..)` /
`invoke_admitted(..)` only; they are checked against this rule in the implementation PR.

## Deleted

- `RecoveringConnection::run`'s retry arm and `run_statement`'s retry arm (statements, `BEGIN`s: run once; the
  loss is still recorded via `lost()`/`PoolRecovery::mark_lost` so revalidation still triggers).
- `execute_idempotent` (callers move to `retry_owner(.., Replay::IdempotentStatement, ..)`).
- `retried()`, `within_retry_window()` on the connection (budget moves to `RetryPolicy`), the `retries` and
  `idempotent_retries` counters in `PoolRecoveryStats` and their test assertions.
- `track_writes_retrying` (replaced by `retry_owner`; routes call sites at `routes/mod.rs` ≈758, ≈4401 switch).
- `db.rs` local loops: `retried` flag at ≈2552 and ≈2612. The route owner now covers a lost `BEGIN`/freeze lock
  (flag still false there). Preparatory registration: it opens a read-write transaction, so a loss after its
  `BEGIN` is uncertain and is no longer replayed (decision point 1).
- `begin_preparatory`/`begin_bulk_read` `run(.., true, ..)` wrappers: plain calls.

## Callers

- Handlers (`/delegate`, `/invoke` authorize): the DB call (`tinycloud.delegate`, `invoke_admitted`) is the attempt of
  `retry_owner(Replay::Never)`; the rest of the handler is outside it. `/revoke` and SQL `persist_write` keep
  `track_writes` only (no retry) unless their idempotency is shown separately.
- Hooks (`write_hooks.rs`): subscription matching and delivery-row writes run inside the invoking transaction;
  not owners. Delivery itself (network) never runs in the attempt: only the delivery row is written in-tx
  (TC-2614 webhook lease relies on this).
- KV reads (`/invoke` get, list, metadata, sync): `invoke_read_admitted` is the attempt of
  `retry_owner(Replay::Never)`. The read audit is its last step, so a run that fails before it recorded nothing and
  an audit failure is not a database error, so it is never retried: one audit record per successful read.
  KV puts and deletes are not retried; they fail once and the client sends them again.
- SQL hydration: the metadata read that starts a cold hydration (`load_meta`) is the attempt of its own
  `retry_owner(Replay::Never)`, inside the hydration task. Payload reads, the cache sink, the actor and the
  saves are outside it. `run_locked` and the cold-hydration entry refuse to run inside an attempt.
- Read-audit batches and the webhook dispatcher's two reads are owners (`IdempotentStatement` for the audit statement).
- share_email (`bridge.rs`, `state.rs`) and encryption_network (`keys.rs`, `key_delete.rs`,
  `deletion_ledger.rs`) transactions are not owners: their errors are mapped to storage errors that do not carry
  the database error, and some bodies handle key material. Their `BEGIN` is no longer retried by the pool wrapper;
  a lost connection returns the storage error and the caller sends the request again. Adopting the owner there
  means keeping the database error visible and moving non-database work out of the attempt.
- Background tasks with no request deadline: `policy` has no deadline condition; condition 4 is skipped.

## Tests (each TC-128 category)

`retry_owner` unit tests with injected `DbErr`: `connection_lost` and `io` before any write → retried once;
same after read-write `BEGIN`, after write success, after `COMMIT` loss → not retried; `pool_timeout`,
`pool_closed`, `statement_timeout`, `serialization`, `other` → not retried; second failure → returned, no third run;
`policy = None` → single run; first run leaving < MIN_RETRY of the budget → skipped; attempt 2 exceeding the remaining budget → dropped, attempt 1's error returned, tracker flag from attempt 2, no third run; background (`ctx = None`) task bounded the same; overload signal (injectable `Clock`, no sleeps): a cut/`pool_timeout`/`statement_timeout` stamp, then a `connection_lost` inside the 30 s window is not retried (also for `IdempotentStatement`), the same error just after the window is retried; a second stamp inside the window extends it; start line logged once per period and end line once (checked with a captured log subscriber), with only `error_class` and `suppress_ms` fields. Deterministic race tests on the pure transitions (manual clock, no threads or sleeps): (i) stamp@t, `watcher_step`@t+29.9 s → SleepFor, stamp@t+29.9 s extends, `watcher_step`@t+30 s → SleepFor(29.9 s), then Done at t+59.9 s: one start, one end; (ii) `watcher_step`@t+30 s → Done (end logged), then stamp@t+30 s → new start line and a new watcher: two periods, two starts, two ends, never an overlap; (iii) the expiry-vs-stamp race in both linearizations: stamp-before-step (window extended, step sleeps, no second start) and step-before-stamp (second period, one new start); (iv) concurrent max: every permutation of stamps at {5,3,9,7} s applied in turn leaves `until = 9 s + 30 s`, an older stamp after a newer one never lowers `until` or the mirror; plus a barrier-released 8-thread run of the same stamps asserting only the final `until`, the mirror, and `starts == 1`; (v) a stamp with an older `now` while active does not log a start; request cut/latched before backoff →
skipped; request cut during the backoff → attempt 2 never starts; remaining deadline < delay + remaining budget → skipped;
nested owner: outer + inner failing runs exactly one retry in total, and the inner never retries on its own;
`IdempotentStatement` retries an autocommit write that lost its connection, does NOT retry on `pool_timeout`,
and does NOT retry when an explicit transaction's `COMMIT` is lost (the idempotent-path lost-COMMIT test).
Route-level: existing `operation_retry.rs` retargeted. Existing statement-retry tests in `db_pool.rs` and
`postgres_connection_recovery.rs` that pin the removed layers are deleted or rewritten (listed to the lead before push,
and not pushed before Naomi approves).

## Decisions

Accepted in review: drop preparatory replay; `IdempotentStatement` only for `read_audit`; no concurrency cap in the first slice.
Overload suppression: Naomi chose the process-wide signal (30 s, all retries), with start/end log lines.

Details: TC-2610
