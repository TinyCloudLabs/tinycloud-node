//! Fair shares of the node for `/invoke` (TC-3216).
//!
//! Two limits are checked after an invocation's signature is verified and
//! before any database work:
//!
//! - **Per verified invoker (session key):** a request-rate token bucket. The
//!   token is taken at the check, so concurrent requests cannot all pass on
//!   one token. It is given back when the request proves to be a replay, so a
//!   replayed copy of someone's request cannot spend their share (Bobbie,
//!   #625).
//! - **Per account:** the account is the owner of the invocation's spaces,
//!   keyed by the same HMAC pseudonym `node_request` logs as `account_hash`.
//!   - A database-time budget: a token bucket in milliseconds, debited by the
//!     measured query time of each response on every route. Only a response
//!     below 400 is charged to its account. Anyone with a valid session key
//!     can sign an invocation naming any space, and its authorization
//!     queries run before it is refused. If refused requests were charged,
//!     anyone could put a stranger's account in debt. A failed response's
//!     database time counts toward the node's total as unattributed.
//!   - A cap on the account's requests in flight at once. It is taken before
//!     authorization, so requests that will be refused also occupy places.
//!     That is harmless in shadow mode. Enforcing it needs those requests
//!     kept out of the count (TC-3216, before enforcement).
//!
//!   An invocation that targets more than one account has no single account
//!   and is not limited per account.
//!
//! Each limit runs in shadow mode until it is enforced: an over-limit request
//! is counted and reported but still admitted. Once enforced, it is refused
//! with `429 rate_limited` and `Retry-After`.
//!
//! Once a minute, [`run_report`] emits aggregated warn lines:
//!
//! - one per limit that was exceeded: `invoke_rate_limited` or
//!   `account_limited`, with the count and the account most often over;
//! - `node_top_talkers`: the three accounts with the most database time and
//!   their share of the node's.
//!
//! Lines carry account pseudonyms only, never a DID, an invoker or a space.

use crate::{
    config::InvocationConfig,
    prometheus::{observe_account_limited, observe_invoke_rate_limited},
};
use rocket::request::{FromRequest, Outcome, Request};
use std::{
    borrow::Borrow,
    collections::HashMap,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

/// An account pseudonym: the bytes `node_request` logs as `account_hash`.
pub type AccountHash = [u8; 32];

/// The window of the aggregated log lines.
pub const REPORT_WINDOW_SECS: u64 = 60;

/// The most callers tracked at once per bucket family. A full bucket is the
/// same as no bucket, so full ones are forgotten first. If the map is still
/// full after that, a new caller is admitted untracked rather than growing the
/// map.
const MAX_TRACKED_CALLERS: usize = 100_000;

/// The most accounts counted by name in one report window. Past that, the
/// database time of an account seen for the first time still counts toward
/// the node's total, but not under its own name.
const MAX_REPORTED_ACCOUNTS: usize = 10_000;

/// How many accounts the top-talker line names.
const TOP_TALKERS: usize = 3;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whole seconds to send as `Retry-After`, at least one.
fn retry_after_secs(wait: Duration) -> u64 {
    wait.as_secs_f64().ceil().max(1.0) as u64
}

/// Which limit a request went over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// The per-invoker request rate.
    Invoker,
    /// The per-account database-time budget.
    DbTime,
    /// The per-account cap on requests in flight.
    InFlight,
}

impl Limit {
    const ALL: [Self; 3] = [Self::Invoker, Self::DbTime, Self::InFlight];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoker => "invoker",
            Self::DbTime => "db_time",
            Self::InFlight => "in_flight",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

fn mode(enforce: bool) -> &'static str {
    if enforce {
        "enforce"
    } else {
        "shadow"
    }
}

struct Buckets<K> {
    state: Mutex<HashMap<K, TokenBucket>>,
    per_second: f64,
    max: f64,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl<K: Eq + Hash> Buckets<K> {
    /// `per_minute` tokens a minute, sustained. A bucket holds at most
    /// `burst` plus one second's refill, and a new key starts full. With a
    /// zero rate the bucket never refills, so callers must not build one.
    fn new(per_minute: u32, burst: u32) -> Self {
        let per_second = f64::from(per_minute) / 60.0;
        Self {
            state: Mutex::new(HashMap::new()),
            per_second,
            max: f64::from(burst) + per_second,
        }
    }

    /// Take `amount` from `key`'s bucket if it holds that much. If not, return
    /// how long until it will.
    fn take<Q>(&self, key: &Q, amount: f64, now: Instant) -> Result<(), Duration>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        self.with_bucket(key, now, |bucket| {
            self.holds(bucket, amount)?;
            bucket.tokens -= amount;
            Ok(())
        })
        .unwrap_or(Ok(()))
    }

    /// Like [`take`](Self::take), but spends nothing.
    fn peek<Q>(&self, key: &Q, amount: f64, now: Instant) -> Result<(), Duration>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        self.with_bucket(key, now, |bucket| self.holds(bucket, amount))
            .unwrap_or(Ok(()))
    }

    /// Give `amount` back to `key`'s bucket, up to its capacity.
    fn give<Q>(&self, key: &Q, amount: f64, now: Instant)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        self.with_bucket(key, now, |bucket| {
            bucket.tokens = (bucket.tokens + amount).min(self.max);
        });
    }

    /// Spend `amount` from `key`'s bucket whether or not it holds that much.
    /// The debt is capped at one full bucket, so a single expensive request
    /// cannot shut its key out for longer than it takes to refill a bucket
    /// twice over.
    fn spend<Q>(&self, key: &Q, amount: f64, now: Instant)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        self.with_bucket(key, now, |bucket| {
            bucket.tokens = (bucket.tokens - amount).max(-self.max);
        });
    }

    fn holds(&self, bucket: &TokenBucket, amount: f64) -> Result<(), Duration> {
        if bucket.tokens >= amount {
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (amount - bucket.tokens) / self.per_second,
            ))
        }
    }

    /// Run `f` on `key`'s bucket after refilling it to `now`. Returns `None`
    /// when the key cannot be tracked (see [`MAX_TRACKED_CALLERS`]).
    fn with_bucket<Q, R>(
        &self,
        key: &Q,
        now: Instant,
        f: impl FnOnce(&mut TokenBucket) -> R,
    ) -> Option<R>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        let mut state = locked(&self.state);
        let refilled = |bucket: &TokenBucket| {
            let elapsed = now.saturating_duration_since(bucket.last_refill);
            (bucket.tokens + elapsed.as_secs_f64() * self.per_second).min(self.max)
        };
        if !state.contains_key(key) {
            if state.len() >= MAX_TRACKED_CALLERS {
                state.retain(|_, bucket| refilled(bucket) < self.max);
                if state.len() >= MAX_TRACKED_CALLERS {
                    return None;
                }
            }
            state.insert(
                key.to_owned(),
                TokenBucket {
                    tokens: self.max,
                    last_refill: now,
                },
            );
        }
        let bucket = state.get_mut(key)?;
        bucket.tokens = refilled(bucket);
        bucket.last_refill = now;
        Some(f(bucket))
    }
}

/// Over-limit requests for one limit in the current report window.
#[derive(Default)]
struct OverLimit {
    count: u64,
    by_account: HashMap<AccountHash, u64>,
}

impl OverLimit {
    fn observe(&mut self, account: Option<AccountHash>) {
        self.count += 1;
        if let Some(account) = account {
            if self.by_account.len() < MAX_REPORTED_ACCOUNTS
                || self.by_account.contains_key(&account)
            {
                *self.by_account.entry(account).or_default() += 1;
            }
        }
    }

    /// The window's summary, if any request went over; resets the window.
    fn take(&mut self) -> Option<OverLimitSummary> {
        let window = std::mem::take(self);
        (window.count > 0).then(|| OverLimitSummary {
            count: window.count,
            accounts: window.by_account.len(),
            // Ties go to the smallest hash, so the line is deterministic.
            top_account: window.by_account.into_iter().max_by(
                |(a_hash, a_count), (b_hash, b_count)| {
                    a_count.cmp(b_count).then_with(|| b_hash.cmp(a_hash))
                },
            ),
        })
    }
}

/// One limit's over-limit requests in a report window.
#[derive(Debug, PartialEq, Eq)]
pub struct OverLimitSummary {
    pub count: u64,
    /// Distinct accounts among them (requests with no single account are not
    /// counted here).
    pub accounts: usize,
    /// The account most often over, with its count.
    pub top_account: Option<(AccountHash, u64)>,
}

/// Database time in the current report window.
#[derive(Default)]
struct Talkers {
    db_ns: u64,
    requests: u64,
    unattributed_db_ns: u64,
    by_account: HashMap<AccountHash, AccountUse>,
}

#[derive(Clone, Copy, Default)]
struct AccountUse {
    db_ns: u64,
    requests: u64,
}

impl Talkers {
    fn observe(&mut self, account: Option<AccountHash>, db_ns: u64) {
        self.db_ns = self.db_ns.saturating_add(db_ns);
        self.requests += 1;
        let Some(account) = account else {
            self.unattributed_db_ns = self.unattributed_db_ns.saturating_add(db_ns);
            return;
        };
        if self.by_account.len() < MAX_REPORTED_ACCOUNTS || self.by_account.contains_key(&account) {
            let usage = self.by_account.entry(account).or_default();
            usage.db_ns = usage.db_ns.saturating_add(db_ns);
            usage.requests += 1;
        }
    }

    /// The window's summary, if it saw any database time.
    fn summarize(self) -> Option<TalkerSummary> {
        if self.db_ns == 0 {
            return None;
        }
        let accounts = self.by_account.len();
        let mut ranked: Vec<_> = self.by_account.into_iter().collect();
        ranked.sort_unstable_by(|(a_hash, a), (b_hash, b)| {
            b.db_ns.cmp(&a.db_ns).then_with(|| a_hash.cmp(b_hash))
        });
        ranked.truncate(TOP_TALKERS);
        let total = self.db_ns;
        Some(TalkerSummary {
            db_ms: total / 1_000_000,
            requests: self.requests,
            unattributed_db_ms: self.unattributed_db_ns / 1_000_000,
            accounts,
            top: ranked
                .into_iter()
                .map(|(account, usage)| TopTalker {
                    account,
                    db_ms: usage.db_ns / 1_000_000,
                    requests: usage.requests,
                    share: usage.db_ns as f64 / total as f64,
                })
                .collect(),
        })
    }
}

/// The node's database time in a report window.
#[derive(Debug, PartialEq)]
pub struct TalkerSummary {
    pub db_ms: u64,
    /// Responses observed, with or without database time.
    pub requests: u64,
    /// Database time of requests with no single account.
    pub unattributed_db_ms: u64,
    /// Distinct accounts seen.
    pub accounts: usize,
    /// At most three accounts, most database time first.
    pub top: Vec<TopTalker>,
}

#[derive(Debug, PartialEq)]
pub struct TopTalker {
    pub account: AccountHash,
    pub db_ms: u64,
    pub requests: u64,
    /// This account's fraction of the window's database time, from 0 to 1.
    pub share: f64,
}

/// What one report window held. [`FairShare::report`] logs it.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub over: Vec<(Limit, OverLimitSummary)>,
    pub talkers: Option<TalkerSummary>,
}

#[derive(Default)]
struct Window {
    over: [OverLimit; 3],
    talkers: Talkers,
}

/// The `/invoke` fair-share limits and the node's database-time accounting.
pub struct FairShare {
    invokers: Option<Buckets<String>>,
    invoker_enforce: bool,
    db_time_ms: Option<Buckets<AccountHash>>,
    max_in_flight: u32,
    in_flight: Mutex<HashMap<AccountHash, u32>>,
    account_enforce: bool,
    window: Mutex<Window>,
}

/// An admitted request's place in its account's in-flight count. It is
/// released on drop.
#[must_use]
pub struct AccountPermit<'a> {
    slot: Option<(&'a Mutex<HashMap<AccountHash, u32>>, AccountHash)>,
}

impl Drop for AccountPermit<'_> {
    fn drop(&mut self) {
        if let Some((in_flight, account)) = self.slot.take() {
            let mut in_flight = locked(in_flight);
            if let Some(count) = in_flight.get_mut(&account) {
                *count -= 1;
                if *count == 0 {
                    in_flight.remove(&account);
                }
            }
        }
    }
}

impl FairShare {
    /// The limits `config` sets. A zero rate, budget or cap turns that limit
    /// off. An invoker burst below one would refuse every request, so it is
    /// raised to one.
    pub fn new(config: &InvocationConfig) -> Self {
        Self {
            invokers: (config.rate_limit_per_minute > 0).then(|| {
                Buckets::new(config.rate_limit_per_minute, config.rate_limit_burst.max(1))
            }),
            invoker_enforce: config.rate_limit_enforce,
            db_time_ms: (config.account_db_ms_per_minute > 0)
                .then(|| Buckets::new(config.account_db_ms_per_minute, config.account_db_burst_ms)),
            max_in_flight: config.account_max_in_flight,
            in_flight: Mutex::new(HashMap::new()),
            account_enforce: config.account_limit_enforce,
            window: Mutex::new(Window::default()),
        }
    }

    fn over(&self, limit: Limit, account: Option<AccountHash>, enforce: bool) {
        let mode = mode(enforce);
        match limit {
            Limit::Invoker => observe_invoke_rate_limited(mode),
            Limit::DbTime | Limit::InFlight => observe_account_limited(limit.as_str(), mode),
        }
        locked(&self.window).over[limit.index()].observe(account);
    }

    /// Take one of `invoker`'s tokens for a `/invoke` request. `invoker` is a
    /// verified invocation's issuer and `account` the account it targets. If
    /// the request is refused later as a replay, give the token back with
    /// [`refund_invoker`](Self::refund_invoker).
    ///
    /// Returns `Ok(true)` when a token was taken. Over the limit, the request
    /// is counted; enforced, the result is the whole seconds to send as
    /// `Retry-After`, and shadowed, `Ok(false)` (admitted, nothing taken).
    pub fn check_invoker(&self, invoker: &str, account: Option<AccountHash>) -> Result<bool, u64> {
        let Some(buckets) = &self.invokers else {
            return Ok(false);
        };
        let Err(wait) = buckets.take(invoker, 1.0, Instant::now()) else {
            return Ok(true);
        };
        self.over(Limit::Invoker, account, self.invoker_enforce);
        if self.invoker_enforce {
            Err(retry_after_secs(wait))
        } else {
            Ok(false)
        }
    }

    /// Give back the token [`check_invoker`](Self::check_invoker) took for a
    /// request that was then refused before doing its work (a replay, or an
    /// enforced per-account limit).
    pub fn refund_invoker(&self, invoker: &str) {
        if let Some(buckets) = &self.invokers {
            buckets.give(invoker, 1.0, Instant::now());
        }
    }

    /// Admit one `/invoke` request for `account` if its database-time budget
    /// is not in debt and it has fewer than the cap in flight. Hold the
    /// returned permit until the request's work is done.
    ///
    /// Over either limit, the request is counted. Enforced, the result is the
    /// whole seconds to send as `Retry-After`: until the debt is repaid, or
    /// one second for the in-flight cap. Shadowed, it is admitted and counted
    /// in flight.
    pub fn check_account(&self, account: AccountHash) -> Result<AccountPermit<'_>, u64> {
        let mut refused = None;
        if let Some(buckets) = &self.db_time_ms {
            if let Err(wait) = buckets.peek(&account, 0.0, Instant::now()) {
                self.over(Limit::DbTime, Some(account), self.account_enforce);
                refused = Some(retry_after_secs(wait));
            }
        }
        let mut permit = AccountPermit { slot: None };
        if self.max_in_flight > 0 {
            let mut in_flight = locked(&self.in_flight);
            let current = in_flight.get(&account).copied().unwrap_or(0);
            if current >= self.max_in_flight {
                self.over(Limit::InFlight, Some(account), self.account_enforce);
                refused.get_or_insert(1);
            }
            let admitted = refused.is_none() || !self.account_enforce;
            if admitted && (current > 0 || in_flight.len() < MAX_TRACKED_CALLERS) {
                *in_flight.entry(account).or_default() += 1;
                permit.slot = Some((&self.in_flight, account));
            }
        }
        match refused {
            Some(retry_after) if self.account_enforce => Err(retry_after),
            _ => Ok(permit),
        }
    }

    /// Account one response's database time, `query_time_ns`, to `account`,
    /// the request's single target account if it had one. Debits the
    /// account's budget and adds to the top-talker window.
    ///
    /// A response with `status` 400 or above is charged to no account and
    /// counts as unattributed. Its request may have named a space it was then
    /// refused, and charging the space's owner would let anyone spend a
    /// stranger's budget.
    pub fn observe_db_time(&self, account: Option<AccountHash>, status: u16, query_time_ns: u64) {
        let account = account.filter(|_| status < 400);
        if let (Some(buckets), Some(account)) = (&self.db_time_ms, account) {
            if query_time_ns > 0 {
                buckets.spend(&account, query_time_ns as f64 / 1_000_000.0, Instant::now());
            }
        }
        locked(&self.window).talkers.observe(account, query_time_ns);
    }

    /// Take the window since the last call, starting a new one.
    fn take_window(&self) -> Report {
        let window = std::mem::take(&mut *locked(&self.window));
        let Window { over, talkers } = window;
        Report {
            over: Limit::ALL
                .into_iter()
                .zip(over)
                .filter_map(|(limit, mut over)| over.take().map(|summary| (limit, summary)))
                .collect(),
            talkers: talkers.summarize(),
        }
    }

    /// Log the window since the last report and start a new one. Emits one
    /// line per limit that was exceeded, and the top-talker line if the node
    /// spent any database time.
    pub fn report(&self) -> Report {
        let report = self.take_window();
        for (limit, over) in &report.over {
            let (top_account_hash, top_account_count) = over
                .top_account
                .map_or((String::new(), 0), |(hash, count)| {
                    (hex::encode(hash), count)
                });
            match limit {
                Limit::Invoker => tracing::warn!(
                    event = "invoke_rate_limited",
                    mode = mode(self.invoker_enforce),
                    count = over.count,
                    accounts = over.accounts,
                    top_account_hash,
                    top_account_count,
                    window_s = REPORT_WINDOW_SECS,
                    "invocations over the per-invoker rate limit"
                ),
                Limit::DbTime | Limit::InFlight => tracing::warn!(
                    event = "account_limited",
                    limit = limit.as_str(),
                    mode = mode(self.account_enforce),
                    count = over.count,
                    accounts = over.accounts,
                    top_account_hash,
                    top_account_count,
                    window_s = REPORT_WINDOW_SECS,
                    "invocations over a per-account limit"
                ),
            }
        }
        if let Some(talkers) = &report.talkers {
            let field = |rank: usize| {
                talkers
                    .top
                    .get(rank)
                    .map_or((String::new(), 0, 0, 0.0), |top| {
                        (hex::encode(top.account), top.db_ms, top.requests, top.share)
                    })
            };
            let (top1_account_hash, top1_db_ms, top1_requests, top1_share) = field(0);
            let (top2_account_hash, top2_db_ms, top2_requests, top2_share) = field(1);
            let (top3_account_hash, top3_db_ms, top3_requests, top3_share) = field(2);
            tracing::warn!(
                event = "node_top_talkers",
                window_s = REPORT_WINDOW_SECS,
                db_ms = talkers.db_ms,
                requests = talkers.requests,
                unattributed_db_ms = talkers.unattributed_db_ms,
                accounts = talkers.accounts,
                top1_account_hash,
                top1_db_ms,
                top1_requests,
                top1_share,
                top2_account_hash,
                top2_db_ms,
                top2_requests,
                top2_share,
                top3_account_hash,
                top3_db_ms,
                top3_requests,
                top3_share,
                "accounts with the most database time"
            );
        }
        report
    }
}

/// Report once every [`REPORT_WINDOW_SECS`] until `stop` resolves.
pub async fn run_report(fair_share: Arc<FairShare>, stop: impl Future<Output = ()>) {
    let period = Duration::from_secs(REPORT_WINDOW_SECS);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                fair_share.report();
            }
            _ = &mut stop => break,
        }
    }
}

/// The node's [`FairShare`], when one is managed. Rockets built without one
/// (unit-test rockets) are not limited.
pub struct InvokeFairShare<'r>(pub Option<&'r FairShare>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for InvokeFairShare<'r> {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(
            request.rocket().state::<Arc<FairShare>>().map(Arc::as_ref),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> InvocationConfig {
        InvocationConfig {
            rate_limit_per_minute: 0,
            account_db_ms_per_minute: 0,
            account_max_in_flight: 0,
            ..Default::default()
        }
    }

    const A: AccountHash = [0xaa; 32];
    const B: AccountHash = [0xbb; 32];
    const C: AccountHash = [0xcc; 32];
    const D: AccountHash = [0xdd; 32];

    /// A budget of 60 ms a minute refills 1 ms a second, so a test's own run
    /// time barely moves the balance.
    fn db_time_config(enforce: bool) -> InvocationConfig {
        InvocationConfig {
            account_db_ms_per_minute: 60,
            account_db_burst_ms: 100,
            account_limit_enforce: enforce,
            ..config()
        }
    }

    #[test]
    fn an_account_in_database_time_debt_is_refused_until_repaid() {
        let fair_share = FairShare::new(&db_time_config(true));
        assert!(
            fair_share.check_account(A).is_ok(),
            "a new account has budget"
        );

        // 500 ms against a 101 ms bucket: the debt is capped at one bucket.
        fair_share.observe_db_time(Some(A), 200, 500_000_000);
        let retry_after = fair_share
            .check_account(A)
            .err()
            .expect("an account in debt is refused");
        // The debt is capped at one bucket (101 ms), repaid at 1 ms a second.
        assert!(
            (100..=101).contains(&retry_after),
            "Retry-After {retry_after}"
        );
        assert!(
            fair_share.check_account(B).is_ok(),
            "another account keeps its own budget"
        );
        let report = fair_share.take_window();
        assert_eq!(
            report.over,
            vec![(
                Limit::DbTime,
                OverLimitSummary {
                    count: 1,
                    accounts: 1,
                    top_account: Some((A, 1)),
                }
            )]
        );
    }

    #[test]
    fn database_time_debt_is_counted_but_admitted_in_shadow_mode() {
        let fair_share = FairShare::new(&db_time_config(false));
        fair_share.observe_db_time(Some(A), 200, 500_000_000);
        assert!(fair_share.check_account(A).is_ok());
        assert!(fair_share.check_account(A).is_ok());
        let report = fair_share.take_window();
        assert_eq!(report.over.len(), 1);
        assert_eq!(report.over[0].0, Limit::DbTime);
        assert_eq!(report.over[0].1.count, 2);
    }

    #[test]
    fn database_time_without_a_single_account_spends_no_budget() {
        let fair_share = FairShare::new(&db_time_config(true));
        fair_share.observe_db_time(None, 200, 500_000_000);
        assert!(fair_share.check_account(A).is_ok());
    }

    #[test]
    fn a_refused_requests_database_time_is_charged_to_no_account() {
        let fair_share = FairShare::new(&db_time_config(true));
        for status in [401, 403, 404, 500] {
            fair_share.observe_db_time(Some(A), status, 500_000_000);
        }
        assert!(
            fair_share.check_account(A).is_ok(),
            "a stranger's refused requests do not spend the account's budget"
        );
        let talkers = fair_share.take_window().talkers.expect("database time");
        assert_eq!(talkers.unattributed_db_ms, 2_000);
        assert_eq!(talkers.accounts, 0);
        assert!(talkers.top.is_empty());
    }

    #[test]
    fn the_in_flight_cap_frees_a_place_when_a_request_finishes() {
        let fair_share = FairShare::new(&InvocationConfig {
            account_max_in_flight: 2,
            account_limit_enforce: true,
            ..config()
        });
        let first = fair_share.check_account(A).expect("first in flight");
        let _second = fair_share.check_account(A).expect("second in flight");
        assert_eq!(fair_share.check_account(A).err(), Some(1));
        assert!(
            fair_share.check_account(B).is_ok(),
            "the cap is per account"
        );

        drop(first);
        assert!(
            fair_share.check_account(A).is_ok(),
            "a finished request frees its place"
        );
    }

    #[test]
    fn a_shadowed_in_flight_cap_still_counts_the_admitted_request() {
        let fair_share = FairShare::new(&InvocationConfig {
            account_max_in_flight: 1,
            ..config()
        });
        let _first = fair_share.check_account(A).expect("admitted");
        let _second = fair_share.check_account(A).expect("shadow admits");
        let _third = fair_share.check_account(A).expect("shadow admits");
        let report = fair_share.take_window();
        assert_eq!(report.over[0].0, Limit::InFlight);
        assert_eq!(
            report.over[0].1.count, 2,
            "the second and third were both over one in flight"
        );
    }

    #[test]
    fn a_refunded_invoker_token_admits_the_next_request() {
        let fair_share = FairShare::new(&InvocationConfig {
            rate_limit_per_minute: 1,
            rate_limit_burst: 1,
            rate_limit_enforce: true,
            ..config()
        });
        assert_eq!(fair_share.check_invoker("did:key:z1", Some(A)), Ok(true));
        assert!(fair_share.check_invoker("did:key:z1", Some(A)).is_err());
        fair_share.refund_invoker("did:key:z1");
        assert_eq!(fair_share.check_invoker("did:key:z1", Some(A)), Ok(true));

        let report = fair_share.take_window();
        assert_eq!(
            report.over,
            vec![(
                Limit::Invoker,
                OverLimitSummary {
                    count: 1,
                    accounts: 1,
                    top_account: Some((A, 1)),
                }
            )]
        );
    }

    #[test]
    fn a_refund_never_raises_a_bucket_above_its_capacity() {
        let fair_share = FairShare::new(&InvocationConfig {
            rate_limit_per_minute: 1,
            rate_limit_burst: 1,
            rate_limit_enforce: true,
            ..config()
        });
        fair_share.refund_invoker("did:key:z1");
        fair_share.refund_invoker("did:key:z1");
        assert_eq!(fair_share.check_invoker("did:key:z1", None), Ok(true));
        assert!(fair_share.check_invoker("did:key:z1", None).is_err());
    }

    #[test]
    fn the_top_talkers_are_ranked_by_database_time_with_their_share() {
        let fair_share = FairShare::new(&config());
        for _ in 0..3 {
            fair_share.observe_db_time(Some(A), 200, 100_000_000);
        }
        fair_share.observe_db_time(Some(B), 200, 500_000_000);
        fair_share.observe_db_time(Some(C), 304, 200_000_000);
        fair_share.observe_db_time(Some(D), 200, 100_000_000);
        fair_share.observe_db_time(None, 200, 100_000_000);
        fair_share.observe_db_time(Some(D), 200, 0);

        let talkers = fair_share.take_window().talkers.expect("database time");
        assert_eq!(talkers.db_ms, 1_200);
        assert_eq!(talkers.requests, 8);
        assert_eq!(talkers.unattributed_db_ms, 100);
        assert_eq!(talkers.accounts, 4);
        let ranked: Vec<_> = talkers
            .top
            .iter()
            .map(|top| (top.account, top.db_ms, top.requests))
            .collect();
        assert_eq!(ranked, vec![(B, 500, 1), (A, 300, 3), (C, 200, 1)]);
        assert!((talkers.top[0].share - 500.0 / 1_200.0).abs() < 1e-9);

        assert_eq!(
            fair_share.take_window(),
            Report::default(),
            "a report starts a new window"
        );
    }
}
