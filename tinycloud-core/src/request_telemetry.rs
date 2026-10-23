//! Request-local database metrics and bounded, node-keyed identity pseudonyms.
//!
//! Raw account/space identifiers and the HMAC key never enter metrics, snapshots,
//! or diagnostic formatting. Conflicting identities permanently omit that hash
//! for the request instead of reporting a misleading first identity.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use pin_project::pin_project;
use tinycloud_auth::resource::SpaceId;
use uuid::Uuid;

use crate::failure_diagnostic::{FailureCode, FailureNote, Service};
use crate::telemetry::{Pseudonym, Pseudonymizer};

pub use sqlx_core::request_telemetry::{Metrics, PoolTimer, QueryTimer, Snapshot};

thread_local! {
    static CURRENT: RefCell<Option<Arc<RequestContext>>> = const { RefCell::new(None) };
}

#[derive(Default)]
enum HashSlot {
    #[default]
    Unobserved,
    One(Pseudonym),
    Conflicted,
}

impl HashSlot {
    fn observe(&mut self, hash: Pseudonym) {
        match self {
            Self::Unobserved => *self = Self::One(hash),
            // CtOutput compares cryptographic bytes in constant time.
            Self::One(previous) if *previous != hash => *self = Self::Conflicted,
            _ => {}
        }
    }

    fn hash(&self) -> Option<[u8; 32]> {
        match self {
            Self::One(hash) => Some(hash.clone().into_bytes().into()),
            Self::Unobserved | Self::Conflicted => None,
        }
    }
}

#[derive(Default)]
struct IdentityState {
    account: HashSlot,
    space: HashSlot,
}

/// Optional binary hashes; encode as lowercase hex only when emitting an event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hashes {
    /// HMAC of the unique target space-owner DID, or absent/ambiguous.
    pub account_hash: Option<[u8; 32]>,
    /// HMAC of the unique canonical target SpaceId, or absent/ambiguous.
    pub space_hash: Option<[u8; 32]>,
}

/// One request's ID, data-free counters, and bounded pseudonym state.
///
/// Deliberately has no `Debug` implementation and retains no raw identities.
pub struct RequestContext {
    request_id: Uuid,
    metrics: Arc<Metrics>,
    pseudonymizer: Arc<Pseudonymizer>,
    identities: Mutex<IdentityState>,
    failure: Mutex<Option<FailureNote>>,
}

impl RequestContext {
    /// Create independent counters for one canonical request UUID.
    pub fn new(request_id: Uuid, pseudonymizer: Arc<Pseudonymizer>) -> Arc<Self> {
        Arc::new(Self {
            request_id,
            metrics: Arc::new(Metrics::default()),
            pseudonymizer,
            identities: Mutex::new(IdentityState::default()),
            failure: Mutex::new(None),
        })
    }

    /// Return the request ID for same-request outbound HTTP propagation.
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Share this request's counters with an explicitly scoped worker.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Read this request's numeric database timing totals.
    pub fn snapshot(&self) -> Snapshot {
        self.metrics.snapshot()
    }

    /// Observe an authenticated/canonical space without retaining its identity.
    ///
    /// Hashes the exact `SpaceId` display bytes without allocating a formatted
    /// string. Only bounded digests are kept; repeated identities must be hashed
    /// to compare them, while an already-conflicted slot requires no more work.
    pub fn observe_space(&self, space: &SpaceId) {
        let mut identities = self
            .identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(identities.account, HashSlot::Conflicted) {
            identities
                .account
                .observe(self.pseudonymizer.account_hash(space));
        }
        if !matches!(identities.space, HashSlot::Conflicted) {
            identities
                .space
                .observe(self.pseudonymizer.space_hash(space));
        }
    }

    /// Return only unambiguous pseudonyms; absent/conflicting identities are omitted.
    pub fn hashes(&self) -> Hashes {
        let identities = self
            .identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Hashes {
            account_hash: identities.account.hash(),
            space_hash: identities.space.hash(),
        }
    }

    /// Record the request's database failure, replacing an earlier one.
    pub fn note_failure(&self, note: FailureNote) {
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(note);
    }

    /// The recorded failure becomes one after which a write may have been
    /// applied; with none recorded, `service` and `db_hash` start one of
    /// kind `other`.
    pub fn note_outcome_unknown(&self, service: Service, db_hash: Option<String>) {
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let note = failure.get_or_insert_with(|| FailureNote {
            service,
            code: FailureCode::OutcomeUnknown,
            kind: "other",
            write_may_have_applied: true,
            db_hash,
        });
        note.code = FailureCode::OutcomeUnknown;
        note.write_may_have_applied = true;
    }

    /// The request's recorded database failure, if any.
    pub fn failure(&self) -> Option<FailureNote> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Return the request installed for the current poll or synchronous worker.
pub fn current() -> Option<Arc<RequestContext>> {
    CURRENT.with(|current| current.borrow().clone())
}

/// Observe a space if an HTTP request context is currently installed.
pub fn observe_space(space: &SpaceId) {
    if let Some(context) = current() {
        context.observe_space(space);
    }
}

/// The keyed pseudonym of the database (`service`, `space`, `physical_name`)
/// as 64 lowercase hex digits, from the current request's pseudonymizer
/// ([`Pseudonymizer::db_hash`]). `None` outside an HTTP request.
pub fn db_hash(service: &str, space: &SpaceId, physical_name: &str) -> Option<String> {
    let context = current()?;
    let hash = context
        .pseudonymizer
        .db_hash(service, space, physical_name)
        .ok()?;
    Some(hex::encode(hash.into_bytes()))
}

/// Record the database failure the current request is about to answer with a
/// 5xx (TC-1796); a later note replaces an earlier one. A no-op outside an
/// HTTP request.
pub fn note_failure(note: FailureNote) {
    if let Some(context) = current() {
        context.note_failure(note);
    }
}

/// The request's write may have been applied before it failed (its artifact
/// write was sent): the recorded failure becomes
/// [`FailureCode::OutcomeUnknown`]. A request with no recorded failure gets
/// one for `service` and `db_hash`, kind `other`.
pub fn note_outcome_unknown(service: Service, db_hash: Option<String>) {
    if let Some(context) = current() {
        context.note_outcome_unknown(service, db_hash);
    }
}

/// Restores both request identity and SQLx metrics on the entering thread.
pub struct EnterGuard {
    previous: Option<Arc<RequestContext>>,
    _metrics: sqlx_core::request_telemetry::EnterGuard,
}

/// Install context for synchronous work. Never keep the guard across an await.
pub fn enter(context: Option<Arc<RequestContext>>) -> EnterGuard {
    let metrics = sqlx_core::request_telemetry::enter(context.as_ref().map(|ctx| ctx.metrics()));
    let previous = CURRENT.with(|current| current.replace(context));
    EnterGuard {
        previous,
        _metrics: metrics,
    }
}

impl Drop for EnterGuard {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
    }
}

/// An allocation-free future wrapper installing context for each poll only.
#[pin_project]
pub struct Scope<F> {
    context: Arc<RequestContext>,
    #[pin]
    future: F,
}

/// Scope a request handler without leaking its context to interleaved tasks.
pub fn scope<F: Future>(context: Arc<RequestContext>, future: F) -> Scope<F> {
    Scope { context, future }
}

impl<F: Future> Future for Scope<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let _guard = enter(Some(Arc::clone(this.context)));
        this.future.poll(cx)
    }
}
