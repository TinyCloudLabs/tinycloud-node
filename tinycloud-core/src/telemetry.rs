use prometheus::{register_histogram_vec, HistogramVec};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::{Duration, Instant},
};

static TELEMETRY_ENABLED: AtomicBool = AtomicBool::new(false);

/// Explicit buckets for the internal pipeline-stage histogram. Individual
/// stages (DB begin, chain-guard waits, closure queries, read-audit waits)
/// are frequently sub-millisecond, so the low end is finer than the
/// request-level histograms while still reaching two minutes for the
/// pathological tail.
pub const SPAN_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
];

fn span_histogram() -> &'static HistogramVec {
    static SPAN_HISTOGRAM: OnceLock<HistogramVec> = OnceLock::new();
    SPAN_HISTOGRAM.get_or_init(|| {
        register_histogram_vec!(
            "tinycloud_span_duration_seconds",
            "Named internal operation latencies in seconds.",
            &["span", "outcome"],
            SPAN_BUCKETS.to_vec()
        )
        .expect("span histogram should register exactly once")
    })
}

pub fn set_enabled(enabled: bool) {
    TELEMETRY_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    TELEMETRY_ENABLED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationStage {
    RequestDecode,
    /// TC-326: no longer emitted by the auth-header guard, which actually
    /// measures header decode and now emits
    /// [`Self::AuthorizationHeaderDecode`] instead. TC-409 repurposes this
    /// label for the one cryptographic signature verification a successful
    /// `/invoke` performs, emitted by `AdmittedInvocation::admit`.
    InvocationSignatureVerify,
    ReplayCheck,
    AuthorizationGraphLoad,
    RevocationWork,
    KvIndexLookup,
    BlockRead,
    BlockWrite,
    EpochPersist,
    ResponseHandling,
    /// Decode of the base64url auth header into a typed event (TC-326: split
    /// out from the mislabeled `InvocationSignatureVerify`).
    AuthorizationHeaderDecode,
    /// Load of the delegation-closure edges that seed the chain guards.
    ChainClosureQuery,
    /// Time spent acquiring the per-chain mutex guards (contention wait).
    ChainGuardWait,
    /// Time spent acquiring a pooled database connection.
    DbPoolAcquire,
    /// The `BEGIN` transaction call (includes the coupled pool acquisition
    /// that sea-orm does not expose separately on the generic connection).
    DbTxBegin,
    /// Work performed inside the write transaction, from post-`BEGIN` to
    /// pre-`COMMIT`.
    DbTxBody,
    /// Wait for the durable read-audit record receipt on the read-only path.
    ReadAuditWait,
}

impl InvocationStage {
    pub const ALL: [Self; 17] = [
        Self::RequestDecode,
        Self::InvocationSignatureVerify,
        Self::ReplayCheck,
        Self::AuthorizationGraphLoad,
        Self::RevocationWork,
        Self::KvIndexLookup,
        Self::BlockRead,
        Self::BlockWrite,
        Self::EpochPersist,
        Self::ResponseHandling,
        Self::AuthorizationHeaderDecode,
        Self::ChainClosureQuery,
        Self::ChainGuardWait,
        Self::DbPoolAcquire,
        Self::DbTxBegin,
        Self::DbTxBody,
        Self::ReadAuditWait,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestDecode => "request_decode",
            Self::InvocationSignatureVerify => "invocation_signature_verify",
            Self::ReplayCheck => "replay_check",
            Self::AuthorizationGraphLoad => "authorization_graph_load",
            Self::RevocationWork => "revocation_work",
            Self::KvIndexLookup => "kv_index_lookup",
            Self::BlockRead => "block_read",
            Self::BlockWrite => "block_write",
            Self::EpochPersist => "epoch_persist",
            Self::ResponseHandling => "response_handling",
            Self::AuthorizationHeaderDecode => "authorization_header_decode",
            Self::ChainClosureQuery => "chain_closure_query",
            Self::ChainGuardWait => "chain_guard_wait",
            Self::DbPoolAcquire => "db_pool_acquire",
            Self::DbTxBegin => "db_tx_begin",
            Self::DbTxBody => "db_tx_body",
            Self::ReadAuditWait => "read_audit_wait",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageOutcome {
    Ok,
    Error,
}

impl StageOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

impl From<bool> for StageOutcome {
    fn from(value: bool) -> Self {
        if value {
            Self::Ok
        } else {
            Self::Error
        }
    }
}

pub fn observe_span(span: &'static str, outcome: &'static str, duration: Duration) {
    if enabled() {
        span_histogram()
            .with_label_values(&[span, outcome])
            .observe(duration.as_secs_f64());
    }
}

pub fn observe_stage(stage: InvocationStage, outcome: StageOutcome, duration: Duration) {
    observe_span(stage.as_str(), outcome.as_str(), duration);
}

/// RAII stage timer for spans with many exit points. Defaults to an `Error`
/// outcome so that any early `?`/`return` inside the guarded region is
/// recorded as a failure; call [`StageTimer::observe_ok`] at the success
/// boundary to record `Ok` (and disarm the drop). Used for the write-tx
/// body, whose failure modes are scattered across the transaction.
#[must_use = "the stage is only observed when the timer is dropped or finished"]
pub struct StageTimer {
    stage: InvocationStage,
    start: Instant,
    armed: bool,
}

impl StageTimer {
    pub fn start(stage: InvocationStage) -> Self {
        Self {
            stage,
            start: Instant::now(),
            armed: true,
        }
    }

    /// Record the span as successful and disarm the drop-time observation.
    pub fn observe_ok(mut self) {
        observe_stage(self.stage, StageOutcome::Ok, self.start.elapsed());
        self.armed = false;
    }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        if self.armed {
            observe_stage(self.stage, StageOutcome::Error, self.start.elapsed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_histogram_uses_fine_grained_buckets() {
        set_enabled(true);
        observe_stage(
            InvocationStage::DbTxBegin,
            StageOutcome::Ok,
            Duration::from_millis(1),
        );

        let metric = prometheus::gather()
            .into_iter()
            .find(|family| family.get_name() == "tinycloud_span_duration_seconds")
            .expect("span histogram should be registered");
        let bounds: Vec<f64> = metric.get_metric()[0]
            .get_histogram()
            .get_bucket()
            .iter()
            .map(|bucket| bucket.get_upper_bound())
            .collect();

        assert_eq!(bounds, SPAN_BUCKETS.to_vec());
    }

    #[test]
    fn all_stage_labels_are_unique_and_match_count() {
        let labels: Vec<&'static str> = InvocationStage::ALL
            .into_iter()
            .map(InvocationStage::as_str)
            .collect();
        assert_eq!(labels.len(), InvocationStage::ALL.len());
        let unique: std::collections::HashSet<&&str> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "stage labels must be unique");
    }
}
