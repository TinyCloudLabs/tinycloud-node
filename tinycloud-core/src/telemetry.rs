use prometheus::{register_histogram_vec, HistogramVec};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::Duration,
};

static TELEMETRY_ENABLED: AtomicBool = AtomicBool::new(false);

fn span_histogram() -> &'static HistogramVec {
    static SPAN_HISTOGRAM: OnceLock<HistogramVec> = OnceLock::new();
    SPAN_HISTOGRAM.get_or_init(|| {
        register_histogram_vec!(
            "tinycloud_span_duration_seconds",
            "Named internal operation latencies in seconds.",
            &["span", "outcome"]
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
    InvocationSignatureVerify,
    ReplayCheck,
    AuthorizationGraphLoad,
    RevocationWork,
    KvIndexLookup,
    BlockRead,
    BlockWrite,
    EpochPersist,
    ResponseHandling,
}

impl InvocationStage {
    pub const ALL: [Self; 10] = [
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
