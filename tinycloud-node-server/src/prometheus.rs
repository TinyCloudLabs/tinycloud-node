use hyper::{header::CONTENT_TYPE, Body, Request, Response};
use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, Encoder, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    TextEncoder,
};

pub use tinycloud_core::telemetry::{
    enabled, observe_span, observe_stage, set_enabled, InvocationStage, StageOutcome,
};

/// Explicit buckets for the request-level latency histograms (route,
/// authorized-invoke, authorization). The prometheus default buckets top out
/// at 10s, which collapses everything slow into `+Inf` and hides the tail we
/// need for the scaling review; these reach five minutes.
pub const REQUEST_LATENCY_BUCKETS: &[f64] = &[
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0,
    180.0, 300.0,
];

/// Buckets for remaining-validity slack (`exp - now`) observed at successful
/// invocation validation. Short-lived session tokens cluster in the tens of
/// seconds; the ten-minute ceiling covers longer-lived delegations.
pub const VALIDITY_SLACK_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 15.0, 30.0, 45.0, 60.0, 90.0, 120.0, 300.0, 600.0,
];

lazy_static! {
    pub static ref REQUEST_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_http_request_duration_seconds",
        "HTTP request latencies in seconds.",
        &["method", "route", "status"],
        REQUEST_LATENCY_BUCKETS.to_vec()
    )
    .unwrap();
    pub static ref AUTHORIZED_INVOKE_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_authorized_invoke_duration_seconds",
        "The authorized invocations latencies in seconds.",
        &["action"],
        REQUEST_LATENCY_BUCKETS.to_vec()
    )
    .unwrap();
    pub static ref AUTHORIZATION_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_authorization_duration_seconds",
        "The authorization latencies in seconds.",
        &["request"],
        REQUEST_LATENCY_BUCKETS.to_vec()
    )
    .unwrap();
    pub static ref SIGNED_KV_BYTES: IntCounterVec = register_int_counter_vec!(
        "tinycloud_signed_kv_bytes_total",
        "Object and response bytes for successful signed KV reads.",
        &["measure"]
    )
    .unwrap();
    /// Rejections of invocations whose signed time window is invalid, split by
    /// a fixed, bounded reason label.
    pub static ref INVOCATION_TIME_REJECTIONS: IntCounterVec = register_int_counter_vec!(
        "tinycloud_invocation_time_rejections_total",
        "Invocations rejected for an invalid time window, by reason.",
        &["kind"]
    )
    .unwrap();
    /// Remaining validity (`exp - now`, seconds) at successful invocation
    /// validation.
    pub static ref INVOCATION_VALIDITY_SLACK: Histogram = register_histogram!(
        "tinycloud_invocation_validity_slack_seconds",
        "Remaining validity in seconds (exp - now) at successful invocation validation.",
        VALIDITY_SLACK_BUCKETS.to_vec()
    )
    .unwrap();
    /// Current total size of the database connection pool.
    pub static ref DB_POOL_SIZE: IntGauge = register_int_gauge!(
        "tinycloud_db_pool_size",
        "Current number of connections in the database pool."
    )
    .unwrap();
    /// Current number of idle connections in the database pool.
    pub static ref DB_POOL_IDLE: IntGauge = register_int_gauge!(
        "tinycloud_db_pool_idle",
        "Current number of idle connections in the database pool."
    )
    .unwrap();
    /// Cumulative durable read-audit records committed.
    pub static ref READ_AUDIT_RECORDS: IntCounter = register_int_counter!(
        "tinycloud_read_audit_records_total",
        "Cumulative durable read-audit records committed."
    )
    .unwrap();
    /// Cumulative durable read-audit commit batches.
    pub static ref READ_AUDIT_BATCHES: IntCounter = register_int_counter!(
        "tinycloud_read_audit_batches_total",
        "Cumulative durable read-audit commit batches."
    )
    .unwrap();
}

pub fn observe_signed_kv_transfer(object_bytes: u64, served_bytes: u64) {
    if enabled() {
        SIGNED_KV_BYTES
            .with_label_values(&["object"])
            .inc_by(object_bytes);
        SIGNED_KV_BYTES
            .with_label_values(&["served"])
            .inc_by(served_bytes);
    }
}

/// Reason an invocation's signed time window was rejected. The label set is
/// fixed and bounded (never derived from request data).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeRejection {
    Expired,
    NotYetValid,
}

impl TimeRejection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
        }
    }
}

pub fn observe_invocation_time_rejection(kind: TimeRejection) {
    if enabled() {
        INVOCATION_TIME_REJECTIONS
            .with_label_values(&[kind.as_str()])
            .inc();
    }
}

pub fn observe_invocation_validity_slack(slack_seconds: f64) {
    if enabled() {
        INVOCATION_VALIDITY_SLACK.observe(slack_seconds);
    }
}

/// Update the database-pool gauges from a sampler tick.
pub fn set_db_pool_gauges(size: i64, idle: i64) {
    if enabled() {
        DB_POOL_SIZE.set(size);
        DB_POOL_IDLE.set(idle);
    }
}

/// Advance the cumulative read-audit counters by the deltas observed since the
/// previous sampler tick. Read-audit stats are process-cumulative and
/// monotonic, so the sampler feeds monotonic increments here.
pub fn add_read_audit_stats(records_delta: u64, batches_delta: u64) {
    if enabled() {
        READ_AUDIT_RECORDS.inc_by(records_delta);
        READ_AUDIT_BATCHES.inc_by(batches_delta);
    }
}

pub async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let encoder = TextEncoder::new();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::Duration;

    #[test]
    fn invocation_stage_labels_are_static_and_bounded() {
        let labels: Vec<&'static str> = InvocationStage::ALL
            .into_iter()
            .map(InvocationStage::as_str)
            .collect();
        let expected = vec![
            "request_decode",
            "invocation_signature_verify",
            "replay_check",
            "authorization_graph_load",
            "revocation_work",
            "kv_index_lookup",
            "block_read",
            "block_write",
            "epoch_persist",
            "response_handling",
            "authorization_header_decode",
            "chain_closure_query",
            "chain_guard_wait",
            "db_pool_acquire",
            "db_tx_begin",
            "db_tx_body",
            "read_audit_wait",
        ];

        assert_eq!(labels, expected);
        assert_eq!(labels.iter().collect::<HashSet<_>>().len(), labels.len());
        for label in labels {
            assert!(!label.contains(' '), "{label} must not contain spaces");
            assert!(!label.contains('/'), "{label} must not contain paths");
            assert!(!label.contains(':'), "{label} must not contain DIDs/CIDs");
            assert!(
                !label.contains("trace"),
                "{label} must not contain trace IDs"
            );
            assert!(
                !label.contains("space"),
                "{label} must not contain space IDs"
            );
            assert!(!label.contains("did"), "{label} must not contain DIDs");
            assert!(!label.contains("cid"), "{label} must not contain CIDs");
            assert!(!label.contains("path"), "{label} must not contain paths");
        }
    }

    #[test]
    fn stage_histogram_registers_static_labels() {
        set_enabled(true);
        observe_stage(
            InvocationStage::RequestDecode,
            StageOutcome::Ok,
            Duration::from_millis(1),
        );

        let metric = prometheus::gather()
            .into_iter()
            .find(|family| family.get_name() == "tinycloud_span_duration_seconds")
            .expect("span histogram should be registered");
        let sample = metric
            .get_metric()
            .iter()
            .find(|entry| {
                let labels = entry.get_label();
                labels.iter().any(|label| {
                    label.get_name() == "span" && label.get_value() == "request_decode"
                }) && labels
                    .iter()
                    .any(|label| label.get_name() == "outcome" && label.get_value() == "ok")
            })
            .expect("static stage labels should be observable");

        assert!(sample.get_histogram().get_sample_count() > 0);
    }

    fn gathered_bucket_bounds(name: &str) -> Vec<f64> {
        prometheus::gather()
            .into_iter()
            .find(|family| family.get_name() == name)
            .unwrap_or_else(|| panic!("{name} should be registered"))
            .get_metric()[0]
            .get_histogram()
            .get_bucket()
            .iter()
            .map(|bucket| bucket.get_upper_bound())
            .collect()
    }

    #[test]
    fn request_level_histograms_use_explicit_latency_buckets() {
        // Touch each histogram so a series exists to read buckets from.
        REQUEST_HISTOGRAM
            .with_label_values(&["GET", "/x", "200"])
            .observe(0.001);
        AUTHORIZED_INVOKE_HISTOGRAM
            .with_label_values(&["kv/get"])
            .observe(0.001);
        AUTHORIZATION_HISTOGRAM
            .with_label_values(&["invoke"])
            .observe(0.001);

        assert_eq!(
            gathered_bucket_bounds("tinycloud_http_request_duration_seconds"),
            REQUEST_LATENCY_BUCKETS.to_vec()
        );
        assert_eq!(
            gathered_bucket_bounds("tinycloud_authorized_invoke_duration_seconds"),
            REQUEST_LATENCY_BUCKETS.to_vec()
        );
        assert_eq!(
            gathered_bucket_bounds("tinycloud_authorization_duration_seconds"),
            REQUEST_LATENCY_BUCKETS.to_vec()
        );
    }

    #[test]
    fn validity_slack_histogram_uses_configured_buckets_and_observes() {
        set_enabled(true);
        let before = INVOCATION_VALIDITY_SLACK.get_sample_count();
        observe_invocation_validity_slack(42.0);
        assert_eq!(INVOCATION_VALIDITY_SLACK.get_sample_count(), before + 1);
        assert_eq!(
            gathered_bucket_bounds("tinycloud_invocation_validity_slack_seconds"),
            VALIDITY_SLACK_BUCKETS.to_vec()
        );
    }

    #[test]
    fn time_rejection_counter_increments_by_fixed_kind() {
        set_enabled(true);
        let expired_before = INVOCATION_TIME_REJECTIONS
            .with_label_values(&["expired"])
            .get();
        let not_yet_before = INVOCATION_TIME_REJECTIONS
            .with_label_values(&["not_yet_valid"])
            .get();

        observe_invocation_time_rejection(TimeRejection::Expired);
        observe_invocation_time_rejection(TimeRejection::NotYetValid);

        assert_eq!(
            INVOCATION_TIME_REJECTIONS
                .with_label_values(&["expired"])
                .get(),
            expired_before + 1
        );
        assert_eq!(
            INVOCATION_TIME_REJECTIONS
                .with_label_values(&["not_yet_valid"])
                .get(),
            not_yet_before + 1
        );
        // The label set is fixed and bounded.
        assert_eq!(TimeRejection::Expired.as_str(), "expired");
        assert_eq!(TimeRejection::NotYetValid.as_str(), "not_yet_valid");
    }
}
