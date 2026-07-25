use hyper::{header::CONTENT_TYPE, Body, Request, Response};
use lazy_static::lazy_static;
use prometheus::{register_histogram_vec, Encoder, HistogramVec, TextEncoder};

pub use tinycloud_core::telemetry::{
    enabled, observe_span, observe_stage, set_enabled, InvocationStage, StageOutcome,
};

lazy_static! {
    pub static ref REQUEST_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_http_request_duration_seconds",
        "HTTP request latencies in seconds.",
        &["method", "route", "status"]
    )
    .unwrap();
    pub static ref AUTHORIZED_INVOKE_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_authorized_invoke_duration_seconds",
        "The authorized invocations latencies in seconds.",
        &["action"]
    )
    .unwrap();
    pub static ref AUTHORIZATION_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_authorization_duration_seconds",
        "The authorization latencies in seconds.",
        &["request"]
    )
    .unwrap();
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
}
