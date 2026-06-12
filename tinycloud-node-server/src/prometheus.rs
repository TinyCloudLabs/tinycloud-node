use hyper::{header::CONTENT_TYPE, Body, Request, Response};
use lazy_static::lazy_static;
use prometheus::{register_histogram_vec, Encoder, HistogramVec, TextEncoder};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

static TELEMETRY_ENABLED: AtomicBool = AtomicBool::new(false);

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
    pub static ref SPAN_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "tinycloud_span_duration_seconds",
        "Named internal operation latencies in seconds.",
        &["span", "outcome"]
    )
    .unwrap();
}

pub fn set_enabled(enabled: bool) {
    TELEMETRY_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    TELEMETRY_ENABLED.load(Ordering::Relaxed)
}

pub fn observe_span(span: &'static str, outcome: &'static str, duration: Duration) {
    if enabled() {
        SPAN_HISTOGRAM
            .with_label_values(&[span, outcome])
            .observe(duration.as_secs_f64());
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
