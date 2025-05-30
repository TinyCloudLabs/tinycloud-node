use hyper::{header::CONTENT_TYPE, Body, Request, Response};
use lazy_static::lazy_static;
use prometheus::{register_histogram_vec, Encoder, HistogramVec, TextEncoder};

lazy_static! {
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
