use opentelemetry::trace::{TraceContextExt, TracerProvider};
use opentelemetry_otlp::ExporterBuildError;
use rocket::{
    config::LogLevel,
    fairing::{Fairing, Info, Kind},
    http::{Method, Status},
    request::{FromRequest, Outcome},
    Data, Request, Response,
};
use serde::{de::Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    borrow::Cow,
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tracing::{
    field::{Field, Visit},
    info_span,
    level_filters::LevelFilter,
    subscriber::set_global_default,
    Event, Level, Metadata, Span, Subscriber,
};
use tracing_log::LogTracer;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{
    filter::filter_fn, layer::Context, layer::SubscriberExt, Layer, Registry,
};

use crate::config;

/// Fallback `route` label for `REQUEST_HISTOGRAM` when a request matches no
/// Rocket route (e.g. scanner traffic to `/.env`, `/wp-login.php`, ...).
/// Using a fixed sentinel instead of the raw request path keeps the metric's
/// cardinality bounded to the set of mounted route templates plus this one
/// value, regardless of how many distinct unmatched paths are probed.
const UNMATCHED_ROUTE_LABEL: &str = "<unmatched>";

/// Target of the one log line per request (method, route template, status,
/// latency). It replaces Rocket's own request logging, which prints the raw URI.
const REQUEST_LOG_TARGET: &str = "tinycloud::request";
pub const MAX_JSON_LOG_LINE_BYTES: usize = 15_000;
const TRUNCATION_MARKER: &str = "[truncated]";
const JSON_LOG_FALLBACK: &[u8] = b"{\"fields\":{\"message\":\"log line exceeded 15000 bytes\"}}\n";

fn collect_string_fields<'a>(value: &'a mut Value, strings: &mut Vec<&'a mut String>) {
    match value {
        Value::String(string) => strings.push(string),
        Value::Array(values) => {
            for value in values {
                collect_string_fields(value, strings);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                collect_string_fields(value, strings);
            }
        }
        _ => {}
    }
}

fn is_valid_json(json: &[u8]) -> bool {
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    serde::de::IgnoredAny::deserialize(&mut deserializer).is_ok() && deserializer.end().is_ok()
}

pub fn cap_json_log_line(line: &[u8]) -> Vec<u8> {
    cap_json_log_buffer(line.to_vec())
}

fn cap_json_log_buffer(mut line: Vec<u8>) -> Vec<u8> {
    let content_len = line.len() - usize::from(line.ends_with(b"\n"));
    let json = &line[..content_len];
    if json.contains(&b'\n') || !is_valid_json(json) {
        return JSON_LOG_FALLBACK.to_vec();
    }
    if line.len() <= MAX_JSON_LOG_LINE_BYTES {
        if content_len == line.len() {
            line.push(b'\n');
        }
        return line;
    }

    let Ok(mut value) = serde_json::from_slice::<Value>(json) else {
        return JSON_LOG_FALLBACK.to_vec();
    };
    loop {
        let Ok(mut encoded) = serde_json::to_vec(&value) else {
            return JSON_LOG_FALLBACK.to_vec();
        };
        encoded.push(b'\n');
        if encoded.len() <= MAX_JSON_LOG_LINE_BYTES {
            return encoded;
        }

        let mut strings = Vec::new();
        collect_string_fields(&mut value, &mut strings);
        let mut longest_index = None;
        let mut longest_len = TRUNCATION_MARKER.len();
        for (index, string) in strings.iter().enumerate() {
            if string.len() > longest_len {
                longest_index = Some(index);
                longest_len = string.len();
            }
        }
        let Some(longest_index) = longest_index else {
            return JSON_LOG_FALLBACK.to_vec();
        };
        let longest = strings
            .into_iter()
            .nth(longest_index)
            .expect("selected field exists");
        let excess = encoded.len() - MAX_JSON_LOG_LINE_BYTES;
        let mut keep = longest
            .len()
            .saturating_sub(excess + TRUNCATION_MARKER.len());
        while !longest.is_char_boundary(keep) {
            keep -= 1;
        }
        longest.truncate(keep);
        longest.push_str(TRUNCATION_MARKER);
    }
}

struct CappedJsonMakeWriter<M>(M);

struct CappedJsonWriter<W: std::io::Write> {
    inner: W,
    bytes: Vec<u8>,
}

impl<W: std::io::Write> std::io::Write for CappedJsonWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: std::io::Write> Drop for CappedJsonWriter<W> {
    fn drop(&mut self) {
        let line = cap_json_log_buffer(std::mem::take(&mut self.bytes));
        let _ = self.inner.write_all(&line);
    }
}

impl<'a, M> tracing_subscriber::fmt::MakeWriter<'a> for CappedJsonMakeWriter<M>
where
    M: tracing_subscriber::fmt::MakeWriter<'a>,
{
    type Writer = CappedJsonWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        CappedJsonWriter {
            inner: self.0.make_writer(),
            bytes: Vec::with_capacity(512),
        }
    }
}

/// Rocket modules that log only at ignite, liftoff or shutdown, never request
/// data. Rocket's other modules log per request.
const ROCKET_STARTUP_MODULES: &[&str] = &[
    "rocket::launch",
    "rocket::rkt",
    "rocket::config",
    "rocket::fairing",
    "rocket::shield",
    "rocket::error",
    "rocket::state",
];

/// Whether an event or span may reach any log output (TC-961: production logs
/// are public).
///
/// Request URIs carry bearer credentials (`/signed/kv/<ticket_id>`) and space
/// IDs, which embed wallet addresses. Rocket logs the raw URI of every request
/// at INFO, of unmatched ones at ERROR, and the whole request with headers at
/// DEBUG. Its generated route code logs failed guards with their raw input
/// under `<module>::_` targets. All of that is dropped at every level;
/// `TracingFairing` logs each request by route template instead. Rocket's
/// startup messages and its non-request `rocket::server` warnings (signals,
/// shutdown, malformed HTTP) still pass.
///
/// sea-orm's TRACE spans record every statement with its bound values, and
/// the outbound HTTP clients log full URLs below INFO: reqwest a redirect's
/// URL (the quota service URL holds the space id), the AWS SDK the S3 key
/// (which starts with the space id) and the SigV4-signed request. Those are
/// dropped too.
fn may_be_logged(metadata: &Metadata<'_>) -> bool {
    let target = metadata.target();
    let level = *metadata.level();
    if target == "rocket::server" {
        return level <= Level::WARN;
    }
    if target == "rocket" || target.starts_with("rocket::") {
        let module = target.strip_suffix("::_").unwrap_or(target);
        return ROCKET_STARTUP_MODULES.iter().any(|allowed| {
            module
                .strip_prefix(allowed)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
        });
    }
    if target.starts_with("sea_orm") && level == Level::TRACE {
        return false;
    }
    if (target.starts_with("aws_") || target.starts_with("reqwest")) && level > Level::INFO {
        return false;
    }
    !target.ends_with("::_")
}

/// Default application log level for Rocket's `log_level` setting
/// (`TINYCLOUD_LOG_LEVEL`), used when `RUST_LOG` is unset.
fn default_log_level(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Critical => LevelFilter::WARN,
        LogLevel::Normal => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Off => LevelFilter::OFF,
    }
}

#[derive(Clone)]
pub struct TracingSpan(pub Span);

#[derive(Clone)]
struct RequestTelemetry {
    start: Instant,
    /// The method as received. Rocket rewrites an unrouted HEAD to GET before
    /// dispatching it to a GET route.
    method: Method,
}

pub struct TracingFairing {
    pub header_name: String,
    pub tracing_enabled: bool,
}

impl TracingFairing {
    pub fn new(cfg: &config::Tracing) -> Self {
        Self {
            header_name: cfg.traceheader.clone(),
            tracing_enabled: cfg.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    #[serde(skip)]
    #[allow(dead_code)]
    seq: u64,
    timestamp: String,
    level: String,
    target: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Value>,
    #[serde(skip)]
    #[allow(dead_code)]
    timestamp_nanos: i128,
}

#[derive(Debug, Default)]
struct LogBufferState {
    next_seq: u64,
    entries: VecDeque<LogEntry>,
}

#[derive(Debug)]
pub struct LogBuffer {
    state: Mutex<LogBufferState>,
    capacity: usize,
}

impl LogBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(LogBufferState::default()),
            capacity,
        }
    }

    pub fn global() -> Arc<Self> {
        static LOG_BUFFER: OnceLock<Arc<LogBuffer>> = OnceLock::new();
        LOG_BUFFER
            .get_or_init(|| Arc::new(LogBuffer::new(2000)))
            .clone()
    }

    pub fn push(
        &self,
        level: &str,
        target: &str,
        message: String,
        fields: Option<Value>,
    ) -> String {
        let mut state = self
            .state
            .lock()
            .expect("log buffer should not be poisoned");
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);

        let now = OffsetDateTime::now_utc();
        let timestamp = now.format(&Rfc3339).unwrap_or_default();
        let entry = LogEntry {
            seq,
            timestamp,
            level: level.to_string(),
            target: target.to_string(),
            message,
            fields,
            timestamp_nanos: now.unix_timestamp_nanos(),
        };

        state.entries.push_back(entry);
        while state.entries.len() > self.capacity {
            state.entries.pop_front();
        }

        format!("{seq}")
    }

    #[allow(dead_code)]
    pub fn tail(
        &self,
        lines: usize,
        cursor: Option<u64>,
        since: Option<OffsetDateTime>,
    ) -> (Vec<LogEntry>, Option<String>) {
        let state = self
            .state
            .lock()
            .expect("log buffer should not be poisoned");
        let entries: Vec<LogEntry> = state.entries.iter().cloned().collect();
        if entries.is_empty() {
            return (Vec::new(), None);
        }

        let newest_seq = state
            .entries
            .back()
            .map(|entry| entry.seq)
            .unwrap_or_default();
        let oldest_seq = state
            .entries
            .front()
            .map(|entry| entry.seq)
            .unwrap_or_default();

        let mut selected = if let Some(cursor) = cursor {
            if cursor.saturating_add(1) < oldest_seq || cursor > newest_seq {
                newest_window(entries, lines)
            } else {
                entries
                    .into_iter()
                    .filter(|entry| entry.seq > cursor)
                    .collect()
            }
        } else if let Some(since) = since {
            let since_nanos = since.unix_timestamp_nanos();
            entries
                .into_iter()
                .filter(|entry| entry.timestamp_nanos >= since_nanos)
                .collect()
        } else {
            newest_window(entries, lines)
        };

        if selected.len() > lines {
            selected = selected.split_off(selected.len() - lines);
        }

        let cursor = selected.last().map(|entry| entry.seq.to_string());
        (selected, cursor)
    }
}

#[allow(dead_code)]
fn newest_window(entries: Vec<LogEntry>, lines: usize) -> Vec<LogEntry> {
    if entries.len() <= lines {
        entries
    } else {
        entries[entries.len() - lines..].to_vec()
    }
}

#[derive(Default)]
struct LogVisitor {
    message: Option<String>,
    fields: Map<String, Value>,
}

impl LogVisitor {
    fn into_fields(self) -> Option<Value> {
        if self.fields.is_empty() {
            None
        } else {
            Some(Value::Object(self.fields))
        }
    }
}

fn normalize_debug_value(rendered: String) -> String {
    if rendered.len() >= 2 && rendered.starts_with('"') && rendered.ends_with('"') {
        rendered[1..rendered.len() - 1].to_string()
    } else {
        rendered
    }
}

impl Visit for LogVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), Value::Bool(value));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), Value::from(value));
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), Value::from(value));
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let value = Value::from(value);
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), Value::String(value.to_string()));
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_debug(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = normalize_debug_value(format!("{value:?}"));
        if field.name() == "message" {
            self.message = Some(rendered);
        } else {
            self.fields
                .insert(field.name().to_string(), Value::String(rendered));
        }
    }
}

#[derive(Clone, Copy)]
struct CaptureLayer;

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        let message = visitor
            .message
            .clone()
            .unwrap_or_else(|| event.metadata().name().to_string());
        let _ = LogBuffer::global().push(
            event.metadata().level().as_str(),
            event.metadata().target(),
            message,
            visitor.into_fields(),
        );
    }
}

pub fn tracing_try_init(
    config: &config::Logging,
    log_level: LogLevel,
) -> Result<(), ExporterBuildError> {
    let _ = LogTracer::init();
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default_log_level(log_level).into())
        .from_env_lossy();
    let subscriber = tracing_subscriber::fmt::layer();
    let log = match config.format {
        config::LoggingFormat::Text => subscriber.boxed(),
        config::LoggingFormat::Json => subscriber
            .json()
            .with_writer(CappedJsonMakeWriter(std::io::stderr))
            .boxed(),
    };
    let telemetry = if config.tracing.enabled {
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(
                opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .build()?,
            )
            .build();
        let tracer = provider.tracer("tinycloud");

        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        Some(telemetry)
    } else {
        None
    };
    let collector = Registry::default()
        .with(env_filter)
        .with(filter_fn(may_be_logged))
        .with(log)
        .with(CaptureLayer)
        .with(telemetry);
    let _ = set_global_default(collector);
    Ok(())
}

#[rocket::async_trait]
impl Fairing for TracingFairing {
    fn info(&self) -> Info {
        Info {
            name: "Tracing Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }
    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        let span = info_span!(parent: None, "request", trace_id = tracing::field::Empty);
        // Resolving the OTel context (and recording it onto the span) is only
        // meaningful when tracing is enabled and an OTel layer is installed
        // (tracing_try_init only attaches one in that case); skip the work
        // otherwise. The span itself is still created and cached below since
        // `TracingSpan` is a hard `FromRequest` dependency for several routes.
        if self.tracing_enabled {
            span.record(
                "trace_id",
                tracing::field::display(&span.context().span().span_context().trace_id()),
            );
        }
        req.local_cache(|| Some(TracingSpan(span)));
        req.local_cache(|| {
            Some(RequestTelemetry {
                start: Instant::now(),
                method: req.method(),
            })
        });
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        if let Some(TracingSpan(span)) = req.local_cache(|| Option::<TracingSpan>::None).to_owned()
        {
            // Only resolve the real OTel trace id when tracing is enabled;
            // otherwise the context downcast can never succeed (no OTel layer
            // installed) and always resolves to the invalid all-zero id, so
            // use that constant directly instead of paying for the lookup.
            let trace_id = if self.tracing_enabled {
                span.context().span().span_context().trace_id()
            } else {
                opentelemetry::trace::TraceId::INVALID
            };
            res.set_raw_header(self.header_name.clone(), format!("{trace_id}"));
        }
        let Some(telemetry) = req
            .local_cache(|| Option::<RequestTelemetry>::None)
            .to_owned()
        else {
            return;
        };
        let elapsed = telemetry.start.elapsed();
        // Unmatched requests (404s from scanner traffic, e.g. `/.env`,
        // `/wp-login.php`) have no `Route`, so fall back to a fixed sentinel.
        // Neither the log line nor the metric label ever carries the raw
        // request path: it can hold bearer tickets and space IDs (TC-961), and
        // every distinct probed path would otherwise create its own permanent
        // histogram series (TC-286).
        let route = match req.route() {
            Some(route) => Cow::Owned(route.uri.to_string()),
            None => Cow::Borrowed(UNMATCHED_ROUTE_LABEL),
        };
        let status = res.status().code;
        tracing::info!(
            target: REQUEST_LOG_TARGET,
            method = %telemetry.method,
            route = %route,
            status,
            latency_us = elapsed.as_micros() as u64,
            "request"
        );
        if crate::prometheus::enabled() {
            crate::prometheus::REQUEST_HISTOGRAM
                .with_label_values(&[
                    req.method().as_str(),
                    route.as_ref(),
                    status.to_string().as_str(),
                ])
                .observe(elapsed.as_secs_f64());
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for TracingSpan {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, ()> {
        match request.local_cache(|| Option::<TracingSpan>::None) {
            Some(TracingSpan(span)) => Outcome::Success(TracingSpan(span.to_owned())),
            None => Outcome::Error((Status::InternalServerError, ())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::local::asynchronous::Client;

    #[rocket::get("/tc286-known")]
    fn known() -> &'static str {
        "ok"
    }

    #[rocket::get("/tc286-span-guard")]
    fn span_guard(_span: TracingSpan) -> &'static str {
        "ok"
    }

    fn disabled_fairing() -> TracingFairing {
        TracingFairing {
            header_name: "TinyCloud-Trace-Id".to_string(),
            tracing_enabled: false,
        }
    }

    /// Regression test for TC-286: unmatched requests must collapse into a
    /// single bounded `route` label rather than leaking the raw request path
    /// (which would let scanner traffic create unbounded histogram series).
    #[tokio::test]
    async fn unmatched_routes_collapse_into_a_bounded_sentinel_label() {
        let was_enabled = crate::prometheus::enabled();
        crate::prometheus::set_enabled(true);

        let rocket = rocket::build()
            .mount("/", rocket::routes![known])
            .attach(disabled_fairing());
        let client = Client::tracked(rocket)
            .await
            .expect("valid rocket instance");

        for path in ["/tc286-scan-a", "/tc286-scan-b", "/tc286-scan-c"] {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.status(), Status::NotFound);
        }

        let known_response = client.get("/tc286-known").dispatch().await;
        assert_eq!(known_response.status(), Status::Ok);

        let route_labels: Vec<String> = ::prometheus::gather()
            .into_iter()
            .find(|family| family.get_name() == "tinycloud_http_request_duration_seconds")
            .expect("request histogram should be registered")
            .get_metric()
            .iter()
            .flat_map(|metric| metric.get_label())
            .filter(|label| label.get_name() == "route")
            .map(|label| label.get_value().to_string())
            .collect();

        assert!(
            route_labels
                .iter()
                .all(|value| !value.starts_with("/tc286-scan")),
            "unmatched scanner paths must not leak into the route label: {route_labels:?}"
        );
        assert!(
            route_labels
                .iter()
                .any(|value| value == UNMATCHED_ROUTE_LABEL),
            "expected the sentinel route label to be present: {route_labels:?}"
        );
        assert!(
            route_labels.iter().any(|value| value == "/tc286-known"),
            "matched routes must still report their own route label: {route_labels:?}"
        );

        crate::prometheus::set_enabled(was_enabled);
    }

    /// Regression test: disabling the tracing gate must not stop
    /// `TracingSpan` from being cached, since it is a hard `FromRequest`
    /// dependency for several routes (e.g. /invoke, /delegate).
    #[tokio::test]
    async fn tracing_disabled_still_caches_a_span_for_the_request_guard() {
        let rocket = rocket::build()
            .mount("/", rocket::routes![span_guard])
            .attach(disabled_fairing());
        let client = Client::tracked(rocket)
            .await
            .expect("valid rocket instance");

        let response = client.get("/tc286-span-guard").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert!(
            response.headers().get_one("TinyCloud-Trace-Id").is_some(),
            "trace header should still be set (as the all-zero id) when tracing is disabled"
        );
    }
    #[test]
    fn json_formatter_caps_each_complete_serialized_event() {
        #[derive(Clone)]
        struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for CaptureWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("capture mutex")
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let output = Arc::new(Mutex::new(Vec::new()));
        let capture = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(CappedJsonMakeWriter(move || CaptureWriter(capture.clone())))
            .finish();
        let over_16k = "a".repeat(17 * 1024);
        let several_a = "b".repeat(7 * 1024);
        let several_b = "c".repeat(7 * 1024);
        let several_c = "d".repeat(7 * 1024);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(oversized = %over_16k, "one oversized field");
            tracing::info!(
                large_a = %several_a,
                large_b = %several_b,
                large_c = %several_c,
                "several large fields"
            );
        });

        let bytes = output.lock().expect("capture mutex");
        let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
        assert_eq!(lines.len(), 2, "each event must produce exactly one line");
        for line in lines {
            assert!(
                line.len() <= MAX_JSON_LOG_LINE_BYTES,
                "line size: {}",
                line.len()
            );
            assert_eq!(line.last(), Some(&b'\n'), "line must be newline terminated");
            let record: Value =
                serde_json::from_slice(&line[..line.len() - 1]).expect("capped line must be JSON");
            assert!(
                record["fields"]
                    .as_object()
                    .expect("JSON fields")
                    .values()
                    .any(|value| value
                        .as_str()
                        .is_some_and(|text| text.ends_with(TRUNCATION_MARKER))),
                "large string fields should carry the fixed truncation marker"
            );
        }
    }
}
