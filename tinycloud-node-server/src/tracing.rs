use opentelemetry::trace::{TraceContextExt, TracerProvider};
use opentelemetry_otlp::ExporterBuildError;
use rocket::{
    config::LogLevel,
    fairing::{Fairing, Info, Kind},
    http::{Method, Status},
    request::{FromRequest, Outcome},
    Data, Request, Response,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_core::{
    failure_diagnostic::{FailureCode, FailureNote, KIND_READ_AUDIT_BUSY, KIND_REQUEST_TIMEOUT},
    request_telemetry::{self, RequestContext},
    telemetry::Pseudonymizer,
};
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
use uuid::{Uuid, Variant};

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

/// Explicit origin classification, parsed once at startup, never from a request.
pub(crate) struct RequestIdOrigins(Vec<reqwest::Url>);

impl RequestIdOrigins {
    pub(crate) fn new(origins: &[String]) -> Result<Self, &'static str> {
        let origins = origins
            .iter()
            .map(|value| {
                let origin = reqwest::Url::parse(value)
                    .map_err(|_| "invalid request-ID first-party origin")?;
                if !matches!(origin.scheme(), "http" | "https")
                    || origin.host_str().is_none()
                    || !origin.username().is_empty()
                    || origin.password().is_some()
                    || origin.path() != "/"
                    || origin.query().is_some()
                    || origin.fragment().is_some()
                {
                    return Err("request-ID first-party origins must be HTTP(S) origins only");
                }
                Ok(origin)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self(origins))
    }

    pub(crate) fn allows(&self, destination: &str) -> bool {
        let Ok(destination) = reqwest::Url::parse(destination) else {
            return false;
        };
        self.0.iter().any(|origin| {
            origin.scheme() == destination.scheme()
                && origin.host_str() == destination.host_str()
                && origin.port_or_known_default() == destination.port_or_known_default()
        })
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
    // SQLx statements/notices/pool errors, SeaORM diagnostics and sqlparser's
    // token/AST debug logs can carry SQL, values or database-generated text.
    // Typed DB hooks supply timing independently of all diagnostic output.
    if target.starts_with("sea_orm")
        || target.starts_with("sqlx")
        || target.starts_with("sqlparser")
    {
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

/// Request-owned state; never shared with detached background work.
struct RequestTelemetry {
    start: Instant,
    /// The method as received. Rocket rewrites an unrouted HEAD to GET before
    /// dispatching it to a GET route.
    method: Method,
    request_id_replaced: bool,
    context: Arc<RequestContext>,
}

pub struct TracingFairing {
    pub header_name: String,
    pub tracing_enabled: bool,
    pseudonymizer: Arc<Pseudonymizer>,
}

impl TracingFairing {
    /// Share the node's single startup-derived pseudonymizer with request logs.
    pub fn new(cfg: &config::Tracing, pseudonymizer: Arc<Pseudonymizer>) -> Self {
        Self {
            header_name: cfg.traceheader.clone(),
            tracing_enabled: cfg.enabled,
            pseudonymizer,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(cfg: &config::Tracing) -> Self {
        let secret = tinycloud_core::keys::StaticSecret::new(vec![0x42; 32]).unwrap();
        Self::new(cfg, Arc::new(Pseudonymizer::new(&secret)))
    }
}

/// Scope the entire generated handler, including authorization/data guards and
/// responder construction. A request fairing alone cannot scope an async handler.
#[derive(Clone)]
struct TelemetryHandler(Box<dyn rocket::route::Handler>);

#[rocket::async_trait]
impl rocket::route::Handler for TelemetryHandler {
    async fn handle<'r>(
        &self,
        request: &'r Request<'_>,
        data: Data<'r>,
    ) -> rocket::route::Outcome<'r> {
        let telemetry = request.local_cache(|| Option::<RequestTelemetry>::None);
        match telemetry {
            Some(telemetry) => {
                request_telemetry::scope(
                    Arc::clone(&telemetry.context),
                    self.0.handle(request, data),
                )
                .await
            }
            None => self.0.handle(request, data).await,
        }
    }
}

pub(crate) fn instrument_route(mut route: rocket::Route) -> rocket::Route {
    route.handler = Box::new(TelemetryHandler(route.handler));
    route
}

fn incoming_request_id(request: &Request<'_>) -> (Uuid, bool) {
    let mut headers = request.headers().get("x-request-id");
    let Some(value) = headers.next() else {
        return (Uuid::new_v4(), false);
    };
    let accepted = (headers.next().is_none() && value.len() == 36)
        .then(|| Uuid::parse_str(value).ok())
        .flatten()
        .filter(|id| {
            id.get_variant() == Variant::RFC4122 && (1..=8).contains(&id.get_version_num())
        });
    accepted
        .map(|id| (id, false))
        .unwrap_or_else(|| (Uuid::new_v4(), true))
}

fn hash_field<'a>(hash: Option<&[u8; 32]>, buffer: &'a mut [u8; 64]) -> Option<&'a str> {
    let hash = hash?;
    hex::encode_to_slice(hash, &mut *buffer).expect("32 bytes encode to 64 hex bytes");
    Some(std::str::from_utf8(buffer).expect("hex is ASCII"))
}

/// The one diagnostic line a request logs when it ends in a database failure
/// or a busy/timeout 5xx (TC-1796).
///
/// Its fields are all there is: fixed vocabulary, the route template, the
/// elapsed time and the keyed `db_hash` pseudonym of the database. It never
/// carries a space id, DID, database name or path, SQL, parameters, the
/// database's error text, headers, tokens, addresses or bodies.
struct DatabaseFailureLine<'a> {
    status: u16,
    code: &'static str,
    service: &'static str,
    route: &'a str,
    elapsed_ms: u64,
    failure_kind: &'static str,
    write_may_have_applied: bool,
    /// Absent when the failing layer does not know its database.
    db_hash: Option<String>,
}

impl<'a> DatabaseFailureLine<'a> {
    /// The line for a request that recorded `note` and was answered `status`,
    /// or `None` when the answer is not the one the note describes (a `503`
    /// is `unavailable_retryable` or a busy code, a `500` is
    /// `outcome_unknown` or `internal`), so a line never states a code the
    /// client did not receive.
    fn new(
        note: FailureNote,
        status: u16,
        route: &'a str,
        elapsed: Duration,
    ) -> Option<DatabaseFailureLine<'a>> {
        let (code, expected_status) = match note.code {
            FailureCode::UnavailableRetryable => (
                crate::routes::UNAVAILABLE_RETRYABLE,
                Status::ServiceUnavailable,
            ),
            FailureCode::OutcomeUnknown => {
                (crate::routes::OUTCOME_UNKNOWN, Status::InternalServerError)
            }
            FailureCode::Internal => ("internal", Status::InternalServerError),
            FailureCode::Busy => (
                match note.kind {
                    KIND_REQUEST_TIMEOUT => crate::routes::REQUEST_TIMEOUT,
                    KIND_READ_AUDIT_BUSY => crate::routes::READ_AUDIT_BUSY,
                    _ => crate::routes::SQL_BUSY,
                },
                Status::ServiceUnavailable,
            ),
        };
        (status == expected_status.code).then(|| Self {
            status,
            code,
            service: note.service.as_str(),
            route,
            elapsed_ms: elapsed.as_millis() as u64,
            failure_kind: note.kind,
            write_may_have_applied: note.write_may_have_applied,
            db_hash: note.db_hash,
        })
    }

    fn emit(&self) {
        tracing::warn!(
            target: REQUEST_LOG_TARGET,
            status = self.status,
            code = self.code,
            service = self.service,
            route = self.route,
            elapsed_ms = self.elapsed_ms,
            failure_kind = self.failure_kind,
            write_may_have_applied = self.write_may_have_applied,
            db_hash = self.db_hash.as_deref(),
            "database failure answered with a 5xx"
        );
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
        config::LoggingFormat::Json => subscriber.json().boxed(),
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
        let start = Instant::now();
        let (request_id, request_id_replaced) = incoming_request_id(req);
        // Replace, don't append: guards and local delegates see only the
        // validated canonical value, never the untrusted original header.
        req.replace_header(rocket::http::Header::new(
            "x-request-id",
            request_id.to_string(),
        ));
        let span = info_span!(
            parent: None, "request",
            request_id = %request_id,
            trace_id = tracing::field::Empty
        );
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
                start,
                method: req.method(),
                request_id_replaced,
                context: RequestContext::new(request_id, Arc::clone(&self.pseudonymizer)),
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
            .as_ref()
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
        let route = req
            .route()
            .map(|route| route.uri.as_str())
            .unwrap_or(UNMATCHED_ROUTE_LABEL);
        let status = res.status().code;
        res.set_raw_header("x-request-id", telemetry.context.request_id().to_string());
        let database = telemetry.context.snapshot();
        let hashes = telemetry.context.hashes();
        let mut account_buffer = [0; 64];
        let mut space_buffer = [0; 64];
        let account_hash = hash_field(hashes.account_hash.as_ref(), &mut account_buffer);
        let space_hash = hash_field(hashes.space_hash.as_ref(), &mut space_buffer);
        tracing::info!(
            target: REQUEST_LOG_TARGET,
            event = "node_request",
            svc = "api",
            request_id = %telemetry.context.request_id(),
            request_id_replaced = telemetry.request_id_replaced,
            method = %telemetry.method,
            route,
            status,
            latency_us = elapsed.as_micros() as u64,
            pool_wait_ms = database.pool_wait_ns as f64 / 1_000_000.0,
            query_time_ms = database.query_time_ns as f64 / 1_000_000.0,
            query_count = database.query_count,
            account_hash,
            space_hash,
            "request"
        );
        if status >= 500 {
            if let Some(line) = telemetry
                .context
                .failure()
                .and_then(|note| DatabaseFailureLine::new(note, status, route, elapsed))
            {
                line.emit();
            }
        }
        if crate::prometheus::enabled() {
            crate::prometheus::REQUEST_HISTOGRAM
                .with_label_values(&[req.method().as_str(), route, status.to_string().as_str()])
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

    #[test]
    fn first_party_origins_use_exact_http_origin_not_host_suffix_or_path() {
        let policy = RequestIdOrigins::new(&[
            "https://FIRST.example:443".to_string(),
            "http://localhost:80".to_string(),
        ])
        .unwrap();
        assert!(policy.allows("https://first.example/api/quota"));
        assert!(policy.allows("http://LOCALHOST/path"));
        for destination in [
            "http://first.example/api/quota",
            "https://first.example:444/api/quota",
            "https://first.example.attacker.invalid/api/quota",
            "https://other.first.example/api/quota",
            "http://localhost:8000/path",
            "file:///first.example",
        ] {
            assert!(!policy.allows(destination));
        }
        for invalid in [
            "https://first.example/private",
            "https://user:pass@first.example",
            "https://first.example?query=private",
            "https://first.example#private",
            "file:///private",
        ] {
            assert!(RequestIdOrigins::new(&[invalid.to_string()]).is_err());
        }
    }

    #[tokio::test]
    async fn canonical_vectors_reject_application_visible_padding_newlines_and_duplicates() {
        // Canonical TC-959 corpus at tinycloud-dev 76bd10752a52f179ac2a49214f488236d02f8192.
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/request-id-vectors.json"))
                .unwrap();
        let client = Client::tracked(rocket::build().mount("/", rocket::routes![known]))
            .await
            .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let mut request = client.get("/tc286-known");
            if let Some(values) = case["incoming"].as_array() {
                for value in values {
                    request = request.header(rocket::http::Header::new(
                        "x-request-id",
                        value.as_str().unwrap().to_string(),
                    ));
                }
            }
            let (id, replaced) = incoming_request_id(request.inner());
            assert_eq!(
                Value::Bool(replaced),
                case["request_id_replaced"],
                "{}",
                case["name"]
            );
            if let Some(normalized) = case["normalized"].as_str() {
                assert_eq!(id.to_string(), normalized, "{}", case["name"]);
            } else {
                assert_eq!(id.get_version_num(), 4, "{}", case["name"]);
                assert_eq!(id.get_variant(), Variant::RFC4122);
            }
        }
    }

    #[rocket::get("/tc286-known")]
    fn known() -> &'static str {
        "ok"
    }

    #[rocket::get("/tc286-span-guard")]
    fn span_guard(_span: TracingSpan) -> &'static str {
        "ok"
    }

    fn disabled_fairing() -> TracingFairing {
        TracingFairing::for_test(&config::Tracing {
            enabled: false,
            ..Default::default()
        })
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

    fn note(code: FailureCode) -> FailureNote {
        FailureNote {
            service: tinycloud_core::failure_diagnostic::Service::Sql,
            code,
            kind: "pool_timeout",
            write_may_have_applied: code == FailureCode::OutcomeUnknown,
            db_hash: None,
        }
    }

    #[test]
    fn a_diagnostic_line_states_only_the_code_the_client_received() {
        let line = |code, status| {
            DatabaseFailureLine::new(note(code), status, "/invoke", Duration::from_millis(41_900))
                .map(|line| {
                    (
                        line.code,
                        line.status,
                        line.elapsed_ms,
                        line.write_may_have_applied,
                    )
                })
        };
        assert_eq!(
            line(FailureCode::UnavailableRetryable, 503),
            Some(("unavailable_retryable", 503, 41_900, false))
        );
        assert_eq!(
            line(FailureCode::OutcomeUnknown, 500),
            Some(("outcome_unknown", 500, 41_900, true))
        );
        assert_eq!(
            line(FailureCode::Internal, 500),
            Some(("internal", 500, 41_900, false))
        );
        assert_eq!(
            line(FailureCode::Busy, 503),
            Some(("sql_busy", 503, 41_900, false))
        );
        for (code, status) in [
            (FailureCode::UnavailableRetryable, 500),
            (FailureCode::OutcomeUnknown, 503),
            (FailureCode::Internal, 503),
            (FailureCode::Internal, 200),
            (FailureCode::Busy, 500),
            (FailureCode::Busy, 200),
        ] {
            assert!(line(code, status).is_none(), "{code:?} answered {status}");
        }
    }

    /// Log output written at the WARN level, as JSON.
    #[derive(Clone, Default)]
    struct Captured(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    const SECRET_SPACE: &str =
        "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:secret-space";
    const SECRET_DB: &str = "secret-db-name";
    const SECRET_TEXT: &str = "secret-database-error-text";

    #[rocket::get("/tc1796-with-db")]
    fn failing_with_db() -> (Status, String) {
        request_telemetry::note_failure(FailureNote {
            db_hash: request_telemetry::db_hash("sql", &SECRET_SPACE.parse().unwrap(), SECRET_DB),
            ..note(FailureCode::UnavailableRetryable)
        });
        (
            Status::ServiceUnavailable,
            format!("unavailable_retryable: {SECRET_TEXT} {SECRET_SPACE} {SECRET_DB}"),
        )
    }

    #[rocket::get("/tc1796-without-db")]
    fn failing_without_db() -> (Status, String) {
        request_telemetry::note_failure(FailureNote {
            service: tinycloud_core::failure_diagnostic::Service::Kv,
            kind: "io",
            ..note(FailureCode::OutcomeUnknown)
        });
        (
            Status::InternalServerError,
            format!("outcome_unknown: {SECRET_TEXT}"),
        )
    }

    #[rocket::get("/tc1796-no-note")]
    fn failing_without_note() -> (Status, &'static str) {
        (Status::ServiceUnavailable, "sql_busy: lock_wait")
    }

    /// A request that ends in a database-failure 5xx logs exactly one WARN
    /// line with the allowed fields and nothing else, and the response is
    /// the route's, untouched. `#[tokio::test]` runs on one thread, so the
    /// thread-scoped subscriber sees the fairing's event.
    #[tokio::test]
    async fn a_database_failure_5xx_logs_one_line_with_only_the_allowed_fields() {
        let captured = Captured::default();
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .json()
                .with_writer(captured.clone())
                .with_max_level(Level::WARN)
                .finish(),
        );
        let routes: Vec<_> =
            rocket::routes![failing_with_db, failing_without_db, failing_without_note]
                .into_iter()
                .map(instrument_route)
                .collect();
        let client = Client::tracked(
            rocket::build()
                .mount("/", routes)
                .attach(disabled_fairing()),
        )
        .await
        .expect("valid rocket instance");

        let response = client.get("/tc1796-with-db").dispatch().await;
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(
            response.into_string().await.unwrap(),
            format!("unavailable_retryable: {SECRET_TEXT} {SECRET_SPACE} {SECRET_DB}"),
            "the response body is the route's"
        );
        let response = client.get("/tc1796-without-db").dispatch().await;
        assert_eq!(response.status(), Status::InternalServerError);
        let response = client.get("/tc1796-no-note").dispatch().await;
        assert_eq!(response.status(), Status::ServiceUnavailable);

        let output = String::from_utf8(captured.0.lock().clone()).unwrap();
        for secret in [SECRET_SPACE, SECRET_DB, SECRET_TEXT, "secret"] {
            assert!(!output.contains(secret), "{secret} in {output}");
        }
        let events: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2, "one line per failing request: {output}");
        let allowed = |with_db: bool| -> Vec<&str> {
            let mut fields = vec![
                "code",
                "elapsed_ms",
                "failure_kind",
                "message",
                "route",
                "service",
                "status",
                "write_may_have_applied",
            ];
            if with_db {
                fields.push("db_hash");
            }
            fields.sort_unstable();
            fields
        };
        let keys = |event: &Value| -> Vec<String> {
            let mut keys: Vec<String> = event["fields"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            keys.sort_unstable();
            keys
        };

        let first = &events[0];
        assert_eq!(first["level"], "WARN");
        assert_eq!(first["target"], REQUEST_LOG_TARGET);
        assert_eq!(keys(first), allowed(true));
        let fields = &first["fields"];
        assert_eq!(fields["status"], 503);
        assert_eq!(fields["code"], "unavailable_retryable");
        assert_eq!(fields["service"], "sql");
        assert_eq!(fields["route"], "/tc1796-with-db");
        assert_eq!(fields["failure_kind"], "pool_timeout");
        assert_eq!(fields["write_may_have_applied"], false);
        let expected_hash =
            Pseudonymizer::new(&tinycloud_core::keys::StaticSecret::new(vec![0x42; 32]).unwrap())
                .db_hash("sql", &SECRET_SPACE.parse().unwrap(), SECRET_DB)
                .unwrap();
        assert_eq!(fields["db_hash"], hex::encode(expected_hash.into_bytes()));
        assert!(fields["elapsed_ms"].is_u64());

        let second = &events[1];
        assert_eq!(
            keys(second),
            allowed(false),
            "db_hash is omitted when unknown"
        );
        let fields = &second["fields"];
        assert_eq!(fields["status"], 500);
        assert_eq!(fields["code"], "outcome_unknown");
        assert_eq!(fields["service"], "kv");
        assert_eq!(fields["failure_kind"], "io");
        assert_eq!(fields["write_may_have_applied"], true);
    }

    fn busy(kind: &'static str, with_db: bool) -> FailureNote {
        FailureNote {
            code: FailureCode::Busy,
            kind,
            db_hash: with_db.then(|| {
                request_telemetry::db_hash("sql", &SECRET_SPACE.parse().unwrap(), SECRET_DB)
                    .unwrap()
            }),
            ..note(FailureCode::Busy)
        }
    }

    #[rocket::get("/tc1796-lock-wait")]
    fn busy_lock_wait() -> (Status, &'static str) {
        request_telemetry::note_failure(busy("lock_wait", true));
        (Status::ServiceUnavailable, "sql_busy: lock_wait: busy")
    }

    #[rocket::get("/tc1796-hydration")]
    fn busy_hydration() -> (Status, &'static str) {
        request_telemetry::note_failure(busy("hydration", true));
        (Status::ServiceUnavailable, "sql_busy: hydration: busy")
    }

    #[rocket::get("/tc1796-artifact-transfer")]
    fn busy_artifact_transfer() -> (Status, &'static str) {
        request_telemetry::note_failure(busy("artifact_transfer", true));
        (
            Status::ServiceUnavailable,
            "sql_busy: artifact_transfer: busy",
        )
    }

    #[rocket::get("/tc1796-timeout")]
    fn busy_request_timeout() -> (Status, &'static str) {
        request_telemetry::note_failure(busy(KIND_REQUEST_TIMEOUT, false));
        (
            Status::ServiceUnavailable,
            "request_timeout: no change was applied",
        )
    }

    #[rocket::get("/tc1796-read-audit")]
    fn busy_read_audit() -> (Status, &'static str) {
        request_telemetry::note_failure(busy(KIND_READ_AUDIT_BUSY, false));
        (Status::ServiceUnavailable, "read_audit_busy: backlogged")
    }

    /// A busy wait whose outcome turned out unknown is answered 500.
    #[rocket::get("/tc1796-busy-then-unknown")]
    fn busy_then_unknown() -> (Status, &'static str) {
        request_telemetry::note_failure(busy("artifact_transfer", true));
        request_telemetry::note_outcome_unknown(
            tinycloud_core::failure_diagnostic::Service::Other,
            None,
        );
        (
            Status::InternalServerError,
            "outcome_unknown: may have applied",
        )
    }

    #[rocket::get("/tc1796-internal")]
    fn sql_internal() -> (Status, &'static str) {
        request_telemetry::note_failure(FailureNote::internal(
            tinycloud_core::failure_diagnostic::Service::Sql,
        ));
        (Status::InternalServerError, "Internal error: boom")
    }

    /// A busy note answered with another status (here a 500) logs nothing.
    #[rocket::get("/tc1796-busy-mismatch")]
    fn busy_answered_500() -> (Status, &'static str) {
        request_telemetry::note_failure(busy("lock_wait", true));
        (Status::InternalServerError, "something else")
    }

    /// Each busy, timeout and internal path logs exactly one line, with the
    /// code the client received, the elapsed time and the fixed kind.
    #[tokio::test]
    async fn busy_timeout_and_internal_5xxs_log_one_line_each_with_elapsed_time() {
        let captured = Captured::default();
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .json()
                .with_writer(captured.clone())
                .with_max_level(Level::WARN)
                .finish(),
        );
        let routes: Vec<_> = rocket::routes![
            busy_lock_wait,
            busy_hydration,
            busy_artifact_transfer,
            busy_request_timeout,
            busy_read_audit,
            busy_then_unknown,
            sql_internal,
            busy_answered_500
        ]
        .into_iter()
        .map(instrument_route)
        .collect();
        let client = Client::tracked(
            rocket::build()
                .mount("/", routes)
                .attach(disabled_fairing()),
        )
        .await
        .expect("valid rocket instance");

        // (path, status, code, kind, write_may_have_applied, has db_hash)
        let expected = [
            (
                "/tc1796-lock-wait",
                503,
                "sql_busy",
                "lock_wait",
                false,
                true,
            ),
            (
                "/tc1796-hydration",
                503,
                "sql_busy",
                "hydration",
                false,
                true,
            ),
            (
                "/tc1796-artifact-transfer",
                503,
                "sql_busy",
                "artifact_transfer",
                false,
                true,
            ),
            (
                "/tc1796-timeout",
                503,
                "request_timeout",
                "request_timeout",
                false,
                false,
            ),
            (
                "/tc1796-read-audit",
                503,
                "read_audit_busy",
                "read_audit_busy",
                false,
                false,
            ),
            (
                "/tc1796-busy-then-unknown",
                500,
                "outcome_unknown",
                "artifact_transfer",
                true,
                true,
            ),
            ("/tc1796-internal", 500, "internal", "other", false, false),
        ];
        for (path, status, ..) in expected {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.status().code, status, "{path}");
        }
        let response = client.get("/tc1796-busy-mismatch").dispatch().await;
        assert_eq!(response.status(), Status::InternalServerError);

        let output = String::from_utf8(captured.0.lock().clone()).unwrap();
        let events: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            events.len(),
            expected.len(),
            "one line per request: {output}"
        );
        for (event, (path, status, code, kind, write, has_hash)) in events.iter().zip(expected) {
            let fields = &event["fields"];
            assert_eq!(fields["route"], path);
            assert_eq!(fields["status"], status, "{path}");
            assert_eq!(fields["code"], code, "{path}");
            assert_eq!(fields["failure_kind"], kind, "{path}");
            assert_eq!(fields["write_may_have_applied"], write, "{path}");
            assert!(fields["elapsed_ms"].is_u64(), "{path}: {fields}");
            assert_eq!(fields.get("db_hash").is_some(), has_hash, "{path}");
            assert_eq!(fields.as_object().unwrap().len(), 8 + usize::from(has_hash));
        }
    }
}
