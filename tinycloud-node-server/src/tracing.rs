use opentelemetry::trace::{TraceContextExt, TracerProvider};
use opentelemetry_otlp::ExporterBuildError;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Status,
    request::{FromRequest, Outcome},
    Data, Request, Response,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tracing::{
    field::{Field, Visit},
    info_span,
    subscriber::set_global_default,
    Event, Level, Span, Subscriber,
};
use tracing_log::LogTracer;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::Context, layer::SubscriberExt, Layer, Registry};

use crate::config;

#[derive(Clone)]
pub struct TracingSpan(pub Span);

#[derive(Clone)]
struct RequestTelemetry {
    start: Instant,
}

pub struct TracingFairing {
    pub header_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    #[serde(skip)]
    seq: u64,
    timestamp: String,
    level: String,
    target: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Value>,
    #[serde(skip)]
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

pub fn tracing_try_init(config: &config::Logging) -> Result<(), ExporterBuildError> {
    let _ = LogTracer::init();
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
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
        span.record(
            "trace_id",
            tracing::field::display(&span.context().span().span_context().trace_id()),
        );
        req.local_cache(|| Some(TracingSpan(span)));
        if crate::prometheus::enabled() {
            req.local_cache(|| {
                Some(RequestTelemetry {
                    start: Instant::now(),
                })
            });
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        if let Some(TracingSpan(span)) = req.local_cache(|| Option::<TracingSpan>::None).to_owned()
        {
            let trace_id = span.context().span().span_context().trace_id();
            res.set_raw_header(self.header_name.clone(), format!("{trace_id}"));
        }
        if crate::prometheus::enabled() {
            if let Some(telemetry) = req
                .local_cache(|| Option::<RequestTelemetry>::None)
                .to_owned()
            {
                let route = req
                    .route()
                    .map(|route| route.uri.to_string())
                    .unwrap_or_else(|| req.uri().path().to_string());
                crate::prometheus::REQUEST_HISTOGRAM
                    .with_label_values(&[
                        req.method().as_str(),
                        route.as_str(),
                        res.status().code.to_string().as_str(),
                    ])
                    .observe(telemetry.start.elapsed().as_secs_f64());
            }
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
