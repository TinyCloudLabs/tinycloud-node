use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::encode_config;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, RwLock},
    task::JoinHandle,
};

use crate::{
    config::{self, Config, LoggingFormat},
    node_control::{
        key_provider::{self, IdentityPurpose, IdentitySnapshot},
        paths::{
            dir_to_json_string, systemd_system_group_gid, KeyBackend, LogMode, Profile,
            CONTROL_CONTRACT_VERSION,
        },
        service::{self, PublicApi},
    },
    tracing::{LogBuffer, LogEntry},
    BlockConfig,
};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const PUBLIC_PROTOCOL_VERSION: u32 = tinycloud_auth::protocol::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlRuntimeState {
    Starting = 0,
    Running = 1,
    Stopping = 2,
    Error = 3,
}

impl ControlRuntimeState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Stopping,
            3 => Self::Error,
            _ => Self::Starting,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlState {
    Starting,
    Running,
    Stopping,
    Error,
}

impl From<ControlRuntimeState> for ControlState {
    fn from(value: ControlRuntimeState) -> Self {
        match value {
            ControlRuntimeState::Starting => Self::Starting,
            ControlRuntimeState::Running => Self::Running,
            ControlRuntimeState::Stopping => Self::Stopping,
            ControlRuntimeState::Error => Self::Error,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlErrorResponse {
    contract_version: &'static str,
    error: ControlErrorBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlErrorBody {
    code: String,
    message: String,
    details: Value,
}

#[derive(Debug)]
pub struct ControlError {
    status: StatusCode,
    body: ControlErrorResponse,
}

impl ControlError {
    fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            status,
            body: ControlErrorResponse {
                contract_version: CONTROL_CONTRACT_VERSION,
                error: ControlErrorBody {
                    code: code.into(),
                    message: message.into(),
                    details,
                },
            },
        }
    }

    fn invalid_request(message: impl Into<String>, details: Value) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message, details)
    }

    fn invalid_token(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            message,
            json!({}),
        )
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message, json!({}))
    }

    fn internal_error(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            message,
            json!({}),
        )
    }
}

impl IntoResponse for ControlError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

type ControlResult<T> = Result<T, ControlError>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlVersionResponse {
    contract_version: &'static str,
    app_version: &'static str,
    public_protocol_version: u32,
    identity_ready: bool,
    key_backend: Option<KeyBackend>,
    node_did: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlStatusResponse {
    contract_version: &'static str,
    state: ControlState,
    pid: u32,
    version: &'static str,
    public_api: PublicApi,
    config_path: String,
    data_path: String,
    log_mode: LogMode,
    key_backend: Option<KeyBackend>,
    identity_ready: bool,
    node_did: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlConfigResponse {
    contract_version: &'static str,
    base_config_path: String,
    overlay_path: String,
    config: PublicConfigSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlPatchResponse {
    contract_version: &'static str,
    base_config_path: String,
    overlay_path: String,
    restart_required: bool,
    applied_paths: Vec<String>,
    config: PublicConfigSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlLogsTailResponse {
    contract_version: &'static str,
    source: String,
    cursor: Option<String>,
    entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicConfigSnapshot {
    log: PublicLogSnapshot,
    storage: PublicStorageSnapshot,
    spaces: PublicSpacesSnapshot,
    hooks: PublicHooksSnapshot,
    public_api: PublicApi,
    telemetry: PublicTelemetrySnapshot,
    prometheus: PublicPrometheusSnapshot,
    cors: bool,
    key_provider: PublicKeyProviderSnapshot,
    tee: PublicTeeSnapshot,
    public_spaces: PublicPublicSpacesSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicLogSnapshot {
    format: String,
    tracing: PublicTracingSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTracingSnapshot {
    enabled: bool,
    trace_header: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicStorageSnapshot {
    data_dir: String,
    blocks: PublicBlocksSnapshot,
    staging: PublicStagingSnapshot,
    database: PublicDatabaseSnapshot,
    limit_bytes: Option<u64>,
    sql: PublicSqlSnapshot,
    duckdb: PublicDuckDbSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicStagingSnapshot {
    FileSystem,
    Memory,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicBlocksSnapshot {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicDatabaseSnapshot {
    backend_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicSqlSnapshot {
    path: Option<String>,
    memory_threshold_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicDuckDbSnapshot {
    path: Option<String>,
    memory_threshold_bytes: u64,
    idle_timeout_seconds: u64,
    max_memory_per_connection: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicSpacesSnapshot {
    allowlist_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicHooksSnapshot {
    max_ticket_ttl_seconds: u64,
    max_scopes_per_ticket: usize,
    max_active_sse_streams: usize,
    sse_broadcast_capacity: usize,
    max_webhook_subscriptions_per_space: usize,
    webhook_timeout_seconds: u64,
    webhook_max_attempts: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTelemetrySnapshot {
    enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicPrometheusSnapshot {
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyProviderSnapshot {
    backend: Option<KeyBackend>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTeeSnapshot {
    mode: String,
    attestation: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicPublicSpacesSnapshot {
    rate_limit_per_minute: u32,
    rate_limit_burst: u32,
    storage_limit_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayFile {
    #[serde(default)]
    global: ControlOverlayGlobal,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayGlobal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cors: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log: Option<ControlOverlayLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage: Option<ControlOverlayStorage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_spaces: Option<ControlOverlayPublicSpaces>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hooks: Option<ControlOverlayHooks>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayLog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<LoggingFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tracing: Option<ControlOverlayTracing>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayTracing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayStorage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<ControlOverlayLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlOverlayLimit {
    /// TOML has no native `null`, so the overlay file stores `0` as the clear sentinel.
    Clear,
    Set(rocket::data::ByteUnit),
}

impl Serialize for ControlOverlayLimit {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Clear => serializer.serialize_u64(0),
            Self::Set(value) => serializer.serialize_u64(value.as_u64()),
        }
    }
}

impl<'de> Deserialize<'de> for ControlOverlayLimit {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 {
            Ok(Self::Clear)
        } else {
            Ok(Self::Set(rocket::data::ByteUnit::Byte(value)))
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayPublicSpaces {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit_burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_limit: Option<rocket::data::ByteUnit>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ControlOverlayHooks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_ticket_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_scopes_per_ticket: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_active_sse_streams: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sse_broadcast_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_webhook_subscriptions_per_space: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webhook_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webhook_max_attempts: Option<usize>,
}

#[derive(Clone)]
pub struct ControlPlaneHandle {
    inner: Arc<ControlPlaneInner>,
}

pub struct ControlPlaneServer {
    handle: ControlPlaneHandle,
    shutdown: Arc<Notify>,
    join: JoinHandle<Result<()>>,
}

struct ControlPlaneInner {
    profile: Profile,
    pid: u32,
    base_config_path: PathBuf,
    data_path: PathBuf,
    runtime_dir: PathBuf,
    overlay_path: PathBuf,
    control_json_path: PathBuf,
    control_token_path: PathBuf,
    control_addr: SocketAddr,
    public_api: PublicApi,
    log_mode: LogMode,
    token: String,
    identity: RwLock<IdentitySnapshot>,
    state: AtomicU8,
    overlay_lock: Mutex<()>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogsTailQuery {
    lines: Option<usize>,
    cursor: Option<String>,
    since: Option<String>,
}

pub async fn spawn_control_plane(
    config: &Config,
    base_config_path: PathBuf,
    profile: Profile,
) -> Result<ControlPlaneServer> {
    let mut effective_config = config.clone();
    effective_config.storage.resolve();

    let pid = std::process::id();
    let data_path = effective_config.storage.datadir.clone();
    let runtime_dir = data_path.join("runtime");
    let overlay_path = runtime_dir.join("config.override.toml");
    let control_json_path = runtime_dir.join("control.json");
    let control_token_path = runtime_dir.join("control.token");
    let public_api = service::public_api_from_config(&base_config_path);
    let identity_state = key_provider::resolve_identity_state(
        Some(&effective_config.keys),
        &effective_config.storage.datadir,
        IdentityPurpose::Probe,
    )?;
    let identity = key_provider::identity_snapshot(&identity_state);
    let token = generate_token();
    let std_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("failed to bind loopback control listener")?;
    std_listener
        .set_nonblocking(true)
        .context("failed to configure control listener")?;
    let listener =
        TcpListener::from_std(std_listener).context("failed to open control listener")?;
    let control_addr = listener
        .local_addr()
        .context("failed to read control listener address")?;
    if !control_addr.ip().is_loopback() {
        return Err(anyhow!("control listener must bind to loopback"));
    }

    let inner = Arc::new(ControlPlaneInner {
        profile,
        pid,
        base_config_path,
        data_path,
        runtime_dir,
        overlay_path,
        control_json_path,
        control_token_path,
        control_addr,
        public_api,
        log_mode: profile.log_mode(),
        token,
        identity: RwLock::new(identity),
        state: AtomicU8::new(ControlRuntimeState::Starting as u8),
        overlay_lock: Mutex::new(()),
    });

    inner.write_runtime_files().await?;

    let router = build_router(inner.clone());
    let shutdown = Arc::new(Notify::new());
    let serve_shutdown = shutdown.clone();
    let join = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                serve_shutdown.notified().await;
            })
            .await
            .context("control listener failed")
    });

    Ok(ControlPlaneServer {
        handle: ControlPlaneHandle { inner },
        shutdown,
        join,
    })
}

impl ControlPlaneServer {
    pub fn handle(&self) -> ControlPlaneHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> Result<()> {
        self.handle.mark_stopping();
        self.shutdown.notify_waiters();
        let result = self.join.await.context("control listener task failed")?;
        self.handle.cleanup_runtime_files().await;
        result
    }
}

impl ControlPlaneHandle {
    fn state(&self) -> ControlState {
        ControlRuntimeState::from_u8(self.inner.state.load(Ordering::SeqCst)).into()
    }

    pub fn mark_running(&self) {
        if matches!(
            ControlRuntimeState::from_u8(self.inner.state.load(Ordering::SeqCst)),
            ControlRuntimeState::Starting
        ) {
            self.inner
                .state
                .store(ControlRuntimeState::Running as u8, Ordering::SeqCst);
        }
    }

    pub fn mark_stopping(&self) {
        self.inner
            .state
            .store(ControlRuntimeState::Stopping as u8, Ordering::SeqCst);
    }

    pub async fn set_identity_snapshot(&self, identity: IdentitySnapshot) {
        *self.inner.identity.write().await = identity;
    }

    async fn read_identity_snapshot(&self) -> IdentitySnapshot {
        self.inner.identity.read().await.clone()
    }

    fn token(&self) -> &str {
        &self.inner.token
    }

    async fn cleanup_runtime_files(&self) {
        remove_if_exists(&self.inner.control_json_path).await;
        remove_if_exists(&self.inner.control_token_path).await;
    }

    fn control_status(&self) -> ControlState {
        self.state()
    }

    fn status_response(&self, identity: IdentitySnapshot) -> ControlStatusResponse {
        ControlStatusResponse {
            contract_version: CONTROL_CONTRACT_VERSION,
            state: self.control_status(),
            pid: self.inner.pid,
            version: APP_VERSION,
            public_api: self.inner.public_api.clone(),
            config_path: self.inner.base_config_path.display().to_string(),
            data_path: dir_to_json_string(&self.inner.data_path),
            log_mode: self.inner.log_mode,
            key_backend: identity.key_backend,
            identity_ready: identity.identity_ready,
            node_did: identity.node_did,
        }
    }

    fn version_response(&self, identity: IdentitySnapshot) -> ControlVersionResponse {
        ControlVersionResponse {
            contract_version: CONTROL_CONTRACT_VERSION,
            app_version: APP_VERSION,
            public_protocol_version: PUBLIC_PROTOCOL_VERSION,
            identity_ready: identity.identity_ready,
            key_backend: identity.key_backend,
            node_did: identity.node_did,
        }
    }

    async fn public_config_response(&self) -> ControlResult<ControlConfigResponse> {
        let _guard = self.inner.overlay_lock.lock().await;
        effective_public_config(&self.inner.base_config_path)
    }

    async fn patch_config(&self, patch: Value) -> ControlResult<ControlPatchResponse> {
        let patch = patch
            .as_object()
            .ok_or_else(|| {
                ControlError::invalid_request(
                    "request body must be a JSON object",
                    json!({ "field": "body" }),
                )
            })?
            .clone();

        validate_keys(
            &patch,
            &["cors", "log", "storage", "publicSpaces", "hooks"],
            "request body",
        )?;

        let _guard = self.inner.overlay_lock.lock().await;
        let before = effective_public_config(&self.inner.base_config_path)?;
        let before_value = serde_json::to_value(&before.config)
            .map_err(|err| ControlError::internal_error(err.to_string()))?;

        let mut overlay = self
            .read_overlay()
            .await
            .map_err(|err| ControlError::internal_error(err.to_string()))?;
        let mut overlay_changed = false;

        if let Some(value) = patch.get("cors") {
            let new_value = parse_bool_or_default(value, "cors", false)?;
            let entry = overlay.global.cors;
            if entry != Some(new_value) {
                overlay_changed = true;
            }
            overlay.global.cors = Some(new_value);
        }

        if let Some(value) = patch.get("log") {
            let log = value.as_object().ok_or_else(|| {
                ControlError::invalid_request(
                    "field 'log' must be an object",
                    json!({ "field": "log" }),
                )
            })?;
            validate_keys(log, &["format", "tracing"], "log")?;
            let entry = overlay
                .global
                .log
                .get_or_insert_with(ControlOverlayLog::default);

            if let Some(value) = log.get("format") {
                let new_value = parse_log_format(value, "log.format")?;
                if entry.format != Some(new_value.clone()) {
                    overlay_changed = true;
                }
                entry.format = Some(new_value);
            }

            if let Some(value) = log.get("tracing") {
                let tracing = value.as_object().ok_or_else(|| {
                    ControlError::invalid_request(
                        "field 'log.tracing' must be an object",
                        json!({ "field": "log.tracing" }),
                    )
                })?;
                validate_keys(tracing, &["enabled"], "log.tracing")?;
                let tracing_entry = entry
                    .tracing
                    .get_or_insert_with(ControlOverlayTracing::default);
                if let Some(value) = tracing.get("enabled") {
                    let new_value = parse_bool_or_default(value, "log.tracing.enabled", false)?;
                    if tracing_entry.enabled != Some(new_value) {
                        overlay_changed = true;
                    }
                    tracing_entry.enabled = Some(new_value);
                }
            }
        }

        if let Some(value) = patch.get("storage") {
            let storage = value.as_object().ok_or_else(|| {
                ControlError::invalid_request(
                    "field 'storage' must be an object",
                    json!({ "field": "storage" }),
                )
            })?;
            validate_keys(storage, &["limitBytes"], "storage")?;
            let entry = overlay
                .global
                .storage
                .get_or_insert_with(ControlOverlayStorage::default);
            if let Some(value) = storage.get("limitBytes") {
                let new_value = parse_byte_unit_patch(value, "storage.limitBytes")?;
                if entry.limit.as_ref() != Some(&new_value) {
                    overlay_changed = true;
                }
                entry.limit = Some(new_value);
            }
        }

        if let Some(value) = patch.get("publicSpaces") {
            let public_spaces = value.as_object().ok_or_else(|| {
                ControlError::invalid_request(
                    "field 'publicSpaces' must be an object",
                    json!({ "field": "publicSpaces" }),
                )
            })?;
            validate_keys(
                public_spaces,
                &["rateLimitPerMinute", "rateLimitBurst", "storageLimitBytes"],
                "publicSpaces",
            )?;
            let entry = overlay
                .global
                .public_spaces
                .get_or_insert_with(ControlOverlayPublicSpaces::default);

            if let Some(value) = public_spaces.get("rateLimitPerMinute") {
                let new_value = parse_u32_or_default(value, "publicSpaces.rateLimitPerMinute", 60)?;
                if entry.rate_limit_per_minute != Some(new_value) {
                    overlay_changed = true;
                }
                entry.rate_limit_per_minute = Some(new_value);
            }

            if let Some(value) = public_spaces.get("rateLimitBurst") {
                let new_value = parse_u32_or_default(value, "publicSpaces.rateLimitBurst", 10)?;
                if entry.rate_limit_burst != Some(new_value) {
                    overlay_changed = true;
                }
                entry.rate_limit_burst = Some(new_value);
            }

            if let Some(value) = public_spaces.get("storageLimitBytes") {
                let new_value = parse_byte_unit_or_default(
                    value,
                    "publicSpaces.storageLimitBytes",
                    10 * 1024 * 1024,
                )?;
                if entry.storage_limit != Some(new_value) {
                    overlay_changed = true;
                }
                entry.storage_limit = Some(new_value);
            }
        }

        if let Some(value) = patch.get("hooks") {
            let hooks = value.as_object().ok_or_else(|| {
                ControlError::invalid_request(
                    "field 'hooks' must be an object",
                    json!({ "field": "hooks" }),
                )
            })?;
            validate_keys(
                hooks,
                &[
                    "maxTicketTtlSeconds",
                    "maxScopesPerTicket",
                    "maxActiveSseStreams",
                    "sseBroadcastCapacity",
                    "maxWebhookSubscriptionsPerSpace",
                    "webhookTimeoutSeconds",
                    "webhookMaxAttempts",
                ],
                "hooks",
            )?;
            let entry = overlay
                .global
                .hooks
                .get_or_insert_with(ControlOverlayHooks::default);

            if let Some(value) = hooks.get("maxTicketTtlSeconds") {
                let new_value = parse_u64_or_default(value, "hooks.maxTicketTtlSeconds", 300)?;
                if entry.max_ticket_ttl_seconds != Some(new_value) {
                    overlay_changed = true;
                }
                entry.max_ticket_ttl_seconds = Some(new_value);
            }

            if let Some(value) = hooks.get("maxScopesPerTicket") {
                let new_value = parse_usize_or_default(value, "hooks.maxScopesPerTicket", 32)?;
                if entry.max_scopes_per_ticket != Some(new_value) {
                    overlay_changed = true;
                }
                entry.max_scopes_per_ticket = Some(new_value);
            }

            if let Some(value) = hooks.get("maxActiveSseStreams") {
                let new_value = parse_usize_or_default(value, "hooks.maxActiveSseStreams", 100)?;
                if entry.max_active_sse_streams != Some(new_value) {
                    overlay_changed = true;
                }
                entry.max_active_sse_streams = Some(new_value);
            }

            if let Some(value) = hooks.get("sseBroadcastCapacity") {
                let new_value = parse_usize_or_default(value, "hooks.sseBroadcastCapacity", 1024)?;
                if entry.sse_broadcast_capacity != Some(new_value) {
                    overlay_changed = true;
                }
                entry.sse_broadcast_capacity = Some(new_value);
            }

            if let Some(value) = hooks.get("maxWebhookSubscriptionsPerSpace") {
                let new_value =
                    parse_usize_or_default(value, "hooks.maxWebhookSubscriptionsPerSpace", 5)?;
                if entry.max_webhook_subscriptions_per_space != Some(new_value) {
                    overlay_changed = true;
                }
                entry.max_webhook_subscriptions_per_space = Some(new_value);
            }

            if let Some(value) = hooks.get("webhookTimeoutSeconds") {
                let new_value = parse_u64_or_default(value, "hooks.webhookTimeoutSeconds", 10)?;
                if entry.webhook_timeout_seconds != Some(new_value) {
                    overlay_changed = true;
                }
                entry.webhook_timeout_seconds = Some(new_value);
            }

            if let Some(value) = hooks.get("webhookMaxAttempts") {
                let new_value = parse_usize_or_default(value, "hooks.webhookMaxAttempts", 5)?;
                if entry.webhook_max_attempts != Some(new_value) {
                    overlay_changed = true;
                }
                entry.webhook_max_attempts = Some(new_value);
            }
        }

        prune_overlay(&mut overlay);
        self.write_overlay(&overlay)
            .await
            .map_err(|err| ControlError::internal_error(err.to_string()))?;

        let after = effective_public_config(&self.inner.base_config_path)?;
        let after_value = serde_json::to_value(&after.config)
            .map_err(|err| ControlError::internal_error(err.to_string()))?;

        let mut applied_paths = Vec::new();
        for path in [
            "cors",
            "log.format",
            "log.tracing.enabled",
            "storage.limitBytes",
            "publicSpaces.rateLimitPerMinute",
            "publicSpaces.rateLimitBurst",
            "publicSpaces.storageLimitBytes",
            "hooks.maxTicketTtlSeconds",
            "hooks.maxScopesPerTicket",
            "hooks.maxActiveSseStreams",
            "hooks.sseBroadcastCapacity",
            "hooks.maxWebhookSubscriptionsPerSpace",
            "hooks.webhookTimeoutSeconds",
            "hooks.webhookMaxAttempts",
        ] {
            if patch_path_present(&patch, path) && leaf_changed(&before_value, &after_value, path) {
                applied_paths.push(path.to_string());
            }
        }

        Ok(ControlPatchResponse {
            contract_version: CONTROL_CONTRACT_VERSION,
            base_config_path: self.inner.base_config_path.display().to_string(),
            overlay_path: self.inner.overlay_path.display().to_string(),
            restart_required: overlay_changed,
            applied_paths,
            config: after.config,
        })
    }

    async fn logs_tail(&self, query: LogsTailQuery) -> ControlResult<ControlLogsTailResponse> {
        let log_source = log_source_name(self.inner.log_mode);
        let LogsTailQuery {
            lines,
            cursor: cursor_param,
            since,
        } = query;
        let lines = match lines.unwrap_or(200) {
            0 => {
                return Err(ControlError::invalid_request(
                    "field 'lines' must be between 1 and 2000",
                    json!({ "field": "lines" }),
                ))
            }
            value if value > 2000 => {
                return Err(ControlError::invalid_request(
                    "field 'lines' must be between 1 and 2000",
                    json!({ "field": "lines" }),
                ))
            }
            value => value,
        };

        let cursor = cursor_param
            .as_deref()
            .and_then(|cursor| parse_log_cursor(self.inner.log_mode, cursor));

        let since = if cursor_param.is_some() {
            None
        } else if let Some(since) = since {
            Some(
                OffsetDateTime::parse(&since, &time::format_description::well_known::Rfc3339)
                    .map_err(|_| {
                        ControlError::invalid_request(
                            "field 'since' must be RFC3339",
                            json!({ "field": "since" }),
                        )
                    })?,
            )
        } else {
            None
        };

        let (entries, cursor) = LogBuffer::global().tail(lines, cursor, since);
        Ok(ControlLogsTailResponse {
            contract_version: CONTROL_CONTRACT_VERSION,
            source: log_source.to_string(),
            cursor: cursor.map(|cursor| encode_log_cursor(self.inner.log_mode, cursor)),
            entries,
        })
    }

    async fn read_overlay(&self) -> Result<ControlOverlayFile> {
        read_overlay(&self.inner.overlay_path).await
    }

    async fn write_overlay(&self, overlay: &ControlOverlayFile) -> Result<()> {
        write_overlay(&self.inner.overlay_path, overlay).await
    }
}

impl ControlPlaneInner {
    async fn write_runtime_files(&self) -> Result<()> {
        let ownership = runtime_ownership(self.profile)?;
        ensure_dir_mode(&self.runtime_dir, runtime_dir_mode(self.profile), ownership).await?;
        write_private_text(
            &self.control_token_path,
            &self.token,
            runtime_file_mode(self.profile),
            ownership,
        )
        .await?;
        let rendered = serde_json::to_string_pretty(&service::ControlManifest {
            contract_version: CONTROL_CONTRACT_VERSION.to_string(),
            host: self.control_addr.ip().to_string(),
            port: self.control_addr.port(),
            pid: Some(self.pid),
            token_path: self.control_token_path.display().to_string(),
        })?;
        write_private_text(
            &self.control_json_path,
            &rendered,
            runtime_file_mode(self.profile),
            ownership,
        )
        .await?;
        Ok(())
    }
}

fn build_router(handle: Arc<ControlPlaneInner>) -> Router {
    let state = ControlPlaneHandle { inner: handle };
    Router::new()
        .route("/v1/status", get(get_status))
        .route("/v1/version", get(get_version))
        .route("/v1/identity", get(get_identity))
        .route("/v1/config", get(get_config).patch(patch_config))
        .route("/v1/logs/tail", get(get_logs_tail))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

async fn auth_middleware(
    State(handle): State<ControlPlaneHandle>,
    request: Request<Body>,
    next: Next,
) -> Response {
    match authorize(&handle, request.headers()) {
        Ok(()) => next.run(request).await,
        Err(err) => err.into_response(),
    }
}

fn authorize(handle: &ControlPlaneHandle, headers: &axum::http::HeaderMap) -> ControlResult<()> {
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(provided) = provided else {
        return Err(ControlError::invalid_token("missing bearer token"));
    };

    if provided
        .as_bytes()
        .ct_eq(handle.token().as_bytes())
        .unwrap_u8()
        == 1
    {
        Ok(())
    } else {
        Err(ControlError::invalid_token("invalid bearer token"))
    }
}

async fn get_status(
    State(handle): State<ControlPlaneHandle>,
) -> ControlResult<Json<ControlStatusResponse>> {
    let identity = handle.read_identity_snapshot().await;
    Ok(Json(handle.status_response(identity)))
}

async fn get_version(
    State(handle): State<ControlPlaneHandle>,
) -> ControlResult<Json<ControlVersionResponse>> {
    let identity = handle.read_identity_snapshot().await;
    Ok(Json(handle.version_response(identity)))
}

async fn get_identity(
    State(handle): State<ControlPlaneHandle>,
) -> ControlResult<Json<IdentitySnapshot>> {
    let identity = handle.read_identity_snapshot().await;
    Ok(Json(identity))
}

async fn get_config(
    State(handle): State<ControlPlaneHandle>,
) -> ControlResult<Json<ControlConfigResponse>> {
    Ok(Json(handle.public_config_response().await?))
}

async fn patch_config(
    State(handle): State<ControlPlaneHandle>,
    Json(body): Json<Value>,
) -> ControlResult<Json<ControlPatchResponse>> {
    Ok(Json(handle.patch_config(body).await?))
}

async fn get_logs_tail(
    State(handle): State<ControlPlaneHandle>,
    Query(query): Query<LogsTailQuery>,
) -> ControlResult<Json<ControlLogsTailResponse>> {
    Ok(Json(handle.logs_tail(query).await?))
}

async fn not_found() -> ControlError {
    ControlError::not_found("unknown control API path")
}

fn effective_public_config(base_config_path: &Path) -> ControlResult<ControlConfigResponse> {
    (|| -> Result<ControlConfigResponse> {
        let figment = crate::runtime::serve_config_figment(base_config_path)?;
        let mut config = figment.extract::<Config>()?;
        config.storage.resolve();

        let identity = key_provider::resolve_identity_state(
            Some(&config.keys),
            &config.storage.datadir,
            IdentityPurpose::Probe,
        )?;
        let public_api = service::public_api_from_config(base_config_path);

        Ok(ControlConfigResponse {
            contract_version: CONTROL_CONTRACT_VERSION,
            base_config_path: base_config_path.display().to_string(),
            overlay_path: config
                .storage
                .datadir
                .join("runtime/config.override.toml")
                .display()
                .to_string(),
            config: PublicConfigSnapshot {
                log: PublicLogSnapshot {
                    format: logging_format_string(&config.log.format),
                    tracing: PublicTracingSnapshot {
                        enabled: config.log.tracing.enabled,
                        trace_header: config.log.tracing.traceheader.clone(),
                    },
                },
                storage: PublicStorageSnapshot {
                    data_dir: dir_to_json_string(&config.storage.datadir),
                    blocks: public_block_config(&config.storage.blocks),
                    staging: public_staging_snapshot(&config.storage.staging),
                    database: PublicDatabaseSnapshot {
                        backend_kind: database_backend_kind(config.storage.database()),
                        path: database_path(config.storage.database()),
                    },
                    limit_bytes: config.storage.limit.map(|value| value.as_u64()),
                    sql: PublicSqlSnapshot {
                        path: config.storage.sql.path.clone(),
                        memory_threshold_bytes: config.storage.sql.memory_threshold.as_u64(),
                    },
                    duckdb: PublicDuckDbSnapshot {
                        path: config.storage.duckdb.path.clone(),
                        memory_threshold_bytes: config.storage.duckdb.memory_threshold.as_u64(),
                        idle_timeout_seconds: config.storage.duckdb.idle_timeout_secs,
                        max_memory_per_connection: config
                            .storage
                            .duckdb
                            .max_memory_per_connection
                            .clone(),
                    },
                },
                spaces: PublicSpacesSnapshot {
                    allowlist_url: config
                        .spaces
                        .allowlist
                        .as_ref()
                        .map(|allowlist| allowlist.0.clone()),
                },
                hooks: PublicHooksSnapshot {
                    max_ticket_ttl_seconds: config.hooks.max_ticket_ttl_seconds,
                    max_scopes_per_ticket: config.hooks.max_scopes_per_ticket,
                    max_active_sse_streams: config.hooks.max_active_sse_streams,
                    sse_broadcast_capacity: config.hooks.sse_broadcast_capacity,
                    max_webhook_subscriptions_per_space: config
                        .hooks
                        .max_webhook_subscriptions_per_space,
                    webhook_timeout_seconds: config.hooks.webhook_timeout_seconds,
                    webhook_max_attempts: config.hooks.webhook_max_attempts,
                },
                public_api,
                telemetry: PublicTelemetrySnapshot {
                    enabled: config.telemetry.enabled,
                },
                prometheus: PublicPrometheusSnapshot {
                    port: config.prometheus.port,
                },
                cors: config.cors,
                key_provider: PublicKeyProviderSnapshot {
                    backend: identity.backend,
                },
                tee: PublicTeeSnapshot {
                    mode: tee_mode_string(&config.tee.mode),
                    attestation: config.tee.attestation,
                },
                public_spaces: PublicPublicSpacesSnapshot {
                    rate_limit_per_minute: config.public_spaces.rate_limit_per_minute,
                    rate_limit_burst: config.public_spaces.rate_limit_burst,
                    storage_limit_bytes: config.public_spaces.storage_limit.as_u64(),
                },
            },
        })
    })()
    .map_err(|err| ControlError::internal_error(err.to_string()))
}

fn public_block_config(blocks: &BlockConfig) -> PublicBlocksSnapshot {
    match blocks {
        BlockConfig::A(s3) => PublicBlocksSnapshot {
            kind: "s3".to_string(),
            path: None,
            bucket: Some(s3.bucket.clone()),
            endpoint: s3.endpoint.as_ref().map(|uri| uri.to_string()),
        },
        BlockConfig::B(local) => PublicBlocksSnapshot {
            kind: "local".to_string(),
            path: Some(local.path().display().to_string()),
            bucket: None,
            endpoint: None,
        },
    }
}

fn logging_format_string(format: &LoggingFormat) -> String {
    match format {
        LoggingFormat::Text => "text".to_string(),
        LoggingFormat::Json => "json".to_string(),
    }
}

fn tee_mode_string(mode: &config::TeeMode) -> String {
    match mode {
        config::TeeMode::Auto => "auto".to_string(),
        config::TeeMode::Dstack => "dstack".to_string(),
        config::TeeMode::Off => "off".to_string(),
    }
}

fn log_source_name(log_mode: LogMode) -> &'static str {
    match log_mode {
        LogMode::File => "file",
        LogMode::Journald => "journald",
        LogMode::Stdout => "stdout",
    }
}

fn public_staging_snapshot(staging: &crate::BlockStage) -> PublicStagingSnapshot {
    match staging {
        crate::BlockStage::A(_) => PublicStagingSnapshot::FileSystem,
        crate::BlockStage::B(_) => PublicStagingSnapshot::Memory,
    }
}

fn encode_log_cursor(log_mode: LogMode, cursor: String) -> String {
    match log_mode {
        LogMode::File => format!("file:{cursor}"),
        LogMode::Journald => format!("journald:{cursor}"),
        LogMode::Stdout => cursor,
    }
}

fn parse_log_cursor(log_mode: LogMode, cursor: &str) -> Option<u64> {
    let rendered = match log_mode {
        LogMode::File => cursor.strip_prefix("file:").unwrap_or(cursor),
        LogMode::Journald => cursor.strip_prefix("journald:").unwrap_or(cursor),
        LogMode::Stdout => cursor,
    };

    rendered.parse::<u64>().ok()
}

fn database_backend_kind(database: &str) -> String {
    if database.starts_with("sqlite:") {
        "sqlite".to_string()
    } else if database.starts_with("mysql:") || database.starts_with("mysql://") {
        "mysql".to_string()
    } else if database.starts_with("postgres:")
        || database.starts_with("postgres://")
        || database.starts_with("postgresql:")
        || database.starts_with("postgresql://")
    {
        "postgres".to_string()
    } else {
        "other".to_string()
    }
}

fn database_path(database: &str) -> Option<String> {
    let path = database.strip_prefix("sqlite:")?;
    let path = path.split('?').next().unwrap_or(path);
    if path == ":memory:" || path.starts_with(":memory:") {
        None
    } else {
        Some(path.to_string())
    }
}

fn validate_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> ControlResult<()> {
    for key in object.keys() {
        if !allowed.iter().any(|allowed| allowed == key) {
            return Err(ControlError::invalid_request(
                format!("field '{}' is not supported in {}", key, context),
                json!({ "field": format!("{context}.{key}") }),
            ));
        }
    }
    Ok(())
}

fn parse_bool_or_default(value: &Value, path: &str, default: bool) -> ControlResult<bool> {
    match value {
        Value::Null => Ok(default),
        Value::Bool(value) => Ok(*value),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be a boolean or null", path),
            json!({ "field": path }),
        )),
    }
}

fn parse_u64_or_default(value: &Value, path: &str, default: u64) -> ControlResult<u64> {
    match value {
        Value::Null => Ok(default),
        Value::Number(number) => number.as_u64().ok_or_else(|| {
            ControlError::invalid_request(
                format!("field '{}' must be a non-negative integer or null", path),
                json!({ "field": path }),
            )
        }),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be a non-negative integer or null", path),
            json!({ "field": path }),
        )),
    }
}

fn parse_u32_or_default(value: &Value, path: &str, default: u32) -> ControlResult<u32> {
    match value {
        Value::Null => Ok(default),
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                ControlError::invalid_request(
                    format!("field '{}' must be a non-negative integer or null", path),
                    json!({ "field": path }),
                )
            }),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be a non-negative integer or null", path),
            json!({ "field": path }),
        )),
    }
}

fn parse_usize_or_default(value: &Value, path: &str, default: usize) -> ControlResult<usize> {
    match value {
        Value::Null => Ok(default),
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                ControlError::invalid_request(
                    format!("field '{}' must be a non-negative integer or null", path),
                    json!({ "field": path }),
                )
            }),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be a non-negative integer or null", path),
            json!({ "field": path }),
        )),
    }
}

fn parse_byte_unit_or_default(
    value: &Value,
    path: &str,
    default: u64,
) -> ControlResult<rocket::data::ByteUnit> {
    match value {
        Value::Null => Ok(rocket::data::ByteUnit::Byte(default)),
        Value::Number(number) => number
            .as_u64()
            .map(rocket::data::ByteUnit::Byte)
            .ok_or_else(|| {
                ControlError::invalid_request(
                    format!("field '{}' must be a non-negative integer or null", path),
                    json!({ "field": path }),
                )
            }),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be a non-negative integer or null", path),
            json!({ "field": path }),
        )),
    }
}

fn parse_byte_unit_patch(value: &Value, path: &str) -> ControlResult<ControlOverlayLimit> {
    match value {
        Value::Null => Ok(ControlOverlayLimit::Clear),
        Value::Number(number) => number
            .as_u64()
            .filter(|value| *value > 0)
            .map(|value| ControlOverlayLimit::Set(rocket::data::ByteUnit::Byte(value)))
            .ok_or_else(|| {
                ControlError::invalid_request(
                    format!("field '{}' must be a positive integer or null", path),
                    json!({ "field": path }),
                )
            }),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be a positive integer or null", path),
            json!({ "field": path }),
        )),
    }
}

fn parse_log_format(value: &Value, path: &str) -> ControlResult<LoggingFormat> {
    let rendered = match value {
        Value::Null => "text".to_string(),
        Value::String(value) => value.to_ascii_lowercase(),
        _ => {
            return Err(ControlError::invalid_request(
                format!("field '{}' must be 'text', 'json', or null", path),
                json!({ "field": path }),
            ))
        }
    };

    match rendered.as_str() {
        "text" => Ok(LoggingFormat::Text),
        "json" => Ok(LoggingFormat::Json),
        _ => Err(ControlError::invalid_request(
            format!("field '{}' must be 'text', 'json', or null", path),
            json!({ "field": path }),
        )),
    }
}

fn patch_path_present(patch: &serde_json::Map<String, Value>, path: &str) -> bool {
    match path {
        "cors" => patch.contains_key("cors"),
        "log.format" => patch
            .get("log")
            .and_then(|log| log.as_object())
            .and_then(|log| log.get("format"))
            .is_some(),
        "log.tracing.enabled" => patch
            .get("log")
            .and_then(|log| log.as_object())
            .and_then(|log| log.get("tracing"))
            .and_then(|tracing| tracing.as_object())
            .and_then(|tracing| tracing.get("enabled"))
            .is_some(),
        "storage.limitBytes" => patch
            .get("storage")
            .and_then(|storage| storage.as_object())
            .and_then(|storage| storage.get("limitBytes"))
            .is_some(),
        "publicSpaces.rateLimitPerMinute" => patch
            .get("publicSpaces")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("rateLimitPerMinute"))
            .is_some(),
        "publicSpaces.rateLimitBurst" => patch
            .get("publicSpaces")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("rateLimitBurst"))
            .is_some(),
        "publicSpaces.storageLimitBytes" => patch
            .get("publicSpaces")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("storageLimitBytes"))
            .is_some(),
        "hooks.maxTicketTtlSeconds" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("maxTicketTtlSeconds"))
            .is_some(),
        "hooks.maxScopesPerTicket" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("maxScopesPerTicket"))
            .is_some(),
        "hooks.maxActiveSseStreams" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("maxActiveSseStreams"))
            .is_some(),
        "hooks.sseBroadcastCapacity" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("sseBroadcastCapacity"))
            .is_some(),
        "hooks.maxWebhookSubscriptionsPerSpace" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("maxWebhookSubscriptionsPerSpace"))
            .is_some(),
        "hooks.webhookTimeoutSeconds" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("webhookTimeoutSeconds"))
            .is_some(),
        "hooks.webhookMaxAttempts" => patch
            .get("hooks")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("webhookMaxAttempts"))
            .is_some(),
        _ => false,
    }
}

fn leaf_changed(before: &Value, after: &Value, path: &str) -> bool {
    let pointer = match path {
        "cors" => "/cors",
        "log.format" => "/log/format",
        "log.tracing.enabled" => "/log/tracing/enabled",
        "storage.limitBytes" => "/storage/limitBytes",
        "publicSpaces.rateLimitPerMinute" => "/publicSpaces/rateLimitPerMinute",
        "publicSpaces.rateLimitBurst" => "/publicSpaces/rateLimitBurst",
        "publicSpaces.storageLimitBytes" => "/publicSpaces/storageLimitBytes",
        "hooks.maxTicketTtlSeconds" => "/hooks/maxTicketTtlSeconds",
        "hooks.maxScopesPerTicket" => "/hooks/maxScopesPerTicket",
        "hooks.maxActiveSseStreams" => "/hooks/maxActiveSseStreams",
        "hooks.sseBroadcastCapacity" => "/hooks/sseBroadcastCapacity",
        "hooks.maxWebhookSubscriptionsPerSpace" => "/hooks/maxWebhookSubscriptionsPerSpace",
        "hooks.webhookTimeoutSeconds" => "/hooks/webhookTimeoutSeconds",
        "hooks.webhookMaxAttempts" => "/hooks/webhookMaxAttempts",
        _ => return false,
    };

    before.pointer(pointer) != after.pointer(pointer)
}

fn prune_overlay(overlay: &mut ControlOverlayFile) {
    if let Some(log) = overlay.global.log.as_ref() {
        if log.format.is_none()
            && log
                .tracing
                .as_ref()
                .is_none_or(|tracing| tracing.enabled.is_none())
        {
            overlay.global.log = None;
        }
    }

    if let Some(storage) = overlay.global.storage.as_ref() {
        if storage.limit.is_none() {
            overlay.global.storage = None;
        }
    }

    if let Some(public_spaces) = overlay.global.public_spaces.as_ref() {
        if public_spaces.rate_limit_per_minute.is_none()
            && public_spaces.rate_limit_burst.is_none()
            && public_spaces.storage_limit.is_none()
        {
            overlay.global.public_spaces = None;
        }
    }

    if let Some(hooks) = overlay.global.hooks.as_ref() {
        if hooks.max_ticket_ttl_seconds.is_none()
            && hooks.max_scopes_per_ticket.is_none()
            && hooks.max_active_sse_streams.is_none()
            && hooks.sse_broadcast_capacity.is_none()
            && hooks.max_webhook_subscriptions_per_space.is_none()
            && hooks.webhook_timeout_seconds.is_none()
            && hooks.webhook_max_attempts.is_none()
        {
            overlay.global.hooks = None;
        }
    }

    if overlay.global.cors.is_none()
        && overlay.global.log.is_none()
        && overlay.global.storage.is_none()
        && overlay.global.public_spaces.is_none()
        && overlay.global.hooks.is_none()
    {
        overlay.global = ControlOverlayGlobal::default();
    }
}

async fn read_overlay(path: &Path) -> Result<ControlOverlayFile> {
    match tokio::fs::read_to_string(path).await {
        Ok(rendered) => {
            toml::from_str(&rendered).with_context(|| format!("failed to parse {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ControlOverlayFile::default()),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn write_overlay(path: &Path, overlay: &ControlOverlayFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let rendered = toml::to_string_pretty(overlay)?;
    write_private_text(path, &rendered, 0o600, None).await
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

async fn ensure_dir_mode(path: &Path, mode: u32, ownership: Option<(u32, u32)>) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("failed to stat {}", path.display()))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        tokio::fs::set_permissions(path, permissions)
            .await
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        set_private_ownership(path, ownership).await?;
    }
    Ok(())
}

async fn write_private_text(
    path: &Path,
    contents: &str,
    mode: u32,
    ownership: Option<(u32, u32)>,
) -> Result<()> {
    tokio::fs::write(path, contents)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    set_private_permissions(path, mode).await?;
    set_private_ownership(path, ownership).await?;
    Ok(())
}

async fn remove_if_exists(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
}

async fn set_private_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("failed to stat {}", path.display()))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        tokio::fs::set_permissions(path, permissions)
            .await
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

async fn set_private_ownership(path: &Path, ownership: Option<(u32, u32)>) -> Result<()> {
    #[cfg(unix)]
    if let Some((uid, gid)) = ownership {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let rendered = CString::new(path.as_os_str().as_bytes()).with_context(|| {
            format!("failed to prepare {} for ownership change", path.display())
        })?;
        let rc = unsafe { libc::chown(rendered.as_ptr(), uid, gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to set ownership on {}", path.display()));
        }
    }
    Ok(())
}

fn runtime_dir_mode(profile: Profile) -> u32 {
    if matches!(profile, Profile::LinuxSystem) {
        0o750
    } else {
        0o700
    }
}

fn runtime_file_mode(profile: Profile) -> u32 {
    if matches!(profile, Profile::LinuxSystem) {
        0o640
    } else {
        0o600
    }
}

#[cfg(unix)]
fn runtime_ownership(profile: Profile) -> Result<Option<(u32, u32)>> {
    if matches!(profile, Profile::LinuxSystem) {
        let gid = systemd_system_group_gid().ok_or_else(|| {
            anyhow!("systemd-system installs require the 'tinycloud' group to exist")
        })?;
        Ok(Some((0, gid)))
    } else {
        Ok(None)
    }
}

#[cfg(not(unix))]
fn runtime_ownership(_profile: Profile) -> Result<Option<(u32, u32)>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        node_control::{
            paths::{Profile, ProfilePaths},
            service::{self, DoctorCheckStatus, ServiceManifest, ServiceState},
        },
        runtime,
        test_support::env_lock,
    };
    use reqwest::Client;
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use tempfile::{tempdir, TempDir};
    use tokio::time::{sleep, Duration};

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    struct ProfileSetup {
        profile: Profile,
        paths: ProfilePaths,
        _temp: TempDir,
        _guards: Vec<EnvGuard>,
    }

    fn setup_profile(temp: TempDir) -> ProfileSetup {
        #[cfg(target_os = "macos")]
        {
            let guards = vec![
                EnvGuard::set("TINYCLOUD_NODE_CONFIG_ROOT", temp.path()),
                EnvGuard::set(
                    "TINYCLOUD_KEYS_SECRET",
                    base64::encode_config([7u8; 32], base64::URL_SAFE_NO_PAD),
                ),
            ];
            let profile = Profile::MacosUser;
            let paths = profile.paths();
            ProfileSetup {
                profile,
                paths,
                _temp: temp,
                _guards: guards,
            }
        }

        #[cfg(target_os = "linux")]
        {
            let home = temp.path().join("home");
            let config_home = temp.path().join("config");
            let data_home = temp.path().join("data");
            let state_home = temp.path().join("state");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&config_home).unwrap();
            fs::create_dir_all(&data_home).unwrap();
            fs::create_dir_all(&state_home).unwrap();
            let guards = vec![
                EnvGuard::set("HOME", &home),
                EnvGuard::set("XDG_CONFIG_HOME", &config_home),
                EnvGuard::set("XDG_DATA_HOME", &data_home),
                EnvGuard::set("XDG_STATE_HOME", &state_home),
                EnvGuard::set(
                    "TINYCLOUD_KEYS_SECRET",
                    base64::encode_config([7u8; 32], base64::URL_SAFE_NO_PAD),
                ),
            ];
            let profile = Profile::LinuxUser;
            let paths = profile.paths();
            ProfileSetup {
                profile,
                paths,
                _temp: temp,
                _guards: guards,
            }
        }
    }

    fn write_base_config(paths: &ProfilePaths) -> PathBuf {
        let config_path = paths.config_path.clone();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(
            &config_path,
            format!(
                "[global]\naddress = \"127.0.0.1\"\nport = 8081\nlog_level = \"normal\"\n\n[global.storage]\ndatadir = \"{}\"\n\n[global.keys]\ntype = \"provider\"\n",
                paths.data_root.display()
            ),
        )
        .unwrap();
        config_path
    }

    fn write_service_manifest(paths: &ProfilePaths, profile: Profile) {
        let manifest = ServiceManifest {
            contract_version: CONTROL_CONTRACT_VERSION.to_string(),
            profile,
            platform: profile.platform(),
            manager: profile.manager(),
            version: APP_VERSION.to_string(),
            config_path: paths.config_path_json(),
            data_path: paths.data_root_json(),
            log_mode: profile.log_mode(),
            key_backend: profile.key_backend(),
        };
        if let Some(parent) = paths.service_manifest_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(
            &paths.service_manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn assert_keys_exact(value: &Value, expected: &[&str]) {
        let actual = value
            .as_object()
            .expect("expected JSON object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected = expected
            .iter()
            .map(|value| value.to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    async fn spawn_server(
        profile: Profile,
        paths: &ProfilePaths,
    ) -> (ControlPlaneServer, ControlPlaneHandle) {
        let base_config_path = write_base_config(paths);
        let figment = runtime::serve_config_figment(&base_config_path).unwrap();
        let mut config = figment.extract::<Config>().unwrap();
        config.storage.resolve();
        let server = spawn_control_plane(&config, base_config_path, profile)
            .await
            .unwrap();
        let handle = server.handle();
        (server, handle)
    }

    async fn wait_for_status(client: &Client, base_url: &str, token: &str) -> Value {
        for _ in 0..50 {
            if let Ok(response) = client
                .get(format!("{base_url}/v1/status"))
                .bearer_auth(token)
                .send()
                .await
            {
                if response.status().is_success() {
                    return response.json::<Value>().await.unwrap();
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("control listener did not become ready");
    }

    async fn json_response(
        client: &Client,
        base_url: &str,
        token: Option<&str>,
        path: &str,
    ) -> (reqwest::StatusCode, Value) {
        let mut request = client.get(format!("{base_url}{path}"));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let json = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
        (status, json)
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn control_files_are_written_and_cleaned_up() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let setup = setup_profile(temp);
        write_service_manifest(&setup.paths, setup.profile);

        let (server, handle) = spawn_server(setup.profile, &setup.paths).await;
        let control_json = setup.paths.control_json_path.clone();
        let control_token = setup.paths.control_token_path.clone();
        assert!(handle.inner.control_addr.ip().is_loopback());
        assert!(control_json.exists());
        assert!(control_token.exists());
        let manifest: service::ControlManifest =
            serde_json::from_str(&fs::read_to_string(&control_json).unwrap()).unwrap();
        assert_eq!(manifest.contract_version, CONTROL_CONTRACT_VERSION);
        assert_eq!(manifest.host, "127.0.0.1");
        assert_eq!(manifest.port, handle.inner.control_addr.port());
        assert_eq!(manifest.pid, Some(std::process::id()));
        assert_eq!(manifest.token_path, control_token.display().to_string());
        let client = Client::builder().build().unwrap();
        let token = fs::read_to_string(&control_token).unwrap();
        let base_url = format!(
            "http://{}:{}",
            handle.inner.control_addr.ip(),
            handle.inner.control_addr.port()
        );
        let _ = wait_for_status(&client, &base_url, token.trim()).await;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&control_token).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        server.shutdown().await.unwrap();
        assert!(!control_json.exists());
        assert!(!control_token.exists());
        drop(handle);
    }

    #[::core::prelude::v1::test]
    fn runtime_access_modes_follow_the_install_profile() {
        assert_eq!(runtime_dir_mode(Profile::MacosUser), 0o700);
        assert_eq!(runtime_dir_mode(Profile::LinuxUser), 0o700);
        assert_eq!(runtime_dir_mode(Profile::LinuxSystem), 0o750);

        assert_eq!(runtime_file_mode(Profile::MacosUser), 0o600);
        assert_eq!(runtime_file_mode(Profile::LinuxUser), 0o600);
        assert_eq!(runtime_file_mode(Profile::LinuxSystem), 0o640);
    }

    #[cfg(unix)]
    #[::core::prelude::v1::test]
    fn runtime_ownership_follows_the_install_profile() {
        assert_eq!(runtime_ownership(Profile::MacosUser).unwrap(), None);
        assert_eq!(runtime_ownership(Profile::LinuxUser).unwrap(), None);

        match systemd_system_group_gid() {
            Some(gid) => assert_eq!(
                runtime_ownership(Profile::LinuxSystem).unwrap(),
                Some((0, gid))
            ),
            None => assert!(runtime_ownership(Profile::LinuxSystem).is_err()),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn patch_overlay_does_not_downgrade_runtime_directory_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();

        let mut permissions = fs::metadata(&runtime_dir).unwrap().permissions();
        permissions.set_mode(0o750);
        fs::set_permissions(&runtime_dir, permissions).unwrap();

        let overlay_path = runtime_dir.join("config.override.toml");
        write_overlay(&overlay_path, &ControlOverlayFile::default())
            .await
            .unwrap();

        assert_eq!(
            fs::metadata(&runtime_dir).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn control_auth_and_endpoints_match_the_contract() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let setup = setup_profile(temp);
        write_service_manifest(&setup.paths, setup.profile);

        let (server, handle) = spawn_server(setup.profile, &setup.paths).await;
        let client = Client::builder().build().unwrap();
        let token = fs::read_to_string(&setup.paths.control_token_path)
            .unwrap()
            .trim()
            .to_string();
        let base_url = format!(
            "http://{}:{}",
            handle.inner.control_addr.ip(),
            handle.inner.control_addr.port()
        );
        assert!(handle.inner.control_addr.ip().is_loopback());
        assert_eq!(
            handle.inner.control_addr,
            std::net::SocketAddr::new(
                std::net::Ipv4Addr::LOCALHOST.into(),
                handle.inner.control_addr.port()
            )
        );
        let unauthorized = client
            .get(format!("{base_url}/v1/status"))
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
        let unauthorized = unauthorized.json::<Value>().await.unwrap();
        assert_keys_exact(&unauthorized, &["contractVersion", "error"]);
        assert_keys_exact(
            unauthorized.get("error").unwrap(),
            &["code", "message", "details"],
        );
        assert_eq!(unauthorized["error"]["code"], "invalid_token");

        let wrong_token = client
            .get(format!("{base_url}/v1/status"))
            .bearer_auth("wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_token.status(), reqwest::StatusCode::UNAUTHORIZED);
        let wrong_token = wrong_token.json::<Value>().await.unwrap();
        assert_eq!(wrong_token["error"]["code"], "invalid_token");

        let unknown_path = client
            .get(format!("{base_url}/v1/does-not-exist"))
            .send()
            .await
            .unwrap();
        assert_eq!(unknown_path.status(), reqwest::StatusCode::UNAUTHORIZED);
        let unknown_path = unknown_path.json::<Value>().await.unwrap();
        assert_eq!(unknown_path["error"]["code"], "invalid_token");

        let (status_code, status_body) =
            json_response(&client, &base_url, None, "/v1/status").await;
        assert_eq!(status_code, reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(status_body["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(status_body["error"]["code"], "invalid_token");

        let (status_code, _) =
            json_response(&client, &base_url, Some("wrong-token"), "/v1/status").await;
        assert_eq!(status_code, reqwest::StatusCode::UNAUTHORIZED);

        let starting = wait_for_status(&client, &base_url, &token).await;
        assert_keys_exact(
            &starting,
            &[
                "contractVersion",
                "state",
                "pid",
                "version",
                "publicApi",
                "configPath",
                "dataPath",
                "logMode",
                "keyBackend",
                "identityReady",
                "nodeDid",
            ],
        );
        assert_eq!(starting["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(starting["state"], "starting");
        assert_eq!(starting["pid"], json!(std::process::id()));
        assert_eq!(starting["version"], APP_VERSION);
        assert_eq!(starting["publicApi"]["address"], "127.0.0.1");
        assert_eq!(starting["publicApi"]["port"], json!(8081));
        assert_eq!(
            starting["configPath"],
            json!(setup.paths.config_path.display().to_string())
        );
        assert_eq!(starting["dataPath"], json!(setup.paths.data_root_json()));
        assert_eq!(
            starting["logMode"],
            serde_json::to_value(setup.profile.log_mode()).unwrap()
        );
        assert_eq!(
            starting["keyBackend"],
            serde_json::to_value(KeyBackend::Static).unwrap()
        );
        assert_eq!(starting["identityReady"], true);
        assert!(starting["nodeDid"].as_str().is_some());

        handle.mark_running();
        let running = wait_for_status(&client, &base_url, &token).await;
        assert_eq!(running["state"], "running");

        let (_, version) = json_response(&client, &base_url, Some(&token), "/v1/version").await;
        assert_keys_exact(
            &version,
            &[
                "contractVersion",
                "appVersion",
                "publicProtocolVersion",
                "identityReady",
                "keyBackend",
                "nodeDid",
            ],
        );
        assert_eq!(version["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(version["appVersion"], APP_VERSION);
        assert_eq!(
            version["publicProtocolVersion"],
            json!(PUBLIC_PROTOCOL_VERSION)
        );
        assert_eq!(version["identityReady"], true);
        assert_eq!(
            version["keyBackend"],
            serde_json::to_value(KeyBackend::Static).unwrap()
        );
        assert!(version["nodeDid"].as_str().is_some());

        let (_, identity) = json_response(&client, &base_url, Some(&token), "/v1/identity").await;
        assert_keys_exact(
            &identity,
            &["contractVersion", "identityReady", "keyBackend", "nodeDid"],
        );
        assert_eq!(identity["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(identity["identityReady"], true);
        assert_eq!(
            identity["keyBackend"],
            serde_json::to_value(KeyBackend::Static).unwrap()
        );
        assert!(identity["nodeDid"].as_str().is_some());
        assert!(identity.get("secret").is_none());

        let (_, config) = json_response(&client, &base_url, Some(&token), "/v1/config").await;
        assert_keys_exact(
            &config,
            &["contractVersion", "baseConfigPath", "overlayPath", "config"],
        );
        assert_eq!(config["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(
            config["baseConfigPath"],
            setup.paths.config_path.display().to_string()
        );
        assert_eq!(
            config["overlayPath"],
            setup.paths.overlay_path.display().to_string()
        );
        assert_keys_exact(
            &config["config"],
            &[
                "log",
                "storage",
                "spaces",
                "hooks",
                "publicApi",
                "telemetry",
                "prometheus",
                "cors",
                "keyProvider",
                "tee",
                "publicSpaces",
            ],
        );
        assert_keys_exact(&config["config"]["log"], &["format", "tracing"]);
        assert_keys_exact(
            &config["config"]["log"]["tracing"],
            &["enabled", "traceHeader"],
        );
        assert_keys_exact(
            &config["config"]["storage"],
            &[
                "dataDir",
                "blocks",
                "staging",
                "database",
                "limitBytes",
                "sql",
                "duckdb",
            ],
        );
        assert_keys_exact(&config["config"]["storage"]["blocks"], &["type", "path"]);
        assert_eq!(config["config"]["storage"]["staging"], "memory");
        assert_keys_exact(
            &config["config"]["storage"]["database"],
            &["backendKind", "path"],
        );
        assert_keys_exact(
            &config["config"]["storage"]["sql"],
            &["path", "memoryThresholdBytes"],
        );
        assert_keys_exact(
            &config["config"]["storage"]["duckdb"],
            &[
                "path",
                "memoryThresholdBytes",
                "idleTimeoutSeconds",
                "maxMemoryPerConnection",
            ],
        );
        assert_keys_exact(&config["config"]["spaces"], &["allowlistUrl"]);
        assert_keys_exact(
            &config["config"]["hooks"],
            &[
                "maxTicketTtlSeconds",
                "maxScopesPerTicket",
                "maxActiveSseStreams",
                "sseBroadcastCapacity",
                "maxWebhookSubscriptionsPerSpace",
                "webhookTimeoutSeconds",
                "webhookMaxAttempts",
            ],
        );
        assert_keys_exact(&config["config"]["publicApi"], &["address", "port"]);
        assert_keys_exact(&config["config"]["telemetry"], &["enabled"]);
        assert_keys_exact(&config["config"]["prometheus"], &["port"]);
        assert_keys_exact(&config["config"]["keyProvider"], &["backend"]);
        assert_keys_exact(&config["config"]["tee"], &["mode", "attestation"]);
        assert_keys_exact(
            &config["config"]["publicSpaces"],
            &["rateLimitPerMinute", "rateLimitBurst", "storageLimitBytes"],
        );
        assert_eq!(config["config"]["publicApi"]["address"], "127.0.0.1");
        assert_eq!(config["config"]["publicApi"]["port"], 8081);
        assert_eq!(
            config["config"]["keyProvider"]["backend"],
            serde_json::to_value(KeyBackend::Static).unwrap()
        );
        assert_eq!(
            config["config"]["log"]["tracing"]["traceHeader"],
            "TinyCloud-Trace-Id"
        );

        LogBuffer::global().push("INFO", "tinycloud::tests", "first log".to_string(), None);
        let (_, tail) =
            json_response(&client, &base_url, Some(&token), "/v1/logs/tail?lines=1").await;
        assert_keys_exact(&tail, &["contractVersion", "source", "cursor", "entries"]);
        assert_eq!(tail["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(
            tail["source"],
            serde_json::to_value(setup.profile.log_mode()).unwrap()
        );
        assert_eq!(tail["entries"].as_array().unwrap().len(), 1);
        assert_keys_exact(
            tail["entries"].as_array().unwrap().first().unwrap(),
            &["timestamp", "level", "target", "message"],
        );
        assert_eq!(tail["entries"][0]["message"], "first log");
        let cursor = tail["cursor"].as_str().unwrap().to_string();
        LogBuffer::global().push("INFO", "tinycloud::tests", "second log".to_string(), None);
        let (_, tail_next) = json_response(
            &client,
            &base_url,
            Some(&token),
            &format!("/v1/logs/tail?lines=2000&cursor={cursor}"),
        )
        .await;
        assert_eq!(
            tail_next["source"],
            serde_json::to_value(setup.profile.log_mode()).unwrap()
        );
        assert_keys_exact(
            &tail_next,
            &["contractVersion", "source", "cursor", "entries"],
        );
        assert!(tail_next["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["message"] == "second log"));
        assert!(!tail_next["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["message"] == "first log"));

        let (_, invalid_cursor) = json_response(
            &client,
            &base_url,
            Some(&token),
            "/v1/logs/tail?lines=1&cursor=not-a-cursor",
        )
        .await;
        assert_eq!(invalid_cursor["entries"].as_array().unwrap().len(), 1);
        assert_eq!(invalid_cursor["entries"][0]["message"], "second log");

        handle.mark_stopping();
        let stopping = wait_for_status(&client, &base_url, &token).await;
        assert_eq!(stopping["state"], "stopping");

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn control_config_patch_whitelist_and_cli_paths_work_live() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let setup = setup_profile(temp);
        write_service_manifest(&setup.paths, setup.profile);

        #[cfg(target_os = "macos")]
        let _cors = EnvGuard::set("TINYCLOUD_CORS", "true");
        #[cfg(target_os = "linux")]
        let _cors = EnvGuard::set("TINYCLOUD_CORS", "true");

        let (server, handle) = spawn_server(setup.profile, &setup.paths).await;
        handle.mark_running();
        let client = Client::builder().build().unwrap();
        let token = fs::read_to_string(&setup.paths.control_token_path)
            .unwrap()
            .trim()
            .to_string();
        let base_url = format!(
            "http://{}:{}",
            handle.inner.control_addr.ip(),
            handle.inner.control_addr.port()
        );
        let _ = wait_for_status(&client, &base_url, &token).await;

        let patch = json!({
            "cors": false,
            "storage": { "limitBytes": 20971520 },
            "publicSpaces": { "rateLimitPerMinute": 77 }
        });
        let response = client
            .patch(format!("{base_url}/v1/config"))
            .bearer_auth(&token)
            .json(&patch)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let patch_response = response.json::<Value>().await.unwrap();
        assert_keys_exact(
            &patch_response,
            &[
                "contractVersion",
                "baseConfigPath",
                "overlayPath",
                "restartRequired",
                "appliedPaths",
                "config",
            ],
        );
        assert_eq!(patch_response["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(patch_response["restartRequired"], true);
        assert!(patch_response["appliedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "storage.limitBytes"));
        assert!(patch_response["appliedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "publicSpaces.rateLimitPerMinute"));
        assert!(!patch_response["appliedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "cors"));
        assert_eq!(patch_response["config"]["cors"], true);
        assert_eq!(
            patch_response["config"]["storage"]["limitBytes"],
            json!(20971520)
        );
        assert_eq!(
            patch_response["config"]["publicSpaces"]["rateLimitPerMinute"],
            json!(77)
        );

        let overlay = fs::read_to_string(&setup.paths.overlay_path).unwrap();
        assert!(overlay.contains("cors = false"));
        assert!(overlay.contains("limit = 20971520"));
        assert!(overlay.contains("rate_limit_per_minute = 77"));

        let clear_limit = client
            .patch(format!("{base_url}/v1/config"))
            .bearer_auth(&token)
            .json(&json!({
                "storage": { "limitBytes": null }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(clear_limit.status(), reqwest::StatusCode::OK);
        let clear_limit = clear_limit.json::<Value>().await.unwrap();
        assert_keys_exact(
            &clear_limit,
            &[
                "contractVersion",
                "baseConfigPath",
                "overlayPath",
                "restartRequired",
                "appliedPaths",
                "config",
            ],
        );
        assert!(clear_limit["appliedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "storage.limitBytes"));
        assert_eq!(clear_limit["restartRequired"], true);
        assert!(clear_limit["config"]["storage"]["limitBytes"].is_null());

        let zero_limit = client
            .patch(format!("{base_url}/v1/config"))
            .bearer_auth(&token)
            .json(&json!({
                "storage": { "limitBytes": 0 }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(zero_limit.status(), reqwest::StatusCode::BAD_REQUEST);
        let zero_limit_body = zero_limit.json::<Value>().await.unwrap();
        assert_keys_exact(&zero_limit_body, &["contractVersion", "error"]);
        assert_eq!(zero_limit_body["error"]["code"], "invalid_request");
        assert_eq!(
            zero_limit_body["error"]["details"]["field"],
            "storage.limitBytes"
        );

        let invalid = client
            .patch(format!("{base_url}/v1/config"))
            .bearer_auth(&token)
            .json(&json!({
                "publicApi": { "port": 9090 }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(invalid.status(), reqwest::StatusCode::BAD_REQUEST);
        let invalid_body = invalid.json::<Value>().await.unwrap();
        assert_keys_exact(&invalid_body, &["contractVersion", "error"]);
        assert_keys_exact(
            invalid_body.get("error").unwrap(),
            &["code", "message", "details"],
        );
        assert_eq!(invalid_body["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(invalid_body["error"]["code"], "invalid_request");
        assert_eq!(
            invalid_body["error"]["details"]["field"],
            "request body.publicApi"
        );

        let service_status = tokio::task::spawn_blocking(service::service_status)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(service_status.contract_version, CONTROL_CONTRACT_VERSION);
        assert_eq!(service_status.state, ServiceState::Running);
        assert!(service_status.identity_ready);
        assert!(service_status.node_did.is_some());
        assert_eq!(service_status.control_api, None);
        assert_eq!(service_status.version, Some(APP_VERSION.to_string()));

        let node_status = tokio::task::spawn_blocking(service::node_status)
            .await
            .unwrap()
            .unwrap();
        assert_keys_exact(
            &node_status,
            &[
                "contractVersion",
                "state",
                "pid",
                "version",
                "publicApi",
                "configPath",
                "dataPath",
                "logMode",
                "keyBackend",
                "identityReady",
                "nodeDid",
            ],
        );
        assert_eq!(node_status["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(node_status["state"], "running");
        assert!(node_status["nodeDid"].as_str().is_some());

        let node_identity = tokio::task::spawn_blocking(service::node_key_export_body)
            .await
            .unwrap()
            .unwrap();
        let node_identity: Value = serde_json::from_str(&node_identity).unwrap();
        assert_keys_exact(
            &node_identity,
            &["contractVersion", "identityReady", "keyBackend", "nodeDid"],
        );
        assert_eq!(node_identity["contractVersion"], CONTROL_CONTRACT_VERSION);
        assert_eq!(node_identity["identityReady"], true);
        assert!(node_identity["nodeDid"].as_str().is_some());

        let doctor = tokio::task::spawn_blocking(service::node_doctor)
            .await
            .unwrap()
            .unwrap();
        assert!(doctor.ok);
        assert!(doctor.checks.iter().any(
            |check| check.name == "control" && matches!(check.status, DoctorCheckStatus::Pass)
        ));
        assert!(doctor.checks.iter().any(
            |check| check.name == "identity" && matches!(check.status, DoctorCheckStatus::Pass)
        ));
        assert!(
            doctor
                .checks
                .iter()
                .any(|check| check.name == "config"
                    && matches!(check.status, DoctorCheckStatus::Pass))
        );

        server.shutdown().await.unwrap();
    }
}
