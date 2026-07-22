use crate::{
    allow_list::SpaceAllowListService,
    storage::{file_system::FileSystemConfig, s3::S3BlockConfig},
    BlockConfig, BlockStage,
};
use rocket::data::ByteUnit;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, FromInto,
};
use std::path::PathBuf;
use tinycloud_core::keys::StaticSecret;

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Config {
    pub log: Logging,
    pub storage: Storage,
    pub spaces: SpacesConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default)]
    pub tc_bench: TcBenchConfig,
    pub relay: Relay,
    #[serde(default)]
    pub telemetry: Telemetry,
    pub prometheus: Prometheus,
    pub cors: bool,
    #[serde(default)]
    pub keys: Keys,
    #[serde(default)]
    pub tee: TeeConfig,
    #[serde(default)]
    pub public_spaces: PublicSpacesConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicSpacesConfig {
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    #[serde(default = "default_public_storage_limit")]
    pub storage_limit: ByteUnit,
}

fn default_rate_limit_per_minute() -> u32 {
    60
}

fn default_rate_limit_burst() -> u32 {
    10
}

fn default_public_storage_limit() -> ByteUnit {
    ByteUnit::Mebibyte(10)
}

impl Default for PublicSpacesConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: default_rate_limit_per_minute(),
            rate_limit_burst: default_rate_limit_burst(),
            storage_limit: default_public_storage_limit(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct TcBenchConfig {
    #[serde(default = "default_tc_bench_region")]
    pub region: String,
    #[serde(default)]
    pub worker_bundle_sha256: Option<String>,
    #[serde(default)]
    pub wasm_bundle_sha256: Option<String>,
}

fn default_tc_bench_region() -> String {
    "phala-cvm".to_string()
}

impl Default for TcBenchConfig {
    fn default() -> Self {
        Self {
            region: default_tc_bench_region(),
            worker_bundle_sha256: None,
            wasm_bundle_sha256: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct HooksConfig {
    #[serde(default = "default_hooks_max_ticket_ttl_seconds")]
    pub max_ticket_ttl_seconds: u64,
    #[serde(default = "default_hooks_max_scopes_per_ticket")]
    pub max_scopes_per_ticket: usize,
    #[serde(default = "default_hooks_max_active_sse_streams")]
    pub max_active_sse_streams: usize,
    #[serde(default = "default_hooks_sse_broadcast_capacity")]
    pub sse_broadcast_capacity: usize,
    #[serde(default = "default_hooks_max_webhook_subscriptions_per_space")]
    pub max_webhook_subscriptions_per_space: usize,
    #[serde(default = "default_hooks_webhook_timeout_seconds")]
    pub webhook_timeout_seconds: u64,
    #[serde(default = "default_hooks_webhook_max_attempts")]
    pub webhook_max_attempts: usize,
}

fn default_hooks_max_ticket_ttl_seconds() -> u64 {
    300
}

fn default_hooks_max_scopes_per_ticket() -> usize {
    32
}

fn default_hooks_max_active_sse_streams() -> usize {
    100
}

fn default_hooks_sse_broadcast_capacity() -> usize {
    1024
}

fn default_hooks_max_webhook_subscriptions_per_space() -> usize {
    5
}

fn default_hooks_webhook_timeout_seconds() -> u64 {
    10
}

fn default_hooks_webhook_max_attempts() -> usize {
    5
}

impl Default for HooksConfig {
    fn default() -> Self {
        Self {
            max_ticket_ttl_seconds: default_hooks_max_ticket_ttl_seconds(),
            max_scopes_per_ticket: default_hooks_max_scopes_per_ticket(),
            max_active_sse_streams: default_hooks_max_active_sse_streams(),
            sse_broadcast_capacity: default_hooks_sse_broadcast_capacity(),
            max_webhook_subscriptions_per_space: default_hooks_max_webhook_subscriptions_per_space(
            ),
            webhook_timeout_seconds: default_hooks_webhook_timeout_seconds(),
            webhook_max_attempts: default_hooks_webhook_max_attempts(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
#[serde(tag = "type")]
pub enum Keys {
    #[serde(rename = "static", alias = "Static")]
    Static(Static),
    #[cfg(feature = "dstack")]
    #[serde(rename = "dstack", alias = "Dstack")]
    Dstack,
    #[default]
    #[serde(rename = "auto", alias = "Auto")]
    Auto,
    #[serde(rename = "provider", alias = "Provider")]
    Provider,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct TeeConfig {
    #[serde(default = "default_tee_mode")]
    pub mode: TeeMode,
    #[serde(default)]
    pub attestation: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum TeeMode {
    #[default]
    Auto,
    Dstack,
    Off,
}

fn default_tee_mode() -> TeeMode {
    TeeMode::Auto
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: TeeMode::Auto,
            attestation: false,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct Static {
    #[serde_as(as = "Option<Base64<UrlSafe, Unpadded>>")]
    secret: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretInitError {
    #[error("Secret required to be at least 32 bytes, but was {0}")]
    NotEnoughEntropy(usize),
    #[error("Missing secret")]
    MissingSecret,
}

impl TryFrom<Static> for StaticSecret {
    type Error = SecretInitError;
    fn try_from(s: Static) -> Result<Self, Self::Error> {
        let secret = s.secret.ok_or(SecretInitError::MissingSecret)?;
        StaticSecret::new(secret).map_err(|v| SecretInitError::NotEnoughEntropy(v.len()))
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Logging {
    pub format: LoggingFormat,
    pub tracing: Tracing,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub enum LoggingFormat {
    #[default]
    Text,
    Json,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Tracing {
    pub traceheader: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct SpacesConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<SpaceAllowListService>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct SqlStorageConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_sql_memory_threshold")]
    pub memory_threshold: ByteUnit,
}

fn default_sql_memory_threshold() -> ByteUnit {
    ByteUnit::Mebibyte(10)
}

impl Default for SqlStorageConfig {
    fn default() -> Self {
        Self {
            path: None,
            memory_threshold: default_sql_memory_threshold(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct DuckDbStorageConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_duckdb_memory_threshold")]
    pub memory_threshold: ByteUnit,
    #[serde(default = "default_duckdb_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_duckdb_max_memory")]
    pub max_memory_per_connection: String,
}

fn default_duckdb_memory_threshold() -> ByteUnit {
    ByteUnit::Mebibyte(10)
}

fn default_duckdb_idle_timeout() -> u64 {
    300
}

fn default_duckdb_max_memory() -> String {
    "128MB".to_string()
}

impl Default for DuckDbStorageConfig {
    fn default() -> Self {
        Self {
            path: None,
            memory_threshold: default_duckdb_memory_threshold(),
            idle_timeout_secs: default_duckdb_idle_timeout(),
            max_memory_per_connection: default_duckdb_max_memory(),
        }
    }
}

// P2 (compute-service.md §11.4, §10.1): numeric ceilings for the wasmtime
// backend's caveat enforcement. `default_*` are the fallback applied when a
// `D_fn`/invocation carries no explicit `ComputeCaveats` value;
// `*_ceiling_*` are hard, config-capped maximums a caveat can never exceed
// (§10.1 "numeric caveats are validated against sane ceilings on ingest").
// Present unconditionally (not `#[cfg(feature = "compute")]`) so a
// `[storage.compute]` TOML block always parses, mirroring the existing
// `sql`/`duckdb` sections that are not feature-gated either.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ComputeStorageConfig {
    #[serde(default = "default_compute_max_duration_ms")]
    pub default_max_duration_ms: u64,
    #[serde(default = "default_compute_max_duration_ceiling_ms")]
    pub max_duration_ceiling_ms: u64,
    #[serde(default = "default_compute_max_memory")]
    pub default_max_memory: ByteUnit,
    #[serde(default = "default_compute_max_memory_ceiling")]
    pub max_memory_ceiling: ByteUnit,
    /// §10.1 CPU→fuel: the wasmtime fuel budget granted to each execution.
    /// `ComputeCaveats` has no CPU field, so this is a node-level ceiling
    /// (belt-and-braces with `maxDuration`→epoch). Large default; lower it
    /// in tests to exercise the fuel-exhaustion trap.
    #[serde(default = "default_compute_max_fuel")]
    pub max_fuel: u64,
    /// §9.1.1: also persist the execution manifest to a KV audit path under
    /// the routine's own `D_fn` grant. The in-outcome manifest is always
    /// returned regardless of this setting.
    #[serde(default)]
    pub persist_manifest: bool,
    /// Memory-safety ceiling (Codex P2 finding): the maximum byte length the
    /// executor will trust for ANY guest-controlled length crossing the ABI
    /// boundary -- a host-import request and the `run()` result length. A
    /// hard NODE invariant, not caveat-tunable: a guest that claims a length
    /// beyond it is rejected BEFORE the host allocates a buffer sized by
    /// that untrusted value, so a bogus negative/huge length can never
    /// trigger an out-of-control host allocation.
    #[serde(default = "default_compute_max_abi_message_bytes")]
    pub max_abi_message_bytes: u64,
}

fn default_compute_max_duration_ms() -> u64 {
    5_000
}

fn default_compute_max_duration_ceiling_ms() -> u64 {
    60_000
}

fn default_compute_max_memory() -> ByteUnit {
    ByteUnit::Mebibyte(128)
}

fn default_compute_max_memory_ceiling() -> ByteUnit {
    ByteUnit::Mebibyte(512)
}

fn default_compute_max_fuel() -> u64 {
    1_000_000_000
}

fn default_compute_max_abi_message_bytes() -> u64 {
    8 * 1024 * 1024 // 8 MiB
}

impl Default for ComputeStorageConfig {
    fn default() -> Self {
        Self {
            default_max_duration_ms: default_compute_max_duration_ms(),
            max_duration_ceiling_ms: default_compute_max_duration_ceiling_ms(),
            default_max_memory: default_compute_max_memory(),
            max_memory_ceiling: default_compute_max_memory_ceiling(),
            max_fuel: default_compute_max_fuel(),
            persist_manifest: false,
            max_abi_message_bytes: default_compute_max_abi_message_bytes(),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Storage {
    /// Root directory for all local data (database, blocks, sql, duckdb).
    /// Individual paths can still be overridden explicitly.
    #[serde(default = "default_datadir")]
    pub datadir: PathBuf,
    #[serde_as(as = "FromInto<BlockStorage>")]
    #[serde(default = "fs_store")]
    pub blocks: BlockConfig,
    #[serde_as(as = "FromInto<StagingStorage>")]
    #[serde(default = "memory_stage")]
    pub staging: BlockStage,
    #[serde(default)]
    pub database: Option<String>,
    pub limit: Option<ByteUnit>,
    #[serde(default)]
    pub sql: SqlStorageConfig,
    #[serde(default)]
    pub duckdb: DuckDbStorageConfig,
    #[serde(default)]
    pub compute: ComputeStorageConfig,
}

fn default_datadir() -> PathBuf {
    PathBuf::from("./data")
}

impl Storage {
    /// Resolve all unset paths relative to `datadir`.
    /// Call this after config extraction so that overrides from
    /// tinycloud.toml or TINYCLOUD_ env vars take precedence.
    pub fn resolve(&mut self) {
        let dir = &self.datadir;

        if self.database.is_none() {
            self.database = Some(format!("sqlite:{}", dir.join("caps.db").display()));
        }

        if self.sql.path.is_none() {
            self.sql.path = Some(dir.join("sql").to_string_lossy().into_owned());
        }

        if self.duckdb.path.is_none() {
            self.duckdb.path = Some(dir.join("duckdb").to_string_lossy().into_owned());
        }

        // Resolve blocks path if it's the Local variant with the empty default
        if let BlockConfig::B(ref fs) = self.blocks {
            if fs.path().as_os_str().is_empty() {
                self.blocks = BlockConfig::B(FileSystemConfig::new(dir.join("blocks")));
            }
        }

        if self.limit.map(|limit| limit.as_u64()) == Some(0) {
            self.limit = None;
        }
    }

    /// Get the database connection string. Panics if called before resolve().
    pub fn database(&self) -> &str {
        self.database
            .as_deref()
            .expect("Storage::resolve() must be called before accessing database")
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            datadir: default_datadir(),
            blocks: BlockStorage::default().into(),
            staging: StagingStorage::default().into(),
            database: None,
            limit: None,
            sql: SqlStorageConfig::default(),
            duckdb: DuckDbStorageConfig::default(),
            compute: ComputeStorageConfig::default(),
        }
    }
}

fn memory_stage() -> BlockStage {
    StagingStorage::Memory.into()
}

fn fs_store() -> BlockConfig {
    BlockStorage::default().into()
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum BlockStorage {
    Local(FileSystemConfig),
    S3(S3BlockConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum StagingStorage {
    FileSystem,
    #[default]
    Memory,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Relay {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct Telemetry {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Prometheus {
    pub port: u16,
}

impl Default for Tracing {
    fn default() -> Tracing {
        Tracing {
            enabled: false,
            traceheader: "TinyCloud-Trace-Id".to_string(),
        }
    }
}

impl Default for BlockStorage {
    fn default() -> BlockStorage {
        BlockStorage::Local(FileSystemConfig::default())
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".into(),
            port: 8081,
        }
    }
}

impl Default for Prometheus {
    fn default() -> Self {
        Self { port: 8001 }
    }
}
