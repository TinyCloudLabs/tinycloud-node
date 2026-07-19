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
    pub relay: Relay,
    #[serde(default)]
    pub telemetry: Telemetry,
    pub prometheus: Prometheus,
    pub cors: bool,
    pub keys: Keys,
    #[serde(default)]
    pub tee: TeeConfig,
    #[serde(default)]
    pub public_spaces: PublicSpacesConfig,
    #[serde(default)]
    pub share_email: ShareEmailConfig,
}

/// Production exact-email composition.  The capability remains unavailable
/// until every trust/key/dependency field is configured; there are no fake
/// adapters or development credentials in this configuration surface.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ShareEmailConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_share_target_origin")]
    pub target_origin: String,
    #[serde(default = "default_share_node_audience")]
    pub node_audience: String,
    #[serde(default = "default_share_return_origin")]
    pub return_origin: String,
    #[serde(default = "default_share_node_signing_kid")]
    pub node_signing_kid: String,
    #[serde(default = "default_share_invitation_kid")]
    pub invitation_kid: String,
    #[serde(default)]
    pub invitation_public_key: Option<String>,
    #[serde(default = "default_share_issuer_did")]
    pub issuer_did: String,
    #[serde(default = "default_share_issuer_kid")]
    pub issuer_kid: String,
    #[serde(default = "default_share_issuer_key_version")]
    pub issuer_key_version: u64,
    #[serde(default)]
    pub issuer_public_key: Option<String>,
    #[serde(default)]
    pub expected_email: String,
    #[serde(default = "default_share_clock_skew")]
    pub clock_skew_seconds: i64,
    #[serde(default = "default_share_challenge_ttl")]
    pub challenge_ttl_seconds: u64,
    #[serde(default = "default_share_space_name")]
    pub space_name: String,
    #[serde(default)]
    pub named_sql: Option<ShareEmailNamedSqlConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ShareEmailNamedSqlConfig {
    pub database: String,
    pub path: String,
    pub statement: String,
    pub sql: String,
}

fn default_share_target_origin() -> String {
    "https://node.example".to_owned()
}
fn default_share_node_audience() -> String {
    "did:web:node.example".to_owned()
}
fn default_share_return_origin() -> String {
    "https://share.tinycloud.xyz".to_owned()
}
fn default_share_node_signing_kid() -> String {
    "did:web:node.example#invitation-key-1".to_owned()
}
fn default_share_invitation_kid() -> String {
    "did:web:node.example#invitation-key-1".to_owned()
}
fn default_share_issuer_did() -> String {
    "did:web:issuer.credentials.org".to_owned()
}
fn default_share_issuer_kid() -> String {
    "did:web:issuer.credentials.org#email-signing-key-1".to_owned()
}
fn default_share_issuer_key_version() -> u64 {
    1
}
fn default_share_clock_skew() -> i64 {
    30
}
fn default_share_challenge_ttl() -> u64 {
    120
}
fn default_share_space_name() -> String {
    "default".to_owned()
}

impl Default for ShareEmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_origin: default_share_target_origin(),
            node_audience: default_share_node_audience(),
            return_origin: default_share_return_origin(),
            node_signing_kid: default_share_node_signing_kid(),
            invitation_kid: default_share_invitation_kid(),
            invitation_public_key: None,
            issuer_did: default_share_issuer_did(),
            issuer_kid: default_share_issuer_kid(),
            issuer_key_version: default_share_issuer_key_version(),
            issuer_public_key: None,
            expected_email: String::new(),
            clock_skew_seconds: default_share_clock_skew(),
            challenge_ttl_seconds: default_share_challenge_ttl(),
            space_name: default_share_space_name(),
            named_sql: None,
        }
    }
}

impl ShareEmailConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.enabled {
            return Ok(());
        }
        if self.target_origin != "https://node.example"
            || self.node_audience != "did:web:node.example"
            || self.return_origin != "https://share.tinycloud.xyz"
            || self.node_signing_kid != self.invitation_kid
            || self.issuer_did != "did:web:issuer.credentials.org"
            || self.issuer_kid != "did:web:issuer.credentials.org#email-signing-key-1"
            || self.expected_email.is_empty()
            || self.issuer_key_version == 0
            || self.clock_skew_seconds < 0
            || self.clock_skew_seconds > 300
            || self.challenge_ttl_seconds == 0
            || self.challenge_ttl_seconds > 120
            || self.invitation_public_key.is_none()
            || self.issuer_public_key.is_none()
            || self.named_sql.is_none()
        {
            return Err("share email configuration is incomplete");
        }
        Ok(())
    }

    pub fn pinned_statement(
        &self,
    ) -> anyhow::Result<tinycloud_core::share_email::data_plane::PinnedNamedStatement> {
        let sql = self
            .named_sql
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("named SQL configuration is required"))?;
        let database = tinycloud_core::share_email::DatabaseName::parse(sql.database.clone())
            .map_err(|_| anyhow::anyhow!("invalid named SQL database"))?;
        let path = tinycloud_core::share_email::Path::parse(sql.path.clone())
            .map_err(|_| anyhow::anyhow!("invalid named SQL path"))?;
        let _statement = tinycloud_core::share_email::NamedStatement::parse(sql.statement.clone())
            .map_err(|_| anyhow::anyhow!("invalid named SQL statement"))?;
        Ok(
            tinycloud_core::share_email::data_plane::PinnedNamedStatement {
                database,
                path,
                statement: tinycloud_core::policy_capability::sql_caveat::ConstrainedStatement {
                    name: sql.statement.clone(),
                    sql: sql.sql.clone(),
                    fixed_params: Vec::new(),
                },
            },
        )
    }
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
    Static(Static),
    #[cfg(feature = "dstack")]
    Dstack,
    #[default]
    Auto,
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
