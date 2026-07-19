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
use std::{fs, path::PathBuf};
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
    /// The only browser origin allowed to call the node's share-email API.
    /// This is deliberately a list so the deployed value is visible in the
    /// configuration and cannot accidentally become a wildcard.
    #[serde(default = "default_share_allowed_origins")]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_share_node_signing_kid")]
    pub node_signing_kid: String,
    #[serde(default = "default_share_invitation_kid")]
    pub invitation_kid: String,
    #[serde(default)]
    pub invitation_public_key: Option<String>,
    #[serde(default = "default_share_issuer_did")]
    pub issuer_did: String,
    #[serde(default = "default_share_issuer_vct")]
    pub issuer_vct: String,
    #[serde(default = "default_share_issuer_kid")]
    pub issuer_kid: String,
    #[serde(default = "default_share_issuer_key_version")]
    pub issuer_key_version: u64,
    #[serde(default)]
    pub issuer_public_key: Option<String>,
    /// Operator-delivered owner-signed authority material. A missing or
    /// unreadable source keeps the capability unavailable.
    #[serde(default)]
    pub authority_material_path: Option<String>,
    #[serde(default)]
    pub postgres_tls: ShareEmailPostgresTlsConfig,
    #[serde(default = "default_share_readiness_max_age")]
    pub readiness_max_age_seconds: u64,
    #[serde(default = "default_share_clock_skew")]
    pub clock_skew_seconds: i64,
    #[serde(default = "default_share_challenge_ttl")]
    pub challenge_ttl_seconds: u64,
    #[serde(default = "default_share_space_name")]
    pub space_name: String,
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
fn default_share_allowed_origins() -> Vec<String> {
    vec![default_share_return_origin()]
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
fn default_share_issuer_vct() -> String {
    tinycloud_auth::share_email_evidence::EMAIL_VCT.to_owned()
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
fn default_share_readiness_max_age() -> u64 {
    300
}

/// PostgreSQL TLS settings used by the enabled share-email runtime.  The
/// default is intentionally disabled so existing SQLite development nodes do
/// not change behavior; a PostgreSQL-backed enabled deployment must set the
/// exact `verify-full` mode and a CA bundle path.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ShareEmailPostgresTlsConfig {
    #[serde(default = "default_share_postgres_sslmode")]
    pub sslmode: String,
    #[serde(default)]
    pub root_cert_path: Option<String>,
}

fn default_share_postgres_sslmode() -> String {
    "disabled".to_owned()
}

impl Default for ShareEmailPostgresTlsConfig {
    fn default() -> Self {
        Self {
            sslmode: default_share_postgres_sslmode(),
            root_cert_path: None,
        }
    }
}

impl Default for ShareEmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_origin: default_share_target_origin(),
            node_audience: default_share_node_audience(),
            return_origin: default_share_return_origin(),
            allowed_origins: default_share_allowed_origins(),
            node_signing_kid: default_share_node_signing_kid(),
            invitation_kid: default_share_invitation_kid(),
            invitation_public_key: None,
            issuer_did: default_share_issuer_did(),
            issuer_vct: default_share_issuer_vct(),
            issuer_kid: default_share_issuer_kid(),
            issuer_key_version: default_share_issuer_key_version(),
            issuer_public_key: None,
            authority_material_path: None,
            postgres_tls: ShareEmailPostgresTlsConfig::default(),
            readiness_max_age_seconds: default_share_readiness_max_age(),
            clock_skew_seconds: default_share_clock_skew(),
            challenge_ttl_seconds: default_share_challenge_ttl(),
            space_name: default_share_space_name(),
        }
    }
}

impl ShareEmailConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.enabled {
            return Ok(());
        }
        if tinycloud_core::share_email::TargetOrigin::parse(self.target_origin.clone()).is_err()
            || tinycloud_core::share_email::TargetOrigin::parse(self.return_origin.clone()).is_err()
            || self.allowed_origins.len() != 1
            || self.allowed_origins.first() != Some(&self.return_origin)
            || self.allowed_origins.iter().any(|origin| {
                origin == "*"
                    || tinycloud_core::share_email::TargetOrigin::parse(origin.clone()).is_err()
            })
            || tinycloud_core::share_email::Did::parse(self.node_audience.clone()).is_err()
            || self.node_signing_kid != self.invitation_kid
            || !self
                .node_signing_kid
                .starts_with(&format!("{}#", self.node_audience))
            || self.issuer_did.is_empty()
            || self.issuer_did != tinycloud_auth::share_email_evidence::OPEN_CREDENTIALS_ISSUER_DID
            || self.issuer_vct != tinycloud_auth::share_email_evidence::EMAIL_VCT
            || !self
                .issuer_kid
                .split_once('#')
                .is_some_and(|(did, fragment)| did == self.issuer_did && !fragment.is_empty())
            || self.issuer_key_version == 0
            || self.clock_skew_seconds < 0
            || self.clock_skew_seconds > 300
            || self.challenge_ttl_seconds == 0
            || self.challenge_ttl_seconds > 120
            || self.invitation_public_key.is_none()
            || self.issuer_public_key.is_none()
            || self.authority_material_path.is_none()
            || self
                .authority_material_path
                .as_deref()
                .is_some_and(|path| path.trim().is_empty())
            || self.readiness_max_age_seconds == 0
            || self.readiness_max_age_seconds > 300
        {
            return Err("share email configuration is incomplete");
        }
        Ok(())
    }

    /// Validate settings that depend on the resolved node database.  This is
    /// called before any connection is opened, so an enabled PostgreSQL
    /// deployment cannot accidentally start with an unauthenticated TLS mode
    /// or a missing CA bundle.
    pub fn validate_for_database(&self, database: &str) -> Result<(), &'static str> {
        self.validate()?;
        if !self.enabled {
            return Ok(());
        }
        if is_postgres_database(database) {
            if self.postgres_tls.sslmode != "verify-full"
                || !database_has_query(database, "sslmode", "verify-full")
                || database_has_forbidden_query(database)
                || self.postgres_tls.root_cert_path.is_none()
            {
                return Err("share email PostgreSQL requires sslmode=verify-full and a CA bundle");
            }
            let root_cert = self
                .postgres_tls
                .root_cert_path
                .as_deref()
                .unwrap_or_default();
            if root_cert.trim().is_empty()
                || !fs::metadata(root_cert)
                    .map(|metadata| metadata.is_file())
                    .unwrap_or(false)
            {
                return Err("share email PostgreSQL CA bundle is missing");
            }
        } else if self.postgres_tls.sslmode != "disabled"
            || self.postgres_tls.root_cert_path.is_some()
        {
            return Err("share email PostgreSQL TLS settings require a PostgreSQL database");
        }
        Ok(())
    }
}

fn is_postgres_database(database: &str) -> bool {
    database.starts_with("postgres://") || database.starts_with("postgresql://")
}

fn database_has_query(database: &str, expected_key: &str, expected_value: &str) -> bool {
    let Some((_, query)) = database.split_once('?') else {
        return false;
    };
    let mut found = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == expected_key {
            if found.is_some() {
                return false;
            }
            found = Some(value);
        }
    }
    found == Some(expected_value)
}

fn database_has_forbidden_query(database: &str) -> bool {
    const FORBIDDEN: [&str; 6] = [
        "sslrootcert",
        "sslcert",
        "sslkey",
        "sslpassword",
        "sslcrl",
        "hostaddr",
    ];
    database.split_once('?').is_some_and(|(_, query)| {
        query.split('&').any(|pair| {
            pair.split_once('=')
                .is_some_and(|(key, _)| FORBIDDEN.contains(&key))
        })
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> ShareEmailConfig {
        ShareEmailConfig {
            enabled: true,
            invitation_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            issuer_public_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
            authority_material_path: Some("/run/tinycloud/authority-material.json".into()),
            ..ShareEmailConfig::default()
        }
    }

    #[tokio::test]
    async fn enabled_share_email_requires_complete_trust_material() {
        let config = ShareEmailConfig {
            enabled: true,
            ..ShareEmailConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err("share email configuration is incomplete")
        );
    }

    #[tokio::test]
    async fn wildcard_or_extra_browser_origins_are_rejected() {
        let mut config = enabled_config();
        config.allowed_origins = vec!["*".into()];
        assert!(config.validate().is_err());

        config.allowed_origins = vec![config.return_origin.clone(), "https://evil.example".into()];
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn issuer_vct_is_pinned_to_the_frozen_opencredentials_profile() {
        let mut config = enabled_config();
        config.issuer_vct = "opencredentials.email/test".into();
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn postgres_requires_verify_full_and_an_existing_ca_bundle() {
        let config = enabled_config();
        assert!(config
            .validate_for_database("postgres://user:password@db.example/share")
            .is_err());

        let mut config = enabled_config();
        config.postgres_tls.sslmode = "require".into();
        config.postgres_tls.root_cert_path = Some("/tmp/does-not-exist.pem".into());
        assert!(config
            .validate_for_database("postgres://user:password@db.example/share?sslmode=verify-full")
            .is_err());
    }

    #[tokio::test]
    async fn postgres_tls_validation_accepts_only_the_configured_ca_bundle() {
        let file = tempfile::NamedTempFile::new().expect("temporary CA bundle");
        let mut config = enabled_config();
        config.postgres_tls.sslmode = "verify-full".into();
        config.postgres_tls.root_cert_path = Some(file.path().display().to_string());

        assert!(config
            .validate_for_database(
                "postgresql://user:password@db.example/share?sslmode=verify-full"
            )
            .is_ok());
        assert!(config
            .validate_for_database(
                "postgresql://user:password@db.example/share?sslmode=verify-full&sslmode=require"
            )
            .is_err());
        assert!(config
            .validate_for_database(
                "postgresql://user:password@db.example/share?sslmode=verify-full&sslrootcert=/tmp/other.pem"
            )
            .is_err());
    }

    #[tokio::test]
    async fn sqlite_fixture_does_not_accept_postgres_tls_overrides() {
        let mut config = enabled_config();
        config.postgres_tls.sslmode = "verify-full".into();
        assert!(config
            .validate_for_database("sqlite:/tmp/tinycloud-share-email.db")
            .is_err());
    }
}
