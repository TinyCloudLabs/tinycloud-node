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
    pub relay: Relay,
    pub prometheus: Prometheus,
    pub cors: bool,
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
    pub limit: Option<ByteUnit>,
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
            limit: None,
            memory_threshold: default_sql_memory_threshold(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct DuckDbStorageConfig {
    #[serde(default)]
    pub path: Option<String>,
    pub limit: Option<ByteUnit>,
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
            limit: None,
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
