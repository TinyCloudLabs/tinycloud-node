#[macro_use]
extern crate rocket;
extern crate anyhow;
#[cfg(test)]
#[macro_use]
extern crate tokio;

use anyhow::{Context, Result};
use rocket::{fairing::AdHoc, figment::Figment, http::Header, Build, Rocket};
use std::path::Path;

pub mod allow_list;
pub mod auth_guards;
pub mod authorization;
pub mod config;
#[cfg(feature = "dstack")]
pub mod dstack;
pub mod prometheus;
pub mod quota;
pub mod routes;
pub mod storage;
pub mod tee;
mod tracing;

use config::{BlockStorage, Config, Keys, ReplicationRole, StagingStorage};
use quota::QuotaCache;
use routes::{
    admin::{delete_quota, get_quota, list_quotas, set_quota},
    attestation::attestation,
    delegate, info, invoke, open_host_key,
    public::{public_kv_get, public_kv_head, public_kv_list, public_kv_options, RateLimiter},
    replication::{
        auth_reconcile, auth_replication_export, kv_state, kv_state_compare, peer_missing_apply,
        peer_missing_plan, peer_missing_quarantine, recon_compare, recon_export, recon_split,
        recon_split_compare, reconcile, reconcile_split, replication_export, replication_info,
        replication_session_open, sql_reconcile, sql_replication_export,
    },
    revoke,
    util_routes::*,
    version,
};
use storage::{
    file_system::{FileSystemConfig, FileSystemStore, TempFileSystemStage},
    s3::{S3BlockConfig, S3BlockStore},
};
use tee::TeeContext;
use tinycloud_core::{
    duckdb::DuckDbService,
    keys::{SecretsSetup, StaticSecret},
    sea_orm::{ConnectOptions, Database, DatabaseConnection},
    sql::SqlService,
    storage::{either::Either, memory::MemoryStaging, StorageConfig},
    ReplicationService, SpaceDatabase,
};

pub type BlockStores = Either<S3BlockStore, FileSystemStore>;
pub type BlockConfig = Either<S3BlockConfig, FileSystemConfig>;
pub type BlockStage = Either<TempFileSystemStage, MemoryStaging>;

impl From<BlockStorage> for BlockConfig {
    fn from(c: BlockStorage) -> BlockConfig {
        match c {
            BlockStorage::S3(s) => Self::A(s),
            BlockStorage::Local(l) => Self::B(l),
        }
    }
}

impl From<BlockConfig> for BlockStorage {
    fn from(c: BlockConfig) -> Self {
        match c {
            BlockConfig::A(a) => Self::S3(a),
            BlockConfig::B(b) => Self::Local(b),
        }
    }
}

impl From<StagingStorage> for BlockStage {
    fn from(c: StagingStorage) -> Self {
        match c {
            StagingStorage::Memory => Self::B(MemoryStaging),
            StagingStorage::FileSystem => Self::A(TempFileSystemStage),
        }
    }
}

impl From<BlockStage> for StagingStorage {
    fn from(c: BlockStage) -> Self {
        match c {
            BlockStage::B(_) => Self::Memory,
            BlockStage::A(_) => Self::FileSystem,
        }
    }
}

pub type TinyCloud = SpaceDatabase<DatabaseConnection, BlockStores, StaticSecret>;

pub async fn app(config: &Figment) -> Result<Rocket<Build>> {
    let mut tinycloud_config: Config = config.extract::<Config>()?;
    tinycloud_config.storage.resolve();
    tinycloud_config.replication.apply_env_overrides()?;

    // Ensure local storage directories exist.
    // SQLite file paths and local dirs are resources the server owns — auto-create them.
    // Remote backends (Postgres, S3) are left alone; connection errors surface naturally.
    ensure_local_dirs(&tinycloud_config.storage).await?;

    tracing::tracing_try_init(&tinycloud_config.log)?;

    let routes = routes![
        healthcheck,
        cors,
        info,
        version,
        open_host_key,
        invoke,
        delegate,
        revoke,
        replication_info,
        replication_session_open,
        auth_replication_export,
        auth_reconcile,
        replication_export,
        kv_state,
        kv_state_compare,
        peer_missing_plan,
        peer_missing_apply,
        peer_missing_quarantine,
        recon_export,
        recon_split,
        recon_split_compare,
        recon_compare,
        reconcile,
        reconcile_split,
        sql_replication_export,
        sql_reconcile,
        public_kv_get,
        public_kv_head,
        public_kv_list,
        public_kv_options,
        attestation,
        set_quota,
        delete_quota,
        get_quota,
        list_quotas,
    ];

    let key_setup: StaticSecret = resolve_keys(&tinycloud_config.keys).await?;

    // Initialize TEE context if running in dstack mode
    let tee_context: Option<TeeContext> = {
        #[cfg(feature = "dstack")]
        {
            if dstack::is_available() {
                match dstack::get_info().await {
                    Ok(info) => {
                        ::tracing::info!(
                            app_id = %info.app_id,
                            compose_hash = %info.compose_hash,
                            "Running in dstack TEE mode"
                        );
                        Some(TeeContext {
                            app_id: info.app_id,
                            compose_hash: info.compose_hash,
                            instance_id: info.instance_id,
                        })
                    }
                    Err(e) => {
                        ::tracing::warn!("dstack socket available but get_info failed: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        }
        #[cfg(not(feature = "dstack"))]
        {
            None
        }
    };

    let database = tinycloud_config.storage.database();
    let mut connect_opts = ConnectOptions::from(database);
    let is_sqlite = database.starts_with("sqlite");
    if is_sqlite {
        // SQLite cannot handle concurrent write transactions — two DEFERRED
        // transactions deadlock when both try to upgrade to writers.  Use a
        // single connection to serialize writes, and enable WAL mode so reads
        // outside transactions remain concurrent.
        connect_opts.max_connections(1);
        connect_opts.map_sqlx_sqlite_opts(|opts| {
            opts.create_if_missing(true)
                .pragma("journal_mode", "WAL")
                .busy_timeout(std::time::Duration::from_secs(5))
        });
    } else {
        connect_opts.max_connections(100);
    }

    let tinycloud = TinyCloud::new(
        Database::connect(connect_opts).await?,
        tinycloud_config.storage.blocks.open().await?,
        key_setup.setup(()).await?,
    )
    .await?;

    let sql_service = SqlService::new(
        tinycloud_config.storage.sql.path.clone().expect("resolved"),
        tinycloud_config.storage.sql.memory_threshold.as_u64(),
    );

    let duckdb_service = DuckDbService::new(
        tinycloud_config
            .storage
            .duckdb
            .path
            .clone()
            .expect("resolved"),
        tinycloud_config.storage.duckdb.memory_threshold.as_u64(),
        tinycloud_config.storage.duckdb.idle_timeout_secs,
        tinycloud_config
            .storage
            .duckdb
            .max_memory_per_connection
            .clone(),
    );

    let quota_cache = QuotaCache::new(
        tinycloud_config.storage.limit,
        std::env::var("TINYCLOUD_QUOTA_URL").ok(),
    );

    let rate_limiter = RateLimiter::new(&tinycloud_config.public_spaces);

    let rocket = rocket::custom(config)
        .mount("/", routes)
        .attach(AdHoc::config::<Config>())
        .attach(tracing::TracingFairing {
            header_name: tinycloud_config.log.tracing.traceheader.clone(),
        })
        .manage(tinycloud)
        .manage(sql_service)
        .manage(duckdb_service)
        .manage(ReplicationService::with_session_ttl(
            replication_status(&tinycloud_config),
            std::time::Duration::from_secs(tinycloud_config.replication.session_ttl_secs),
        ))
        .manage(quota_cache)
        .manage(rate_limiter)
        .manage(tee_context)
        .manage(tinycloud_config.storage.staging.open().await?);

    if tinycloud_config.cors {
        Ok(rocket.attach(AdHoc::on_response("CORS", |_, resp| {
            Box::pin(async move {
                resp.set_header(Header::new("Access-Control-Allow-Origin", "*"));
                resp.set_header(Header::new(
                    // allow these methods for requests
                    "Access-Control-Allow-Methods",
                    "POST, PUT, GET, OPTIONS, DELETE",
                ));
                resp.set_header(Header::new(
                    // expose response headers to browser-run scripts
                    "Access-Control-Expose-Headers",
                    "*, Authorization, Replication-Session, Peer-Replication-Session",
                ));
                resp.set_header(Header::new(
                    // allow custom headers + Authorization in requests
                    "Access-Control-Allow-Headers",
                    "*, Authorization, Replication-Session, Peer-Replication-Session",
                ));
                resp.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
            })
        })))
    } else {
        Ok(rocket)
    }
}

async fn resolve_keys(keys: &Keys) -> Result<StaticSecret> {
    match keys {
        Keys::Static(s) => Ok(s.clone().try_into()?),
        #[cfg(feature = "dstack")]
        Keys::Dstack => {
            let key_bytes = dstack::get_key("tinycloud/keys/primary").await?;
            StaticSecret::new(key_bytes)
                .map_err(|v| anyhow::anyhow!("dstack key too short: {} bytes", v.len()))
        }
        Keys::Auto => {
            // Check TINYCLOUD_TEE_MODE env var first
            match std::env::var("TINYCLOUD_TEE_MODE").ok().as_deref() {
                #[cfg(feature = "dstack")]
                Some("dstack") => {
                    let key_bytes = dstack::get_key("tinycloud/keys/primary").await?;
                    StaticSecret::new(key_bytes)
                        .map_err(|v| anyhow::anyhow!("dstack key too short: {} bytes", v.len()))
                }
                Some("off") => {
                    anyhow::bail!(
                        "TEE mode disabled but no static key configured. \
                         Set TINYCLOUD_KEYS_SECRET or configure [keys] in config."
                    )
                }
                _ => {
                    // Auto-detect: check for dstack socket
                    #[cfg(feature = "dstack")]
                    if dstack::is_available() {
                        ::tracing::info!("dstack socket detected, using TEE key derivation");
                        let key_bytes = dstack::get_key("tinycloud/keys/primary").await?;
                        return StaticSecret::new(key_bytes).map_err(|v| {
                            anyhow::anyhow!("dstack key too short: {} bytes", v.len())
                        });
                    }
                    anyhow::bail!(
                        "No key source configured. Either:\n  \
                         - Set TINYCLOUD_KEYS_SECRET environment variable\n  \
                         - Configure [keys] section in tinycloud.toml\n  \
                         - Run inside a dstack TEE (with 'dstack' feature enabled)"
                    )
                }
            }
        }
    }
}

/// Ensure local storage directories exist before connecting.
///
/// For local resources (SQLite file paths, filesystem dirs), create them
/// automatically. For remote backends (Postgres, S3), do nothing — connection
/// errors from those backends are already descriptive.
async fn ensure_local_dirs(storage: &config::Storage) -> Result<()> {
    let database = storage.database();

    // SQLite: ensure the parent directory of the database file exists.
    // Connection strings look like "sqlite:./data/caps.db" or "sqlite::memory:".
    if let Some(path) = database.strip_prefix("sqlite:") {
        if path != ":memory:" && !path.starts_with(":memory:") {
            // Strip query params (e.g., "?mode=rwc")
            let file_path = path.split('?').next().unwrap_or(path);
            if let Some(parent) = Path::new(file_path).parent() {
                if !parent.as_os_str().is_empty() {
                    tokio::fs::create_dir_all(parent).await.with_context(|| {
                        format!("creating database directory: {}", parent.display())
                    })?;
                }
            }
        }
    }

    // SQL and DuckDB storage paths are always local filesystem
    if let Some(ref sql_path) = storage.sql.path {
        tokio::fs::create_dir_all(sql_path)
            .await
            .with_context(|| format!("creating SQL storage directory: {}", sql_path))?;
    }
    if let Some(ref duckdb_path) = storage.duckdb.path {
        tokio::fs::create_dir_all(duckdb_path)
            .await
            .with_context(|| format!("creating DuckDB storage directory: {}", duckdb_path))?;
    }

    Ok(())
}

fn replication_status(config: &Config) -> tinycloud_core::replication::ReplicationStatus {
    let role_name = match config.replication.role {
        ReplicationRole::Host => "host",
        ReplicationRole::Replica => "replica",
    };
    let peer_serving = match config.replication.role {
        ReplicationRole::Host => true,
        ReplicationRole::Replica => config.replication.peer_serving,
    };

    tinycloud_core::replication::ReplicationStatus {
        supported: true,
        enabled: true,
        roles_supported: vec!["host", "replica"],
        roles_enabled: vec![role_name],
        peer_serving,
        recon: true,
        auth_sync: true,
        authored_fact_exchange: true,
        notifications: false,
        snapshots: false,
    }
}
