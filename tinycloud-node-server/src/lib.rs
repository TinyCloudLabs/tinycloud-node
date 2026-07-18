//! TinyCloud node server: public API (Rocket), local control plane, and the
//! `tinycloud node service ...` CLI for desktop/local installs.

#[macro_use]
extern crate rocket;
extern crate anyhow;

use anyhow::{Context, Result};
use rocket::{fairing::AdHoc, figment::Figment, http::Header, Build, Rocket};
use std::{path::Path, sync::Arc};

pub mod allow_list;
pub mod auth_guards;
pub mod authorization;
pub mod cli;
pub mod config;
#[cfg(feature = "dstack")]
pub mod dstack;
pub mod hooks;
pub mod invocation_replay;
pub mod node_control;
pub mod prometheus;
pub mod quota;
pub mod routes;
pub mod runtime;
pub mod signed_urls;
pub mod storage;
pub mod tee;
mod tracing;
pub mod webhook_dispatcher;

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
pub(crate) mod test_support {
    use std::sync::{Mutex, OnceLock};

    pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }
}

use config::{BlockStorage, Config, StagingStorage};
use hooks::HookRuntime;
use invocation_replay::InvocationReplayCache;
use node_control::{
    control::ControlPlaneHandle,
    key_provider::{self, IdentityPurpose},
};
use quota::QuotaCache;
use routes::{
    admin::{delete_quota, get_quota, get_usage, list_quotas, set_quota},
    attestation::attestation,
    create_signed_kv_url, delegate, delegation_query, delegation_status,
    encryption::{
        create_network as create_encryption_network, decrypt as encryption_decrypt,
        get_network as get_encryption_network, revoke_network as revoke_encryption_network,
        well_known_network as encryption_well_known,
    },
    hooks::{create_hook_ticket, create_webhook, delete_webhook, hook_events, list_webhooks},
    info, invoke, open_host_key,
    public::{public_kv_get, public_kv_head, public_kv_list, public_kv_options, RateLimiter},
    revoke, signed_kv_get,
    util_routes::*,
    version,
};
use storage::{
    file_system::{FileSystemConfig, FileSystemStore, TempFileSystemStage},
    s3::{S3BlockConfig, S3BlockStore},
};
use tee::TeeContext;
#[cfg(feature = "compute")]
use tinycloud_core::compute::ComputeService;
#[cfg(feature = "duckdb")]
use tinycloud_core::duckdb::DuckDbService;
use tinycloud_core::{
    database_artifacts::{DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository},
    encryption_network::{EncryptionService, LocalOneOfOneBackend},
    keys::{SecretsSetup, StaticSecret},
    sea_orm::{ConnectOptions, Database, DatabaseConnection},
    sql::SqlService,
    sql_sizes::{SizeTrackingArtifactRepository, SqlSizes},
    storage::{either::Either, memory::MemoryStaging, StorageConfig},
    ColumnEncryption, SpaceDatabase,
};
use webhook_dispatcher::{spawn_webhook_dispatcher, WebhookDispatcher};

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

pub async fn app(
    config: &Figment,
    tinycloud_config: &Config,
    control: Option<ControlPlaneHandle>,
) -> Result<Rocket<Build>> {
    // Ensure local storage directories exist.
    // SQLite file paths and local dirs are resources the server owns — auto-create them.
    // Remote backends (Postgres, S3) are left alone; connection errors surface naturally.
    ensure_local_dirs(&tinycloud_config.storage).await?;

    prometheus::set_enabled(tinycloud_config.telemetry.enabled);

    tracing::tracing_try_init(&tinycloud_config.log)?;

    let routes = routes![
        healthcheck,
        cors,
        info,
        version,
        open_host_key,
        invoke,
        delegate,
        delegation_query,
        delegation_status,
        revoke,
        create_signed_kv_url,
        signed_kv_get,
        create_hook_ticket,
        hook_events,
        create_webhook,
        list_webhooks,
        delete_webhook,
        public_kv_get,
        public_kv_head,
        public_kv_list,
        public_kv_options,
        attestation,
        set_quota,
        delete_quota,
        get_quota,
        list_quotas,
        get_usage,
        create_encryption_network,
        get_encryption_network,
        encryption_well_known,
        encryption_decrypt,
        revoke_encryption_network,
    ];

    let identity_state = key_provider::resolve_identity_state(
        Some(&tinycloud_config.keys),
        &tinycloud_config.storage.datadir,
        IdentityPurpose::Serve,
    )?;
    if let Some(control) = control.as_ref() {
        control
            .set_identity_snapshot(key_provider::identity_snapshot(&identity_state))
            .await;
    }
    let key_setup = identity_state
        .secret
        .ok_or_else(|| anyhow::anyhow!("node identity is not ready"))?;
    let webhook_encryption =
        ColumnEncryption::new(key_setup.derive_key(b"tinycloud/hooks/webhook-secrets"));
    let hook_runtime = HookRuntime::new(
        tinycloud_config.hooks.clone(),
        key_setup.derive_key(b"tinycloud/hooks/tickets"),
    );
    let signed_url_runtime =
        signed_urls::SignedUrlRuntime::new(key_setup.derive_key(b"tinycloud/kv/signed-urls"));

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

    let database_connection = Database::connect(connect_opts).await?;
    // SQL/DuckDB artifact-size mirror folded into `store_size`. Empty here;
    // wired into the decorator + SpaceDatabase BEFORE migrations, then seeded
    // from DB truth AFTER `TinyCloud::new` runs migrations (see below).
    let sql_sizes = SqlSizes::new();
    let seed_conn = database_connection.clone();
    let raw_artifact_repository = Arc::new(SeaOrmDatabaseArtifactRepository::new(
        database_connection.clone(),
    ));
    let database_artifact_repository: Arc<dyn DatabaseArtifactRepository> = Arc::new(
        SizeTrackingArtifactRepository::new(raw_artifact_repository, sql_sizes.clone()),
    );

    // Encryption module: seal network private keys with the same kind of derived
    // key used for DB column encryption. In DStack mode the seal is rooted in
    // the dstack-derived `key_setup`, so this naturally lifts the network
    // private key into DStack-derived key management.
    let encryption_seal =
        ColumnEncryption::new(key_setup.derive_key(b"tinycloud/encryption/network-seal"));
    let encryption_backend = std::sync::Arc::new(LocalOneOfOneBackend::new(encryption_seal));
    let node_keypair = key_setup.node_keypair();
    let encryption_service = EncryptionService::new_with_node_keypair(
        database_connection.clone(),
        node_keypair,
        encryption_backend,
    );

    let tinycloud = TinyCloud::new(
        database_connection,
        tinycloud_config.storage.blocks.open().await?,
        key_setup.setup(()).await?,
    )
    .await?
    .with_encryption(Some(webhook_encryption.clone()))
    .with_sql_sizes(sql_sizes.clone());

    // Seed the SQL-size mirror AFTER `TinyCloud::new` ran migrations — the
    // `database_artifact` table now exists (seeding before migrations would
    // fail boot on a fresh datadir). Runs before Rocket serves any request.
    sql_sizes.seed_from(&seed_conn).await?;

    let sql_service = SqlService::new(
        tinycloud_config.storage.sql.path.clone().expect("resolved"),
        tinycloud_config.storage.sql.memory_threshold.as_u64(),
        database_artifact_repository.clone(),
    );

    #[cfg(feature = "duckdb")]
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
        database_artifact_repository,
    );

    // P0 walking skeleton: a stateless stub. The artifact repository,
    // backend registry, and routine-key derivation handle are P1/P2
    // additions (compute-service.md §11.1).
    #[cfg(feature = "compute")]
    let compute_service = ComputeService::new();

    let quota_cache = QuotaCache::new(
        tinycloud_config.storage.limit,
        std::env::var("TINYCLOUD_QUOTA_URL").ok(),
    );
    let invocation_replay_cache = InvocationReplayCache::new();

    let rate_limiter = RateLimiter::new(&tinycloud_config.public_spaces);
    let webhook_dispatcher = WebhookDispatcher::new(
        tinycloud.clone(),
        tinycloud_config.hooks.clone(),
        webhook_encryption.clone(),
    )?;
    spawn_webhook_dispatcher(webhook_dispatcher);

    let rocket = rocket::custom(config)
        .mount("/", routes)
        .attach(AdHoc::config::<Config>())
        .attach(tracing::TracingFairing {
            header_name: tinycloud_config.log.tracing.traceheader.clone(),
        })
        .manage(tinycloud)
        .manage(sql_service);
    #[cfg(feature = "duckdb")]
    let rocket = rocket.manage(duckdb_service);
    #[cfg(feature = "compute")]
    let rocket = rocket.manage(compute_service);
    let rocket = rocket
        .manage(quota_cache)
        .manage(invocation_replay_cache)
        .manage(hook_runtime)
        .manage(signed_url_runtime)
        .manage(webhook_encryption)
        .manage(rate_limiter)
        .manage(tee_context)
        .manage(encryption_service)
        .manage(tinycloud_config.storage.staging.open().await?);

    let rocket = if let Some(control) = control {
        let control_running = control.clone();
        let control_stopping = control.clone();
        rocket
            .attach(AdHoc::on_liftoff("control-plane-running", move |_| {
                let control = control_running.clone();
                Box::pin(async move {
                    control.mark_running();
                })
            }))
            .attach(AdHoc::on_shutdown("control-plane-stopping", move |_| {
                let control = control_stopping.clone();
                Box::pin(async move {
                    control.mark_stopping();
                })
            }))
    } else {
        rocket
    };

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
                    "*, Authorization",
                ));
                resp.set_header(Header::new(
                    // allow custom headers + Authorization in requests
                    "Access-Control-Allow-Headers",
                    "*, Authorization",
                ));
                resp.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
            })
        })))
    } else {
        Ok(rocket)
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

    // SQL storage paths are always local filesystem.
    if let Some(ref sql_path) = storage.sql.path {
        tokio::fs::create_dir_all(sql_path)
            .await
            .with_context(|| format!("creating SQL storage directory: {}", sql_path))?;
    }
    #[cfg(feature = "duckdb")]
    if let Some(ref duckdb_path) = storage.duckdb.path {
        tokio::fs::create_dir_all(duckdb_path)
            .await
            .with_context(|| format!("creating DuckDB storage directory: {}", duckdb_path))?;
    }

    Ok(())
}
