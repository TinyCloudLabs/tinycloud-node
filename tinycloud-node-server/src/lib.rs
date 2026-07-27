extern crate anyhow;
#[allow(unused_imports)]
#[macro_use]
extern crate rocket;
#[macro_use]
#[allow(unused_imports)]
extern crate async_trait;
#[cfg(test)]
extern crate tokio;

use anyhow::{Context, Result};
use rocket::{fairing::AdHoc, figment::Figment, http::Header, Build, Rocket};
use std::{path::Path, sync::Arc};

pub mod allow_list;
pub mod auth_guards;
pub mod authorization;
pub mod config;
#[cfg(feature = "dstack")]
pub mod dstack;
pub mod hooks;
pub mod invocation_replay;
pub mod link;
pub mod node_control;
pub mod prometheus;
pub mod quota;
pub mod routes;
pub mod runtime;
pub mod share_email;
pub mod share_v2;
pub mod signed_urls;
pub mod storage;
pub mod tee;
mod tracing;
pub mod tunnel;
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

use config::{BlockStorage, Config, Keys, StagingStorage};
use hooks::HookRuntime;
use invocation_replay::InvocationReplayCache;
use node_control::control::ControlPlaneHandle;
use quota::QuotaCache;
#[cfg(feature = "tc-bench-v1")]
use routes::tc_bench::{
    auth_verify as tc_bench_auth_verify, block_get as tc_bench_block_get,
    block_put as tc_bench_block_put, health as tc_bench_health, kv_get as tc_bench_kv_get,
    kv_put as tc_bench_kv_put, BenchState,
};
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

/// Size of the SQLite connection pool used for the capability database.
const SQLITE_MAX_CONNECTIONS: u32 = 16;

/// SQLite tuning for the capability database. Extracted into a free function
/// so it can be exercised directly by a test that reads the pragmas back off
/// a live pooled connection, rather than only asserting that the builder was
/// called.
///
/// NOTE: `synchronous = "NORMAL"` is a durability trade-off under WAL mode —
/// it cannot corrupt the database, but it can lose the last committed
/// transaction(s) on power loss / host crash, which weakens the "commits
/// before acknowledgment" contract documented in
/// docs/read-audit-durability.md. This must be reviewed by a human before
/// merging; see the PR description.
fn sqlite_connect_options(database: &str) -> ConnectOptions {
    let mut connect_opts = ConnectOptions::from(database);
    connect_opts.max_connections(SQLITE_MAX_CONNECTIONS);
    connect_opts.map_sqlx_sqlite_opts(|opts| {
        opts.create_if_missing(true)
            .pragma("journal_mode", "WAL")
            .busy_timeout(std::time::Duration::from_secs(5))
            .pragma("synchronous", "NORMAL") // durability trade-off, see above
            .pragma("cache_size", "-65536") // 64 MiB page cache per connection
            .pragma("mmap_size", "268435456") // 256 MiB mmap per connection
            .pragma("temp_store", "MEMORY")
            .pragma("wal_autocheckpoint", "1000") // explicit; matches SQLite's compiled-in default
    });
    connect_opts
}

pub async fn app(config: &Figment) -> Result<Rocket<Build>> {
    let tinycloud_config = config.extract::<Config>()?;
    app_with_control(config, &tinycloud_config, None).await
}

pub async fn app_with_control(
    config: &Figment,
    tinycloud_config: &Config,
    control: Option<ControlPlaneHandle>,
) -> Result<Rocket<Build>> {
    let mut tinycloud_config = tinycloud_config.clone();
    tinycloud_config.storage.resolve();
    tinycloud_config.share_email = tinycloud_config
        .share_email
        .resolve_trust_bundle()
        .map_err(|error| anyhow::anyhow!(error))?;
    tinycloud_config
        .share_email
        .validate_for_v2_database(tinycloud_config.storage.database())
        .map_err(|error| anyhow::anyhow!(error))?;

    // Ensure local storage directories exist.
    // SQLite file paths and local dirs are resources the server owns — auto-create them.
    // Remote backends (Postgres, S3) are left alone; connection errors surface naturally.
    ensure_local_dirs(&tinycloud_config.storage).await?;

    prometheus::set_enabled(tinycloud_config.telemetry.enabled);

    tracing::tracing_try_init(&tinycloud_config.log)?;

    let mut routes = rocket::routes![
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
    routes.extend(share_email::public_routes());
    routes.extend(share_v2::public_routes());
    #[cfg(feature = "tc-bench-v1")]
    routes.extend(rocket::routes![
        tc_bench_auth_verify,
        tc_bench_kv_put,
        tc_bench_kv_get,
        tc_bench_block_put,
        tc_bench_block_get,
        tc_bench_health,
    ]);

    let key_setup: StaticSecret = resolve_keys(&tinycloud_config.keys).await?;
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
                            enforcer_did: key_setup.node_did(),
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
    // Test-only, key-derived fallback for hosts with no real dstack TEE
    // (local dev, canonical local-launch harnesses). Gated by the
    // `local-tee` feature, which is never part of a production build. It
    // never overrides a real dstack-attested context above.
    #[cfg(feature = "local-tee")]
    let tee_context = tee_context.or_else(|| {
        ::tracing::warn!(
            "share-v2 local-tee feature active: deriving a deterministic, non-attested TEE identity from node key material"
        );
        Some(TeeContext::derive_local(&key_setup))
    });

    let database = tinycloud_config.storage.database();
    let is_sqlite = database.starts_with("sqlite");
    let mut connect_opts = if is_sqlite {
        // WAL permits readers to progress while the core's shared writer lock
        // serializes mutations and durable read-audit batches. A one-connection
        // pool made every authenticated read wait behind audit writes.
        sqlite_connect_options(database)
    } else {
        ConnectOptions::from(database)
    };
    if !is_sqlite {
        connect_opts.max_connections(100);
        if let Some(root_cert_path) = tinycloud_config
            .share_email
            .postgres_tls
            .root_cert_path
            .as_deref()
        {
            let root_cert_path = root_cert_path.to_owned();
            connect_opts.map_sqlx_postgres_opts(move |options| {
                options.ssl_root_cert(root_cert_path.clone())
            });
        }
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
    #[cfg(feature = "tc-bench-v1")]
    let bench_state = BenchState::new(
        &tinycloud_config.tc_bench,
        seed_conn.clone(),
        if is_sqlite { 1 } else { 100 },
    )
    .await?;

    let sql_service = SqlService::new(
        tinycloud_config.storage.sql.path.clone().expect("resolved"),
        tinycloud_config.storage.sql.memory_threshold.as_u64(),
        database_artifact_repository.clone(),
    );

    let share_email_runtime = share_email::compose(
        tinycloud_config.share_email.clone(),
        seed_conn.clone(),
        &key_setup,
        Arc::new(tinycloud.clone()),
        Arc::new(sql_service.clone()),
    )?;
    #[cfg(feature = "dstack")]
    let dstack_tee_key_derived = matches!(tinycloud_config.keys, config::Keys::Dstack)
        || matches!(tinycloud_config.keys, config::Keys::Auto) && dstack::is_available();
    #[cfg(not(feature = "dstack"))]
    let dstack_tee_key_derived = false;
    // `local-tee` always derives its TeeContext from real node key material
    // (see `TeeContext::derive_local`), so it is a derived identity too.
    let tee_key_derived = dstack_tee_key_derived || cfg!(feature = "local-tee");
    let share_v2_runtime = if tinycloud_config.share_email.enabled {
        Some(
            share_v2::compose(
                seed_conn.clone(),
                &key_setup,
                tinycloud_config.share_email.clone(),
                tee_context.clone(),
                tee_key_derived,
                Arc::new(tinycloud.clone()),
            )
            .await?,
        )
    } else {
        None
    };
    if let Some(runtime) = share_email_runtime.as_ref() {
        if !runtime.bridge.self_check().await {
            anyhow::bail!(
                "share email readiness failed: authority, fresh status, attestation, or database is unavailable"
            );
        }
    }
    if let Some(runtime) = share_email_runtime.as_ref() {
        let state = runtime.state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(error) = state.cleanup(time::OffsetDateTime::now_utc()).await {
                    ::tracing::warn!(
                        ?error,
                        "share-email cleanup failed; capability remains fail-closed"
                    );
                }
            }
        });
    }

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

    let quota_cache = QuotaCache::new(
        tinycloud_config.storage.limit,
        std::env::var("TINYCLOUD_QUOTA_URL").ok(),
    );
    let invocation_replay_cache = InvocationReplayCache::new(seed_conn.clone());
    let replay_cleanup = invocation_replay_cache.clone();

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
        .attach(tracing::TracingFairing::new(&tinycloud_config.log.tracing))
        .attach(AdHoc::on_liftoff(
            "invocation-replay-cleanup",
            move |rocket| {
                let replay_cleanup = replay_cleanup.clone();
                let shutdown = rocket.shutdown();
                Box::pin(async move {
                    tokio::spawn(async move {
                        let _ = replay_cleanup
                            .cleanup_expired(time::OffsetDateTime::now_utc())
                            .await;
                        let period = std::time::Duration::from_secs(60);
                        let mut interval =
                            tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                        tokio::pin!(shutdown);
                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    let _ = replay_cleanup
                                        .cleanup_expired(time::OffsetDateTime::now_utc())
                                        .await;
                                }
                                _ = &mut shutdown => break,
                            }
                        }
                    });
                })
            },
        ))
        .manage(tinycloud)
        .manage(sql_service);
    #[cfg(feature = "tc-bench-v1")]
    let rocket = rocket.manage(bench_state);
    #[cfg(feature = "duckdb")]
    let rocket = rocket.manage(duckdb_service);
    let rocket = rocket
        .manage(quota_cache)
        .manage(invocation_replay_cache)
        .manage(hook_runtime)
        .manage(signed_url_runtime)
        .manage(webhook_encryption)
        .manage(rate_limiter)
        .manage(share_email_runtime)
        .manage(share_v2_runtime)
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

    let share_allowed_origin = tinycloud_config
        .share_email
        .allowed_origins
        .first()
        .cloned()
        .unwrap_or_else(|| tinycloud_config.share_email.return_origin.clone());
    let rocket = rocket.attach(AdHoc::on_response(
        "share-email-security-headers",
        move |request, response| {
            let share_allowed_origin = share_allowed_origin.clone();
            Box::pin(async move {
                if request.uri().path().starts_with("/share/v1/")
                    || request.uri().path().starts_with("/share/v2/")
                {
                    response.set_header(Header::new("Cache-Control", "no-store"));
                    response.set_header(Header::new("X-Content-Type-Options", "nosniff"));
                    response.set_header(Header::new("Referrer-Policy", "no-referrer"));
                    response.set_header(Header::new(
                        "Access-Control-Allow-Origin",
                        share_allowed_origin,
                    ));
                    response.set_header(Header::new("Access-Control-Allow-Methods", "GET, POST"));
                    response
                        .set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
                }
            })
        },
    ));

    if tinycloud_config.cors {
        Ok(rocket.attach(AdHoc::on_response("CORS", |request, resp| {
            Box::pin(async move {
                if request.uri().path().starts_with("/share/v1/")
                    || request.uri().path().starts_with("/share/v2/")
                {
                    return;
                }
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
        Keys::Provider => anyhow::bail!(
            "provider key mode must be resolved through the node control key-provider path"
        ),
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

#[cfg(test)]
mod sqlite_tuning_tests {
    use super::*;
    use tinycloud_core::sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

    async fn pragma(db: &DatabaseConnection, name: &str) -> String {
        let row = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("PRAGMA {name}"),
            ))
            .await
            .unwrap()
            .expect("pragma returns a row");
        row.try_get_by_index::<i64>(0)
            .map(|v| v.to_string())
            .or_else(|_| row.try_get_by_index::<String>(0))
            .unwrap()
    }

    /// Asserts the SQLite tuning pragmas as read back off a real, live pooled
    /// connection handed out by `sqlite_connect_options` — not merely that the
    /// builder was called. Run against unmodified `sqlite_connect_options` (no
    /// `synchronous`/`cache_size`/`mmap_size`/`temp_store` pragmas) this test
    /// failed with `synchronous == "2"` (FULL), which is the empirical proof
    /// that FULL was the shipped default before this change.
    #[tokio::test]
    async fn sqlite_pragmas_are_applied_on_live_pooled_connections() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite:{}?mode=rwc", dir.path().join("caps.db").display());
        let db = Database::connect(sqlite_connect_options(&url))
            .await
            .unwrap();
        assert_eq!(pragma(&db, "journal_mode").await, "wal");
        assert_eq!(pragma(&db, "synchronous").await, "1"); // 1 = NORMAL, 2 = FULL
        assert_eq!(pragma(&db, "cache_size").await, "-65536");
        assert_eq!(pragma(&db, "temp_store").await, "2"); // 2 = MEMORY
        assert_eq!(pragma(&db, "mmap_size").await, "268435456");
    }
}
