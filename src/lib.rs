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
pub mod prometheus;
pub mod routes;
pub mod storage;
mod tracing;

use config::{BlockStorage, Config, Keys, StagingStorage};
use routes::{
    delegate, invoke, open_host_key,
    public::{public_kv_get, public_kv_head, public_kv_list, public_kv_options, RateLimiter},
    util_routes::*,
    version,
};
use storage::{
    file_system::{FileSystemConfig, FileSystemStore, TempFileSystemStage},
    s3::{S3BlockConfig, S3BlockStore},
};
use tinycloud_core::{
    duckdb::DuckDbService,
    keys::{SecretsSetup, StaticSecret},
    sea_orm::{ConnectOptions, Database, DatabaseConnection},
    sql::SqlService,
    storage::{either::Either, memory::MemoryStaging, StorageConfig},
    SpaceDatabase,
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
    let tinycloud_config: Config = config.extract::<Config>()?;

    // Ensure local storage directories exist.
    // SQLite file paths and local dirs are resources the server owns — auto-create them.
    // Remote backends (Postgres, S3) are left alone; connection errors surface naturally.
    ensure_local_dirs(&tinycloud_config.storage).await?;

    tracing::tracing_try_init(&tinycloud_config.log)?;

    let routes = routes![
        healthcheck,
        cors,
        version,
        open_host_key,
        invoke,
        delegate,
        public_kv_get,
        public_kv_head,
        public_kv_list,
        public_kv_options,
    ];

    let key_setup: StaticSecret = match tinycloud_config.keys {
        Keys::Static(s) => s.try_into()?,
    };

    let mut connect_opts = ConnectOptions::from(&tinycloud_config.storage.database);
    connect_opts.max_connections(100);

    let tinycloud = TinyCloud::new(
        Database::connect(connect_opts).await?,
        tinycloud_config.storage.blocks.open().await?,
        key_setup.setup(()).await?,
    )
    .await?;

    let sql_service = SqlService::new(
        tinycloud_config.storage.sql.path.clone(),
        tinycloud_config.storage.sql.memory_threshold.as_u64(),
    );

    let duckdb_service = DuckDbService::new(
        tinycloud_config.storage.duckdb.path.clone(),
        tinycloud_config.storage.duckdb.memory_threshold.as_u64(),
        tinycloud_config.storage.duckdb.idle_timeout_secs,
        tinycloud_config
            .storage
            .duckdb
            .max_memory_per_connection
            .clone(),
    );

    let rate_limiter = RateLimiter::new(&tinycloud_config.public_spaces);

    let rocket = rocket::custom(config)
        .mount("/", routes)
        .attach(AdHoc::config::<Config>())
        .attach(tracing::TracingFairing {
            header_name: tinycloud_config.log.tracing.traceheader,
        })
        .manage(tinycloud)
        .manage(sql_service)
        .manage(duckdb_service)
        .manage(rate_limiter)
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
    // SQLite: ensure the parent directory of the database file exists.
    // Connection strings look like "sqlite:./data/caps.db" or "sqlite::memory:".
    if let Some(path) = storage.database.strip_prefix("sqlite:") {
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
    tokio::fs::create_dir_all(&storage.sql.path)
        .await
        .with_context(|| format!("creating SQL storage directory: {}", storage.sql.path))?;
    tokio::fs::create_dir_all(&storage.duckdb.path)
        .await
        .with_context(|| format!("creating DuckDB storage directory: {}", storage.duckdb.path))?;

    Ok(())
}
