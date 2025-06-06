#[macro_use]
extern crate rocket;
extern crate anyhow;
#[cfg(test)]
#[macro_use]
extern crate tokio;

use anyhow::Result;
use rocket::{fairing::AdHoc, figment::Figment, http::Header, Build, Rocket};
use tinycloud_lib::libipld::{block::Block as OBlock, store::DefaultParams};

pub mod allow_list;
pub mod auth_guards;
pub mod authorization;
pub mod config;
pub mod prometheus;
pub mod routes;
pub mod storage;
mod tracing;

use config::{BlockStorage, Config, Keys, StagingStorage};
use routes::{delegate, invoke, open_host_key, util_routes::*};
use storage::{
    file_system::{FileSystemConfig, FileSystemStore, TempFileSystemStage},
    s3::{S3BlockConfig, S3BlockStore},
};
use tinycloud_core::{
    keys::{SecretsSetup, StaticSecret},
    sea_orm::{ConnectOptions, Database, DatabaseConnection},
    storage::{either::Either, memory::MemoryStaging, StorageConfig},
    OrbitDatabase,
};

pub type Block = OBlock<DefaultParams>;
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

pub type TinyCloud = OrbitDatabase<DatabaseConnection, BlockStores, StaticSecret>;

pub async fn app(config: &Figment) -> Result<Rocket<Build>> {
    let tinycloud_config: Config = config.extract::<Config>()?;

    tracing::tracing_try_init(&tinycloud_config.log)?;

    let routes = routes![healthcheck, cors, open_host_key, invoke, delegate,];

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

    let rocket = rocket::custom(config)
        .mount("/", routes)
        .attach(AdHoc::config::<Config>())
        .attach(tracing::TracingFairing {
            header_name: tinycloud_config.log.tracing.traceheader,
        })
        .manage(tinycloud)
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
