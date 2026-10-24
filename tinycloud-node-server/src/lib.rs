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
use rocket::{
    fairing::AdHoc,
    figment::Figment,
    http::{Header, Method},
    Build, Rocket, Route,
};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

pub mod allow_list;
pub mod auth_guards;
pub mod authorization;
pub mod cli;
pub mod config;
pub mod dstack;
pub mod egress;
pub mod epoch_head_backfill;
pub mod hooks;
pub mod invocation_replay;
pub mod issuer_set;
pub mod link;
pub mod node_control;
pub mod policy_v3;
pub mod prometheus;
pub mod quota;
pub mod routes;
pub mod runtime;
pub mod share_email;
#[cfg(tinycloud_legacy_share_v2)]
pub mod share_v2;
#[cfg(not(tinycloud_legacy_share_v2))]
pub mod share_v2 {
    #[derive(serde::Serialize)]
    pub struct CapabilityDescriptor {}

    pub struct ShareV2Runtime;

    impl ShareV2Runtime {
        pub fn capability(&self) -> Option<CapabilityDescriptor> {
            None
        }
    }
}
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

    /// Sets a process environment variable for the lifetime of the guard and
    /// restores the previous value on drop. Hold [`env_lock`] across it.
    #[allow(dead_code)]
    pub struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        #[allow(dead_code)]
        pub fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
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

    /// Resolve the PostgreSQL URL that the `postgres_*` tests connect to, or
    /// `None` when they skip. The rule is in [`postgres_gate`].
    pub fn postgres_test_url(test: &str) -> Option<String> {
        postgres_gate(
            std::env::var("TINYCLOUD_TEST_POSTGRES_URL").ok(),
            std::env::var_os("GITHUB_ACTIONS").map(|value| value.to_string_lossy().into_owned()),
            std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").ok(),
            test,
        )
    }

    /// Decides whether a PostgreSQL-backed test connects. Pure, so the rule is
    /// unit-tested without touching the process environment.
    ///
    /// A test connects only when `url` is set and non-empty AND either
    /// `github_actions` is `"true"` (set by GitHub Actions) or `allow_local` is
    /// `"1"` (an isolated server the developer started). Otherwise it skips with
    /// one line on stderr. When `github_actions` is `"true"` and `url` is not, it
    /// panics: the CI job must never skip these tests silently (TC-381).
    pub fn postgres_gate(
        url: Option<String>,
        github_actions: Option<String>,
        allow_local: Option<String>,
        test: &str,
    ) -> Option<String> {
        let Some(url) = url.filter(|url| !url.trim().is_empty()) else {
            if github_actions.as_deref() == Some("true") {
                panic!(
                    "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset (or empty) on GitHub Actions. \
                     This test must not be allowed to skip on GitHub Actions — see TC-381. Check the \
                     `postgres` service container and the `env:` block in .github/workflows/rust.yml."
                );
            }
            skip_postgres_test(test);
            return None;
        };
        if github_actions.as_deref() == Some("true") || allow_local.as_deref() == Some("1") {
            return Some(url);
        }
        skip_postgres_test(test);
        None
    }

    fn skip_postgres_test(test: &str) {
        use std::io::Write;
        // Written to the process stderr directly: libtest captures `eprintln!` output of passing tests.
        let _ = writeln!(
            std::io::stderr(),
            "skipping {test}: PostgreSQL-backed tests run only on GitHub Actions (or with TINYCLOUD_ALLOW_LOCAL_PG=1 for an isolated server you started yourself); not connecting"
        );
    }

    #[cfg(test)]
    mod postgres_gate_tests {
        use super::postgres_gate;

        const URL: &str = "postgres://gate.invalid:1/x";
        const TEST: &str = "gate_case";

        fn some(value: &str) -> Option<String> {
            Some(value.to_owned())
        }

        #[test]
        fn ci_true_without_github_actions_skips_even_when_the_url_is_set() {
            // `CI` is not an input to the rule. With GITHUB_ACTIONS and the local
            // opt-in both unset, a set URL is never connected to.
            assert_eq!(postgres_gate(some(URL), None, None, TEST), None);
        }

        #[test]
        fn url_with_github_actions_true_connects() {
            assert_eq!(
                postgres_gate(some(URL), some("true"), None, TEST),
                some(URL)
            );
        }

        #[test]
        fn url_with_github_actions_other_than_true_skips() {
            for github_actions in ["1", "TRUE", "false", ""] {
                assert_eq!(
                    postgres_gate(some(URL), some(github_actions), None, TEST),
                    None,
                    "GITHUB_ACTIONS={github_actions:?}"
                );
            }
        }

        #[test]
        fn url_with_allow_local_one_connects() {
            assert_eq!(postgres_gate(some(URL), None, some("1"), TEST), some(URL));
        }

        #[test]
        fn url_with_allow_local_other_than_one_skips() {
            for allow in ["true", "0"] {
                assert_eq!(
                    postgres_gate(some(URL), None, some(allow), TEST),
                    None,
                    "TINYCLOUD_ALLOW_LOCAL_PG={allow:?}"
                );
            }
        }

        #[test]
        fn url_unset_without_github_actions_skips() {
            assert_eq!(postgres_gate(None, None, None, TEST), None);
        }

        #[test]
        fn blank_url_without_github_actions_skips() {
            assert_eq!(postgres_gate(some("  "), None, None, TEST), None);
        }

        #[test]
        #[should_panic(expected = "requires TINYCLOUD_TEST_POSTGRES_URL")]
        fn url_unset_with_github_actions_true_panics() {
            postgres_gate(None, some("true"), None, TEST);
        }

        #[test]
        #[should_panic(expected = "requires TINYCLOUD_TEST_POSTGRES_URL")]
        fn blank_url_with_github_actions_true_panics() {
            postgres_gate(some(""), some("true"), None, TEST);
        }
    }
}

use config::{BlockStorage, Config, Keys, StagingStorage};
use hooks::HookRuntime;
use invocation_replay::InvocationReplayCache;
use node_control::control::ControlPlaneHandle;
use node_control::key_provider::{self, IdentityPurpose};
use policy_v3::{
    authorize_delivery as authorize_policy_v3_delivery, challenge as policy_v3_challenge,
    get_status as get_policy_v3_status, issue_enforcer_binding as policy_v3_enforcer_binding,
    mint as policy_v3_mint, register_policy as register_policy_v3,
    revoke_root as revoke_policy_v3_root, status as policy_v3_status, PolicyV3Runtime,
};
use quota::QuotaCache;
#[cfg(feature = "tc-bench-v1")]
use routes::tc_bench::{
    auth_verify as tc_bench_auth_verify, block_get as tc_bench_block_get,
    block_put as tc_bench_block_put, health as tc_bench_health, kv_get as tc_bench_kv_get,
    kv_put as tc_bench_kv_put, BenchState,
};
use routes::{
    admin::{delete_quota, get_quota, get_usage, list_quotas, set_quota},
    admin_stats::get_stats,
    attestation::attestation,
    create_signed_kv_url, delegate, delegation_query, delegation_status,
    encryption::{
        block_encryption_key, create_encryption_key, create_network as create_encryption_network,
        decrypt as encryption_decrypt, describe_encryption_key,
        get_network as get_encryption_network, public_encryption_key,
        revoke_network as revoke_encryption_network, unblock_encryption_key,
        well_known_network as encryption_well_known,
    },
    hooks::{create_hook_ticket, create_webhook, delete_webhook, hook_events, list_webhooks},
    info, invoke,
    node_keys::{node_keys, NodePublicKeys},
    open_host_key,
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
    db_pool::PoolRecovery,
    encryption_network::{EncryptionService, LocalOneOfOneBackend},
    keys::{SecretsSetup, StaticSecret},
    sea_orm::{ConnectOptions, Database},
    sql::SqlService,
    sql_sizes::{SizeTrackingArtifactRepository, SqlSizes},
    storage::{either::Either, memory::MemoryStaging, StorageConfig},
    ColumnEncryption, RecoveringConnection, SpaceDatabase,
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

pub type TinyCloud = SpaceDatabase<RecoveringConnection, BlockStores, StaticSecret>;

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

/// sqlx logs the text of every statement (placeholders, never bound values)
/// at INFO, and of statements slower than 1 s at WARN. Keep statement text out
/// of production logs (TC-961): a statement built with an inline literal would
/// carry it.
const STATEMENT_LOG_LEVEL: tracing_log::log::LevelFilter = tracing_log::log::LevelFilter::Debug;
const SLOW_STATEMENT_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);

/// Open the node's capability-database pool from the resolved configuration.
///
/// Postgres gets [`postgres_pool`]: no unconditional pre-acquire ping, plus
/// connection-loss recovery (TC-951). MySQL keeps sqlx's default pre-acquire
/// ping, since no recovery hook exists for it here. Both, and SQLite, are
/// wrapped in a [`RecoveringConnection`], which retries a `BEGIN` or a
/// read-only statement once after a lost connection.
pub async fn connect_database(tinycloud_config: &Config) -> Result<RecoveringConnection> {
    let database = tinycloud_config.storage.database();
    if database.starts_with("sqlite") {
        // WAL permits readers to progress while the core's shared writer lock
        // serializes mutations and durable read-audit batches. A one-connection
        // pool made every authenticated read wait behind audit writes.
        let mut connect_opts = sqlite_connect_options(database);
        connect_opts
            .sqlx_logging_level(STATEMENT_LOG_LEVEL)
            .sqlx_slow_statements_logging_settings(STATEMENT_LOG_LEVEL, SLOW_STATEMENT_THRESHOLD);
        return Ok(RecoveringConnection::new(
            Database::connect(connect_opts).await?,
        ));
    }
    let mut connect_opts = ConnectOptions::from(database);
    connect_opts
        .max_connections(tinycloud_config.database.max_connections)
        // Recycle connections before a middlebox idle cutoff drops them
        // silently (TC-1054).
        .idle_timeout(Duration::from_secs(
            tinycloud_config.database.idle_timeout_secs,
        ))
        .max_lifetime(Duration::from_secs(
            tinycloud_config.database.max_lifetime_secs,
        ));
    if database.starts_with("postgres://") || database.starts_with("postgresql://") {
        return postgres_pool(
            connect_opts,
            tinycloud_config
                .share_email
                .postgres_tls
                .root_cert_path
                .as_deref(),
            &tinycloud_config.database,
        )
        .await;
    }
    connect_opts
        .sqlx_logging_level(STATEMENT_LOG_LEVEL)
        .sqlx_slow_statements_logging_settings(STATEMENT_LOG_LEVEL, SLOW_STATEMENT_THRESHOLD);
    Ok(RecoveringConnection::new(
        Database::connect(connect_opts).await?,
    ))
}

static POSTGRES_CONNECTIONS_OPENED: AtomicU64 = AtomicU64::new(0);

/// PostgreSQL connections the node's pools have opened in this process.
pub fn postgres_connections_opened() -> u64 {
    POSTGRES_CONNECTIONS_OPENED.load(Ordering::Relaxed)
}

/// Build the Postgres pool for `connect_opts` (its URL and pool settings).
///
/// sqlx pings every pooled connection before handing it out by default. Most
/// statements run directly on the pool, so with the database a WAN round trip
/// away that ping doubled the cost of nearly every statement. It is off here;
/// instead the pool's [`PoolRecovery`] hook pings only the idle connections
/// that predate an observed connection loss or have been idle for a minute,
/// and [`RecoveringConnection`] retries the statement that observed a loss
/// when that is safe.
///
/// Every new connection then gets, from `database` (TC-1054):
/// - TCP keepalive and `TCP_USER_TIMEOUT` on its socket, set by the vendored
///   sqlx-core's `connect_tcp` as it connects (`vendor/sqlx-core/PATCH.md`),
///   so a connection the network drops silently fails within tens of
///   seconds instead of hanging for up to ~15 min. A connect whose options
///   cannot be set fails;
/// - in [`tinycloud_core::db_pool::StatementTimeoutMode::Session`], `SET statement_timeout`, so a
///   statement stuck on a live connection fails server-side. Migrations and
///   whole-artifact transfers scope their own limits
///   ([`tinycloud_core::db::migrate`], [`RecoveringConnection::begin_bulk`]).
///
/// sea-orm's `Database::connect` cannot install these hooks, so the pool is
/// built here with the same connect options it would have applied: the URL,
/// statement logging, and the configured TLS root certificate. No search
/// path is configured, and the pool connects eagerly, as before.
pub async fn postgres_pool(
    connect_opts: ConnectOptions,
    root_cert_path: Option<&str>,
    database: &config::DatabaseConfig,
) -> Result<RecoveringConnection> {
    postgres_pool_with_recovery(connect_opts, root_cert_path, database, PoolRecovery::new()).await
}

/// [`postgres_pool`] with a given recovery state. Production uses
/// [`postgres_pool`]; tests use this to shorten the idle threshold
/// ([`PoolRecovery::with_idle_revalidation`]).
pub async fn postgres_pool_with_recovery(
    connect_opts: ConnectOptions,
    root_cert_path: Option<&str>,
    database: &config::DatabaseConfig,
    recovery: Arc<PoolRecovery>,
) -> Result<RecoveringConnection> {
    use tinycloud_core::sea_orm::{
        sqlx::{postgres::PgConnectOptions, ConnectOptions as _, Executor as _, Postgres},
        SqlxPostgresConnector,
    };

    let mut options = connect_opts
        .get_url()
        .parse::<PgConnectOptions>()?
        .log_statements(STATEMENT_LOG_LEVEL)
        .log_slow_statements(STATEMENT_LOG_LEVEL, SLOW_STATEMENT_THRESHOLD);
    if let Some(root_cert_path) = root_cert_path {
        options = options.ssl_root_cert(root_cert_path);
    }
    // Registered per connect target before the pool opens its first
    // connection; the vendored sqlx-core applies it in `connect_tcp`.
    let keepalive = database.tcp_keepalive();
    sqlx_core::net::tcp_keepalive::set_tcp_keepalive(
        options.get_host(),
        options.get_port(),
        keepalive,
    );
    let statement_timeouts = database.statement_timeouts();
    let session_statement = statement_timeouts.session_statement();
    let pool = recovery
        .install(
            connect_opts
                .sqlx_pool_options::<Postgres>()
                .test_before_acquire(false),
        )
        .after_connect(move |conn, _meta| {
            let session_statement = session_statement.clone();
            Box::pin(async move {
                POSTGRES_CONNECTIONS_OPENED.fetch_add(1, Ordering::Relaxed);
                if let Some(statement) = session_statement {
                    conn.execute(statement.as_str()).await?;
                }
                Ok(())
            })
        })
        .connect_with(options)
        .await?;
    // After a deploy, `sockets_configured >= connections_opened` shows every
    // connection got its keepalive options (a connect that cannot set them
    // fails, with a warning from sqlx-core).
    ::tracing::info!(
        statement_timeout_mode = ?statement_timeouts.mode,
        statement_timeout_ms = statement_timeouts.base.as_millis() as u64,
        bulk_statement_timeout_ms = statement_timeouts.bulk.as_millis() as u64,
        retry_window_ms = database.retry_window_ms,
        tcp_keepalive = keepalive.is_some(),
        tcp_keepalive_idle_secs = keepalive.map(|k| k.idle.as_secs()),
        tcp_keepalive_interval_secs = keepalive.map(|k| k.interval.as_secs()),
        tcp_keepalive_retries = keepalive.map(|k| k.retries),
        tcp_user_timeout_ms = keepalive
            .and_then(|k| k.user_timeout)
            .map(|t| t.as_millis() as u64),
        sockets_configured = sqlx_core::net::tcp_keepalive::sockets_configured(),
        connections_opened = postgres_connections_opened(),
        "PostgreSQL pool connection limits"
    );
    Ok(RecoveringConnection::with_recovery(
        SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
        recovery,
    )
    .with_statement_timeouts(statement_timeouts)
    .with_retry_window(Duration::from_millis(database.retry_window_ms)))
}

fn node_replay_cache(tinycloud: &TinyCloud) -> InvocationReplayCache {
    InvocationReplayCache::new(tinycloud.connection().clone())
        .with_sqlite_writer_lock(tinycloud.sqlite_writer_lock())
}

fn node_artifact_repository(tinycloud: &TinyCloud) -> SeaOrmDatabaseArtifactRepository {
    SeaOrmDatabaseArtifactRepository::new(tinycloud.connection().clone())
        .with_sqlite_writer_lock(tinycloud.sqlite_writer_lock())
}

pub async fn app(config: &Figment) -> Result<Rocket<Build>> {
    let tinycloud_config = config.extract::<Config>()?;
    app_with_control(config, &tinycloud_config, None).await
}

/// Resolve startup configuration without opening a key, database, or socket.
/// The deploy job invokes this on the candidate image before stopping the node.
pub fn resolve_runtime_config(tinycloud_config: &Config) -> Result<Config> {
    let mut resolved = tinycloud_config.clone();
    resolved.hooks.validate().map_err(anyhow::Error::msg)?;
    resolved.database.validate().map_err(anyhow::Error::msg)?;
    resolved
        .epoch_head_backfill
        .validate()
        .map_err(anyhow::Error::msg)?;
    resolved.sql_store.validate().map_err(anyhow::Error::msg)?;
    tracing::RequestIdOrigins::new(&resolved.log.request_id_first_party_origins)
        .map_err(anyhow::Error::msg)?;
    resolved.storage.resolve();
    resolved.share_email = resolved
        .share_email
        .resolve_trust_bundle()
        .map_err(|error| anyhow::anyhow!(error))?;
    resolved
        .share_email
        .validate_for_v2_database(resolved.storage.database())
        .map_err(|error| anyhow::anyhow!(error))?;
    resolved.share_email.credential_issuer_set()?;
    Ok(resolved)
}

/// The named-key routes. Mounted only while `named_keys_v1` is on, so with it
/// off these paths answer as any unmounted path does.
fn named_key_routes() -> Vec<Route> {
    rocket::routes![
        create_encryption_key,
        describe_encryption_key,
        public_encryption_key,
        block_encryption_key,
        unblock_encryption_key,
    ]
}

/// The public Node surface keeps policy admission separate from the generic
/// delegation and invocation data plane. Share-specific data routes are not
/// mounted.
fn production_routes(named_keys_v1: bool) -> Vec<Route> {
    let mut routes = rocket::routes![
        healthcheck,
        cors,
        info,
        version,
        node_keys,
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
        get_stats,
        create_encryption_network,
        get_encryption_network,
        encryption_well_known,
        encryption_decrypt,
        revoke_encryption_network,
        register_policy_v3,
        get_policy_v3_status,
        policy_v3_enforcer_binding,
        authorize_policy_v3_delivery,
        policy_v3_challenge,
        policy_v3_mint,
        policy_v3_status,
        revoke_policy_v3_root,
    ];
    if named_keys_v1 {
        routes.extend(named_key_routes());
    }
    routes
}

pub async fn app_with_control(
    config: &Figment,
    tinycloud_config: &Config,
    control: Option<ControlPlaneHandle>,
) -> Result<Rocket<Build>> {
    let tinycloud_config = resolve_runtime_config(tinycloud_config)?;
    let request_id_origins =
        tracing::RequestIdOrigins::new(&tinycloud_config.log.request_id_first_party_origins)
            .map_err(anyhow::Error::msg)?;
    let quota_url = std::env::var("TINYCLOUD_QUOTA_URL").ok();
    let egress_policy = Arc::new(egress::EgressPolicy::from_config(
        &tinycloud_config,
        quota_url.as_deref(),
    )?);
    if egress_policy.refresh().await.is_err() {
        ::tracing::warn!("webhook egress closed: internal endpoint lookup failed");
    }
    tinycloud_core::did_resolution::configure(
        tinycloud_core::did_resolution::DidResolutionPolicy {
            network_methods: tinycloud_config.did_resolution.network_methods,
        },
    );
    tinycloud_core::did_resolution::set_refusal_observer(
        prometheus::observe_did_resolution_refused,
    );
    lazy_static::initialize(&prometheus::DID_RESOLUTION_REFUSED);

    // Ensure local storage directories exist.
    // SQLite file paths and local dirs are resources the server owns — auto-create them.
    // Remote backends (Postgres, S3) are left alone; connection errors surface naturally.
    ensure_local_dirs(&tinycloud_config.storage).await?;

    prometheus::set_enabled(tinycloud_config.telemetry.enabled);

    // `log_level` (`TINYCLOUD_LOG_LEVEL`) sets the default application log
    // level; `RUST_LOG` overrides it.
    tracing::tracing_try_init(
        &tinycloud_config.log,
        config.extract_inner::<rocket::config::LogLevel>("log_level")?,
    )?;

    ::tracing::info!(network_methods = tinycloud_config.did_resolution.network_methods,
        offline_methods = ?tinycloud_core::did_resolution::OFFLINE_DID_METHODS, "did resolution policy");
    if tinycloud_config.did_resolution.network_methods {
        ::tracing::warn!("network DID resolution enabled: did:web/did:tz fetches use the unhardened ssi client (TC-1080)");
    }

    let routes = production_routes(tinycloud_config.encryption_network.named_keys_v1);
    #[cfg(feature = "tc-bench-v1")]
    let mut routes = routes;

    #[cfg(feature = "tc-bench-v1")]
    routes.extend(rocket::routes![
        tc_bench_auth_verify,
        tc_bench_kv_put,
        tc_bench_kv_get,
        tc_bench_block_put,
        tc_bench_block_get,
        tc_bench_health,
    ]);

    let key_setup: StaticSecret =
        match resolve_keys(&tinycloud_config.keys, &tinycloud_config.tee).await? {
            Some(key_setup) => key_setup,
            None => {
                // The node's stored identity, generated on its first start. The
                // control plane only probed it at spawn, so publish what serve
                // resolved.
                let identity = key_provider::resolve_identity_state(
                    Some(&tinycloud_config.keys),
                    &tinycloud_config.storage.datadir,
                    IdentityPurpose::Serve,
                )?;
                if let Some(control) = control.as_ref() {
                    control
                        .set_identity_snapshot(key_provider::identity_snapshot(&identity))
                        .await;
                }
                identity
                    .secret
                    .ok_or_else(|| anyhow::anyhow!("node identity is not ready"))?
            }
        };
    let pseudonymizer =
        std::sync::Arc::new(tinycloud_core::telemetry::Pseudonymizer::new(&key_setup));
    let tracing_fairing = tracing::TracingFairing::new(
        &tinycloud_config.log.tracing,
        std::sync::Arc::clone(&pseudonymizer),
    );
    // TC-359: publish the derived public halves so an operator can read the
    // invitation key a dstack-keyed node actually signs with.
    let node_public_keys = NodePublicKeys::derive(&key_setup);
    let webhook_encryption =
        ColumnEncryption::new(key_setup.derive_key(b"tinycloud/hooks/webhook-secrets"));
    let hook_runtime = HookRuntime::new(
        tinycloud_config.hooks.clone(),
        key_setup.derive_key(hooks::HOOK_TICKET_KEY_CONTEXT),
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

    let database_connection = connect_database(&tinycloud_config).await?;
    // SQL/DuckDB artifact-size mirror folded into `store_size`. Empty here;
    // wired into SpaceDatabase, then seeded
    // from DB truth AFTER `TinyCloud::new` runs migrations (see below).
    let sql_sizes = SqlSizes::new();
    let seed_conn = database_connection.clone();

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

    let tinycloud = TinyCloud::new_with_encryption(
        database_connection,
        tinycloud_config.storage.blocks.open().await?,
        key_setup.setup(()).await?,
        Some(webhook_encryption.clone()),
    )
    .await?
    .with_sql_sizes(sql_sizes.clone())
    .with_delegated_sql_caveats(tinycloud_config.sql.delegated_caveats_enforced)
    .with_named_keys(tinycloud_config.encryption_network.named_keys_v1);
    tinycloud.set_read_audit_wait(Duration::from_millis(
        tinycloud_config.database.read_audit_wait_ms,
    ));
    let encryption_service =
        encryption_service.with_sqlite_writer_lock(tinycloud.sqlite_writer_lock());
    // Runs after the migrations: a key row under `apps/` that is not a
    // deletable key stops the node from starting.
    tinycloud_core::encryption_network::keys::ensure_no_deterministic_app_keys(&seed_conn).await?;
    let database_artifact_repository: Arc<dyn DatabaseArtifactRepository> =
        Arc::new(SizeTrackingArtifactRepository::new(
            Arc::new(node_artifact_repository(&tinycloud)),
            sql_sizes.clone(),
        ));

    // Seed the SQL-size mirror AFTER `TinyCloud::new` ran migrations — the
    // `database_artifact` table now exists (seeding before migrations would
    // fail boot on a fresh datadir). Runs before Rocket serves any request.
    sql_sizes.seed_from(&seed_conn).await?;
    // TC-1578: the S3 block store sizes spaces from objects with bytes, so a
    // hosted space with no blocks has no entry after a restart. Give every
    // space in the table one (existing byte counts are kept).
    let seeded_spaces = tinycloud.seed_store_sizes().await?;
    ::tracing::info!(spaces = seeded_spaces, "seeded block-store space sizes");
    #[cfg(feature = "tc-bench-v1")]
    let bench_state = BenchState::new(
        &tinycloud_config.tc_bench,
        seed_conn.clone(),
        if tinycloud_config.storage.database().starts_with("sqlite") {
            1
        } else {
            100
        },
    )
    .await?;

    let sql_service = SqlService::new(
        tinycloud_config.storage.sql.path.clone().expect("resolved"),
        tinycloud_config.storage.sql.memory_threshold.as_u64(),
        database_artifact_repository.clone(),
    )
    .with_wait_bounds(tinycloud_config.storage.sql.wait_bounds())
    .with_durability(tinycloud_config.storage.sql.durability())
    .with_ddl_policy(tinycloud_config.storage.sql.ddl_requires_schema);

    let mut policy_v3_runtime =
        PolicyV3Runtime::new(seed_conn.clone(), key_setup.node_did(), key_setup.clone())
            .with_sqlite_writer_lock(tinycloud.sqlite_writer_lock());
    if tinycloud_config.share_email.enabled {
        policy_v3_runtime = policy_v3_runtime.with_delivery(&tinycloud_config.share_email)?;
    }
    // The pinned issuer set is built (and every set-load rule applied) whether
    // or not share-email is enabled; a violation stops the node from starting.
    let credential_issuers = tinycloud_config.share_email.credential_issuer_set()?;
    if !credential_issuers.is_empty() {
        policy_v3_runtime = policy_v3_runtime.with_credential_issuers(credential_issuers);
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

    // Billing shares TINYCLOUD_ADMIN_SECRET with the node (it calls the
    // node's admin API with it) and accepts it on quota fetches (TC-627).
    let quota_cache = QuotaCache::new(tinycloud_config.storage.limit, quota_url)
        .with_request_id_origins(&request_id_origins)
        .with_service_secret(std::env::var("TINYCLOUD_ADMIN_SECRET").ok());
    let invocation_replay_cache = node_replay_cache(&tinycloud);
    let replay_cleanup = invocation_replay_cache.clone();
    // TC-341: the periodic sweep also reclaims rows beyond the lifetime cap.
    let replay_max_lifetime_secs = tinycloud_config.invocation.max_lifetime_secs;

    let rate_limiter = RateLimiter::new(&tinycloud_config.public_spaces);
    let webhook_dispatcher = WebhookDispatcher::new(
        tinycloud.clone(),
        tinycloud_config.hooks.clone(),
        webhook_encryption.clone(),
        egress_policy.clone(),
    )?;
    spawn_webhook_dispatcher(webhook_dispatcher);

    // TC-326: capture handles for the telemetry DB sampler before `tinycloud`
    // is moved into Rocket-managed state below.
    let telemetry_enabled = tinycloud_config.telemetry.enabled;
    let telemetry_tinycloud = tinycloud.clone();
    let backfill_tinycloud = tinycloud.clone();

    let rocket = rocket::custom(config)
        .attach(AdHoc::on_liftoff("webhook-egress-refresh", {
            let policy = egress_policy.clone();
            move |rocket| {
                let policy = policy.clone();
                let shutdown = rocket.shutdown();
                Box::pin(async move {
                    tokio::spawn(egress::run_refresh(policy, shutdown));
                })
            }
        }))
        .mount(
            "/",
            routes
                .into_iter()
                .map(tracing::instrument_route)
                .collect::<Vec<_>>(),
        )
        .attach(AdHoc::config::<Config>())
        .attach(tracing_fairing)
        .attach(AdHoc::on_liftoff(
            "invocation-replay-cleanup",
            move |rocket| {
                let replay_cleanup = replay_cleanup.clone();
                let shutdown = rocket.shutdown();
                Box::pin(async move {
                    tokio::spawn(async move {
                        let _ = replay_cleanup
                            .cleanup(time::OffsetDateTime::now_utc(), replay_max_lifetime_secs)
                            .await;
                        let period = std::time::Duration::from_secs(60);
                        let mut interval =
                            tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                        tokio::pin!(shutdown);
                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    let _ = replay_cleanup
                                        .cleanup(
                                            time::OffsetDateTime::now_utc(),
                                            replay_max_lifetime_secs,
                                        )
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
        .manage(node_public_keys)
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
        .manage(egress_policy)
        .manage(rate_limiter)
        .manage(tee_context)
        .manage(encryption_service)
        .manage(policy_v3_runtime)
        .manage(seed_conn.clone())
        .manage(tinycloud_config.storage.staging.open().await?);

    // TC-287: opt-in retention sweeper. Mirrors the invocation-replay cleanup
    // fairing above — an on-liftoff task that prunes terminal hook deliveries
    // and expired signed KV tickets every 5 minutes and stops on shutdown.
    let rocket = if tinycloud_config.retention.enabled {
        let retention_conn = seed_conn.clone();
        let retention_config = tinycloud_config.retention.clone();
        rocket.attach(AdHoc::on_liftoff("retention-sweeper", move |rocket| {
            let retention_conn = retention_conn.clone();
            let retention_config = retention_config.clone();
            let shutdown = rocket.shutdown();
            Box::pin(async move {
                tokio::spawn(async move {
                    run_retention_sweep(&retention_conn, &retention_config).await;
                    let period = std::time::Duration::from_secs(300);
                    let mut interval =
                        tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                    tokio::pin!(shutdown);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                run_retention_sweep(&retention_conn, &retention_config).await;
                            }
                            _ = &mut shutdown => break,
                        }
                    }
                });
            })
        }))
    } else {
        rocket
    };

    // TC-1274: one gentle pass that fills the `epoch_head` cache of spaces
    // written before it existed. Writes stay correct without it.
    let rocket = if tinycloud_config.epoch_head_backfill.enabled {
        let backfill_config = tinycloud_config.epoch_head_backfill.clone();
        rocket.attach(AdHoc::on_liftoff("epoch-head-backfill", move |rocket| {
            let tinycloud = backfill_tinycloud.clone();
            let backfill_config = backfill_config.clone();
            let shutdown = rocket.shutdown();
            Box::pin(async move {
                tokio::spawn(async move {
                    epoch_head_backfill::run(&tinycloud, &backfill_config, shutdown).await;
                });
            })
        }))
    } else {
        rocket
    };

    // TC-326: pool + read-audit telemetry sampler. Gated on telemetry.enabled;
    // an on-liftoff task that samples the DB pool gauges, probes pool-acquire
    // latency, and advances the read-audit commit counters every 5 seconds,
    // stopping on shutdown. Mirrors the retention-sweeper fairing above.
    let rocket = if telemetry_enabled {
        let telemetry_conn = seed_conn.clone();
        rocket.attach(AdHoc::on_liftoff("telemetry-db-sampler", move |rocket| {
            let telemetry_conn = telemetry_conn.clone();
            let telemetry_tinycloud = telemetry_tinycloud.clone();
            let shutdown = rocket.shutdown();
            Box::pin(async move {
                tokio::spawn(async move {
                    let mut last_read_audit = tinycloud_core::ReadAuditHealth::default();
                    let period = std::time::Duration::from_secs(5);
                    let mut interval =
                        tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                    tokio::pin!(shutdown);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                sample_db_telemetry(
                                    &telemetry_conn,
                                    &telemetry_tinycloud,
                                    &mut last_read_audit,
                                )
                                .await;
                            }
                            _ = &mut shutdown => break,
                        }
                    }
                });
            })
        }))
    } else {
        rocket
    };

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
    let rocket = attach_response_fairings(rocket, share_allowed_origin);

    if tinycloud_config.cors {
        Ok(rocket.attach(cors_fairing()))
    } else {
        Ok(rocket)
    }
}

/// The response fairings every node mounts, in the order they must run.
///
/// [`no_transform_fairing`] runs after [`share_security_fairing`] because that
/// fairing replaces `Cache-Control` on the share paths.
fn attach_response_fairings(rocket: Rocket<Build>, share_allowed_origin: String) -> Rocket<Build> {
    rocket
        .attach(share_security_fairing(share_allowed_origin))
        .attach(retry_after_fairing())
        .attach(no_transform_fairing())
}

/// `Cache-Control: no-transform` on every response that carries an `ETag`
/// (TC-1432).
///
/// A CDN that re-encodes a response (gzip/brotli) must turn a strong `ETag`
/// into a weak one (RFC 9110 8.8.3), and a weak `ETag` is refused by `If-Match`
/// (RFC 9110 13.1.1). TinyCloud's KV compare-and-swap needs the strong
/// `"blake3-<hex>"` value to survive the edge, so the node forbids the
/// re-encoding. Existing `Cache-Control` directives are kept. Responses
/// without an `ETag` are untouched.
fn no_transform_fairing() -> AdHoc {
    AdHoc::on_response("etag-no-transform", |_, response| {
        Box::pin(async move { add_no_transform_to_etag_response(response) })
    })
}

fn add_no_transform_to_etag_response(response: &mut rocket::Response<'_>) {
    if !response.headers().contains("ETag") {
        return;
    }
    let existing: Vec<String> = response
        .headers()
        .get("Cache-Control")
        .map(str::to_owned)
        .collect();
    let has_no_transform = existing.iter().any(|value| {
        value.split(',').any(|directive| {
            directive
                .split('=')
                .next()
                .is_some_and(|name| name.trim().eq_ignore_ascii_case("no-transform"))
        })
    });
    if has_no_transform {
        return;
    }
    let mut directives: Vec<&str> = existing
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    directives.push("no-transform");
    response.set_header(Header::new("Cache-Control", directives.join(", ")));
}

/// How long, in seconds, a browser may reuse a CORS preflight result for the
/// generic data plane before sending another `OPTIONS`.
///
/// Without `Access-Control-Max-Age` Chromium caches a preflight for only 5 s,
/// so most `/invoke` calls paid an extra round trip through the TEE gateway.
/// 7200 is Chromium's upper bound (Firefox allows 86400; WebKit clamps to
/// 600). It also bounds how long a browser can keep acting on a cached
/// preflight after the policy in [`cors_fairing`] is tightened.
const CORS_PREFLIGHT_MAX_AGE_SECS: u32 = 7200;

/// `Retry-After` on a failure that is safe to retry (TC-1054, TC-1274).
///
/// Routes report these as plain-text `(Status, String)` `503`s whose body
/// starts with [`routes::UNAVAILABLE_RETRYABLE`] or
/// [`routes::REQUEST_TIMEOUT`] (`Retry-After: 1`), or [`routes::SQL_BUSY`]
/// (`Retry-After: 5`). Other `503`s (cutover fence, missing configuration)
/// and the `500` [`routes::OUTCOME_UNKNOWN`] get no header.
fn retry_after_fairing() -> AdHoc {
    AdHoc::on_response("Retry-After", |_, resp| {
        Box::pin(async move {
            if resp.status() != rocket::http::Status::ServiceUnavailable {
                return;
            }
            let Ok(body) = resp.body_mut().to_string().await else {
                return;
            };
            let retry_after = if body.starts_with(routes::SQL_BUSY)
                || body.starts_with(routes::READ_AUDIT_BUSY)
            {
                Some(routes::SQL_BUSY_RETRY_AFTER_SECS)
            } else if body.starts_with(routes::UNAVAILABLE_RETRYABLE)
                || body.starts_with(routes::REQUEST_TIMEOUT)
            {
                Some(routes::RETRY_AFTER_SECS)
            } else {
                None
            };
            if let Some(secs) = retry_after {
                resp.set_header(Header::new("Retry-After", secs.to_string()));
            }
            resp.set_sized_body(body.len(), std::io::Cursor::new(body));
        })
    })
}

fn cors_fairing() -> AdHoc {
    AdHoc::on_response("CORS", |request, resp| {
        Box::pin(async move {
            if is_mounted_share_path(request.uri().path().as_str()) {
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
                "*, Authorization, X-Request-Id",
            ));
            resp.set_header(Header::new(
                // allow custom headers + Authorization in requests
                "Access-Control-Allow-Headers",
                "*, Authorization, X-Request-Id",
            ));
            resp.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
            if request.method() == Method::Options {
                // only meaningful on a preflight response; lets the browser
                // skip the OPTIONS round trip on subsequent requests
                resp.set_header(Header::new(
                    "Access-Control-Max-Age",
                    CORS_PREFLIGHT_MAX_AGE_SECS.to_string(),
                ));
            }
        })
    })
}

fn share_security_fairing(share_allowed_origin: String) -> AdHoc {
    AdHoc::on_response("share-email-security-headers", move |request, response| {
        let share_allowed_origin = share_allowed_origin.clone();
        Box::pin(async move {
            if is_mounted_share_path(request.uri().path().as_str()) {
                response.set_header(Header::new("Cache-Control", "no-store"));
                response.set_header(Header::new("X-Content-Type-Options", "nosniff"));
                response.set_header(Header::new("Referrer-Policy", "no-referrer"));
                response.set_header(Header::new(
                    "Access-Control-Allow-Origin",
                    share_allowed_origin,
                ));
                response.set_header(Header::new("Access-Control-Allow-Methods", "GET, POST"));
                response.set_header(Header::new(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization, X-Request-Id",
                ));
                response.set_header(Header::new("Access-Control-Expose-Headers", "X-Request-Id"));
            }
        })
    })
}

fn is_mounted_share_path(path: &str) -> bool {
    path.starts_with("/policy/v3/")
}

#[cfg(test)]
mod production_route_tests {
    use super::{named_key_routes, production_routes};

    #[test]
    fn generic_data_plane_and_embedded_policy_admission_are_mounted_without_share_data_routes() {
        let routes: std::collections::HashSet<_> = production_routes(true)
            .into_iter()
            .map(|route| format!("{} {}", route.method, route.uri))
            .collect();

        // The four routes the post-deploy workflow probes
        // (.github/workflows/docker.yml, guarded by
        // scripts/check-deployment-policy-probes.mjs) must all be mounted, or
        // a release deploys, mutates production, and only then fails its probe.
        for route in [
            "POST /delegate",
            "POST /invoke",
            "POST /policy/v3/enforcer-bindings",
            "POST /policy/v3/policies",
            "POST /policy/v3/challenges",
            "POST /policy/v3/delegations",
            "POST /policy/v3/deliveries/authorize",
        ] {
            assert!(routes.contains(route), "missing required route: {route}");
        }
        for route in [
            "POST /share/v1/read",
            "POST /share/v2/invoke",
            "POST /share/v2/deliveries/authorize",
            "POST /share/v3/policy/challenges",
            "POST /share/v3/policy/delegations",
        ] {
            assert!(
                !routes.contains(route),
                "retired share data route is mounted: {route}"
            );
        }
        assert!(
            routes
                .iter()
                .all(|route| !route.split_once(' ').unwrap().1.starts_with("/share/")),
            "production routes must not mount any /share/* handler"
        );
    }

    /// The five key routes are mounted only with `named_keys_v1` on; the
    /// network routes are mounted either way.
    #[test]
    fn named_key_routes_are_mounted_only_when_named_keys_are_on() {
        let describe = |routes: Vec<rocket::Route>| -> Vec<String> {
            routes
                .into_iter()
                .map(|route| format!("{} {}", route.method, route.uri))
                .collect()
        };
        let key_routes = describe(named_key_routes());
        assert_eq!(key_routes.len(), 5, "{key_routes:?}");
        let off = describe(production_routes(false));
        let on = describe(production_routes(true));
        for route in &key_routes {
            assert!(!off.contains(route), "mounted while off: {route}");
            assert!(on.contains(route), "missing while on: {route}");
        }
        for route in [
            "POST /encryption/networks",
            "GET /encryption/networks/<network_id>",
            "POST /encryption/networks/<network_id>/decrypt",
            "POST /encryption/networks/<network_id>/revoke",
        ] {
            let route = route.to_string();
            assert!(off.contains(&route), "missing while off: {route}");
            assert!(on.contains(&route), "missing while on: {route}");
        }
        assert_eq!(on.len(), off.len() + 5);
    }
}

/// One telemetry sample tick: update the DB pool gauges, probe pool-acquire
/// latency (the `DbPoolAcquire` span), and update the read-audit metrics.
/// `last_read_audit` carries the previous cumulative counts so the monotonic
/// counters advance by deltas.
///
/// sea-orm couples pool acquisition with `BEGIN` on the generic connection, so
/// the request-path `DbTxBegin` span cannot separate the two. This sampler is
/// the one place the concrete pool is reachable, so it hosts the standalone
/// pool-acquire probe (bounded by a short timeout so it never delays shutdown).
async fn sample_db_telemetry(
    conn: &RecoveringConnection,
    tinycloud: &TinyCloud,
    last_read_audit: &mut tinycloud_core::ReadAuditHealth,
) {
    use tinycloud_core::sea_orm::{ConnectionTrait, DatabaseBackend};

    macro_rules! sample_pool {
        ($pool:expr) => {{
            let pool = $pool;
            crate::prometheus::set_db_pool_gauges(pool.size() as i64, pool.num_idle() as i64);
            let acquire_start = std::time::Instant::now();
            let acquired =
                tokio::time::timeout(std::time::Duration::from_secs(2), pool.acquire()).await;
            crate::prometheus::observe_stage(
                crate::prometheus::InvocationStage::DbPoolAcquire,
                crate::prometheus::StageOutcome::from(matches!(acquired, Ok(Ok(_)))),
                acquire_start.elapsed(),
            );
        }};
    }
    let pool = conn.sea_orm_connection();
    match pool.get_database_backend() {
        DatabaseBackend::Postgres => sample_pool!(pool.get_postgres_connection_pool()),
        DatabaseBackend::Sqlite => sample_pool!(pool.get_sqlite_connection_pool()),
        DatabaseBackend::MySql => sample_pool!(pool.get_mysql_connection_pool()),
    }

    let read_audit = tinycloud.read_audit_health();
    crate::prometheus::observe_read_audit(last_read_audit, &read_audit);
    *last_read_audit = read_audit;
}

/// Run one retention sweep: prune terminal hook deliveries and expired signed
/// KV tickets older than the configured windows, in bounded batches. Errors are
/// logged (not fatal) — this is a periodic background maintenance pass.
async fn run_retention_sweep<C: tinycloud_core::sea_orm::ConnectionTrait>(
    conn: &C,
    retention: &config::RetentionConfig,
) {
    use time::format_description::well_known::Rfc3339;

    let now = time::OffsetDateTime::now_utc();
    let cutoff = |days: u32| {
        (now - time::Duration::days(days as i64))
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339")
    };

    let delivered_before = cutoff(retention.hook_delivered_days);
    match tinycloud_core::db::prune_delivered_hook_deliveries(
        conn,
        &delivered_before,
        retention.batch_rows,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            ::tracing::info!(deleted, "retention: pruned delivered hook deliveries")
        }
        Ok(_) => {}
        Err(error) => {
            ::tracing::warn!(
                error_class =
                    tinycloud_core::db_pool::transient_error_class(&error).unwrap_or("database"),
                "retention: delivered hook delivery prune failed"
            )
        }
    }

    let dead_letter_before = cutoff(retention.hook_dead_letter_days);
    match tinycloud_core::db::prune_dead_letter_hook_deliveries(
        conn,
        &dead_letter_before,
        retention.batch_rows,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            ::tracing::info!(deleted, "retention: pruned dead-letter hook deliveries")
        }
        Ok(_) => {}
        Err(error) => {
            ::tracing::warn!(
                error_class =
                    tinycloud_core::db_pool::transient_error_class(&error).unwrap_or("database"),
                "retention: dead-letter hook delivery prune failed"
            )
        }
    }

    let expired_before = cutoff(retention.ticket_expired_days);
    match tinycloud_core::db::prune_expired_signed_kv_tickets(
        conn,
        &expired_before,
        retention.batch_rows,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            ::tracing::info!(deleted, "retention: pruned expired signed KV tickets")
        }
        Ok(_) => {}
        Err(error) => ::tracing::warn!(
            error_class =
                tinycloud_core::db_pool::transient_error_class(&error).unwrap_or("database"),
            "retention: signed KV ticket prune failed"
        ),
    }
}

/// The node key from a Static or dstack key source. `None` means the key is
/// the node's stored identity: provider keys, and Auto outside a TEE. Where
/// the environment indicates a dstack TEE, provider keys always refuse and
/// Auto refuses when no dstack key is available, so a TEE node never runs
/// under a local DID. For Auto, `TINYCLOUD_TEE_MODE=off` is checked first and
/// opts out of TEE detection.
pub(crate) async fn resolve_keys(
    keys: &Keys,
    tee: &config::TeeConfig,
) -> Result<Option<StaticSecret>> {
    match keys {
        Keys::Static(s) => Ok(Some(s.clone().try_into()?)),
        #[cfg(feature = "dstack")]
        Keys::Dstack => {
            let key_bytes = dstack::get_key("tinycloud/keys/primary").await?;
            StaticSecret::new(key_bytes)
                .map(Some)
                .map_err(|v| anyhow::anyhow!("dstack key too short: {} bytes", v.len()))
        }
        Keys::Auto => {
            // Check TINYCLOUD_TEE_MODE env var first
            match std::env::var("TINYCLOUD_TEE_MODE").ok().as_deref() {
                #[cfg(feature = "dstack")]
                Some("dstack") => {
                    let key_bytes = dstack::get_key("tinycloud/keys/primary").await?;
                    StaticSecret::new(key_bytes)
                        .map(Some)
                        .map_err(|v| anyhow::anyhow!("dstack key too short: {} bytes", v.len()))
                }
                Some("off") => Ok(None),
                _ => {
                    // Auto-detect: check for dstack socket
                    #[cfg(feature = "dstack")]
                    if dstack::is_available() {
                        ::tracing::info!("dstack socket detected, using TEE key derivation");
                        let key_bytes = dstack::get_key("tinycloud/keys/primary").await?;
                        return StaticSecret::new(key_bytes).map(Some).map_err(|v| {
                            anyhow::anyhow!("dstack key too short: {} bytes", v.len())
                        });
                    }
                    if let Some(hint) = dstack_indication(tee) {
                        anyhow::bail!(
                            "refusing to create a new node identity: {hint} indicates a dstack TEE, \
                             but no dstack key is available (socket {}{}). Start the node with its \
                             dstack socket, or remove {hint} if this host is not a TEE.",
                            dstack::socket_path(),
                            if cfg!(feature = "dstack") {
                                ""
                            } else {
                                "; this build has no dstack support"
                            },
                        );
                    }
                    Ok(None)
                }
            }
        }
        Keys::Provider => {
            if let Some(hint) = dstack_indication(tee) {
                anyhow::bail!(
                    "refusing keys.type = provider: {hint} indicates a dstack TEE, where the node \
                     key must come from dstack. Use keys.type = Dstack, or remove {hint} if this \
                     host is not a TEE."
                );
            }
            Ok(None)
        }
    }
}

/// Why the environment looks like a dstack deployment, if it does: the TEE
/// mode the node reads, the key type dstack deployments set, an explicit
/// dstack socket, or a dstack socket this build cannot use. Variable names
/// match case-insensitively, as figment's `TINYCLOUD_` prefix does.
fn dstack_indication(tee: &config::TeeConfig) -> Option<&'static str> {
    let env_is_dstack = |name: &str| {
        std::env::vars_os().any(|(key, value)| {
            key.to_str()
                .is_some_and(|key| key.eq_ignore_ascii_case(name))
                && value
                    .to_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case("dstack"))
        })
    };
    if env_is_dstack("TINYCLOUD_TEE_MODE") {
        Some("TINYCLOUD_TEE_MODE=dstack")
    } else if tee.mode == config::TeeMode::Dstack {
        Some("tee.mode = \"Dstack\"")
    } else if env_is_dstack("TINYCLOUD_KEYS_TYPE") || env_is_dstack("TINYCLOUD_KEYS__TYPE") {
        Some("TINYCLOUD_KEYS_TYPE=Dstack")
    } else if std::env::var_os("DSTACK_SIMULATOR_ENDPOINT").is_some() {
        Some("DSTACK_SIMULATOR_ENDPOINT")
    } else if dstack::is_available() {
        Some("the dstack socket")
    } else {
        None
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
    use tinycloud_core::sea_orm::{
        ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement,
    };

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

    async fn artifact_save_preserves_delegation_snapshot(delta: bool) {
        use tinycloud_core::{
            database_artifacts::ArtifactExpectation,
            hash::hash,
            models::{actor, delegation},
            sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, PaginatorTrait},
            storage::{either::Either, StorageConfig},
        };

        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("caps.db").display()
        );
        let connection = Database::connect(sqlite_connect_options(&url))
            .await
            .unwrap();
        let blocks = storage::file_system::FileSystemConfig::new(directory.path().join("blocks"))
            .open()
            .await
            .unwrap();
        let node = TinyCloud::new(
            connection.into(),
            Either::B(blocks),
            tinycloud_core::keys::StaticSecret::new(vec![7u8; 64]).unwrap(),
        )
        .await
        .unwrap();
        // Exercise the production repository wiring as well as its write path.
        let repository = node_artifact_repository(&node);
        let actor_id = "did:key:artifact-snapshot-fixture";
        actor::ActiveModel {
            id: Set(actor_id.to_owned()),
        }
        .insert(node.connection())
        .await
        .unwrap();
        repository
            .save(
                "sql",
                "space",
                "main",
                vec![1; 100],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();

        let gate = node.sqlite_writer_lock().unwrap();
        let writer = gate.lock().await;
        let transaction = node.readable().await.unwrap();
        delegation::Entity::find()
            .count(&transaction)
            .await
            .unwrap();
        let mut save = tokio::spawn(async move {
            if delta {
                repository
                    .save_delta(
                        "sql",
                        "space",
                        "main",
                        vec![2; 12],
                        ArtifactExpectation::Any,
                    )
                    .await
                    .map(|saved| saved.revision)
            } else {
                repository
                    .save(
                        "sql",
                        "space",
                        "main",
                        vec![3; 120],
                        ArtifactExpectation::Any,
                    )
                    .await
                    .map(|saved| saved.revision)
            }
        });
        let early = tokio::time::timeout(std::time::Duration::from_millis(100), &mut save).await;

        delegation::ActiveModel {
            id: Set(hash(b"artifact-delegation-write-snapshot")),
            delegator: Set(actor_id.to_owned()),
            delegatee: Set(actor_id.to_owned()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(b"synthetic database race fixture".to_vec()),
        }
        .insert(&transaction)
        .await
        .expect("artifact persistence must not invalidate the delegation snapshot");
        transaction.commit().await.unwrap();
        assert!(
            early.is_err(),
            "artifact persistence must wait for the node's writer gate"
        );
        drop(writer);
        assert_eq!(save.await.unwrap().unwrap(), 2);
    }

    #[tokio::test]
    async fn artifact_checkpoint_cannot_invalidate_a_delegation_write_snapshot() {
        artifact_save_preserves_delegation_snapshot(false).await;
    }

    #[tokio::test]
    async fn artifact_delta_cannot_invalidate_a_delegation_write_snapshot() {
        artifact_save_preserves_delegation_snapshot(true).await;
    }
}

#[cfg(test)]
mod share_security_fairing_tests {
    use super::share_security_fairing;
    use rocket::{http::Header, local::asynchronous::Client, options, routes};

    #[options("/policy/v3/challenges")]
    fn policy_admission_preflight() {}

    #[options("/v1/config")]
    fn non_share_preflight() {}

    #[tokio::test]
    async fn chromium_policy_admission_preflight_allows_authorization() {
        let client = Client::tracked(
            rocket::build()
                .mount(
                    "/",
                    routes![policy_admission_preflight, non_share_preflight],
                )
                .attach(share_security_fairing("https://share.tinycloud.xyz".into())),
        )
        .await
        .expect("valid Rocket instance");

        for path in ["/policy/v3/challenges"] {
            let response = client
                .options(path)
                .header(Header::new("Origin", "https://share.tinycloud.xyz"))
                .header(Header::new("Access-Control-Request-Method", "POST"))
                .header(Header::new(
                    "Access-Control-Request-Headers",
                    "authorization,content-type,x-request-id",
                ))
                .dispatch()
                .await;

            assert_eq!(response.status(), rocket::http::Status::Ok, "{path}");
            assert_eq!(
                response.headers().get_one("Access-Control-Allow-Origin"),
                Some("https://share.tinycloud.xyz"),
                "{path}"
            );
            let methods: std::collections::BTreeSet<_> = response
                .headers()
                .get_one("Access-Control-Allow-Methods")
                .unwrap()
                .split(',')
                .map(str::trim)
                .collect();
            assert_eq!(methods, std::collections::BTreeSet::from(["GET", "POST"]));
            let allowed = response
                .headers()
                .get_one("Access-Control-Allow-Headers")
                .unwrap()
                .to_ascii_lowercase();
            let allowed: std::collections::BTreeSet<_> =
                allowed.split(',').map(str::trim).collect();
            assert_eq!(
                allowed,
                std::collections::BTreeSet::from(
                    ["authorization", "content-type", "x-request-id",]
                )
            );
            assert!(response
                .headers()
                .get_one("Access-Control-Expose-Headers")
                .unwrap()
                .split(',')
                .any(|name| name.trim().eq_ignore_ascii_case("x-request-id")));
        }
    }

    #[tokio::test]
    async fn non_share_preflight_does_not_receive_share_cors_headers() {
        let client = Client::tracked(
            rocket::build()
                .mount(
                    "/",
                    routes![policy_admission_preflight, non_share_preflight],
                )
                .attach(share_security_fairing("https://share.tinycloud.xyz".into())),
        )
        .await
        .expect("valid Rocket instance");

        let response = client.options("/v1/config").dispatch().await;

        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert!(response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .is_none());
        assert!(response
            .headers()
            .get_one("Access-Control-Allow-Headers")
            .is_none());
    }
}

#[cfg(test)]
mod cors_fairing_tests {
    use super::{cors_fairing, share_security_fairing};
    use crate::routes::util_routes;
    use rocket::{
        http::{Header, Status},
        local::asynchronous::Client,
        post, routes,
    };

    #[post("/invoke")]
    fn invoke() {}

    /// Mirrors production: the real catch-all `OPTIONS` route, with the share
    /// fairing attached before the generic CORS fairing.
    async fn client() -> Client {
        Client::tracked(
            rocket::build()
                .mount("/", routes![util_routes::cors, invoke])
                .attach(share_security_fairing("https://share.tinycloud.xyz".into()))
                .attach(cors_fairing()),
        )
        .await
        .expect("valid Rocket instance")
    }

    #[tokio::test]
    async fn invoke_preflight_is_cacheable_without_widening_the_policy() {
        let client = client().await;
        let response = client
            .options("/invoke")
            .header(Header::new("Origin", "https://tinycloud.chat"))
            .header(Header::new("Access-Control-Request-Method", "POST"))
            .header(Header::new(
                "Access-Control-Request-Headers",
                "authorization,content-type,x-request-id",
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let headers = response.headers();
        assert_eq!(headers.get_one("Access-Control-Max-Age"), Some("7200"));
        assert_eq!(headers.get_one("Access-Control-Allow-Origin"), Some("*"));
        let methods: std::collections::BTreeSet<_> = headers
            .get_one("Access-Control-Allow-Methods")
            .unwrap()
            .split(',')
            .map(str::trim)
            .collect();
        assert_eq!(
            methods,
            std::collections::BTreeSet::from(["DELETE", "GET", "OPTIONS", "POST", "PUT",])
        );
        let allowed = headers
            .get_one("Access-Control-Allow-Headers")
            .unwrap()
            .to_ascii_lowercase();
        let allowed: std::collections::BTreeSet<_> = allowed.split(',').map(str::trim).collect();
        assert_eq!(
            allowed,
            std::collections::BTreeSet::from(["*", "authorization", "x-request-id"])
        );
        assert!(headers
            .get_one("Access-Control-Expose-Headers")
            .unwrap()
            .split(',')
            .any(|name| name.trim().eq_ignore_ascii_case("x-request-id")));
        assert_eq!(
            headers.get_one("Access-Control-Allow-Credentials"),
            Some("true")
        );
    }

    #[tokio::test]
    async fn max_age_is_not_sent_on_actual_or_share_responses() {
        let client = client().await;

        let response = client
            .post("/invoke")
            .header(Header::new("Origin", "https://tinycloud.chat"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Access-Control-Allow-Origin"),
            Some("*")
        );
        assert!(response
            .headers()
            .get_one("Access-Control-Max-Age")
            .is_none());

        // the share fairing owns /policy/v3/* and is left untouched
        let response = client
            .options("/policy/v3/challenges")
            .header(Header::new("Origin", "https://share.tinycloud.xyz"))
            .header(Header::new("Access-Control-Request-Method", "POST"))
            .dispatch()
            .await;
        assert_eq!(
            response.headers().get_one("Access-Control-Allow-Origin"),
            Some("https://share.tinycloud.xyz")
        );
        assert!(response
            .headers()
            .get_one("Access-Control-Max-Age")
            .is_none());
    }
}

#[cfg(test)]
mod did_resolution_test_support {
    include!("../../tinycloud-core/tests/support/did_resolution.rs");
}

#[cfg(test)]
mod retry_after_fairing_tests {
    use super::{cors_fairing, retry_after_fairing, routes};
    use rocket::{get, http::Status, local::asynchronous::Client, routes};

    #[get("/retryable")]
    fn retryable() -> (Status, String) {
        (
            Status::ServiceUnavailable,
            format!("{}: pool exhausted", routes::UNAVAILABLE_RETRYABLE),
        )
    }

    #[get("/unknown")]
    fn unknown() -> (Status, String) {
        (
            Status::InternalServerError,
            format!(
                "{}: the write may have been applied",
                routes::OUTCOME_UNKNOWN
            ),
        )
    }

    #[get("/fenced")]
    fn fenced() -> (Status, String) {
        (
            Status::ServiceUnavailable,
            "SQL identity cutover fence is active".to_string(),
        )
    }

    #[get("/busy")]
    fn busy() -> (Status, String) {
        let error =
            tinycloud_core::sql::SqlError::Busy(tinycloud_core::sql::SqlBusyStage::LockWait);
        (Status::ServiceUnavailable, error.to_string())
    }

    #[get("/timeout")]
    fn timeout() -> (Status, String) {
        (
            Status::ServiceUnavailable,
            routes::REQUEST_TIMEOUT_BODY.to_string(),
        )
    }

    #[get("/read-audit-busy")]
    fn read_audit_busy() -> (Status, String) {
        (
            Status::ServiceUnavailable,
            tinycloud_core::ReadAuditError::Busy.to_string(),
        )
    }

    /// TC-1054: clients tell a retryable database failure (503,
    /// `unavailable_retryable`, `Retry-After`) from one whose write may have
    /// applied (500, `outcome_unknown`, no `Retry-After`); CORS still applies.
    #[tokio::test]
    async fn only_retryable_database_failures_carry_retry_after() {
        let client = Client::tracked(
            rocket::build()
                .mount(
                    "/",
                    routes![retryable, unknown, fenced, busy, timeout, read_audit_busy],
                )
                .attach(retry_after_fairing())
                .attach(cors_fairing()),
        )
        .await
        .expect("valid Rocket instance");

        let response = client.get("/retryable").dispatch().await;
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(response.headers().get_one("Retry-After"), Some("1"));
        assert_eq!(
            response.headers().get_one("Access-Control-Allow-Origin"),
            Some("*")
        );
        let body = response.into_string().await.unwrap();
        assert_eq!(body, "unavailable_retryable: pool exhausted", "body kept");

        // TC-1274, TC-1317: a busy database or a backlogged read audit asks
        // for a longer pause than a request that timed out before writing.
        for (path, retry_after) in [("/busy", "5"), ("/read-audit-busy", "5"), ("/timeout", "1")] {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.status(), Status::ServiceUnavailable, "{path}");
            assert_eq!(
                response.headers().get_one("Retry-After"),
                Some(retry_after),
                "{path}"
            );
            assert_eq!(
                response.headers().get_one("Access-Control-Allow-Origin"),
                Some("*"),
                "{path}"
            );
        }

        for path in ["/unknown", "/fenced"] {
            let response = client.get(path).dispatch().await;
            assert!(
                response.headers().get_one("Retry-After").is_none(),
                "{path}"
            );
            assert_eq!(
                response.headers().get_one("Access-Control-Allow-Origin"),
                Some("*"),
                "{path}"
            );
            assert!(!response.into_string().await.unwrap().is_empty(), "{path}");
        }
    }

    /// An artifact store that never answers, so a cold SQL database never
    /// finishes hydrating.
    struct StalledArtifacts;

    #[async_trait::async_trait]
    impl tinycloud_core::database_artifacts::DatabaseArtifactRepository for StalledArtifacts {
        async fn load_meta(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<
            Option<tinycloud_core::database_artifacts::ArtifactMeta>,
            tinycloud_core::database_artifacts::DatabaseArtifactError,
        > {
            std::future::pending().await
        }

        async fn read_chunks(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &tinycloud_core::database_artifacts::ArtifactMeta,
            _: &mut dyn tinycloud_core::database_artifacts::ArtifactSink,
        ) -> Result<(), tinycloud_core::database_artifacts::DatabaseArtifactError> {
            std::future::pending().await
        }

        async fn save(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Vec<u8>,
            _: tinycloud_core::database_artifacts::ArtifactExpectation,
        ) -> Result<
            tinycloud_core::database_artifacts::DatabaseArtifact,
            tinycloud_core::database_artifacts::DatabaseArtifactError,
        > {
            std::future::pending().await
        }

        async fn save_delta(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Vec<u8>,
            _: tinycloud_core::database_artifacts::ArtifactExpectation,
        ) -> Result<
            tinycloud_core::database_artifacts::DeltaSave,
            tinycloud_core::database_artifacts::DatabaseArtifactError,
        > {
            std::future::pending().await
        }
    }

    /// A SQL read through the `/invoke` deadline wrapper and the real SQL
    /// service, as the route runs it.
    #[rocket::post("/stalled-sql")]
    async fn stalled_sql(
        config: &rocket::State<crate::config::Config>,
        sql: &rocket::State<tinycloud_core::sql::SqlService>,
        space: &rocket::State<tinycloud_auth::resource::SpaceId>,
    ) -> Result<String, routes::InvokeError> {
        routes::with_invoke_deadline(
            config,
            Box::pin(async move {
                sql.execute(
                    space,
                    "a",
                    tinycloud_core::sql::SqlRequest::Query {
                        sql: "SELECT 1".into(),
                        params: Vec::new(),
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                )
                .await
                .map(|_| "served".to_string())
                .map_err(|error| (routes::sql_error_to_status(&error), error.to_string()).into())
            }),
        )
        .await
    }

    /// TC-1274: over HTTP, a SQL request stalled in hydration is answered at
    /// the deadline with `503 request_timeout`, `Retry-After: 1` and CORS.
    #[tokio::test]
    async fn a_stalled_sql_request_is_answered_at_its_deadline() {
        use tinycloud_auth::{
            resolver::DID_METHODS,
            ssi::{dids::DIDBuf, jwk::JWK},
        };
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        let space = tinycloud_auth::resource::SpaceId::new(did, "default".parse().unwrap());
        let cache = tempfile::TempDir::new().unwrap();
        let sql = tinycloud_core::sql::SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            std::sync::Arc::new(StalledArtifacts),
        );
        let mut config = crate::config::Config::default();
        config.invocation.deadline_ms = 300;
        let client = Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![stalled_sql])
                .manage(config)
                .manage(sql)
                .manage(space)
                .attach(retry_after_fairing())
                .attach(cors_fairing()),
        )
        .await
        .expect("valid Rocket instance");

        let started = std::time::Instant::now();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.post("/stalled-sql").dispatch(),
        )
        .await
        .expect("the deadline must answer the request");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(response.headers().get_one("Retry-After"), Some("1"));
        assert_eq!(
            response.headers().get_one("Access-Control-Allow-Origin"),
            Some("*")
        );
        assert_eq!(
            response.into_string().await.unwrap(),
            routes::REQUEST_TIMEOUT_BODY
        );
    }
}

/// TC-1432: every `ETag`-bearing response forbids CDN re-encoding, which would
/// weaken the strong `ETag` that `If-Match` compare-and-swap needs.
#[cfg(test)]
mod no_transform_fairing_tests {
    use super::attach_response_fairings;
    use crate::{auth_guards::KVResponse, signed_urls::SignedKvReadResponse};
    use futures::io::Cursor;
    use rocket::{
        get,
        http::{Header, Status},
        local::asynchronous::Client,
        response::Response,
        routes,
    };
    use std::collections::BTreeMap;
    use tinycloud_core::{hash::hash, storage::Content, types::Metadata};

    const ETAG: &str =
        "\"blake3-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";

    struct Stub(Response<'static>);

    impl<'r> rocket::response::Responder<'r, 'static> for Stub {
        fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
            Ok(self.0)
        }
    }

    fn stub(
        etag: bool,
        cache_control: &'static [&'static str],
        status: Status,
    ) -> Response<'static> {
        let mut response = Response::build();
        response.status(status);
        if etag {
            response.header(Header::new("ETag", ETAG));
        }
        for value in cache_control {
            response.header_adjoin(Header::new("Cache-Control", *value));
        }
        response
            .sized_body(2, std::io::Cursor::new("ok"))
            .finalize()
    }

    #[get("/etag")]
    fn etag_only() -> Stub {
        Stub(stub(true, &[], Status::Ok))
    }

    #[get("/etag-private")]
    fn etag_private() -> Stub {
        Stub(stub(true, &["private, no-cache"], Status::Ok))
    }

    #[get("/etag-no-store")]
    fn etag_no_store() -> Stub {
        Stub(stub(true, &["no-store"], Status::Ok))
    }

    #[get("/etag-two-headers")]
    fn etag_two_headers() -> Stub {
        Stub(stub(true, &["private", "max-age=0"], Status::Ok))
    }

    #[get("/etag-already")]
    fn etag_already() -> Stub {
        Stub(stub(true, &["No-Transform, private"], Status::Ok))
    }

    #[get("/etag-empty-cache-control")]
    fn etag_empty_cache_control() -> Stub {
        Stub(stub(true, &[""], Status::Ok))
    }

    #[get("/etag-304")]
    fn etag_not_modified() -> Stub {
        Stub(stub(true, &["private, no-cache"], Status::NotModified))
    }

    #[get("/etag-412")]
    fn etag_precondition_failed() -> Stub {
        Stub(stub(true, &["private"], Status::PreconditionFailed))
    }

    #[get("/plain")]
    fn plain() -> Stub {
        Stub(stub(false, &[], Status::Ok))
    }

    #[get("/plain-cache")]
    fn plain_cache() -> Stub {
        Stub(stub(false, &["public, max-age=60"], Status::Ok))
    }

    #[get("/policy/v3/etag")]
    fn share_path_etag() -> Stub {
        Stub(stub(true, &["public, max-age=60"], Status::Ok))
    }

    #[get("/policy/v3/plain")]
    fn share_path_plain() -> Stub {
        Stub(stub(false, &[], Status::Ok))
    }

    #[get("/kv")]
    fn kv() -> KVResponse<Cursor<Vec<u8>>> {
        let content = b"hello".to_vec();
        KVResponse::new(
            Metadata(BTreeMap::new()),
            hash(&content),
            Content::new(content.len() as u64, Cursor::new(content)),
        )
    }

    #[get("/signed/<variant>")]
    fn signed(variant: &str) -> SignedKvReadResponse<Cursor<Vec<u8>>> {
        let hash = hash(b"hello world");
        let metadata = Metadata(BTreeMap::new());
        match variant {
            "full" => SignedKvReadResponse::Full {
                metadata,
                hash,
                content: Content::new(11, Cursor::new(b"hello world".to_vec())),
            },
            _ => SignedKvReadResponse::Unsatisfiable {
                hash,
                total_size: 11,
            },
        }
    }

    async fn client() -> Client {
        Client::tracked(attach_response_fairings(
            rocket::build().mount(
                "/",
                routes![
                    etag_only,
                    etag_private,
                    etag_no_store,
                    etag_two_headers,
                    etag_already,
                    etag_empty_cache_control,
                    etag_not_modified,
                    etag_precondition_failed,
                    plain,
                    plain_cache,
                    share_path_etag,
                    share_path_plain,
                    kv,
                    signed,
                ],
            ),
            "https://share.tinycloud.xyz".into(),
        ))
        .await
        .expect("valid Rocket instance")
    }

    async fn cache_control(client: &Client, path: &str) -> (Status, Vec<String>, bool) {
        let response = client.get(path).dispatch().await;
        let status = response.status();
        let values = response
            .headers()
            .get("Cache-Control")
            .map(str::to_owned)
            .collect();
        let etag = response.headers().get_one("ETag").is_some();
        (status, values, etag)
    }

    #[tokio::test]
    async fn etag_response_without_cache_control_gets_no_transform() {
        let client = client().await;
        let response = client.get("/etag").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.headers().get_one("ETag"), Some(ETAG));
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some("no-transform")
        );
        assert_eq!(response.into_string().await.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn existing_cache_control_directives_are_preserved() {
        let client = client().await;
        for (path, expected) in [
            ("/etag-private", "private, no-cache, no-transform"),
            ("/etag-no-store", "no-store, no-transform"),
            ("/etag-two-headers", "private, max-age=0, no-transform"),
            ("/etag-empty-cache-control", "no-transform"),
        ] {
            let (status, values, etag) = cache_control(&client, path).await;
            assert_eq!(status, Status::Ok, "{path}");
            assert!(etag, "{path}");
            assert_eq!(values, vec![expected.to_string()], "{path}");
        }
    }

    #[tokio::test]
    async fn an_existing_no_transform_is_not_duplicated() {
        let client = client().await;
        let (_, values, _) = cache_control(&client, "/etag-already").await;
        assert_eq!(values, vec!["No-Transform, private".to_string()]);
    }

    #[tokio::test]
    async fn not_modified_and_precondition_failed_etag_responses_get_no_transform() {
        let client = client().await;
        for (path, status) in [
            ("/etag-304", Status::NotModified),
            ("/etag-412", Status::PreconditionFailed),
        ] {
            let (got, values, etag) = cache_control(&client, path).await;
            assert_eq!(got, status, "{path}");
            assert!(etag, "{path}");
            assert_eq!(values.len(), 1, "{path}");
            assert!(values[0].ends_with(", no-transform"), "{path}: {values:?}");
        }
    }

    #[tokio::test]
    async fn responses_without_an_etag_are_unchanged() {
        let client = client().await;
        let (_, values, etag) = cache_control(&client, "/plain").await;
        assert!(values.is_empty() && !etag);
        let (_, values, etag) = cache_control(&client, "/plain-cache").await;
        assert_eq!(values, vec!["public, max-age=60".to_string()]);
        assert!(!etag);
        // An absent route (404 catcher) carries no ETag either.
        let (status, values, _) = cache_control(&client, "/missing").await;
        assert_eq!(status, Status::NotFound);
        assert!(values.is_empty());
    }

    /// The share fairing replaces `Cache-Control` with `no-store`; the
    /// `no-transform` merge must run after it.
    #[tokio::test]
    async fn share_paths_keep_no_store_and_add_no_transform_only_with_an_etag() {
        let client = client().await;
        let (_, values, _) = cache_control(&client, "/policy/v3/etag").await;
        assert_eq!(values, vec!["no-store, no-transform".to_string()]);
        let (_, values, _) = cache_control(&client, "/policy/v3/plain").await;
        assert_eq!(values, vec!["no-store".to_string()]);
    }

    #[tokio::test]
    async fn kv_get_responder_keeps_status_etag_and_body() {
        let client = client().await;
        let response = client.get("/kv").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some("private, no-cache, no-transform")
        );
        let etag = response.headers().get_one("ETag").unwrap().to_string();
        assert!(etag.starts_with("\"blake3-") && !etag.starts_with("W/"));
        assert_eq!(response.into_string().await.as_deref(), Some("hello"));

        let not_modified = client
            .get("/kv")
            .header(Header::new("If-None-Match", etag.clone()))
            .dispatch()
            .await;
        assert_eq!(not_modified.status(), Status::NotModified);
        assert_eq!(not_modified.headers().get_one("ETag"), Some(etag.as_str()));
        assert_eq!(
            not_modified.headers().get_one("Cache-Control"),
            Some("private, no-cache, no-transform")
        );
        assert!(not_modified.into_string().await.is_none());
    }

    #[tokio::test]
    async fn signed_url_responses_keep_no_store_and_add_no_transform() {
        let client = client().await;
        for (path, status) in [
            ("/signed/full", Status::Ok),
            ("/signed/unsatisfiable", Status::RangeNotSatisfiable),
        ] {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.status(), status, "{path}");
            assert!(response.headers().get_one("ETag").is_some(), "{path}");
            assert_eq!(
                response.headers().get_one("Cache-Control"),
                Some("private, no-store, no-transform"),
                "{path}"
            );
        }
    }
}
