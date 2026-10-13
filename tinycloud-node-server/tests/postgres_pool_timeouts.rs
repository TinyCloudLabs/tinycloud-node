//! TC-1054: the PostgreSQL pool bounds statements on dead and slow
//! connections, so one stuck round trip cannot wedge a SQL database's
//! operation lock.
//!
//! - TCP keepalive and `TCP_USER_TIMEOUT` are set on every pool socket
//!   (read back with `getsockopt`).
//! - `statement_timeout` applies per session, is lifted for migrations,
//!   raised for whole-artifact transfers, and surfaces as a retryable
//!   `SqlError::Unavailable` (503) that releases the database's lock.
//! - Large artifacts still persist and hydrate under the default limits.
//!
//! These run wherever `TINYCLOUD_TEST_POSTGRES_URL` is set, and fail in CI
//! without it (TC-381):
//!
//! ```text
//! TINYCLOUD_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
//!   cargo test -p tinycloud-node --test postgres_pool_timeouts
//! ```
//!
//! The `blackhole_*` tests also need `TINYCLOUD_TEST_BLACKHOLE=1` and
//! `iptables` (as root, or through passwordless `sudo -n`). They put an
//! in-test TCP proxy between the pool and PostgreSQL and drop the packets of
//! chosen proxy connections, by their exact loopback 4-tuple, so the pool
//! sees a real network black hole: no FIN, no RST, no ACK. A userspace proxy
//! that merely stops forwarding cannot do that, since its kernel still ACKs
//! data and keepalive probes. CI runs them (`.github/workflows/rust.yml`).
//! On a shared host, run the test binary inside a throwaway network
//! namespace instead, e.g. in the PostgreSQL container's:
//!
//! ```text
//! docker run -d --name tc1054-pg --cap-add NET_ADMIN -e POSTGRES_PASSWORD=postgres postgres:16
//! docker exec tc1054-pg sh -c 'apt-get update && apt-get install -y iptables'
//! cargo test -p tinycloud-node --test postgres_pool_timeouts --no-run   # note the binary path
//! docker cp target/debug/deps/postgres_pool_timeouts-<hash> tc1054-pg:/t
//! docker exec -e TINYCLOUD_TEST_BLACKHOLE=1 \
//!   -e TINYCLOUD_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
//!   tc1054-pg /t blackhole --test-threads 1 --nocapture
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tinycloud::config::Config;
use tinycloud_auth::resolver::DID_METHODS;
use tinycloud_auth::resource::SpaceId;
use tinycloud_auth::ssi::dids::DIDBuf;
use tinycloud_auth::ssi::jwk::JWK;
use tinycloud_core::database_artifacts::{
    DatabaseArtifactError, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
};
use tinycloud_core::db_pool::{is_transient_error, transient_error_class, StatementTimeoutMode};
use tinycloud_core::sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    TransactionTrait,
};
use tinycloud_core::sql::{SqlError, SqlRequest, SqlResponse, SqlService, SqlValue};
use tinycloud_core::RecoveringConnection;
use tinycloud_core::{SizeTrackingArtifactRepository, SqlSizes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn postgres_url(test: &str) -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            assert!(
                std::env::var_os("CI").is_none(),
                "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset in CI (TC-381)"
            );
            eprintln!("skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset");
            None
        }
    }
}

/// The black-hole tests' URL, when `TINYCLOUD_TEST_BLACKHOLE=1` allows them.
fn blackhole_url(test: &str) -> Option<String> {
    if std::env::var("TINYCLOUD_TEST_BLACKHOLE").as_deref() != Ok("1") {
        assert!(
            std::env::var_os("CI").is_none(),
            "{test} requires TINYCLOUD_TEST_BLACKHOLE=1 in CI (TC-1054)"
        );
        eprintln!("skipping {test}: TINYCLOUD_TEST_BLACKHOLE is not 1");
        return None;
    }
    postgres_url(test)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "tinycloud=info,tinycloud_core::db_pool=warn,tinycloud_core::sql=warn",
        ))
        .try_init();
}

/// A throwaway schema on the test server.
struct Schema {
    admin: DatabaseConnection,
    name: String,
}

impl Schema {
    async fn new(url: &str, test: &str) -> Self {
        init_tracing();
        let admin = Database::connect(ConnectOptions::new(url.to_owned()))
            .await
            .expect("connect to the test server");
        let name = format!(
            "tc1054_{test}_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000
        );
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {}", name))
            .await
            .expect("create the test schema");
        Self { admin, name }
    }

    /// `url` with this schema on the search path, pointed at `via` (a test
    /// proxy) when given.
    fn url(&self, url: &str, via: Option<SocketAddr>) -> String {
        let mut url = reqwest::Url::parse(url).expect("TINYCLOUD_TEST_POSTGRES_URL is a URL");
        if let Some(via) = via {
            url.set_host(Some(&via.ip().to_string())).unwrap();
            url.set_port(Some(via.port())).unwrap();
        }
        url.query_pairs_mut()
            .append_pair("application_name", &self.name)
            .append_pair("options", &format!("-c search_path={}", self.name));
        url.to_string()
    }

    async fn drop(self) {
        let _ = self
            .admin
            .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.name))
            .await;
    }
}

/// The production pool (`connect_database`) for `url`, with `tune` applied
/// to the default configuration.
async fn pool(url: String, tune: impl FnOnce(&mut Config)) -> RecoveringConnection {
    let mut config = Config::default();
    config.storage.database = Some(url);
    config.database.max_connections = 6;
    tune(&mut config);
    tinycloud::connect_database(&config)
        .await
        .expect("production pool connects")
}

fn upstream_addr(url: &str) -> SocketAddr {
    let url = reqwest::Url::parse(url).unwrap();
    let host = match url.host_str().unwrap_or("127.0.0.1") {
        "localhost" => "127.0.0.1",
        host => host,
    };
    format!("{host}:{}", url.port().unwrap_or(5432))
        .parse()
        .expect("the test server is addressed by IP")
}

fn statement(sql: &str) -> Statement {
    Statement::from_string(DbBackend::Postgres, sql)
}

async fn show_statement_timeout<C: ConnectionTrait>(conn: &C) -> String {
    conn.query_one(statement("SHOW statement_timeout"))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index::<String>(0)
        .unwrap()
}

fn test_space(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

fn sql_service(pool: &RecoveringConnection, cache: &tempfile::TempDir) -> SqlService {
    SqlService::new(
        cache.path().to_string_lossy().into_owned(),
        u64::MAX,
        Arc::new(SeaOrmDatabaseArtifactRepository::new(pool.clone())),
    )
}

fn insert_blob(bytes: usize) -> SqlRequest {
    SqlRequest::Execute {
        schema: Some(vec![
            "CREATE TABLE IF NOT EXISTS items (body BLOB)".to_string()
        ]),
        sql: "INSERT INTO items (body) VALUES (?)".to_string(),
        params: vec![SqlValue::Blob(vec![7u8; bytes])],
    }
}

fn count_items() -> SqlRequest {
    SqlRequest::Query {
        sql: "SELECT COUNT(*) FROM items".to_string(),
        params: Vec::new(),
        max_rows: None,
        max_bytes: None,
    }
}

async fn write(
    service: &SqlService,
    space: &SpaceId,
    db: &str,
    bytes: usize,
) -> Result<(), SqlError> {
    service
        .execute(
            space,
            db,
            insert_blob(bytes),
            None,
            "tinycloud.sql/write".into(),
        )
        .await
        .map(|_| ())
}

async fn count(service: &SqlService, space: &SpaceId, db: &str) -> Result<i64, SqlError> {
    let result = service
        .execute(space, db, count_items(), None, "tinycloud.sql/read".into())
        .await?;
    match result.response {
        SqlResponse::Query(query) => match query.rows.as_slice() {
            [row] => match row.as_slice() {
                [SqlValue::Integer(count)] => Ok(*count),
                other => panic!("unexpected row {other:?}"),
            },
            other => panic!("unexpected rows {other:?}"),
        },
        other => panic!("expected a query response, got {other:?}"),
    }
}

/// Every pool socket carries the configured keepalive and
/// `TCP_USER_TIMEOUT`, read back from the kernel with `getsockopt`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_pool_sockets_carry_keepalive_and_user_timeout() {
    let Some(url) = postgres_url("postgres_pool_sockets_carry_keepalive_and_user_timeout") else {
        return;
    };
    let schema = Schema::new(&url, "keepalive").await;
    // A peer no other pool in this process connects to: a scan configures
    // every new socket to its database peer, whichever pool opened it.
    let proxy = Proxy::start(upstream_addr(&url), None).await;
    let conn = pool(schema.url(&url, Some(proxy.addr)), |config| {
        config.database.tcp_keepalive_idle_secs = 7;
        config.database.tcp_keepalive_interval_secs = 3;
        config.database.tcp_keepalive_retries = 4;
        config.database.tcp_user_timeout_ms = 11_000;
    })
    .await;
    let pool = conn.sea_orm_connection().get_postgres_connection_pool();
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(pool.acquire().await.unwrap());
    }

    let port = proxy.addr.port();
    let mut configured = 0;
    for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // SAFETY: borrowed for getsockopt only; the pool keeps these open.
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let socket = socket2::SockRef::from(&fd);
        let to_server = socket
            .peer_addr()
            .ok()
            .and_then(|addr| addr.as_socket())
            .is_some_and(|peer| peer.port() == port);
        if !to_server {
            continue;
        }
        configured += 1;
        assert_eq!(socket.keepalive_time().unwrap(), Duration::from_secs(7));
        assert!(socket.keepalive().unwrap(), "SO_KEEPALIVE");
        assert_eq!(socket.keepalive_interval().unwrap(), Duration::from_secs(3));
        assert_eq!(socket.keepalive_retries().unwrap(), 4);
        assert_eq!(
            socket.tcp_user_timeout().unwrap(),
            Some(Duration::from_millis(11_000))
        );
    }
    assert_eq!(
        configured,
        pool.size() as usize,
        "every connection of the pool is configured"
    );
    drop(held);
    conn.sea_orm_connection().clone().close().await.unwrap();
    schema.drop().await;
}

/// The session `statement_timeout` bounds a statement on a live connection
/// with a transient error (57014); a bulk scope raises it for its
/// transaction only; migrations run with none; `local` and `off` behave as
/// documented.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_statement_timeout_modes_scopes_and_migrations() {
    let Some(url) = postgres_url("postgres_statement_timeout_modes_scopes_and_migrations") else {
        return;
    };
    let schema = Schema::new(&url, "modes").await;

    // The production default.
    let default = pool(schema.url(&url, None), |_| {}).await;
    assert_eq!(show_statement_timeout(&default).await, "30s");

    let session = pool(schema.url(&url, None), |config| {
        config.database.statement_timeout_ms = 300;
        config.database.bulk_statement_timeout_ms = 5_000;
    })
    .await;
    assert_eq!(show_statement_timeout(&session).await, "300ms");
    let started = Instant::now();
    let error = session
        .execute(statement("SELECT pg_sleep(2)"))
        .await
        .expect_err("a statement past the timeout is cancelled");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(is_transient_error(&error), "{error:?}");
    assert_eq!(transient_error_class(&error), Some("sqlstate_57014"));

    let scope = session.begin_bulk().await.unwrap();
    assert_eq!(show_statement_timeout(&scope).await, "5s");
    scope
        .execute(statement("SELECT pg_sleep(0.6)"))
        .await
        .expect("the bulk timeout applies inside the scope");
    scope.commit().await.unwrap();
    for _ in 0..4 {
        assert_eq!(
            show_statement_timeout(&session).await,
            "300ms",
            "SET LOCAL did not leak"
        );
    }

    // Migrations are exempt: they apply from scratch on a pool whose every
    // other statement must finish within 1 ms.
    let strict = pool(schema.url(&url, None), |config| {
        config.database.statement_timeout_ms = 1;
    })
    .await;
    assert_eq!(show_statement_timeout(&strict).await, "1ms");
    tinycloud_core::db::migrate(&strict)
        .await
        .expect("migrations run without a statement timeout");

    let local = pool(schema.url(&url, None), |config| {
        config.database.statement_timeout_mode = StatementTimeoutMode::Local;
        config.database.statement_timeout_ms = 300;
    })
    .await;
    assert_eq!(
        show_statement_timeout(&local).await,
        "0",
        "no session timeout"
    );
    local
        .execute(statement("SELECT pg_sleep(0.5)"))
        .await
        .expect("autocommit statements are not covered in local mode");
    let transaction = local.begin().await.unwrap();
    assert_eq!(show_statement_timeout(&transaction).await, "300ms");
    let error = transaction
        .execute(statement("SELECT pg_sleep(2)"))
        .await
        .expect_err("explicit transactions are covered in local mode");
    assert!(is_transient_error(&error), "{error:?}");
    drop(transaction);

    let off = pool(schema.url(&url, None), |config| {
        config.database.statement_timeout_mode = StatementTimeoutMode::Off;
    })
    .await;
    assert_eq!(show_statement_timeout(&off).await, "0");
    let scope = off.begin_bulk().await.unwrap();
    assert_eq!(
        show_statement_timeout(&scope).await,
        "0",
        "no bulk transaction when off"
    );
    scope.commit().await.unwrap();

    for conn in [default, session, strict, local, off] {
        conn.sea_orm_connection().clone().close().await.unwrap();
    }
    schema.drop().await;
}

/// A statement timeout on the SQL persistence path is a bounded, retryable
/// `Unavailable` (503): the database's operation lock is released, the
/// next request on it succeeds, and other databases are unaffected. A full
/// checkpoint larger than a delta runs under the bulk timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_sql_statement_timeout_is_retryable_and_releases_the_lock() {
    let Some(url) =
        postgres_url("postgres_sql_statement_timeout_is_retryable_and_releases_the_lock")
    else {
        return;
    };
    let schema = Schema::new(&url, "sqllock").await;
    let conn = pool(schema.url(&url, None), |config| {
        config.database.statement_timeout_ms = 500;
        config.database.bulk_statement_timeout_ms = 10_000;
    })
    .await;
    tinycloud_core::db::migrate(&conn).await.unwrap();
    let cache = tempfile::TempDir::new().unwrap();
    let service = sql_service(&conn, &cache);
    let space = test_space("sqllock");
    write(&service, &space, "a", 1024).await.unwrap();
    write(&service, &space, "b", 1024).await.unwrap();

    // Every artifact update of `a` now takes 1.5 s inside PostgreSQL.
    let name = &schema.name;
    schema
        .admin
        .execute_unprepared(&format!(
            "CREATE FUNCTION {name}.slow_artifact() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN PERFORM pg_sleep(1.5); RETURN NEW; END $$; \
             CREATE TRIGGER slow_artifact BEFORE UPDATE ON {name}.database_artifact \
             FOR EACH ROW WHEN (NEW.name = 'a') EXECUTE FUNCTION {name}.slow_artifact();"
        ))
        .await
        .unwrap();

    // A delta persist hits the base timeout: bounded, retryable.
    let started = Instant::now();
    let error = write(&service, &space, "a", 1024)
        .await
        .expect_err("the delta update exceeds the statement timeout");
    assert!(matches!(error, SqlError::Unavailable), "{error:?}");
    assert!(
        started.elapsed() < Duration::from_millis(1_400),
        "{:?}",
        started.elapsed()
    );

    // The lock was released: the next request on `a` re-hydrates and runs
    // at once, without the refused write. `b` was never affected.
    let next = tokio::time::timeout(Duration::from_secs(5), count(&service, &space, "a"))
        .await
        .expect("the failed request released the database lock");
    assert_eq!(next.unwrap(), 1);
    write(&service, &space, "b", 1024).await.unwrap();
    assert_eq!(count(&service, &space, "b").await.unwrap(), 2);

    // A WAL past the 8 MiB delta bound persists as a full checkpoint, whose
    // write runs under the bulk timeout and survives the slow trigger.
    write(&service, &space, "a", 9 * 1024 * 1024)
        .await
        .expect("a full checkpoint runs under the bulk statement timeout");

    schema
        .admin
        .execute_unprepared(&format!(
            "DROP TRIGGER slow_artifact ON {name}.database_artifact"
        ))
        .await
        .unwrap();
    write(&service, &space, "a", 1024).await.unwrap();
    let cold_cache = tempfile::TempDir::new().unwrap();
    let cold = sql_service(&conn, &cold_cache);
    assert_eq!(count(&cold, &space, "a").await.unwrap(), 3);
    conn.sea_orm_connection().clone().close().await.unwrap();
    schema.drop().await;
}

/// Large artifacts (a delta just under the 8 MiB bound, then a full
/// checkpoint past it) persist and hydrate under the default limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_large_artifacts_persist_under_default_timeouts() {
    let Some(url) = postgres_url("postgres_large_artifacts_persist_under_default_timeouts") else {
        return;
    };
    let schema = Schema::new(&url, "large").await;
    let conn = pool(schema.url(&url, None), |_| {}).await;
    tinycloud_core::db::migrate(&conn).await.unwrap();
    let cache = tempfile::TempDir::new().unwrap();
    let service = sql_service(&conn, &cache);
    let space = test_space("large");
    write(&service, &space, "big", 1024).await.unwrap();
    write(&service, &space, "big", 7 * 1024 * 1024)
        .await
        .unwrap();
    write(&service, &space, "big", 9 * 1024 * 1024)
        .await
        .unwrap();
    let (delta, checkpoint): (i64, i64) = schema
        .admin
        .query_one(statement(&format!(
            "SELECT delta_size_bytes, checkpoint_size_bytes FROM {}.database_artifact",
            schema.name
        )))
        .await
        .unwrap()
        .map(|row| {
            (
                row.try_get_by_index(0).unwrap(),
                row.try_get_by_index(1).unwrap(),
            )
        })
        .unwrap();
    assert_eq!(
        delta, 0,
        "the last write replaced the WAL with a checkpoint"
    );
    assert!(checkpoint > 16 * 1024 * 1024, "{checkpoint}");

    let cold_cache = tempfile::TempDir::new().unwrap();
    let cold = sql_service(&conn, &cold_cache);
    assert_eq!(count(&cold, &space, "big").await.unwrap(), 3);
    conn.sea_orm_connection().clone().close().await.unwrap();
    schema.drop().await;
}

/// A large hydration whose server-side work outlasts the base statement
/// timeout succeeds, because the size mirror marks the artifact large and
/// its load runs under the bulk timeout; the same load forced under the base
/// timeout is cancelled (Opus's M6). The artifact is read through a view
/// that sleeps 1 s per row, standing in for detoasting and decompressing a
/// large payload. (A slow network does not exercise this: the artifact is
/// one row, and PostgreSQL does not cancel a statement while it is writing
/// a row to the client.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_large_hydration_runs_under_the_bulk_timeout() {
    let Some(url) = postgres_url("postgres_large_hydration_runs_under_the_bulk_timeout") else {
        return;
    };
    let schema = Schema::new(&url, "bulkload").await;
    let direct = pool(schema.url(&url, None), |_| {}).await;
    tinycloud_core::db::migrate(&direct).await.unwrap();
    let space = test_space("bulkload");
    {
        let cache = tempfile::TempDir::new().unwrap();
        let seed = sql_service(&direct, &cache);
        for _ in 0..3 {
            write(&seed, &space, "a", 4 * 1024 * 1024).await.unwrap();
        }
    }
    let name = &schema.name;
    schema
        .admin
        .execute_unprepared(&format!(
            "ALTER TABLE {name}.database_artifact RENAME TO database_artifact_rows; \
             CREATE FUNCTION {name}.slow_row() RETURNS boolean LANGUAGE plpgsql AS \
             $$ BEGIN PERFORM pg_sleep(1); RETURN true; END $$; \
             CREATE VIEW {name}.database_artifact AS \
             SELECT * FROM {name}.database_artifact_rows WHERE {name}.slow_row();"
        ))
        .await
        .unwrap();

    let strict = pool(schema.url(&url, None), |config| {
        config.database.statement_timeout_ms = 500;
        config.database.bulk_statement_timeout_ms = 10_000;
    })
    .await;
    let sizes = SqlSizes::new();
    sizes.seed_from(&direct).await.unwrap();
    let repository = Arc::new(SeaOrmDatabaseArtifactRepository::new(strict.clone()));
    let cache = tempfile::TempDir::new().unwrap();
    let service = SqlService::new(
        cache.path().to_string_lossy().into_owned(),
        u64::MAX,
        Arc::new(SizeTrackingArtifactRepository::new(
            repository.clone(),
            sizes,
        )),
    );
    assert_eq!(count(&service, &space, "a").await.unwrap(), 3);

    let error = repository
        .load_sized("sql", &space.to_string(), "a", Some(0))
        .await
        .expect_err("the same load under the 500 ms base timeout is cancelled");
    match &error {
        DatabaseArtifactError::Db(error) => {
            assert_eq!(
                transient_error_class(error),
                Some("sqlstate_57014"),
                "{error:?}"
            )
        }
        other => panic!("expected a database error, got {other:?}"),
    }
    for conn in [direct, strict] {
        conn.sea_orm_connection().clone().close().await.unwrap();
    }
    schema.drop().await;
}

/// A connection whose socket cannot be configured is never admitted
/// (Astra's P1): sqlx retries the connect until the acquire deadline and the
/// pool fails with a retryable acquire error instead of handing out an
/// unprotected connection. Linux caps `TCP_KEEPCNT` at 127, so 1000 makes
/// every configuration fail.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_unconfigurable_keepalive_admits_no_connection() {
    let Some(url) = postgres_url("postgres_unconfigurable_keepalive_admits_no_connection") else {
        return;
    };
    let schema = Schema::new(&url, "failclosed").await;
    // A peer port of its own, so no other pool's scan configures the socket.
    let proxy = Proxy::start(upstream_addr(&url), None).await;
    let mut config = Config::default();
    config.database.tcp_keepalive_retries = 1000;
    let mut options = ConnectOptions::new(schema.url(&url, Some(proxy.addr)));
    options
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(2));
    let missed = tinycloud::pg_keepalive::KeepaliveConfigurator::missed();
    let started = Instant::now();
    let result = tinycloud::postgres_pool_with_recovery(
        options,
        None,
        &config.database,
        tinycloud_core::db_pool::PoolRecovery::new(),
    )
    .await;
    assert!(result.is_err(), "no connection was admitted");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert!(tinycloud::pg_keepalive::KeepaliveConfigurator::missed() > missed);
    schema.drop().await;
}

// ---------------------------------------------------------------------------
// Black-hole tests.

/// One client connection through the [`Proxy`].
struct Link {
    /// The pool's end of the connection.
    client: SocketAddr,
    /// Bytes forwarded from PostgreSQL to the pool.
    down: Arc<AtomicU64>,
}

/// A TCP proxy between a pool and PostgreSQL that records its connections
/// and can throttle what it forwards to the pool.
struct Proxy {
    addr: SocketAddr,
    links: Arc<Mutex<Vec<Link>>>,
}

impl Proxy {
    async fn start(upstream: SocketAddr, down_bytes_per_sec: Option<u64>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let links = Arc::new(Mutex::new(Vec::new()));
        let registry = Arc::clone(&links);
        tokio::spawn(async move {
            while let Ok((client, peer)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(upstream).await else {
                    continue;
                };
                let down = Arc::new(AtomicU64::new(0));
                registry.lock().unwrap().push(Link {
                    client: peer,
                    down: Arc::clone(&down),
                });
                tokio::spawn(pipe(client, server, down, down_bytes_per_sec));
            }
        });
        Self { addr, links }
    }

    /// Start counting forwarded bytes afresh on every connection.
    fn reset_counters(&self) {
        for link in self.links.lock().unwrap().iter() {
            link.down.store(0, Ordering::Relaxed);
        }
    }

    fn clients(&self) -> Vec<SocketAddr> {
        self.links
            .lock()
            .unwrap()
            .iter()
            .map(|link| link.client)
            .collect()
    }

    /// Connections that have forwarded more than `bytes` to the pool.
    fn streaming(&self, bytes: u64) -> Vec<SocketAddr> {
        self.links
            .lock()
            .unwrap()
            .iter()
            .filter(|link| link.down.load(Ordering::Relaxed) > bytes)
            .map(|link| link.client)
            .collect()
    }
}

async fn pipe(client: TcpStream, server: TcpStream, down: Arc<AtomicU64>, rate: Option<u64>) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(n @ 1..) = client_read.read(&mut buf).await {
            if server_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(n @ 1..) = server_read.read(&mut buf).await {
        if client_write.write_all(&buf[..n]).await.is_err() {
            break;
        }
        down.fetch_add(n as u64, Ordering::Relaxed);
        if let Some(rate) = rate {
            tokio::time::sleep(Duration::from_secs_f64(n as f64 / rate as f64)).await;
        }
    }
    up.abort();
}

/// `iptables` DROP rules for chosen proxy connections, removed on drop.
/// Each rule matches one direction of one connection's exact loopback
/// 4-tuple, so nothing else on the host is affected.
struct Blackhole {
    proxy: SocketAddr,
    clients: Vec<SocketAddr>,
}

impl Blackhole {
    fn new(proxy: SocketAddr) -> Self {
        Self {
            proxy,
            clients: Vec::new(),
        }
    }

    fn rules(&self, client: SocketAddr) -> [Vec<String>; 2] {
        let rule = |from: SocketAddr, to: SocketAddr| {
            [
                "OUTPUT",
                "-p",
                "tcp",
                "-s",
                &from.ip().to_string(),
                "--sport",
                &from.port().to_string(),
                "-d",
                &to.ip().to_string(),
                "--dport",
                &to.port().to_string(),
                "-j",
                "DROP",
            ]
            .map(str::to_owned)
            .to_vec()
        };
        [rule(client, self.proxy), rule(self.proxy, client)]
    }

    fn drop_packets_of(&mut self, client: SocketAddr) {
        if self.clients.contains(&client) {
            return;
        }
        for rule in self.rules(client) {
            iptables("-I", &rule);
        }
        self.clients.push(client);
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        for client in std::mem::take(&mut self.clients) {
            for rule in self.rules(client) {
                iptables("-D", &rule);
            }
        }
    }
}

fn iptables(action: &str, rule: &[String]) {
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let mut command = if root {
        std::process::Command::new("iptables")
    } else {
        let mut sudo = std::process::Command::new("sudo");
        sudo.args(["-n", "iptables"]);
        sudo
    };
    let status = command
        .args(["-w", action])
        .args(rule)
        .status()
        .expect("run iptables");
    assert!(status.success(), "iptables {action} {rule:?}: {status}");
}

/// Keepalive tuned for tests: a dead connection is detected in about 3 s.
fn fast_keepalive(config: &mut Config) {
    config.database.tcp_keepalive_idle_secs = 1;
    config.database.tcp_keepalive_interval_secs = 1;
    config.database.tcp_keepalive_retries = 2;
    config.database.tcp_user_timeout_ms = 3_000;
}

async fn settle_idle(conn: &RecoveringConnection, count: usize) {
    let pool = conn.sea_orm_connection().get_postgres_connection_pool();
    let mut held = Vec::new();
    for _ in 0..count {
        held.push(pool.acquire().await.unwrap());
    }
    drop(held);
    for _ in 0..400 {
        if pool.num_idle() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("pool did not settle at {count} idle connections");
}

/// (a) Idle pooled connections the network silently drops (TC-1054 exp 5
/// and 6; 1.20.4 hung such requests for minutes). Without keepalive a
/// statement on one still hangs; with it, the statement ends within
/// seconds, and the pool then serves again on fresh connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_idle_connections_fail_fast_and_recover() {
    let Some(url) = blackhole_url("blackhole_idle_connections_fail_fast_and_recover") else {
        return;
    };
    let schema = Schema::new(&url, "bhidle").await;

    // Control: the black hole is real. No keepalive, so the statement on a
    // dead connection is still waiting after 8 s.
    let proxy = Proxy::start(upstream_addr(&url), None).await;
    let mut blackhole = Blackhole::new(proxy.addr);
    let unprotected = pool(schema.url(&url, Some(proxy.addr)), |config| {
        config.database.tcp_keepalive = false;
        config.database.max_connections = 1;
    })
    .await;
    settle_idle(&unprotected, 1).await;
    for client in proxy.clients() {
        blackhole.drop_packets_of(client);
    }
    let hung = tokio::time::timeout(
        Duration::from_secs(8),
        unprotected.query_one(statement("SELECT 1")),
    )
    .await;
    assert!(
        hung.is_err(),
        "without keepalive the statement hangs: {hung:?}"
    );

    let proxy = Proxy::start(upstream_addr(&url), None).await;
    let mut blackhole = Blackhole::new(proxy.addr);
    let conn = pool(schema.url(&url, Some(proxy.addr)), |config| {
        fast_keepalive(config);
        config.database.max_connections = 4;
    })
    .await;
    settle_idle(&conn, 3).await;
    let dead = proxy.clients();
    for client in &dead {
        blackhole.drop_packets_of(*client);
    }

    // The first statement draws a dead connection: it ends within the
    // bound, either with a transient error or, after its one read retry,
    // with a result.
    let started = Instant::now();
    let first = tokio::time::timeout(
        Duration::from_secs(20),
        conn.query_one(statement("SELECT 1")),
    )
    .await
    .expect("a statement on a dead connection is bounded");
    let elapsed = started.elapsed();
    eprintln!("first statement after the black hole: {elapsed:?} {first:?}");
    if let Err(error) = &first {
        assert!(is_transient_error(error), "{error:?}");
    }
    // Recovery: dead connections are replaced, so statements succeed again.
    let started = Instant::now();
    for _ in 0..4 {
        tokio::time::timeout(
            Duration::from_secs(20),
            conn.query_one(statement("SELECT 1")),
        )
        .await
        .expect("bounded")
        .expect("the pool serves from fresh connections");
    }
    eprintln!("recovered in {:?}", started.elapsed());
    assert!(
        proxy.clients().iter().any(|client| !dead.contains(client)),
        "fresh connections were opened"
    );
    drop(blackhole);
    schema.drop().await;
}

/// (b, c) A connection that dies mid-hydration, while the request holds its
/// database's operation lock (TC-1054 exp 4; 1.20.4 hung 156 s). Every
/// connection streaming the large artifact is black-holed. The first attempt
/// fails within the retry window (test keepalive detects in about 3 s, the
/// default window is 10 s), so the read is retried once; the retry is cut
/// too, and the request ends with a retryable `Unavailable`. The lock is
/// released, so the next request on the database hydrates and succeeds;
/// another database is served throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_mid_hydration_releases_the_database_lock() {
    let Some(url) = blackhole_url("blackhole_mid_hydration_releases_the_database_lock") else {
        return;
    };
    let (elapsed, cut) = mid_hydration_blackhole(&url, "bhlock", |_| {}).await;
    assert_eq!(cut, 2, "the attempt and its one retry were each cut");
    // Two detections (about 3 s each), never a third from a nested retry.
    assert!(elapsed < Duration::from_secs(9), "{elapsed:?}");
}

/// The bound under the lock (TC-1054, Opus): a hydration whose connection
/// loss took longer than the retry window to detect is not retried, so the
/// request waits for one detection, not two. In production the window is
/// 10 s and a detection about 30 s, so the worst case is about 40 s, under
/// the 60 s ingress timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_mid_hydration_waits_for_one_detection_only() {
    let Some(url) = blackhole_url("blackhole_mid_hydration_waits_for_one_detection_only") else {
        return;
    };
    let (elapsed, cut) = mid_hydration_blackhole(&url, "bhbound", |config| {
        config.database.retry_window_ms = 1_000;
    })
    .await;
    assert_eq!(cut, 1, "no retry after a slow detection");
    // Under 1 s of transfer before the cut, plus one detection (about 3 s).
    assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");
}

/// The case CI found: the hydration's `BEGIN` draws an idle connection that
/// died silently, and the load on the next connection is cut mid-transfer.
/// The attempt is retried as a whole, its `BEGIN` never on its own, so the
/// request waits for at most two detections, not three.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_dead_idle_connection_then_cut_hydration_waits_two_detections_at_most() {
    let Some(url) = blackhole_url(
        "blackhole_dead_idle_connection_then_cut_hydration_waits_two_detections_at_most",
    ) else {
        return;
    };
    let (elapsed, _) = mid_hydration_blackhole_with(&url, "bhidlecut", |_| {}, true).await;
    assert!(elapsed < Duration::from_secs(9), "{elapsed:?}");
}

/// Black-hole every connection streaming db `a`'s hydration on a cold node,
/// check the request on `a` fails retryably while db `b` is served, then
/// that the next request on `a` succeeds. Returns the failed request's
/// duration and how many connections were cut.
async fn mid_hydration_blackhole(
    url: &str,
    name: &'static str,
    tune: impl FnOnce(&mut Config),
) -> (Duration, usize) {
    mid_hydration_blackhole_with(url, name, tune, false).await
}

/// [`mid_hydration_blackhole`]; with `kill_idle`, every idle pooled
/// connection is black-holed first too, so the hydration's `BEGIN` may draw
/// a dead one (and db `b` is not expected to be served meanwhile).
async fn mid_hydration_blackhole_with(
    url: &str,
    name: &'static str,
    tune: impl FnOnce(&mut Config),
    kill_idle: bool,
) -> (Duration, usize) {
    let schema = Schema::new(url, name).await;
    // 4 MiB/s to the pool: a 12 MiB hydration takes about 3 s.
    let proxy = Arc::new(Proxy::start(upstream_addr(url), Some(4 * 1024 * 1024)).await);
    let conn = pool(schema.url(url, Some(proxy.addr)), |config| {
        fast_keepalive(config);
        tune(config);
    })
    .await;
    tinycloud_core::db::migrate(&conn).await.unwrap();
    let space = test_space(name);
    {
        let cache = tempfile::TempDir::new().unwrap();
        let seed = sql_service(&conn, &cache);
        for _ in 0..3 {
            write(&seed, &space, "a", 4 * 1024 * 1024).await.unwrap();
        }
        write(&seed, &space, "b", 1024).await.unwrap();
    }

    // A cold node: the next request on each database hydrates it. Only
    // traffic from here on marks a connection as streaming the artifact.
    let cache = tempfile::TempDir::new().unwrap();
    let service = Arc::new(sql_service(&conn, &cache));
    proxy.reset_counters();
    let blackhole = Arc::new(Mutex::new(Blackhole::new(proxy.addr)));
    if kill_idle {
        for client in proxy.clients() {
            blackhole.lock().unwrap().drop_packets_of(client);
        }
    }
    let cutting = Arc::new(AtomicBool::new(true));
    let cutter = {
        let (proxy, blackhole, cutting) = (proxy.clone(), blackhole.clone(), cutting.clone());
        tokio::spawn(async move {
            while cutting.load(Ordering::Relaxed) {
                for client in proxy.streaming(1024 * 1024) {
                    blackhole.lock().unwrap().drop_packets_of(client);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };
    let other = {
        let (service, space, cutting) = (service.clone(), space.clone(), cutting.clone());
        tokio::spawn(async move {
            let mut latencies = Vec::new();
            while !kill_idle && cutting.load(Ordering::Relaxed) {
                let started = Instant::now();
                let rows = count(&service, &space, "b")
                    .await
                    .expect("db b is unaffected");
                assert_eq!(rows, 1);
                latencies.push(started.elapsed());
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            latencies
        })
    };

    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(45), count(&service, &space, "a"))
        .await
        .expect("a request whose connection died mid-statement is bounded");
    let elapsed = started.elapsed();
    eprintln!("hydration through the black hole: {elapsed:?} {result:?}");
    assert!(matches!(result, Err(SqlError::Unavailable)), "{result:?}");
    assert!(
        !blackhole.lock().unwrap().clients.is_empty(),
        "the hydration was cut mid-transfer"
    );

    cutting.store(false, Ordering::Relaxed);
    cutter.await.unwrap();
    let latencies = other.await.unwrap();
    eprintln!("db b during the black hole: {latencies:?}");
    assert!(kill_idle || latencies.len() >= 3, "{latencies:?}");
    assert!(
        latencies
            .iter()
            .all(|latency| *latency < Duration::from_secs(5)),
        "{latencies:?}"
    );

    // The lock was released: the next request on `a` hydrates and succeeds.
    let started = Instant::now();
    let rows = tokio::time::timeout(Duration::from_secs(45), count(&service, &space, "a"))
        .await
        .expect("the database lock was released")
        .expect("the next request on the database succeeds");
    assert_eq!(rows, 3);
    eprintln!("next request on a: {:?}", started.elapsed());
    let cut = blackhole.lock().unwrap().clients.len();
    drop(blackhole);
    schema.drop().await;
    (elapsed, cut)
}
