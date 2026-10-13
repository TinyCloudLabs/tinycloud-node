//! TC-951: the Postgres pool recovers from connections lost while idle.
//!
//! The production pool (`tinycloud::connect_database`) skips sqlx's
//! unconditional pre-acquire ping. These tests kill pooled connections the
//! ways production loses them and show that the real request paths still
//! succeed: a KV put and a KV get through `SpaceDatabase::invoke`, and a
//! `delegate`, each with a signed owner invocation or delegation.
//!
//! - A terminated backend (`pg_terminate_backend`, what a failover or an
//!   idle-session reaper does) answers with FATAL 57P01.
//! - A cut connection (a proxy or NAT dropping it) is reset by an in-test
//!   TCP proxy between the pool and Postgres.
//!
//! Each test runs in its own schema and identifies its pool's backends by a
//! unique `application_name`. They skip (or, in CI, fail) when
//! `TINYCLOUD_TEST_POSTGRES_URL` is unset:
//!
//! ```text
//! TINYCLOUD_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
//!   cargo test -p tinycloud-node --test postgres_connection_recovery
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::io::AsyncWriteExt;
use tinycloud::config::Config;
use tinycloud_auth::authorization::{HeaderEncode, TinyCloudDelegation};
use tinycloud_auth::resolver::DID_METHODS;
use tinycloud_auth::resource::{Path, Service, SpaceId};
use tinycloud_auth::ssi::claims::jwt::NumericDate;
use tinycloud_auth::ssi::dids::{DIDBuf, DIDURLBuf};
use tinycloud_auth::ssi::jwk::JWK;
use tinycloud_auth::ssi::ucan::Payload;
use tinycloud_auth::ucan_capabilities_object::{Ability, Capabilities};
use tinycloud_core::db_pool::{is_connection_error, PoolRecoveryStats};
use tinycloud_core::events::{Delegation, Invocation, TinyCloudInvocation};
use tinycloud_core::keys::StaticSecret;
use tinycloud_core::models::space as space_model;
use tinycloud_core::sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DbBackend, Statement,
};
use tinycloud_core::storage::memory::{MemoryStaging, MemoryStore};
use tinycloud_core::storage::{HashBuffer, StorageSetup};
use tinycloud_core::types::{Metadata, SpaceIdWrap};
use tinycloud_core::{RecoveringConnection, SpaceDatabase};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Db = SpaceDatabase<RecoveringConnection, MemoryStore, StaticSecret>;

/// The pool size the tests run with.
const MAX_CONNECTIONS: u32 = 15;
/// Concurrent requests run to warm the pool's statement caches.
const WARM_CONCURRENCY: usize = 8;
/// Idle connections the pool holds after warm-up.
const WARM_CONNECTIONS: usize = 12;

/// Show the recovery warnings (`--nocapture`): they name the error class
/// each loss produced.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "tinycloud_core::db_pool=warn",
        ))
        .try_init();
}

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

/// One space owner: its signing key, verification method, and space.
struct Owner {
    jwk: JWK,
    verification_method: String,
    did: String,
    space: SpaceId,
}

impl Owner {
    fn generate() -> Result<Self, BoxError> {
        let jwk = JWK::generate_ed25519()?;
        let did = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = did
            .rsplit_once(':')
            .map(|(_, fragment)| fragment.to_owned())
            .ok_or("did:key has no method-specific id")?;
        Ok(Self {
            verification_method: format!("{did}#{fragment}"),
            space: SpaceId::new(did.parse::<DIDBuf>()?, "default".parse()?),
            did,
            jwk,
        })
    }

    fn payload(&self, audience: &str, ability: &str, key: &Path, nonce: &str) -> Payload {
        let resource = self.space.clone().to_resource(
            "kv".parse::<Service>().unwrap(),
            Some(key.clone()),
            None,
            None,
        );
        let mut caps = Capabilities::new();
        caps.with_action(
            resource.as_uri(),
            ability.parse::<Ability>().unwrap(),
            [BTreeMap::<String, serde_json::Value>::new()],
        );
        Payload {
            issuer: self.verification_method.parse::<DIDURLBuf>().unwrap(),
            audience: audience.parse::<DIDBuf>().unwrap(),
            not_before: None,
            expiration: NumericDate::try_from_seconds(
                time::OffsetDateTime::now_utc().unix_timestamp() as f64 + 1_800.0,
            )
            .unwrap(),
            nonce: Some(nonce.to_owned()),
            facts: Some(Vec::<serde_json::Value>::new()),
            proof: vec![],
            attenuation: caps,
        }
    }

    /// An owner-root (no proofs) KV invocation on `{space}/kv/{key}`.
    fn invocation(&self, ability: &str, key: &Path, nonce: &str) -> Result<Invocation, BoxError> {
        let header = self
            .payload(&self.did, ability, key, nonce)
            .sign(self.jwk.get_algorithm().unwrap_or_default(), &self.jwk)?
            .encode()?;
        Ok(Invocation::from_header_ser::<TinyCloudInvocation>(&header)?)
    }

    /// An owner-root delegation of `kv/get` on `key` to a fresh did:key.
    fn delegation(&self, key: &Path, nonce: &str) -> Result<Delegation, BoxError> {
        let delegate = DID_METHODS
            .generate(&JWK::generate_ed25519()?, "key")?
            .to_string();
        let ucan = self
            .payload(&delegate, "tinycloud.kv/get", key, nonce)
            .sign(self.jwk.get_algorithm().unwrap_or_default(), &self.jwk)?;
        let header = TinyCloudDelegation::Ucan(Box::new(ucan)).encode()?;
        Ok(Delegation::from_header_ser::<TinyCloudDelegation>(&header)?)
    }
}

/// A per-test schema, `application_name`, and the production pool on them.
struct Fixture {
    name: &'static str,
    admin: DatabaseConnection,
    schema: String,
    application_name: String,
    conn: RecoveringConnection,
    db: Db,
    owner: Owner,
    requests: u64,
}

/// `url` with this test's `application_name` and `search_path`, optionally
/// pointed at `via` (the test proxy) instead of the server.
fn pool_url(url: &str, application_name: &str, schema: &str, via: Option<SocketAddr>) -> String {
    let mut url = reqwest::Url::parse(url).expect("TINYCLOUD_TEST_POSTGRES_URL is a URL");
    if let Some(via) = via {
        url.set_host(Some(&via.ip().to_string())).unwrap();
        url.set_port(Some(via.port())).unwrap();
    }
    url.query_pairs_mut()
        .append_pair("application_name", application_name)
        .append_pair("options", &format!("-c search_path={schema}"));
    url.to_string()
}

fn upstream_addr(url: &str) -> SocketAddr {
    let url = reqwest::Url::parse(url).unwrap();
    let host = url.host_str().unwrap_or("127.0.0.1");
    let host = if host == "localhost" {
        "127.0.0.1"
    } else {
        host
    };
    format!("{host}:{}", url.port().unwrap_or(5432))
        .parse()
        .expect("the test server is addressed by IP")
}

impl Fixture {
    async fn new(name: &'static str, url: &str, via: Option<SocketAddr>) -> Self {
        init_tracing();
        let admin = Database::connect(ConnectOptions::new(url.to_owned()))
            .await
            .expect("connect to the test server");
        let unique = format!(
            "{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000
        );
        let schema = format!("tc951_{name}_{unique}");
        let application_name = format!("tc951-{name}-{unique}");
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .expect("create the test schema");

        // The production constructor, as `app_with_control` calls it.
        let mut config = Config::default();
        config.storage.database = Some(pool_url(url, &application_name, &schema, via));
        config.database.max_connections = MAX_CONNECTIONS;
        let conn = tinycloud::connect_database(&config)
            .await
            .expect("production pool connects");
        assert!(conn.recovery().is_some(), "Postgres pools carry recovery");
        assert!(
            !conn
                .sea_orm_connection()
                .get_postgres_connection_pool()
                .options()
                .get_test_before_acquire(),
            "the production pool must not ping before every acquire"
        );

        let store = MemoryStore::default();
        let db = SpaceDatabase::new(
            conn.clone(),
            store.clone(),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
        )
        .await
        .expect("migrations apply in the test schema");
        let owner = Owner::generate().unwrap();
        space_model::ActiveModel {
            id: Set(SpaceIdWrap(owner.space.clone())),
        }
        .insert(&conn)
        .await
        .unwrap();
        store
            .create(&owner.space)
            .await
            .map_err(|_| "block store space setup failed")
            .unwrap();
        let mut fixture = Self {
            name,
            admin,
            schema,
            application_name,
            conn,
            db,
            owner,
            requests: 0,
        };
        fixture.put("warm/seed").await.expect("seed put");
        fixture
    }

    fn stats(&self) -> PoolRecoveryStats {
        self.conn.recovery().unwrap().stats()
    }

    fn nonce(&mut self) -> String {
        self.requests += 1;
        format!("urn:uuid:tc951-{}-{}", self.name, self.requests)
    }

    async fn put(&mut self, key: &str) -> Result<(), String> {
        let key: Path = key.parse().unwrap();
        let nonce = self.nonce();
        let invocation = self
            .owner
            .invocation("tinycloud.kv/put", &key, &nonce)
            .unwrap();
        let mut stage = HashBuffer::new(Vec::new());
        stage.write_all(b"tc951 value").await.unwrap();
        let mut inputs = HashMap::new();
        inputs.insert(
            (self.owner.space.clone(), key),
            (Metadata(BTreeMap::new()), stage),
        );
        self.db
            .invoke::<MemoryStaging>(invocation, inputs)
            .await
            .map(|_| ())
            .map_err(|error| format!("kv put: {error}"))
    }

    async fn get(&mut self, key: &str) -> Result<(), String> {
        let key: Path = key.parse().unwrap();
        let nonce = self.nonce();
        let invocation = self
            .owner
            .invocation("tinycloud.kv/get", &key, &nonce)
            .unwrap();
        let (_, outcomes) = self
            .db
            .invoke::<MemoryStaging>(invocation, HashMap::new())
            .await
            .map_err(|error| format!("kv get: {error}"))?;
        if outcomes.len() == 1 {
            Ok(())
        } else {
            Err(format!("kv get: {} outcomes", outcomes.len()))
        }
    }

    async fn delegate(&mut self, key: &str) -> Result<(), String> {
        let key: Path = key.parse().unwrap();
        let nonce = self.nonce();
        let delegation = self.owner.delegation(&key, &nonce).unwrap();
        self.db
            .delegate(delegation)
            .await
            .map(|_| ())
            .map_err(|error| format!("delegate: {error}"))
    }

    /// Run two rounds of `WARM_CONCURRENCY` concurrent put + get pairs, so
    /// the pool holds several connections, then wait until they are idle.
    async fn warm(&mut self) -> BTreeSet<i32> {
        for round in 0..2 {
            let mut tasks = Vec::new();
            for worker in 0..WARM_CONCURRENCY {
                let db = self.db.clone();
                let key: Path = format!("warm/{round}/{worker}").parse().unwrap();
                let (put_nonce, get_nonce) = (self.nonce(), self.nonce());
                let put = self
                    .owner
                    .invocation("tinycloud.kv/put", &key, &put_nonce)
                    .unwrap();
                let get = self
                    .owner
                    .invocation("tinycloud.kv/get", &key, &get_nonce)
                    .unwrap();
                let space = self.owner.space.clone();
                tasks.push(tokio::spawn(async move {
                    let mut stage = HashBuffer::new(Vec::new());
                    stage.write_all(b"warm").await.unwrap();
                    let mut inputs = HashMap::new();
                    inputs.insert((space, key), (Metadata(BTreeMap::new()), stage));
                    db.invoke::<MemoryStaging>(put, inputs)
                        .await
                        .map_err(|e| e.to_string())?;
                    db.invoke::<MemoryStaging>(get, HashMap::new())
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok::<_, String>(())
                }));
            }
            for task in tasks {
                task.await.unwrap().expect("warm-up request");
            }
        }
        // Same-space writes serialize, so the requests alone open only a few
        // connections.
        self.fill_pool().await
    }

    /// Hold `WARM_CONNECTIONS` at once, so the pool opens that many, and
    /// wait until they are all idle.
    async fn fill_pool(&self) -> BTreeSet<i32> {
        let pool = self
            .conn
            .sea_orm_connection()
            .get_postgres_connection_pool();
        let mut held = Vec::new();
        for _ in 0..WARM_CONNECTIONS {
            held.push(pool.acquire().await.unwrap());
        }
        drop(held);
        let idle = self.settle().await;
        assert_eq!(idle.len(), WARM_CONNECTIONS, "idle pooled connections");
        idle
    }

    /// Backend pids of this pool, by state.
    async fn backends(&self) -> Vec<(i32, String)> {
        self.admin
            .query_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT pid, coalesce(state, '') AS state FROM pg_stat_activity \
                 WHERE application_name = $1",
                [self.application_name.clone().into()],
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.try_get::<i32>("", "pid").unwrap(),
                    row.try_get::<String>("", "state").unwrap(),
                )
            })
            .collect()
    }

    /// Wait until every pooled connection is back in the idle queue (sqlx
    /// returns a released connection asynchronously, after a ping).
    async fn settle(&self) -> BTreeSet<i32> {
        let pool = self
            .conn
            .sea_orm_connection()
            .get_postgres_connection_pool();
        for _ in 0..200 {
            let backends = self.backends().await;
            if pool.num_idle() as u32 == pool.size()
                && backends.len() == pool.size() as usize
                && backends.iter().all(|(_, state)| state == "idle")
            {
                return backends.into_iter().map(|(pid, _)| pid).collect();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("pool did not settle: {:?}", self.backends().await);
    }

    /// Terminate `pids` and wait until they are gone.
    async fn terminate(&self, pids: &BTreeSet<i32>) {
        for pid in pids {
            let terminated = self
                .admin
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT pg_terminate_backend($1) AS terminated",
                    [(*pid).into()],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<bool>("", "terminated")
                .unwrap();
            assert!(terminated, "pg_terminate_backend({pid})");
        }
        for _ in 0..200 {
            let alive = self.backends().await;
            if alive.iter().all(|(pid, _)| !pids.contains(pid)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("terminated backends linger");
    }

    /// Hold every idle connection, then release them so that `victim`
    /// position in sqlx's FIFO idle queue is `position` (0 = acquired next).
    async fn order_idle_queue(&self, position: usize) -> i32 {
        let pool = self
            .conn
            .sea_orm_connection()
            .get_postgres_connection_pool();
        let idle = self.settle().await.len();
        let mut held = Vec::new();
        for _ in 0..idle {
            let mut conn = pool.acquire().await.unwrap();
            let pid: i32 = tinycloud_core::sea_orm::sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            held.push((pid, conn));
        }
        let victim = held.pop().unwrap();
        held.insert(position.min(held.len()), victim);
        let victim_pid = held[position.min(held.len() - 1)].0;
        for (released, (_, conn)) in held.into_iter().enumerate() {
            drop(conn);
            for _ in 0..200 {
                if pool.num_idle() > released {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        assert_eq!(pool.num_idle(), idle);
        victim_pid
    }

    async fn row_count(&self, table: &str) -> i64 {
        self.admin
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!("SELECT count(*) AS n FROM {}.{table}", self.schema),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap()
    }

    async fn drop_schema(self) {
        self.conn
            .sea_orm_connection()
            .get_postgres_connection_pool()
            .close()
            .await;
        self.admin
            .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

/// Retries and losses observed during one request.
fn delta(before: PoolRecoveryStats, after: PoolRecoveryStats) -> PoolRecoveryStats {
    PoolRecoveryStats {
        losses: after.losses - before.losses,
        retries: after.retries - before.retries,
        revalidations: after.revalidations - before.revalidations,
        revalidation_failures: after.revalidation_failures - before.revalidation_failures,
    }
}

/// A TCP proxy between the pool and Postgres that can reset every client
/// connection, or the one connection that sends a marker after the server
/// received it but before its response is forwarded.
struct Proxy {
    addr: SocketAddr,
    cut: watch::Sender<u64>,
    cut_after: Arc<watch::Sender<Option<Vec<u8>>>>,
}

impl Proxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cut, cut_rx) = watch::channel(0u64);
        let cut_after = Arc::new(watch::Sender::new(None::<Vec<u8>>));
        let marker = Arc::clone(&cut_after);
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(upstream).await else {
                    continue;
                };
                tokio::spawn(pipe(client, server, cut_rx.clone(), Arc::clone(&marker)));
            }
        });
        Self {
            addr,
            cut,
            cut_after,
        }
    }

    /// Reset every connection that exists now.
    fn cut_all(&self) {
        self.cut.send_modify(|generation| *generation += 1);
    }

    fn cut_after_forwarding(&self, marker: &[u8]) {
        self.cut_after.send_replace(Some(marker.to_vec()));
    }
}

async fn pipe(
    mut client: TcpStream,
    mut server: TcpStream,
    mut cut: watch::Receiver<u64>,
    cut_after: Arc<watch::Sender<Option<Vec<u8>>>>,
) {
    cut.mark_unchanged();
    {
        let (mut client_read, mut client_write) = client.split();
        let (mut server_read, mut server_write) = server.split();
        let mut up = vec![0u8; 64 * 1024];
        let mut down = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                _ = cut.changed() => break,
                read = client_read.read(&mut up) => {
                    let Ok(n @ 1..) = read else { break };
                    if server_write.write_all(&up[..n]).await.is_err() {
                        break;
                    }
                    let matched = cut_after
                        .borrow()
                        .as_deref()
                        .is_some_and(|m| up[..n].windows(m.len()).any(|w| w == m));
                    if matched {
                        cut_after.send_replace(None);
                        // Let the server run and commit it; never forward the
                        // response.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        break;
                    }
                }
                read = server_read.read(&mut down) => {
                    let Ok(n @ 1..) = read else { break };
                    if client_write.write_all(&down[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    // RST, not FIN: the client sees the connection reset. A zero linger
    // never blocks on drop, which is why `set_linger` is deprecated.
    #[allow(deprecated)]
    let _ = client.set_linger(Some(Duration::ZERO));
}

/// Mass loss, as in a failover: every idle backend of the pool is
/// terminated. Each request still succeeds, with at most one retry, and the
/// pool replaces the dead connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_requests_survive_termination_of_every_idle_connection() {
    let Some(url) = postgres_url("postgres_requests_survive_termination_of_every_idle_connection")
    else {
        return;
    };
    let mut fixture = Fixture::new("mass", &url, None).await;
    let idle = fixture.warm().await;
    let before = fixture.stats();
    assert_eq!(before.losses, 0);
    fixture.terminate(&idle).await;

    let mut per_request = Vec::new();
    for request in ["put", "get", "delegate"] {
        let start = fixture.stats();
        let result = match request {
            "put" => fixture.put("after/mass").await,
            "get" => fixture.get("after/mass").await,
            _ => fixture.delegate("after/mass").await,
        };
        result.unwrap_or_else(|error| panic!("{request} after mass termination: {error}"));
        per_request.push((request, delta(start, fixture.stats())));
    }
    let total = delta(before, fixture.stats());
    eprintln!(
        "mass termination of {} idle connections: per request {per_request:?}, total {total:?}",
        idle.len()
    );

    // The first statement met a dead connection and was retried once. From
    // then on the acquire hook checks each connection idle since before the
    // loss as the queue hands it out, and closes the dead ones.
    assert_eq!(per_request[0].1.retries, 1, "{per_request:?}");
    assert!(
        per_request.iter().all(|(_, d)| d.retries <= 1),
        "{per_request:?}"
    );
    assert_eq!((total.losses, total.retries), (1, 1), "{total:?}");
    assert!(
        total.revalidation_failures >= 1,
        "the hook closed dead idle connections: {total:?}"
    );

    // Keep serving until every terminated connection has come up.
    let mut rounds = 0;
    while fixture.stats().revalidation_failures - before.revalidation_failures
        < (idle.len() - 1) as u64
    {
        rounds += 1;
        assert!(rounds <= 30, "dead connections never came up");
        fixture
            .get("after/mass")
            .await
            .unwrap_or_else(|error| panic!("get round {rounds}: {error}"));
    }
    let total = delta(before, fixture.stats());
    assert_eq!((total.losses, total.retries), (1, 1), "{total:?}");
    assert_eq!(
        total.revalidation_failures,
        (idle.len() - 1) as u64,
        "every other terminated connection was closed at acquire: {total:?}"
    );
    let now = fixture.settle().await;
    assert!(
        now.is_disjoint(&idle),
        "no terminated backend remains pooled"
    );
    assert!(!now.is_empty(), "fresh connections were opened");
    fixture.drop_schema().await;
}

/// One stale connection among live ones, at every position of the FIFO idle
/// queue in turn: whichever statement of a put, get or delegate meets it,
/// requests cycle the queue through it and every request succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_requests_survive_one_stale_pooled_connection() {
    let Some(url) = postgres_url("postgres_requests_survive_one_stale_pooled_connection") else {
        return;
    };
    let mut fixture = Fixture::new("single", &url, None).await;
    fixture.warm().await;
    let mut rounds_to_reach = Vec::new();
    for position in 0..WARM_CONNECTIONS {
        fixture.fill_pool().await;
        let victim = fixture.order_idle_queue(position).await;
        fixture.terminate(&BTreeSet::from([victim])).await;
        let before = fixture.stats();

        // Until a statement meets the dead connection.
        let mut rounds = 0;
        while fixture.stats().losses == before.losses {
            rounds += 1;
            assert!(
                rounds <= 30,
                "position {position}: the pool never reached the stale connection"
            );
            let key = format!("after/single/{position}/{rounds}");
            for result in [
                fixture.put(&key).await,
                fixture.get(&key).await,
                fixture.delegate(&key).await,
            ] {
                result.unwrap_or_else(|error| panic!("position {position}: {error}"));
            }
        }
        let key = format!("after/single/{position}/tail");
        fixture.put(&key).await.unwrap();
        fixture.get(&key).await.unwrap();
        fixture.delegate(&key).await.unwrap();
        let total = delta(before, fixture.stats());
        assert_eq!(
            (total.losses, total.retries),
            (1, 1),
            "position {position}: {total:?}"
        );
        rounds_to_reach.push(rounds);
    }
    eprintln!("one stale connection at each queue position 0..{WARM_CONNECTIONS}: reached in request rounds {rounds_to_reach:?}");
    fixture.drop_schema().await;
}

/// A network cut: a proxy resets every client connection while idle (EOF/RST,
/// no FATAL message). Requests still succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_requests_survive_a_network_cut_of_every_connection() {
    let Some(url) = postgres_url("postgres_requests_survive_a_network_cut_of_every_connection")
    else {
        return;
    };
    let proxy = Proxy::start(upstream_addr(&url)).await;
    let mut fixture = Fixture::new("cut", &url, Some(proxy.addr)).await;
    let idle = fixture.warm().await;
    let before = fixture.stats();
    proxy.cut_all();
    // The server sees its side close and ends those backends; the pool
    // still holds the client sockets, now reset.
    for _ in 0..200 {
        if fixture
            .backends()
            .await
            .iter()
            .all(|(pid, _)| !idle.contains(pid))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    fixture.put("after/cut").await.unwrap();
    let first = delta(before, fixture.stats());
    fixture.get("after/cut").await.unwrap();
    fixture.delegate("after/cut").await.unwrap();
    let total = delta(before, fixture.stats());
    eprintln!(
        "network cut of {} connections: first request {first:?}, total {total:?}",
        idle.len()
    );
    assert_eq!(first.retries, 1, "{first:?}");
    assert_eq!(total.retries, 1, "{total:?}");
    assert!(total.revalidation_failures >= 1, "{total:?}");
    fixture.drop_schema().await;
}

/// A write is never retried: on a terminated connection the INSERT fails
/// and is not run again; when the connection drops after the server
/// committed it, it ran exactly once and the error is still returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_writes_are_never_retried() {
    let Some(url) = postgres_url("postgres_writes_are_never_retried") else {
        return;
    };
    let proxy = Proxy::start(upstream_addr(&url)).await;
    let mut fixture = Fixture::new("write", &url, Some(proxy.addr)).await;
    fixture
        .conn
        .execute_unprepared("CREATE TABLE tc951_effects (marker text NOT NULL)")
        .await
        .unwrap();
    let insert = |marker: &str| {
        Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO tc951_effects (marker) VALUES ($1)",
            [marker.to_owned().into()],
        )
    };
    // Prepare the statement on every connection, so the marker below
    // travels in the same write as its Execute and Sync.
    let idle = fixture.warm().await;
    for _ in 0..idle.len() * 2 {
        fixture.conn.execute(insert("warm")).await.unwrap();
    }
    fixture
        .conn
        .execute_unprepared("DELETE FROM tc951_effects")
        .await
        .unwrap();
    let idle = fixture.settle().await;

    // The connection is dead before the statement is sent.
    fixture.terminate(&idle).await;
    let before = fixture.stats();
    let error = fixture
        .conn
        .execute(insert("tc951-terminated"))
        .await
        .expect_err("an INSERT on a terminated connection fails");
    assert!(is_connection_error(&error), "{error:?}");
    let after = delta(before, fixture.stats());
    assert_eq!((after.losses, after.retries), (1, 0), "{after:?}");
    assert_eq!(fixture.row_count("tc951_effects").await, 0);
    eprintln!("INSERT on a terminated connection: {error:?}");

    // The server commits the INSERT, then the connection drops before the
    // client reads the result.
    let before = fixture.stats();
    proxy.cut_after_forwarding(b"tc951-committed");
    let error = fixture
        .conn
        .execute(insert("tc951-committed"))
        .await
        .expect_err("the INSERT's response was lost");
    assert!(is_connection_error(&error), "{error:?}");
    let after = delta(before, fixture.stats());
    assert_eq!((after.losses, after.retries), (1, 0), "{after:?}");
    assert_eq!(
        fixture.row_count("tc951_effects").await,
        1,
        "the INSERT ran exactly once"
    );
    eprintln!("INSERT whose response was lost: {error:?}");
    fixture.drop_schema().await;
}

/// With no loss, the acquire hook never pings; after one loss it re-validates
/// the connections that predate it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_steady_state_acquire_costs_no_ping() {
    let Some(url) = postgres_url("postgres_steady_state_acquire_costs_no_ping") else {
        return;
    };
    let mut fixture = Fixture::new("steady", &url, None).await;
    let idle = fixture.warm().await;
    for request in 0..5 {
        let key = format!("steady/{request}");
        fixture.put(&key).await.unwrap();
        fixture.get(&key).await.unwrap();
        fixture.delegate(&key).await.unwrap();
    }
    let steady = fixture.stats();
    assert_eq!(
        steady,
        PoolRecoveryStats::default(),
        "no loss, no retry and no ping in the steady state"
    );

    let victim = fixture.order_idle_queue(0).await;
    fixture.terminate(&BTreeSet::from([victim])).await;
    fixture.put("steady/after-loss").await.unwrap();
    let after = fixture.stats();
    eprintln!(
        "steady state {steady:?}; after one loss among {} idle connections {after:?}",
        idle.len()
    );
    assert_eq!((after.losses, after.retries), (1, 1), "{after:?}");
    assert!(
        after.revalidations >= 1,
        "connections idle since before the loss are pinged: {after:?}"
    );
    assert_eq!(after.revalidation_failures, 0, "only the victim was dead");
    fixture.drop_schema().await;
}
