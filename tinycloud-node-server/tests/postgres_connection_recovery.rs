//! TC-951: the Postgres pool recovers from connections lost while idle.
//!
//! The production pool (`tinycloud::connect_database`) skips sqlx's
//! unconditional pre-acquire ping. These tests kill pooled connections the
//! ways production loses them and show that the real request paths still
//! succeed: a KV put and a KV get through `SpaceDatabase::invoke`, and a
//! `delegate`, each with a signed owner invocation or delegation.
//!
//! - A terminated backend (`pg_terminate_backend`, what a failover does)
//!   answers with FATAL 57P01; an idle-session reaper with FATAL 57P05.
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
use tinycloud_core::hash::Hash;
use tinycloud_core::keys::StaticSecret;
use tinycloud_core::models::space as space_model;
use tinycloud_core::sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DbBackend, Statement, TransactionTrait,
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

/// Each test holds up to `MAX_CONNECTIONS` server connections; the test
/// server's `max_connections` (100 by default) is shared with other suites.
/// At most this many of these tests hold their pools at once.
static SERVER_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(3);

async fn server_slot() -> tokio::sync::SemaphorePermit<'static> {
    SERVER_SLOTS.acquire().await.unwrap()
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
    _slot: tokio::sync::SemaphorePermit<'static>,
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
        let slot = server_slot().await;
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
            _slot: slot,
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
        self.get_audited(key).await.map(|_| ())
    }

    /// A KV get; returns the id of its invocation, which the read audit
    /// records.
    async fn get_audited(&mut self, key: &str) -> Result<Hash, String> {
        let key: Path = key.parse().unwrap();
        let nonce = self.nonce();
        let invocation = self
            .owner
            .invocation("tinycloud.kv/get", &key, &nonce)
            .unwrap();
        let id = invocation.content_hash();
        let (_, outcomes) = self
            .db
            .invoke::<MemoryStaging>(invocation, HashMap::new())
            .await
            .map_err(|error| format!("kv get: {error}"))?;
        if outcomes.len() == 1 {
            Ok(id)
        } else {
            Err(format!("kv get: {} outcomes", outcomes.len()))
        }
    }

    /// Audit rows recorded for invocation `id`.
    async fn audit_rows(&self, id: Hash) -> i64 {
        self.admin
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT count(*) AS n FROM {}.invocation WHERE id = $1",
                    self.schema
                ),
                [id.into()],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap()
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
        // The read-audit pipeline shares the pool and may have opened one more.
        assert!(
            idle.len() >= WARM_CONNECTIONS,
            "only {} idle pooled connections",
            idle.len()
        );
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
        idempotent_retries: after.idempotent_retries - before.idempotent_retries,
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
    /// Markers a connection must forward, in order; the connection is cut
    /// after it forwards the last one.
    cut_after: Arc<watch::Sender<Option<Vec<Vec<u8>>>>>,
}

impl Proxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cut, cut_rx) = watch::channel(0u64);
        let cut_after = Arc::new(watch::Sender::new(None::<Vec<Vec<u8>>>));
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
        self.cut_after_forwarding_in_order(&[marker]);
    }

    /// Cut the first connection that forwards every one of `markers`, in
    /// order, right after it forwards the last.
    fn cut_after_forwarding_in_order(&self, markers: &[&[u8]]) {
        self.cut_after
            .send_replace(Some(markers.iter().map(|m| m.to_vec()).collect()));
    }
}

async fn pipe(
    mut client: TcpStream,
    mut server: TcpStream,
    mut cut: watch::Receiver<u64>,
    cut_after: Arc<watch::Sender<Option<Vec<Vec<u8>>>>>,
) {
    cut.mark_unchanged();
    // How many of the armed markers this connection has forwarded.
    let mut forwarded = 0;
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
                    let matched = {
                        let armed = cut_after.borrow();
                        match armed.as_deref() {
                            Some(markers) => {
                                if markers.get(forwarded).is_some_and(|m| {
                                    up[..n].windows(m.len()).any(|w| w == m.as_slice())
                                }) {
                                    forwarded += 1;
                                }
                                forwarded == markers.len()
                            }
                            None => {
                                forwarded = 0;
                                false
                            }
                        }
                    };
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
/// terminated. Requests issued one at a time each succeed, with at most one
/// retry, and the pool replaces the dead connections. (Concurrent requests
/// right after the loss: `postgres_concurrent_wave_after_mass_loss`.)
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

/// Candidate registration is an idempotent write before upload. A stale idle
/// connection must be retried here, before any blob can land in storage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_preupload_candidate_registration_retries_stale_connection() {
    let Some(url) =
        postgres_url("postgres_preupload_candidate_registration_retries_stale_connection")
    else {
        return;
    };
    let fixture = Fixture::new("candidate", &url, None).await;
    fixture.fill_pool().await;
    let victim = fixture.order_idle_queue(0).await;
    fixture.terminate(&BTreeSet::from([victim])).await;
    let before = fixture.stats();
    let blob = (
        fixture.owner.space.clone(),
        tinycloud_core::hash::hash(b"preupload-stale-connection"),
    );
    tinycloud_core::kv_orphans::register_candidates_idempotent(&fixture.conn, &[blob])
        .await
        .expect("candidate is registered after reconnect");
    let recovered = delta(before, fixture.stats());
    assert_eq!(
        (
            recovered.losses,
            recovered.retries,
            recovered.idempotent_retries
        ),
        (1, 1, 1),
        "{recovered:?}"
    );
    assert_eq!(fixture.row_count("kv_orphan_candidate").await, 1);
    fixture.drop_schema().await;
}

/// A protected write crosses the durable freeze row before storage.persist.
/// Losing an idle pooled connection must not bypass that fence or strand its
/// candidate; the resulting KV remains readable after the recovered commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_protected_preupload_fence_survives_stale_connection() {
    let Some(url) = postgres_url("postgres_protected_preupload_fence_survives_stale_connection")
    else {
        return;
    };
    let mut fixture = Fixture::new("protected", &url, None).await;
    fixture.fill_pool().await;
    let victim = fixture.order_idle_queue(0).await;
    fixture.terminate(&BTreeSet::from([victim])).await;
    let before = fixture.stats();
    let key = "xyz.tinycloud.tinychat/connectors/fireflies/transcript/stale-pool";
    fixture
        .put(key)
        .await
        .expect("protected put survives reconnect");
    fixture.get(key).await.expect("committed blob is readable");
    let recovered = delta(before, fixture.stats());
    assert_eq!(
        (recovered.losses, recovered.retries),
        (1, 1),
        "{recovered:?}"
    );
    assert_eq!(fixture.row_count("kv_orphan_candidate").await, 0);
    fixture.drop_schema().await;
}

/// A dead backend during the protected row lock rolls back that transaction.
/// Because storage has not run yet, the invocation can acquire a fresh
/// transaction, retake the fence, then upload and commit exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_preupload_freeze_lock_recovers_a_lost_transaction() {
    let Some(url) = postgres_url("postgres_preupload_freeze_lock_recovers_a_lost_transaction")
    else {
        return;
    };
    let mut fixture = Fixture::new("guardloss", &url, None).await;
    fixture
        .admin
        .execute_unprepared(&format!(
            "CREATE SEQUENCE {schema}.kill_once; \
             CREATE FUNCTION {schema}.kill_guard_once() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF nextval('{schema}.kill_once') = 1 THEN \
                 PERFORM pg_terminate_backend(pg_backend_pid()); \
               END IF; \
               RETURN NEW; \
             END $$; \
             CREATE TRIGGER kill_guard_once BEFORE INSERT ON {schema}.meeting_legacy_write_guard \
             FOR EACH ROW EXECUTE FUNCTION {schema}.kill_guard_once()",
            schema = fixture.schema
        ))
        .await
        .unwrap();
    let key = "xyz.tinycloud.tinychat/connectors/fireflies/transcript/guard-loss";
    fixture
        .put(key)
        .await
        .expect("retry preupload transaction after dead guard connection");
    fixture
        .get(key)
        .await
        .expect("only committed value survives");
    let killed = fixture
        .admin
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!("SELECT last_value AS n FROM {}.kill_once", fixture.schema),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap();
    assert_eq!(killed, 2, "row lock was retried exactly once");
    assert_eq!(fixture.row_count("kv_write").await, 2); // seed plus this put
    assert_eq!(fixture.row_count("kv_orphan_candidate").await, 0);
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

/// TC-1054 (Astra's P2): a KV put whose `COMMIT` reached the server but
/// whose reply was lost has an unknown outcome, and is reported as such, not
/// as a retryable failure: the put is durable, and a fresh retry would write
/// a second version. A put that never got a connection is retryable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_kv_put_with_a_lost_commit_reply_has_an_unknown_outcome() {
    use tinycloud_core::db_pool::{classify_failure, track_writes, TransientFailure};
    use tinycloud_core::{TxError, TxStoreError};

    let Some(url) = postgres_url("postgres_kv_put_with_a_lost_commit_reply_has_an_unknown_outcome")
    else {
        return;
    };
    let proxy = Proxy::start(upstream_addr(&url)).await;
    let mut fixture = Fixture::new("lostcommit", &url, Some(proxy.addr)).await;
    fixture.warm().await;
    fixture.settle().await;

    let put = |fixture: &mut Fixture, key: &str| {
        let key: Path = key.parse().unwrap();
        let nonce = fixture.nonce();
        let invocation = fixture
            .owner
            .invocation("tinycloud.kv/put", &key, &nonce)
            .unwrap();
        let mut inputs = HashMap::new();
        inputs.insert(
            (fixture.owner.space.clone(), key),
            (
                Metadata(BTreeMap::new()),
                HashBuffer::new(b"tc1054 value".to_vec()),
            ),
        );
        (fixture.db.clone(), invocation, inputs)
    };
    let db_error = |result| match result {
        Err(TxStoreError::Tx(TxError::Db(error))) => error,
        Err(other) => panic!("expected a database error, got {other}"),
        Ok(_) => panic!("expected a database error, got success"),
    };

    // The put's own connection: its key, then its COMMIT.
    proxy.cut_after_forwarding_in_order(&[b"tc1054/lost-commit", b"COMMIT"]);
    let (db, invocation, inputs) = put(&mut fixture, "tc1054/lost-commit");
    let (result, applied) = track_writes(db.invoke::<MemoryStaging>(invocation, inputs)).await;
    let error = db_error(result);
    assert!(is_connection_error(&error), "{error:?}");
    assert!(applied, "the transaction was begun and its COMMIT sent");
    assert_eq!(
        classify_failure(&error, applied),
        Some(TransientFailure::OutcomeUnknown)
    );
    fixture
        .get("tc1054/lost-commit")
        .await
        .expect("the put committed; reading back finds it");

    // No connection to be had: nothing was written, a fresh put is safe.
    fixture
        .conn
        .sea_orm_connection()
        .clone()
        .close()
        .await
        .unwrap();
    let (db, invocation, inputs) = put(&mut fixture, "tc1054/no-connection");
    let (result, applied) = track_writes(db.invoke::<MemoryStaging>(invocation, inputs)).await;
    let error = db_error(result);
    assert!(!applied);
    assert_eq!(
        classify_failure(&error, applied),
        Some(TransientFailure::Retryable),
        "{error:?}"
    );
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

/// A pool on `url` with `application_name` and server `session_options`
/// (`-c name=value ...`): the production constructor when `recovery` is
/// `None`, else the same pool builder with that recovery state.
async fn session_pool(
    url: &str,
    application_name: &str,
    session_options: &str,
    max_connections: u32,
    recovery: Option<Arc<tinycloud_core::db_pool::PoolRecovery>>,
) -> RecoveringConnection {
    init_tracing();
    let mut url = reqwest::Url::parse(url).unwrap();
    url.query_pairs_mut()
        .append_pair("application_name", application_name)
        .append_pair("options", session_options);
    let conn = match recovery {
        None => {
            let mut config = Config::default();
            config.storage.database = Some(url.to_string());
            config.database.max_connections = max_connections;
            tinycloud::connect_database(&config).await.unwrap()
        }
        Some(recovery) => {
            let mut options = ConnectOptions::new(url.to_string());
            options.max_connections(max_connections);
            tinycloud::postgres_pool_with_recovery(options, None, &Default::default(), recovery)
                .await
                .unwrap()
        }
    };
    assert!(conn.recovery().is_some());
    conn
}

/// Open `count` connections at once and wait until all are idle again.
async fn open_idle(conn: &RecoveringConnection, count: usize) {
    let pool = conn.sea_orm_connection().get_postgres_connection_pool();
    let mut held = Vec::new();
    for _ in 0..count {
        held.push(pool.acquire().await.unwrap());
    }
    drop(held);
    for _ in 0..400 {
        if pool.num_idle() == count && pool.size() as usize == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("pool did not settle at {count} idle connections");
}

fn unique(name: &str) -> String {
    format!(
        "tc951-{name}-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000
    )
}

fn select_one() -> Statement {
    Statement::from_string(DbBackend::Postgres, "SELECT 1 AS one")
}

/// PostgreSQL's `idle_session_timeout` ends an idle pooled session with
/// FATAL 57P05 (Astra's repro). It is a lost connection: on the production
/// pool, a read and a `BEGIN` after the timeout each succeed with one retry,
/// and once a loss is seen the other reaped connections are revalidated
/// before reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_idle_session_timeout_is_a_lost_connection() {
    let Some(url) = postgres_url("postgres_idle_session_timeout_is_a_lost_connection") else {
        return;
    };
    let _slot = server_slot().await;
    let timeout = "-c idle_session_timeout=500ms";

    // The raw error a reaped session returns, unretried.
    let conn = session_pool(&url, &unique("57p05-raw"), timeout, 1, None).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let error = conn
        .sea_orm_connection()
        .query_one(select_one())
        .await
        .expect_err("the reaped session fails");
    eprintln!("a session reaped by idle_session_timeout: {error:?}");
    assert!(is_connection_error(&error), "{error:?}");

    // One connection: a read, then a BEGIN, each after the timeout.
    let conn = session_pool(&url, &unique("57p05-one"), timeout, 1, None).await;
    let recovery = Arc::clone(conn.recovery().unwrap());
    tokio::time::sleep(Duration::from_secs(1)).await;
    conn.query_one(select_one())
        .await
        .expect("the read recovers")
        .unwrap();
    assert_eq!((recovery.stats().losses, recovery.stats().retries), (1, 1));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let tx = conn.begin().await.expect("BEGIN recovers");
    tx.query_one(select_one()).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert_eq!((recovery.stats().losses, recovery.stats().retries), (2, 2));

    // Several reaped connections: after the first loss the rest are
    // revalidated, and closed, before reuse.
    let conn = session_pool(&url, &unique("57p05-many"), timeout, 4, None).await;
    let recovery = Arc::clone(conn.recovery().unwrap());
    open_idle(&conn, 4).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    conn.query_one(select_one())
        .await
        .expect("the read recovers")
        .unwrap();
    let stats = recovery.stats();
    eprintln!("4 reaped connections, one read: {stats:?}");
    assert_eq!((stats.losses, stats.retries), (1, 1), "{stats:?}");
    assert!(
        stats.revalidations >= 1 && stats.revalidation_failures >= 1,
        "{stats:?}"
    );
}

/// A reaper that keeps closing idle connections (`idle_session_timeout`, a
/// NAT or load balancer) produces dead connections released after any
/// observed loss. The idle threshold covers them: each autocommit INSERT
/// and each BEGIN, after the session timeout, succeeds with no loss, the
/// hook having revalidated its connection, and no INSERT runs twice. The
/// threshold is shortened from production's 60 s to 500 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_idle_reaped_connections_are_revalidated_before_reuse() {
    let Some(url) = postgres_url("postgres_idle_reaped_connections_are_revalidated_before_reuse")
    else {
        return;
    };
    let _slot = server_slot().await;
    let admin = Database::connect(ConnectOptions::new(url.clone()))
        .await
        .unwrap();
    let schema = unique("reaped").replace('-', "_");
    admin
        .execute_unprepared(&format!(
            "CREATE SCHEMA {schema}; CREATE TABLE {schema}.tc951_reaped (marker text NOT NULL)"
        ))
        .await
        .unwrap();
    let recovery =
        tinycloud_core::db_pool::PoolRecovery::with_idle_revalidation(Duration::from_millis(500));
    let conn = session_pool(
        &url,
        &unique("reaped"),
        &format!("-c search_path={schema} -c idle_session_timeout=1000"),
        4,
        Some(Arc::clone(&recovery)),
    )
    .await;
    open_idle(&conn, 4).await;

    let insert = |marker: String| {
        Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO tc951_reaped (marker) VALUES ($1)",
            [marker.into()],
        )
    };
    let rounds = 4;
    for round in 0..rounds {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        conn.execute(insert(format!("autocommit-{round}")))
            .await
            .unwrap_or_else(|error| panic!("autocommit INSERT {round}: {error:?}"));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let tx = conn
            .begin()
            .await
            .unwrap_or_else(|error| panic!("BEGIN {round}: {error:?}"));
        tx.execute(insert(format!("transaction-{round}")))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let stats = recovery.stats();
    eprintln!("{rounds} rounds of INSERT and BEGIN after 1.5 s idle: {stats:?}");
    assert_eq!((stats.losses, stats.retries), (0, 0), "{stats:?}");
    assert!(stats.revalidations > 0, "{stats:?}");
    let rows = admin
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!("SELECT count(*) AS n, count(DISTINCT marker) AS d FROM {schema}.tc951_reaped"),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rows.try_get::<i64>("", "n").unwrap(), 2 * rounds);
    assert_eq!(rows.try_get::<i64>("", "d").unwrap(), 2 * rounds);
    conn.sea_orm_connection()
        .get_postgres_connection_pool()
        .close()
        .await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Astra's probe: `SELECT nextval(...)` is not read-only. When its response
/// is lost after the server ran it, it is not run again: the error is
/// returned and the sequence advanced exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_side_effecting_select_is_not_retried() {
    let Some(url) = postgres_url("postgres_side_effecting_select_is_not_retried") else {
        return;
    };
    let proxy = Proxy::start(upstream_addr(&url)).await;
    let fixture = Fixture::new("nextval", &url, Some(proxy.addr)).await;
    fixture
        .conn
        .execute_unprepared("CREATE SEQUENCE tc951_seq")
        .await
        .unwrap();
    fixture.settle().await;
    let before = fixture.stats();
    proxy.cut_after_forwarding(b"tc951_seq");
    let error = fixture
        .conn
        .execute_unprepared("SELECT nextval('tc951_seq')")
        .await
        .expect_err("the nextval response was lost");
    assert!(is_connection_error(&error), "{error:?}");
    let after = delta(before, fixture.stats());
    assert_eq!((after.losses, after.retries), (1, 0), "{after:?}");
    let last = fixture
        .admin
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT last_value, is_called FROM {}.tc951_seq",
                fixture.schema
            ),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(last.try_get::<i64>("", "last_value").unwrap(), 1);
    assert!(last.try_get::<bool>("", "is_called").unwrap());
    fixture.drop_schema().await;
}

/// A concurrent wave right after every idle connection died. The tasks that
/// acquired a dead connection before the first loss was observed each meet
/// it: the reads and BEGINs among them are retried and succeed; the writes
/// among them fail, never more than the dead connections. Every request
/// after the wave succeeds with no further loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_concurrent_wave_after_mass_loss() {
    let Some(url) = postgres_url("postgres_concurrent_wave_after_mass_loss") else {
        return;
    };
    let mut fixture = Fixture::new("wave", &url, None).await;
    fixture
        .conn
        .execute_unprepared("CREATE TABLE tc951_wave (marker text NOT NULL)")
        .await
        .unwrap();
    let idle = fixture.warm().await;
    fixture.terminate(&idle).await;
    let before = fixture.stats();

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Kind {
        Read,
        Begin,
        Write,
    }
    let per_kind = 6;
    let wave = [Kind::Read, Kind::Begin, Kind::Write]
        .into_iter()
        .flat_map(|kind| (0..per_kind).map(move |i| (kind, i)))
        .collect::<Vec<_>>();
    let barrier = Arc::new(tokio::sync::Barrier::new(wave.len()));
    let tasks = wave
        .into_iter()
        .map(|(kind, i)| {
            let conn = fixture.conn.clone();
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                let insert = Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "INSERT INTO tc951_wave (marker) VALUES ($1)",
                    [format!("{kind:?}-{i}").into()],
                );
                barrier.wait().await;
                let result = match kind {
                    Kind::Read => conn.query_one(select_one()).await.map(|_| ()),
                    Kind::Begin => {
                        async {
                            let tx = conn.begin().await?;
                            tx.execute(insert).await?;
                            tx.commit().await
                        }
                        .await
                    }
                    Kind::Write => conn.execute(insert).await.map(|_| ()),
                };
                (kind, result)
            })
        })
        .collect::<Vec<_>>();
    let mut write_failures = 0u64;
    let mut written = 0i64;
    for task in tasks {
        let (kind, result) = task.await.unwrap();
        match (kind, result) {
            (Kind::Write, Err(error)) => {
                assert!(is_connection_error(&error), "{error:?}");
                write_failures += 1;
            }
            (_, Err(error)) => panic!("{kind:?} failed: {error:?}"),
            (Kind::Read, Ok(())) => {}
            (_, Ok(())) => written += 1,
        }
    }
    let wave_stats = delta(before, fixture.stats());
    eprintln!(
        "wave of {} after terminating {} idle connections: {write_failures} write failures, {wave_stats:?}",
        3 * per_kind,
        idle.len()
    );
    assert!(write_failures <= idle.len() as u64);
    assert_eq!(
        wave_stats.losses,
        wave_stats.retries + write_failures,
        "every loss was retried, or is a failed write: {wave_stats:?}"
    );
    assert_eq!(
        fixture.row_count("tc951_wave").await,
        written,
        "no write ran twice"
    );

    let after_wave = fixture.stats();
    for round in 0..3 {
        fixture.conn.query_one(select_one()).await.unwrap();
        let tx = fixture.conn.begin().await.unwrap();
        tx.commit().await.unwrap();
        fixture
            .conn
            .execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO tc951_wave (marker) VALUES ($1)",
                [format!("after-{round}").into()],
            ))
            .await
            .unwrap();
        let key = format!("after/wave/{round}");
        fixture.put(&key).await.unwrap();
        fixture.get(&key).await.unwrap();
        fixture.delegate(&key).await.unwrap();
    }
    assert_eq!(
        delta(after_wave, fixture.stats()).losses,
        0,
        "no loss after the wave"
    );
    fixture.drop_schema().await;
}

/// The read audit commits on PostgreSQL as one `WITH ... INSERT` statement,
/// which the read-only classifier does not retry. It goes through
/// `execute_idempotent` instead: with one dead connection at each position
/// of the idle queue, some KV get's audit statement meets it, is retried,
/// and the get succeeds with its audit row written exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_read_audit_statement_survives_a_stale_connection() {
    let Some(url) = postgres_url("postgres_read_audit_statement_survives_a_stale_connection")
    else {
        return;
    };
    let mut fixture = Fixture::new("audit", &url, None).await;
    fixture.warm().await;
    fixture.put("audit/key").await.unwrap();
    let mut audit_hits = Vec::new();
    for position in 0..WARM_CONNECTIONS {
        fixture.fill_pool().await;
        let victim = fixture.order_idle_queue(position).await;
        fixture.terminate(&BTreeSet::from([victim])).await;
        let before = fixture.stats();
        let mut rounds = 0;
        while fixture.stats().losses == before.losses {
            rounds += 1;
            assert!(rounds <= 30, "position {position}: never reached");
            let id = fixture
                .get_audited("audit/key")
                .await
                .unwrap_or_else(|error| panic!("position {position}: {error}"));
            assert_eq!(
                fixture.audit_rows(id).await,
                1,
                "position {position}: the get's audit row exists exactly once"
            );
        }
        let total = delta(before, fixture.stats());
        assert_eq!(
            (total.losses, total.retries),
            (1, 1),
            "position {position}: {total:?}"
        );
        if total.idempotent_retries == 1 {
            audit_hits.push(position);
        }
    }
    eprintln!("queue positions whose dead connection met the read-audit statement: {audit_hits:?}");
    assert!(
        !audit_hits.is_empty(),
        "no position put the dead connection under the read-audit statement"
    );
    fixture.drop_schema().await;
}
