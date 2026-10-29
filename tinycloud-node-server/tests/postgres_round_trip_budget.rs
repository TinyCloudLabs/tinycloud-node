//! TC-951: PostgreSQL round-trip budget for an SDK sign-in, a KV put and a
//! KV get.
//!
//! The node's request latency on a remote database is dominated by round
//! trips, not by statement cost. This test counts them on the wire and fails
//! when a flow needs more than its budget, so a change that adds a round trip
//! to these paths (a pre-acquire ping, an extra transaction, a statement that
//! could have been folded into another) is caught by `cargo test` instead of
//! by a slower production node.
//!
//! # What is driven
//!
//! The real node: `tinycloud::app_with_control` behind
//! `rocket::local::asynchronous::Client`, so the pool is built through the
//! production configuration path. The budget fixture caps its pool as described
//! below; its database URL points at an in-test TCP proxy in front of PostgreSQL,
//! with TLS off and a throwaway schema on the search path. The flows are the node side
//! of what `@tinycloud/node-sdk` sends, built with the SDK's own Rust half
//! (`tinycloud-sdk-wasm`). The SDK's sign-in touches several spaces and
//! repeats these requests for each; one space is enough to price them:
//!
//! - **sign-in**: `GET /peer/generate/<space>`, the space-host `/delegate`
//!   (creates the account space), the session `/delegate` (SIWE ReCap to a
//!   session key), and the account-space SQL call (the account index's
//!   `CREATE TABLE IF NOT EXISTS`, through the TC-780 fence and resolve);
//! - **kv put**: an `/invoke` `tinycloud.kv/put` of a new key;
//! - **kv get**: an `/invoke` `tinycloud.kv/get` of that key, which waits for
//!   the durable read-audit commit before it answers;
//! - **kv batch get / kv batch head**: one `/invoke` of `tinycloud.kv/get` or
//!   `tinycloud.kv/metadata` over 100 keys (TC-1274).
//!
//! # What is counted
//!
//! The proxy parses the frontend protocol after startup. A round trip ends at
//! every simple `Query` ('Q') and every `Sync` ('S'): an extended statement,
//! a BEGIN or COMMIT, and sqlx's ping, which is a bare Sync. sqlx pings on
//! every release, and on every acquire when `test_before_acquire` is on, so
//! statement counts alone undercount and re-enabling the pre-acquire ping
//! fails this test. Statements (Execute plus simple Query) and new
//! connections (StartupMessage) are reported alongside.
//!
//! Round trips that depend on history rather than on the request are reported
//! but not budgeted:
//!
//! - `statement-cache`: sqlx prepares a named statement in its own round trip
//!   the first time a connection runs it, and closes one in another when the
//!   connection's 100-statement cache is full. Which pooled connection serves
//!   which statement varies from run to run, so these vary too.
//! - `excluded`: traffic that shares the pool but belongs to no request,
//!   recognised by its statement text, together with the release ping that
//!   follows it on the same connection: the webhook dispatcher's 1 Hz
//!   due-delivery poll, which `app_with_control` always spawns and no setting
//!   disables; the invocation-replay cleanup at liftoff and every 60 s; and
//!   the legacy-artifact scan of the SQL fence, which reruns only once its 1 s
//!   cache has expired, so whether a given SQL call pays it depends on wall
//!   time.
//!
//! The counts are deterministic without sleeping for them: every request is
//! measured between two barriers that wait until every pooled connection is
//! idle again, so the release ping of the last statement is inside the window
//! and no request overlaps another's traffic. The barriers cannot stop the
//! webhook dispatcher from checking a connection out just after a mark, and a
//! request that then finds no idle connection opens one and pays its
//! `SET statement_timeout` round trip. So the pool is capped at `POOL_SIZE`
//! and every connection it may hold is opened before the first flow, and a
//! measured request that still opens a connection fails the test instead of
//! being counted. The cap only keeps the fully opened pool small, because
//! test binaries run concurrently against one CI PostgreSQL and the default
//! of 100 connections each could exhaust it; a request's round trips do not
//! depend on the pool size. The flows then run three times first, so the
//! statements are prepared.
//!
//! # Budgets
//!
//! Each budget is the count measured when it was last changed, with no slack.
//! A change that lowers a count should lower the budget with it; the test
//! prints the measured counts for that. Run it with:
//!
//! ```text
//! TINYCLOUD_ALLOW_LOCAL_PG=1 \
//! TINYCLOUD_TEST_POSTGRES_URL=postgres://<user>:<password>@<host>:<port>/<database> \
//!   cargo test -p tinycloud-node --test postgres_round_trip_budget -- --nocapture
//! ```
//!
//! PostgreSQL-backed tests connect only when `TINYCLOUD_TEST_POSTGRES_URL` is set
//! and either `GITHUB_ACTIONS=true` (GitHub Actions) or `TINYCLOUD_ALLOW_LOCAL_PG=1`
//! (an isolated server you started yourself). Otherwise they skip. On GitHub
//! Actions, an unset URL fails the test (TC-381).

mod common;

use std::{
    collections::HashMap,
    fmt::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::{Client, LocalRequest},
};
use sha3::{Digest, Keccak256};
use tinycloud_auth::{
    cacaos::{
        siwe::{Message, TimeStamp},
        siwe_cacao::Signature,
    },
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::dids::DIDBuf,
};
use tinycloud_core::{
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    sql::SqlRequest,
    RecoveringConnection,
};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Round trips allowed per flow; see the module docs. Each invocation's
/// transaction-scoped authorization snapshot fetches edges, delegations,
/// abilities and revocations in one tagged query (TC-735, #302); capability
/// checks and connection-release pings are part of each flow's count. Measured
/// on PostgreSQL before the pre-persist write path:
///
/// - sign-in 71 = peer key 0 plus host `/delegate` 18 plus session
///   `/delegate` 19 plus account-space SQL write 34, including the `epoch_head`
///   cache writes and post-commit `hook_subscription` SELECT and release ping.
///   The hook lookup runs asynchronously and can fall outside the measured
///   window, so a run may print 2 fewer. Details: TC-2214
/// - kv get 16, including its durable read-audit commit.
///
/// TC-1274: a batch of 100 `kv/get` or `kv/metadata` capabilities is one
/// `current_kv` lookup per space, so it costs what a single kv get costs. The
/// flows also check the responses against the fixture, and the test fails if a
/// batch reads `current_kv` in more than one statement.
///
/// KV PUT is 42: 35 round trips for the put itself (31 statements and pings,
/// with #302 and the `epoch_head` cache write) plus seven around the upload:
/// the preparatory transaction's `BEGIN`, its authorization graph read, the
/// candidate-and-attempt claim CTE (which also checks that every invocation
/// space is hosted) and its `COMMIT`; the preparatory connection's release
/// ping; the joined active-fence/own-attempt lock that excludes GC after
/// upload; and the successful-commit CTE that retires the attempt and an
/// already referenced last fence. A failed last attempt persists a deleting
/// fence until physical absence is confirmed. SQLite and MySQL use the
/// equivalent guarded multi-statement paths rather than the PostgreSQL-only
/// CTEs.
///
/// Multi-write puts (a multipart `kv/put` of several keys, one invocation):
/// the two-key rows use the same request shape, so they differ only in how
/// many distinct blobs the keys hold. Each distinct blob adds its registration
/// statement, its fence lock and its finish; every key adds its own
/// precondition read and write rows. All claims of one put share one
/// preparatory transaction.
///
/// Full-flow ceilings, including asynchronous sign-in work. Details: TC-2214
const BUDGETS: [(&str, u64); 7] = [
    ("sign-in", 71),
    ("kv put", 42),
    ("kv get", 16),
    ("kv batch get", 16),
    ("kv batch head", 16),
    ("kv put 2 blobs", 48),
    ("kv put 1 blob 2 keys", 45),
];

/// Full sign-in plus put plus get rounds run before the measured one.
const WARM_UP_ROUNDS: u8 = 3;

/// Connections in the measured node's pool, all opened before the flows run;
/// see the module docs.
const POOL_SIZE: u32 = 4;

/// The account space and SQL database the SDK bootstraps at sign-in.
const ACCOUNT_SPACE: &str = "account";
const ACCOUNT_DATABASE: &str = "account";
/// First statement of the SDK's account index (`ACCOUNT_INDEX_SCHEMA`).
const ACCOUNT_INDEX_DDL: &str = "CREATE TABLE IF NOT EXISTS applications (
    app_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    updated_at TEXT,
    manifest_json TEXT NOT NULL
  )";
/// The key the SDK writes when the account bootstrap completes.
const KV_KEY: &str = "bootstrap/complete";
const KV_VALUE: &[u8] = br#"{"version":1}"#;

/// PostgreSQL protocol 3.0, the version field of a StartupMessage.
const PROTOCOL_V3: i32 = 196_608;

/// TC-381: see `common::postgres_test_url`.
fn postgres_test_url(test: &str) -> Option<String> {
    common::postgres_test_url(test)
}

// ---------------------------------------------------------------------------
// Wire counting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// Part of the request: counted against the budget.
    Counted,
    /// sqlx's per-connection statement cache at work: the Parse of a named
    /// statement the connection had not cached yet, or the Close that evicts
    /// one when the cache (100 statements) is full.
    StatementCache,
    /// Background or wall-clock-dependent traffic; see the module docs.
    Excluded(&'static str),
}

#[derive(Debug, Clone)]
struct RoundTrip {
    connection: u64,
    kind: Kind,
    /// Statements executed in this round trip (Execute or simple Query).
    executed: Vec<String>,
    /// Statements parsed in this round trip.
    parsed: Vec<String>,
}

#[derive(Default)]
struct Log {
    connections: u64,
    round_trips: Vec<RoundTrip>,
}

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<Log>>);

#[derive(Clone, Copy)]
struct Mark {
    connections: u64,
    round_trips: usize,
}

impl Wire {
    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.0.lock().expect("wire log poisoned")
    }

    fn mark(&self) -> Mark {
        let log = self.log();
        Mark {
            connections: log.connections,
            round_trips: log.round_trips.len(),
        }
    }

    fn since(&self, mark: Mark) -> Window {
        let log = self.log();
        Window {
            connections: log.connections - mark.connections,
            round_trips: log.round_trips[mark.round_trips..].to_vec(),
        }
    }
}

/// Traffic that is not part of any request, by statement text.
fn background(sql: &str) -> Option<&'static str> {
    if sql.starts_with(r#"SELECT "hook_delivery"."id" AS "A_id""#) {
        Some("webhook dispatcher poll")
    } else if sql.starts_with(r#"DELETE FROM "invocation_replay""#) {
        Some("invocation replay cleanup")
    } else if sql.starts_with(r#"SELECT "database_artifact"."service""#)
        && sql.contains(r#"NOT EXISTS(SELECT $3 FROM "database_legacy_artifact""#)
    {
        Some("legacy-artifact scan (1 s cache)")
    } else {
        None
    }
}

/// Splits one connection's frontend byte stream into messages and records a
/// round trip at every Sync and simple Query.
struct FrontendParser {
    wire: Wire,
    connection: u64,
    started: bool,
    buf: Vec<u8>,
    prepared: HashMap<String, String>,
    unnamed: String,
    portal: String,
    executed: Vec<String>,
    parsed: Vec<String>,
    /// This round trip parsed a named statement or closed one.
    cache_traffic: bool,
    /// Set after an excluded statement, so its release ping is excluded too.
    excluded_owner: Option<&'static str>,
}

fn cstr(bytes: &[u8]) -> (String, &[u8]) {
    match bytes.iter().position(|b| *b == 0) {
        Some(end) => (
            String::from_utf8_lossy(&bytes[..end]).into_owned(),
            &bytes[end + 1..],
        ),
        None => (String::from_utf8_lossy(bytes).into_owned(), &[]),
    }
}

fn be_i32(bytes: &[u8]) -> i32 {
    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

impl FrontendParser {
    fn new(wire: Wire, connection: u64) -> Self {
        Self {
            wire,
            connection,
            started: false,
            buf: Vec::new(),
            prepared: HashMap::new(),
            unnamed: String::new(),
            portal: String::new(),
            executed: Vec::new(),
            parsed: Vec::new(),
            cache_traffic: false,
            excluded_owner: None,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        loop {
            if !self.started {
                // Untyped startup-phase message: SSLRequest, GSSENCRequest,
                // CancelRequest or the StartupMessage itself.
                if self.buf.len() < 8 {
                    return;
                }
                let len = be_i32(&self.buf[0..4]).max(8) as usize;
                if self.buf.len() < len {
                    return;
                }
                if be_i32(&self.buf[4..8]) == PROTOCOL_V3 {
                    self.started = true;
                    self.wire.log().connections += 1;
                }
                self.buf.drain(..len);
            } else {
                if self.buf.len() < 5 {
                    return;
                }
                let len = be_i32(&self.buf[1..5]).max(4) as usize;
                if self.buf.len() < 1 + len {
                    return;
                }
                let tag = self.buf[0];
                let body = self.buf[5..1 + len].to_vec();
                self.buf.drain(..1 + len);
                self.message(tag, &body);
            }
        }
    }

    fn message(&mut self, tag: u8, body: &[u8]) {
        match tag {
            b'P' => {
                let (name, rest) = cstr(body);
                let (query, _) = cstr(rest);
                if name.is_empty() {
                    self.unnamed = query.clone();
                } else {
                    self.cache_traffic = true;
                    self.prepared.insert(name, query.clone());
                }
                self.parsed.push(query);
            }
            b'B' => {
                let (_portal, rest) = cstr(body);
                let (statement, _) = cstr(rest);
                self.portal = if statement.is_empty() {
                    self.unnamed.clone()
                } else {
                    self.prepared.get(&statement).cloned().unwrap_or_default()
                };
            }
            b'E' => self.executed.push(self.portal.clone()),
            b'Q' => {
                let (query, _) = cstr(body);
                self.executed.push(query);
                self.finish();
            }
            b'S' => self.finish(),
            // Close of a prepared statement (not of a portal).
            b'C' if body.first() == Some(&b'S') => self.cache_traffic = true,
            _ => {}
        }
    }

    fn finish(&mut self) {
        let executed = std::mem::take(&mut self.executed);
        let parsed = std::mem::take(&mut self.parsed);
        let cache_traffic = std::mem::take(&mut self.cache_traffic);
        let statements = if executed.is_empty() {
            &parsed
        } else {
            &executed
        };
        let background = statements
            .iter()
            .map(|sql| background(sql))
            .reduce(|a, b| if a == b { a } else { None })
            .flatten();
        let kind = if let Some(label) = background {
            self.excluded_owner = Some(label);
            Kind::Excluded(label)
        } else if executed.is_empty() && cache_traffic {
            Kind::StatementCache
        } else if executed.is_empty() && parsed.is_empty() {
            match self.excluded_owner.take() {
                Some(label) => Kind::Excluded(label),
                None => Kind::Counted,
            }
        } else {
            self.excluded_owner = None;
            Kind::Counted
        };
        self.wire.log().round_trips.push(RoundTrip {
            connection: self.connection,
            kind,
            executed,
            parsed,
        });
    }
}

/// Listens on an ephemeral loopback port and relays every connection to
/// `upstream`. Client bytes are parsed before they are forwarded, so a reply
/// from PostgreSQL implies the request that caused it is already logged.
/// Cut the connection that forwards every one of `markers`, in order (TC-1054
/// route tests): the server receives the last one, the node never sees a
/// reply to it, and the connection is reset. Armed for `times` connections.
#[derive(Clone, Default)]
struct Cut(Arc<parking_lot::Mutex<Armed>>);

/// The markers still to match, in order, and how many connections to cut.
type Armed = Option<(Vec<Vec<u8>>, usize)>;

impl Cut {
    fn arm(&self, markers: &[&[u8]], times: usize) {
        *self.0.lock() = Some((markers.iter().map(|m| m.to_vec()).collect(), times));
    }

    fn armed(&self) -> bool {
        self.0.lock().is_some()
    }

    fn disarm(&self) {
        *self.0.lock() = None;
    }

    /// Advance a connection's `progress` through the armed markers over
    /// `bytes`; whether the connection must now be cut.
    fn observe(&self, progress: &mut usize, bytes: &[u8]) -> bool {
        let mut armed = self.0.lock();
        let Some((markers, times)) = armed.as_mut() else {
            *progress = 0;
            return false;
        };
        while let Some(marker) = markers.get(*progress) {
            if !bytes.windows(marker.len()).any(|w| w == marker.as_slice()) {
                break;
            }
            *progress += 1;
        }
        if *progress < markers.len() {
            return false;
        }
        *times -= 1;
        if *times == 0 {
            *armed = None;
        }
        true
    }
}

async fn start_proxy(upstream: (String, u16), wire: Wire, cut: Cut) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let mut next_connection = 0;
        while let Ok((client, _)) = listener.accept().await {
            next_connection += 1;
            let connection = next_connection;
            let upstream = upstream.clone();
            let wire = wire.clone();
            let cut = cut.clone();
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect((upstream.0.as_str(), upstream.1)).await else {
                    return;
                };
                let _ = client.set_nodelay(true);
                let _ = server.set_nodelay(true);
                // A cut connection is reset, not closed.
                #[allow(deprecated)]
                let _ = client.set_linger(Some(Duration::ZERO));
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                let severed = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let backend = {
                    let severed = severed.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0; 16 * 1024];
                        while let Ok(n @ 1..) = server_read.read(&mut buf).await {
                            if severed.load(std::sync::atomic::Ordering::SeqCst)
                                || client_write.write_all(&buf[..n]).await.is_err()
                            {
                                return;
                            }
                        }
                        let _ = client_write.shutdown().await;
                    })
                };
                let mut parser = FrontendParser::new(wire, connection);
                let mut progress = 0;
                let mut buf = vec![0; 16 * 1024];
                loop {
                    let n = match client_read.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    parser.feed(&buf[..n]);
                    let sever = cut.observe(&mut progress, &buf[..n]);
                    if sever {
                        // Before forwarding: no reply may reach the node.
                        severed.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    if server_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if sever {
                        // Let the server act on it (commit), then reset.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        backend.abort();
                        return;
                    }
                }
                let _ = server_write.shutdown().await;
                let _ = backend.await;
            });
        }
    });
    Ok(address)
}

/// The traffic between two marks.
#[derive(Default, Clone)]
struct Window {
    connections: u64,
    round_trips: Vec<RoundTrip>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct Counts {
    round_trips: u64,
    statements: u64,
    statement_cache: u64,
    excluded: u64,
    connections: u64,
}

impl std::ops::AddAssign for Counts {
    fn add_assign(&mut self, other: Self) {
        self.round_trips += other.round_trips;
        self.statements += other.statements;
        self.statement_cache += other.statement_cache;
        self.excluded += other.excluded;
        self.connections += other.connections;
    }
}

impl Window {
    fn counts(&self) -> Counts {
        let mut counts = Counts {
            connections: self.connections,
            ..Counts::default()
        };
        for round_trip in &self.round_trips {
            match round_trip.kind {
                Kind::Counted => {
                    counts.round_trips += 1;
                    counts.statements += round_trip.executed.len() as u64;
                }
                Kind::StatementCache => counts.statement_cache += 1,
                Kind::Excluded(_) => counts.excluded += 1,
            }
        }
        counts
    }

    /// Counted statements that read `current_kv`: the KV index lookups.
    fn current_kv_statements(&self) -> u64 {
        self.round_trips
            .iter()
            .filter(|round_trip| round_trip.kind == Kind::Counted)
            .flat_map(|round_trip| &round_trip.executed)
            .filter(|sql| sql.contains(r#"FROM "current_kv""#))
            .count() as u64
    }

    fn describe(&self, out: &mut String) {
        for round_trip in &self.round_trips {
            let kind = match round_trip.kind {
                Kind::Counted => "",
                Kind::StatementCache => "[statement cache] ",
                Kind::Excluded(label) => &format!("[excluded: {label}] "),
            };
            let text = if !round_trip.executed.is_empty() {
                round_trip.executed.join(" ; ")
            } else if !round_trip.parsed.is_empty() {
                format!("parse {}", round_trip.parsed.join(" ; "))
            } else {
                "<ping>".to_owned()
            };
            let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
            let text: String = text.chars().take(110).collect();
            let _ = writeln!(out, "      c{:<3} {kind}{text}", round_trip.connection);
        }
    }
}

// ---------------------------------------------------------------------------
// The node under test
// ---------------------------------------------------------------------------

struct Node {
    client: Client,
    wire: Wire,
}

/// One measured request.
struct Measured {
    flow: &'static str,
    request: &'static str,
    window: Window,
}

impl Node {
    fn pool(&self) -> &tinycloud_core::sea_orm::sqlx::PgPool {
        self.client
            .rocket()
            .state::<RecoveringConnection>()
            .expect("the node manages its RecoveringConnection")
            .sea_orm_connection()
            .get_postgres_connection_pool()
    }

    /// Wait until every pooled connection is idle: no request statement and
    /// no release ping is still in flight.
    async fn settle(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let pool = self.pool();
            if pool.num_idle() == pool.size() as usize {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "the pool did not return to idle within 30 s"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Open all `max` connections the pool may hold at once, then return them
    /// to idle, so no later request has to connect.
    async fn open_pool(&self, max: u32) -> Result<()> {
        self.settle().await?;
        let pool = self.pool();
        let mut held = Vec::with_capacity(max as usize);
        for _ in 0..max {
            held.push(pool.acquire().await?);
        }
        ensure!(
            pool.size() == max,
            "the pool holds {} connections, not {max}",
            pool.size()
        );
        drop(held);
        self.settle().await
    }

    /// Dispatch `request` between two settled marks.
    async fn measure(
        &self,
        flow: &'static str,
        request_label: &'static str,
        request: LocalRequest<'_>,
        out: &mut Vec<Measured>,
    ) -> Result<(Status, String)> {
        self.settle().await?;
        let mark = self.wire.mark();
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        self.settle().await?;
        out.push(Measured {
            flow,
            request: request_label,
            window: self.wire.since(mark),
        });
        Ok((status, body))
    }
}

/// An Ethereum account that owns an `account` space, like a fresh SDK user.
struct Account {
    key: SigningKey,
    address: [u8; 20],
    space: SpaceId,
}

fn eip55(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());
    lower
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if c.is_ascii_alphabetic() && nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

impl Account {
    fn new(seed: u8) -> Result<Self> {
        let key = SigningKey::from_bytes(&[seed; 32].into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address: [u8; 20] = digest[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", eip55(&address));
        let space = SpaceId::new(did.parse::<DIDBuf>()?, ACCOUNT_SPACE.parse()?);
        Ok(Self {
            key,
            address,
            space,
        })
    }

    /// personal_sign, as a wallet signs a SIWE message.
    fn sign(&self, message: &Message) -> Result<Signature> {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().map_err(|e| anyhow!("{e}"))?)?;
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        Ok(Signature::from(bytes))
    }
}

fn authorization(headers: &impl serde::Serialize) -> Result<String> {
    serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_owned)
        .context("delegation headers carry an Authorization value")
}

fn invocation(session: &Session, service: &str, path: &str, ability: &str) -> Result<String> {
    invocation_with(session, service, path, &[ability])
}

/// An invocation that holds several abilities on one resource, as the SDK
/// sends for the account index (`write` for its rows, `schema` for its DDL).
fn invocation_with(
    session: &Session,
    service: &str,
    path: &str,
    abilities: &[&str],
) -> Result<String> {
    let invocation = session.invoke(
        [(
            service.parse::<Service>()?,
            path.parse::<Path>()?,
            None,
            None,
            abilities
                .iter()
                .map(|ability| ability.parse::<Ability>())
                .collect::<Result<Vec<_>, _>>()?,
        )],
        None,
    )?;
    Ok(invocation.encode()?)
}

fn expect_ok(what: &str, (status, body): (Status, String)) -> Result<String> {
    ensure!(status == Status::Ok, "{what}: {status} {body}");
    Ok(body)
}

/// Sign in, write the bootstrap marker, read it back.
async fn round(node: &Node, account: &Account, out: &mut Vec<Measured>) -> Result<()> {
    let client = &node.client;
    let now = time::OffsetDateTime::now_utc();
    let issued_at: TimeStamp = now.into();

    // sign-in: the node's peer key for the space, the host delegation that
    // creates it, the session delegation, the account-space SQL call.
    let peer = expect_ok(
        "GET /peer/generate",
        node.measure(
            "sign-in",
            "GET /peer/generate",
            client.get(format!("/peer/generate/{}", account.space)),
            out,
        )
        .await?,
    )?;
    let host = generate_host_siwe_message(HostConfig {
        address: account.address,
        chain_id: 1,
        domain: "localhost".parse()?,
        issued_at: issued_at.clone(),
        space_id: account.space.clone(),
        peer_id: peer,
    })?;
    let signature = account.sign(&host)?;
    let host = authorization(&siwe_to_delegation_headers(SignedMessage {
        siwe: host,
        signature,
    }))?;
    expect_ok(
        "host /delegate",
        node.measure(
            "sign-in",
            "POST /delegate (host)",
            client
                .post("/delegate")
                .header(Header::new("Authorization", host)),
            out,
        )
        .await?,
    )?;

    let prepared = prepare_session(SessionConfig {
        abilities: HashMap::from([
            (
                "kv".parse()?,
                HashMap::from([(
                    "".parse()?,
                    ["get", "put", "del", "list", "metadata"]
                        .into_iter()
                        .map(|action| format!("tinycloud.kv/{action}").parse())
                        .collect::<Result<_, _>>()?,
                )]),
            ),
            (
                "sql".parse()?,
                HashMap::from([(
                    ACCOUNT_DATABASE.parse()?,
                    vec![
                        "tinycloud.sql/read".parse()?,
                        "tinycloud.sql/write".parse()?,
                        "tinycloud.sql/schema".parse()?,
                    ],
                )]),
            ),
        ]),
        space_abilities: None,
        raw_abilities: HashMap::new(),
        address: account.address,
        chain_id: 1,
        domain: "localhost".parse()?,
        issued_at,
        space_id: account.space.clone(),
        additional_spaces: None,
        not_before: None,
        expiration_time: (now + time::Duration::hours(1)).into(),
        parents: None,
        jwk: None,
        delegate_uri: None,
        nonce: None,
        invocation_ttl_secs: None,
    })?;
    let signature = account.sign(&prepared.siwe)?;
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature,
    })?;
    expect_ok(
        "session /delegate",
        node.measure(
            "sign-in",
            "POST /delegate (session)",
            client.post("/delegate").header(Header::new(
                "Authorization",
                authorization(&session.delegation_header)?,
            )),
            out,
        )
        .await?,
    )?;

    let sql = SqlRequest::Execute {
        sql: ACCOUNT_INDEX_DDL.to_owned(),
        params: vec![],
        schema: None,
    };
    expect_ok(
        "account SQL /invoke",
        node.measure(
            "sign-in",
            "POST /invoke sql/write (account)",
            client
                .post("/invoke")
                .header(Header::new(
                    "Authorization",
                    invocation_with(
                        &session,
                        "sql",
                        ACCOUNT_DATABASE,
                        &["tinycloud.sql/write", "tinycloud.sql/schema"],
                    )?,
                ))
                .header(ContentType::JSON)
                .body(serde_json::to_string(&sql)?),
            out,
        )
        .await?,
    )?;

    expect_ok(
        "kv put",
        node.measure(
            "kv put",
            "POST /invoke kv/put",
            client
                .post("/invoke")
                .header(Header::new(
                    "Authorization",
                    invocation(&session, "kv", KV_KEY, "tinycloud.kv/put")?,
                ))
                .header(ContentType::JSON)
                .body(KV_VALUE),
            out,
        )
        .await?,
    )?;

    let read = expect_ok(
        "kv get",
        node.measure(
            "kv get",
            "POST /invoke kv/get",
            client.post("/invoke").header(Header::new(
                "Authorization",
                invocation(&session, "kv", KV_KEY, "tinycloud.kv/get")?,
            )),
            out,
        )
        .await?,
    )?;
    ensure!(
        read.as_bytes() == KV_VALUE,
        "kv get returned {read:?}, not the value just put"
    );
    multi_write_puts(node, &session, out).await?;
    batch_reads(node, &session, out).await?;
    Ok(())
}

/// TC-735: one invocation writing two keys is a multipart `kv/put` batch. Its
/// pre-upload registration, fence lock and finish run once per DISTINCT blob
/// (three round trips each), whatever the number of keys. Two keys holding
/// different bytes are two blobs; two keys holding the same bytes are one.
fn multipart_put(keys: &[String], values: &[&[u8]]) -> (ContentType, Vec<u8>) {
    let boundary = "tc735-multi-write-boundary";
    let mut body = Vec::new();
    for (key, value) in keys.iter().zip(values) {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (
        ContentType::new("multipart", "form-data").with_params(("boundary", boundary)),
        body,
    )
}

async fn multi_write_puts(node: &Node, session: &Session, out: &mut Vec<Measured>) -> Result<()> {
    let distinct = vec!["multi/distinct-a".to_owned(), "multi/distinct-b".to_owned()];
    let (content_type, body) = multipart_put(
        &distinct,
        &[b"tc735 multi-write blob a", b"tc735 multi-write blob b"],
    );
    expect_ok(
        "kv put 2 blobs",
        node.measure(
            "kv put 2 blobs",
            "POST /invoke kv/put x2 (two blobs)",
            node.client
                .post("/invoke")
                .header(Header::new(
                    "Authorization",
                    batch_invocation(session, "tinycloud.kv/put", &distinct)?,
                ))
                .header(content_type)
                .body(body),
            out,
        )
        .await?,
    )?;

    let same = vec!["multi/same-a".to_owned(), "multi/same-b".to_owned()];
    let (content_type, body) = multipart_put(
        &same,
        &[
            b"tc735 multi-write shared blob",
            b"tc735 multi-write shared blob",
        ],
    );
    expect_ok(
        "kv put 1 blob 2 keys",
        node.measure(
            "kv put 1 blob 2 keys",
            "POST /invoke kv/put x2 (one blob)",
            node.client
                .post("/invoke")
                .header(Header::new(
                    "Authorization",
                    batch_invocation(session, "tinycloud.kv/put", &same)?,
                ))
                .header(content_type)
                .body(body),
            out,
        )
        .await?,
    )?;
    Ok(())
}

/// Keys the batch flows read: `batch/000`..`batch/099` holding `v<n>`, of
/// which `DELETED_KEY` is then deleted, plus two oversized values.
const BATCH_ITEMS: usize = 100;
const DELETED_KEY: usize = 7;
const BIG_KEY: &str = "batch/big";
const HUGE_KEY: &str = "batch/huge";
const BIG_VALUE: [u8; 64] = [b'b'; 64];
const HUGE_VALUE: [u8; 128] = [b'h'; 128];

fn batch_key(index: usize) -> String {
    format!("batch/{index:03}")
}

/// The value `key` holds after the fixture is written, or `None` when a read
/// of it finds nothing (never written, or deleted).
fn batch_value(key: &str) -> Option<Vec<u8>> {
    match key {
        BIG_KEY => Some(BIG_VALUE.to_vec()),
        HUGE_KEY => Some(HUGE_VALUE.to_vec()),
        _ => {
            let index: usize = key.strip_prefix("batch/")?.parse().ok()?;
            (index < BATCH_ITEMS && index != DELETED_KEY).then(|| format!("v{index}").into_bytes())
        }
    }
}

/// One invocation of `ability` over every key in `keys`, in that order.
fn batch_invocation(session: &Session, ability: &str, keys: &[String]) -> Result<String> {
    let ability: Ability = ability.parse()?;
    let capabilities = keys
        .iter()
        .map(|key| {
            Ok((
                "kv".parse::<Service>()?,
                key.parse::<Path>()?,
                None,
                None,
                [ability.clone()],
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(session.invoke(capabilities, None)?.encode()?)
}

/// The keys a 100-key batch asks for, in request order: a permutation of the
/// fixture (so present, deleted and capability order all vary), with a
/// duplicate pair and two keys that were never written.
fn batch_request() -> Vec<String> {
    let mut keys: Vec<String> = (0..BATCH_ITEMS)
        .map(|n| batch_key(n * 37 % BATCH_ITEMS))
        .collect();
    keys[10] = keys[3].clone();
    keys[90] = keys[3].clone();
    keys[50] = "batch/missing-a".to_owned();
    keys[51] = "batch/missing-b".to_owned();
    keys
}

/// An invocation's capabilities are a map: a repeated key is one capability,
/// and the order they are answered in is the map's, by resource.
fn capability_order(keys: &[String]) -> Vec<String> {
    let mut order = keys.to_vec();
    order.sort();
    order.dedup();
    order
}

/// The error for the first key, in `order`, whose value is over `limit`.
fn batch_too_large(order: &[String], limit: usize) -> Option<String> {
    order.iter().find_map(|key| {
        let size = batch_value(key)?.len();
        (size > limit).then(|| {
            format!("KV response is {size} bytes, exceeding the requested limit of {limit} bytes")
        })
    })
}

async fn batch_put(node: &Node, session: &Session, key: &str, value: &[u8]) -> Result<()> {
    let (status, body, _) = dispatch(
        node.client
            .post("/invoke")
            .header(Header::new(
                "Authorization",
                invocation(session, "kv", key, "tinycloud.kv/put")?,
            ))
            .header(ContentType::JSON)
            .body(value),
    )
    .await;
    expect_ok("batch fixture put", (status, body))?;
    Ok(())
}

fn parse_batch(body: &str) -> Result<Vec<serde_json::Value>> {
    let parsed: serde_json::Value = serde_json::from_str(body)?;
    Ok(parsed["results"]
        .as_array()
        .context("batch response has results")?
        .clone())
}

/// Batch `kv/get` and `kv/metadata` reads of 100 keys (TC-1274): measured as
/// two flows, with the response of each checked against the fixture, so the
/// same assertions hold before and after the reads are batched in the node.
async fn batch_reads(node: &Node, session: &Session, out: &mut Vec<Measured>) -> Result<()> {
    for index in 0..BATCH_ITEMS {
        let key = batch_key(index);
        batch_put(
            node,
            session,
            &key,
            &batch_value(&key).unwrap_or_else(|| b"gone".to_vec()),
        )
        .await?;
    }
    batch_put(node, session, BIG_KEY, &BIG_VALUE).await?;
    batch_put(node, session, HUGE_KEY, &HUGE_VALUE).await?;
    let (status, body, _) = dispatch(node.client.post("/invoke").header(Header::new(
        "Authorization",
        invocation(session, "kv", &batch_key(DELETED_KEY), "tinycloud.kv/del")?,
    )))
    .await;
    expect_ok("batch fixture delete", (status, body))?;

    let keys = batch_request();
    let order = capability_order(&keys);
    let auth = |ability: &str, keys: &[String]| -> Result<Header<'static>> {
        Ok(Header::new(
            "Authorization",
            batch_invocation(session, ability, keys)?,
        ))
    };

    let body = expect_ok(
        "batch get",
        node.measure(
            "kv batch get",
            "POST /invoke kv/get x100",
            node.client
                .post("/invoke")
                .header(auth("tinycloud.kv/get", &keys)?),
            out,
        )
        .await?,
    )?;
    let results = parse_batch(&body)?;
    ensure!(
        results.len() == order.len(),
        "batch get returned {} results",
        results.len()
    );
    let mut etags = HashMap::new();
    for (key, result) in order.iter().zip(&results) {
        ensure!(
            result["key"] == key.as_str(),
            "result order: {key} is {}",
            result["key"]
        );
        match batch_value(key) {
            Some(value) => {
                ensure!(result["ok"] == true, "{key} must be found: {result}");
                let data = base64::decode(result["dataBase64"].as_str().context("data")?)?;
                ensure!(data == value, "{key} returned {data:?}");
                etags.insert(key.clone(), result["headers"]["etag"].clone());
            }
            None => ensure!(
                result["ok"] == false && result["error"]["code"] == "KV_NOT_FOUND",
                "{key} must be missing: {result}"
            ),
        }
    }
    let get_digest = hex::encode(Keccak256::digest(body.as_bytes()));

    let body = expect_ok(
        "batch head",
        node.measure(
            "kv batch head",
            "POST /invoke kv/metadata x100",
            node.client
                .post("/invoke")
                .header(auth("tinycloud.kv/metadata", &keys)?),
            out,
        )
        .await?,
    )?;
    let heads = parse_batch(&body)?;
    ensure!(
        heads.len() == order.len(),
        "batch head returned {} results",
        heads.len()
    );
    for (key, head) in order.iter().zip(&heads) {
        ensure!(
            head["key"] == key.as_str(),
            "head order: {key} is {}",
            head["key"]
        );
        match etags.get(key) {
            Some(etag) => ensure!(
                head["ok"] == true
                    && head.get("dataBase64").is_none()
                    && head["headers"]["etag"] == *etag,
                "{key} head: {head}"
            ),
            None => ensure!(head["ok"] == false, "{key} head: {head}"),
        }
    }
    let head_digest = hex::encode(Keccak256::digest(body.as_bytes()));
    println!("TC-1274 batch body digests: get {get_digest}, head {head_digest}");

    // The per-key response limit: the first oversized capability, in
    // capability order, is the one reported (not the largest), and a value of
    // exactly the limit is not oversized.
    fn sized<'a>(
        node: &'a Node,
        session: &Session,
        keys: &[String],
        limit: u64,
    ) -> Result<LocalRequest<'a>> {
        Ok(node
            .client
            .post("/invoke")
            .header(Header::new(
                "Authorization",
                batch_invocation(session, "tinycloud.kv/get", keys)?,
            ))
            .header(Header::new(
                "x-tinycloud-max-response-bytes",
                limit.to_string(),
            )))
    }
    for limit in [32, 64] {
        let keys = [
            batch_key(1),
            HUGE_KEY.to_owned(),
            batch_key(2),
            BIG_KEY.to_owned(),
        ];
        let expected = batch_too_large(&capability_order(&keys), limit as usize)
            .context("an oversized key")?;
        let (status, body, _) = dispatch(sized(node, session, &keys, limit)?).await;
        ensure!(
            status == Status::PayloadTooLarge && body == expected,
            "limit {limit}: {status} {body} (expected {expected})"
        );
    }
    let keys = [batch_key(1), BIG_KEY.to_owned(), batch_key(2)];
    let (status, body, _) = dispatch(sized(node, session, &keys, 64)?).await;
    ensure!(
        status == Status::Ok,
        "a value of exactly the limit: {status} {body}"
    );
    Ok(())
}

/// Point `url` at the proxy, with TLS off (the proxy must read the protocol)
/// and the test's schema on the search path.
fn proxied_url(url: &str, proxy: SocketAddr, schema: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(url)?;
    url.set_host(Some(&proxy.ip().to_string()))?;
    url.set_port(Some(proxy.port()))
        .map_err(|()| anyhow!("PostgreSQL URL cannot carry a port"))?;
    url.query_pairs_mut()
        .append_pair("sslmode", "disable")
        .append_pair("options", &format!("-c search_path={schema}"));
    Ok(url.to_string())
}

fn upstream(url: &str) -> Result<(String, u16)> {
    let url = reqwest::Url::parse(url)?;
    let host = url
        .host_str()
        .context("PostgreSQL URL has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    Ok((host, url.port().unwrap_or(5432)))
}

/// The real node, its pool behind the test proxy (with `cut`), on `schema`;
/// `max_connections` overrides the pool's default size.
async fn start_node(
    url: &str,
    schema: &str,
    cut: Cut,
    max_connections: Option<u32>,
) -> Result<(Node, tempfile::TempDir)> {
    let wire = Wire::default();
    let proxy = start_proxy(upstream(url)?, wire.clone(), cut).await?;
    let datadir = tempfile::TempDir::new()?;
    let mut overlay = format!(
        r#"
log_level = "critical"
[storage]
datadir = "{}"
database = "{}"
[keys]
type = "Static"
secret = "{}"
# Background traffic that is not a request's (TC-1274): off, so it cannot
# land inside a measured window.
[epoch_head_backfill]
enabled = false
"#,
        datadir.path().join("data").display(),
        proxied_url(url, proxy, schema)?,
        base64::encode_config([7u8; 32], base64::URL_SAFE_NO_PAD),
    );
    if let Some(max_connections) = max_connections {
        let _ = write!(overlay, "[database]\nmax_connections = {max_connections}\n");
    }
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&overlay));
    let config = figment.extract::<tinycloud::config::Config>()?;
    let node = Node {
        client: Client::tracked(tinycloud::app_with_control(&figment, &config, None).await?)
            .await?,
        wire,
    };
    Ok((node, datadir))
}

async fn run(url: &str, schema: &str) -> Result<Vec<Measured>> {
    let (node, _datadir) = start_node(url, schema, Cut::default(), Some(POOL_SIZE)).await?;

    let result = async {
        node.open_pool(POOL_SIZE).await?;
        let mut warm_up = Vec::new();
        for seed in 1..=WARM_UP_ROUNDS {
            round(&node, &Account::new(seed)?, &mut warm_up)
                .await
                .with_context(|| format!("warm-up round {seed}"))?;
        }
        let mut measured = Vec::new();
        round(&node, &Account::new(WARM_UP_ROUNDS + 1)?, &mut measured)
            .await
            .context("measured round")?;
        Ok(measured)
    }
    .await;
    // Stop the webhook dispatcher and the replay cleanup from querying a
    // schema that is about to be dropped.
    node.pool().close().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_round_trip_budget() {
    let Some(url) = postgres_test_url("postgres_round_trip_budget") else {
        return;
    };
    let admin = Database::connect(url.as_str())
        .await
        .expect("connect to PostgreSQL");
    let schema = format!(
        "tc951_rt_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create the isolated schema");
    let result = run(&url, &schema).await;
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop the isolated schema");
    let measured = result.expect("drive sign-in, kv put and kv get");

    let mut report = String::from(
        "TC-951 PostgreSQL round trips per flow; statement-cache and excluded round trips are not budgeted\n",
    );
    let mut violations = Vec::new();
    for (flow, budget) in BUDGETS {
        let mut total = Counts::default();
        let mut detail = String::new();
        for request in measured.iter().filter(|m| m.flow == flow) {
            let counts = request.window.counts();
            total += counts;
            let _ = writeln!(
                detail,
                "    {:<34} {:>3} rt  {:>3} stmt ({} current_kv)  {} cache  {} excl  {} conn",
                request.request,
                counts.round_trips,
                counts.statements,
                request.window.current_kv_statements(),
                counts.statement_cache,
                counts.excluded,
                counts.connections
            );
            request.window.describe(&mut detail);
            if counts.connections > 0 {
                violations.push(format!(
                    "{flow}: {} opened {} connection(s) inside its measured window",
                    request.request, counts.connections
                ));
            }
            // TC-1274: a 100-key batch does O(1) KV lookups, not one per key.
            if flow.starts_with("kv batch") && request.window.current_kv_statements() > 1 {
                violations.push(format!(
                    "{flow}: {} read current_kv in {} statements, not one",
                    request.request,
                    request.window.current_kv_statements()
                ));
            }
        }
        let _ = writeln!(
            report,
            "  {flow:<9} {:>3} round trips (budget {budget}), {} statements, {} statement-cache, {} excluded, {} new connections\n{detail}",
            total.round_trips, total.statements, total.statement_cache, total.excluded, total.connections
        );
        assert!(
            total.round_trips > 0,
            "{flow}: the proxy saw no round trips; the node is not using it"
        );
        if total.round_trips > budget {
            violations.push(format!(
                "{flow}: {} round trips, budget {budget}",
                total.round_trips
            ));
        }
    }
    println!("{report}");
    assert!(
        violations.is_empty(),
        "PostgreSQL round-trip budget check failed (TC-951):\n  {}\n\n{report}",
        violations.join("\n  ")
    );
}

/// TC-1482: `GET /admin/stats` answers from one statement however many spaces
/// the node holds. Its round trips are counted with 3 spaces and again with
/// 303 and must be equal, and the window must hold exactly one statement:
/// the `/admin/usage` shape (one `store_size` call per space) would grow with
/// the space count and fail both checks.
///
/// Measured on PostgreSQL: 2 round trips per request, the statement itself
/// and sqlx's release ping, with exactly 1 statement.
const ADMIN_STATS_BUDGET: u64 = 2;
const ADMIN_STATS_TOKEN: &str = "tc1482-round-trip-token-6e1f0b3a9c5d8274";

/// `count` spaces named from `first`, each owned by its own address and
/// holding one live key, inserted by two statements outside the proxy.
async fn seed_stats_spaces(seed: &impl ConnectionTrait, first: u64, count: u64) -> Result<()> {
    let last = first + count - 1;
    let id = "'tinycloud:pkh:eip155:1:0x' || lpad(to_hex(g), 40, '0') || ':default'";
    for sql in [
        format!("INSERT INTO space (id) SELECT {id} FROM generate_series({first}, {last}) g"),
        format!(
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, \
             metadata, deleted) SELECT {id}, 'k', '\\x01'::bytea, 1, '\\x02'::bytea, 1, \
             '\\x03'::bytea, '{{}}'::json, false FROM generate_series({first}, {last}) g"
        ),
    ] {
        seed.execute(Statement::from_string(DbBackend::Postgres, sql))
            .await?;
    }
    Ok(())
}

async fn measure_stats(node: &Node, expected_owners: u64) -> Result<Window> {
    let mut out = Vec::new();
    let request = node.client.get("/admin/stats").header(Header::new(
        "Authorization",
        format!("Bearer {ADMIN_STATS_TOKEN}"),
    ));
    let (status, body) = node
        .measure("admin stats", "GET /admin/stats", request, &mut out)
        .await?;
    ensure!(status == Status::Ok, "GET /admin/stats answered {status}");
    let body: serde_json::Value = serde_json::from_str(&body)?;
    ensure!(
        body["count"] == expected_owners,
        "expected {expected_owners} owners, the route returned {}",
        body["count"]
    );
    Ok(out.pop().context("no measured window")?.window)
}

async fn admin_stats_windows(url: &str, schema: &str) -> Result<(Window, Window)> {
    let (node, _datadir) = start_node(url, schema, Cut::default(), Some(POOL_SIZE)).await?;
    let result = async {
        node.open_pool(POOL_SIZE).await?;
        let mut scoped = reqwest::Url::parse(url)?;
        scoped
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let seed = Database::connect(scoped.as_str()).await?;

        seed_stats_spaces(&seed, 1, 3).await?;
        // Prepare the statement on every pooled connection first.
        for _ in 0..(2 * POOL_SIZE) {
            measure_stats(&node, 3).await?;
        }
        let few = measure_stats(&node, 3).await?;

        seed_stats_spaces(&seed, 1_000, 300).await?;
        let many = measure_stats(&node, 303).await?;
        seed.close().await?;
        Ok((few, many))
    }
    .await;
    node.pool().close().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_admin_stats_is_one_round_trip_for_any_space_count() {
    let Some(url) = postgres_test_url("postgres_admin_stats_is_one_round_trip") else {
        return;
    };
    let admin = Database::connect(url.as_str())
        .await
        .expect("connect to PostgreSQL");
    let schema = format!(
        "tc1482_rt_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create the isolated schema");
    std::env::set_var("NODE_STATS_READ_TOKEN", ADMIN_STATS_TOKEN);
    let result = admin_stats_windows(&url, &schema).await;
    std::env::remove_var("NODE_STATS_READ_TOKEN");
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop the isolated schema");
    let (few, many) = result.expect("measure GET /admin/stats");

    let (few_counts, many_counts) = (few.counts(), many.counts());
    let mut report = String::from("TC-1482 GET /admin/stats\n  3 spaces:\n");
    few.describe(&mut report);
    let _ = writeln!(report, "  303 spaces:");
    many.describe(&mut report);
    println!("{report}");
    assert_eq!(
        (few_counts.round_trips, few_counts.statements),
        (many_counts.round_trips, many_counts.statements),
        "the round trips must not depend on the number of spaces:\n{report}"
    );
    assert_eq!(
        many_counts.statements, 1,
        "GET /admin/stats must run exactly one statement:\n{report}"
    );
    assert_eq!(
        many_counts.round_trips, ADMIN_STATS_BUDGET,
        "round trips changed from the budget:\n{report}"
    );
    assert_eq!(many_counts.connections, 0, "opened a connection:\n{report}");
}

/// A signed session for `account`, with the same abilities the SDK asks for.
fn new_session(account: &Account) -> Result<Session> {
    let now = time::OffsetDateTime::now_utc();
    let prepared = prepare_session(SessionConfig {
        abilities: HashMap::from([(
            "kv".parse()?,
            HashMap::from([(
                "".parse()?,
                ["get", "put", "del", "list", "metadata"]
                    .into_iter()
                    .map(|action| format!("tinycloud.kv/{action}").parse())
                    .collect::<Result<_, _>>()?,
            )]),
        )]),
        space_abilities: None,
        raw_abilities: HashMap::new(),
        address: account.address,
        chain_id: 1,
        domain: "localhost".parse()?,
        issued_at: now.into(),
        space_id: account.space.clone(),
        additional_spaces: None,
        not_before: None,
        expiration_time: (now + time::Duration::hours(1)).into(),
        parents: None,
        jwk: None,
        delegate_uri: None,
        nonce: None,
        invocation_ttl_secs: None,
    })?;
    let signature = account.sign(&prepared.siwe)?;
    Ok(complete_session_setup(SignedSession {
        session: prepared,
        signature,
    })?)
}

/// Status, body and `Retry-After` of a dispatched request.
async fn dispatch(request: LocalRequest<'_>) -> (Status, String, Option<String>) {
    let response = request.dispatch().await;
    let status = response.status();
    let retry_after = response.headers().get_one("Retry-After").map(str::to_owned);
    let body = response.into_string().await.unwrap_or_default();
    (status, body, retry_after)
}

/// Create `account`'s space and register a session for it.
async fn sign_in(node: &Node, account: &Account) -> Result<Session> {
    let client = &node.client;
    let (status, peer, _) = dispatch(client.get(format!("/peer/generate/{}", account.space))).await;
    ensure!(status == Status::Ok, "peer: {status} {peer}");
    let host = generate_host_siwe_message(HostConfig {
        address: account.address,
        chain_id: 1,
        domain: "localhost".parse()?,
        issued_at: time::OffsetDateTime::now_utc().into(),
        space_id: account.space.clone(),
        peer_id: peer,
    })?;
    let signature = account.sign(&host)?;
    let host = authorization(&siwe_to_delegation_headers(SignedMessage {
        siwe: host,
        signature,
    }))?;
    let (status, body, _) = dispatch(
        client
            .post("/delegate")
            .header(Header::new("Authorization", host)),
    )
    .await;
    ensure!(status == Status::Ok, "host delegate: {status} {body}");
    let session = new_session(account)?;
    let (status, body, _) = dispatch(client.post("/delegate").header(Header::new(
        "Authorization",
        authorization(&session.delegation_header)?,
    )))
    .await;
    ensure!(status == Status::Ok, "session delegate: {status} {body}");
    Ok(session)
}

async fn kv_put(
    node: &Node,
    session: &Session,
    key: &str,
) -> Result<(Status, String, Option<String>)> {
    Ok(dispatch(
        node.client
            .post("/invoke")
            .header(Header::new(
                "Authorization",
                invocation(session, "kv", key, "tinycloud.kv/put")?,
            ))
            .header(ContentType::JSON)
            .body(KV_VALUE),
    )
    .await)
}

/// TC-1054 (Opus R5, R6): the KV put and delegate routes report a database
/// failure before any write as `503 unavailable_retryable` with
/// `Retry-After`, and one after the `COMMIT` was sent as `500
/// outcome_unknown` without it, through the real node and its pool. The
/// proxy cuts a connection: both `BEGIN` attempts (the one retry
/// included), or a `COMMIT` that the server receives and commits but whose
/// reply never arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_write_routes_tell_retryable_failures_from_unknown_outcomes() {
    let Some(url) =
        postgres_test_url("postgres_write_routes_tell_retryable_failures_from_unknown_outcomes")
    else {
        return;
    };
    let admin = Database::connect(url.as_str())
        .await
        .expect("connect to PostgreSQL");
    let schema = format!(
        "tc1054_routes_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create the isolated schema");
    let cut = Cut::default();
    let (node, _datadir) = start_node(&url, &schema, cut.clone(), None)
        .await
        .expect("start the node");

    let result = async {
        let account = Account::new(42)?;
        let session = sign_in(&node, &account).await?;
        let (status, body, _) = kv_put(&node, &session, "tc1054/warm").await?;
        ensure!(status == Status::Ok, "warm-up put: {status} {body}");

        // KV put's preparatory BEGIN retries once in the recovering pool and
        // once around the idempotent preparation (two attempts each). Exhaust
        // both layers before asserting the public retryable response.
        node.settle().await?;
        cut.arm(&[b"BEGIN"], 4);
        let (status, body, retry_after) = kv_put(&node, &session, "tc1054/retryable").await?;
        ensure!(!cut.armed(), "all preparatory BEGIN attempts were cut");
        ensure!(
            status == Status::ServiceUnavailable && body.starts_with("unavailable_retryable:"),
            "kv put before any write: {status} {body}"
        );
        ensure!(
            retry_after.as_deref() == Some("1"),
            "Retry-After: {retry_after:?}"
        );
        let (status, body, _) = kv_put(&node, &session, "tc1054/retryable").await?;
        ensure!(
            status == Status::Ok,
            "a fresh put after a retryable failure: {status} {body}"
        );

        // KV put: the COMMIT reached the server, its reply did not.
        node.settle().await?;
        cut.arm(&[b"tc1054/unknown", b"COMMIT"], 1);
        let (status, body, retry_after) = kv_put(&node, &session, "tc1054/unknown").await?;
        ensure!(!cut.armed(), "the put's COMMIT was cut");
        ensure!(
            status == Status::InternalServerError && body.starts_with("outcome_unknown:"),
            "kv put after its COMMIT was sent: {status} {body}"
        );
        ensure!(
            retry_after.is_none(),
            "no Retry-After on outcome_unknown: {retry_after:?}"
        );
        node.settle().await?;
        let (status, read, _) = dispatch(node.client.post("/invoke").header(Header::new(
            "Authorization",
            invocation(&session, "kv", "tc1054/unknown", "tinycloud.kv/get")?,
        )))
        .await;
        ensure!(
            status == Status::Ok && read.as_bytes() == KV_VALUE,
            "reading back finds the committed put: {status} {read}"
        );

        // Delegation: no connection survives BEGIN.
        let retryable = authorization(&new_session(&account)?.delegation_header)?;
        node.settle().await?;
        cut.arm(&[b"BEGIN"], 2);
        let (status, body, retry_after) = dispatch(
            node.client
                .post("/delegate")
                .header(Header::new("Authorization", retryable)),
        )
        .await;
        ensure!(!cut.armed(), "both BEGIN attempts were cut");
        ensure!(
            status == Status::ServiceUnavailable && body.starts_with("unavailable_retryable:"),
            "delegate before any write: {status} {body}"
        );
        ensure!(
            retry_after.as_deref() == Some("1"),
            "Retry-After: {retry_after:?}"
        );

        // Delegation: the COMMIT reached the server, its reply did not. The
        // identical delegation is idempotent, and re-sending it succeeds.
        let unknown_session = new_session(&account)?;
        let unknown = authorization(&unknown_session.delegation_header)?;
        // The delegatee (the session key's DID) is written by the
        // delegation's own transaction; its COMMIT follows.
        let delegatee = unknown_session
            .verification_method
            .split('#')
            .next()
            .unwrap_or_default()
            .to_owned();
        node.settle().await?;
        cut.arm(&[delegatee.as_bytes(), b"COMMIT"], 1);
        let (status, body, retry_after) = dispatch(
            node.client
                .post("/delegate")
                .header(Header::new("Authorization", unknown.clone())),
        )
        .await;
        ensure!(!cut.armed(), "the delegation's COMMIT was cut");
        ensure!(
            status == Status::InternalServerError && body.starts_with("outcome_unknown:"),
            "delegate after its COMMIT was sent: {status} {body}"
        );
        ensure!(
            retry_after.is_none(),
            "no Retry-After on outcome_unknown: {retry_after:?}"
        );
        node.settle().await?;
        let (status, body, _) = dispatch(
            node.client
                .post("/delegate")
                .header(Header::new("Authorization", unknown)),
        )
        .await;
        ensure!(
            status == Status::Ok,
            "re-sending the committed delegation: {status} {body}"
        );
        Ok(())
    }
    .await;
    node.pool().close().await;
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop the isolated schema");
    result.expect("route outcomes");
}

/// TC-735: a KV put's preparatory `BEGIN` is retried a bounded number of times
/// (two in the recovering pool, around two passes of the preparatory block),
/// and only while the `BEGIN` itself fails. Once a statement of the commit
/// transaction has run, a lost connection is an unknown outcome and nothing is
/// retried: a put that retried would answer 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_kv_put_begin_retry_is_bounded_and_never_follows_a_statement() {
    let Some(url) =
        postgres_test_url("postgres_kv_put_begin_retry_is_bounded_and_never_follows_a_statement")
    else {
        return;
    };
    let admin = Database::connect(url.as_str())
        .await
        .expect("connect to PostgreSQL");
    let schema = format!(
        "tc735_begin_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create the isolated schema");
    let cut = Cut::default();
    let (node, _datadir) = start_node(&url, &schema, cut.clone(), None)
        .await
        .expect("start the node");

    let result = async {
        let account = Account::new(43)?;
        let session = sign_in(&node, &account).await?;
        let (status, body, _) = kv_put(&node, &session, "tc735/warm").await?;
        ensure!(status == Status::Ok, "warm-up put: {status} {body}");

        // Five BEGIN cuts are armed, but a put makes four attempts at most, so
        // one cut is still armed after it answers.
        node.settle().await?;
        cut.arm(&[b"BEGIN"], 5);
        let (status, body, _) = kv_put(&node, &session, "tc735/bounded").await?;
        ensure!(
            cut.armed(),
            "a fifth BEGIN was attempted: the retry is not bounded"
        );
        ensure!(
            status == Status::ServiceUnavailable && body.starts_with("unavailable_retryable:"),
            "kv put whose BEGIN never succeeded: {status} {body}"
        );
        cut.disarm();

        // Cut a statement inside the commit transaction (the fence lock that
        // follows the upload): the put is not retried.
        node.settle().await?;
        cut.arm(&[b"FOR UPDATE OF fence"], 1);
        let (status, body, retry_after) = kv_put(&node, &session, "tc735/after-statement").await?;
        ensure!(!cut.armed(), "the fence lock statement was cut");
        ensure!(
            status == Status::InternalServerError && body.starts_with("outcome_unknown:"),
            "kv put after a statement of its transaction ran: {status} {body}"
        );
        ensure!(
            retry_after.is_none(),
            "no Retry-After on outcome_unknown: {retry_after:?}"
        );
        Ok(())
    }
    .await;
    node.pool().close().await;
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop the isolated schema");
    result.expect("begin retry bounds");
}

/// TC-735: a two-blob put whose later-registered blob has a pending deletion is
/// refused with 503 and claims nothing. The earlier blob keeps no claim, fence
/// or ledger row, so the claims share the preparatory transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_two_blob_put_with_a_pending_deletion_claims_nothing() {
    let Some(url) =
        postgres_test_url("postgres_two_blob_put_with_a_pending_deletion_claims_nothing")
    else {
        return;
    };
    let admin = Database::connect(url.as_str())
        .await
        .expect("connect to PostgreSQL");
    let schema = format!(
        "tc735_claims_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create the isolated schema");
    let (node, _datadir) = start_node(&url, &schema, Cut::default(), None)
        .await
        .expect("start the node");

    let result = async {
        let account = Account::new(44)?;
        let session = sign_in(&node, &account).await?;
        let (status, body, _) = kv_put(&node, &session, "tc735/warm").await?;
        ensure!(status == Status::Ok, "warm-up put: {status} {body}");

        let (one, two): (&[u8], &[u8]) = (b"route two-blob first", b"route two-blob second");
        let (early, late) = if tinycloud_core::hash::hash(one) < tinycloud_core::hash::hash(two) {
            (one, two)
        } else {
            (two, one)
        };
        let space = account.space.to_string();
        let early_hash = Vec::<u8>::from(tinycloud_core::hash::hash(early));
        let late_hash = Vec::<u8>::from(tinycloud_core::hash::hash(late));
        let pool = node.pool();
        tinycloud_core::sea_orm::sqlx::query(
            "INSERT INTO kv_blob_generation (space, value, generation) VALUES ($1, $2, 0)",
        )
        .bind(&space)
        .bind(&late_hash)
        .execute(pool)
        .await?;
        tinycloud_core::sea_orm::sqlx::query(
            "INSERT INTO kv_orphan_candidate
                (space, value, generation, created_at, deleting_at, deletion_bytes)
             VALUES ($1, $2, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)",
        )
        .bind(&space)
        .bind(&late_hash)
        .execute(pool)
        .await?;

        let keys = vec![
            "tc735/pending-early".to_owned(),
            "tc735/pending-late".to_owned(),
        ];
        let (content_type, multipart) = multipart_put(&keys, &[early, late]);
        let (status, body, _) = dispatch(
            node.client
                .post("/invoke")
                .header(Header::new(
                    "Authorization",
                    batch_invocation(&session, "tinycloud.kv/put", &keys)?,
                ))
                .header(content_type)
                .body(multipart),
        )
        .await;
        ensure!(
            status == Status::ServiceUnavailable && body.starts_with("unavailable_retryable:"),
            "two-blob put with a pending deletion: {status} {body}"
        );
        for table in [
            "kv_orphan_attempt",
            "kv_orphan_candidate",
            "kv_blob_generation",
        ] {
            let rows: i64 = tinycloud_core::sea_orm::sqlx::query_scalar(&format!(
                "SELECT count(*) FROM {table} WHERE value = $1"
            ))
            .bind(&early_hash)
            .fetch_one(pool)
            .await?;
            ensure!(rows == 0, "{table} kept {rows} row(s) for the earlier blob");
        }
        Ok(())
    }
    .await;
    node.pool().close().await;
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop the isolated schema");
    result.expect("two-blob put with a pending deletion");
}

/// The `postgres` object of `/info`: exactly the two counters.
async fn postgres_info(node: &Node) -> Result<(u64, u64)> {
    let (status, body, _) = dispatch(node.client.get("/info")).await;
    ensure!(status == Status::Ok, "/info: {status} {body}");
    let info: serde_json::Value = serde_json::from_str(&body)?;
    let postgres = info["postgres"]
        .as_object()
        .with_context(|| format!("/info has a postgres object: {info}"))?;
    let mut keys: Vec<&str> = postgres.keys().map(String::as_str).collect();
    keys.sort_unstable();
    ensure!(
        keys == ["connections_opened", "sockets_configured"],
        "counts only: {postgres:?}"
    );
    // TC-1080 + TC-1054: both public evidence objects survive the merge.
    let did_resolution = info["did_resolution"]
        .as_object()
        .context("/info has a did_resolution object")?;
    ensure!(did_resolution.len() == 2, "boolean and count only");
    ensure!(did_resolution["network_methods"] == false, "default policy");
    ensure!(
        did_resolution["refused_total"].as_u64().is_some(),
        "refusal count"
    );
    println!(
        "TC-1080/TC-1054 /info evidence: {}",
        serde_json::json!({"postgres": postgres, "did_resolution": did_resolution})
    );
    let count = |key: &str| {
        postgres[key]
            .as_u64()
            .with_context(|| format!("{key} is a count"))
    };
    Ok((count("sockets_configured")?, count("connections_opened")?))
}

/// TC-1054: with logs private, the deploy checks keepalive through the
/// public `/info`: `postgres.sockets_configured >= connections_opened > 0`,
/// and both move when the pool opens connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_info_reports_connection_counters() {
    let Some(url) = postgres_test_url("postgres_info_reports_connection_counters") else {
        return;
    };
    let admin = Database::connect(url.as_str())
        .await
        .expect("connect to PostgreSQL");
    let schema = format!(
        "tc1054_info_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create the isolated schema");
    let (node, _datadir) = start_node(&url, &schema, Cut::default(), None)
        .await
        .expect("start the node");

    let result = async {
        let (sockets, opened) = postgres_info(&node).await?;
        ensure!(opened > 0, "the pool connected at startup: {opened}");
        ensure!(
            sockets >= opened,
            "{sockets} sockets for {opened} connections"
        );

        // Hold more connections than the pool has, so it opens new ones.
        node.settle().await?;
        let pool = node.pool();
        let wanted = pool.size() + 2;
        let mut held = Vec::new();
        for _ in 0..wanted {
            held.push(pool.acquire().await?);
        }
        drop(held);
        let (sockets_after, opened_after) = postgres_info(&node).await?;
        ensure!(opened_after > opened, "{opened} -> {opened_after}");
        ensure!(sockets_after > sockets, "{sockets} -> {sockets_after}");
        ensure!(
            sockets_after >= opened_after,
            "{sockets_after} sockets for {opened_after} connections"
        );
        Ok(())
    }
    .await;
    node.pool().close().await;
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop the isolated schema");
    result.expect("postgres counters in /info");
}
