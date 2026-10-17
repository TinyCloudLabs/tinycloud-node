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
//! `rocket::local::asynchronous::Client`, so the pool is built by the
//! production code with the production settings. Only its database URL
//! differs: it points at an in-test TCP proxy in front of PostgreSQL, with TLS
//! off and a throwaway schema on the search path. The flows are the node side
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
//!   the durable read-audit commit before it answers.
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
//! The counts are deterministic: every request is measured between two
//! barriers that wait until every pooled connection is idle again, so the
//! release ping of the last statement is inside the window and no request
//! overlaps another's traffic. The flows run three times first, so the pool
//! has grown to the connections they need and the statements are prepared.
//! A dispatcher poll executed after warm-up is settled before measurement;
//! its connection setup is attributed separately from request traffic.
//!
//! # Budgets
//!
//! Each budget is the count measured when it was last changed, with no slack.
//! A change that lowers a count should lower the budget with it; the test
//! prints the measured counts for that. Run it with:
//!
//! ```text
//! TINYCLOUD_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
//!   cargo test -p tinycloud-node --test postgres_round_trip_budget -- --nocapture
//! ```
//!
//! Without `TINYCLOUD_TEST_POSTGRES_URL` the test skips, except under `CI`,
//! where it fails (TC-381).

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

/// Round trips allowed per flow; see the module docs. Measured with
/// `test_before_acquire(false)`, database identity resolve as one statement
/// and the read audit as one statement (TC-951). TC-1149 adds canonical
/// principal/ancestor cutoff checks and transactional target row locks; the
/// immutable proof signers and CID alias identities share one request query:
///
/// - sign-in 89 = peer key 0 + host `/delegate` 20 + session `/delegate` 21
///   + account-space SQL write 48;
/// - kv put 49, including cross-process principal lock rows and recheck;
/// - kv get 30, including the live key tombstone and read-audit commit.
const BUDGETS: [(&str, u64); 3] = [("sign-in", 89), ("kv put", 49), ("kv get", 30)];

/// Full sign-in plus put plus get rounds run before the measured one.
const WARM_UP_ROUNDS: u8 = 3;

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

/// TC-381, mirroring `tinycloud_core::test_support::postgres_test_url`: skip
/// locally when the URL is unset, but never on CI.
fn postgres_test_url(test: &str) -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            if std::env::var_os("CI").is_some() {
                panic!(
                    "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset (or empty) in CI. \
                     This test must not be allowed to skip on CI — see TC-381. Check the \
                     `postgres` service container and the `env:` block in .github/workflows/rust.yml."
                );
            }
            eprintln!(
                "skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset (set it to run this \
                 locally; it is mandatory in CI)"
            );
            None
        }
    }
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
    started_connections: Vec<u64>,
    round_trips: Vec<RoundTrip>,
}

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<Log>>);

#[derive(Clone, Copy)]
struct Mark {
    connections: usize,
    round_trips: usize,
}

impl Wire {
    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.0.lock().expect("wire log poisoned")
    }

    fn mark(&self) -> Mark {
        let log = self.log();
        Mark {
            connections: log.started_connections.len(),
            round_trips: log.round_trips.len(),
        }
    }

    fn since(&self, mark: Mark) -> Window {
        let log = self.log();
        let new_connections = &log.started_connections[mark.connections..];
        let mut window = Window {
            connections: new_connections.len() as u64,
            round_trips: log.round_trips[mark.round_trips..].to_vec(),
        };
        // A new connection belongs to the dispatcher only if its first
        // executed non-setup SQL is an actual dispatcher SELECT. At most one
        // exact startup timeout SET and bare pings can precede it. A second
        // SET, a SQL batch, another statement, or a Parse without execution
        // never hides request work or a request-path connection.
        for &connection in new_connections {
            let mut saw_setup_set = false;
            let mut saw_poll_parse = false;
            let mut poll_execution = None;
            for (index, round_trip) in window
                .round_trips
                .iter()
                .enumerate()
                .filter(|(_, round_trip)| round_trip.connection == connection)
            {
                if !saw_poll_parse
                    && round_trip.kind == Kind::Counted
                    && round_trip.executed.is_empty()
                    && round_trip.parsed.is_empty()
                {
                    continue;
                }
                if !saw_poll_parse
                    && !saw_setup_set
                    && round_trip.kind == Kind::Counted
                    && round_trip.parsed.is_empty()
                    && round_trip.executed.as_slice() == ["SET statement_timeout = 30000"]
                {
                    saw_setup_set = true;
                    continue;
                }
                if round_trip.kind == Kind::Excluded("webhook dispatcher poll")
                    && round_trip
                        .parsed
                        .iter()
                        .all(|sql| background(sql) == Some("webhook dispatcher poll"))
                {
                    if round_trip.executed.is_empty() && !round_trip.parsed.is_empty() {
                        saw_poll_parse = true;
                        continue;
                    }
                    if !round_trip.executed.is_empty()
                        && round_trip
                            .executed
                            .iter()
                            .all(|sql| background(sql) == Some("webhook dispatcher poll"))
                    {
                        poll_execution = Some(index);
                    }
                }
                break;
            }
            if let Some(poll_execution) = poll_execution {
                window.connections -= 1;
                for round_trip in &mut window.round_trips[..poll_execution] {
                    if round_trip.connection == connection && round_trip.kind == Kind::Counted {
                        round_trip.kind = Kind::Excluded("webhook dispatcher setup");
                    }
                }
            }
        }
        window
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
                    self.wire.log().started_connections.push(self.connection);
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
struct Cut(Arc<Mutex<Armed>>);

/// The markers still to match, in order, and how many connections to cut.
type Armed = Option<(Vec<Vec<u8>>, usize)>;

impl Cut {
    fn arm(&self, markers: &[&[u8]], times: usize) {
        *self.0.lock().unwrap() = Some((markers.iter().map(|m| m.to_vec()).collect(), times));
    }

    fn armed(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }

    /// Advance a connection's `progress` through the armed markers over
    /// `bytes`; whether the connection must now be cut.
    fn observe(&self, progress: &mut usize, bytes: &[u8]) -> bool {
        let mut armed = self.0.lock().unwrap();
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

const DISPATCH_POLL_SQL: &str = r#"SELECT "hook_delivery"."id" AS "A_id""#;

#[test]
fn dispatcher_connection_setup_is_excluded_without_hiding_request_connections() {
    let wire = Wire::default();
    let mark = wire.mark();
    let trip = |connection, kind, sql: &str| RoundTrip {
        connection,
        kind,
        executed: vec![sql.to_owned()],
        parsed: Vec::new(),
    };
    {
        let mut log = wire.log();
        log.started_connections.extend([11, 12]);
        log.round_trips.extend([
            trip(11, Kind::Counted, "SET statement_timeout = 30000"),
            trip(12, Kind::Counted, "SET statement_timeout = 30000"),
            RoundTrip {
                connection: 11,
                kind: Kind::Counted,
                executed: Vec::new(),
                parsed: Vec::new(),
            },
            trip(
                11,
                Kind::Excluded("webhook dispatcher poll"),
                DISPATCH_POLL_SQL,
            ),
            trip(11, Kind::Counted, "SELECT current_kv"),
            trip(12, Kind::Counted, "SELECT current_kv"),
            trip(
                12,
                Kind::Excluded("webhook dispatcher poll"),
                DISPATCH_POLL_SQL,
            ),
        ]);
    }
    let window = wire.since(mark);
    let counts = window.counts();
    assert_eq!(counts.connections, 1, "request connection setup is counted");
    assert_eq!(
        counts.round_trips, 3,
        "request and reused-connection SQL is counted"
    );
    assert_eq!(
        counts.excluded, 4,
        "only dispatcher setup, ping and polls are excluded"
    );
    assert_eq!(
        window.round_trips[0].kind,
        Kind::Excluded("webhook dispatcher setup")
    );
    assert_eq!(window.round_trips[1].kind, Kind::Counted);
    assert_eq!(
        window.round_trips[2].kind,
        Kind::Excluded("webhook dispatcher setup")
    );
    assert_eq!(window.round_trips[4].kind, Kind::Counted);
}

#[test]
fn dispatcher_attribution_never_hides_duplicate_setup_parse_or_prior_request_sql() {
    let wire = Wire::default();
    let mark = wire.mark();
    let trip = |connection, kind, sql: &str| RoundTrip {
        connection,
        kind,
        executed: vec![sql.to_owned()],
        parsed: Vec::new(),
    };
    {
        let mut log = wire.log();
        log.started_connections.extend([13, 14, 15, 16]);
        log.round_trips.extend([
            trip(13, Kind::Counted, "SET statement_timeout = 30000"),
            trip(13, Kind::Counted, "SET statement_timeout = 30000"),
            trip(
                13,
                Kind::Excluded("webhook dispatcher poll"),
                DISPATCH_POLL_SQL,
            ),
            trip(14, Kind::Counted, "SET statement_timeout = 30000"),
            RoundTrip {
                connection: 14,
                kind: Kind::Excluded("webhook dispatcher poll"),
                executed: Vec::new(),
                parsed: vec![DISPATCH_POLL_SQL.to_owned()],
            },
            trip(15, Kind::Counted, "SET statement_timeout = 30000"),
            trip(15, Kind::Counted, "SELECT current_kv"),
            trip(
                15,
                Kind::Excluded("webhook dispatcher poll"),
                DISPATCH_POLL_SQL,
            ),
            trip(
                16,
                Kind::Counted,
                "SET statement_timeout = 30000; SELECT current_kv",
            ),
            trip(
                16,
                Kind::Excluded("webhook dispatcher poll"),
                DISPATCH_POLL_SQL,
            ),
        ]);
    }
    let window = wire.since(mark);
    let counts = window.counts();
    assert_eq!(counts.connections, 4, "all four are request-side setups");
    assert_eq!(counts.round_trips, 6, "no SET or request SQL is hidden");
    assert_eq!(
        counts.excluded, 4,
        "only dispatcher parse/SELECTs are excluded"
    );
    for index in [0, 1, 3, 5, 6, 8] {
        assert_eq!(window.round_trips[index].kind, Kind::Counted);
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
    let invocation = session.invoke(
        [(
            service.parse::<Service>()?,
            path.parse::<Path>()?,
            None,
            None,
            [ability.parse::<Ability>()?],
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
                    invocation(&session, "sql", ACCOUNT_DATABASE, "tinycloud.sql/write")?,
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

/// The real node, its pool behind the test proxy (with `cut`), on `schema`.
async fn start_node(url: &str, schema: &str, cut: Cut) -> Result<(Node, tempfile::TempDir)> {
    let wire = Wire::default();
    let proxy = start_proxy(upstream(url)?, wire.clone(), cut).await?;
    let datadir = tempfile::TempDir::new()?;
    let overlay = format!(
        r#"
log_level = "critical"
[storage]
datadir = "{}"
database = "{}"
[keys]
type = "Static"
secret = "{}"
"#,
        datadir.path().join("data").display(),
        proxied_url(url, proxy, schema)?,
        base64::encode_config([7u8; 32], base64::URL_SAFE_NO_PAD),
    );
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
    let (node, _datadir) = start_node(url, schema, Cut::default()).await?;

    let result = async {
        let mut warm_up = Vec::new();
        for seed in 1..=WARM_UP_ROUNDS {
            round(&node, &Account::new(seed)?, &mut warm_up)
                .await
                .with_context(|| format!("warm-up round {seed}"))?;
        }
        // The dispatcher may open a connection after request warm-up; a
        // background SET precedes its poll SQL. Wait for an actual execution
        // after this mark (not an older poll or a statement-cache Parse), then
        // settle the pool before starting the measured requests.
        let after_warm_up = node.wire.mark();
        let poll_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let polled = {
                let log = node.wire.log();
                log.round_trips[after_warm_up.round_trips..]
                    .iter()
                    .any(|round_trip| {
                        round_trip.kind == Kind::Excluded("webhook dispatcher poll")
                            && round_trip
                                .executed
                                .iter()
                                .any(|sql| background(sql) == Some("webhook dispatcher poll"))
                    })
            };
            if polled {
                break;
            }
            ensure!(
                Instant::now() < poll_deadline,
                "no dispatcher poll executed after warm-up within five seconds"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        node.settle().await?;
        println!("post-warm-up dispatcher execution settled before measured requests");
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
            assert_eq!(
                counts.connections, 0,
                "{flow} {}: a request opened an unwarmed PostgreSQL connection",
                request.request
            );
            total += counts;
            let _ = writeln!(
                detail,
                "    {:<34} {:>3} rt  {:>3} stmt  {} cache  {} excl  {} conn",
                request.request,
                counts.round_trips,
                counts.statements,
                counts.statement_cache,
                counts.excluded,
                counts.connections
            );
            request.window.describe(&mut detail);
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
        "PostgreSQL round-trip budget exceeded (TC-951):\n  {}\n\n{report}",
        violations.join("\n  ")
    );
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
    let (node, _datadir) = start_node(&url, &schema, cut.clone())
        .await
        .expect("start the node");

    let result = async {
        let account = Account::new(42)?;
        let session = sign_in(&node, &account).await?;
        let (status, body, _) = kv_put(&node, &session, "tc1054/warm").await?;
        ensure!(status == Status::Ok, "warm-up put: {status} {body}");

        // KV put: no connection survives BEGIN, so nothing was written.
        node.settle().await?;
        cut.arm(&[b"BEGIN"], 2);
        let (status, body, retry_after) = kv_put(&node, &session, "tc1054/retryable").await?;
        ensure!(!cut.armed(), "both BEGIN attempts were cut");
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
    let (node, _datadir) = start_node(&url, &schema, Cut::default())
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
