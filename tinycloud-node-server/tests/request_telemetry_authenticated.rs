//! TC-959 N2: synthetic SDK sign-in against the real binary, with local-only I/O.
//! Detached maintenance is deliberately not attributed to a request. The burst
//! interleaves authenticated database work with zero-database version requests.
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    net::TcpListener,
    path::{Path as FsPath, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use tinycloud_auth::{
    cacaos::{siwe::Message, siwe_cacao::Signature},
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::dids::DIDBuf,
};
use tinycloud_core::keys::StaticSecret;
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};
use uuid::Uuid;

// Public, synthetic fixture material; never load a developer's credentials.
const SECRET: &str = "VEMtOTU5IHJlcXVlc3QgdGVsZW1ldHJ5IHN5bnRoZXRpYyB0ZXN0IHNlY3JldA";
const KEY: &str = "tc959-private-kv-key-canary";
const VALUE: &str = "tc959-private-kv-value-canary";
const HEADER: &str = "tc959-private-header-canary";
const PARAM: &str = "tc959-private-bound-parameter-canary";
const LITERAL: &str = "tc959-private-sql-literal-canary";
const TABLE: &str = "tc959_private_sql_table_canary";
const DATABASE: &str = "account";

struct Node {
    child: Child,
    base: String,
    client: reqwest::blocking::Client,
    stdout: PathBuf,
    stderr: PathBuf,
    ids: Mutex<Vec<String>>,
    credentials: Mutex<Vec<String>>,
}

struct Reply {
    id: String,
    status: u16,
    body: String,
    event: Value,
}

impl Node {
    fn start(root: &FsPath, run: usize, level: &str, quota_url: &str) -> Self {
        Self::start_with_origins(root, run, level, quota_url, &[quota_url])
    }

    fn start_with_origins(
        root: &FsPath,
        run: usize,
        level: &str,
        quota_url: &str,
        first_party_origins: &[&str],
    ) -> Self {
        let port = free_port();
        let stdout = root.join(format!("stdout-{run}.log"));
        let stderr = root.join(format!("stderr-{run}.log"));
        let child = Command::new(env!("CARGO_BIN_EXE_tinycloud"))
            .env_clear()
            .current_dir(root)
            .env("HOME", root)
            .env("TINYCLOUD_CONFIG_FILE", root.join("isolated.toml"))
            .env("TINYCLOUD_ADDRESS", "127.0.0.1")
            .env("TINYCLOUD_PORT", port.to_string())
            .env("TINYCLOUD_LOG_LEVEL", "normal")
            .env("RUST_LOG", level)
            .env("TINYCLOUD_LOG__FORMAT", "Json")
            .env("TINYCLOUD_TELEMETRY__ENABLED", "false")
            .env("TINYCLOUD_STORAGE__DATADIR", root.join("data"))
            .env("TINYCLOUD_KEYS__TYPE", "static")
            .env("TINYCLOUD_KEYS__SECRET", SECRET)
            .env("TINYCLOUD_QUOTA_URL", quota_url)
            .env(
                "TINYCLOUD_LOG__REQUEST_ID_FIRST_PARTY_ORIGINS",
                serde_json::to_string(first_party_origins).unwrap(),
            )
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .expect("start isolated node binary");
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let mut node = Self {
            child,
            base: format!("http://127.0.0.1:{port}"),
            client,
            stdout,
            stderr,
            ids: Mutex::new(Vec::new()),
            credentials: Mutex::new(Vec::new()),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            assert!(
                node.child.try_wait().unwrap().is_none(),
                "node exited: {}",
                node.logs()
            );
            if node
                .client
                .get(format!("{}/healthz", node.base))
                .send()
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "node startup timed out: {}",
                node.logs()
            );
            thread::sleep(Duration::from_millis(25));
        }
        node
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        auth: Option<&str>,
        body: Option<&str>,
        supplied: Option<&str>,
    ) -> Reply {
        let mut request = self
            .client
            .request(method.parse().unwrap(), format!("{}{path}", self.base))
            .header("x-tc959-private", HEADER);
        if let Some(id) = supplied {
            request = request.header("x-request-id", id);
        }
        if let Some(auth) = auth {
            self.credentials.lock().push(auth.to_owned());
            request = request.header("Authorization", auth);
        }
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_owned());
        }
        let response = request.send().expect("real HTTP response");
        let status = response.status().as_u16();
        let id = response
            .headers()
            .get("x-request-id")
            .expect("response request ID")
            .to_str()
            .unwrap()
            .to_owned();
        let parsed = Uuid::parse_str(&id).expect("response request ID is a UUID");
        assert!(!parsed.is_nil());
        assert_eq!(
            id,
            parsed.hyphenated().to_string(),
            "canonical lowercase UUID"
        );
        if let Some(supplied) = supplied {
            if let Ok(valid) = Uuid::parse_str(supplied) {
                assert_eq!(id, valid.hyphenated().to_string());
            } else {
                assert_ne!(id, supplied, "untrusted header is replaced");
            }
        }
        let body = response.text().unwrap();
        self.ids.lock().push(id.clone());
        let event = self.event(&id);
        assert_eq!(
            event["request_id_replaced"],
            supplied.is_some_and(|value| Uuid::parse_str(value).is_err()),
        );
        check_event(
            &event,
            method,
            if path.starts_with("/peer/generate/") {
                "/peer/generate/<space>"
            } else {
                path
            },
            status,
        );
        Reply {
            id,
            status,
            body,
            event,
        }
    }

    fn invoke(
        &self,
        session: &Session,
        service: &str,
        path: &str,
        action: &str,
        body: Option<&str>,
        id: Option<&str>,
    ) -> Reply {
        let auth = invocation(session, service, path, action).unwrap();
        self.request("POST", "/invoke", Some(&auth), body, id)
    }

    fn logs(&self) -> String {
        [&self.stdout, &self.stderr]
            .map(|path| std::fs::read_to_string(path).unwrap())
            .join("\n")
    }

    fn events(&self) -> Vec<Value> {
        self.logs()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["target"] == "tinycloud::request")
            .map(|event| event["fields"].clone())
            .collect()
    }

    fn event(&self, id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let events = self.events();
            let matching: Vec<_> = events
                .iter()
                .filter(|event| event["request_id"] == id)
                .collect();
            if !matching.is_empty() {
                assert_eq!(
                    matching.len(),
                    1,
                    "exactly one node_request for {id}: {events:?}"
                );
                return matching[0].clone();
            }
            assert!(
                Instant::now() < deadline,
                "missing node_request for {id}: {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(&mut self, accounts: &[&Account]) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        let events = self.events();
        let mut counts = HashMap::new();
        for event in &events {
            let id = event["request_id"].as_str().expect("typed request UUID");
            *counts.entry(id).or_insert(0usize) += 1;
        }
        assert!(
            counts.values().all(|count| *count == 1),
            "duplicate completion events: {events:?}"
        );
        for id in self.ids.lock().iter() {
            assert_eq!(
                counts.get(id.as_str()),
                Some(&1),
                "one final event for every response"
            );
        }
        let logs = self.logs();
        for forbidden in [
            SECRET,
            KEY,
            VALUE,
            HEADER,
            PARAM,
            LITERAL,
            TABLE,
            "SELECT ",
            "INSERT INTO ",
            "UPDATE ",
            "CREATE TABLE ",
            "db.statement",
            "sqlx::query",
        ] {
            assert!(
                !logs.contains(forbidden),
                "stdout/stderr leaked {forbidden}"
            );
        }
        let decoded = base64::decode_config(SECRET, base64::URL_SAFE_NO_PAD).unwrap();
        assert!(!logs.contains(std::str::from_utf8(&decoded).unwrap()));
        for credential in self.credentials.lock().iter() {
            assert!(
                !logs.contains(credential),
                "stdout/stderr leaked signed authorization"
            );
        }
        for account in accounts {
            for identity in [
                account.space.to_string(),
                account.space.did().to_string(),
                format!("0x{}", eip55(&account.address)),
                hex::encode(account.address),
            ] {
                assert!(
                    !logs
                        .to_ascii_lowercase()
                        .contains(&identity.to_ascii_lowercase()),
                    "stdout/stderr leaked a synthetic DID, wallet, or space"
                );
            }
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn check_event(event: &Value, method: &str, route: &str, status: u16) {
    assert_eq!(event["event"], "node_request");
    assert_eq!(event["svc"], "api");
    assert_eq!(event["method"], method);
    assert_eq!(event["route"], route);
    assert_eq!(event["status"].as_u64(), Some(u64::from(status)));
    assert!(
        event["latency_us"].as_u64().is_some(),
        "integer latency: {event}"
    );
    for field in ["pool_wait_ms", "query_time_ms"] {
        let value = event[field]
            .as_f64()
            .unwrap_or_else(|| panic!("numeric {field}: {event}"));
        assert!(value.is_finite() && value >= 0.0);
    }
    assert!(
        event["query_count"].as_u64().is_some(),
        "integer query count: {event}"
    );
    let allowed = [
        "message",
        "event",
        "svc",
        "method",
        "route",
        "status",
        "latency_us",
        "request_id",
        "request_id_replaced",
        "pool_wait_ms",
        "query_time_ms",
        "query_count",
        "account_hash",
        "space_hash",
    ];
    assert!(event
        .as_object()
        .unwrap()
        .keys()
        .all(|key| allowed.contains(&key.as_str())));
    assert!(serde_json::to_vec(event).unwrap().len() < 2048);
}

fn check_authenticated(reply: &Reply, account: &Account) {
    let key = StaticSecret::new(base64::decode_config(SECRET, base64::URL_SAFE_NO_PAD).unwrap())
        .unwrap()
        .derive_key(b"tinycloud/telemetry/pseudonyms/v1");
    for (field, domain, identity) in [
        (
            "account_hash",
            b"account\0".as_slice(),
            account.space.did().to_string(),
        ),
        (
            "space_hash",
            b"space\0".as_slice(),
            account.space.to_string(),
        ),
    ] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(domain);
        mac.update(identity.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(reply.event[field], expected, "keyed canonical pseudonym");
        assert_eq!(reply.event[field].as_str().unwrap().len(), 64);
    }
    assert!(
        reply.event["query_count"].as_u64().unwrap() > 0,
        "auth and SQL work is counted"
    );
    assert!(reply.event["query_time_ms"].as_f64().unwrap() > 0.0);
    assert!(reply.event["pool_wait_ms"].as_f64().unwrap() > 0.0);
}

// Same SDK host/session SIWE flow as postgres_round_trip_budget.rs; only the
// transport changes from Rocket's in-process client to the actual binary.
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
        let space = SpaceId::new(did.parse::<DIDBuf>()?, "account".parse()?);
        Ok(Self {
            key,
            address,
            space,
        })
    }

    fn sign(&self, message: &Message) -> Result<Signature> {
        let (signature, recovery) = self.key.sign_prehash_recoverable(
            &message.eip191_hash().map_err(|error| anyhow!("{error}"))?,
        )?;
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
        .context("SDK delegation Authorization header")
}

fn invocation(session: &Session, service: &str, path: &str, action: &str) -> Result<String> {
    Ok(session
        .invoke(
            [(
                service.parse::<Service>()?,
                path.parse::<Path>()?,
                None,
                None,
                [action.parse::<Ability>()?],
            )],
            None,
        )?
        .encode()?)
}

fn sign_in(node: &Node, account: &Account) -> Result<Session> {
    let peer = node.request(
        "GET",
        &format!("/peer/generate/{}", account.space),
        None,
        None,
        None,
    );
    assert_eq!(peer.status, 200, "peer: {}", peer.body);
    let now = time::OffsetDateTime::now_utc();
    let host = generate_host_siwe_message(HostConfig {
        address: account.address,
        chain_id: 1,
        domain: "localhost".parse()?,
        issued_at: now.into(),
        space_id: account.space.clone(),
        peer_id: peer.body,
    })?;
    let signature = account.sign(&host)?;
    let host = authorization(&siwe_to_delegation_headers(SignedMessage {
        siwe: host,
        signature,
    }))?;
    let delegated = node.request("POST", "/delegate", Some(&host), None, None);
    assert_eq!(delegated.status, 200, "host delegation: {}", delegated.body);
    check_authenticated(&delegated, account);
    let prepared = prepare_session(SessionConfig {
        abilities: HashMap::from([
            (
                "kv".parse()?,
                HashMap::from([(
                    "".parse()?,
                    ["get", "put"]
                        .into_iter()
                        .map(|action| format!("tinycloud.kv/{action}").parse())
                        .collect::<Result<_, _>>()?,
                )]),
            ),
            (
                "sql".parse()?,
                HashMap::from([(
                    DATABASE.parse()?,
                    vec![
                        "tinycloud.sql/read".parse()?,
                        "tinycloud.sql/write".parse()?,
                    ],
                )]),
            ),
            #[cfg(feature = "duckdb")]
            (
                "duckdb".parse()?,
                HashMap::from([(
                    DATABASE.parse()?,
                    vec![
                        "tinycloud.duckdb/read".parse()?,
                        "tinycloud.duckdb/admin".parse()?,
                    ],
                )]),
            ),
        ]),
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
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature,
    })?;
    let delegated = node.request(
        "POST",
        "/delegate",
        Some(&authorization(&session.delegation_header)?),
        None,
        None,
    );
    assert_eq!(
        delegated.status, 200,
        "session delegation: {}",
        delegated.body
    );
    check_authenticated(&delegated, account);
    Ok(session)
}

// Tiny local HTTP quota service. It records real outbound headers and returns
// a permissive limit; it never echoes an inbound ID back to the node.
struct QuotaStub {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl QuotaStub {
    fn start() -> Self {
        let body = r#"{"storage_limit_bytes":100000000}"#;
        Self::with_response(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
    }

    fn redirect(location: &str) -> Self {
        Self::with_response(format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ))
    }

    fn with_response(response: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = requests.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("quota accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0 && bytes.len() + count <= 65536);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                recorded.lock().push(String::from_utf8(bytes).unwrap());
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn assert_forwarded(&self, id: &str) {
        let requests = self.requests.lock();
        let matching: Vec<_> = requests
            .iter()
            .filter(|request| {
                request.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("x-request-id") && value.trim() == id
                    })
                })
            })
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "one synchronous quota request carries SAME request UUID"
        );
        assert!(matching[0].starts_with("GET /api/quota/"));
    }
}

impl Drop for QuotaStub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn configured_quota_receives_correlation_but_redirect_origin_does_not() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("isolated.toml"),
        "# Isolated redirect fixture\n",
    )?;
    let third_party = QuotaStub::start();
    let quota = QuotaStub::redirect(&format!("{}/private", third_party.url));
    let mut node = Node::start(root.path(), 0, "trace", &quota.url);
    let account = Account::new(47)?;
    let session = sign_in(&node, &account)?;
    let put = node.invoke(&session, "kv", KEY, "tinycloud.kv/put", Some(VALUE), None);
    assert_eq!(
        put.status, 200,
        "quota fallback preserves the write: {}",
        put.body
    );
    quota.assert_forwarded(&put.id);
    assert!(
        third_party.requests.lock().is_empty(),
        "no cross-origin follow or correlation disclosure"
    );
    node.finish(&[&account]);
    Ok(())
}

#[test]
fn configured_quota_without_matching_explicit_origin_gets_no_request_id() -> Result<()> {
    for origins in [Vec::<&str>::new(), vec!["http://127.0.0.1:1"]] {
        let root = tempfile::tempdir()?;
        std::fs::write(
            root.path().join("isolated.toml"),
            "# Unclassified destination fixture\n",
        )?;
        let quota = QuotaStub::start();
        let mut node = Node::start_with_origins(root.path(), 0, "trace", &quota.url, &origins);
        let account = Account::new(53)?;
        let session = sign_in(&node, &account)?;
        let put = node.invoke(&session, "kv", KEY, "tinycloud.kv/put", Some(VALUE), None);
        assert_eq!(put.status, 200);
        let requests = quota.requests.lock();
        assert_eq!(requests.len(), 1, "the quota operation still executes");
        assert!(
            requests.iter().all(|request| !request.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
            })),
            "configuring a destination, or a different port, does not classify it first-party"
        );
        drop(requests);
        node.finish(&[&account]);
    }
    Ok(())
}

#[test]
fn authenticated_kv_sql_failure_privacy_forwarding_and_restart() -> Result<()> {
    for level in ["debug", "trace"] {
        let root = tempfile::tempdir()?;
        std::fs::write(
            root.path().join("isolated.toml"),
            "# Isolated synthetic telemetry fixture\n",
        )?;
        let quota = QuotaStub::start();
        let mut node = Node::start(root.path(), 0, level, &quota.url);
        let account = Account::new(37)?;
        let session = sign_in(&node, &account)?;
        let accepted = Uuid::new_v4().to_string();
        let put = node.invoke(
            &session,
            "kv",
            KEY,
            "tinycloud.kv/put",
            Some(VALUE),
            Some(&accepted.to_uppercase()),
        );
        assert_eq!(put.status, 200, "KV write: {}", put.body);
        assert_eq!(put.id, accepted);
        check_authenticated(&put, &account);
        quota.assert_forwarded(&put.id);
        let get = node.invoke(&session, "kv", KEY, "tinycloud.kv/get", None, Some(HEADER));
        assert_eq!(get.status, 200, "KV read: {}", get.body);
        assert_eq!(get.body, VALUE);
        check_authenticated(&get, &account);
        let create = json!({"action":"execute", "sql":format!("CREATE TABLE {TABLE} (id INTEGER PRIMARY KEY, value TEXT UNIQUE)"), "params":[]}).to_string();
        let created = node.invoke(
            &session,
            "sql",
            DATABASE,
            "tinycloud.sql/write",
            Some(&create),
            None,
        );
        assert_eq!(created.status, 200, "SQL schema: {}", created.body);
        check_authenticated(&created, &account);
        let insert = json!({"action":"execute", "sql":format!("INSERT INTO {TABLE} (id, value) VALUES (1, ?)"), "params":[PARAM]}).to_string();
        let inserted = node.invoke(
            &session,
            "sql",
            DATABASE,
            "tinycloud.sql/write",
            Some(&insert),
            None,
        );
        assert_eq!(inserted.status, 200, "SQL insert: {}", inserted.body);
        check_authenticated(&inserted, &account);
        let query = json!({"action":"query", "sql":format!("SELECT value, '{LITERAL}' FROM {TABLE} WHERE id = ?"), "params":[1]}).to_string();
        let selected = node.invoke(
            &session,
            "sql",
            DATABASE,
            "tinycloud.sql/read",
            Some(&query),
            None,
        );
        assert_eq!(selected.status, 200, "SQL query: {}", selected.body);
        assert_eq!(
            serde_json::from_str::<Value>(&selected.body)?["rows"],
            json!([[PARAM, LITERAL]])
        );
        check_authenticated(&selected, &account);

        // Both requests parse and authorize. SQLite itself rejects the last
        // INSERT's duplicate PRIMARY KEY. The late failure must also count
        // seven completed UPDATEs, proving actor work and failures are measured
        // rather than just counting the surrounding auth database operations.
        let mut failed_counts = Vec::new();
        for preceding in [0, 7] {
            let mut statements = vec![
                json!({"sql":format!("UPDATE {TABLE} SET value = ? WHERE id = 1"), "params":[PARAM]});
                preceding
            ];
            statements.push(json!({"sql":format!("INSERT INTO {TABLE} (id, value) VALUES (1, ?)"), "params":[PARAM]}));
            let body = json!({"action":"batch", "statements":statements}).to_string();
            let failed = node.invoke(
                &session,
                "sql",
                DATABASE,
                "tinycloud.sql/write",
                Some(&body),
                None,
            );
            assert_eq!(
                failed.status, 400,
                "backend constraint failure: {}",
                failed.body
            );
            assert!(
                failed
                    .body
                    .to_ascii_lowercase()
                    .contains("unique constraint failed"),
                "must reach SQLite, not admission/parser: {}",
                failed.body
            );
            check_authenticated(&failed, &account);
            failed_counts.push(failed.event["query_count"].as_u64().unwrap());
        }
        assert!(
            failed_counts[1] >= failed_counts[0] + 7,
            "each embedded SQL attempt is counted, including the failed attempt: {failed_counts:?}"
        );
        let before = get.event.clone();
        node.finish(&[&account]);

        // Same isolated datadir and secret, but a new process and fresh UUID.
        let mut restarted = Node::start(root.path(), 1, level, &quota.url);
        let get = restarted.invoke(&session, "kv", KEY, "tinycloud.kv/get", None, None);
        assert_eq!(
            get.status, 200,
            "persisted KV read after restart: {}",
            get.body
        );
        assert_eq!(get.body, VALUE);
        check_authenticated(&get, &account);
        assert_eq!(get.event["account_hash"], before["account_hash"]);
        assert_eq!(get.event["space_hash"], before["space_hash"]);
        restarted.finish(&[&account]);
    }
    Ok(())
}

#[test]
fn concurrent_authenticated_requests_keep_metrics_and_pseudonyms_scoped() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("isolated.toml"),
        "# Isolated synthetic telemetry fixture\n",
    )?;
    let quota = QuotaStub::start();
    let mut node = Node::start(root.path(), 0, "trace", &quota.url);
    let accounts = [Account::new(41)?, Account::new(43)?];
    let sessions = [sign_in(&node, &accounts[0])?, sign_in(&node, &accounts[1])?];
    for (account, session) in accounts.iter().zip(&sessions) {
        let put = node.invoke(session, "kv", KEY, "tinycloud.kv/put", Some(VALUE), None);
        assert_eq!(put.status, 200, "seed KV: {}", put.body);
        check_authenticated(&put, account);
        quota.assert_forwarded(&put.id);
    }
    // Pre-sign distinct invocations so only real HTTP execution is in the
    // burst. Different accounts plus no-DB requests catch sticky TLS/global
    // accumulators, not merely an ID echoed by a mock service.
    for _ in 0..3 {
        let mut jobs = Vec::new();
        for index in 0..12 {
            let owner = if index % 3 == 2 {
                None
            } else {
                Some(index % 3)
            };
            let auth = owner
                .map(|owner| invocation(&sessions[owner], "kv", KEY, "tinycloud.kv/get"))
                .transpose()?;
            jobs.push((Uuid::new_v4().to_string(), owner, auth));
        }
        let barrier = Barrier::new(jobs.len());
        thread::scope(|scope| {
            let handles: Vec<_> = jobs
                .iter()
                .map(|(id, owner, auth)| {
                    let node = &node;
                    let barrier = &barrier;
                    let accounts = &accounts;
                    scope.spawn(move || {
                        barrier.wait();
                        let reply = node.request(
                            if owner.is_some() { "POST" } else { "GET" },
                            if owner.is_some() {
                                "/invoke"
                            } else {
                                "/version"
                            },
                            auth.as_deref(),
                            None,
                            Some(id),
                        );
                        assert_eq!(reply.status, 200, "burst response: {}", reply.body);
                        assert_eq!(&reply.id, id);
                        if let Some(owner) = owner {
                            assert_eq!(reply.body, VALUE);
                            check_authenticated(&reply, &accounts[*owner]);
                        } else {
                            assert_eq!(reply.event["query_count"], 0);
                            assert_eq!(reply.event["pool_wait_ms"], 0.0);
                            assert_eq!(reply.event["query_time_ms"], 0.0);
                            assert!(reply.event.get("account_hash").is_none());
                            assert!(reply.event.get("space_hash").is_none());
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
        });
    }
    node.finish(&[&accounts[0], &accounts[1]]);
    Ok(())
}

#[cfg(feature = "duckdb")]
#[test]
fn native_duckdb_requests_keep_scoped_fields_and_independent_db_timings() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("isolated.toml"), "# Native DuckDB fixture\n")?;
    let quota = QuotaStub::start();
    let mut node = Node::start(root.path(), 0, "trace", &quota.url);
    let account = Account::new(61)?;
    let session = sign_in(&node, &account)?;

    let version = node.request("GET", "/version", None, None, None);
    assert_eq!(version.status, 200);
    assert_eq!(version.event["query_count"], 0);
    assert_eq!(version.event["query_time_ms"], 0.0);
    assert_eq!(version.event["pool_wait_ms"], 0.0);

    // Diagnostic policy is covered by the separate TC-1304 suite. This request
    // proves node telemetry uses independent call-boundary instrumentation.
    let body = json!({
        "action":"query",
        "sql":format!("SELECT '{LITERAL}' AS literal, ? AS parameter"),
        "params":[PARAM],
    })
    .to_string();
    let incoming = Uuid::new_v4().to_string().to_ascii_uppercase();
    let selected = node.invoke(
        &session,
        "duckdb",
        DATABASE,
        "tinycloud.duckdb/read",
        Some(&body),
        Some(&incoming),
    );
    assert_eq!(selected.status, 200, "native query: {}", selected.body);
    assert_eq!(selected.id, incoming.to_ascii_lowercase());
    assert_eq!(selected.event["request_id_replaced"], false);
    let result: Value = serde_json::from_str(&selected.body)?;
    assert_eq!(result["rows"][0], json!([LITERAL, PARAM]));
    check_authenticated(&selected, &account);

    let body = json!({
        "action":"query",
        "sql":format!("SELECT '{LITERAL}' FROM {TABLE}"),
        "params":[],
    }).to_string();
    let failed = node.invoke(
        &session,
        "duckdb",
        DATABASE,
        "tinycloud.duckdb/read",
        Some(&body),
        None,
    );
    assert!(failed.status >= 400);
    check_authenticated(&failed, &account);
    node.finish(&[&account]);
    Ok(())
}
