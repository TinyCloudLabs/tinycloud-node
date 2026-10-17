//! TC-1304: drive the real binary with SDK-signed, synthetic identities.
//!
//! Run with `cargo test -p tinycloud-node --features duckdb --test
//! duckdb_diagnostics_policy -- --nocapture`. No database service, credentials,
//! network quota service, or production endpoint is needed. Every HTTP request
//! goes to this test's loopback child. The child has fresh config/data/HOME and
//! inherits no environment. Its actual stdout/stderr go straight to files.
//!
//! This deliberately uses production INFO logging (`normal`). DEBUG/TRACE
//! application-log redaction is independent N2 work, not this native-sink test.
//! WITH-body write controls cover signed read/readOnly authority and executing
//! plans. File auditing includes data/, exempting only native storage artifacts.
#![cfg(feature = "duckdb")]

use std::{
    collections::HashMap,
    fs::File,
    net::TcpListener,
    path::{Path as FsPath, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use reqwest::{blocking::Client, StatusCode};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tinycloud_auth::{
    cacaos::{siwe::Message, siwe_cacao::Signature},
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::dids::DIDBuf,
};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};

const DATABASE: &str = "diagnostics";
// Public synthetic test material, never an inherited deployment credential.
const STATIC_SECRET: &str = "dGMxMzA0X3N5bnRoZXRpY19ub2RlX2tleV9tYXRlcmlhbF9vbmx5";
const READ: &str = "tinycloud.duckdb/read";
const WRITE: &str = "tinycloud.duckdb/write";
const ADMIN: &str = "tinycloud.duckdb/admin";

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
    fn synthetic() -> Result<Self> {
        let key = SigningKey::from_bytes(&[0x64; 32].into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address: [u8; 20] = digest[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", eip55(&address));
        let space = SpaceId::new(did.parse::<DIDBuf>()?, "tc1304".parse()?);
        Ok(Self {
            key,
            address,
            space,
        })
    }

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
        .context("SDK delegation must contain Authorization")
}

fn invocation(session: &Session, ability: &str, facts: Option<Vec<Value>>) -> Result<String> {
    Ok(session
        .invoke(
            [(
                "duckdb".parse::<Service>()?,
                DATABASE.parse::<Path>()?,
                None,
                None,
                [ability.parse::<Ability>()?],
            )],
            facts,
        )?
        .encode()?)
}

fn template(sql: &str) -> Vec<Value> {
    vec![json!({"duckdbCaveats": {"statements": [{"name": "tenant", "sql": sql}]}})]
}

fn query(sql: &str, params: Value) -> Value {
    json!({"action": "query", "sql": sql, "params": params})
}

fn execute(sql: &str) -> Value {
    json!({"action": "execute", "sql": sql, "params": []})
}

fn named(params: Value) -> Value {
    json!({"action": "executeStatement", "name": "tenant", "params": params})
}

#[derive(Debug)]
struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn ok(self, label: &str) -> Result<Value> {
        ensure!(self.status == StatusCode::OK, "{label}: {self:?}");
        serde_json::from_str(&self.body).with_context(|| format!("{label}: expected JSON"))
    }

    // Authentication failures, storage/fence errors and native binder failures
    // are not evidence that the tenant SQL boundary rejected a primitive.
    fn policy_denied(&self) -> bool {
        matches!(self.status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN)
            && [
                "Permission denied:",
                "Invalid statement:",
                "Read-only violation",
                "Parse error:",
            ]
            .iter()
            .any(|prefix| self.body.contains(prefix))
            && !self.body.contains("DuckDB error:")
    }
}

struct Node {
    directory: tempfile::TempDir,
    server: Option<Child>,
    client: Client,
    base: String,
    // Counts only test /invoke calls; every one must keep its request log.
    invocations: usize,
    canaries: Vec<String>,
    file_canary: PathBuf,
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn child_command(root: &FsPath, port: u16, metrics_port: u16) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
    command
        .env_clear()
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("tmp"))
        .env("XDG_CONFIG_HOME", root.join("home/config"))
        .env("XDG_CACHE_HOME", root.join("home/cache"))
        .env("TINYCLOUD_CONFIG_FILE", root.join("tinycloud.toml"))
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", port.to_string())
        .env("TINYCLOUD_LOG_LEVEL", "normal")
        .env("TINYCLOUD_LOG__FORMAT", "Json")
        .env("TINYCLOUD_TELEMETRY__ENABLED", "true")
        .env("TINYCLOUD_PROMETHEUS__PORT", metrics_port.to_string())
        .env("TINYCLOUD_STORAGE__DATADIR", root.join("data"))
        .env("TINYCLOUD_KEYS__TYPE", "static")
        .env("TINYCLOUD_KEYS__SECRET", STATIC_SECRET)
        .stdin(Stdio::null());
    command
}

impl Node {
    fn start() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for path in ["home", "tmp", "diagnostics", "capture"] {
            std::fs::create_dir_all(root.join(path))?;
        }
        std::fs::write(
            root.join("tinycloud.toml"),
            "[global]\nlog_level = 'normal'\n",
        )?;
        let stdout = File::create(root.join("capture/stdout.log"))?;
        let stderr = File::create(root.join("capture/stderr.log"))?;
        let port = free_port()?;
        let metrics_port = free_port()?;

        // Genuine same-binary stderr control, not a shell/test echo. The
        // service's normal logs use stdout, so an empty stderr alone would not
        // prove that its capture handle was connected. Both child processes
        // receive clones of these same unfiltered OS file handles.
        let validation = child_command(root, port, metrics_port)
            .arg("--validate-config")
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .status()?;
        ensure!(validation.success(), "synthetic node config must be valid");
        let server = child_command(root, port, metrics_port)
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let canaries = ["literal", "bound", "log", "client_error", "file"]
            .into_iter()
            .map(|kind| format!("tc1304_{kind}_{suffix}"))
            .collect::<Vec<_>>();
        let file_canary = root
            .join("diagnostics")
            .join(format!("{}.json", canaries[4]));
        let mut node = Self {
            directory,
            server: Some(server),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .build()?,
            base: format!("http://127.0.0.1:{port}"),
            invocations: 0,
            canaries,
            file_canary,
        };
        node.wait_until_healthy()?;
        Ok(node)
    }

    fn wait_until_healthy(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let server = self.server.as_mut().context("node child is running")?;
            ensure!(
                server.try_wait()?.is_none(),
                "node exited before health check"
            );
            if let Ok(reply) = self.client.get(format!("{}/healthz", self.base)).send() {
                if reply.status().is_success() {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(anyhow!("node did not become healthy within 60s"))
    }

    fn delegate(&self, header: String) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/delegate", self.base))
            .header("Authorization", header)
            .send()?;
        let reply = Reply {
            status: response.status(),
            body: response.text()?,
        };
        ensure!(reply.status == StatusCode::OK, "SDK /delegate: {reply:?}");
        Ok(())
    }

    fn host(&self, account: &Account) -> Result<()> {
        let response = self
            .client
            .get(format!("{}/peer/generate/{}", self.base, account.space))
            .send()?;
        ensure!(
            response.status() == StatusCode::OK,
            "peer generation failed"
        );
        let host = generate_host_siwe_message(HostConfig {
            address: account.address,
            chain_id: 1,
            domain: "localhost".parse()?,
            issued_at: time::OffsetDateTime::now_utc().into(),
            space_id: account.space.clone(),
            peer_id: response.text()?,
        })?;
        let signature = account.sign(&host)?;
        self.delegate(authorization(&siwe_to_delegation_headers(SignedMessage {
            siwe: host,
            signature,
        }))?)
    }

    fn session(&self, account: &Account, ability: &str, seed: u8) -> Result<Session> {
        let now = time::OffsetDateTime::now_utc();
        let session_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let jwk = serde_json::from_value(json!({
            "kty": "OKP", "crv": "Ed25519",
            "d": base64::encode_config(session_key.to_bytes(), base64::URL_SAFE_NO_PAD),
            "x": base64::encode_config(session_key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD)
        }))?;
        let prepared = prepare_session(SessionConfig {
            abilities: HashMap::from([(
                "duckdb".parse()?,
                HashMap::from([(DATABASE.parse()?, vec![ability.parse()?])]),
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
            jwk: Some(jwk),
            delegate_uri: None,
            nonce: None,
            invocation_ttl_secs: None,
        })?;
        let signature = account.sign(&prepared.siwe)?;
        let session = complete_session_setup(SignedSession {
            session: prepared,
            signature,
        })?;
        self.delegate(authorization(&session.delegation_header)?)?;
        Ok(session)
    }

    fn invoke(
        &mut self,
        session: &Session,
        ability: &str,
        body: &Value,
        facts: Option<Vec<Value>>,
    ) -> Result<Reply> {
        let header = invocation(session, ability, facts)?;
        let response = self
            .client
            .post(format!("{}/invoke", self.base))
            .header("Authorization", header)
            .json(body)
            .send()?;
        self.invocations += 1;
        Ok(Reply {
            status: response.status(),
            body: response.text()?,
        })
    }

    fn rows(&mut self, session: &Session, sql: &str, params: Value) -> Result<Value> {
        let result = self
            .invoke(session, READ, &query(sql, params), None)?
            .ok("read query")?;
        ensure!(
            result["columns"].is_array(),
            "query must retain column metadata"
        );
        ensure!(
            result["rowCount"].is_number(),
            "query must retain row count"
        );
        Ok(result["rows"].clone())
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(mut server) = self.server.take() {
            if server.try_wait()?.is_none() {
                server.kill()?;
            }
            server.wait()?;
        }
        Ok(())
    }

    fn audit(&mut self, violations: &mut Vec<String>) -> Result<()> {
        self.stop()?;
        let root = self.directory.path();
        let stdout = std::fs::read(root.join("capture/stdout.log"))?;
        let stderr = std::fs::read(root.join("capture/stderr.log"))?;
        for (name, bytes) in [("stdout", &stdout), ("stderr", &stderr)] {
            for canary in &self.canaries {
                if contains_bytes(bytes, canary.as_bytes()) {
                    violations.push(format!("native {name} disclosed {canary}"));
                }
            }
        }
        let out = strip_ansi(&String::from_utf8_lossy(&stdout));
        let err = strip_ansi(&String::from_utf8_lossy(&stderr));
        ensure!(
            out.contains("did resolution policy"),
            "service startup stdout is missing"
        );
        ensure!(
            err.contains("tinycloud-node runtime configuration is valid"),
            "real-binary stderr capture control is missing"
        );
        let request_events = out
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| {
                event["event"] == "node_request"
                    && event["method"] == "POST"
                    && event["route"] == "/invoke"
            })
            .collect::<Vec<_>>();
        ensure!(
            request_events.len() == self.invocations,
            "request logging was hidden: expected {}, got {}",
            self.invocations,
            request_events.len()
        );
        ensure!(
            request_events
                .iter()
                .any(|event| event["status"].as_u64() == Some(200)),
            "successful requests must still be logged"
        );
        ensure!(
            request_events
                .iter()
                .any(|event| matches!(event["status"].as_u64(), Some(400 | 403))),
            "rejected requests must still be logged"
        );
        if self.file_canary.exists() {
            violations.push(format!(
                "tenant diagnostic file was created: {}",
                self.file_canary.display()
            ));
        }
        // Only exact native database/WAL paths and content-addressed block
        // artifacts for this synthetic space are exempt. Recurse into data/
        // too: a default diagnostic filename there is not application storage.
        scan_owned_files(
            root,
            &root.join("data"),
            &Account::synthetic()?.space,
            &self.canaries,
            violations,
        )?;
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn contains_bytes(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn is_native_storage_artifact(path: &FsPath, data: &FsPath, space: &SpaceId) -> bool {
    if ["caps.db", "caps.db-wal", "caps.db-shm", "caps.db-journal"]
        .iter()
        .any(|name| path == data.join(name))
    {
        return true;
    }
    let cache = data.join("duckdb").join(space.to_string());
    let physical = tinycloud_core::database_identity::logical_name(Some(DATABASE));
    if [
        format!("{physical}.duckdb"),
        format!("{physical}.duckdb.wal"),
    ]
    .iter()
    .any(|name| path == cache.join(name))
    {
        return true;
    }
    let blocks = data
        .join("blocks")
        .join(space.suffix())
        .join(space.name().as_str());
    if path.parent() != Some(blocks.as_path()) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Ok(bytes) = base64::decode_config(name, base64::URL_SAFE) else {
        return false;
    };
    base64::encode_config(&bytes, base64::URL_SAFE) == name
        && tinycloud_core::hash::Hash::try_from(bytes).is_ok()
}

fn scan_owned_files(
    directory: &FsPath,
    data: &FsPath,
    space: &SpaceId,
    canaries: &[String],
    violations: &mut Vec<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            scan_owned_files(&path, data, space, canaries, violations)?;
        } else if kind.is_file() {
            if is_native_storage_artifact(&path, data, space) {
                continue;
            }
            if path.starts_with(data) {
                violations.push(format!(
                    "unexpected non-storage file under owned data directory: {}",
                    path.display()
                ));
            }
            let contents = std::fs::read(&path)?;
            for canary in canaries {
                if contains_bytes(&contents, canary.as_bytes()) {
                    violations.push(format!(
                        "owned non-database file {} contains {canary}",
                        path.display()
                    ));
                }
            }
        } else {
            violations.push(format!(
                "unexpected non-regular diagnostic artifact: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[test]
fn owned_file_audit_scans_data_without_reading_native_storage_artifacts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let data = root.join("data");
    let space = Account::synthetic()?.space;
    let marker = "tc1304_synthetic_file_audit_canary";
    let canaries = vec![marker.into()];
    let physical = tinycloud_core::database_identity::logical_name(Some(DATABASE));
    let block_name = base64::encode_config(
        Vec::<u8>::from(tinycloud_core::hash::hash(marker.as_bytes())),
        base64::URL_SAFE,
    );
    let native = [
        data.join("caps.db"),
        data.join("caps.db-wal"),
        data.join("caps.db-shm"),
        data.join("caps.db-journal"),
        data.join("duckdb")
            .join(space.to_string())
            .join(format!("{physical}.duckdb")),
        data.join("duckdb")
            .join(space.to_string())
            .join(format!("{physical}.duckdb.wal")),
        data.join("blocks")
            .join(space.suffix())
            .join(space.name().as_str())
            .join(block_name),
    ];
    for path in &native {
        std::fs::create_dir_all(path.parent().context("native artifact parent")?)?;
        std::fs::write(path, marker)?;
    }
    let mut violations = Vec::new();
    scan_owned_files(root, &data, &space, &canaries, &mut violations)?;
    ensure!(
        violations.is_empty(),
        "native storage must not be scanned for legitimate stored rows"
    );

    // Unknown files, even with a database suffix or empty contents, must not
    // disappear merely because they live below the application data root.
    for (name, contents) in [
        ("duckdb_profile.json", marker),
        ("decoy.duckdb", marker),
        ("empty_profile.json", ""),
    ] {
        std::fs::write(data.join(name), contents)?;
    }
    std::fs::create_dir_all(data.join("nested"))?;
    std::fs::write(data.join("nested/diagnostics.log"), marker)?;
    scan_owned_files(root, &data, &space, &canaries, &mut violations)?;
    for name in [
        "duckdb_profile.json",
        "decoy.duckdb",
        "empty_profile.json",
        "diagnostics.log",
    ] {
        ensure!(
            violations.iter().any(|violation| violation.contains(name)),
            "owned data diagnostic escaped file audit: {name}"
        );
    }
    ensure!(
        violations.iter().any(|violation| {
            violation.contains("diagnostics.log") && violation.contains(marker)
        }),
        "nested data files must be content-scanned too"
    );
    Ok(())
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn require_denial(label: &str, reply: Reply, violations: &mut Vec<String>) {
    if !reply.policy_denied() {
        violations.push(format!(
            "{label}: expected tenant-policy rejection, got {reply:?}"
        ));
    }
}

fn safe_controls(
    node: &mut Node,
    reader: &Session,
    writer: &Session,
    admin: &Session,
) -> Result<()> {
    node.invoke(
        writer,
        WRITE,
        &execute("CREATE TABLE IF NOT EXISTS safe_rows (id INTEGER, value TEXT)"),
        None,
    )?
    .ok("safe write-tier DDL")?;
    node.invoke(
        writer,
        WRITE,
        &json!({
            "action": "execute", "sql": "INSERT INTO safe_rows VALUES (?, ?)",
            "params": [1, node.canaries[1]]
        }),
        None,
    )?
    .ok("safe bound insert")?;
    let literal = node.canaries[0].clone();
    ensure!(
        node.rows(reader, &format!("SELECT '{literal}' AS value"), json!([]))?
            == json!([[literal]]),
        "literal row changed"
    );
    let bound = node.canaries[1].clone();
    ensure!(
        node.rows(reader, "SELECT ? AS value", json!([bound]))? == json!([[bound]]),
        "bound row changed"
    );
    ensure!(
        node.rows(
            reader,
            "SELECT id, value FROM safe_rows ORDER BY id",
            json!([])
        )? == json!([[1, bound]]),
        "stored rows changed"
    );
    let inert = "write_log('literal') enable_logging(storage='stdout') PRAGMA enable_profile";
    ensure!(
        node.rows(reader, "SELECT ? AS value", json!([inert]))? == json!([[inert]]),
        "diagnostic words in a value are not executable SQL"
    );
    let inert_sql = format!("SELECT '{}' AS value", inert.replace('\'', "''"));
    ensure!(
        node.rows(reader, &inert_sql, json!([]))? == json!([[inert]]),
        "diagnostic words in a SQL literal are not function calls"
    );
    ensure!(
        node.rows(reader, "SELECT 'enable_logging' AS value", json!([]))?
            == json!([["enable_logging"]]),
        "diagnostic identifier literal changed"
    );
    let prepared = node
        .invoke(
            reader,
            READ,
            &named(json!([bound])),
            Some(template("SELECT ? AS value")),
        )?
        .ok("safe named read template")?;
    ensure!(
        prepared["rows"] == json!([[bound]]),
        "named template parameters changed"
    );
    node.invoke(
        admin,
        ADMIN,
        &execute("CREATE VIEW safe_view AS SELECT id, value FROM safe_rows"),
        None,
    )?
    .ok("safe admin DDL")?;
    ensure!(
        node.rows(reader, "SELECT id FROM safe_view", json!([]))? == json!([[1]]),
        "safe view result changed"
    );
    node.invoke(admin, ADMIN, &execute("DROP VIEW safe_view"), None)?
        .ok("safe admin drop")?;
    let missing = node.canaries[3].clone();
    let error = node.invoke(
        reader,
        READ,
        &query(&format!("SELECT {missing} FROM safe_rows"), json!([])),
        None,
    )?;
    ensure!(
        error.status == StatusCode::BAD_REQUEST,
        "actual client error status changed: {error:?}"
    );
    ensure!(
        error.body.contains("DuckDB error:") && error.body.contains(&missing),
        "actual native client error was hidden: {error:?}"
    );
    Ok(())
}

fn signed_sessions(node: &Node) -> Result<(Session, Session, Session)> {
    let account = Account::synthetic()?;
    node.host(&account)?;
    Ok((
        node.session(&account, READ, 0x31)?,
        node.session(&account, WRITE, 0x32)?,
        node.session(&account, ADMIN, 0x33)?,
    ))
}

#[test]
fn signed_read_invocation_facts_cannot_authorize_writes_or_named_ddl() -> Result<()> {
    let mut node = Node::start()?;
    let mut violations = Vec::new();
    let result = (|| -> Result<()> {
        let (reader, writer, admin) = signed_sessions(&node)?;
        safe_controls(&mut node, &reader, &writer, &admin)?;
        for (index, sql) in [
            "CREATE TABLE tenant_created (value INTEGER)",
            "INSERT INTO safe_rows VALUES (2, 'unauthorized')",
            "UPDATE safe_rows SET value = 'unauthorized' WHERE id = 1",
            "DELETE FROM safe_rows WHERE id = 1",
            "ALTER TABLE safe_rows ADD COLUMN unauthorized INTEGER",
            "DROP TABLE safe_rows",
        ]
        .into_iter()
        .enumerate()
        {
            // Exact same signed read-only session and SQL with/without facts:
            // only the invocation-controlled template list is changing.
            let baseline = node.invoke(&reader, READ, &execute(sql), None)?;
            require_denial(&format!("read baseline {index}"), baseline, &mut violations);
            let exact = node.invoke(&reader, READ, &execute(sql), Some(template(sql)))?;
            require_denial(
                &format!("read exact template {index}"),
                exact,
                &mut violations,
            );
            let by_name = node.invoke(&reader, READ, &named(json!([])), Some(template(sql)))?;
            require_denial(
                &format!("read named template {index}"),
                by_name,
                &mut violations,
            );
        }
        let executing_plan =
            "EXPLAIN ANALYZE UPDATE safe_rows SET value = 'unauthorized' WHERE id = 1";
        for facts in [None, Some(template(executing_plan))] {
            let response = node.invoke(&reader, READ, &query(executing_plan, json!([])), facts)?;
            require_denial("read executing plan", response, &mut violations);
        }
        let bound = node.canaries[1].clone();
        let rows = node.rows(
            &reader,
            "SELECT id, value FROM safe_rows ORDER BY id",
            json!([]),
        )?;
        ensure!(
            rows == json!([[1, bound]]),
            "rejected writes changed data: {rows}"
        );
        ensure!(node.rows(&reader, "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'tenant_created'", json!([]))? == json!([[0]]), "read-only template created a table");
        Ok(())
    })();
    // Audit even if a public API positive control or final data check failed.
    let audit = node.audit(&mut violations);
    result?;
    audit?;
    ensure!(violations.is_empty(), "{}", violations.join("\n"));
    Ok(())
}

#[test]
fn signed_tenant_tiers_cannot_activate_native_diagnostic_sinks() -> Result<()> {
    let mut node = Node::start()?;
    let mut violations = Vec::new();
    let result = (|| -> Result<()> {
        let (reader, writer, admin) = signed_sessions(&node)?;
        safe_controls(&mut node, &reader, &writer, &admin)?;
        let marker = node.canaries[2].clone();
        let path = node.file_canary.to_string_lossy().replace('\'', "''");
        let cases = vec![
            format!("SET profiling_output = '{path}'"),
            format!("SET profile_output = '{path}'"),
            "SET enable_profiling = 'json'".into(),
            "sEt \"enable_profiling\" = 'query_tree'".into(),
            "SET profiling_mode = 'detailed'".into(),
            "SET enable_logging = true".into(),
            "SET logging_storage = 'stdout'".into(),
            "PRAGMA enable_profile".into(),
            "pRaGmA enable_profiling".into(),
            "PRAGMA disable_profile".into(),
            "RESET enable_profiling".into(),
            "SELECT * FROM enable_logging(storage='stdout')".into(),
            "SELECT * FROM \"EnAbLe_LoGgInG\"(storage='stderr')".into(),
            "SELECT * FROM main.enable_logging(storage='stdout')".into(),
            "CALL enable_logging(storage='stdout')".into(),
            "CALL \"system\".\"main\".\"enable_logging\"(storage='stderr')".into(),
            format!("SELECT write_log('{marker}')"),
            format!("SELECT \"WrItE_LoG\"('{marker}')"),
            format!("SELECT main.write_log('{marker}')"),
            format!("SELECT \"system\".\"main\".\"write_log\"('{marker}')"),
            format!("CALL write_log('{marker}')"),
            format!("SELECT (SELECT write_log('{marker}'))"),
            format!(
                "WITH nested AS (SELECT write_log('{marker}') AS value) SELECT value FROM nested"
            ),
            format!("SELECT CASE WHEN true THEN write_log('{marker}') ELSE NULL END"),
            // A dynamic SQL bridge is rejected even when this particular
            // payload is harmless; this never asks native code for an effect.
            "SELECT * FROM query('SELECT 1 AS value')".into(),
            // Definitions are tested at the guard, never invoked for effects.
            format!("CREATE VIEW unsafe_view AS SELECT write_log('{marker}') AS value"),
            format!("CREATE MACRO unsafe_macro() AS write_log('{marker}')"),
        ];
        for (ability, session) in [(READ, &reader), (WRITE, &writer), (ADMIN, &admin)] {
            for (index, sql) in cases.iter().enumerate() {
                let request = if sql.trim_start().to_ascii_uppercase().starts_with("SELECT")
                    || sql.starts_with("WITH ")
                {
                    query(sql, json!([]))
                } else {
                    execute(sql)
                };
                let plain = node.invoke(session, ability, &request, None)?;
                require_denial(
                    &format!("{ability} plain diagnostic {index}"),
                    plain,
                    &mut violations,
                );
                let exact = node.invoke(session, ability, &request, Some(template(sql)))?;
                require_denial(
                    &format!("{ability} exact diagnostic {index}"),
                    exact,
                    &mut violations,
                );
                let by_name =
                    node.invoke(session, ability, &named(json!([])), Some(template(sql)))?;
                require_denial(
                    &format!("{ability} named diagnostic {index}"),
                    by_name,
                    &mut violations,
                );
            }
        }
        // If an activation incorrectly succeeded, these queries exercise it
        // with distinct literal and bound canaries instead of just checking an
        // error code. Native output cannot pass through tracing redaction.
        let literal = node.canaries[0].clone();
        let bound = node.canaries[1].clone();
        ensure!(
            node.rows(&reader, &format!("SELECT '{literal}' AS value"), json!([]))?
                == json!([[literal]]),
            "post-rejection literal row changed"
        );
        ensure!(
            node.rows(&reader, "SELECT ? AS value", json!([bound]))? == json!([[bound]]),
            "post-rejection bound row changed"
        );
        let settings = node.rows(&reader, "SELECT current_setting('enable_external_access'), current_setting('lock_configuration'), CAST(current_setting('enable_logging') AS BOOLEAN)", json!([]))?;
        ensure!(settings == json!([[false, true, false]]), "native connection did not keep external access/logging off and configuration locked: {settings}");
        Ok(())
    })();
    let audit = node.audit(&mut violations);
    result?;
    audit?;
    ensure!(violations.is_empty(), "{}", violations.join("\n"));
    Ok(())
}

#[test]
fn signed_with_prefixed_writes_and_executing_plans_require_write_authority() -> Result<()> {
    fn statement(insert: bool, analyze: bool, id: i64, value: i64) -> String {
        let sql = if insert {
            format!(
                "WITH change AS (SELECT {id} AS id, {value} AS value) \
                 INSERT INTO nested_rows SELECT id, value FROM change"
            )
        } else {
            format!(
                "WITH change AS (SELECT {value} AS value) \
                 UPDATE nested_rows SET value = (SELECT value FROM change) WHERE id = 1"
            )
        };
        if analyze {
            format!("EXPLAIN ANALYZE {sql}")
        } else {
            sql
        }
    }

    let mut node = Node::start()?;
    let mut violations = Vec::new();
    let result = (|| -> Result<()> {
        let (reader, writer, admin) = signed_sessions(&node)?;
        safe_controls(&mut node, &reader, &writer, &admin)?;
        for sql in [
            "CREATE TABLE nested_rows (id INTEGER, value INTEGER)",
            "INSERT INTO nested_rows VALUES (1, 7)",
        ] {
            node.invoke(&writer, WRITE, &execute(sql), None)?
                .ok("nested-write fixture")?;
        }
        let data_sql = "SELECT id, value FROM nested_rows ORDER BY id";
        let catalog_sql =
            "SELECT table_name, column_name, data_type FROM information_schema.columns \
                           WHERE table_schema = 'main' ORDER BY table_name, ordinal_position";
        let before_rows = node.rows(&reader, data_sql, json!([]))?;
        let before_catalog = node.rows(&reader, catalog_sql, json!([]))?;
        for analyze in [false, true] {
            for insert in [false, true] {
                let sql = statement(insert, analyze, 2, 99);
                for (session, ability, read_only) in [
                    (&reader, READ, false),
                    (&writer, WRITE, true),
                    (&admin, ADMIN, true),
                ] {
                    for mode in ["raw", "exact", "named"] {
                        let facts = if read_only {
                            let mut caveats = json!({"readOnly": true});
                            if mode != "raw" {
                                caveats["statements"] = json!([{"name": "tenant", "sql": sql}]);
                            }
                            Some(vec![json!({"duckdbCaveats": caveats})])
                        } else if mode != "raw" {
                            Some(template(&sql))
                        } else {
                            None
                        };
                        // Raw/exact executing plans MUST use Query. Native
                        // execute() may reject a returned plan after a write;
                        // that is neither policy denial nor absence of effect.
                        let body = if mode == "named" {
                            named(json!([]))
                        } else {
                            query(&sql, json!([]))
                        };
                        let reply = node.invoke(session, ability, &body, facts)?;
                        require_denial(
                            &format!("{ability} readOnly={read_only} {mode} {sql}"),
                            reply,
                            &mut violations,
                        );
                    }
                }
            }
        }
        ensure!(
            node.rows(&reader, data_sql, json!([]))? == before_rows,
            "rejected WITH-prefixed writes changed real row data"
        );
        ensure!(
            node.rows(&reader, catalog_sql, json!([]))? == before_catalog,
            "rejected WITH-prefixed writes changed the native catalog"
        );

        let mut expected = vec![json!([1, 7])];
        let mut next_id = 2;
        let mut next_value = 10;
        for (session, ability) in [(&writer, WRITE), (&admin, ADMIN)] {
            for analyze in [false, true] {
                for insert in [false, true] {
                    for mode in ["raw", "exact", "named"] {
                        // Named templates retain the execute response path.
                        // Positive executing-plan controls use Query instead.
                        if analyze && mode == "named" {
                            continue;
                        }
                        let sql = statement(insert, analyze, next_id, next_value);
                        let facts = (mode != "raw").then(|| template(&sql));
                        let body = if mode == "named" {
                            named(json!([]))
                        } else {
                            query(&sql, json!([]))
                        };
                        let result = node.invoke(session, ability, &body, facts)?.ok(&format!(
                            "authorized {ability} {mode} analyze={analyze} insert={insert}"
                        ))?;
                        if mode != "named" {
                            ensure!(
                                result["columns"]
                                    .as_array()
                                    .is_some_and(|columns| !columns.is_empty())
                                    && result["rows"]
                                        .as_array()
                                        .is_some_and(|rows| !rows.is_empty()),
                                "authorized Query must return native row/plan results: {result}"
                            );
                            ensure!(
                                result["rowCount"].as_u64()
                                    == result["rows"].as_array().map(|rows| rows.len() as u64),
                                "authorized Query lost its real row count"
                            );
                        }
                        if insert {
                            expected.push(json!([next_id, next_value]));
                            next_id += 1;
                        } else {
                            expected[0] = json!([1, next_value]);
                        }
                        next_value += 1;
                        ensure!(
                            node.rows(&reader, data_sql, json!([]))? == json!(expected),
                            "authorized WITH-prefixed write did not change real row data"
                        );
                    }
                }
            }
        }
        ensure!(
            node.rows(&reader, catalog_sql, json!([]))? == before_catalog,
            "authorized DML changed catalog definitions"
        );
        Ok(())
    })();
    // Preserve stream, result, request-log and file canary controls even when
    // an authorization or native-result assertion reports a failure.
    let audit = node.audit(&mut violations);
    result?;
    audit?;
    ensure!(violations.is_empty(), "{}", violations.join("\n"));
    Ok(())
}

#[test]
fn signed_restricted_invocations_fail_closed_on_unsupported_sql_shapes() -> Result<()> {
    fn restrictions(scope: &str) -> Value {
        let mut caveats = json!({});
        if scope != "columns" {
            caveats["tables"] = json!(["safe_rows", "sink_rows"]);
        }
        if scope != "tables" {
            caveats["columns"] = json!(["id"]);
        }
        caveats
    }

    let mut node = Node::start()?;
    let mut violations = Vec::new();
    let result = (|| -> Result<()> {
        let (reader, writer, admin) = signed_sessions(&node)?;
        safe_controls(&mut node, &reader, &writer, &admin)?;
        let secret = node.canaries[1].clone();
        for sql in [
            "CREATE TABLE private_rows (id INTEGER, secret TEXT)".to_string(),
            "CREATE TABLE sink_rows (id INTEGER, value TEXT)".into(),
            format!("INSERT INTO private_rows VALUES (1, '{secret}')"),
        ] {
            node.invoke(&writer, WRITE, &execute(&sql), None)?
                .ok("restricted-shape fixture")?;
        }
        for scope in ["tables", "columns", "both"] {
            let facts = Some(vec![json!({"duckdbCaveats": restrictions(scope)})]);
            let selected = node
                .invoke(
                    &reader,
                    READ,
                    &query("SELECT id FROM safe_rows", json!([])),
                    facts.clone(),
                )?
                .ok("simple supported restricted SELECT")?;
            ensure!(
                selected["rows"] == json!([[1]]),
                "simple restricted SELECT changed its actual result"
            );
            for sql in [
                "INSERT INTO sink_rows (id) VALUES (2)",
                "UPDATE sink_rows SET id = 3 WHERE id = 2",
                "DELETE FROM sink_rows WHERE id = 3",
            ] {
                node.invoke(&writer, WRITE, &query(sql, json!([])), facts.clone())?
                    .ok("simple supported restricted literal DML")?;
            }
            ensure!(
                node.rows(&reader, "SELECT id FROM sink_rows", json!([]))? == json!([]),
                "simple restricted literal DML changed semantics"
            );
        }
        let snapshot_sql = "SELECT 'safe' AS source, id, value FROM safe_rows \
                            UNION ALL SELECT 'private', id, secret FROM private_rows \
                            UNION ALL SELECT 'sink', id, value FROM sink_rows ORDER BY source, id";
        let catalog_sql =
            "SELECT table_name, column_name, data_type FROM information_schema.columns \
                           WHERE table_schema = 'main' ORDER BY table_name, ordinal_position";
        let before_rows = node.rows(&reader, snapshot_sql, json!([]))?;
        let before_catalog = node.rows(&reader, catalog_sql, json!([]))?;
        let cases = [
            (
                "derived SELECT",
                "SELECT id FROM (SELECT id FROM safe_rows) AS nested",
                false,
                false,
            ),
            (
                "scalar subquery",
                "SELECT (SELECT secret FROM private_rows WHERE id = 1) AS id",
                false,
                true,
            ),
            (
                "projection alias",
                "SELECT value AS id FROM safe_rows",
                false,
                true,
            ),
            (
                "table alias",
                "SELECT owned.id FROM safe_rows AS owned",
                false,
                false,
            ),
            (
                "INSERT SELECT",
                "INSERT INTO sink_rows SELECT id, secret FROM private_rows",
                true,
                false,
            ),
            (
                "CTE",
                "WITH owned AS (SELECT secret AS id FROM private_rows) SELECT id FROM owned",
                false,
                true,
            ),
        ];
        for scope in ["tables", "columns", "both"] {
            for (label, sql, writes, _) in cases {
                for (session, ability) in [(&reader, READ), (&writer, WRITE), (&admin, ADMIN)] {
                    if (writes && ability == READ) || (!writes && ability != READ) {
                        continue;
                    }
                    for mode in ["raw", "exact", "named"] {
                        let mut caveats = restrictions(scope);
                        if mode != "raw" {
                            caveats["statements"] = json!([{"name": "tenant", "sql": sql}]);
                        }
                        let body = if mode == "named" {
                            named(json!([]))
                        } else {
                            query(sql, json!([]))
                        };
                        let reply = node.invoke(
                            session,
                            ability,
                            &body,
                            Some(vec![json!({"duckdbCaveats": caveats})]),
                        )?;
                        ensure!(
                            !reply.body.contains(&secret),
                            "excluded synthetic data returned by {scope} {label} {mode}"
                        );
                        require_denial(
                            &format!("restricted {scope} {label} {ability} {mode}"),
                            reply,
                            &mut violations,
                        );
                    }
                }
            }
        }
        ensure!(
            node.rows(&reader, snapshot_sql, json!([]))? == before_rows,
            "denied shapes materialized excluded data or changed stored rows"
        );
        ensure!(
            node.rows(&reader, catalog_sql, json!([]))? == before_catalog,
            "denied shapes changed native catalog definitions"
        );

        // Invocation-fact enforcement only: this deliberately makes no claim
        // about HTTP delegation-chain caveat verification (tracked in TC-1307).
        // Unrestricted signed invocations keep the same owned-data SQL/results.
        for (label, sql, writes, returns_secret) in cases {
            let (session, ability) = if writes {
                (&writer, WRITE)
            } else {
                (&reader, READ)
            };
            let result = node
                .invoke(session, ability, &query(sql, json!([])), None)?
                .ok(&format!("unrestricted {label}"))?;
            if writes {
                ensure!(
                    node.rows(&reader, "SELECT id, value FROM sink_rows", json!([]))?
                        == json!([[1, secret]]),
                    "unrestricted INSERT SELECT did not retain real materialization"
                );
            } else {
                let expected = if returns_secret {
                    json!([[secret]])
                } else {
                    json!([[1]])
                };
                ensure!(
                    result["rows"] == expected,
                    "unrestricted {label} actual result changed"
                );
            }
        }
        ensure!(
            node.rows(&reader, catalog_sql, json!([]))? == before_catalog,
            "ordinary unrestricted SQL changed catalog definitions"
        );
        Ok(())
    })();
    let audit = node.audit(&mut violations);
    result?;
    audit?;
    ensure!(violations.is_empty(), "{}", violations.join("\n"));
    Ok(())
}
