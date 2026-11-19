//! TC-3035: a `read_only` caveat holds for the DuckDB admin tier through the
//! real binary. An admin session prepares a write without the caveat; with
//! `readOnly: true` the same session can't run it, nor write any other way.
//!
//! Run with `cargo test -p tinycloud-node --features duckdb --test
//! duckdb_read_only_admin -- --nocapture`. Synthetic identity and keys; every
//! request goes to this test's loopback child.
#![cfg(feature = "duckdb")]

use std::{
    collections::HashMap,
    net::TcpListener,
    path::Path as FsPath,
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
    session::{complete_session_setup, prepare_session, SessionConfig, SignedSession},
};

const DATABASE: &str = "readonly";
// Public synthetic test material, never a deployment credential.
const STATIC_SECRET: &str = "dGMzMDM1X3N5bnRoZXRpY19ub2RlX2tleV9tYXRlcmlhbF9vbmx5";
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
        let key = SigningKey::from_bytes(&[0x35; 32].into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address: [u8; 20] = digest[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", eip55(&address));
        let space = SpaceId::new(did.parse::<DIDBuf>()?, "tc3035".parse()?)?;
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
        .env("TINYCLOUD_CONFIG_FILE", root.join("tinycloud.toml"))
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", port.to_string())
        .env("TINYCLOUD_PROMETHEUS__PORT", metrics_port.to_string())
        .env("TINYCLOUD_STORAGE__DATADIR", root.join("data"))
        .env("TINYCLOUD_KEYS__TYPE", "static")
        .env("TINYCLOUD_KEYS__SECRET", STATIC_SECRET)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

struct Node {
    directory: tempfile::TempDir,
    server: Child,
    client: Client,
    base: String,
}

#[derive(Debug)]
struct Reply {
    status: StatusCode,
    body: String,
}

impl Node {
    fn start() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for path in ["home", "tmp"] {
            std::fs::create_dir_all(root.join(path))?;
        }
        std::fs::write(
            root.join("tinycloud.toml"),
            "[global]\nlog_level = 'normal'\n",
        )?;
        let port = free_port()?;
        let server = child_command(root, port, free_port()?).spawn()?;
        let mut node = Self {
            directory,
            server,
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .build()?,
            base: format!("http://127.0.0.1:{port}"),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            ensure!(
                node.server.try_wait()?.is_none(),
                "node exited before health check"
            );
            if let Ok(reply) = node.client.get(format!("{}/healthz", node.base)).send() {
                if reply.status().is_success() {
                    return Ok(node);
                }
            }
            ensure!(Instant::now() < deadline, "node did not become healthy");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn delegate(&self, header: String) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/delegate", self.base))
            .header("Authorization", header)
            .send()?;
        ensure!(
            response.status() == StatusCode::OK,
            "SDK /delegate: {}",
            response.text()?
        );
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

    fn admin_session(&self, account: &Account) -> Result<tinycloud_sdk_wasm::session::Session> {
        let now = time::OffsetDateTime::now_utc();
        let session_key = ed25519_dalek::SigningKey::from_bytes(&[0x36; 32]);
        let jwk = serde_json::from_value(json!({
            "kty": "OKP", "crv": "Ed25519",
            "d": base64::encode_config(session_key.to_bytes(), base64::URL_SAFE_NO_PAD),
            "x": base64::encode_config(session_key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD)
        }))?;
        let prepared = prepare_session(SessionConfig {
            abilities: HashMap::from([(
                "duckdb".parse()?,
                HashMap::from([(DATABASE.parse()?, vec![ADMIN.parse()?])]),
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

    /// One admin `/invoke`, with `readOnly: true` in the signed facts when
    /// `read_only` is set.
    fn invoke(
        &self,
        session: &tinycloud_sdk_wasm::session::Session,
        read_only: bool,
        body: &Value,
    ) -> Result<Reply> {
        let facts = read_only.then(|| vec![json!({"duckdbCaveats": {"readOnly": true}})]);
        let header = session
            .invoke(
                [(
                    "duckdb".parse::<Service>()?,
                    DATABASE.parse::<Path>()?,
                    None,
                    None,
                    [ADMIN.parse::<Ability>()?],
                )],
                facts,
            )?
            .encode()?;
        let response = self
            .client
            .post(format!("{}/invoke", self.base))
            .header("Authorization", header)
            .json(body)
            .send()?;
        Ok(Reply {
            status: response.status(),
            body: response.text()?,
        })
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

fn execute(sql: &str) -> Value {
    json!({"action": "execute", "sql": sql, "params": []})
}

fn query(sql: &str) -> Value {
    json!({"action": "query", "sql": sql, "params": []})
}

fn rows(node: &Node, session: &tinycloud_sdk_wasm::session::Session) -> Result<Value> {
    let reply = node.invoke(session, true, &query("SELECT id FROM t ORDER BY id"))?;
    ensure!(
        reply.status == StatusCode::OK,
        "read-only SELECT: {reply:?}"
    );
    Ok(serde_json::from_str::<Value>(&reply.body)?["rows"].clone())
}

#[test]
fn read_only_admin_cannot_write_through_prepared_files_settings_or_batches() -> Result<()> {
    let node = Node::start()?;
    let account = Account::synthetic()?;
    node.host(&account)?;
    let admin = node.admin_session(&account)?;

    // Without the caveat: a table with one row, and a prepared write on the
    // database's connection that the read-only invocations below try to run.
    for sql in [
        "CREATE TABLE t (id INTEGER)",
        "INSERT INTO t VALUES (1)",
        "PREPARE p AS INSERT INTO t VALUES (2)",
    ] {
        let reply = node.invoke(&admin, false, &execute(sql))?;
        ensure!(reply.status == StatusCode::OK, "{sql}: {reply:?}");
    }
    ensure!(rows(&node, &admin)? == json!([[1]]), "fixture rows");

    let dir = node.directory.path().join("tmp");
    let file = |name: &str| dir.join(name).display().to_string();
    let refused = [
        "EXECUTE p".to_string(),
        "PREPARE q AS INSERT INTO t VALUES (3)".to_string(),
        "DEALLOCATE p".to_string(),
        "INSERT INTO t VALUES (3)".to_string(),
        "TRUNCATE t".to_string(),
        "CREATE SCHEMA s".to_string(),
        format!("COPY t TO '{}'", file("leak.csv")),
        format!("ATTACH '{}' AS other", file("other.duckdb")),
        "PRAGMA threads = 1".to_string(),
        "SET threads = 1".to_string(),
        "SELECT 1; EXECUTE p".to_string(),
        "SELECT 1; INSERT INTO t VALUES (3)".to_string(),
    ];
    for sql in &refused {
        let reply = node.invoke(&admin, true, &execute(sql))?;
        println!("readOnly admin {sql:?} -> {} {}", reply.status, reply.body);
        ensure!(
            reply.status == StatusCode::FORBIDDEN && reply.body.contains("Read-only violation"),
            "{sql}: expected a read-only violation, got {reply:?}"
        );
    }
    for name in ["leak.csv", "other.duckdb"] {
        ensure!(!dir.join(name).exists(), "{name} was created");
    }
    ensure!(
        rows(&node, &admin)? == json!([[1]]),
        "refused statements changed the data"
    );

    // Control: the prepared write was there to run. Without the caveat it
    // runs, so the refusal above is the caveat's.
    let reply = node.invoke(&admin, false, &execute("EXECUTE p"))?;
    ensure!(reply.status == StatusCode::OK, "EXECUTE p: {reply:?}");
    let after = rows(&node, &admin)?;
    println!("rows after unrestricted EXECUTE p: {after}");
    ensure!(after == json!([[1], [2]]), "control EXECUTE p: {after}");
    Ok(())
}
