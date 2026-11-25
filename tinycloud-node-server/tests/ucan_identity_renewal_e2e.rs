//! TC-4366: a high-S ES256 original whose lease and stamps were stored under
//! the old identity rule keeps renewing after the node restarts on the new
//! rule (the boot step re-keys its alias). Real binary, loopback HTTP and the
//! renewal scheduler on the test clock; no renewal rows are seeded.
#![cfg(feature = "renewal-test-clock")]

use anyhow::{ensure, Context, Result};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tinycloud_auth::{
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::hash,
    keys::StaticSecret,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
};

/// Group order of P-256, big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// The high-S encoding of a P-256 `token`: same header, payload and `r`, and
/// whichever of `s`, `n - s` is the larger.
fn high_s(token: &str) -> String {
    let (signed, signature) = token.rsplit_once('.').expect("JWS");
    let signature = decode_config(signature, URL_SAFE_NO_PAD).expect("base64url signature");
    assert_eq!(signature.len(), 64, "r || s");
    let mut other = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = i16::from(P256_ORDER[i]) - i16::from(signature[32 + i]) - borrow;
        borrow = i16::from(digit < 0);
        if digit < 0 {
            digit += 256;
        }
        other[i] = digit as u8;
    }
    let mut high = signature.clone();
    if signature[32..] < other[..] {
        high[32..].copy_from_slice(&other);
    }
    format!("{signed}.{}", encode_config(high, URL_SAFE_NO_PAD))
}

fn key_did(key: &JWK) -> Result<String> {
    Ok(DID_METHODS.generate(key, "key").context("DID")?.to_string())
}

fn token(
    key: &JWK,
    audience: &str,
    resource: &str,
    ability: &str,
    start: i64,
    end: i64,
) -> Result<String> {
    let did = key_did(key)?;
    let method = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(resource.parse()?, ability.parse()?, [BTreeMap::new()]);
    Ok(Payload::<Value> {
        issuer: method.parse()?,
        audience: audience.parse()?,
        not_before: Some(NumericDate::try_from_seconds(start as f64)?),
        expiration: NumericDate::try_from_seconds(end as f64)?,
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(key.get_algorithm().unwrap_or(Algorithm::EdDSA), key)?
    .encode()?)
}

fn advance(path: &Path, now: i64) -> Result<()> {
    let next = path.with_extension("next");
    std::fs::write(&next, now.to_string())?;
    std::fs::rename(next, path)?;
    Ok(())
}

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A node on `dir`'s data and test clock. Each start uses a fresh port.
struct Running {
    _node: Node,
    client: reqwest::Client,
    base: String,
}

async fn start(dir: &Path, clock: &Path) -> Result<Running> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let data = dir.join("data");
    let config = dir.join("tinycloud.toml");
    std::fs::write(
        &config,
        format!(
            r#"[default]
address = "127.0.0.1"
port = {port}
[default.telemetry]
enabled = false
[default.storage]
datadir = {data:?}
database = {:?}
[default.keys]
type = "static"
secret = "{}"
"#,
            database_url(dir),
            encode_config([0x42; 32], URL_SAFE_NO_PAD)
        ),
    )?;
    let log_path = dir.join("node.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("TINYCLOUD_")
            || name.to_string_lossy().starts_with("ROCKET_")
        {
            command.env_remove(name);
        }
    }
    let mut node = Node(
        command
            .current_dir(dir)
            .env("HOME", dir)
            .env("TINYCLOUD_CONFIG_FILE", &config)
            .env("TINYCLOUD_RENEWAL_TEST_CLOCK", clock)
            .env("ROCKET_LOG_LEVEL", "off")
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let base = format!("http://127.0.0.1:{port}");
    let ready = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(exit) = node.0.try_wait()? {
            anyhow::bail!(
                "node exited {exit}: {}",
                std::fs::read_to_string(&log_path)?
            );
        }
        if let Ok(response) = client
            .get(format!("{base}/.well-known/tinycloud/node-keys"))
            .send()
            .await
        {
            response.error_for_status()?;
            break;
        }
        ensure!(
            tokio::time::Instant::now() < ready,
            "node readiness timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(Running {
        _node: node,
        client,
        base,
    })
}

fn database_url(dir: &Path) -> String {
    format!("sqlite:{}", dir.join("data").join("caps.db").display())
}

impl Running {
    async fn register(&self, signed: String) -> Result<String> {
        let cid = hash(signed.as_bytes()).to_cid(0x55).to_string();
        let response = self
            .client
            .post(format!("{}/delegate", self.base))
            .header("Authorization", signed)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status.is_success(), "/delegate {status}: {body}");
        Ok(cid)
    }

    /// `delegation/status` of `cid`, asked by its holder.
    async fn status(&self, grant: &Grant) -> Result<Value> {
        let auth = token(
            &grant.holder,
            &grant.node_did,
            &format!("urn:cid:{}", grant.cid),
            "tinycloud.delegation/status",
            grant.now - 1,
            grant.now + 3600,
        )?;
        let response = self
            .client
            .post(format!("{}/delegation/status", self.base))
            .header("Authorization", auth)
            .json(&json!({ "cid": grant.cid }))
            .send()
            .await?;
        let code = response.status();
        let body = response.text().await?;
        ensure!(code.is_success(), "status {code}: {body}");
        Ok(serde_json::from_str(&body)?)
    }

    /// Advance the clock to `at` and wait for `count` stamps in the history.
    async fn stamps(&self, clock: &Path, at: i64, count: usize, grant: &Grant) -> Result<Value> {
        advance(clock, at)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let value = self.status(grant).await?;
            let stamps = value["renewal_history"]
                .as_array()
                .context("history")?
                .len();
            if stamps >= count {
                return Ok(value);
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "scheduler did not admit stamp {count}: {value}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

/// The renewed original, its holder, and what a status request needs.
struct Grant {
    holder: JWK,
    cid: String,
    node_did: String,
    now: i64,
}

async fn alias(dir: &Path, id: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let db = Database::connect(database_url(dir)).await?;
    let id: tinycloud_auth::ipld_core::cid::Cid = id.parse()?;
    let id = Vec::<u8>::from(tinycloud_core::hash::Hash::from(id));
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT id, canonical FROM delegation_cid_alias WHERE id = $1",
            [id.into()],
        ))
        .await?
        .context("alias row")?;
    Ok((row.try_get("", "id")?, row.try_get("", "canonical")?))
}

#[tokio::test]
async fn a_high_s_original_renewed_under_the_old_rule_still_renews_after_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let clock: PathBuf = dir.path().join("clock");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    advance(&clock, now)?;
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let node_did = secret.node_did();

    let owner = JWK::generate_p256();
    let holder = JWK::generate_ed25519()?;
    let space: SpaceId = format!(
        "tinycloud:{}:renewal",
        key_did(&owner)?.strip_prefix("did:").unwrap()
    )
    .parse()?;
    let resource = space
        .to_resource("kv".parse()?, Some("test".parse()?), None, None)
        .to_string();

    let node = start(dir.path(), &clock).await?;
    let original = high_s(&token(
        &owner,
        &key_did(&holder)?,
        &resource,
        "tinycloud.kv/get",
        now - 1,
        now + 120,
    )?);
    let cid = node.register(original).await?;
    node.register(token(
        &owner,
        &secret.renewal_did(),
        &format!("urn:cid:{cid}"),
        "tinycloud.delegation/renew",
        now - 1,
        now + 240,
    )?)
    .await?;
    let grant = Grant {
        holder,
        cid: cid.clone(),
        node_did,
        now,
    };
    let first = node.stamps(&clock, now + 75, 1, &grant).await?;
    ensure!(
        first["effective_expiry"] == now + 196,
        "unexpected first extension: {first}"
    );
    drop(node);

    // The database as the older image left it: the original's alias is its
    // own id and the new rule was never applied.
    let (id, canonical) = alias(dir.path(), &cid).await?;
    ensure!(canonical != id, "the new rule re-keys a high-S alias");
    {
        let db = Database::connect(database_url(dir.path())).await?;
        db.execute_unprepared("UPDATE delegation_cid_alias SET canonical = id")
            .await?;
        db.execute_unprepared("DELETE FROM delegation_cid_alias_rule")
            .await?;
    }
    ensure!(alias(dir.path(), &cid).await?.1 == id, "older-image alias");

    let node = start(dir.path(), &clock).await?;
    ensure!(
        alias(dir.path(), &cid).await?.1 == canonical,
        "the restart re-keyed the alias before serving"
    );
    let second = node.stamps(&clock, now + 150, 2, &grant).await?;
    ensure!(
        second["effective_expiry"] == now + 240,
        "the original renewed to its lease end after the restart: {second}"
    );
    Ok(())
}
