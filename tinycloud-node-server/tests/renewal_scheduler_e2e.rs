//! Real loopback HTTP and scheduler; no renewal rows or stamps are seeded.
#![cfg(feature = "renewal-test-clock")]
mod common;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
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
use tinycloud_core::{hash::hash, keys::StaticSecret};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn token(
    key: &JWK,
    audience: &str,
    resource: &str,
    ability: &str,
    start: i64,
    end: i64,
) -> Result<String> {
    let did = DID_METHODS
        .generate(key, "key")
        .context("owner DID")?
        .to_string();
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
    .sign(Algorithm::EdDSA, key)?
    .encode()?)
}

fn advance(path: &std::path::Path, now: i64) -> Result<()> {
    let next = path.with_extension("next");
    std::fs::write(&next, now.to_string())?;
    std::fs::rename(next, path)?;
    Ok(())
}

async fn exercise(database: Option<&str>) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let clock = dir.path().join("clock");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    advance(&clock, now)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let data = dir.path().join("data");
    let url = database
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sqlite:{}", data.join("caps.db").display()));
    let config = dir.path().join("tinycloud.toml");
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
database = {url:?}
[default.keys]
type = "static"
secret = "{}"
"#,
            base64::encode_config([0x42; 32], base64::URL_SAFE_NO_PAD)
        ),
    )?;
    let log = std::fs::File::create(dir.path().join("node.log"))?;
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
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("TINYCLOUD_CONFIG_FILE", &config)
            .env("TINYCLOUD_RENEWAL_TEST_CLOCK", &clock)
            .env("ROCKET_LOG_LEVEL", "off")
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let base = format!("http://127.0.0.1:{port}");
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let ready = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(exit) = node.0.try_wait()? {
            anyhow::bail!(
                "node exited {exit}: {}",
                std::fs::read_to_string(dir.path().join("node.log"))?
            );
        }
        if let Ok(response) = client
            .get(format!("{base}/.well-known/tinycloud/node-keys"))
            .send()
            .await
        {
            let keys: Value = response.error_for_status()?.json().await?;
            ensure!(
                keys["nodeDid"] == secret.node_did(),
                "unexpected node identity"
            );
            ensure!(
                keys["renewerDid"] == secret.renewal_did(),
                "unexpected renewer identity"
            );
            ensure!(keys["renewerEpoch"] == 1, "unexpected renewer epoch");
            break;
        }
        ensure!(
            tokio::time::Instant::now() < ready,
            "node readiness timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let key = JWK::generate_ed25519()?;
    let owner = DID_METHODS
        .generate(&key, "key")
        .context("owner DID")?
        .to_string();
    let holder_key = JWK::generate_ed25519()?;
    let holder = DID_METHODS
        .generate(&holder_key, "key")
        .context("holder DID")?
        .to_string();
    let space: SpaceId = format!(
        "tinycloud:{}:scheduler",
        owner.strip_prefix("did:").unwrap()
    )
    .parse()?;
    let resource = space
        .to_resource("kv".parse()?, Some("test".parse()?), None, None)
        .to_string();
    let original = token(
        &key,
        &holder,
        &resource,
        "tinycloud.kv/get",
        now - 1,
        now + 120,
    )?;
    let cid = hash(original.as_bytes()).to_cid(0x55).to_string();
    let lease = token(
        &key,
        &secret.renewal_did(),
        &format!("urn:cid:{cid}"),
        "tinycloud.delegation/renew",
        now - 1,
        now + 240,
    )?;
    let lease_cid = hash(lease.as_bytes()).to_cid(0x55).to_string();
    for signed in [original, lease] {
        let response = client
            .post(format!("{base}/delegate"))
            .header("Authorization", signed)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status.is_success(), "registration {status}: {body}");
    }
    let status = || async {
        let auth = token(
            &holder_key,
            &secret.node_did(),
            &format!("urn:cid:{cid}"),
            "tinycloud.delegation/status",
            now - 1,
            now + 3600,
        )?;
        let response = client
            .post(format!("{base}/delegation/status"))
            .header("Authorization", auth)
            .json(&json!({"cid": cid}))
            .send()
            .await?;
        let code = response.status();
        let body = response.text().await?;
        ensure!(code.is_success(), "status {code}: {body}");
        Ok::<Value, anyhow::Error>(serde_json::from_str(&body)?)
    };
    let initial = status().await?;
    ensure!(
        initial["renewal_history"]
            .as_array()
            .context("history")?
            .is_empty(),
        "unexpected initial stamp: {initial}"
    );
    advance(&clock, now + 75)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let renewed = loop {
        let value = status().await?;
        if !value["renewal_history"]
            .as_array()
            .context("history")?
            .is_empty()
        {
            break value;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "scheduler did not admit stamp: {value}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    ensure!(
        renewed["effective_expiry"] == now + 196,
        "incorrect signed-period extension: {renewed}"
    );
    let stamp = &renewed["renewal_history"][0];
    let bytes = base64::decode_config(
        stamp["signed_bytes"].as_str().context("stamp bytes")?,
        base64::URL_SAFE_NO_PAD,
    )?;
    let signature = base64::decode_config(
        stamp["signature"].as_str().context("stamp signature")?,
        base64::URL_SAFE_NO_PAD,
    )?;
    let public = ed25519_dalek::SigningKey::from_bytes(
        &secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT),
    )
    .verifying_key()
    .to_bytes();
    tinycloud_core::renewal::verify_stamp_signature(&bytes, &signature, &public)?;
    ensure!(
        hash(&bytes).to_cid(0x55).to_string() == stamp["cid"],
        "stamp CID mismatch"
    );
    advance(&clock, now + 122)?;
    let past_original = status().await?;
    ensure!(
        past_original["status"] == "active",
        "original did not survive signed expiry: {past_original}"
    );
    ensure!(
        past_original["effective_expiry"] == renewed["effective_expiry"],
        "unexpected extension before due threshold"
    );
    // At the next due threshold, the signed lease end caps the new stamp.
    advance(&clock, now + 150)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let capped = loop {
        let value = status().await?;
        if value["renewal_history"]
            .as_array()
            .context("history")?
            .len()
            >= 2
        {
            break value;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "second scheduler stamp missing: {value}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    ensure!(
        capped["effective_expiry"] == now + 240,
        "lease did not cap stamp: {capped}"
    );
    ensure!(
        capped["status"] == "active",
        "holder authority is not active: {capped}"
    );
    if let Some(directory) = std::env::var_os("TINYCLOUD_HISTORY_SDK_FIXTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory)?;
        let fixture = json!({
            "input": {"originalCid": cid, "leaseCid": lease_cid, "leaseExpiresAt": now + 240,
                "now": now + 150, "history": capped["renewal_history"],
                "nodeIdentity": {"nodeDid": secret.node_did(), "renewerDid": secret.renewal_did(),
                    "renewerPublicKey": base64::encode_config(public, base64::URL_SAFE_NO_PAD), "renewerEpoch": 1}},
            "originalSignedExpiry": now + 120, "expectedExpiry": capped["effective_expiry"]
        });
        let backend = if database.is_some() {
            "postgres"
        } else {
            "sqlite"
        };
        std::fs::write(
            directory.join(format!("{backend}.json")),
            serde_json::to_vec_pretty(&fixture)?,
        )?;
    }
    advance(&clock, now + 241)?;
    // Give the running scheduler another interval after the lease boundary.
    tokio::time::sleep(Duration::from_millis(75)).await;
    let expired = status().await?;
    ensure!(
        expired["status"] == "expired",
        "lease expiry did not end authority: {expired}"
    );
    ensure!(
        expired["renewal_history"] == capped["renewal_history"],
        "scheduler renewed expired lease"
    );
    Ok(())
}

#[tokio::test]
async fn scheduler_renews_over_http_then_lease_expires() -> Result<()> {
    exercise(None).await?;
    eprintln!("renewal scheduler: SQLite HTTP, signed extension, lease cap and expiry PASS");
    if let Some(url) = common::postgres_test_url("scheduler_renews_over_http_then_lease_expires") {
        use tinycloud_core::sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};
        let admin = Database::connect(&url).await?;
        let version = admin
            .query_one(Statement::from_string(
                DatabaseBackend::Postgres,
                "SHOW server_version_num",
            ))
            .await?
            .context("PG version")?
            .try_get::<String>("", "server_version_num")?;
        ensure!(
            version.starts_with("16"),
            "harness requires PostgreSQL 16, got {version}"
        );
        let schema = format!("renewal_scheduler_{}", uuid::Uuid::new_v4().simple());
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await?;
        let mut isolated = reqwest::Url::parse(&url)?;
        isolated
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let result = exercise(Some(isolated.as_str())).await;
        admin
            .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        result?;
        eprintln!("renewal scheduler: PostgreSQL {version} HTTP, signed extension, lease cap and expiry PASS");
    }
    Ok(())
}
