//! Node-wide renewal STOP-ALL switch over real loopback HTTP and the real
//! scheduler: admin auth, registration while paused, no stamps or scheduler
//! warnings while paused, persistence across a restart, renewal on resume.
#![cfg(feature = "renewal-test-clock")]
mod common;

use anyhow::{ensure, Context, Result};
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
use tinycloud_core::{hash::hash, keys::StaticSecret};

const ADMIN_SECRET: &str = "stop-all-test-admin-secret-6f1d2c9a";

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

fn advance(path: &Path, now: i64) -> Result<()> {
    let next = path.with_extension("next");
    std::fs::write(&next, now.to_string())?;
    std::fs::rename(next, path)?;
    Ok(())
}

struct Harness {
    dir: tempfile::TempDir,
    config: PathBuf,
    clock: PathBuf,
    log: PathBuf,
    base: String,
    client: reqwest::Client,
}

impl Harness {
    fn new(database: Option<&str>, now: i64) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let clock = dir.path().join("clock");
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
        let log = dir.path().join("node.log");
        Ok(Self {
            dir,
            config,
            clock,
            log,
            base: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
        })
    }

    async fn start(&self) -> Result<Node> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)?;
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
                .current_dir(self.dir.path())
                .env("HOME", self.dir.path())
                .env("TINYCLOUD_CONFIG_FILE", &self.config)
                .env("TINYCLOUD_RENEWAL_TEST_CLOCK", &self.clock)
                .env("TINYCLOUD_ADMIN_SECRET", ADMIN_SECRET)
                .env("ROCKET_LOG_LEVEL", "off")
                // Warnings on, so "no scheduler warning while paused" is observable.
                .env("RUST_LOG", "warn")
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        );
        let ready = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(exit) = node.0.try_wait()? {
                anyhow::bail!("node exited {exit}: {}", self.logs()?);
            }
            if let Ok(response) = self
                .client
                .get(format!("{}/.well-known/tinycloud/node-keys", self.base))
                .send()
                .await
            {
                response.error_for_status()?;
                return Ok(node);
            }
            ensure!(
                tokio::time::Instant::now() < ready,
                "node readiness timed out"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn logs(&self) -> Result<String> {
        Ok(std::fs::read_to_string(&self.log)?)
    }

    async fn switch(&self, bearer: Option<&str>, paused: Option<bool>) -> Result<(u16, String)> {
        let url = format!("{}/admin/renewals", self.base);
        let mut request = match paused {
            Some(paused) => self.client.put(url).json(&json!({ "paused": paused })),
            None => self.client.get(url),
        };
        if let Some(bearer) = bearer {
            request = request.header("Authorization", format!("Bearer {bearer}"));
        }
        let response = request.send().await?;
        Ok((response.status().as_u16(), response.text().await?))
    }

    async fn switch_state(&self) -> Result<Value> {
        let (code, body) = self.switch(Some(ADMIN_SECRET), None).await?;
        ensure!(code == 200, "switch read {code}: {body}");
        Ok(serde_json::from_str(&body)?)
    }

    async fn set_paused(&self, paused: bool) -> Result<Value> {
        let (code, body) = self.switch(Some(ADMIN_SECRET), Some(paused)).await?;
        ensure!(code == 200, "switch set {code}: {body}");
        let state: Value = serde_json::from_str(&body)?;
        ensure!(state["paused"] == paused, "switch did not apply: {state}");
        Ok(state)
    }
}

async fn exercise(database: Option<&str>) -> Result<()> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let harness = Harness::new(database, now)?;
    let node = harness.start().await?;
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();

    // Admin auth: no secret or a wrong one is refused and changes nothing.
    for bearer in [None, Some("not-the-admin-secret")] {
        for paused in [None, Some(true)] {
            let (code, body) = harness.switch(bearer, paused).await?;
            ensure!(
                code == 401,
                "unauthorized switch call answered {code}: {body}"
            );
        }
    }
    let initial = harness.switch_state().await?;
    ensure!(
        initial == json!({"paused": false, "changedAt": null}),
        "fresh node is not running renewals: {initial}"
    );
    harness.set_paused(true).await?;

    // Registration is unchanged while paused.
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
    let space: SpaceId =
        format!("tinycloud:{}:stopall", owner.strip_prefix("did:").unwrap()).parse()?;
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
    for signed in [original, lease] {
        let response = harness
            .client
            .post(format!("{}/delegate", harness.base))
            .header("Authorization", signed)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(
            status.is_success(),
            "registration while paused {status}: {body}"
        );
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
        let response = harness
            .client
            .post(format!("{}/delegation/status", harness.base))
            .header("Authorization", auth)
            .json(&json!({"cid": cid}))
            .send()
            .await?;
        let code = response.status();
        let body = response.text().await?;
        ensure!(code.is_success(), "status {code}: {body}");
        Ok::<Value, anyhow::Error>(serde_json::from_str(&body)?)
    };
    let no_stamps = |value: &Value| {
        value["renewal_history"]
            .as_array()
            .is_some_and(|history| history.is_empty())
    };

    // Due for renewal, but paused: many 25 ms ticks issue nothing.
    advance(&harness.clock, now + 75)?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let paused = status().await?;
    ensure!(no_stamps(&paused), "stamp issued while paused: {paused}");
    ensure!(
        paused["effective_expiry"] == now + 120,
        "paused grant end moved: {paused}"
    );

    // The pause is persisted: it survives a restart.
    drop(node);
    let node = harness.start().await?;
    ensure!(
        harness.switch_state().await?["paused"] == true,
        "pause lost across restart"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let restarted = status().await?;
    ensure!(
        no_stamps(&restarted),
        "stamp issued after restart while paused: {restarted}"
    );

    // Paused ticks log nothing; only the flip itself is logged.
    let logs = harness.logs()?;
    ensure!(
        logs.contains("renewals paused node-wide"),
        "pause audit line missing: {logs}"
    );
    ensure!(
        logs.lines()
            .filter(|line| line.contains("renewal_scheduler"))
            .all(|line| line.contains("renewal_scheduler_switch")),
        "paused ticks logged warnings: {logs}"
    );

    // Resume: the next tick renews the still-live grant without re-consent.
    harness.set_paused(false).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let renewed = loop {
        let value = status().await?;
        if !no_stamps(&value) {
            break value;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "scheduler did not stamp after resume: {value}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    ensure!(
        renewed["effective_expiry"] == now + 196,
        "incorrect extension after resume: {renewed}"
    );
    ensure!(
        harness.logs()?.contains("renewals resumed node-wide"),
        "resume audit line missing"
    );
    drop(node);
    Ok(())
}

#[tokio::test]
async fn stop_all_pauses_renewals_until_resumed() -> Result<()> {
    exercise(None).await?;
    eprintln!("renewal stop-all: SQLite PASS");
    if let Some(url) = common::postgres_test_url("stop_all_pauses_renewals_until_resumed") {
        use tinycloud_core::sea_orm::{ConnectionTrait, Database};
        let admin = Database::connect(&url).await?;
        let schema = format!("renewal_stop_all_{}", uuid::Uuid::new_v4().simple());
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
        eprintln!("renewal stop-all: PostgreSQL PASS");
    }
    Ok(())
}
