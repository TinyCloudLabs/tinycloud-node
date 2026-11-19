//! Real loopback HTTP and scheduler; no renewal rows or stamps are seeded.
mod common;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tinycloud_auth::{resolver::DID_METHODS, resource::SpaceId, ssi::jwk::JWK};
use tinycloud_core::{hash::hash, keys::StaticSecret};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn owner_key() -> (k256::ecdsa::SigningKey, [u8; 20], String) {
    use sha3::{Digest, Keccak256};
    let key = k256::ecdsa::SigningKey::from_bytes(&[0x11; 32].into()).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
        .try_into()
        .unwrap();
    let did = format!(
        "did:pkh:eip155:1:0x{}",
        tinycloud_auth::cacaos::siwe::encode_eip55(&address)
    );
    (key, address, did)
}

fn token(
    audience: &str,
    resource: &str,
    ability: &str,
    start: i64,
    end: i64,
    millis: u16,
) -> Result<String> {
    use tinycloud_auth::{
        authorization::{HeaderEncode, TinyCloudDelegation},
        cacaos::{
            siwe::{Message, Version},
            siwe_cacao::{Header, Signature, SiweCacao},
        },
        siwe_recap::Capability,
    };
    let (key, address, _) = owner_key();
    let timestamp = |seconds: i64, milliseconds: u16| -> Result<String> {
        Ok(time::OffsetDateTime::from_unix_timestamp(seconds)?
            .replace_millisecond(milliseconds)?
            .format(&time::format_description::well_known::Rfc3339)?)
    };
    let message = Message {
        scheme: Some("https".parse()?),
        domain: "renewal-precision.invalid".parse()?,
        address,
        statement: None,
        uri: audience.parse()?,
        version: Version::V1,
        chain_id: 1,
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        issued_at: timestamp(start, 366)?.parse()?,
        expiration_time: Some(timestamp(end, millis)?.parse()?),
        not_before: None,
        request_id: None,
        resources: vec![],
    };
    let mut caps = Capability::<Value>::new();
    caps.with_action(resource.parse()?, ability.parse()?, [BTreeMap::new()]);
    let message = caps.build_message(message)?;
    let (signature, recovery) = key.sign_prehash_recoverable(&message.eip191_hash()?)?;
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    bytes[64] = u8::from(recovery) + 27;
    Ok(TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
        message.into(),
        Signature::from(bytes),
        Header,
    )))
    .encode()?)
}

fn status_token(key: &JWK, audience: &str, cid: &str, now: i64) -> Result<String> {
    use tinycloud_auth::{
        ssi::{claims::jwt::NumericDate, jwk::Algorithm, ucan::Payload},
        ucan_capabilities_object::Capabilities,
    };
    let did = DID_METHODS
        .generate(key, "key")
        .context("holder DID")?
        .to_string();
    let method = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(
        format!("urn:cid:{cid}").parse()?,
        "tinycloud.delegation/status".parse()?,
        [BTreeMap::new()],
    );
    Ok(Payload::<Value> {
        issuer: method.parse()?,
        audience: audience.parse()?,
        not_before: Some(NumericDate::try_from_seconds((now - 1) as f64)?),
        expiration: NumericDate::try_from_seconds((now + 3600) as f64)?,
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)?
    .encode()?)
}

fn cid(token: &str) -> Result<String> {
    let event = tinycloud_core::events::Delegation::from_header_ser::<
        tinycloud_auth::authorization::TinyCloudDelegation,
    >(token)
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(hash(event.serialized_bytes()).to_cid(0x55).to_string())
}

async fn exercise(database: Option<&str>) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
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
    let start_node = || -> Result<Node> {
        let log = std::fs::File::create(dir.path().join("node.log"))?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("TINYCLOUD_")
                || name.to_string_lossy().starts_with("ROCKET_")
            {
                command.env_remove(name);
            }
        }
        Ok(Node(
            command
                .current_dir(dir.path())
                .env("HOME", dir.path())
                .env("TINYCLOUD_CONFIG_FILE", &config)
                .env("ROCKET_LOG_LEVEL", "off")
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        ))
    };
    let mut node = start_node()?;
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
    let (_, _, owner) = owner_key();
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
        &holder,
        &resource,
        "tinycloud.kv/get",
        now - 150,
        now + 90,
        366,
    )?;
    let cid = cid(&original)?;
    let lease = token(
        &secret.renewal_did(),
        &format!("urn:cid:{cid}"),
        "tinycloud.delegation/renew",
        now - 1,
        now + 100,
        999,
    )?;
    let lease_cid = self::cid(&lease)?;
    for signed in [original, lease.clone()] {
        let response = client
            .post(format!("{base}/delegate"))
            .header("Authorization", signed)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status.is_success(), "registration {status}: {body}");
    }
    use tinycloud_core::sea_orm::{ConnectionTrait, Database, Statement};
    let inspect = Database::connect(&url).await?;
    let expiries = inspect
        .query_all(Statement::from_string(
            inspect.get_database_backend(),
            "SELECT expiry FROM delegation",
        ))
        .await?;
    let fractions = expiries
        .iter()
        .map(|row| {
            row.try_get::<time::OffsetDateTime>("", "expiry")
                .map(|value| value.millisecond())
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        fractions.contains(&366) && fractions.contains(&999),
        "signed delegation expiries lost milliseconds: {fractions:?}"
    );
    let stored = inspect
        .query_one(Statement::from_string(
            inspect.get_database_backend(),
            "SELECT original_expiry,lease_expiry FROM renewal_lease",
        ))
        .await?
        .context("registered lease")?;
    for column in ["original_expiry", "lease_expiry"] {
        ensure!(
            stored
                .try_get::<time::OffsetDateTime>("", column)?
                .nanosecond()
                == 0,
            "renewal time not stored at second precision"
        );
    }
    // Same storage and identity; the unmodified startup scheduler now sees the lease.
    drop(node);
    node = start_node()?;
    let status = || async {
        let auth = status_token(&holder_key, &secret.node_did(), &cid, now)?;
        let response = client
            .post(format!("{base}/delegation/status"))
            .header("Authorization", auth)
            .json(&json!({"cid":cid}))
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "status response {}",
            response.status()
        );
        Ok::<Value, anyhow::Error>(response.json().await?)
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let rows = loop {
        if let Some(exit) = node.0.try_wait()? {
            anyhow::bail!("restarted node exited {exit}");
        }
        let rows = inspect
            .query_all(Statement::from_string(
                inspect.get_database_backend(),
                "SELECT lease_cid,new_end,signed_bytes,signature FROM renewal_stamp",
            ))
            .await?;
        if !rows.is_empty() {
            break rows;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "no scheduler stamp for millisecond expiries"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    ensure!(rows.len() == 1, "unexpected stamp count");
    let end: time::OffsetDateTime = rows[0].try_get("", "new_end")?;
    ensure!(
        end.unix_timestamp() == now + 100 && end.nanosecond() == 0,
        ".999 lease must cap at earlier whole second"
    );
    let stored_lease: Vec<u8> = rows[0].try_get("", "lease_cid")?;
    ensure!(
        tinycloud_core::hash::Hash::try_from(stored_lease)?
            .to_cid(0x55)
            .to_string()
            == lease_cid,
        "wrong lease"
    );
    let bytes: Vec<u8> = rows[0].try_get("", "signed_bytes")?;
    let signature: Vec<u8> = rows[0].try_get("", "signature")?;
    let signed: Value = serde_ipld_dagcbor::from_slice(&bytes)?;
    let signed_end = time::OffsetDateTime::parse(
        signed["unsigned"]["newEnd"]
            .as_str()
            .context("signed newEnd")?,
        &time::format_description::well_known::Rfc3339,
    )?;
    ensure!(
        signed_end == end,
        "signed stamp must use the same earlier whole-second cap"
    );

    let signing = ed25519_dalek::SigningKey::from_bytes(
        &secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT),
    );
    tinycloud_core::renewal::verify_stamp_signature(
        &bytes,
        &signature,
        &signing.verifying_key().to_bytes(),
    )?;
    let renewed = status().await?;
    ensure!(renewed["status"] == "active", "{renewed}");
    ensure!(
        renewed["effective_expiry"] == now + 100,
        "status did not use floored cap: {renewed}"
    );
    // Re-registering the same signed lease compares its timestamps at stored precision too.
    let repeated = client
        .post(format!("{base}/delegate"))
        .header("Authorization", lease)
        .send()
        .await?;
    ensure!(
        repeated.status().is_success(),
        "millisecond lease re-registration {}: {}",
        repeated.status(),
        repeated.text().await?
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_scheduler_renews_millisecond_siwe_and_floors_lease_cap() -> Result<()> {
    exercise(None).await?;
    eprintln!("renewal scheduler: SQLite HTTP, millisecond SIWE registration, scheduler and .999 lease cap PASS");
    Ok(())
}

#[tokio::test]
async fn postgres_scheduler_renews_millisecond_siwe_and_floors_lease_cap() -> Result<()> {
    if let Some(url) =
        common::postgres_test_url("scheduler_renews_millisecond_siwe_and_floors_lease_cap")
    {
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
        eprintln!("renewal scheduler: PostgreSQL {version} HTTP, millisecond SIWE registration, scheduler and .999 lease cap PASS");
    }
    Ok(())
}
