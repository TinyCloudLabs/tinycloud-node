//! TC-887 S0: at-rest checks against the native harness in
//! `scripts/at-rest-harness/` (a real `tinycloud` binary on native PostgreSQL
//! and native MinIO). Every test is `#[ignore]`d: they need the harness up and
//! are run through `scripts/at-rest-harness/harness.sh test green|red`, which
//! sets `TC887_HARNESS_STATE` and refuses a zero-test run.
//!
//! - `green_*` prove the harness is live: an SDK-signed write through the
//!   node's public API lands in MinIO / `database_artifact`. They stay green
//!   before and after encryption, so a RED result is never a harness no-op.
//! - `red_*` assert the TC-887 at-rest property on the raw stored bytes. They
//!   FAIL today (plaintext at rest) and turn green with slices S3 (KV) and S4
//!   (SQL).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tinycloud_auth::{
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::Signature,
    },
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::dids::DIDBuf,
};
use tinycloud_core::models::database_artifact;
use tinycloud_core::sea_orm::{
    ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter,
};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const SQL_DATABASE: &str = "tc887";
const KV_PUT: &str = "tinycloud.kv/put";
const KV_GET: &str = "tinycloud.kv/get";
const SQL_ADMIN: &str = "tinycloud.sql/admin";

/// The running harness, from the state file `harness.sh up` wrote.
struct Harness {
    node: String,
    http: Client,
    s3: aws_sdk_s3::Client,
    bucket: String,
    pg: DatabaseConnection,
}

impl Harness {
    async fn connect() -> Result<Self> {
        let path = std::env::var("TC887_HARNESS_STATE").context(
            "TC887_HARNESS_STATE is unset: start the harness with \
             `scripts/at-rest-harness/harness.sh up` and run these checks with \
             `scripts/at-rest-harness/harness.sh test green|red`",
        )?;
        let state: Value = serde_json::from_slice(
            &std::fs::read(&path).with_context(|| format!("read harness state {path}"))?,
        )?;
        ensure!(state["status"] == "up", "harness at {path} is not up");
        let env_file = state["env_file"]
            .as_str()
            .context("state file has no env_file")?;
        let env: HashMap<String, String> = std::fs::read_to_string(env_file)
            .with_context(|| format!("read harness env file {env_file}"))?
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        let var = |key: &str| {
            env.get(key)
                .cloned()
                .with_context(|| format!("{key} missing from harness env file"))
        };

        let sdk = aws_config::from_env()
            .region(aws_sdk_s3::Region::new(var("TC887_S3_REGION")?))
            .credentials_provider(aws_sdk_s3::Credentials::new(
                var("TC887_S3_ACCESS_KEY_ID")?,
                var("TC887_S3_SECRET_ACCESS_KEY")?,
                None,
                None,
                "tc887-harness",
            ))
            .load()
            .await;
        let endpoint: rocket::http::hyper::Uri = var("TC887_S3_ENDPOINT")?.parse()?;
        let s3 = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::from(&sdk)
                .endpoint_resolver(aws_sdk_s3::Endpoint::immutable(endpoint))
                .build(),
        );
        let pg = Database::connect(var("TC887_PG_URL")?)
            .await
            .context("connect to the harness PostgreSQL")?;
        Ok(Self {
            node: var("TC887_NODE_URL")?,
            http: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(60))
                .build()?,
            s3,
            bucket: var("TC887_S3_BUCKET")?,
            pg,
        })
    }

    /// Every object in the harness bucket, raw bytes as MinIO stores them.
    async fn objects(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut objects = BTreeMap::new();
        let mut token = None;
        loop {
            let page = self
                .s3
                .list_objects_v2()
                .bucket(&self.bucket)
                .set_continuation_token(token)
                .send()
                .await
                .context("list the harness bucket")?;
            for object in page.contents().unwrap_or_default() {
                let key = object.key().context("object without key")?.to_owned();
                let body = self
                    .s3
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send()
                    .await
                    .with_context(|| format!("GET raw object {key}"))?
                    .body
                    .collect()
                    .await?
                    .into_bytes()
                    .to_vec();
                objects.insert(key, body);
            }
            if !page.is_truncated() {
                return Ok(objects);
            }
            token = page.next_continuation_token().map(str::to_owned);
        }
    }

    async fn delegate(&self, authorization: String) -> Result<()> {
        let response = self
            .http
            .post(format!("{}/delegate", self.node))
            .header("Authorization", authorization)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status == StatusCode::OK, "/delegate: {status} {body}");
        Ok(())
    }

    /// Host a fresh space and open an SDK session on it, the way the SDK's
    /// `signIn` does: host SIWE delegation to the node's peer, then a session
    /// delegation to an ephemeral Ed25519 key.
    async fn sign_in(&self) -> Result<(Account, Session)> {
        let account = Account::random()?;
        let response = self
            .http
            .get(format!("{}/peer/generate/{}", self.node, account.space))
            .send()
            .await?;
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
            peer_id: response.text().await?,
        })?;
        let signature = account.sign(&host)?;
        self.delegate(authorization(&siwe_to_delegation_headers(SignedMessage {
            siwe: host,
            signature,
        }))?)
        .await?;

        let now = time::OffsetDateTime::now_utc();
        let session_key = ed25519_dalek::SigningKey::from_bytes(&uuid_seed());
        let jwk = serde_json::from_value(json!({
            "kty": "OKP", "crv": "Ed25519",
            "d": base64::encode_config(session_key.to_bytes(), base64::URL_SAFE_NO_PAD),
            "x": base64::encode_config(session_key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD)
        }))?;
        let prepared = prepare_session(SessionConfig {
            abilities: HashMap::from([
                (
                    "kv".parse()?,
                    HashMap::from([("".parse()?, vec![KV_PUT.parse()?, KV_GET.parse()?])]),
                ),
                (
                    "sql".parse()?,
                    HashMap::from([(SQL_DATABASE.parse()?, vec![SQL_ADMIN.parse()?])]),
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
        self.delegate(authorization(&session.delegation_header)?)
            .await?;
        Ok((account, session))
    }

    async fn invoke(
        &self,
        session: &Session,
        service: &str,
        path: &str,
        ability: &str,
        body: reqwest::Body,
        content_type: &str,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let invocation = session
            .invoke(
                [(
                    service.parse::<Service>()?,
                    path.parse::<Path>()?,
                    None,
                    None,
                    [ability.parse::<Ability>()?],
                )],
                None,
            )?
            .encode()?;
        let response = self
            .http
            .post(format!("{}/invoke", self.node))
            .header("Authorization", invocation)
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await?;
        Ok((response.status(), response.bytes().await?.to_vec()))
    }

    async fn sql(&self, session: &Session, request: Value) -> Result<Value> {
        let (status, body) = self
            .invoke(
                session,
                "sql",
                SQL_DATABASE,
                SQL_ADMIN,
                serde_json::to_vec(&request)?.into(),
                "application/json",
            )
            .await?;
        ensure!(
            status == StatusCode::OK,
            "sql {}: {status} {}",
            request["action"],
            String::from_utf8_lossy(&body)
        );
        Ok(serde_json::from_slice(&body)?)
    }
}

fn authorization(headers: &impl serde::Serialize) -> Result<String> {
    serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_owned)
        .context("SDK delegation must contain Authorization")
}

/// 32 fresh random bytes (two v4 UUIDs: 244 bits from the OS RNG).
fn uuid_seed() -> [u8; 32] {
    let mut seed = [0; 32];
    seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed
}

fn marker(kind: &str) -> String {
    format!("TC887-{kind}-MARKER-{}", uuid::Uuid::new_v4().simple())
}

/// A synthetic per-run wallet and its space; never a real credential.
struct Account {
    key: SigningKey,
    address: [u8; 20],
    space: SpaceId,
}

impl Account {
    fn random() -> Result<Self> {
        let key = SigningKey::from_bytes(&uuid_seed().into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address: [u8; 20] = digest[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        let name = format!("tc887{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let space = SpaceId::new(did.parse::<DIDBuf>()?, name.parse()?);
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

    /// Lower-case hex wallet address, as it can appear in any casing.
    fn address_hex(&self) -> String {
        hex::encode(self.address)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// One KV put through the node, with the bucket listed before and after.
struct KvWrite {
    account: Account,
    marker: String,
    new_keys: BTreeSet<String>,
    objects: BTreeMap<String, Vec<u8>>,
}

async fn kv_write(harness: &Harness) -> Result<KvWrite> {
    let (account, session) = harness.sign_in().await?;
    let before: BTreeSet<String> = harness.objects().await?.into_keys().collect();
    let marker = marker("KV");
    let path = format!("tc887/{}", uuid::Uuid::new_v4().simple());
    let value = format!("at-rest probe {marker}");
    let (status, body) = harness
        .invoke(
            &session,
            "kv",
            &path,
            KV_PUT,
            value.clone().into(),
            "text/plain",
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "kv put: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = harness
        .invoke(
            &session,
            "kv",
            &path,
            KV_GET,
            Vec::new().into(),
            "text/plain",
        )
        .await?;
    ensure!(
        status == StatusCode::OK && body == value.as_bytes(),
        "kv get through the node: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let objects = harness.objects().await?;
    let new_keys = objects
        .keys()
        .filter(|key| !before.contains(*key))
        .cloned()
        .collect();
    Ok(KvWrite {
        account,
        marker,
        new_keys,
        objects,
    })
}

/// One SQL database created and written through the node, with its
/// `database_artifact` rows read straight from PostgreSQL.
struct SqlWrite {
    account: Account,
    markers: [String; 2],
    rows: Vec<database_artifact::Model>,
}

async fn sql_write(harness: &Harness) -> Result<SqlWrite> {
    let (account, session) = harness.sign_in().await?;
    let markers = [marker("SQL-WRITE1"), marker("SQL-WRITE2")];
    // First write: no checkpoint exists, so the node saves a full checkpoint
    // into `database_artifact.payload` before replying.
    harness
        .sql(
            &session,
            json!({"action": "batch", "statements": [
                {"sql": "CREATE TABLE probe (id INTEGER PRIMARY KEY, secret TEXT NOT NULL)", "params": []},
                {"sql": "INSERT INTO probe (secret) VALUES (?)", "params": [markers[0]]},
            ]}),
        )
        .await?;
    // Second write: persisted before the reply as a WAL delta
    // (`delta_payload`) or a fresh checkpoint, whichever the node picks.
    harness
        .sql(
            &session,
            json!({"action": "execute", "sql": "INSERT INTO probe (secret) VALUES (?)", "params": [markers[1]]}),
        )
        .await?;
    let read = harness
        .sql(
            &session,
            json!({"action": "query", "sql": "SELECT secret FROM probe ORDER BY id", "params": []}),
        )
        .await?;
    ensure!(
        read["rows"] == json!([[markers[0]], [markers[1]]]),
        "sql read through the node: {read}"
    );
    let rows = database_artifact::Entity::find()
        .filter(database_artifact::Column::Service.eq("sql"))
        .filter(database_artifact::Column::Space.eq(account.space.to_string()))
        .all(&harness.pg)
        .await
        .context("read database_artifact")?;
    Ok(SqlWrite {
        account,
        markers,
        rows,
    })
}

fn kv_reached_minio(write: &KvWrite) -> Result<()> {
    if write.new_keys.is_empty() {
        bail!(
            "harness no-op: the KV put created no object in the MinIO bucket ({} objects total)",
            write.objects.len()
        );
    }
    for key in &write.new_keys {
        ensure!(!write.objects[key].is_empty(), "new object {key} is empty");
    }
    Ok(())
}

fn sql_reached_postgres(write: &SqlWrite) -> Result<()> {
    if write.rows.is_empty() {
        bail!(
            "harness no-op: no database_artifact row for service=sql space={}",
            write.account.space
        );
    }
    ensure!(
        write
            .rows
            .iter()
            .any(|row| row.revision >= 1 && !row.payload.is_empty()),
        "database_artifact rows for {} carry no payload",
        write.account.space
    );
    Ok(())
}

#[tokio::test]
#[ignore = "TC-887 harness: run via scripts/at-rest-harness/harness.sh test green"]
async fn green_kv_put_reaches_minio() -> Result<()> {
    let harness = Harness::connect().await?;
    let write = kv_write(&harness).await?;
    kv_reached_minio(&write)?;
    println!(
        "KV put for {} reached MinIO: {} new object(s), {} bytes; bucket holds {} object(s)",
        write.account.space,
        write.new_keys.len(),
        write
            .new_keys
            .iter()
            .map(|key| write.objects[key].len())
            .sum::<usize>(),
        write.objects.len()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "TC-887 harness: run via scripts/at-rest-harness/harness.sh test green"]
async fn green_sql_write_reaches_postgres() -> Result<()> {
    let harness = Harness::connect().await?;
    let write = sql_write(&harness).await?;
    sql_reached_postgres(&write)?;
    for row in &write.rows {
        println!(
            "database_artifact row ({}, {}, {}) revision={} payload={}B delta_payload={}B",
            row.service,
            row.space,
            row.name,
            row.revision,
            row.payload.len(),
            row.delta_payload.as_ref().map_or(0, Vec::len)
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "TC-887 RED: plaintext at rest until S3/S4"]
async fn red_kv_blocks_are_sealed_in_minio() -> Result<()> {
    let harness = Harness::connect().await?;
    let write = kv_write(&harness).await?;
    kv_reached_minio(&write)?;
    let space = write.account.space.to_string();
    let address = write.account.address_hex();
    let mut findings = Vec::new();
    for (key, body) in &write.objects {
        if key.contains(&space) {
            findings.push(format!("object key {key:?} contains the space id {space}"));
        }
        if key.to_ascii_lowercase().contains(&address) {
            findings.push(format!(
                "object key {key:?} contains the wallet address 0x{address} (case-insensitive)"
            ));
        }
        if let Some(offset) = find(body, write.marker.as_bytes()) {
            findings.push(format!(
                "raw object {key:?} ({} bytes) contains the plaintext marker {:?} at byte {offset}",
                body.len(),
                write.marker
            ));
        }
    }
    ensure!(
        findings.is_empty(),
        "TC-887 RED: KV data is not sealed at rest in MinIO ({} finding(s)):\n  {}",
        findings.len(),
        findings.join("\n  ")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "TC-887 RED: plaintext at rest until S3/S4"]
async fn red_sql_artifacts_are_sealed_in_postgres() -> Result<()> {
    let harness = Harness::connect().await?;
    let write = sql_write(&harness).await?;
    sql_reached_postgres(&write)?;
    let mut findings = Vec::new();
    for row in &write.rows {
        let id = format!("({}, {}, {})", row.service, row.space, row.name);
        if row.payload.starts_with(SQLITE_MAGIC) {
            findings.push(format!(
                "database_artifact{id}.payload ({} bytes) starts with the SQLite magic {:?}",
                row.payload.len(),
                String::from_utf8_lossy(&row.payload[..SQLITE_MAGIC.len()])
            ));
        }
        for (column, bytes) in [
            ("payload", Some(&row.payload)),
            ("delta_payload", row.delta_payload.as_ref()),
        ] {
            for marker in &write.markers {
                if let Some(offset) = bytes.and_then(|bytes| find(bytes, marker.as_bytes())) {
                    findings.push(format!(
                        "database_artifact{id}.{column} contains the plaintext marker {marker:?} at byte {offset}"
                    ));
                }
            }
        }
    }
    ensure!(
        findings.is_empty(),
        "TC-887 RED: SQL artifacts are not sealed at rest in PostgreSQL ({} finding(s)):\n  {}",
        findings.len(),
        findings.join("\n  ")
    );
    Ok(())
}
