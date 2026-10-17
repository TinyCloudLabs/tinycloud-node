//! TC-887 S0: at-rest checks against the native harness in
//! `scripts/at-rest-harness/` (a real `tinycloud` binary on native PostgreSQL
//! and native MinIO). Every test is `#[ignore]`d: they need the harness up and
//! are run through `scripts/at-rest-harness/harness.sh test green|red STATE`,
//! which sets `TC887_HARNESS_STATE` and checks the expected outcome.
//!
//! Each check writes the same plaintext into two fresh spaces through the
//! node's public API (SDK-style sign-in, `/invoke`): a short value carrying a
//! unique marker and a 64 KiB value of the marker repeated (highly
//! compressible). For SQL, the second write lands as a WAL delta
//! (`delta_payload`), because the harness runs the node with
//! `storage.sql.memory_threshold = 0`.
//!
//! - `green_*` prove the harness is live: the writes round-trip through the
//!   node and land in MinIO / `database_artifact` (including a delta). They
//!   stay green before and after encryption, and the RED checks re-run the
//!   same preconditions, so a RED result is never a harness no-op.
//! - `red_*` assert the TC-887 at-rest property on the raw stored bytes. They
//!   FAIL today (plaintext at rest) and turn green with slices S3 (KV) and S4
//!   (SQL). Besides the marker, the space id/address and SQLite magic, they
//!   reject the plaintext fingerprint in object names and any deterministic,
//!   non-encrypting transform (encoding, XOR, compression): the two spaces'
//!   stored bytes must share no [`MAX_SHARED_RUN`]-byte run, and stored bytes
//!   must not compress below [`MIN_INCOMPRESSIBLE_RATIO`].

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
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
const SQLITE_WAL_MAGIC: [[u8; 4]; 2] = [[0x37, 0x7f, 0x06, 0x82], [0x37, 0x7f, 0x06, 0x83]];
const SQL_DATABASE: &str = "tc887";
const KV_PUT: &str = "tinycloud.kv/put";
const KV_GET: &str = "tinycloud.kv/get";
const SQL_ADMIN: &str = "tinycloud.sql/admin";
/// Size of the compressible probe value (the marker repeated).
const BIG_VALUE_LEN: usize = 64 * 1024;

/// Stored bytes of two independent writes of the same plaintext (in two
/// spaces) must not share a run of this many bytes.
///
/// A sealed blob (plan §1.2-1.3: a 64-byte TCE1 header, then AES-256-GCM
/// segments under a per-blob key derived from a random 32-byte salt) repeats
/// only fixed header fields between two writes of the same plaintext: magic,
/// version, algorithm, flags, reserved, `dek_id` and `plaintext_len` (20
/// bytes), then the random salt, then `seg_log2` and padding (12 bytes). So
/// honest ciphertexts share runs of at most ~20 bytes, while a chance 32-byte
/// match between pseudorandom strings of n and m bytes has probability about
/// n·m/2^256. A deterministic transform of identical plaintext (encoding,
/// XOR, compression, an unsalted cipher keyed the same in both spaces) keeps
/// runs as long as the data itself.
const MAX_SHARED_RUN: usize = 32;

/// zlib must not shrink stored bytes below this fraction of their length.
/// Ciphertext is incompressible (zlib ratio ≈ 1.0); the 64 KiB repeated-marker
/// plaintext compresses to ≈ 0.01, and base64 or XOR of it to ≈ 0.03.
const MIN_INCOMPRESSIBLE_RATIO: f64 = 0.95;

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

    /// Every object key in the harness bucket.
    async fn keys(&self) -> Result<BTreeSet<String>> {
        let mut keys = BTreeSet::new();
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
                keys.insert(object.key().context("object without key")?.to_owned());
            }
            if !page.is_truncated() {
                return Ok(keys);
            }
            token = page.next_continuation_token().map(str::to_owned);
        }
    }

    /// One object's raw bytes, as MinIO stores them.
    async fn object(&self, key: &str) -> Result<Vec<u8>> {
        Ok(self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("GET raw object {key}"))?
            .body
            .collect()
            .await?
            .into_bytes()
            .to_vec())
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

/// `marker` repeated (space-separated) to at least `len` bytes.
fn repeated(marker: &str, len: usize) -> String {
    let mut value = String::with_capacity(len + marker.len() + 1);
    while value.len() < len {
        value.push_str(marker);
        value.push(' ');
    }
    value
}

/// zlib-compressed size over input size.
fn zlib_ratio(bytes: &[u8]) -> Result<f64> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?.len() as f64 / bytes.len().max(1) as f64)
}

/// The longest run starting at the first [`MAX_SHARED_RUN`]-byte window of
/// `a` that also occurs in `b`: (offset in a, offset in b, run length).
fn shared_run(a: &[u8], b: &[u8]) -> Option<(usize, usize, usize)> {
    if a.len() < MAX_SHARED_RUN || b.len() < MAX_SHARED_RUN {
        return None;
    }
    let mut windows = HashMap::new();
    for (offset, window) in b.windows(MAX_SHARED_RUN).enumerate() {
        windows.entry(window).or_insert(offset);
    }
    let (i, j) = a
        .windows(MAX_SHARED_RUN)
        .enumerate()
        .find_map(|(i, window)| windows.get(window).map(|&j| (i, j)))?;
    let len = a[i..]
        .iter()
        .zip(&b[j..])
        .take_while(|(x, y)| x == y)
        .count();
    Some((i, j, len))
}

/// Findings for stored bytes `a` and `b` of the same plaintext written into
/// two different spaces.
fn compare_writes(what: &str, a: &[u8], b: &[u8], findings: &mut Vec<String>) {
    if a == b {
        findings.push(format!(
            "{what}: the two spaces stored byte-identical {}-byte blobs for the same plaintext \
             (deterministic, no per-blob randomness)",
            a.len()
        ));
    } else if let Some((i, j, len)) = shared_run(a, b) {
        findings.push(format!(
            "{what}: the two spaces' blobs ({} and {} bytes) for the same plaintext share a \
             {len}-byte run (space A byte {i}, space B byte {j}; limit {})",
            a.len(),
            b.len(),
            MAX_SHARED_RUN - 1
        ));
    }
}

/// Finding if zlib shrinks `bytes` below [`MIN_INCOMPRESSIBLE_RATIO`].
fn check_incompressible(what: &str, bytes: &[u8], findings: &mut Vec<String>) -> Result<()> {
    let ratio = zlib_ratio(bytes)?;
    if ratio <= MIN_INCOMPRESSIBLE_RATIO {
        findings.push(format!(
            "{what} ({} bytes) compresses to {ratio:.3} of its size with zlib \
             (ciphertext stays above {MIN_INCOMPRESSIBLE_RATIO})",
            bytes.len()
        ));
    }
    Ok(())
}

/// A text encoding of the plaintext's blake3 fingerprint.
struct Fingerprint {
    label: String,
    text: String,
    case_insensitive: bool,
}

/// blake3(value), as the raw digest and as the multihash the node stores,
/// in b64url (padded and unpadded), standard base64 (padded and unpadded)
/// and hex.
fn fingerprints(value: &[u8]) -> Vec<Fingerprint> {
    let hash = tinycloud_core::hash::hash(value);
    let digest = hash.as_ref().to_vec();
    let multihash: Vec<u8> = hash.into();
    let mut out = Vec::new();
    for (form, bytes) in [("blake3", &digest), ("blake3 multihash", &multihash)] {
        for (encoding, config) in [
            ("b64url", base64::URL_SAFE),
            ("b64url-nopad", base64::URL_SAFE_NO_PAD),
            ("base64", base64::STANDARD),
            ("base64-nopad", base64::STANDARD_NO_PAD),
        ] {
            out.push(Fingerprint {
                label: format!("{form} {encoding}"),
                text: base64::encode_config(bytes, config),
                case_insensitive: false,
            });
        }
        out.push(Fingerprint {
            label: format!("{form} hex"),
            text: hex::encode(bytes),
            case_insensitive: true,
        });
    }
    out
}

/// A raw object in MinIO.
struct StoredObject {
    key: String,
    body: Vec<u8>,
}

/// KV probes written into one space, with the objects each put created.
struct KvSpace {
    account: Account,
    /// Per probe (same order as [`KvRun::probes`]).
    objects: Vec<Vec<StoredObject>>,
}

/// The same KV probes written into two fresh spaces.
struct KvRun {
    marker: String,
    probes: Vec<(&'static str, String)>,
    spaces: Vec<KvSpace>,
}

/// One KV put through the node, round-tripped through a get; returns the
/// objects it added to the bucket. Fails if it added none (a harness no-op).
async fn kv_put(
    harness: &Harness,
    session: &Session,
    account: &Account,
    path: &str,
    value: &str,
) -> Result<Vec<StoredObject>> {
    let before = harness.keys().await?;
    let (status, body) = harness
        .invoke(
            session,
            "kv",
            path,
            KV_PUT,
            value.to_owned().into(),
            "text/plain",
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "kv put {path}: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = harness
        .invoke(session, "kv", path, KV_GET, Vec::new().into(), "text/plain")
        .await?;
    ensure!(
        status == StatusCode::OK && body == value.as_bytes(),
        "kv get {path} through the node: {status}, {} bytes back for a {}-byte value",
        body.len(),
        value.len()
    );
    let mut objects = Vec::new();
    for key in harness.keys().await?.difference(&before) {
        let body = harness.object(key).await?;
        ensure!(!body.is_empty(), "new object {key} is empty");
        objects.push(StoredObject {
            key: key.clone(),
            body,
        });
    }
    if objects.is_empty() {
        bail!(
            "harness no-op: the {}-byte KV put to {}/{path} created no object in the MinIO bucket",
            value.len(),
            account.space
        );
    }
    Ok(objects)
}

async fn kv_run(harness: &Harness) -> Result<KvRun> {
    let marker = marker("KV");
    let probes = vec![
        ("short", format!("at-rest probe {marker}")),
        ("compressible", repeated(&marker, BIG_VALUE_LEN)),
    ];
    let mut spaces = Vec::new();
    for _ in 0..2 {
        let (account, session) = harness.sign_in().await?;
        let mut objects = Vec::new();
        for (label, value) in &probes {
            objects.push(
                kv_put(
                    harness,
                    &session,
                    &account,
                    &format!("tc887/{label}"),
                    value,
                )
                .await?,
            );
        }
        spaces.push(KvSpace { account, objects });
    }
    Ok(KvRun {
        marker,
        probes,
        spaces,
    })
}

/// SQL probes written into one space, with its `database_artifact` rows.
struct SqlSpace {
    account: Account,
    rows: Vec<database_artifact::Model>,
}

/// The same SQL statements run in two fresh spaces.
struct SqlRun {
    markers: [String; 2],
    spaces: Vec<SqlSpace>,
}

async fn sql_run(harness: &Harness) -> Result<SqlRun> {
    let markers = [marker("SQL-WRITE1"), marker("SQL-WRITE2")];
    let big = [
        repeated(&markers[0], BIG_VALUE_LEN),
        repeated(&markers[1], BIG_VALUE_LEN),
    ];
    let insert = "INSERT INTO probe (secret) VALUES (?)";
    let writes = [
        // No checkpoint exists yet: the node saves a full checkpoint into
        // `database_artifact.payload` before replying.
        json!({"action": "batch", "statements": [
            {"sql": "CREATE TABLE probe (id INTEGER PRIMARY KEY, secret TEXT NOT NULL)", "params": []},
            {"sql": insert, "params": [markers[0]]},
            {"sql": insert, "params": [big[0]]},
        ]}),
        // The database is file-backed (memory_threshold = 0), so this write
        // is saved as a WAL delta into `delta_payload` before replying.
        json!({"action": "batch", "statements": [
            {"sql": insert, "params": [markers[1]]},
            {"sql": insert, "params": [big[1]]},
        ]}),
    ];
    let expected = json!([[markers[0]], [big[0]], [markers[1]], [big[1]]]);
    let mut spaces = Vec::new();
    for _ in 0..2 {
        let (account, session) = harness.sign_in().await?;
        for write in &writes {
            harness.sql(&session, write.clone()).await?;
        }
        let read = harness
            .sql(
                &session,
                json!({"action": "query", "sql": "SELECT secret FROM probe ORDER BY id", "params": []}),
            )
            .await?;
        ensure!(
            read["rows"] == expected,
            "sql read through the node for {} returned other rows ({} row(s))",
            account.space,
            read["rows"].as_array().map_or(0, Vec::len)
        );
        let rows = database_artifact::Entity::find()
            .filter(database_artifact::Column::Service.eq("sql"))
            .filter(database_artifact::Column::Space.eq(account.space.to_string()))
            .all(&harness.pg)
            .await
            .context("read database_artifact")?;
        let space = SqlSpace { account, rows };
        sql_reached_postgres(&space)?;
        spaces.push(space);
    }
    Ok(SqlRun { markers, spaces })
}

/// The writes reached PostgreSQL as a checkpoint and a WAL delta.
fn sql_reached_postgres(space: &SqlSpace) -> Result<()> {
    if space.rows.is_empty() {
        bail!(
            "harness no-op: no database_artifact row for service=sql space={}",
            space.account.space
        );
    }
    ensure!(
        space
            .rows
            .iter()
            .any(|row| row.revision >= 1 && !row.payload.is_empty()),
        "harness no-op: database_artifact rows for {} carry no payload",
        space.account.space
    );
    ensure!(
        space.rows.iter().any(|row| row
            .delta_payload
            .as_ref()
            .is_some_and(|delta| !delta.is_empty())),
        "harness gap: database_artifact rows for {} have no delta_payload, so the WAL-delta \
         path did not run (the harness must start the node with \
         TINYCLOUD_STORAGE__SQL__MEMORY_THRESHOLD=0)",
        space.account.space
    );
    Ok(())
}

fn row_id(row: &database_artifact::Model) -> String {
    format!(
        "database_artifact({}, {}, {})",
        row.service, row.space, row.name
    )
}

#[tokio::test]
#[ignore = "TC-887 harness: run via scripts/at-rest-harness/harness.sh test green STATE"]
async fn green_kv_put_reaches_minio() -> Result<()> {
    let harness = Harness::connect().await?;
    let run = kv_run(&harness).await?;
    for space in &run.spaces {
        for ((label, value), objects) in run.probes.iter().zip(&space.objects) {
            println!(
                "KV {label} put ({} bytes) for {} reached MinIO: {} new object(s), {} bytes",
                value.len(),
                space.account.space,
                objects.len(),
                objects
                    .iter()
                    .map(|object| object.body.len())
                    .sum::<usize>()
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "TC-887 harness: run via scripts/at-rest-harness/harness.sh test green STATE"]
async fn green_sql_write_reaches_postgres() -> Result<()> {
    let harness = Harness::connect().await?;
    let run = sql_run(&harness).await?;
    for row in run.spaces.iter().flat_map(|space| &space.rows) {
        println!(
            "{} revision={} payload={}B delta_payload={}",
            row_id(row),
            row.revision,
            row.payload.len(),
            row.delta_payload
                .as_ref()
                .map_or("NULL".to_owned(), |delta| format!("{}B", delta.len()))
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "TC-887 RED: plaintext at rest until S3/S4"]
async fn red_kv_blocks_are_sealed_in_minio() -> Result<()> {
    let harness = Harness::connect().await?;
    let run = kv_run(&harness).await?;
    let mut findings = Vec::new();
    for space in &run.spaces {
        let space_id = space.account.space.to_string();
        let address = space.account.address_hex();
        for ((label, value), objects) in run.probes.iter().zip(&space.objects) {
            let fingerprints = fingerprints(value.as_bytes());
            for StoredObject { key, body } in objects {
                if key.contains(&space_id) {
                    findings.push(format!(
                        "object key {key:?} contains the space id {space_id}"
                    ));
                }
                let lower = key.to_ascii_lowercase();
                if lower.contains(&address) {
                    findings.push(format!(
                        "object key {key:?} contains the wallet address 0x{address} (case-insensitive)"
                    ));
                }
                let leaked = fingerprints
                    .iter()
                    .filter(|fp| {
                        if fp.case_insensitive {
                            lower.contains(&fp.text)
                        } else {
                            key.contains(&fp.text)
                        }
                    })
                    .map(|fp| format!("{} {}", fp.label, fp.text))
                    .collect::<Vec<_>>();
                if !leaked.is_empty() {
                    findings.push(format!(
                        "object key {key:?} contains the plaintext fingerprint of the {label} value: {}",
                        leaked.join(", ")
                    ));
                }
                if let Some(offset) = find(body, run.marker.as_bytes()) {
                    findings.push(format!(
                        "raw object {key:?} ({} bytes, {label} value) contains the plaintext marker {:?} at byte {offset}",
                        body.len(),
                        run.marker
                    ));
                }
                if *label == "compressible" {
                    check_incompressible(
                        &format!("raw object {key:?} [{label} value]"),
                        body,
                        &mut findings,
                    )?;
                }
            }
        }
    }
    for (index, (label, _)) in run.probes.iter().enumerate() {
        let a = &run.spaces[0].objects[index];
        let b = &run.spaces[1].objects[index];
        for (a, b) in a.iter().zip(b) {
            compare_writes(
                &format!("KV {label} value ({:?} vs {:?})", a.key, b.key),
                &a.body,
                &b.body,
                &mut findings,
            );
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
    let run = sql_run(&harness).await?;
    let mut findings = Vec::new();
    for row in run.spaces.iter().flat_map(|space| &space.rows) {
        let id = row_id(row);
        if row.payload.starts_with(SQLITE_MAGIC) {
            findings.push(format!(
                "{id}.payload ({} bytes) starts with the SQLite magic {:?}",
                row.payload.len(),
                String::from_utf8_lossy(&row.payload[..SQLITE_MAGIC.len()])
            ));
        }
        if let Some(delta) = &row.delta_payload {
            if SQLITE_WAL_MAGIC
                .iter()
                .any(|magic| delta.starts_with(magic))
            {
                findings.push(format!(
                    "{id}.delta_payload ({} bytes) starts with the SQLite WAL magic {}",
                    delta.len(),
                    hex::encode(&delta[..4])
                ));
            }
        }
        for (column, bytes) in [
            ("payload", Some(&row.payload)),
            ("delta_payload", row.delta_payload.as_ref()),
        ] {
            let Some(bytes) = bytes else { continue };
            for marker in &run.markers {
                if let Some(offset) = find(bytes, marker.as_bytes()) {
                    findings.push(format!(
                        "{id}.{column} contains the plaintext marker {marker:?} at byte {offset}"
                    ));
                }
            }
            check_incompressible(&format!("{id}.{column}"), bytes, &mut findings)?;
        }
    }
    for a in &run.spaces[0].rows {
        let b = run.spaces[1]
            .rows
            .iter()
            .find(|b| b.name == a.name)
            .with_context(|| {
                format!(
                    "no database_artifact row named {} for the second space {}",
                    a.name, run.spaces[1].account.space
                )
            })?;
        compare_writes(
            &format!("database_artifact payload of {}", a.name),
            &a.payload,
            &b.payload,
            &mut findings,
        );
        if let (Some(da), Some(db)) = (&a.delta_payload, &b.delta_payload) {
            compare_writes(
                &format!("database_artifact delta_payload of {}", a.name),
                da,
                db,
                &mut findings,
            );
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

fn random_bytes(len: usize) -> Vec<u8> {
    (0..len.div_ceil(16))
        .flat_map(|_| *uuid::Uuid::new_v4().as_bytes())
        .take(len)
        .collect()
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("zlib into memory");
    encoder.finish().expect("zlib into memory")
}

/// A stand-in for one sealed blob of `len` plaintext bytes: the fixed TCE1
/// header fields two writes of the same plaintext share (plan §1.3), a random
/// salt, and random ciphertext.
fn sealed_like(len: usize) -> Vec<u8> {
    let mut blob = b"TCE1\x01\x01\x00\x00".to_vec();
    blob.extend(1u32.to_be_bytes()); // dek_id
    blob.extend((len as u64).to_be_bytes()); // plaintext_len
    blob.extend(random_bytes(32)); // salt
    blob.push(16); // seg_log2
    blob.extend([0; 11]); // pad
    blob.extend(random_bytes(len + 16 * len.div_ceil(1 << 16)));
    blob
}

/// Offline check of the RED predicates themselves (runs in plain `cargo
/// test`, no harness; its name stays clear of the `green_`/`red_` filters
/// `harness.sh test` uses): deterministic transforms of identical plaintext
/// are flagged even with the marker and magic gone, and two sealed-like
/// blobs of the same plaintext are not.
#[test]
fn selftest_predicates_flag_deterministic_transforms_not_ciphertext() -> Result<()> {
    let marker = marker("SELFTEST");
    let plaintext = repeated(&marker, BIG_VALUE_LEN).into_bytes();
    type Transform = fn(&[u8]) -> Vec<u8>;
    let transforms: [(&str, Transform); 4] = [
        ("identity", |bytes| bytes.to_vec()),
        ("base64", |bytes| base64::encode(bytes).into_bytes()),
        ("xor 0x5a", |bytes| {
            bytes.iter().map(|byte| byte ^ 0x5a).collect()
        }),
        ("zlib", zlib),
    ];
    for (name, transform) in transforms {
        let (a, b) = (transform(&plaintext), transform(&plaintext));
        let mut findings = Vec::new();
        compare_writes(name, &a, &b, &mut findings);
        ensure!(
            findings.len() == 1,
            "{name}: two-space comparison missed it"
        );
        if name != "zlib" {
            check_incompressible(name, &a, &mut findings)?;
            ensure!(findings.len() == 2, "{name}: compressibility missed it");
        }
        // A per-write random prefix doesn't hide a deterministic body.
        let (a, b) = (
            [random_bytes(16), a].concat(),
            [random_bytes(16), b].concat(),
        );
        let mut findings = Vec::new();
        compare_writes(name, &a, &b, &mut findings);
        ensure!(
            findings.len() == 1 && findings[0].contains("run"),
            "{name} behind a random prefix: shared-run check missed it"
        );
    }
    for len in [62, BIG_VALUE_LEN] {
        let (a, b) = (sealed_like(len), sealed_like(len));
        let mut findings = Vec::new();
        compare_writes("sealed", &a, &b, &mut findings);
        if len == BIG_VALUE_LEN {
            check_incompressible("sealed", &a, &mut findings)?;
        }
        ensure!(
            find(&a, marker.as_bytes()).is_none() && findings.is_empty(),
            "sealed-like blobs of {len} bytes were flagged: {findings:?}"
        );
    }
    Ok(())
}
