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
//!   stored bytes must share no [`MAX_SHARED_RUN`]-byte run, stored bytes
//!   must not compress below [`MIN_INCOMPRESSIBLE_RATIO`], and a blob must be
//!   at least as large as the plaintext it holds (TCE1 never shrinks data).
//!
//! The KV RED check also covers the at-rest key mirror: every `_tc/` object,
//! in the bucket at boot and after the puts, must have an allowed name and an
//! exact typed schema, carry no raw key, identity, fingerprint or marker, and
//! hold key material that authenticates under the harness's Static root (see
//! [`key_mirror`]).

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
    /// The node's Static root (`TINYCLOUD_KEYS__SECRET`, base64url): the
    /// test re-derives the at-rest key hierarchy from it. Never printed.
    root: Vec<u8>,
    /// Every space any check signed in to on this harness, one per line.
    spaces_log: std::path::PathBuf,
    /// The bucket as the node left it at boot, before any test write.
    boot_snapshot: std::path::PathBuf,
    /// The at-rest mode and escrow choice `up` started the node with.
    policy: key_mirror::Policy,
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
        let policy = key_mirror::Policy {
            encrypt: matches!(
                state["at_rest"]["mode"].as_str(),
                Some("encrypt" | "strict")
            ),
            escrow_none: state["at_rest"]["escrow_none"] == true,
        };
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
        let root_file = var("TC887_NODE_ROOT_FILE")?;
        let root = std::fs::read_to_string(&root_file)
            .with_context(|| format!("read the node root file {root_file}"))?;
        // The decode error could quote secret bytes; don't pass it on.
        let root = base64::decode_config(root.trim(), base64::URL_SAFE_NO_PAD)
            .map_err(|_| anyhow!("{root_file} does not hold unpadded base64url"))?;
        ensure!(
            root.len() >= 32,
            "{root_file}: the node root is shorter than 32 bytes"
        );
        Ok(Self {
            node: var("TC887_NODE_URL")?,
            http: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(60))
                .build()?,
            s3,
            bucket: var("TC887_S3_BUCKET")?,
            pg,
            root,
            spaces_log: var("TC887_SPACES_LOG")?.into(),
            boot_snapshot: var("TC887_BOOT_SNAPSHOT")?.into(),
            policy,
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

    /// Every `_tc/` (control) object now in the bucket.
    async fn control_objects(&self) -> Result<Vec<StoredObject>> {
        let mut objects = Vec::new();
        for key in self.keys().await? {
            if key.starts_with(key_mirror::CONTROL_PREFIX) {
                let body = self.object(&key).await?;
                objects.push(StoredObject { key, body });
            }
        }
        Ok(objects)
    }

    /// The bucket right after the node booted (`harness.sh up` saved it).
    fn boot_objects(&self) -> Result<Vec<StoredObject>> {
        let dir = &self.boot_snapshot;
        let index: Vec<Value> = serde_json::from_slice(
            &std::fs::read(dir.join("index.json"))
                .with_context(|| format!("harness gap: no boot snapshot in {}", dir.display()))?,
        )?;
        index
            .iter()
            .map(|entry| {
                let key = entry["key"]
                    .as_str()
                    .context("boot snapshot entry without key")?;
                let file = entry["file"]
                    .as_str()
                    .context("boot snapshot entry without file")?;
                Ok(StoredObject {
                    key: key.to_owned(),
                    body: std::fs::read(dir.join(file))
                        .with_context(|| format!("boot snapshot of {key:?}"))?,
                })
            })
            .collect()
    }

    /// Every space signed in to on this harness, from any check.
    fn known_spaces(&self) -> Result<Vec<String>> {
        let log = std::fs::read_to_string(&self.spaces_log).unwrap_or_default();
        Ok(log
            .lines()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
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
        // Logged before use, so the RED checks can map every DEK mirror tag
        // back to a space this harness created (ruling 5).
        writeln!(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.spaces_log)
                .with_context(|| format!("open {}", self.spaces_log.display()))?,
            "{}",
            account.space
        )?;
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

/// Finding if `stored` bytes are fewer than the `plaintext` bytes they must
/// hold. TCE1 adds a header and per-segment tags and never shrinks data, so a
/// smaller blob is compressed (or truncated), not sealed. This catches strong
/// compressors (xz, bz2) whose output neither compresses further nor repeats
/// across writes once a per-write salt (e.g. SQLite's WAL salts) is mixed in.
fn check_size_floor(what: &str, stored: usize, plaintext: usize, findings: &mut Vec<String>) {
    if stored < plaintext {
        findings.push(format!(
            "{what} is {stored} bytes, smaller than the {plaintext}-byte plaintext it must hold \
             (sealing never shrinks data: compressed, not sealed)"
        ));
    }
}

/// One text form of a space's identity (its space id or its wallet address)
/// that must never appear in an object name or a key-mirror body.
struct IdentityForm {
    label: String,
    text: String,
    case_insensitive: bool,
}

/// The parts of base64(`bytes`) that are the same wherever `bytes` sits in a
/// longer encoded string: for each of the three byte alignments, the
/// characters that carry only bits of `bytes`.
fn base64_cores(bytes: &[u8], config: base64::Config) -> Vec<String> {
    (0..3)
        .filter_map(|offset| {
            let mut aligned = vec![0u8; offset];
            aligned.extend_from_slice(bytes);
            let encoded = base64::encode_config(&aligned, config);
            let (start, end) = ((8 * offset).div_ceil(6), 8 * aligned.len() / 6);
            (end > start).then(|| encoded[start..end].to_owned())
        })
        .collect()
}

/// The wallet address in a `tinycloud:pkh:eip155:<chain>:0x<40 hex>:<name>`
/// space id: its text (as written) and its 20 bytes.
fn space_address(space: &str) -> Option<(String, [u8; 20])> {
    space.split(':').find_map(|part| {
        let hex_part = part.strip_prefix("0x")?;
        let bytes: [u8; 20] = hex::decode(hex_part).ok()?.try_into().ok()?;
        Some((part.to_owned(), bytes))
    })
}

/// Ruling 4: the space id and its wallet address, raw, lowercase, as hex and
/// as base64 and base64url (any alignment), of both the text and the bytes.
fn identity_forms(space: &str) -> Vec<IdentityForm> {
    let mut forms = Vec::new();
    let mut texts = vec![("space id".to_owned(), space.as_bytes().to_vec())];
    if let Some((text, bytes)) = space_address(space) {
        forms.push(IdentityForm {
            label: "wallet address".into(),
            text: hex::encode(bytes),
            case_insensitive: true,
        });
        for (encoding, config) in [
            ("base64", base64::STANDARD_NO_PAD),
            ("base64url", base64::URL_SAFE_NO_PAD),
        ] {
            for core in base64_cores(&bytes, config) {
                forms.push(IdentityForm {
                    label: format!("wallet address bytes as {encoding}"),
                    text: core,
                    case_insensitive: false,
                });
            }
        }
        texts.push(("wallet address text".into(), text.as_bytes().to_vec()));
        texts.push((
            "lowercase wallet address text".into(),
            text.to_ascii_lowercase().into_bytes(),
        ));
    }
    for (label, bytes) in texts {
        forms.push(IdentityForm {
            label: label.clone(),
            text: String::from_utf8_lossy(&bytes).into_owned(),
            case_insensitive: true,
        });
        forms.push(IdentityForm {
            label: format!("{label} as hex"),
            text: hex::encode(&bytes),
            case_insensitive: true,
        });
        for (encoding, config) in [
            ("base64", base64::STANDARD_NO_PAD),
            ("base64url", base64::URL_SAFE_NO_PAD),
        ] {
            for core in base64_cores(&bytes, config) {
                forms.push(IdentityForm {
                    label: format!("{label} as {encoding}"),
                    text: core,
                    case_insensitive: false,
                });
            }
        }
    }
    forms
}

fn contains_form(haystack: &str, text: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        haystack
            .to_ascii_lowercase()
            .contains(&text.to_ascii_lowercase())
    } else {
        haystack.contains(text)
    }
}

/// Rulings 1 and 4 for one stored object, block or key mirror: no identity
/// form or plaintext fingerprint in its name, no plaintext marker in its
/// bytes, and for a key mirror (`scan_body`) no identity form or fingerprint
/// in its text either.
fn content_findings(
    object: &StoredObject,
    scan_body: bool,
    marker: &str,
    fingerprints: &[(&str, Fingerprint)],
    identities: &[IdentityForm],
) -> Vec<String> {
    let key = &object.key;
    let body_text = String::from_utf8_lossy(&object.body);
    let mut findings = Vec::new();
    let mut places = vec![("name", key.as_str())];
    if scan_body {
        places.push(("body", &*body_text));
    }
    for (place, text) in places {
        let identity = identities
            .iter()
            .filter(|form| contains_form(text, &form.text, form.case_insensitive))
            .map(|form| form.label.as_str())
            .collect::<BTreeSet<_>>();
        if !identity.is_empty() {
            findings.push(format!(
                "object {key:?}: its {place} contains a space identity: {}",
                identity.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        for (label, fp) in fingerprints {
            if contains_form(text, &fp.text, fp.case_insensitive) {
                findings.push(format!(
                    "object {key:?}: its {place} contains the plaintext fingerprint of the {label} value ({} {})",
                    fp.label, fp.text
                ));
            }
        }
    }
    if let Some(offset) = find(&object.body, marker.as_bytes()) {
        findings.push(format!(
            "raw object {key:?} ({} bytes) contains the plaintext marker {marker:?} at byte {offset}",
            object.body.len()
        ));
    }
    findings
}

/// The at-rest key mirror (`_tc/…` objects next to the blocks): exact names,
/// exact typed schemas, a raw-key scan, and an independent re-derivation of
/// the key hierarchy from the harness's Static root, so every sealed ARK and
/// wrapped DEK must authenticate (rulings 1-3, 5).
///
/// Written from the S1 spec, not linked against it (main doesn't carry it):
/// `tinycloud-core/src/at_rest/{hierarchy,store,keyring}.rs`,
/// `tinycloud-at-rest-escrow/src/{lib,bundle,record}.rs` and
/// `tinycloud-node-server/src/at_rest.rs` (the root is the Static secret's
/// bytes: `key_setup.as_bytes()`).
mod key_mirror {
    use std::collections::{BTreeMap, BTreeSet};

    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use hmac::{Hmac, Mac};
    use serde::Deserialize;
    use serde_json::{json, Map, Value};
    use sha2::{Digest, Sha256};

    /// Every object under this prefix is a control object: it must be one of
    /// the mirror kinds below, by exact name.
    pub const CONTROL_PREFIX: &str = "_tc/";
    pub const PREFIX: &str = "_tc/at-rest/";
    pub const W_LABEL: &str = "tinycloud/at-rest/wrap/v1";
    const KEK_INFO: &[u8] = b"tinycloud/at-rest/kek/v1";
    const DEK_TAG_INFO: &[u8] = b"tinycloud/at-rest/dek-mirror-tag/v1";
    const NK_INFO: &[u8] = b"tinycloud/at-rest/object-names/v1";
    const CHAIN_INFO: &[u8] = b"tinycloud/at-rest/ark-chain/v1";
    const SEAL_DOMAIN: &[u8] = b"tinycloud/at-rest/ark-seal/v1";
    const CHAIN_DOMAIN: &[u8] = b"tinycloud/at-rest/ark-chain-aad/v1";
    const DEK_DOMAIN: &[u8] = b"tinycloud/at-rest/dek/v1";
    const EFP_DOMAIN: &[u8] = b"tinycloud/at-rest/escrow-bundle/v1";
    const CANARY_INFO: &[u8] = b"tinycloud/at-rest/escrow-canary/v1";
    const CANARY_FP_DOMAIN: &[u8] = b"tinycloud/at-rest/escrow-canary-fp/v1";
    const MAC_INFO: &[u8] = b"tinycloud/at-rest/escrow-record/v1";
    const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----\n";
    const ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";
    const AGE_MAGIC: &[u8] = b"age-encryption.org/v1\n";
    const MAX_CIPHERTEXT: usize = 4096;
    const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const NONCE_LEN: usize = 12;
    /// nonce ‖ AES-256-GCM(32-byte key) ‖ tag.
    pub const SEALED_LEN: usize = NONCE_LEN + 32 + 16;
    /// `2026-10-17T10:00:00.123456789+00:00`.
    const MAX_TIMESTAMP_LEN: usize = 35;
    const MIRROR_VERSION: u64 = 1;
    const THRESHOLD: u64 = 2;
    const HOLDERS: usize = 3;

    pub type Key = [u8; 32];

    // ---- the key hierarchy (hierarchy.rs, escrow lib.rs/record.rs) -------

    fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).expect("short").to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Key {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// HKDF-SHA256 (RFC 5869), 32 bytes: one expand block. No salt means
    /// HashLen zero bytes, as in the `hkdf` crate.
    pub fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Key {
        let prk = hmac_sha256(salt.unwrap_or(&[0u8; 32]), &[ikm]);
        hmac_sha256(&prk, &[info, &[1u8]])
    }

    fn sha256(bytes: &[u8]) -> Key {
        Sha256::digest(bytes).into()
    }

    pub fn open32(key: &Key, aad: &[u8], sealed: &[u8]) -> Option<Key> {
        if sealed.len() != SEALED_LEN {
            return None;
        }
        let cipher = <Aes256Gcm as KeyInit>::new_from_slice(key).ok()?;
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        let plain = cipher
            .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad })
            .ok()?;
        plain.try_into().ok()
    }

    /// Test-side sealing, for reference vectors only.
    pub fn seal32(key: &Key, aad: &[u8], plaintext: &Key, nonce: [u8; NONCE_LEN]) -> Vec<u8> {
        let cipher = <Aes256Gcm as KeyInit>::new_from_slice(key).expect("32-byte key");
        let ct = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AES-GCM of 32 bytes");
        [nonce.as_slice(), ct.as_slice()].concat()
    }

    /// W = HKDF(R, "tinycloud/at-rest/wrap/v1").
    pub fn wrap_key(root: &[u8]) -> Key {
        hkdf32(None, root, W_LABEL.as_bytes())
    }

    pub fn seal_aad(ark_id: &[u8; 16], generation: u32, w_label: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        lp(&mut aad, SEAL_DOMAIN);
        lp(&mut aad, ark_id);
        aad.extend_from_slice(&generation.to_be_bytes());
        lp(&mut aad, w_label.as_bytes());
        aad
    }

    pub fn chain_aad(older_id: &[u8; 16], older_generation: u32, newer_id: &[u8; 16]) -> Vec<u8> {
        let mut aad = Vec::new();
        lp(&mut aad, CHAIN_DOMAIN);
        lp(&mut aad, older_id);
        aad.extend_from_slice(&older_generation.to_be_bytes());
        lp(&mut aad, newer_id);
        aad
    }

    pub fn dek_aad(space: &str, dek_id: u32, generation: u32, ark_id: &[u8; 16]) -> Vec<u8> {
        let mut aad = Vec::new();
        lp(&mut aad, DEK_DOMAIN);
        lp(&mut aad, space.as_bytes());
        aad.extend_from_slice(&dek_id.to_be_bytes());
        aad.extend_from_slice(&generation.to_be_bytes());
        lp(&mut aad, ark_id);
        aad
    }

    pub fn chain_key(newer_ark: &Key) -> Key {
        hkdf32(None, newer_ark, CHAIN_INFO)
    }

    /// KEK_g = HKDF(ARK_g, "tinycloud/at-rest/kek/v1").
    pub fn kek(ark: &Key) -> Key {
        hkdf32(None, ark, KEK_INFO)
    }

    /// A space's DEK mirror tag: hex(HKDF(HKDF(ARK_1, tag info), space)[..16]).
    pub fn dek_tag(ark_1: &Key, space: &str) -> String {
        hex::encode(&hkdf32(None, &hkdf32(None, ark_1, DEK_TAG_INFO), space.as_bytes())[..16])
    }

    /// Escrow-side keys: HKDF with salt = ark_id.
    fn escrow_key(ark: &Key, ark_id: &[u8; 16], info: &[u8]) -> Key {
        hkdf32(Some(ark_id), ark, info)
    }

    pub fn canary_fp(ark: &Key, ark_id: &[u8; 16], generation: u32) -> Key {
        let mut info = Vec::new();
        lp(&mut info, CANARY_INFO);
        info.extend_from_slice(&generation.to_be_bytes());
        let canary = escrow_key(ark, ark_id, &info);
        let mut pre = Vec::new();
        lp(&mut pre, CANARY_FP_DOMAIN);
        pre.extend_from_slice(ark_id);
        pre.extend_from_slice(&generation.to_be_bytes());
        lp(&mut pre, &canary);
        sha256(&pre)
    }

    // ---- names (store.rs) -------------------------------------------------

    #[derive(Debug, PartialEq)]
    pub enum Kind {
        Ark { generation: u32, ark_id: [u8; 16] },
        Escrow { efp: Key },
        Record { efp: Key },
        Dek { tag: String, dek_id: u32 },
    }

    fn digits10(s: &str) -> Option<u32> {
        (s.len() == 10 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
            .filter(|n| *n >= 1)
    }

    /// Exactly `2 * N` lowercase hex characters.
    pub fn lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
        if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        hex::decode(s).ok()?.try_into().ok()
    }

    /// The allowlist: `ark-{generation:010}-{ark_id:32 hex}.json`,
    /// `escrow-{efp:64 hex}.json`, `record-{efp:64 hex}.json` and
    /// `dek-{tag:32 hex}-{dek_id:010}.json` under `_tc/at-rest/`; numbers ≥ 1.
    pub fn parse_name(name: &str) -> Option<Kind> {
        let rest = name.strip_prefix(PREFIX)?.strip_suffix(".json")?;
        if let Some(rest) = rest.strip_prefix("ark-") {
            let (generation, ark_id) = rest.split_once('-')?;
            return Some(Kind::Ark {
                generation: digits10(generation)?,
                ark_id: lower_hex::<16>(ark_id)?,
            });
        }
        if let Some(efp) = rest.strip_prefix("escrow-") {
            return Some(Kind::Escrow {
                efp: lower_hex::<32>(efp)?,
            });
        }
        if let Some(efp) = rest.strip_prefix("record-") {
            return Some(Kind::Record {
                efp: lower_hex::<32>(efp)?,
            });
        }
        let (tag, dek_id) = rest.strip_prefix("dek-")?.split_once('-')?;
        lower_hex::<16>(tag)?;
        Some(Kind::Dek {
            tag: tag.to_owned(),
            dek_id: digits10(dek_id)?,
        })
    }

    // ---- strict documents (MirroredArk/MirroredDek, EscrowBundle, ----------
    // ---- VerificationRecord: all deny_unknown_fields) --------------------
    // Parsed only to refuse duplicate keys and unknown fields the way the
    // node's serde types do; the typed checks below work on the JSON value.

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct StrictArk {
        version: u32,
        generation: u32,
        ark_id: String,
        w_label: String,
        sealed: String,
        chain: Option<String>,
        created_at: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct StrictDek {
        version: u32,
        dek_id: u32,
        generation: u32,
        wrapped: String,
        created_at: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct StrictShare {
        index: u8,
        holder: String,
        recipient: String,
        commitment: String,
        ciphertext: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct StrictBundle {
        version: u32,
        ark_id: String,
        generation: u32,
        threshold: u8,
        canary_fp: String,
        shares: Vec<StrictShare>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct StrictRecord {
        version: u32,
        efp: String,
        ark_id: String,
        generation: u32,
        verified_indices: Vec<u8>,
        pairs: Vec<[u8; 2]>,
        canary_fp: String,
        app_id: Option<String>,
        compose_hash: Option<String>,
        verified_at: String,
        mac: String,
    }

    fn strict<T: for<'de> Deserialize<'de>>(
        what: &str,
        schema: &str,
        body: &[u8],
        findings: &mut Vec<String>,
    ) {
        // The serde error can quote the offending value; report its place only.
        if let Err(e) = serde_json::from_slice::<T>(body) {
            findings.push(format!(
                "{what}: not a strict {schema} ({:?} error at line {} column {})",
                e.classify(),
                e.line(),
                e.column()
            ));
        }
    }

    pub fn json_type(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "a boolean",
            Value::Number(n) if n.is_u64() => "an unsigned integer",
            Value::Number(n) if n.is_i64() => "a negative integer",
            Value::Number(_) => "a float",
            Value::String(_) => "a string",
            Value::Array(_) => "an array",
            Value::Object(_) => "an object",
        }
    }

    /// Strict RFC 3339 (`T`, `Z` uppercase, 1-9 fraction digits), bounded.
    pub fn strict_timestamp(s: &str) -> bool {
        let b = s.as_bytes();
        if !(20..=MAX_TIMESTAMP_LEN).contains(&b.len()) {
            return false;
        }
        let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
        if !(digits(0..4)
            && b[4] == b'-'
            && digits(5..7)
            && b[7] == b'-'
            && digits(8..10)
            && b[10] == b'T'
            && digits(11..13)
            && b[13] == b':'
            && digits(14..16)
            && b[16] == b':'
            && digits(17..19))
        {
            return false;
        }
        let mut i = 19;
        if b[i] == b'.' {
            let start = i + 1;
            i = start;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if !(1..=9).contains(&(i - start)) {
                return false;
            }
        }
        let zone = &b[i..];
        let zone_ok = zone == b"Z"
            || (zone.len() == 6
                && matches!(zone[0], b'+' | b'-')
                && zone[1..3].iter().all(u8::is_ascii_digit)
                && zone[3] == b':'
                && zone[4..6].iter().all(u8::is_ascii_digit));
        zone_ok
            && time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                .is_ok()
    }

    /// Canonical padded standard base64 of exactly `len` bytes.
    pub fn canonical_b64(s: &str, len: usize) -> Option<Vec<u8>> {
        let bytes = base64::decode_config(s, base64::STANDARD).ok()?;
        (bytes.len() == len && base64::encode_config(&bytes, base64::STANDARD) == s)
            .then_some(bytes)
    }

    fn age_recipient(s: &str) -> bool {
        let data = s
            .strip_prefix("age1yubikey1")
            .or_else(|| s.strip_prefix("age1tag1"))
            .or_else(|| s.strip_prefix("age1"));
        data.is_some_and(|d| (40..=90).contains(&d.len()) && d.chars().all(|c| BECH32.contains(c)))
    }

    fn holder_name(s: &str) -> bool {
        (1..=32).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    }

    /// An ASCII-armored age file (64-column standard base64) whose payload
    /// starts with the age v1 header.
    pub fn age_armor(s: &str) -> bool {
        if s.len() > MAX_CIPHERTEXT {
            return false;
        }
        let Some(body) = s
            .strip_prefix(ARMOR_BEGIN)
            .map(|b| b.strip_suffix('\n').unwrap_or(b))
            .and_then(|b| b.strip_suffix(ARMOR_END))
        else {
            return false;
        };
        let Some(body) = body.strip_suffix('\n') else {
            return false;
        };
        let lines: Vec<&str> = body.split('\n').collect();
        let shaped = lines.iter().enumerate().all(|(i, line)| {
            let full = i + 1 < lines.len();
            (if full {
                line.len() == 64
            } else {
                (1..=64).contains(&line.len())
            }) && line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        });
        shaped
            && base64::decode_config(lines.concat(), base64::STANDARD)
                .is_ok_and(|bin| bin.starts_with(AGE_MAGIC))
    }

    /// Typed field checks; findings name the field and the JSON type found,
    /// never the value (it could be key material).
    struct Fields<'a> {
        what: &'a str,
        map: &'a Map<String, Value>,
        findings: &'a mut Vec<String>,
    }

    impl Fields<'_> {
        fn bad(&mut self, field: &str, expected: &str) {
            let map = self.map;
            let found = map.get(field).map_or("nothing", json_type);
            self.findings.push(format!(
                "{}: field `{field}` must be {expected}, found {found}",
                self.what
            ));
        }

        fn exact(&mut self, names: &[&str]) {
            let map = self.map;
            let want: BTreeSet<&str> = names.iter().copied().collect();
            let extra = map.keys().filter(|k| !want.contains(k.as_str())).count();
            let missing: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| !map.contains_key(*n))
                .collect();
            if extra > 0 || !missing.is_empty() {
                self.findings.push(format!(
                    "{}: fields must be exactly {names:?}; {extra} unknown field(s), missing {missing:?}",
                    self.what
                ));
            }
        }

        fn int(&mut self, field: &str, want: u64) {
            let map = self.map;
            if map.get(field).and_then(Value::as_u64) != Some(want) {
                self.bad(field, &format!("the integer {want}"));
            }
        }

        fn u32_min(&mut self, field: &str, min: u32) -> Option<u32> {
            let map = self.map;
            let value = map
                .get(field)
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n >= min);
            if value.is_none() {
                self.bad(field, &format!("an integer in {min}..={}", u32::MAX));
            }
            value
        }

        fn hex<const N: usize>(&mut self, field: &str) -> Option<[u8; N]> {
            let map = self.map;
            let value = map
                .get(field)
                .and_then(Value::as_str)
                .and_then(lower_hex::<N>);
            if value.is_none() {
                self.bad(field, &format!("{} lowercase hex characters", 2 * N));
            }
            value
        }

        fn base64(&mut self, field: &str, len: usize) -> Option<Vec<u8>> {
            let map = self.map;
            let value = map
                .get(field)
                .and_then(Value::as_str)
                .and_then(|s| canonical_b64(s, len));
            if value.is_none() {
                self.bad(field, &format!("canonical padded base64 of {len} bytes"));
            }
            value
        }

        fn nullable_base64(&mut self, field: &str, len: usize) -> Option<Option<Vec<u8>>> {
            let map = self.map;
            let value = match map.get(field) {
                Some(Value::Null) => Some(None),
                Some(Value::String(s)) => canonical_b64(s, len).map(Some),
                _ => None,
            };
            if value.is_none() {
                self.bad(
                    field,
                    &format!("null or canonical padded base64 of {len} bytes"),
                );
            }
            value
        }

        fn string(
            &mut self,
            field: &str,
            check: fn(&str) -> bool,
            expected: &str,
        ) -> Option<String> {
            let map = self.map;
            let value = map
                .get(field)
                .and_then(Value::as_str)
                .filter(|s| check(s))
                .map(str::to_owned);
            if value.is_none() {
                self.bad(field, expected);
            }
            value
        }

        fn timestamp(&mut self, field: &str) -> Option<String> {
            self.string(field, strict_timestamp, "a strict RFC 3339 timestamp")
        }

        fn equals(&mut self, field: &str, want: &Value, expected: &str) {
            let map = self.map;
            if map.get(field) != Some(want) {
                self.bad(field, expected);
            }
        }

        fn finding(&mut self, text: String) {
            self.findings.push(format!("{}: {text}", self.what));
        }
    }

    pub struct ArkDoc {
        pub key: String,
        pub generation: u32,
        pub ark_id: [u8; 16],
        pub sealed: Vec<u8>,
        pub chain: Option<Vec<u8>>,
    }

    pub struct DekDoc {
        pub key: String,
        pub tag: String,
        pub dek_id: u32,
        pub generation: u32,
        pub wrapped: Vec<u8>,
    }

    pub struct ShareDoc {
        pub index: u8,
        pub holder: String,
        pub recipient: String,
        pub commitment: Key,
        pub ciphertext: String,
    }

    pub struct BundleDoc {
        pub key: String,
        pub name_efp: Key,
        pub ark_id: [u8; 16],
        pub generation: u32,
        pub canary_fp: Key,
        pub shares: Vec<ShareDoc>,
    }

    pub struct RecordDoc {
        pub key: String,
        pub efp: Key,
        pub ark_id: [u8; 16],
        pub generation: u32,
        pub canary_fp: Key,
        pub verified_at: String,
        pub mac: Key,
    }

    fn ark_doc(
        what: &str,
        key: &str,
        map: &Map<String, Value>,
        name: (u32, [u8; 16]),
        findings: &mut Vec<String>,
    ) -> Option<ArkDoc> {
        let mut f = Fields {
            what,
            map,
            findings,
        };
        f.exact(&[
            "version",
            "generation",
            "ark_id",
            "w_label",
            "sealed",
            "chain",
            "created_at",
        ]);
        f.int("version", MIRROR_VERSION);
        let generation = f.u32_min("generation", 1);
        let ark_id = f.hex::<16>("ark_id");
        f.equals(
            "w_label",
            &json!(W_LABEL),
            &format!("the string {W_LABEL:?}"),
        );
        let sealed = f.base64("sealed", SEALED_LEN);
        let chain = f.nullable_base64("chain", SEALED_LEN);
        f.timestamp("created_at");
        if generation.is_some_and(|g| g != name.0) || ark_id.is_some_and(|id| id != name.1) {
            f.finding("generation/ark_id differ from the object name".into());
        }
        Some(ArkDoc {
            key: key.to_owned(),
            generation: generation?,
            ark_id: ark_id?,
            sealed: sealed?,
            chain: chain?,
        })
    }

    fn dek_doc(
        what: &str,
        key: &str,
        map: &Map<String, Value>,
        name: (String, u32),
        findings: &mut Vec<String>,
    ) -> Option<DekDoc> {
        let mut f = Fields {
            what,
            map,
            findings,
        };
        f.exact(&["version", "dek_id", "generation", "wrapped", "created_at"]);
        f.int("version", MIRROR_VERSION);
        let dek_id = f.u32_min("dek_id", 1);
        let generation = f.u32_min("generation", 1);
        let wrapped = f.base64("wrapped", SEALED_LEN);
        f.timestamp("created_at");
        if dek_id.is_some_and(|id| id != name.1) {
            f.finding("dek_id differs from the object name".into());
        }
        Some(DekDoc {
            key: key.to_owned(),
            tag: name.0,
            dek_id: dek_id?,
            generation: generation?,
            wrapped: wrapped?,
        })
    }

    fn bundle_doc(
        what: &str,
        key: &str,
        map: &Map<String, Value>,
        name_efp: Key,
        findings: &mut Vec<String>,
    ) -> Option<BundleDoc> {
        let mut f = Fields {
            what,
            map,
            findings,
        };
        f.exact(&[
            "version",
            "ark_id",
            "generation",
            "threshold",
            "canary_fp",
            "shares",
        ]);
        f.int("version", MIRROR_VERSION);
        let ark_id = f.hex::<16>("ark_id");
        let generation = f.u32_min("generation", 1);
        f.int("threshold", THRESHOLD);
        let canary_fp = f.hex::<32>("canary_fp");
        let mut shares = Vec::new();
        match map.get("shares") {
            Some(Value::Array(items)) if items.len() == HOLDERS => {
                for (i, item) in items.iter().enumerate() {
                    let share_what = format!("{what} share {}", i + 1);
                    let Value::Object(share) = item else {
                        f.finding(format!(
                            "share {} must be an object, found {}",
                            i + 1,
                            json_type(item)
                        ));
                        continue;
                    };
                    let mut s = Fields {
                        what: &share_what,
                        map: share,
                        findings: &mut *f.findings,
                    };
                    s.exact(&["index", "holder", "recipient", "commitment", "ciphertext"]);
                    s.int("index", i as u64 + 1);
                    let holder = s.string("holder", holder_name, "1-32 characters of a-z 0-9 - _");
                    let recipient = s.string(
                        "recipient",
                        age_recipient,
                        "an age1/age1yubikey1/age1tag1 bech32 recipient",
                    );
                    let commitment = s.hex::<32>("commitment");
                    let ciphertext = s.string("ciphertext", age_armor, "an ASCII-armored age file");
                    if let (Some(holder), Some(recipient), Some(commitment), Some(ciphertext)) =
                        (holder, recipient, commitment, ciphertext)
                    {
                        shares.push(ShareDoc {
                            index: i as u8 + 1,
                            holder,
                            recipient,
                            commitment,
                            ciphertext,
                        });
                    }
                }
            }
            _ => f.bad("shares", &format!("an array of {HOLDERS} share objects")),
        }
        let holders: BTreeSet<&str> = shares.iter().map(|s| s.holder.as_str()).collect();
        let recipients: BTreeSet<&str> = shares.iter().map(|s| s.recipient.as_str()).collect();
        if shares.len() == HOLDERS && (holders.len() != HOLDERS || recipients.len() != HOLDERS) {
            f.finding("holders and recipients must be unique".into());
        }
        (shares.len() == HOLDERS).then_some(())?;
        Some(BundleDoc {
            key: key.to_owned(),
            name_efp,
            ark_id: ark_id?,
            generation: generation?,
            canary_fp: canary_fp?,
            shares,
        })
    }

    fn record_doc(
        what: &str,
        key: &str,
        map: &Map<String, Value>,
        name_efp: Key,
        findings: &mut Vec<String>,
    ) -> Option<RecordDoc> {
        let mut f = Fields {
            what,
            map,
            findings,
        };
        f.exact(&[
            "version",
            "efp",
            "ark_id",
            "generation",
            "verified_indices",
            "pairs",
            "canary_fp",
            "app_id",
            "compose_hash",
            "verified_at",
            "mac",
        ]);
        f.int("version", MIRROR_VERSION);
        let efp = f.hex::<32>("efp");
        let ark_id = f.hex::<16>("ark_id");
        let generation = f.u32_min("generation", 1);
        f.equals(
            "verified_indices",
            &json!([1, 2, 3]),
            "the integers [1, 2, 3]",
        );
        f.equals(
            "pairs",
            &json!([[1, 2], [1, 3], [2, 3]]),
            "the pairs [[1, 2], [1, 3], [2, 3]]",
        );
        let canary_fp = f.hex::<32>("canary_fp");
        // The harness runs a Static-root node outside a TEE: no TEE identity.
        f.equals("app_id", &Value::Null, "null (no TEE)");
        f.equals("compose_hash", &Value::Null, "null (no TEE)");
        let verified_at = f.timestamp("verified_at");
        let mac = f.hex::<32>("mac");
        if efp.is_some_and(|e| e != name_efp) {
            f.finding("efp differs from the object name".into());
        }
        Some(RecordDoc {
            key: key.to_owned(),
            efp: efp?,
            ark_id: ark_id?,
            generation: generation?,
            canary_fp: canary_fp?,
            verified_at: verified_at?,
            mac: mac?,
        })
    }

    /// The escrow fingerprint (bundle.rs `EscrowBundle::fingerprint`).
    pub fn bundle_efp(b: &BundleDoc) -> Key {
        let mut pre = Vec::new();
        lp(&mut pre, EFP_DOMAIN);
        pre.extend_from_slice(&(MIRROR_VERSION as u32).to_be_bytes());
        pre.extend_from_slice(&b.ark_id);
        pre.extend_from_slice(&b.generation.to_be_bytes());
        pre.push(THRESHOLD as u8);
        pre.extend_from_slice(&b.canary_fp);
        pre.push(u8::try_from(b.shares.len()).unwrap_or(u8::MAX));
        for s in &b.shares {
            pre.push(s.index);
            lp(&mut pre, s.holder.as_bytes());
            lp(&mut pre, s.recipient.as_bytes());
            pre.extend_from_slice(&s.commitment);
            pre.extend_from_slice(&sha256(s.ciphertext.as_bytes()));
        }
        sha256(&pre)
    }

    /// The verification record's MAC (record.rs `compute_mac`), with no TEE
    /// identity (`app_id`, `compose_hash` null).
    pub fn record_mac(ark: &Key, r: &RecordDoc) -> Key {
        let mut info = Vec::new();
        lp(&mut info, MAC_INFO);
        let key = escrow_key(ark, &r.ark_id, &info);
        let mut body = Vec::new();
        body.extend_from_slice(&(MIRROR_VERSION as u32).to_be_bytes());
        body.extend_from_slice(&r.efp);
        body.extend_from_slice(&r.ark_id);
        body.extend_from_slice(&r.generation.to_be_bytes());
        lp(&mut body, &[1, 2, 3]);
        lp(&mut body, &[1, 2, 1, 3, 2, 3]);
        body.extend_from_slice(&r.canary_fp);
        body.extend_from_slice(&[0, 0]);
        lp(&mut body, r.verified_at.as_bytes());
        hmac_sha256(&key, &[&body])
    }

    // ---- raw-key scan (ruling 3 backstop) ---------------------------------

    const KEY_PREFIXES: [&str; 2] = ["0x", "\\x"];

    /// RFC 4648 base32 (either case, padding optional).
    pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
        let (mut bits, mut acc, mut out) = (0u32, 0u64, Vec::new());
        for c in s.trim_end_matches('=').bytes() {
            let value = match c.to_ascii_uppercase() {
                upper @ b'A'..=b'Z' => upper - b'A',
                digit @ b'2'..=b'7' => digit - b'2' + 26,
                _ => return None,
            };
            acc = (acc << 5) | u64::from(value);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Some(out)
    }

    /// Every byte string `s` decodes to as hex, base64, base64url (padded or
    /// not) or base32, after removing whitespace and optionally a prefix:
    /// `0x`, `\x`, any short `label:` (`base64:`, `k:`, …) or a
    /// `data:…;base64,` URL head.
    pub fn decodings(s: &str) -> Vec<Vec<u8>> {
        let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = compact.to_ascii_lowercase();
        let mut candidates = vec![compact.as_str()];
        for prefix in KEY_PREFIXES {
            if lower.starts_with(prefix) {
                candidates.push(&compact[prefix.len()..]);
            }
        }
        if let Some((label, rest)) = compact.split_once(':') {
            if (1..=16).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                candidates.push(rest);
            }
        }
        if let Some(at) = lower.find(";base64,") {
            candidates.push(&compact[at + ";base64,".len()..]);
        }
        let mut out = Vec::new();
        for candidate in candidates.into_iter().filter(|c| !c.is_empty()) {
            if let Ok(bytes) = hex::decode(candidate) {
                out.push(bytes);
            }
            for config in [
                base64::STANDARD,
                base64::STANDARD_NO_PAD,
                base64::URL_SAFE,
                base64::URL_SAFE_NO_PAD,
            ] {
                if let Ok(bytes) = base64::decode_config(candidate, config) {
                    out.push(bytes);
                }
            }
            out.extend(base32_decode(candidate));
        }
        out
    }

    /// A path component that never echoes a long or unusual JSON key.
    fn component(key: &str, i: usize) -> String {
        if key.len() <= 24 && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            key.to_owned()
        } else {
            format!("<key #{i}>")
        }
    }

    fn byte_array(items: &[Value]) -> bool {
        items.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255))
    }

    /// Which fields the raw-key scan leaves alone.
    #[derive(Clone, Copy)]
    struct Exempt<'a> {
        /// Exact encodings the schema checked: no 32-byte or 16-byte check.
        encoded: &'a [&'a str],
        /// Checked exactly by the schema, but short enough to be 16 bytes by
        /// chance (escrow holder names): no 16+16 split check.
        halves: &'a [&'a str],
    }

    struct Scan {
        halves: Vec<String>,
        found: Vec<String>,
    }

    fn scan_string(s: &str, at: String, is_key: bool, exempt: Exempt, scan: &mut Scan) {
        if !is_key && exempt.encoded.contains(&at.as_str()) {
            return;
        }
        let lens: BTreeSet<usize> = decodings(s).iter().map(Vec::len).collect();
        let longest = lens.last().copied().unwrap_or(0);
        let place = if is_key {
            format!("a JSON key in `{at}`")
        } else {
            format!("`{at}`")
        };
        if lens.contains(&32) {
            scan.found
                .push(format!("{place} decodes to 32 bytes (a raw key's size)"));
        } else if longest > 32 {
            scan.found.push(format!(
                "{place} decodes to {longest} bytes (more than a raw key)"
            ));
        } else if lens.contains(&16) && (is_key || !exempt.halves.contains(&at.as_str())) {
            scan.halves.push(place);
        }
    }

    fn walk(value: &Value, path: &str, exempt: Exempt, scan: &mut Scan) {
        match value {
            Value::Object(map) => {
                let here = if path.is_empty() {
                    "/".to_owned()
                } else {
                    path.to_owned()
                };
                for (i, (key, child)) in map.iter().enumerate() {
                    scan_string(key, here.clone(), true, exempt, scan);
                    let name = component(key, i);
                    let at = if path.is_empty() {
                        name
                    } else {
                        format!("{path}.{name}")
                    };
                    walk(child, &at, exempt, scan);
                }
            }
            Value::Array(items) if items.len() == 32 && byte_array(items) => {
                scan.found.push(format!(
                    "`{path}` is an array of 32 byte values (a raw key)"
                ));
            }
            Value::Array(items) if items.len() == 16 && byte_array(items) => {
                scan.halves.push(format!("`{path}` (16 byte values)"));
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, &format!("{path}[]"), exempt, scan);
                }
            }
            Value::String(s) => scan_string(s, path.to_owned(), false, exempt, scan),
            _ => {}
        }
    }

    /// Every JSON key and every string outside the exact-encoding fields
    /// must not decode to 32 bytes or more; no array may be 32 byte values;
    /// no two fields (outside `halves`) may hold 16 bytes each (a split key).
    pub fn raw_key_findings(
        what: &str,
        doc: &Value,
        encoded: &[&str],
        halves: &[&str],
    ) -> Vec<String> {
        let mut scan = Scan {
            halves: Vec::new(),
            found: Vec::new(),
        };
        walk(doc, "", Exempt { encoded, halves }, &mut scan);
        let mut findings: Vec<String> = scan
            .found
            .into_iter()
            .map(|f| format!("{what}: {f}"))
            .collect();
        if scan.halves.len() >= 2 {
            findings.push(format!(
                "{what}: {} hold 16 bytes each (a 32-byte key split across fields)",
                scan.halves.join(", ")
            ));
        }
        findings
    }

    // ---- derived secrets in mirror contents (round 5, ruling 1) ------------

    /// A secret the harness re-derived (or unwrapped) from its Static root.
    pub struct Secret {
        pub label: String,
        pub bytes: Vec<u8>,
    }

    /// Every string of a mirror document (values and JSON keys) with its
    /// path, plus the escrow holder names concatenated pairwise and all in
    /// order (a key split across holders).
    fn strings(doc: &Value) -> Vec<(String, String)> {
        fn collect(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
            match value {
                Value::Object(map) => {
                    for (i, (key, child)) in map.iter().enumerate() {
                        let name = component(key, i);
                        let at = if path.is_empty() {
                            name
                        } else {
                            format!("{path}.{name}")
                        };
                        out.push((format!("a JSON key in `{at}`"), key.clone()));
                        collect(child, &at, out);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        collect(item, &format!("{path}[]"), out);
                    }
                }
                Value::String(s) => out.push((format!("`{path}`"), s.clone())),
                _ => {}
            }
        }
        let mut out = Vec::new();
        collect(doc, "", &mut out);
        let holders: Vec<&str> = doc["shares"]
            .as_array()
            .map(|shares| shares.iter().filter_map(|s| s["holder"].as_str()).collect())
            .unwrap_or_default();
        for (i, a) in holders.iter().enumerate() {
            for (j, b) in holders.iter().enumerate() {
                if i != j {
                    out.push((format!("holders {} + {}", i + 1, j + 1), format!("{a}{b}")));
                }
            }
        }
        if holders.len() > 2 {
            out.push(("all holders in order".into(), holders.concat()));
        }
        out
    }

    /// The bytes an armored age file carries (its base64 body), if `s` is one.
    fn armor_payload(s: &str) -> Option<Vec<u8>> {
        let body: String = s
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        s.starts_with("-----BEGIN")
            .then(|| base64::decode_config(body, base64::STANDARD).ok())
            .flatten()
    }

    /// Findings for any string of `doc` that carries one of `secrets`: in its
    /// text as hex, base64 or base64url (any alignment), or in any decoding
    /// of it (hex, base64, base64url, base32, an armored age payload).
    pub fn secret_findings(what: &str, doc: &Value, secrets: &[Secret]) -> Vec<String> {
        let mut findings = BTreeSet::new();
        for (place, text) in strings(doc) {
            let mut decoded = decodings(&text);
            decoded.extend(armor_payload(&text));
            decoded.push(text.as_bytes().to_vec());
            let lower = text.to_ascii_lowercase();
            for secret in secrets {
                let in_text = lower.contains(&hex::encode(&secret.bytes))
                    || [base64::STANDARD_NO_PAD, base64::URL_SAFE_NO_PAD]
                        .into_iter()
                        .flat_map(|config| super::base64_cores(&secret.bytes, config))
                        .any(|core| text.contains(&core));
                let in_bytes = decoded
                    .iter()
                    .any(|bytes| super::find(bytes, &secret.bytes).is_some());
                if in_text || in_bytes {
                    findings.insert(format!(
                        "{what}: {place} carries the harness-derived {} (raw key material)",
                        secret.label
                    ));
                }
            }
        }
        findings.into_iter().collect()
    }

    // ---- one snapshot -------------------------------------------------------

    pub struct ObjectRef<'a> {
        pub key: &'a str,
        pub body: &'a [u8],
    }

    /// How the harness started the node (state.json `at_rest`).
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Policy {
        /// Mode `encrypt` or `strict`: blocks must be sealed and backed by
        /// mirrors (round 5, ruling 4).
        pub encrypt: bool,
        /// `escrow_none = true`: no escrow bundle or record may exist.
        pub escrow_none: bool,
    }

    /// ARK generations beyond this are refused outright (INTERFACES: 1..=9),
    /// so an absurd name can't make the generation checks loop or allocate.
    pub const MAX_ARK_GENERATION: u32 = 9;

    /// `NK = HKDF(ARK_1, "tinycloud/at-rest/object-names/v1")`.
    pub fn object_name_key(ark_1: &Key) -> Key {
        hkdf32(None, ark_1, NK_INFO)
    }

    /// A space's sealed-block name prefix (names.rs `space_tag`):
    /// `b64url(HMAC(NK, lp("space") ‖ lp(space))[..16])`.
    pub fn space_tag(nk: &Key, space: &str) -> String {
        let mut msg = Vec::new();
        lp(&mut msg, b"space");
        lp(&mut msg, space.as_bytes());
        base64::encode_config(&hmac_sha256(nk, &[&msg])[..16], base64::URL_SAFE_NO_PAD)
    }

    /// Every `_tc/` object of one bucket snapshot: an allowed name, an exact
    /// typed schema, no raw or harness-derived key, and authentic key
    /// material under the harness's Static `root`, with DEK tags mapped to
    /// `spaces`. In encrypt mode, every block in `blocks` must be sealed and
    /// belong to a space whose DEK mirror authenticates.
    pub fn check_snapshot(
        label: &str,
        objects: &[ObjectRef],
        blocks: &[&str],
        root: &[u8],
        spaces: &[String],
        policy: Policy,
    ) -> Vec<String> {
        let mut findings = Vec::new();
        let mut arks: Vec<ArkDoc> = Vec::new();
        let mut deks: Vec<DekDoc> = Vec::new();
        let mut bundles: Vec<BundleDoc> = Vec::new();
        let mut records: Vec<RecordDoc> = Vec::new();
        let mut docs: Vec<(String, Value)> = Vec::new();
        for object in objects {
            let what = format!("[{label}] at-rest control object {:?}", object.key);
            let Some(kind) = parse_name(object.key) else {
                findings.push(format!(
                    "{what}: not an allowed mirror name ({PREFIX}ark-<10 digits>-<32 hex>.json, \
                     escrow-<64 hex>.json, record-<64 hex>.json or dek-<32 hex>-<10 digits>.json)"
                ));
                continue;
            };
            if policy.escrow_none && matches!(kind, Kind::Escrow { .. } | Kind::Record { .. }) {
                findings.push(format!(
                    "{what}: the node runs with escrow_none, so no escrow bundle or record may exist"
                ));
            }
            let doc: Value = match serde_json::from_slice(object.body) {
                Ok(doc) => doc,
                Err(e) => {
                    findings.push(format!(
                        "{what}: not JSON ({:?} error at line {} column {})",
                        e.classify(),
                        e.line(),
                        e.column()
                    ));
                    continue;
                }
            };
            let Value::Object(map) = &doc else {
                findings.push(format!(
                    "{what}: JSON {} where an object is required",
                    json_type(&doc)
                ));
                continue;
            };
            let (encoded, halves): (&[&str], &[&str]) = match kind {
                Kind::Ark { generation, ark_id } => {
                    strict::<StrictArk>(&what, "MirroredArk", object.body, &mut findings);
                    arks.extend(ark_doc(
                        &what,
                        object.key,
                        map,
                        (generation, ark_id),
                        &mut findings,
                    ));
                    (&["ark_id", "sealed", "chain"], &[])
                }
                Kind::Dek { tag, dek_id } => {
                    strict::<StrictDek>(&what, "MirroredDek", object.body, &mut findings);
                    deks.extend(dek_doc(
                        &what,
                        object.key,
                        map,
                        (tag, dek_id),
                        &mut findings,
                    ));
                    (&["wrapped"], &[])
                }
                Kind::Escrow { efp } => {
                    strict::<StrictBundle>(&what, "EscrowBundle", object.body, &mut findings);
                    bundles.extend(bundle_doc(&what, object.key, map, efp, &mut findings));
                    (
                        &[
                            "ark_id",
                            "canary_fp",
                            "shares[].recipient",
                            "shares[].commitment",
                            "shares[].ciphertext",
                        ],
                        &["shares[].holder"],
                    )
                }
                Kind::Record { efp } => {
                    strict::<StrictRecord>(&what, "VerificationRecord", object.body, &mut findings);
                    records.extend(record_doc(&what, object.key, map, efp, &mut findings));
                    (&["efp", "ark_id", "canary_fp", "mac"], &[])
                }
            };
            findings.extend(raw_key_findings(&what, &doc, encoded, halves));
            docs.push((what, doc));
        }
        let keys = authenticate(
            label,
            root,
            spaces,
            &arks,
            &deks,
            &bundles,
            &records,
            &mut findings,
        );
        for (what, doc) in &docs {
            findings.extend(secret_findings(what, doc, &keys.secrets));
        }
        if policy.encrypt {
            require_mirrors(label, blocks, spaces, &arks, &keys, &mut findings);
        }
        findings
    }

    /// What authentication recovered: every secret it derived or unwrapped,
    /// ARK_1 (if authentic) and the spaces whose DEK mirror authenticated.
    pub struct Recovered {
        pub secrets: Vec<Secret>,
        pub ark_1: Option<Key>,
        pub spaces_with_dek: BTreeSet<String>,
    }

    /// Round 5, ruling 4 (encrypt mode): an ARK mirror exists; every block is
    /// sealed (`v1/<space tag>/…`), its tag (from NK) names a harness space,
    /// and that space has a DEK mirror that authenticates.
    fn require_mirrors(
        label: &str,
        blocks: &[&str],
        spaces: &[String],
        arks: &[ArkDoc],
        keys: &Recovered,
        findings: &mut Vec<String>,
    ) {
        if arks.is_empty() {
            findings.push(format!(
                "[{label}] encrypt mode, but no ARK mirror is in the bucket"
            ));
        }
        if blocks.is_empty() {
            return;
        }
        let Some(ark_1) = keys.ark_1 else {
            findings.push(format!(
                "[{label}] {} block(s) but no authentic generation-1 ARK to derive the object-name key from",
                blocks.len()
            ));
            return;
        };
        let nk = object_name_key(&ark_1);
        let tags: BTreeMap<String, &String> =
            spaces.iter().map(|s| (space_tag(&nk, s), s)).collect();
        for block in blocks {
            let what = format!("[{label}] block {block:?}");
            let Some(tag) = block
                .strip_prefix("v1/")
                .and_then(|rest| rest.split_once('/'))
                .map(|(tag, _)| tag)
            else {
                findings.push(format!(
                    "{what}: encrypt mode, but the block is not named as sealed (v1/<space tag>/…)"
                ));
                continue;
            };
            match tags.get(tag) {
                None => findings.push(format!(
                    "{what}: its space tag belongs to none of the {} spaces this harness created",
                    spaces.len()
                )),
                Some(space) if !keys.spaces_with_dek.contains(*space) => findings.push(format!(
                    "{what}: its space has no DEK mirror that authenticates"
                )),
                Some(_) => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticate(
        label: &str,
        root: &[u8],
        spaces: &[String],
        arks: &[ArkDoc],
        deks: &[DekDoc],
        bundles: &[BundleDoc],
        records: &[RecordDoc],
        findings: &mut Vec<String>,
    ) -> Recovered {
        let w = wrap_key(root);
        let mut recovered = Recovered {
            secrets: vec![
                Secret {
                    label: "Static root".into(),
                    bytes: root.to_vec(),
                },
                Secret {
                    label: "wrap key W".into(),
                    bytes: w.to_vec(),
                },
            ],
            ark_1: None,
            spaces_with_dek: BTreeSet::new(),
        };
        // Bounded by the ceiling and by the mirrors found, never by a number
        // read from a name (round 5, ruling 3).
        let generations: BTreeSet<u32> = arks.iter().map(|d| d.generation).collect();
        let newest = generations.last().copied();
        if let Some(newest) = newest {
            if newest > MAX_ARK_GENERATION {
                findings.push(format!(
                    "[{label}] ARK generation {newest} is above the ceiling {MAX_ARK_GENERATION}"
                ));
            }
            if generations.len() as u64 != u64::from(newest) {
                findings.push(format!(
                    "[{label}] ARK mirrors cover {} generation(s) up to {newest}, not every generation 1..={newest}",
                    generations.len()
                ));
            }
        }
        let mut opened: BTreeMap<u32, ([u8; 16], Key)> = BTreeMap::new();
        for d in arks.iter().filter(|d| d.generation <= MAX_ARK_GENERATION) {
            match open_ark_doc(&w, d) {
                Some(ark) => match opened.get(&d.generation) {
                    Some((id, other)) if *id != d.ark_id || *other != ark => findings.push(format!(
                        "[{label}] two different ARKs are mirrored for generation {}",
                        d.generation
                    )),
                    Some(_) => {}
                    None => {
                        opened.insert(d.generation, (d.ark_id, ark));
                    }
                },
                None => findings.push(format!(
                    "[{label}] sealed ARK {:?} (generation {}) does not authenticate under W from the harness's Static root",
                    d.key, d.generation
                )),
            }
        }
        for (g, (id, ark)) in &opened {
            let mut canary_info = Vec::new();
            lp(&mut canary_info, CANARY_INFO);
            canary_info.extend_from_slice(&g.to_be_bytes());
            let mut mac_info = Vec::new();
            lp(&mut mac_info, MAC_INFO);
            for (name, bytes) in [
                ("ARK", *ark),
                ("KEK", kek(ark)),
                ("chain key", chain_key(ark)),
                ("escrow canary key", escrow_key(ark, id, &canary_info)),
                ("escrow record MAC key", escrow_key(ark, id, &mac_info)),
            ] {
                recovered.secrets.push(Secret {
                    label: format!("{name} of generation {g}"),
                    bytes: bytes.to_vec(),
                });
            }
        }
        for d in arks {
            let what = format!("[{label}] ARK {:?}", d.key);
            match (&d.chain, Some(d.generation) == newest) {
                (None, true) => {}
                (Some(_), true) => {
                    findings.push(format!("{what}: the newest generation has a chain"))
                }
                (None, false) => findings.push(format!(
                    "{what}: an older generation has no chain to the next"
                )),
                (Some(chain), false) => {
                    let next = d.generation.saturating_add(1);
                    let opens = match (opened.get(&next), opened.get(&d.generation)) {
                        (Some((newer_id, newer)), Some((_, older))) => {
                            open32(
                                &chain_key(newer),
                                &chain_aad(&d.ark_id, d.generation, newer_id),
                                chain,
                            )
                            .as_ref()
                                == Some(older)
                        }
                        _ => false,
                    };
                    if !opens {
                        findings.push(format!("{what}: its chain does not open to this generation's ARK under the next one"));
                    }
                }
            }
        }
        let Some((_, ark_1)) = opened.get(&1) else {
            if !(deks.is_empty() && bundles.is_empty() && records.is_empty()) {
                findings.push(format!(
                    "[{label}] {} DEK, {} escrow and {} record mirror(s) but no authentic generation-1 ARK to check them against",
                    deks.len(),
                    bundles.len(),
                    records.len()
                ));
            }
            return recovered;
        };
        recovered.ark_1 = Some(*ark_1);
        let tag_key = hkdf32(None, ark_1, DEK_TAG_INFO);
        for (name, bytes) in [
            ("object-name key NK", object_name_key(ark_1)),
            ("DEK mirror tag key", tag_key),
        ] {
            recovered.secrets.push(Secret {
                label: name.into(),
                bytes: bytes.to_vec(),
            });
        }
        let tags: BTreeMap<String, &String> =
            spaces.iter().map(|s| (dek_tag(ark_1, s), s)).collect();
        for d in deks {
            let what = format!("[{label}] DEK {:?}", d.key);
            let Some(space) = tags.get(&d.tag) else {
                findings.push(format!(
                    "{what}: its tag belongs to none of the {} spaces this harness created",
                    spaces.len()
                ));
                continue;
            };
            let Some((ark_id, ark)) = opened.get(&d.generation) else {
                findings.push(format!(
                    "{what}: wrapped under generation {}, which has no authentic ARK",
                    d.generation
                ));
                continue;
            };
            match open32(
                &kek(ark),
                &dek_aad(space, d.dek_id, d.generation, ark_id),
                &d.wrapped,
            ) {
                Some(dek) => {
                    recovered.spaces_with_dek.insert((*space).clone());
                    recovered.secrets.push(Secret {
                        label: format!("DEK {} of a harness space", d.dek_id),
                        bytes: dek.to_vec(),
                    });
                }
                None => findings.push(format!(
                    "{what}: the wrapped DEK does not authenticate under KEK_{} with its AAD (space, dek_id, generation, ark_id)",
                    d.generation
                )),
            }
        }
        for b in bundles {
            let what = format!("[{label}] escrow bundle {:?}", b.key);
            match opened.get(&b.generation) {
                Some((id, ark)) if *id == b.ark_id => {
                    if canary_fp(ark, id, b.generation) != b.canary_fp {
                        findings.push(format!("{what}: canary_fp is not this generation's canary"));
                    }
                }
                _ => findings.push(format!("{what}: names no authentic ARK generation and id")),
            }
            if bundle_efp(b) != b.name_efp {
                findings.push(format!(
                    "{what}: the name's EFP is not the bundle's fingerprint"
                ));
            }
        }
        for r in records {
            let what = format!("[{label}] verification record {:?}", r.key);
            let Some(b) = bundles
                .iter()
                .find(|b| b.name_efp == r.efp && bundle_efp(b) == r.efp)
            else {
                findings.push(format!("{what}: no mirrored escrow bundle has its EFP"));
                continue;
            };
            if (r.ark_id, r.generation, r.canary_fp) != (b.ark_id, b.generation, b.canary_fp) {
                findings.push(format!(
                    "{what}: ark_id, generation or canary_fp differ from its bundle"
                ));
            }
            match opened.get(&r.generation) {
                Some((id, ark)) if *id == r.ark_id && record_mac(ark, r) == r.mac => {}
                _ => findings.push(format!(
                    "{what}: its MAC does not verify under the generation's ARK"
                )),
            }
        }
        recovered
    }

    fn open_ark_doc(w: &Key, d: &ArkDoc) -> Option<Key> {
        open32(w, &seal_aad(&d.ark_id, d.generation, W_LABEL), &d.sealed)
    }
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
    /// Per probe (same order as [`KvRun::probes`]): the block objects it
    /// created. Control objects (`_tc/…`, e.g. the space's wrapped data key
    /// on its first sealed write) are not KV data, so they are not paired or
    /// size-checked here; the RED check reads every one of them from the
    /// boot and after-put snapshots instead.
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
        if key.starts_with(key_mirror::CONTROL_PREFIX) {
            continue;
        }
        let body = harness.object(key).await?;
        ensure!(!body.is_empty(), "new object {key} is empty");
        objects.push(StoredObject {
            key: key.clone(),
            body,
        });
    }
    if objects.is_empty() {
        bail!(
            "harness no-op: the {}-byte KV put to {}/{path} created no block object in the MinIO bucket",
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
    /// Bytes of the smaller 64 KiB value; every payload and delta holds one.
    big_len: usize,
    spaces: Vec<SqlSpace>,
}

async fn sql_run(harness: &Harness) -> Result<SqlRun> {
    let markers = [marker("SQL-WRITE1"), marker("SQL-WRITE2")];
    let big = [
        repeated(&markers[0], BIG_VALUE_LEN),
        repeated(&markers[1], BIG_VALUE_LEN),
    ];
    let big_len = big[0].len().min(big[1].len());
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
    Ok(SqlRun {
        markers,
        big_len,
        spaces,
    })
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
    let spaces = harness.known_spaces()?;
    let identities: Vec<IdentityForm> = spaces.iter().flat_map(|s| identity_forms(s)).collect();
    let fingerprints: Vec<(&str, Fingerprint)> = run
        .probes
        .iter()
        .flat_map(|(label, value)| {
            fingerprints(value.as_bytes())
                .into_iter()
                .map(move |fp| (*label, fp))
        })
        .collect();
    for space in &run.spaces {
        let space_id = space.account.space.to_string();
        for ((label, value), objects) in run.probes.iter().zip(&space.objects) {
            check_size_floor(
                &format!("KV {label} put for {space_id}: its new object(s) in total"),
                objects.iter().map(|object| object.body.len()).sum(),
                value.len(),
                &mut findings,
            );
            for object in objects {
                findings.extend(content_findings(
                    object,
                    false,
                    &run.marker,
                    &fingerprints,
                    &identities,
                ));
                if *label == "compressible" {
                    check_incompressible(
                        &format!("raw object {:?} [{label} value]", object.key),
                        &object.body,
                        &mut findings,
                    )?;
                }
            }
        }
    }
    // Control objects (`_tc/…`) as the node left them at boot and after the
    // puts: the same name and content scans (also over their text), then an
    // exact name, an exact typed schema, no raw or harness-derived key,
    // authentic key material under the harness's Static root and, in
    // encrypt mode, a mirror behind every sealed block.
    let after_blocks: Vec<String> = harness
        .keys()
        .await?
        .into_iter()
        .filter(|key| !key.starts_with(key_mirror::CONTROL_PREFIX))
        .collect();
    let boot = harness.boot_objects()?;
    let boot_blocks: Vec<String> = boot
        .iter()
        .filter(|o| !o.key.starts_with(key_mirror::CONTROL_PREFIX))
        .map(|o| o.key.clone())
        .collect();
    for (snapshot, objects, blocks) in [
        ("boot", boot, boot_blocks),
        (
            "after the puts",
            harness.control_objects().await?,
            after_blocks,
        ),
    ] {
        for object in &objects {
            findings.extend(content_findings(
                object,
                true,
                &run.marker,
                &fingerprints,
                &identities,
            ));
        }
        let control: Vec<key_mirror::ObjectRef> = objects
            .iter()
            .filter(|o| o.key.starts_with(key_mirror::CONTROL_PREFIX))
            .map(|o| key_mirror::ObjectRef {
                key: &o.key,
                body: &o.body,
            })
            .collect();
        let blocks: Vec<&str> = blocks.iter().map(String::as_str).collect();
        println!(
            "[{snapshot}] {} control object(s), {} block(s) checked ({:?})",
            control.len(),
            blocks.len(),
            harness.policy
        );
        findings.extend(key_mirror::check_snapshot(
            snapshot,
            &control,
            &blocks,
            &harness.root,
            &spaces,
            harness.policy,
        ));
    }
    // Compare every object of a put in space A with every object of the same
    // put in space B: sealed names sort randomly, so no pairing by order.
    for (index, (label, _)) in run.probes.iter().enumerate() {
        let a = &run.spaces[0].objects[index];
        let b = &run.spaces[1].objects[index];
        ensure!(
            a.len() == b.len(),
            "harness: the same KV {label} put created {} object(s) in {} but {} in {}",
            a.len(),
            run.spaces[0].account.space,
            b.len(),
            run.spaces[1].account.space
        );
        for a in a {
            for b in b {
                compare_writes(
                    &format!("KV {label} value ({:?} vs {:?})", a.key, b.key),
                    &a.body,
                    &b.body,
                    &mut findings,
                );
            }
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
            check_size_floor(
                &format!("{id}.{column}"),
                bytes.len(),
                run.big_len,
                &mut findings,
            );
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
/// are flagged even with the marker and magic gone, a compressed-only blob is
/// flagged by the size floor, and two sealed-like blobs of the same plaintext
/// pass every predicate.
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
    // Compressed only, with a per-write salt mixed in (like a WAL delta):
    // the size floor still catches it.
    let deflate_best = |bytes: &[u8]| -> Result<Vec<u8>> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(bytes)?;
        Ok(encoder.finish()?)
    };
    let salted = deflate_best(&[random_bytes(32), plaintext.clone()].concat())?;
    let mut findings = Vec::new();
    check_size_floor("deflate-9", salted.len(), plaintext.len(), &mut findings);
    ensure!(
        findings.len() == 1,
        "a {}-byte compressed-only blob of {} bytes passed the size floor",
        salted.len(),
        plaintext.len()
    );
    for len in [62, BIG_VALUE_LEN] {
        let (a, b) = (sealed_like(len), sealed_like(len));
        let mut findings = Vec::new();
        compare_writes("sealed", &a, &b, &mut findings);
        check_size_floor("sealed", a.len(), len, &mut findings);
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

fn random_key() -> key_mirror::Key {
    random_bytes(32).try_into().expect("32 bytes")
}

fn random_nonce() -> [u8; 12] {
    random_bytes(12).try_into().expect("12 bytes")
}

fn standard_b64(bytes: &[u8]) -> String {
    base64::encode_config(bytes, base64::STANDARD)
}

/// A Static root and the mirror objects an S1 node writes for it, built with
/// this file's reference sealing (random nonces), not the node's code: ARK
/// generations 1 and 2 (1 chained under 2), a DEK in each of two spaces (one
/// per generation), and generation 2's escrow bundle with its record.
struct MirrorFixture {
    root: Vec<u8>,
    spaces: Vec<String>,
    keys: FixtureKeys,
    objects: Vec<(String, Value)>,
}

/// The fixture's secrets, for building negative cases.
struct FixtureKeys {
    w: key_mirror::Key,
    ark_1: key_mirror::Key,
    ark_2: key_mirror::Key,
    nk: key_mirror::Key,
    /// The unwrapped DEK of each space, in `spaces` order.
    deks: Vec<key_mirror::Key>,
}

type ShareTweak = dyn Fn(&FixtureKeys, &mut [key_mirror::ShareDoc]);

impl MirrorFixture {
    fn new() -> Self {
        Self::build(&|_, _| {})
    }

    /// `tweak` edits the escrow shares before the bundle's EFP, its name and
    /// the record (EFP and MAC) are computed, so only the rule under test can
    /// flag the result.
    fn build(tweak: &ShareTweak) -> Self {
        use key_mirror::*;
        let root = random_bytes(32);
        let w = wrap_key(&root);
        let ts = "2026-10-17T10:00:00.123456789Z";
        let (ark_1, id_1, ark_2, id_2) = (random_key(), [1u8; 16], random_key(), [2u8; 16]);
        let mut keys = FixtureKeys {
            w,
            ark_1,
            ark_2,
            nk: object_name_key(&ark_1),
            deks: Vec::new(),
        };
        let ark = |generation: u32, id: &[u8; 16], key: &Key, chain: Value| {
            let sealed = seal32(&w, &seal_aad(id, generation, W_LABEL), key, random_nonce());
            json!({
                "version": 1, "generation": generation, "ark_id": hex::encode(id),
                "w_label": W_LABEL, "sealed": standard_b64(&sealed), "chain": chain,
                "created_at": ts,
            })
        };
        let chain = seal32(
            &chain_key(&ark_2),
            &chain_aad(&id_1, 1, &id_2),
            &ark_1,
            random_nonce(),
        );
        let mut objects = vec![
            (
                format!("{PREFIX}ark-{:010}-{}.json", 1, hex::encode(id_1)),
                ark(1, &id_1, &ark_1, json!(standard_b64(&chain))),
            ),
            (
                format!("{PREFIX}ark-{:010}-{}.json", 2, hex::encode(id_2)),
                ark(2, &id_2, &ark_2, Value::Null),
            ),
        ];
        let spaces = vec![
            "tinycloud:pkh:eip155:1:0x5005aE13512FEfD4745e2750329B6d09572Ee176:tc887fixturea"
                .to_owned(),
            "tinycloud:pkh:eip155:1:0x9BADDA8920399B6471BB3B89e5244964EB14Ef30:tc887fixtureb"
                .to_owned(),
        ];
        for (space, (generation, id, key)) in
            spaces.iter().zip([(1, id_1, ark_1), (2, id_2, ark_2)])
        {
            let dek = random_key();
            keys.deks.push(dek);
            let wrapped = seal32(
                &kek(&key),
                &dek_aad(space, 1, generation, &id),
                &dek,
                random_nonce(),
            );
            objects.push((
                format!("{PREFIX}dek-{}-{:010}.json", dek_tag(&ark_1, space), 1),
                json!({
                    "version": 1, "dek_id": 1, "generation": generation,
                    "wrapped": standard_b64(&wrapped), "created_at": ts,
                }),
            ));
        }
        let canary = canary_fp(&ark_2, &id_2, 2);
        let mut shares: Vec<ShareDoc> = (1..=3u8)
            .map(|index| ShareDoc {
                index,
                holder: format!("holder-{index}"),
                recipient: format!("age1{}", ["q", "p", "z"][usize::from(index) - 1].repeat(58)),
                commitment: random_key(),
                ciphertext: age_armor_of(&random_bytes(150)),
            })
            .collect();
        tweak(&keys, &mut shares);
        let share_json: Vec<Value> = shares
            .iter()
            .map(|s| {
                json!({
                    "index": s.index, "holder": s.holder, "recipient": s.recipient,
                    "commitment": hex::encode(s.commitment), "ciphertext": s.ciphertext,
                })
            })
            .collect();
        let bundle = BundleDoc {
            key: String::new(),
            name_efp: [0; 32],
            ark_id: id_2,
            generation: 2,
            canary_fp: canary,
            shares,
        };
        let efp = bundle_efp(&bundle);
        objects.push((
            format!("{PREFIX}escrow-{}.json", hex::encode(efp)),
            json!({
                "version": 1, "ark_id": hex::encode(id_2), "generation": 2, "threshold": 2,
                "canary_fp": hex::encode(canary), "shares": share_json,
            }),
        ));
        let mut record = RecordDoc {
            key: String::new(),
            efp,
            ark_id: id_2,
            generation: 2,
            canary_fp: canary,
            verified_at: ts.to_owned(),
            mac: [0; 32],
        };
        record.mac = record_mac(&ark_2, &record);
        objects.push((
            format!("{PREFIX}record-{}.json", hex::encode(efp)),
            json!({
                "version": 1, "efp": hex::encode(efp), "ark_id": hex::encode(id_2), "generation": 2,
                "verified_indices": [1, 2, 3], "pairs": [[1, 2], [1, 3], [2, 3]],
                "canary_fp": hex::encode(canary), "app_id": null, "compose_hash": null,
                "verified_at": ts, "mac": hex::encode(record.mac),
            }),
        ));
        Self {
            root,
            spaces,
            keys,
            objects,
        }
    }

    /// The fixture's objects, the first one named with `target` edited:
    /// `edit` changes its name and JSON, or returns raw bytes for its body.
    fn with_edit(
        &self,
        target: &str,
        edit: &dyn Fn(&mut String, &mut Value) -> Option<Vec<u8>>,
    ) -> Vec<StoredObject> {
        let mut edited = false;
        let mut out = Vec::new();
        for (key, value) in &self.objects {
            let (mut key, mut value) = (key.clone(), value.clone());
            let mut raw = None;
            if !edited && key.contains(target) {
                edited = true;
                raw = edit(&mut key, &mut value);
            }
            let body = raw.unwrap_or_else(|| serde_json::to_vec(&value).expect("JSON"));
            out.push(StoredObject { key, body });
        }
        assert!(edited, "no fixture object named with {target:?}");
        out
    }

    fn check(&self, objects: &[StoredObject]) -> Vec<String> {
        self.check_with(objects, &[], key_mirror::Policy::default())
    }

    fn check_with(
        &self,
        objects: &[StoredObject],
        blocks: &[&str],
        policy: key_mirror::Policy,
    ) -> Vec<String> {
        let refs: Vec<key_mirror::ObjectRef> = objects
            .iter()
            .map(|o| key_mirror::ObjectRef {
                key: &o.key,
                body: &o.body,
            })
            .collect();
        key_mirror::check_snapshot("selftest", &refs, blocks, &self.root, &self.spaces, policy)
    }

    /// A sealed-shaped block name in `space`, its tag from the fixture's NK.
    fn block(&self, space: usize) -> String {
        format!(
            "v1/{}/{}",
            key_mirror::space_tag(&self.keys.nk, &self.spaces[space]),
            base64::encode_config(random_bytes(32), base64::URL_SAFE_NO_PAD)
        )
    }
}

/// An armored age file whose payload is the age v1 header, then `body`.
fn age_armor_of(body: &[u8]) -> String {
    let mut payload = b"age-encryption.org/v1\n-> X25519 ".to_vec();
    payload.extend_from_slice(body);
    let encoded = standard_b64(&payload);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN AGE ENCRYPTED FILE-----\n{}\n-----END AGE ENCRYPTED FILE-----\n",
        lines.join("\n")
    )
}

/// Every bit of `sealed`, flipped one at a time, must fail to open.
fn every_bit_flip_fails(sealed: &[u8], open: impl Fn(&[u8]) -> bool) -> bool {
    (0..sealed.len() * 8).all(|bit| {
        let mut flipped = sealed.to_vec();
        flipped[bit / 8] ^= 1 << (bit % 8);
        !open(&flipped)
    })
}

/// Offline cross-check of the re-derived key hierarchy (ruling 5): HKDF
/// matches RFC 5869; a sealed ARK and a wrapped DEK made with this file's
/// reference sealing open under the right root and binding, and fail under
/// any one-bit flip, another root, ARK id, generation, W label, space, data
/// key id or KEK.
#[test]
fn selftest_key_hierarchy_reference_vectors() -> Result<()> {
    use key_mirror::*;
    // RFC 5869 A.3 (no salt) and A.1 (salt), first 32 bytes of the OKM.
    ensure!(
        hex::encode(hkdf32(None, &[0x0b; 22], b""))
            == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
        "HKDF-SHA256 without salt does not match RFC 5869 A.3"
    );
    let salt: Vec<u8> = (0x00..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    ensure!(
        hex::encode(hkdf32(Some(&salt), &[0x0b; 22], &info))
            == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "HKDF-SHA256 with salt does not match RFC 5869 A.1"
    );

    let root = random_bytes(32);
    let w = wrap_key(&root);
    let (ark, id) = (random_key(), [7u8; 16]);
    let sealed = seal32(&w, &seal_aad(&id, 1, W_LABEL), &ark, random_nonce());
    ensure!(
        sealed.len() == SEALED_LEN,
        "a sealed ARK is nonce ‖ ct ‖ tag"
    );
    let opens = |w: &Key, sealed: &[u8], id: &[u8; 16], g: u32, label: &str| {
        open32(w, &seal_aad(id, g, label), sealed) == Some(ark)
    };
    ensure!(
        opens(&w, &sealed, &id, 1, W_LABEL),
        "the sealed ARK does not open"
    );
    ensure!(
        every_bit_flip_fails(&sealed, |s| opens(&w, s, &id, 1, W_LABEL)),
        "a one-bit flip of the sealed ARK still opens"
    );
    ensure!(
        !opens(&wrap_key(&random_bytes(32)), &sealed, &id, 1, W_LABEL)
            && !opens(&w, &sealed, &[8; 16], 1, W_LABEL)
            && !opens(&w, &sealed, &id, 2, W_LABEL)
            && !opens(&w, &sealed, &id, 1, "tinycloud/at-rest/wrap/v2")
            && !opens(&w, &sealed[..SEALED_LEN - 1], &id, 1, W_LABEL),
        "the sealed ARK opens under another root, id, generation, label or length"
    );

    let space = "tinycloud:pkh:eip155:1:0x5005aE13512FEfD4745e2750329B6d09572Ee176:tc887vector";
    let dek = random_key();
    let k = kek(&ark);
    let wrapped = seal32(&k, &dek_aad(space, 1, 1, &id), &dek, random_nonce());
    let unwraps = |k: &Key, wrapped: &[u8], space: &str, dek_id: u32, g: u32, id: &[u8; 16]| {
        open32(k, &dek_aad(space, dek_id, g, id), wrapped) == Some(dek)
    };
    ensure!(
        unwraps(&k, &wrapped, space, 1, 1, &id),
        "the wrapped DEK does not open"
    );
    ensure!(
        every_bit_flip_fails(&wrapped, |s| unwraps(&k, s, space, 1, 1, &id)),
        "a one-bit flip of the wrapped DEK still opens"
    );
    ensure!(
        !unwraps(&k, &wrapped, &format!("{space}x"), 1, 1, &id)
            && !unwraps(&k, &wrapped, space, 2, 1, &id)
            && !unwraps(&k, &wrapped, space, 1, 2, &id)
            && !unwraps(&k, &wrapped, space, 1, 1, &[8; 16])
            && !unwraps(&kek(&random_key()), &wrapped, space, 1, 1, &id),
        "the wrapped DEK opens under another space, id, generation, ARK id or KEK"
    );

    let tag = dek_tag(&ark, space);
    ensure!(
        tag.len() == 32
            && lower_hex::<16>(&tag).is_some()
            && tag == dek_tag(&ark, space)
            && tag != dek_tag(&ark, &format!("{space}x"))
            && tag != dek_tag(&random_key(), space),
        "DEK mirror tags must be 32 lowercase hex, deterministic, per space and per ARK"
    );
    Ok(())
}

/// Offline: mirrors shaped exactly like S1's (ARK, chain, DEK, escrow bundle,
/// verification record) pass every key-mirror rule and the content scans.
#[test]
fn selftest_key_mirror_accepts_s1_shaped_mirrors() -> Result<()> {
    let fx = MirrorFixture::new();
    let objects = fx.with_edit("ark-", &|_, _| None);
    let findings = fx.check(&objects);
    ensure!(
        findings.is_empty(),
        "S1-shaped mirrors were flagged: {findings:#?}"
    );
    let identities: Vec<IdentityForm> = fx.spaces.iter().flat_map(|s| identity_forms(s)).collect();
    let fingerprints: Vec<(&str, Fingerprint)> = fingerprints(b"some value")
        .into_iter()
        .map(|fp| ("probe", fp))
        .collect();
    for object in &objects {
        let found = content_findings(
            object,
            true,
            &marker("SELFTEST"),
            &fingerprints,
            &identities,
        );
        ensure!(
            found.is_empty(),
            "content scan flagged {:?}: {found:?}",
            object.key
        );
    }
    // Sealed-shaped block names carry no identity.
    for _ in 0..64 {
        let object = StoredObject {
            key: format!(
                "v1/{}/{}",
                base64::encode_config(random_bytes(16), base64::URL_SAFE_NO_PAD),
                base64::encode_config(random_bytes(32), base64::URL_SAFE_NO_PAD)
            ),
            body: random_bytes(64),
        };
        let found = content_findings(&object, false, "TC887-X", &fingerprints, &identities);
        ensure!(
            found.is_empty(),
            "a sealed-shaped name was flagged: {found:?}"
        );
    }
    Ok(())
}

type MirrorEdit = Box<dyn Fn(&mut String, &mut Value) -> Option<Vec<u8>>>;

fn name_edit(f: impl Fn(&str) -> String + 'static) -> MirrorEdit {
    Box::new(move |key, _| {
        *key = f(key);
        None
    })
}

fn body_edit(f: impl Fn(&mut Value) + 'static) -> MirrorEdit {
    Box::new(move |_, value| {
        f(value);
        None
    })
}

fn set(field: &'static str, to: Value) -> MirrorEdit {
    body_edit(move |value| value[field] = to.clone())
}

fn raw_body(f: impl Fn() -> Vec<u8> + 'static) -> MirrorEdit {
    Box::new(move |_, _| Some(f()))
}

/// The 32 hex characters after `dek-` in a DEK mirror name.
fn dek_tag_in(name: &str) -> String {
    name.split("/dek-").nth(1).unwrap_or_default()[..32].to_owned()
}

/// Offline negative cases (ruling 6): every bypass the review listed and
/// every rule, each on an otherwise S1-shaped mirror set, must be flagged
/// with the expected finding.
#[test]
fn selftest_key_mirror_flags_every_bypass() -> Result<()> {
    let fx = MirrorFixture::new();
    let raw = random_key();
    let hex_key = hex::encode(raw);
    let b64 = |config| base64::encode_config(raw, config);
    let spaced: String = hex_key
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).expect("hex"))
        .collect::<Vec<_>>()
        .join(" \n");
    let other_space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:other";
    let other_tag = key_mirror::dek_tag(&fx.keys.ark_1, other_space);
    let second_tag = key_mirror::dek_tag(&fx.keys.ark_1, &fx.spaces[1]);
    let flip_b64 = |field: &'static str| {
        body_edit(move |value| {
            let mut bytes = base64::decode(value[field].as_str().expect("string")).expect("b64");
            bytes[20] ^= 1;
            value[field] = json!(standard_b64(&bytes));
        })
    };
    let raw_plus_junk = |field: &'static str| {
        let mut bytes = raw.to_vec();
        bytes.extend(random_bytes(28));
        set(field, json!(standard_b64(&bytes)))
    };
    let cases: Vec<(&str, &str, MirrorEdit, &str)> = vec![
        // Ruling 1/2: names.
        (
            "unknown _tc/ object",
            "dek-",
            name_edit(|_| "_tc/other/blob".into()),
            "not an allowed mirror name",
        ),
        (
            "unknown at-rest kind",
            "dek-",
            name_edit(|_| "_tc/at-rest/zzz.json".into()),
            "not an allowed mirror name",
        ),
        (
            "uppercase kind",
            "dek-",
            name_edit(|k| k.replace("/dek-", "/DEK-")),
            "not an allowed mirror name",
        ),
        (
            "uppercase tag",
            "dek-",
            name_edit(|k| k.replace(&dek_tag_in(k), &dek_tag_in(k).to_uppercase())),
            "not an allowed mirror name",
        ),
        (
            "31-hex tag",
            "dek-",
            name_edit(|k| k.replace(&dek_tag_in(k), &dek_tag_in(k)[1..])),
            "not an allowed mirror name",
        ),
        (
            "9-digit dek id",
            "dek-",
            name_edit(|k| k.replace("-0000000001.json", "-000000001.json")),
            "not an allowed mirror name",
        ),
        (
            "11-digit dek id",
            "dek-",
            name_edit(|k| k.replace("-0000000001.json", "-00000000001.json")),
            "not an allowed mirror name",
        ),
        (
            "dek id 0",
            "dek-",
            name_edit(|k| k.replace("-0000000001.json", "-0000000000.json")),
            "not an allowed mirror name",
        ),
        (
            "suffix .JSON",
            "dek-",
            name_edit(|k| k.replace(".json", ".JSON")),
            "not an allowed mirror name",
        ),
        (
            "suffix .json.bak",
            "dek-",
            name_edit(|k| format!("{k}.bak")),
            "not an allowed mirror name",
        ),
        (
            "extra name part",
            "dek-",
            name_edit(|k| k.replace(".json", "-x.json")),
            "not an allowed mirror name",
        ),
        (
            "double slash",
            "dek-",
            name_edit(|k| k.replace("at-rest/", "at-rest//")),
            "not an allowed mirror name",
        ),
        (
            "9-digit generation",
            "ark-0000000002",
            name_edit(|k| k.replace("ark-0000000002", "ark-000000002")),
            "not an allowed mirror name",
        ),
        (
            "uppercase ark id",
            "ark-0000000002",
            name_edit(|k| k.replace("02020202", "0202020A")),
            "not an allowed mirror name",
        ),
        (
            "63-hex efp",
            "escrow-",
            name_edit(|k| format!("{}.json", &k[..k.len() - 6])),
            "not an allowed mirror name",
        ),
        (
            "uppercase record efp",
            "record-",
            name_edit(|k| {
                let (head, efp) = k.split_at(k.len() - 69);
                format!(
                    "{head}{}.json",
                    efp.trim_end_matches(".json").to_uppercase()
                )
            }),
            "not an allowed mirror name",
        ),
        // Ruling 3: exact typed schemas.
        (
            "not JSON",
            "dek-",
            raw_body(|| random_bytes(80)),
            "not JSON",
        ),
        (
            "JSON array",
            "dek-",
            body_edit(|v| *v = json!([1, 2, 3])),
            "where an object is required",
        ),
        (
            "extra field",
            "dek-",
            set("note", json!("x")),
            "fields must be exactly",
        ),
        (
            "missing field",
            "dek-",
            body_edit(|v| {
                v.as_object_mut().expect("object").remove("created_at");
            }),
            "fields must be exactly",
        ),
        (
            "version as string",
            "dek-",
            set("version", json!("1")),
            "`version` must be the integer 1",
        ),
        (
            "version as float",
            "dek-",
            set("version", json!(1.0)),
            "`version` must be the integer 1",
        ),
        (
            "version 2",
            "dek-",
            set("version", json!(2)),
            "`version` must be the integer 1",
        ),
        (
            "dek_id as string",
            "dek-",
            set("dek_id", json!("1")),
            "`dek_id` must be an integer",
        ),
        (
            "negative generation",
            "dek-",
            set("generation", json!(-1)),
            "`generation` must be an integer",
        ),
        (
            "generation over u32",
            "dek-",
            set("generation", json!(4_294_967_296u64)),
            "`generation` must be an integer",
        ),
        (
            "created_at as integer",
            "dek-",
            set("created_at", json!(123)),
            "strict RFC 3339",
        ),
        (
            "created_at free text",
            "dek-",
            set("created_at", json!("yesterday")),
            "strict RFC 3339",
        ),
        (
            "created_at with a space",
            "dek-",
            set("created_at", json!("2026-10-17 10:00:00Z")),
            "strict RFC 3339",
        ),
        (
            "created_at lowercase",
            "dek-",
            set("created_at", json!("2026-10-17t10:00:00z")),
            "strict RFC 3339",
        ),
        (
            "created_at 10 fraction digits",
            "dek-",
            set("created_at", json!("2026-10-17T10:00:00.1234567890Z")),
            "strict RFC 3339",
        ),
        (
            "created_at month 13",
            "dek-",
            set("created_at", json!("2026-13-17T10:00:00Z")),
            "strict RFC 3339",
        ),
        (
            "created_at as object",
            "dek-",
            set("created_at", json!({})),
            "strict RFC 3339",
        ),
        (
            "version as array",
            "dek-",
            set("version", json!([1])),
            "`version` must be the integer 1",
        ),
        (
            "wrapped as int array",
            "dek-",
            set("wrapped", json!(vec![7u8; 60])),
            "canonical padded base64",
        ),
        (
            "wrapped base64url",
            "dek-",
            set(
                "wrapped",
                json!(base64::encode_config([0xffu8; 60], base64::URL_SAFE)),
            ),
            "canonical padded base64",
        ),
        (
            "wrapped with a newline",
            "dek-",
            body_edit(|v| {
                let s = v["wrapped"].as_str().expect("string").to_owned();
                v["wrapped"] = json!(format!("{}\n{}", &s[..40], &s[40..]));
            }),
            "canonical padded base64",
        ),
        (
            "wrapped 59 bytes",
            "dek-",
            set("wrapped", json!(standard_b64(&random_bytes(59)))),
            "canonical padded base64",
        ),
        (
            "wrapped 61 bytes",
            "dek-",
            set("wrapped", json!(standard_b64(&random_bytes(61)))),
            "canonical padded base64",
        ),
        (
            "ARK w_label v2",
            "ark-0000000002",
            set("w_label", json!("tinycloud/at-rest/wrap/v2")),
            "`w_label` must be the string",
        ),
        (
            "ARK generation differs from its name",
            "ark-0000000002",
            set("generation", json!(3)),
            "differ from the object name",
        ),
        (
            "escrow extra share field",
            "escrow-",
            body_edit(|v| v["shares"][0]["note"] = json!("x")),
            "fields must be exactly",
        ),
        (
            "escrow holder charset",
            "escrow-",
            body_edit(|v| v["shares"][1]["holder"] = json!("Sam!")),
            "1-32 characters",
        ),
        (
            "escrow ciphertext not armor",
            "escrow-",
            body_edit(|v| v["shares"][2]["ciphertext"] = json!("hello")),
            "ASCII-armored age file",
        ),
        (
            "escrow two shares",
            "escrow-",
            body_edit(|v| {
                v["shares"].as_array_mut().expect("array").pop();
            }),
            "array of 3 share objects",
        ),
        (
            "record app_id",
            "record-",
            set("app_id", json!("app")),
            "null (no TEE)",
        ),
        (
            "record pairs",
            "record-",
            set("pairs", json!([[1, 2]])),
            "`pairs` must be",
        ),
        // Ruling 3: raw-key scan, as an extra field and as a JSON key.
        (
            "raw key, lowercase hex",
            "dek-",
            set("k", json!(hex_key)),
            "decodes to 32 bytes",
        ),
        (
            "raw key, uppercase hex",
            "dek-",
            set("k", json!(hex_key.to_uppercase())),
            "decodes to 32 bytes",
        ),
        (
            "raw key, 0x hex",
            "dek-",
            set("k", json!(format!("0x{hex_key}"))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, whitespace-split hex",
            "dek-",
            set("k", json!(spaced)),
            "decodes to 32 bytes",
        ),
        (
            "raw key, base64",
            "dek-",
            set("k", json!(b64(base64::STANDARD))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, base64 unpadded",
            "dek-",
            set("k", json!(b64(base64::STANDARD_NO_PAD))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, base64url",
            "dek-",
            set("k", json!(b64(base64::URL_SAFE))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, base64url unpadded",
            "dek-",
            set("k", json!(b64(base64::URL_SAFE_NO_PAD))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, base64: prefix",
            "dek-",
            set("k", json!(format!("base64:{}", b64(base64::STANDARD)))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, data URL",
            "dek-",
            set(
                "k",
                json!(format!(
                    "data:application/octet-stream;base64,{}",
                    b64(base64::STANDARD)
                )),
            ),
            "decodes to 32 bytes",
        ),
        (
            "raw key as a JSON key",
            "dek-",
            body_edit(move |v| v[hex::encode(raw)] = json!(1)),
            "a JSON key in `/` decodes to 32 bytes",
        ),
        (
            "raw key as 32 ints",
            "dek-",
            set("k", json!(raw.to_vec())),
            "array of 32 byte values",
        ),
        (
            "raw key, k: prefix",
            "dek-",
            set("k", json!(format!("k:{}", b64(base64::STANDARD)))),
            "decodes to 32 bytes",
        ),
        (
            "raw key, base32",
            "dek-",
            set("k", json!(base32_lower(&raw).to_uppercase())),
            "decodes to 32 bytes",
        ),
        (
            "33 bytes, hex",
            "dek-",
            set("k", json!(hex::encode(random_bytes(33)))),
            "more than a raw key",
        ),
        (
            "raw key split 16+16",
            "dek-",
            body_edit(move |v| {
                v["a"] = json!(hex::encode(&raw[..16]));
                v["b"] = json!(base64::encode(&raw[16..]));
            }),
            "16 bytes each",
        ),
        // Ruling 5: authenticity under the harness root.
        (
            "wrapped = raw key + 28 junk bytes",
            "dek-",
            raw_plus_junk("wrapped"),
            "does not authenticate",
        ),
        (
            "wrapped, one bit flipped",
            "dek-",
            flip_b64("wrapped"),
            "does not authenticate",
        ),
        (
            "sealed ARK = raw key + 28 junk bytes",
            "ark-0000000002",
            raw_plus_junk("sealed"),
            "does not authenticate",
        ),
        (
            "sealed ARK, one bit flipped",
            "ark-0000000001",
            flip_b64("sealed"),
            "does not authenticate",
        ),
        (
            "ARK chain, one bit flipped",
            "ark-0000000001",
            flip_b64("chain"),
            "chain does not open",
        ),
        (
            "older ARK without chain",
            "ark-0000000001",
            set("chain", Value::Null),
            "has no chain",
        ),
        (
            "newest ARK with a chain",
            "ark-0000000002",
            body_edit(|v| v["chain"] = json!(standard_b64(&random_bytes(60)))),
            "newest generation has a chain",
        ),
        (
            "DEK moved to another space's tag",
            "dek-",
            name_edit(move |k| k.replace(&dek_tag_in(k), &second_tag)),
            "does not authenticate",
        ),
        (
            "DEK tagged for an unknown space",
            "dek-",
            name_edit(move |k| k.replace(&dek_tag_in(k), &other_tag)),
            "belongs to none of",
        ),
        (
            "DEK under a generation without ARK",
            "dek-",
            set("generation", json!(3)),
            "no authentic ARK",
        ),
        (
            "escrow canary_fp",
            "escrow-",
            set("canary_fp", json!(hex::encode(random_key()))),
            "canary_fp is not",
        ),
        (
            "escrow name EFP",
            "escrow-",
            name_edit(|_| {
                format!(
                    "{}escrow-{}.json",
                    key_mirror::PREFIX,
                    hex::encode(random_key())
                )
            }),
            "name's EFP is not the bundle's fingerprint",
        ),
        (
            "record MAC",
            "record-",
            body_edit(|v| v["mac"] = json!(hex::encode(random_key()))),
            "MAC does not verify",
        ),
        (
            "record without its bundle",
            "record-",
            body_edit(|v| v["efp"] = json!(hex::encode(random_key()))),
            "no mirrored escrow bundle",
        ),
    ];
    let mut missed = Vec::new();
    for (what, target, edit, expected) in &cases {
        let findings = fx.check(&fx.with_edit(target, edit.as_ref()));
        if !findings.iter().any(|f| f.contains(expected)) {
            missed.push(format!("{what}: expected {expected:?}, got {findings:?}"));
        }
    }
    ensure!(
        missed.is_empty(),
        "key-mirror check missed:\n{}",
        missed.join("\n")
    );

    // Ruling 4: each identity form of each space, in an object name and (for
    // a mirror) in its body.
    let fingerprints: Vec<(&str, Fingerprint)> = fingerprints(b"the probe value")
        .into_iter()
        .map(|fp| ("probe", fp))
        .collect();
    let identities: Vec<IdentityForm> = fx.spaces.iter().flat_map(|s| identity_forms(s)).collect();
    for form in &identities {
        for (key, body, scan_body) in [
            (format!("v1/x{}y/z", form.text), Vec::new(), false),
            (
                "_tc/at-rest/zzz.json".to_owned(),
                json!({"note": format!("x{}y", form.text)})
                    .to_string()
                    .into_bytes(),
                true,
            ),
        ] {
            let object = StoredObject { key, body };
            let found = content_findings(&object, scan_body, "TC887-X", &fingerprints, &identities);
            ensure!(
                found
                    .iter()
                    .any(|f| f.contains("space identity") && f.contains(&form.label)),
                "identity form {:?} was missed: {found:?}",
                form.label
            );
        }
    }
    // Ruling 1: a marker or a fingerprint inside a mirror.
    let marker = marker("SELFTEST");
    for (what, note) in [
        ("marker", format!("value {marker}")),
        ("fingerprint", fingerprints[0].1.text.clone()),
        ("hex fingerprint", fingerprints[4].1.text.to_uppercase()),
    ] {
        let objects = fx.with_edit("dek-", &|_, v| {
            v["note"] = json!(note);
            None
        });
        let object = objects
            .iter()
            .find(|o| o.key.contains("dek-"))
            .expect("dek");
        let found = content_findings(object, true, &marker, &fingerprints, &identities);
        ensure!(
            found
                .iter()
                .any(|f| f.contains("plaintext marker") || f.contains("plaintext fingerprint")),
            "a {what} inside a mirror was missed: {found:?}"
        );
    }
    Ok(())
}

fn any_contains(findings: &[String], needle: &str) -> bool {
    findings.iter().any(|f| f.contains(needle))
}

/// Round 5, rulings 1 and 2, offline: an escrow-none run refuses any escrow
/// bundle or record; otherwise a harness-derived secret anywhere in escrow or
/// record contents is RED (a commitment, holder names split in two, the
/// armored share payload, a record field), even with the bundle's EFP, name
/// and record MAC recomputed; and valid 16-byte-looking holder names are not
/// a split key.
#[test]
fn selftest_key_mirror_refuses_escrow_contents_and_derived_keys() -> Result<()> {
    let fx = MirrorFixture::new();
    let escrow_none = key_mirror::Policy {
        encrypt: false,
        escrow_none: true,
    };
    let findings = fx.check_with(&fx.with_edit("ark-", &|_, _| None), &[], escrow_none);
    ensure!(
        findings
            .iter()
            .filter(|f| f.contains("runs with escrow_none"))
            .count()
            == 2,
        "escrow-none must refuse the escrow bundle and the record: {findings:#?}"
    );

    type Case = (&'static str, Box<ShareTweak>, &'static str);
    fn tweak(f: impl Fn(&FixtureKeys, &mut [key_mirror::ShareDoc]) + 'static) -> Box<ShareTweak> {
        Box::new(f)
    }
    let cases: Vec<Case> = vec![
        (
            "a commitment that is ARK_2",
            tweak(|k, s| s[0].commitment = k.ark_2),
            "ARK of generation 2",
        ),
        (
            "a commitment that is the KEK of generation 1",
            tweak(|k, s| s[1].commitment = key_mirror::kek(&k.ark_1)),
            "KEK of generation 1",
        ),
        (
            "W in base32, split across two holder names",
            tweak(|k, s| {
                let b32 = base32_lower(&k.w);
                s[0].holder = b32[..26].to_owned();
                s[1].holder = b32[26..].to_owned();
            }),
            "wrap key W",
        ),
        (
            "NK inside the armored share payload",
            tweak(|k, s| {
                let mut body = random_bytes(37);
                body.extend_from_slice(&k.nk);
                body.extend(random_bytes(41));
                s[2].ciphertext = age_armor_of(&body);
            }),
            "object-name key NK",
        ),
        (
            "a space's DEK inside the armored share payload",
            tweak(|k, s| {
                let mut body = random_bytes(5);
                body.extend_from_slice(&k.deks[0]);
                s[0].ciphertext = age_armor_of(&body);
            }),
            "DEK 1 of a harness space",
        ),
    ];
    let mut missed = Vec::new();
    for (what, tweak, expected) in &cases {
        let fx = MirrorFixture::build(tweak.as_ref());
        let findings = fx.check(&fx.with_edit("ark-", &|_, _| None));
        if !any_contains(&findings, expected) || !any_contains(&findings, "raw key material") {
            missed.push(format!("{what}: expected {expected:?}, got {findings:?}"));
        }
    }
    // A record field holding a derived key (the MAC no longer verifies too).
    let tag_key = key_mirror::hkdf32(None, &fx.keys.ark_1, b"tinycloud/at-rest/dek-mirror-tag/v1");
    let findings = fx.check(&fx.with_edit("record-", &|_, v| {
        v["mac"] = json!(hex::encode(tag_key));
        None
    }));
    if !any_contains(&findings, "DEK mirror tag key") {
        missed.push(format!(
            "record mac = the DEK mirror tag key: got {findings:?}"
        ));
    }
    ensure!(
        missed.is_empty(),
        "derived-secret scan missed:\n{}",
        missed.join("\n")
    );

    // Ruling 2: valid holder names that decode to 16 bytes are no split key.
    for names in [
        [
            "holder-one-london-hong",
            "holder-two-london-hong",
            "holder-six-london-hong",
        ]
        .map(str::to_owned),
        [0, 1, 2].map(|_| hex::encode(random_bytes(16))),
    ] {
        let fx = MirrorFixture::build(&move |_, s| {
            for (share, name) in s.iter_mut().zip(names.clone()) {
                share.holder = name;
            }
        });
        let findings = fx.check(&fx.with_edit("ark-", &|_, _| None));
        ensure!(
            findings.is_empty(),
            "valid holder names were flagged: {findings:#?}"
        );
    }
    Ok(())
}

/// Lowercase unpadded RFC 4648 base32 (a valid holder-name alphabet).
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut bits, mut acc, mut out) = (0u32, 0u32, String::new());
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Round 5, ruling 3, offline: an absurd ARK generation in a name fails RED
/// at once (no loop to the number), and a gap is one finding.
#[test]
fn selftest_key_mirror_bounds_absurd_generations() -> Result<()> {
    let fx = MirrorFixture::new();
    let mut objects = fx.with_edit("ark-", &|_, _| None);
    let absurd = |generation: u32| StoredObject {
        key: format!(
            "{}ark-{generation:010}-{}.json",
            key_mirror::PREFIX,
            hex::encode([9u8; 16])
        ),
        body: json!({
            "version": 1, "generation": generation, "ark_id": hex::encode([9u8; 16]),
            "w_label": key_mirror::W_LABEL, "sealed": standard_b64(&random_bytes(60)),
            "chain": null, "created_at": "2026-10-17T10:00:00Z",
        })
        .to_string()
        .into_bytes(),
    };
    objects.push(absurd(u32::MAX));
    let started = std::time::Instant::now();
    let findings = fx.check(&objects);
    ensure!(
        started.elapsed() < Duration::from_secs(2),
        "the generation checks took {:?}",
        started.elapsed()
    );
    ensure!(
        any_contains(&findings, "above the ceiling 9")
            && any_contains(&findings, "not every generation 1..=4294967295"),
        "an absurd generation was not refused: {findings:#?}"
    );
    let mut with_gap = fx.with_edit("ark-", &|_, _| None);
    with_gap.push(absurd(5));
    let gap = fx.check(&with_gap);
    ensure!(
        gap.iter()
            .filter(|f| f.contains("not every generation"))
            .count()
            == 1,
        "a gap must be one finding: {gap:#?}"
    );
    Ok(())
}

/// Round 5, ruling 4, offline: in encrypt mode every block must be sealed
/// and belong (by its NK space tag) to a harness space whose DEK mirror
/// authenticates, and an ARK mirror must exist; outside encrypt mode no
/// mirror is required.
#[test]
fn selftest_key_mirror_requires_mirrors_in_encrypt_mode() -> Result<()> {
    let fx = MirrorFixture::new();
    let encrypt = key_mirror::Policy {
        encrypt: true,
        escrow_none: false,
    };
    let all = fx.with_edit("ark-", &|_, _| None);
    let blocks = [fx.block(0), fx.block(0), fx.block(1)];
    let block_refs: Vec<&str> = blocks.iter().map(String::as_str).collect();
    let findings = fx.check_with(&all, &block_refs, encrypt);
    ensure!(
        findings.is_empty(),
        "mirrored sealed blocks were flagged: {findings:#?}"
    );

    let without = |needle: &str| -> Vec<StoredObject> {
        all.iter()
            .filter(|o| !o.key.contains(needle))
            .map(|o| StoredObject {
                key: o.key.clone(),
                body: o.body.clone(),
            })
            .collect()
    };
    let dek_0 = format!("dek-{}", key_mirror::dek_tag(&fx.keys.ark_1, &fx.spaces[0]));
    let unknown = format!(
        "v1/{}/x",
        key_mirror::space_tag(
            &fx.keys.nk,
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:other"
        )
    );
    let plaintext = format!("{}/abc=", fx.spaces[0]);
    let cases: Vec<(&str, Vec<StoredObject>, Vec<&str>, &str)> = vec![
        (
            "a space's DEK mirror deleted",
            without(&dek_0),
            vec![block_refs[0]],
            "its space has no DEK mirror that authenticates",
        ),
        (
            "the generation-2 ARK deleted (its DEK can't authenticate)",
            without("ark-0000000002"),
            vec![block_refs[2]],
            "its space has no DEK mirror that authenticates",
        ),
        (
            "a block of no harness space",
            all.iter()
                .map(|o| StoredObject {
                    key: o.key.clone(),
                    body: o.body.clone(),
                })
                .collect(),
            vec![unknown.as_str()],
            "belongs to none of the 2 spaces",
        ),
        (
            "a plaintext-named block",
            without("record-"),
            vec![plaintext.as_str()],
            "not named as sealed",
        ),
        (
            "no ARK mirror at all",
            without("ark-"),
            vec![block_refs[0]],
            "no ARK mirror is in the bucket",
        ),
    ];
    let mut missed = Vec::new();
    for (what, objects, blocks, expected) in &cases {
        let findings = fx.check_with(objects, blocks, encrypt);
        if !any_contains(&findings, expected) {
            missed.push(format!("{what}: expected {expected:?}, got {findings:?}"));
        }
    }
    ensure!(
        missed.is_empty(),
        "mirror requirement missed:\n{}",
        missed.join("\n")
    );

    let off = fx.check_with(&[], &[plaintext.as_str()], key_mirror::Policy::default());
    ensure!(
        off.is_empty(),
        "mode off must not require mirrors: {off:#?}"
    );
    Ok(())
}
