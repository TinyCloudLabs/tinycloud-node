//! The `DstackKmsEpoch` key source (TC-3554), observed through the real
//! `tinycloud` binary against a stand-in dstack guest agent and either of
//! its two transports: a stand-in dstack KMS (RA-TLS `GetAppKey`) or a
//! stand-in dstack-key-recovery sidecar (`GET /v0/key` on a Unix socket).
//! The KMS protocol and every check are specified in
//! `docs/tc-3554-kms-epoch-fetch.md`.
//!
//! - The node fetches the app key for root epoch 0 and serves the DID
//!   derived from it, never the current epoch's key from dstack `GetKey`.
//! - A wrong epoch, a bad issuance signature, a signature chain for another
//!   key, a refusal or a DID mismatch stops startup without falling back.
//! - The first boot seals the fetched root in the database's `root_wrap`
//!   under dstack `GetKey("tinycloud/keys/primary-wrap")`; later boots open
//!   it with no transport. A tampered blob, a blob that opens to another
//!   identity, or no blob and no transport stops startup.
//! - A refused node writes nothing to its database but `root_wrap`: no
//!   migration and no renewal identity before the identity checks pass.
//! - Configuring both transports stops startup before any call.
//!
//! Every key below is a fixed fixture key; none of them is a real KMS, app or
//! node key.
#![cfg(all(feature = "dstack", target_os = "linux"))]

use k256::ecdsa::SigningKey;
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rusqlite::OptionalExtension;
use rustls::{
    client::danger::HandshakeSignatureValid,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, ServerConfig, ServerConnection, SignatureScheme,
    StreamOwned,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tinycloud_core::{keys::StaticSecret, root_wrap};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};

/// The repository's `tinycloud.toml`, which the Docker image copies next to
/// the `/tinycloud` entrypoint.
const SHIPPED_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tinycloud.toml");

/// The legacy `GetKey` path the node's root comes from.
const PRIMARY_KEY_PATH: &str = "tinycloud/keys/primary";
/// How the stand-in agent records the node's one legitimate `GetKey`: the
/// key that seals the root in `root_wrap`.
const WRAP_KEY_REQUEST: &str = "POST /GetKey tinycloud/keys/primary-wrap";

/// The app id the guest agent reports and the node pins.
const APP_ID: [u8; 20] = *b"tc-3554 fixture app!";
/// The KMS root k256 keys for root epochs 0 and 1.
const KMS_ROOT_KEYS: [[u8; 32]; 2] = [[0x11; 32], [0x22; 32]];
/// The app k256 keys the KMS issues for root epochs 0 and 1.
const APP_KEYS: [[u8; 32]; 2] = [[0x33; 32], [0x44; 32]];
/// What dstack `GetKey` answers: the current epoch's key, which the
/// `DstackKmsEpoch` source must never use.
const CURRENT_GET_KEY: [u8; 32] = [0x55; 32];

/// The guest agent's event log and VM config, passed through verbatim.
const EVENT_LOG: &str = "[]";
const VM_CONFIG: &str = r#"{"spec_version":1}"#;

/// RA-TLS certificate extensions (dstack's legacy encoding).
const QUOTE_OID: &str = "1.3.6.1.4.1.62397.1.1";
const EVENT_LOG_OID: &str = "1.3.6.1.4.1.62397.1.2";
/// The extension that marks the KMS's own RPC server certificate.
const KMS_RPC_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 4];

/// TDX v4 quote: 48-byte header, 584-byte TD report body with REPORTDATA in
/// its last 64 bytes, then a u32 LE signature length and the signature.
const QUOTE_HEADER_LEN: usize = 48;
const TD_QUOTE_BODY_LEN: usize = 584;
const REPORT_DATA_AT: usize = QUOTE_HEADER_LEN + 520;

const GET_TEMP_CA_CERT: &str = "POST /prpc/GetTempCaCert?json";
const GET_APP_KEY: &str = "POST /prpc/GetAppKey?json";

/// The exact request the node sends the key-recovery sidecar for root
/// epoch 0.
const SIDECAR_REQUEST: &str = "GET /v0/key?path=tinycloud%2Fkeys%2Fprimary&root_epoch=0&app_epoch=0 HTTP/1.1\r\nHost: key-recovery\r\nConnection: close\r\n\r\n";

// ---------------------------------------------------------------------------
// The node process (patterns from tests/startup_identity.rs)
// ---------------------------------------------------------------------------

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A `tinycloud` command that inherits no node configuration from the test
/// process, so only the environment each test sets applies.
fn tinycloud(cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(cwd)
        .stdin(Stdio::null());
    command
}

/// Spawn `command` with stdout and stderr in one new log file under `logs`.
fn spawn_logged(command: &mut Command, logs: &Path) -> (KillOnDrop, PathBuf) {
    let log = logs.join(format!("tinycloud-{}.log", uuid::Uuid::new_v4().simple()));
    let file = File::create(&log).unwrap();
    let child = command
        .stdout(file.try_clone().unwrap())
        .stderr(file)
        .spawn()
        .unwrap();
    (KillOnDrop(child), log)
}

struct Node {
    _server: KillOnDrop,
    did: String,
    log: PathBuf,
}

impl Node {
    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap()
    }
}

/// Start the node and wait until it serves the DID it publishes.
fn start_node(mut command: Command, logs: &Path) -> Node {
    let port = free_port();
    command
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", port.to_string());
    let (mut server, log) = spawn_logged(&mut command, logs);

    let url = format!("http://127.0.0.1:{port}/.well-known/tinycloud/node-keys");
    let client = reqwest::blocking::Client::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!(
                "tinycloud exited before serving ({status}):\n{}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        if let Ok(response) = client.get(&url).send() {
            if response.status().is_success() {
                let body: Value = response.json().unwrap();
                let did = body["nodeDid"].as_str().unwrap().to_owned();
                return Node {
                    _server: server,
                    did,
                    log,
                };
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "tinycloud did not serve within 60s:\n{}",
        fs::read_to_string(&log).unwrap_or_default()
    );
}

/// Run `command` until it exits. A node still running after 60 s started
/// serving, which fails the test.
fn run_to_exit(mut command: Command, logs: &Path) -> (Option<i32>, String) {
    command
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", free_port().to_string());
    let (mut server, log) = spawn_logged(&mut command, logs);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            return (status.code(), fs::read_to_string(&log).unwrap());
        }
        assert!(
            Instant::now() < deadline,
            "tinycloud kept running instead of refusing:\n{}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The container layout: `tinycloud.toml` in the working directory.
fn shipped_layout() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::copy(SHIPPED_CONFIG, dir.path().join("tinycloud.toml")).unwrap();
    dir
}

/// The shipped config's capability database: `datadir = "./data"` and no
/// `database` override, so `Storage::resolve` makes it
/// `sqlite:./data/caps.db`, created by `connect_database` on first connect.
fn database(cwd: &Path) -> PathBuf {
    cwd.join("data").join("caps.db")
}

fn assert_database_never_opened(cwd: &Path) {
    let database = database(cwd);
    for file in [
        database.clone(),
        database.with_extension("db-wal"),
        database.with_extension("db-shm"),
    ] {
        assert!(
            !file.exists(),
            "the node opened its database before refusing: {} exists",
            file.display()
        );
    }
}

/// The node's database tables, other than SQLite's own.
fn tables(cwd: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(database(cwd)).unwrap();
    let mut tables = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let mut names = tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names.sort();
    names
}

/// The stored `root_wrap` row: (wrapped, node_did, kms_root_epoch).
fn stored_root(cwd: &Path) -> Option<(Vec<u8>, String, i64)> {
    rusqlite::Connection::open(database(cwd))
        .unwrap()
        .query_row(
            "SELECT wrapped, node_did, kms_root_epoch FROM root_wrap WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .unwrap()
}

/// The refused node wrote nothing to its database but `root_wrap`: no
/// migration ran and no renewal identity was written. Returns whether it
/// stored a root.
fn assert_only_root_wrap(cwd: &Path) -> bool {
    assert!(database(cwd).exists(), "the node never opened its database");
    assert_eq!(
        tables(cwd),
        ["root_wrap"],
        "the node wrote to its database before its identity checks passed"
    );
    stored_root(cwd).is_some()
}

fn assert_refused(code: Option<i32>, log: &str) {
    assert!(
        matches!(code, Some(code) if code != 0),
        "expected a non-zero exit, got {code:?}:\n{log}"
    );
}

// ---------------------------------------------------------------------------
// Key derivations (docs/tc-3554-kms-epoch-fetch.md, steps 9 and 10)
// ---------------------------------------------------------------------------

/// The legacy v0 `GetKey(path)` value for an app key:
/// HKDF-SHA256(salt "RATLS", ikm app key, info path, 32 bytes).
fn legacy_get_key(app_key: &[u8], path: &str) -> [u8; 32] {
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(b"RATLS"), app_key)
        .expand(path.as_bytes(), &mut okm)
        .unwrap();
    okm
}

/// The node DID served from the app key of root epoch `epoch`.
fn epoch_did(epoch: usize) -> String {
    StaticSecret::new(legacy_get_key(&APP_KEYS[epoch], PRIMARY_KEY_PATH).to_vec())
        .unwrap()
        .node_did()
}

/// SEC1-compressed (33-byte) secp256k1 public key of `secret`.
fn compressed_pubkey(secret: &[u8]) -> Vec<u8> {
    SigningKey::from_slice(secret)
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

/// keccak256("dstack-kms-issued:" || app_id || app_pub).
fn issuance_digest(app_id: &[u8], app_pub: &[u8]) -> Vec<u8> {
    Keccak256::new()
        .chain_update(b"dstack-kms-issued:")
        .chain_update(app_id)
        .chain_update(app_pub)
        .finalize()
        .to_vec()
}

/// A 65-byte `r || s || v` recoverable signature of the prehashed `digest`
/// by `key`. k256 signs low-S and adjusts the recovery id to match.
fn recoverable_signature(key: &[u8], digest: &[u8]) -> Vec<u8> {
    let (signature, recovery) = SigningKey::from_slice(key)
        .unwrap()
        .sign_prehash_recoverable(digest)
        .unwrap();
    let mut out = signature.to_bytes().to_vec();
    out.push(recovery.to_byte());
    out
}

/// The KMS's issuance signature of `app_key` by `root`.
fn issuance_signature(root: &[u8], app_key: &[u8]) -> Vec<u8> {
    recoverable_signature(root, &issuance_digest(&APP_ID, &compressed_pubkey(app_key)))
}

/// dstack's v0 key signature: the app root's signature of
/// keccak256(":" || lowercase hex of `public_key`) (purpose "").
fn key_signature(app_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    let message = format!(":{}", hex::encode(public_key));
    recoverable_signature(app_key, &Keccak256::digest(message.as_bytes()))
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 and DER
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    /// The request line and headers, without the terminating blank line.
    head: String,
    body: Vec<u8>,
}

impl Request {
    fn line(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

/// Read one request: the head, then a `Content-Length` body. `None` when the
/// peer closed before sending a complete head.
fn read_request(stream: &mut impl Read) -> io::Result<Option<Request>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut start = lines.next().unwrap_or_default().split(' ');
    let method = start.next().unwrap_or_default().to_owned();
    let path = start.next().unwrap_or_default().to_owned();
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(Some(Request {
        method,
        path,
        head,
        body,
    }))
}

fn write_response(stream: &mut impl Write, status: &str, body: &Value) -> io::Result<()> {
    write_text(stream, status, "application/json", &body.to_string())
}

fn write_text(
    stream: &mut impl Write,
    status: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.flush()
}

/// DER OCTET STRING of `content`.
fn der_octet_string(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let length = content.len().to_be_bytes();
        let skip = length.iter().take_while(|byte| **byte == 0).count();
        out.push(0x80 | (length.len() - skip) as u8);
        out.extend_from_slice(&length[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// The content of a DER OCTET STRING that spans all of `der`.
fn octet_string_content(der: &[u8]) -> Result<&[u8], String> {
    let (&tag, rest) = der.split_first().ok_or("empty value")?;
    if tag != 0x04 {
        return Err(format!("tag {tag:#04x} is not an OCTET STRING"));
    }
    let (&first, rest) = rest.split_first().ok_or("missing length")?;
    let (length, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return Err("invalid length".into());
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |length, byte| length << 8 | *byte as usize);
        (length, &rest[count..])
    };
    if rest.len() != length {
        return Err("length does not match the value".into());
    }
    Ok(rest)
}

/// A structurally valid TDX v4 quote carrying `report_data` (as in
/// `dstack::stub::tdx_quote`). The signature bytes are filler.
fn tdx_quote(report_data: &[u8; 64]) -> Vec<u8> {
    let mut quote = vec![0u8; QUOTE_HEADER_LEN + TD_QUOTE_BODY_LEN];
    quote[0..2].copy_from_slice(&4u16.to_le_bytes());
    quote[2..4].copy_from_slice(&2u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    quote[REPORT_DATA_AT..REPORT_DATA_AT + 64].copy_from_slice(report_data);
    quote.extend_from_slice(&64u32.to_le_bytes());
    quote.extend_from_slice(&[0x5a; 64]);
    quote
}

/// The REPORTDATA of a structurally complete TDX v4 quote.
fn quote_report_data(quote: &[u8]) -> Result<&[u8], String> {
    let signature_length_at = QUOTE_HEADER_LEN + TD_QUOTE_BODY_LEN;
    if quote.len() < signature_length_at + 4 {
        return Err(format!("quote is truncated ({} bytes)", quote.len()));
    }
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);
    if version != 4 || tee_type != 0x81 {
        return Err(format!(
            "unsupported quote: version {version}, TEE type {tee_type:#x}"
        ));
    }
    Ok(&quote[REPORT_DATA_AT..REPORT_DATA_AT + 64])
}

// ---------------------------------------------------------------------------
// Stand-in dstack guest agent
// ---------------------------------------------------------------------------

/// A dstack guest agent on a Unix socket: `Info`, `GetQuote` over the
/// requested report data, and `GetKey` answering the current epoch's key.
/// It records every request line it receives.
struct Agent {
    socket: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Agent {
    fn start(socket: PathBuf) -> Self {
        let listener = UnixListener::bind(&socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || serve_agent(stream, &recorded));
            }
        });
        Self { socket, requests }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().clone()
    }

    /// The node never fell back to dstack `GetKey` for its identity: the
    /// only key it asked for is the `root_wrap` key.
    fn assert_never_asked_for_the_node_key(&self) {
        let requests = self.requests();
        assert!(
            requests
                .iter()
                .filter(|line| line.starts_with("POST /GetKey"))
                .all(|line| line == WRAP_KEY_REQUEST),
            "the node fell back to dstack GetKey: {requests:?}"
        );
    }
}

fn serve_agent(mut stream: UnixStream, recorded: &Mutex<Vec<String>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(Some(request)) = read_request(&mut stream) else {
        return;
    };
    // A `GetKey` is recorded with the key path it asks for.
    let line = match serde_json::from_slice::<Value>(&request.body) {
        Ok(body) if request.path == "/GetKey" => {
            format!(
                "{} {}",
                request.line(),
                body["path"].as_str().unwrap_or("?")
            )
        }
        _ => request.line(),
    };
    recorded.lock().push(line);
    let (status, body) = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/Info") => (
            "200 OK",
            json!({
                "app_id": hex::encode(APP_ID),
                "compose_hash": "tc3554",
                "instance_id": "tc3554",
            }),
        ),
        ("POST", "/GetQuote") => match quote_reply(&request.body) {
            Ok(reply) => ("200 OK", reply),
            Err(error) => ("400 Bad Request", json!({ "error": error })),
        },
        ("POST", "/GetKey") => (
            "200 OK",
            json!({ "key": hex::encode(CURRENT_GET_KEY), "signature_chain": [] }),
        ),
        _ => ("404 Not Found", json!({})),
    };
    let _ = write_response(&mut stream, status, &body);
    let _ = stream.shutdown(Shutdown::Write);
}

/// Answer `GetQuote` like dstack: a quote over the requested bytes
/// zero-padded to 64, echoed back as `report_data`.
fn quote_reply(body: &[u8]) -> Result<Value, String> {
    let body: Value = serde_json::from_slice(body).map_err(|error| error.to_string())?;
    let requested = body["report_data"]
        .as_str()
        .ok_or("missing report_data")?
        .trim_start_matches("0x");
    let requested = hex::decode(requested).map_err(|error| error.to_string())?;
    if requested.len() > 64 {
        return Err(format!("report_data is {} bytes", requested.len()));
    }
    let mut padded = [0u8; 64];
    padded[..requested.len()].copy_from_slice(&requested);
    Ok(json!({
        "quote": hex::encode(tdx_quote(&padded)),
        "event_log": EVENT_LOG,
        "report_data": hex::encode(padded),
        "vm_config": VM_CONFIG,
    }))
}

// ---------------------------------------------------------------------------
// Stand-in dstack KMS
// ---------------------------------------------------------------------------

/// How the stand-in KMS answers an attested, protocol-correct `GetAppKey`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Scenario {
    /// The requested epoch's app key, signed by that epoch's root.
    Happy,
    /// Always epoch 1's app key and signature, with `root_epoch: 1`.
    WrongEpoch,
    /// Epoch 0's app key and `root_epoch: 0`, signed by epoch 1's root.
    BadSignature,
    /// HTTP 400: the app is not authorized for the requested epoch.
    Refused,
}

/// One `GetAppKey` the KMS received, and whether it was protocol-correct.
#[derive(Clone, Debug)]
struct AppKeyCall {
    body: Value,
    verdict: Result<(), String>,
}

#[derive(Clone, Debug, Default)]
struct KmsLog {
    /// Every request line, in order.
    requests: Vec<String>,
    app_key_calls: Vec<AppKeyCall>,
    /// Connections that failed before a complete request (TLS errors).
    connection_errors: Vec<String>,
}

struct KmsState {
    scenario: Scenario,
    ca_pem: String,
    temp_ca_der: Vec<u8>,
    temp_ca_pem: String,
    temp_ca_key_pem: String,
    log: Mutex<KmsLog>,
}

struct Kms {
    port: u16,
    ca_der: Vec<u8>,
    state: Arc<KmsState>,
}

impl Kms {
    fn start(scenario: Scenario) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Dstack KMS CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Dstack KMS");
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                KMS_RPC_OID,
                der_octet_string(b"kms:rpc"),
            ));
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        let temp_ca_key = KeyPair::generate().unwrap();
        let mut temp_ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        temp_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Dstack KMS Temp CA");
        temp_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        temp_ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let temp_ca = temp_ca_params.self_signed(&temp_ca_key).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(Arc::new(AnyClientCert(provider)))
                .with_single_cert(
                    vec![leaf.der().clone(), ca.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
                )
                .unwrap(),
        );

        let state = Arc::new(KmsState {
            scenario,
            ca_pem: ca.pem(),
            temp_ca_der: temp_ca.der().to_vec(),
            temp_ca_pem: temp_ca.pem(),
            temp_ca_key_pem: temp_ca_key.serialize_pem(),
            log: Mutex::new(KmsLog::default()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // `localhost` may resolve to ::1 first; serve it too when the same
        // port is free there.
        let listeners = std::iter::once(listener).chain(TcpListener::bind(("::1", port)).ok());
        for listener in listeners {
            let (config, state) = (Arc::clone(&config), Arc::clone(&state));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let (config, state) = (Arc::clone(&config), Arc::clone(&state));
                    std::thread::spawn(move || serve_kms(stream, config, &state));
                }
            });
        }

        Self {
            port,
            ca_der: ca.der().to_vec(),
            state,
        }
    }

    fn log(&self) -> KmsLog {
        self.state.log.lock().clone()
    }
}

/// Offers client authentication without requiring it, and accepts any
/// presented certificate at the TLS layer: `GetAppKey` checks the chain.
#[derive(Debug)]
struct AnyClientCert(Arc<CryptoProvider>);

impl ClientCertVerifier for AnyClientCert {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// One request per connection: answer it, send close_notify, then close.
fn serve_kms(tcp: TcpStream, config: Arc<ServerConfig>, state: &KmsState) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
    let connection = match ServerConnection::new(config) {
        Ok(connection) => connection,
        Err(error) => {
            state.log.lock().connection_errors.push(error.to_string());
            return;
        }
    };
    let mut tls = StreamOwned::new(connection, tcp);
    let request = match read_request(&mut tls) {
        Ok(Some(request)) => request,
        Ok(None) => return,
        Err(error) => {
            state.log.lock().connection_errors.push(error.to_string());
            return;
        }
    };
    let chain: Vec<Vec<u8>> = tls
        .conn
        .peer_certificates()
        .map(|chain| chain.iter().map(|cert| cert.to_vec()).collect())
        .unwrap_or_default();
    let (status, reply) = state.answer(&request, &chain);
    let _ = write_response(&mut tls, status, &reply);
    tls.conn.send_close_notify();
    while tls.conn.wants_write() {
        if tls.conn.write_tls(&mut tls.sock).is_err() {
            break;
        }
    }
    let _ = tls.sock.shutdown(Shutdown::Write);
    // Wait for the client to close, so closing here never resets the
    // connection before the client has read the reply.
    let _ = tls.sock.set_read_timeout(Some(Duration::from_secs(5)));
    let mut sink = [0u8; 1024];
    while matches!(tls.sock.read(&mut sink), Ok(read) if read > 0) {}
}

fn refuse(error: impl Into<String>) -> (&'static str, Value) {
    ("400 Bad Request", json!({ "error": error.into() }))
}

impl KmsState {
    fn answer(&self, request: &Request, chain: &[Vec<u8>]) -> (&'static str, Value) {
        let line = request.line();
        self.log.lock().requests.push(line.clone());
        match line.as_str() {
            GET_TEMP_CA_CERT => (
                "200 OK",
                json!({
                    "temp_ca_cert": self.temp_ca_pem,
                    "temp_ca_key": self.temp_ca_key_pem,
                    "ca_cert": self.ca_pem,
                }),
            ),
            GET_APP_KEY => self.get_app_key(request, chain),
            _ => ("404 Not Found", json!({ "error": "no such method" })),
        }
    }

    fn get_app_key(&self, request: &Request, chain: &[Vec<u8>]) -> (&'static str, Value) {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let verdict = self.check_app_key_request(&body, chain);
        self.log.lock().app_key_calls.push(AppKeyCall {
            body: body.clone(),
            verdict: verdict.clone(),
        });
        if let Err(error) = verdict {
            return refuse(error);
        }
        let requested = body["root_epoch"].as_u64().unwrap();
        match self.scenario {
            Scenario::Happy => match requested {
                0 | 1 => (
                    "200 OK",
                    self.app_key_reply(requested as usize, requested as usize, requested),
                ),
                _ => refuse(format!("unknown root epoch {requested}")),
            },
            Scenario::WrongEpoch => ("200 OK", self.app_key_reply(1, 1, 1)),
            Scenario::BadSignature => ("200 OK", self.app_key_reply(0, 1, 0)),
            Scenario::Refused => {
                refuse(format!("app is not authorized for root epoch {requested}"))
            }
        }
    }

    /// The checks a KMS makes on an RA-TLS `GetAppKey`
    /// (docs/tc-3554-kms-epoch-fetch.md, steps 4 to 7).
    fn check_app_key_request(&self, body: &Value, chain: &[Vec<u8>]) -> Result<(), String> {
        let [leaf, temp_ca] = chain else {
            return Err(format!(
                "the client chain must be [RA-TLS cert, temp CA cert], got {} certificates",
                chain.len()
            ));
        };
        if *temp_ca != self.temp_ca_der {
            return Err("the client chain's second certificate is not the temp CA".into());
        }
        let (_, temp_ca) = parse_x509_certificate(&self.temp_ca_der)
            .map_err(|error| format!("temp CA: {error:?}"))?;
        let (_, cert) = parse_x509_certificate(leaf)
            .map_err(|error| format!("client certificate: {error:?}"))?;
        cert.verify_signature(Some(temp_ca.public_key()))
            .map_err(|error| {
                format!("client certificate is not signed by the temp CA: {error:?}")
            })?;

        let quote = extension(&cert, QUOTE_OID)?;
        let event_log = extension(&cert, EVENT_LOG_OID)?;
        let report_data = quote_report_data(quote)?;
        let expected = Sha512::new()
            .chain_update(b"ratls-cert:")
            .chain_update(cert.public_key().raw)
            .finalize();
        if report_data != &expected[..] {
            return Err(
                "quote REPORTDATA is not SHA-512(\"ratls-cert:\" || certificate SPKI)".into(),
            );
        }
        if event_log != EVENT_LOG.as_bytes() {
            return Err(format!(
                "event log extension is not the agent's event_log verbatim: {:?}",
                String::from_utf8_lossy(event_log)
            ));
        }

        if body["api_version"].as_u64() != Some(1) {
            return Err(format!(
                "api_version must be 1, got {}",
                body["api_version"]
            ));
        }
        if body["root_epoch"].as_u64().is_none() {
            return Err(format!(
                "root_epoch must be a number, got {}",
                body["root_epoch"]
            ));
        }
        if body["app_epoch"].as_u64() != Some(0) {
            return Err(format!("app_epoch must be 0, got {}", body["app_epoch"]));
        }
        Ok(())
    }

    /// A `GetAppKey` reply with app key `key`, its issuance signed by the
    /// root of epoch `signer`, claiming `root_epoch`.
    fn app_key_reply(&self, key: usize, signer: usize, root_epoch: u64) -> Value {
        json!({
            "ca_cert": self.ca_pem,
            "disk_crypt_key": hex::encode([0xd1u8; 32]),
            "env_crypt_key": hex::encode([0xe1u8; 32]),
            "k256_key": hex::encode(APP_KEYS[key]),
            "k256_signature": hex::encode(issuance_signature(&KMS_ROOT_KEYS[signer], &APP_KEYS[key])),
            "tproxy_app_id": "",
            "gateway_app_id": "",
            "os_image_hash": "",
            "root_epoch": root_epoch,
            "app_epoch": 0,
        })
    }
}

/// The DER OCTET STRING content of the certificate extension `oid`.
fn extension<'a>(cert: &X509Certificate<'a>, oid: &str) -> Result<&'a [u8], String> {
    let extension = cert
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == oid)
        .ok_or_else(|| format!("client certificate lacks extension {oid}"))?;
    octet_string_content(extension.value).map_err(|error| format!("extension {oid}: {error}"))
}

// ---------------------------------------------------------------------------
// Stand-in dstack-key-recovery sidecar
// ---------------------------------------------------------------------------

/// How the stand-in sidecar answers `GET /v0/key`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SidecarScenario {
    /// The requested epoch's key with a valid signature chain.
    Happy,
    /// Always epoch 1's key and chain, with `root_epoch: 1`.
    WrongEpoch,
    /// Epoch 0's key and `root_epoch: 0`, issuance signed by epoch 1's root.
    BadSignature,
    /// Epoch 0's primary key (so the right DID), but the app root's
    /// signature covers another derived key's public key.
    ChainForAnotherKey,
    /// HTTP 500: the sidecar could not get the epoch's keys.
    Refused,
}

/// dstack-key-recovery on a Unix socket. It records every request head
/// (with its terminating blank line) it receives.
struct Sidecar {
    socket: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Sidecar {
    fn start(socket: PathBuf, scenario: SidecarScenario) -> Self {
        let listener = UnixListener::bind(&socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || serve_sidecar(stream, scenario, &recorded));
            }
        });
        Self { socket, requests }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().clone()
    }
}

fn serve_sidecar(mut stream: UnixStream, scenario: SidecarScenario, recorded: &Mutex<Vec<String>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(Some(request)) = read_request(&mut stream) else {
        return;
    };
    recorded.lock().push(format!("{}\r\n\r\n", request.head));
    let requested = request
        .path
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("root_epoch="))
        .and_then(|epoch| epoch.parse::<usize>().ok());
    let reply = match (request.method.as_str(), scenario, requested) {
        ("GET", SidecarScenario::Happy, Some(epoch @ (0 | 1))) => {
            Some(sidecar_reply(epoch, epoch, PRIMARY_KEY_PATH))
        }
        ("GET", SidecarScenario::WrongEpoch, Some(_)) => {
            Some(sidecar_reply(1, 1, PRIMARY_KEY_PATH))
        }
        ("GET", SidecarScenario::BadSignature, Some(_)) => {
            Some(sidecar_reply(0, 1, PRIMARY_KEY_PATH))
        }
        ("GET", SidecarScenario::ChainForAnotherKey, Some(_)) => {
            Some(sidecar_reply(0, 0, "tinycloud/keys/another"))
        }
        _ => None,
    };
    let _ = match reply {
        Some(reply) => write_response(&mut stream, "200 OK", &reply),
        None => write_text(
            &mut stream,
            "500 Internal Server Error",
            "text/plain",
            &format!(
                "failed to get the keys of root epoch {}: app is not authorized",
                requested.map_or("?".to_owned(), |epoch| epoch.to_string())
            ),
        ),
    };
    let _ = stream.shutdown(Shutdown::Write);
}

/// A `GET /v0/key` reply (dstack-key-recovery 0.6.5) for the primary key of
/// epoch `epoch`'s app key, claiming `root_epoch: epoch`. The chain is the
/// app root's signature of the public key of the key derived at
/// `signed_path`, then the issuance of that app key by epoch `signer`'s root.
fn sidecar_reply(epoch: usize, signer: usize, signed_path: &str) -> Value {
    let app_key = &APP_KEYS[epoch];
    let key = legacy_get_key(app_key, PRIMARY_KEY_PATH);
    let signed_public_key = compressed_pubkey(&legacy_get_key(app_key, signed_path));
    json!({
        "api": "v0",
        "key": hex::encode(key),
        "public_key": hex::encode(compressed_pubkey(&key)),
        "signature_chain": [
            hex::encode(key_signature(app_key, &signed_public_key)),
            hex::encode(issuance_signature(&KMS_ROOT_KEYS[signer], app_key)),
        ],
        "root_epoch": epoch,
        "app_epoch": 0,
    })
}

// ---------------------------------------------------------------------------
// The TEE: agent + KMS, and the node configured against them
// ---------------------------------------------------------------------------

struct Tee {
    _sockets: tempfile::TempDir,
    agent: Agent,
    kms: Kms,
}

impl Tee {
    fn start(scenario: Scenario) -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let agent = Agent::start(sockets.path().join("dstack.sock"));
        Self {
            _sockets: sockets,
            agent,
            kms: Kms::start(scenario),
        }
    }

    /// The container entrypoint in `cwd`, selecting `DstackKmsEpoch` for
    /// root epoch 0 with every pin correct.
    fn node(&self, cwd: &Path) -> Command {
        let mut command = tinycloud(cwd);
        command
            .env("TINYCLOUD_KEYS__TYPE", "DstackKmsEpoch")
            .env(
                "TINYCLOUD_KEYS__LEGACY__KMS_URL",
                format!("https://localhost:{}", self.kms.port),
            )
            .env("TINYCLOUD_KEYS__LEGACY__ROOT_EPOCH", "0")
            .env(
                "TINYCLOUD_KEYS__LEGACY__KMS_ROOT_PUBKEY",
                hex::encode(compressed_pubkey(&KMS_ROOT_KEYS[0])),
            )
            .env(
                "TINYCLOUD_KEYS__LEGACY__KMS_CA_CERT",
                base64::encode(&self.kms.ca_der),
            )
            .env("TINYCLOUD_KEYS__LEGACY__APP_ID", hex::encode(APP_ID))
            .env("TINYCLOUD_KEYS__LEGACY__EXPECTED_DID", epoch_did(0))
            .env("DSTACK_SIMULATOR_ENDPOINT", &self.agent.socket);
        command
    }

    /// The node asked for exactly `count` app keys, each an attested,
    /// protocol-correct request for root epoch 0.
    fn assert_app_key_requests(&self, count: usize) {
        let log = self.kms.log();
        assert_eq!(log.app_key_calls.len(), count, "{log:#?}");
        for call in &log.app_key_calls {
            assert_eq!(call.verdict, Ok(()), "{log:#?}");
            assert_eq!(call.body["root_epoch"], json!(0), "{log:#?}");
        }
    }
}

/// The guest agent and the key-recovery sidecar; no KMS.
struct SidecarTee {
    _sockets: tempfile::TempDir,
    agent: Agent,
    sidecar: Sidecar,
}

impl SidecarTee {
    fn start(scenario: SidecarScenario) -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let agent = Agent::start(sockets.path().join("dstack.sock"));
        let sidecar = Sidecar::start(sockets.path().join("key-recovery.sock"), scenario);
        Self {
            _sockets: sockets,
            agent,
            sidecar,
        }
    }

    /// The container entrypoint in `cwd`, selecting `DstackKmsEpoch` through
    /// the sidecar for root epoch 0 with every pin correct.
    fn node(&self, cwd: &Path) -> Command {
        let mut command = tinycloud(cwd);
        command
            .env("TINYCLOUD_KEYS__TYPE", "DstackKmsEpoch")
            .env(
                "TINYCLOUD_KEYS__LEGACY__KEY_RECOVERY_SOCKET",
                &self.sidecar.socket,
            )
            .env("TINYCLOUD_KEYS__LEGACY__ROOT_EPOCH", "0")
            .env(
                "TINYCLOUD_KEYS__LEGACY__KMS_ROOT_PUBKEY",
                hex::encode(compressed_pubkey(&KMS_ROOT_KEYS[0])),
            )
            .env("TINYCLOUD_KEYS__LEGACY__APP_ID", hex::encode(APP_ID))
            .env("TINYCLOUD_KEYS__LEGACY__EXPECTED_DID", epoch_did(0))
            .env("DSTACK_SIMULATOR_ENDPOINT", &self.agent.socket);
        command
    }

    /// The sidecar got exactly `count` requests, each the exact epoch-0
    /// request.
    fn assert_sidecar_requests(&self, count: usize) {
        let requests = self.sidecar.requests();
        assert_eq!(requests.len(), count, "{requests:#?}");
        for request in &requests {
            assert_eq!(request, SIDECAR_REQUEST, "{requests:#?}");
        }
    }

    /// A refused start, through the sidecar under `scenario`: one request,
    /// no fallback, and nothing written to the database.
    fn assert_refused_start(scenario: SidecarScenario) -> String {
        let tee = Self::start(scenario);
        let dir = shipped_layout();
        let (code, log) = run_to_exit(tee.node(dir.path()), dir.path());
        assert_refused(code, &log);
        tee.assert_sidecar_requests(1);
        tee.agent.assert_never_asked_for_the_node_key();
        assert!(!assert_only_root_wrap(dir.path()));
        log
    }
}

/// Seed the shipped layout's database with the `root_wrap` row a previous
/// boot would have stored, but sealing `root`: under the stand-in agent's
/// `GetKey` answer, for the pinned app id and epoch 0's DID.
fn seed_root_wrap(cwd: &Path, root: &[u8]) {
    fs::create_dir_all(cwd.join("data")).unwrap();
    let url = format!("sqlite:{}?mode=rwc", database(cwd).display());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db = tinycloud_core::sea_orm::Database::connect(url)
            .await
            .unwrap();
        root_wrap::ensure_table(&db).await.unwrap();
        root_wrap::insert_if_absent(
            &db,
            &root_wrap::WrappedRoot {
                wrapped: root_wrap::seal(
                    &CURRENT_GET_KEY,
                    &root_wrap::aad(&APP_ID, &epoch_did(0)),
                    root,
                ),
                node_did: epoch_did(0),
                kms_root_epoch: 0,
            },
        )
        .await
        .unwrap();
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The fixture's derivations reproduce the spec's test vectors, so the
/// stand-in KMS signs and the tests derive DIDs exactly as specified.
#[test]
fn fixture_derivations_match_the_spec_vectors() {
    assert_eq!(
        hex::encode(Keccak256::digest(b"")),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    let app_pub = compressed_pubkey(&[0x01; 32]);
    assert_eq!(
        hex::encode(&app_pub),
        "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
    );
    assert_eq!(
        hex::encode(issuance_digest(&[0x35; 20], &app_pub)),
        "b5e4fd2ef63b05285fe79190ddfb3e40efba1eef5a507bf4aed05da771847721"
    );
    let root = legacy_get_key(&[0x01; 32], PRIMARY_KEY_PATH);
    assert_eq!(
        hex::encode(root),
        "bbeb1e02123fe7cfab8471656ab89eff4d0b517fabdd457aa624942d1d5e0b02"
    );
    assert_eq!(
        StaticSecret::new(root.to_vec()).unwrap().node_did(),
        "did:key:z6Mki14g4VZeY9fra5wUt8m5DmYkmAfWDtUKecu65Kd1uWU9"
    );
    assert_eq!(
        der_octet_string(b"kms:rpc"),
        [0x04u8, 0x07, 0x6b, 0x6d, 0x73, 0x3a, 0x72, 0x70, 0x63]
    );
}

/// The node fetches epoch 0's app key over RA-TLS, serves its DID (not
/// epoch 1's, not dstack GetKey's), opens its database, and keeps serving
/// when the any-source DID pin names that DID.
#[test]
fn happy_path_serves_the_epoch0_did() {
    let tee = Tee::start(Scenario::Happy);
    let expected = epoch_did(0);
    assert_ne!(expected, epoch_did(1));
    let current = StaticSecret::new(CURRENT_GET_KEY.to_vec())
        .unwrap()
        .node_did();
    assert_ne!(expected, current);

    let dir = shipped_layout();
    let node = start_node(tee.node(dir.path()), dir.path());
    assert_eq!(node.did, expected);
    // The observable the refusal tests rely on: this same configuration
    // creates the database file once startup gets that far.
    assert!(
        database(dir.path()).exists(),
        "a serving node did not create {}",
        database(dir.path()).display()
    );
    let log = node.log();
    for secret in [
        hex::encode(APP_KEYS[0]),
        hex::encode(legacy_get_key(&APP_KEYS[0], PRIMARY_KEY_PATH)),
    ] {
        assert!(
            !log.contains(&secret),
            "the node logged key material:\n{log}"
        );
    }

    let kms = tee.kms.log();
    assert_eq!(kms.requests, [GET_TEMP_CA_CERT, GET_APP_KEY], "{kms:#?}");
    tee.assert_app_key_requests(1);
    let call = &kms.app_key_calls[0];
    assert_eq!(call.body["api_version"], json!(1), "{kms:#?}");
    assert_eq!(call.body["vm_config"], json!(VM_CONFIG), "{kms:#?}");
    assert_eq!(call.body["app_epoch"], json!(0), "{kms:#?}");
    let agent = tee.agent.requests();
    assert!(agent.iter().any(|line| line == "GET /Info"), "{agent:?}");
    assert!(
        agent.iter().any(|line| line == "POST /GetQuote"),
        "{agent:?}"
    );
    tee.agent.assert_never_asked_for_the_node_key();
    drop(node);

    let pinned_dir = shipped_layout();
    let mut pinned = tee.node(pinned_dir.path());
    pinned.env("TINYCLOUD_KEYS__EXPECTED_NODE_DID", &expected);
    assert_eq!(start_node(pinned, pinned_dir.path()).did, expected);
    tee.assert_app_key_requests(2);
    tee.agent.assert_never_asked_for_the_node_key();
}

/// A KMS that answers another root epoch than the one requested.
#[test]
fn epoch_mismatch_refuses_startup() {
    let tee = Tee::start(Scenario::WrongEpoch);
    let dir = shipped_layout();
    let (code, log) = run_to_exit(tee.node(dir.path()), dir.path());
    assert_refused(code, &log);
    assert!(log.contains("root_epoch"), "{log}");
    tee.assert_app_key_requests(1);
    tee.agent.assert_never_asked_for_the_node_key();
    assert!(!assert_only_root_wrap(dir.path()));
}

/// An app key whose issuance is not signed by the pinned epoch-0 root.
#[test]
fn bad_issuance_signature_refuses_startup() {
    let tee = Tee::start(Scenario::BadSignature);
    let dir = shipped_layout();
    let (code, log) = run_to_exit(tee.node(dir.path()), dir.path());
    assert_refused(code, &log);
    assert!(log.to_lowercase().contains("signature"), "{log}");
    tee.assert_app_key_requests(1);
    tee.agent.assert_never_asked_for_the_node_key();
    assert!(!assert_only_root_wrap(dir.path()));
}

/// A KMS that refuses the epoch: no retry, no fallback to dstack GetKey.
#[test]
fn kms_refusal_refuses_startup_without_fallback() {
    let tee = Tee::start(Scenario::Refused);
    let dir = shipped_layout();
    let (code, log) = run_to_exit(tee.node(dir.path()), dir.path());
    assert_refused(code, &log);
    tee.assert_app_key_requests(1);
    let kms = tee.kms.log();
    assert_eq!(
        kms.requests
            .iter()
            .filter(|line| *line == GET_APP_KEY)
            .count(),
        1,
        "{kms:#?}"
    );
    tee.agent.assert_never_asked_for_the_node_key();
    assert!(!assert_only_root_wrap(dir.path()));
}

/// A fetched root whose DID is not the pinned legacy DID, and a served DID
/// that is not the any-source pin: both refuse before anything but
/// `root_wrap` is written. The fetched root's own DID check refuses before
/// it is sealed.
#[test]
fn did_mismatch_refuses_before_any_other_database_write() {
    let tee = Tee::start(Scenario::Happy);
    let other = epoch_did(1);

    let dir = shipped_layout();
    let mut wrong_legacy_pin = tee.node(dir.path());
    wrong_legacy_pin.env("TINYCLOUD_KEYS__LEGACY__EXPECTED_DID", &other);
    let (code, log) = run_to_exit(wrong_legacy_pin, dir.path());
    assert_refused(code, &log);
    assert!(!assert_only_root_wrap(dir.path()));
    // The fetch itself succeeded; the DID check refused.
    tee.assert_app_key_requests(1);

    let dir = shipped_layout();
    let mut wrong_node_pin = tee.node(dir.path());
    wrong_node_pin.env("TINYCLOUD_KEYS__EXPECTED_NODE_DID", &other);
    let (code, log) = run_to_exit(wrong_node_pin, dir.path());
    assert_refused(code, &log);
    assert!(assert_only_root_wrap(dir.path()));
    tee.assert_app_key_requests(2);

    tee.agent.assert_never_asked_for_the_node_key();
}

/// Through the sidecar, the node serves epoch 0's DID from exactly one
/// `GET /v0/key`, never asks dstack for a key, and opens its database.
#[test]
fn sidecar_happy_path_serves_the_epoch0_did() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let expected = epoch_did(0);
    let dir = shipped_layout();
    let node = start_node(tee.node(dir.path()), dir.path());
    assert_eq!(node.did, expected);
    assert!(
        database(dir.path()).exists(),
        "a serving node did not create {}",
        database(dir.path()).display()
    );
    let log = node.log();
    for secret in [
        hex::encode(APP_KEYS[0]),
        hex::encode(legacy_get_key(&APP_KEYS[0], PRIMARY_KEY_PATH)),
    ] {
        assert!(
            !log.contains(&secret),
            "the node logged key material:\n{log}"
        );
    }
    tee.assert_sidecar_requests(1);
    let agent = tee.agent.requests();
    assert!(agent.iter().any(|line| line == "GET /Info"), "{agent:?}");
    tee.agent.assert_never_asked_for_the_node_key();
}

/// A sidecar that answers another root epoch than the one requested.
#[test]
fn sidecar_epoch_mismatch_refuses_startup() {
    let log = SidecarTee::assert_refused_start(SidecarScenario::WrongEpoch);
    assert!(log.contains("root_epoch"), "{log}");
}

/// A key whose issuance is not signed by the pinned epoch-0 root.
#[test]
fn sidecar_bad_issuance_signature_refuses_startup() {
    let log = SidecarTee::assert_refused_start(SidecarScenario::BadSignature);
    assert!(log.to_lowercase().contains("signature"), "{log}");
}

/// The right key (its DID matches the pin), but a chain that certifies
/// another key: only the chain check can refuse it.
#[test]
fn sidecar_chain_for_another_key_refuses_startup() {
    SidecarTee::assert_refused_start(SidecarScenario::ChainForAnotherKey);
}

/// A sidecar that cannot get the epoch's keys: no retry, no fallback to
/// dstack GetKey (and no KMS is running to fall back to).
#[test]
fn sidecar_refusal_refuses_startup_without_fallback() {
    SidecarTee::assert_refused_start(SidecarScenario::Refused);
}

/// Through the sidecar, a fetched root whose DID is not the pinned legacy
/// DID, and a served DID that is not the any-source pin: both refuse before
/// anything but `root_wrap` is written.
#[test]
fn sidecar_did_mismatch_refuses_before_any_other_database_write() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let other = epoch_did(1);

    let dir = shipped_layout();
    let mut wrong_legacy_pin = tee.node(dir.path());
    wrong_legacy_pin.env("TINYCLOUD_KEYS__LEGACY__EXPECTED_DID", &other);
    let (code, log) = run_to_exit(wrong_legacy_pin, dir.path());
    assert_refused(code, &log);
    assert!(!assert_only_root_wrap(dir.path()));
    tee.assert_sidecar_requests(1);

    let dir = shipped_layout();
    let mut wrong_node_pin = tee.node(dir.path());
    wrong_node_pin.env("TINYCLOUD_KEYS__EXPECTED_NODE_DID", &other);
    let (code, log) = run_to_exit(wrong_node_pin, dir.path());
    assert_refused(code, &log);
    assert!(assert_only_root_wrap(dir.path()));
    tee.assert_sidecar_requests(2);

    tee.agent.assert_never_asked_for_the_node_key();
}

/// The sidecar socket and the KMS both configured: refused before the node
/// calls the agent, the sidecar or the KMS.
#[test]
fn two_transports_configured_refuses_before_any_call() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let kms = Kms::start(Scenario::Happy);
    let dir = shipped_layout();
    let mut both = tee.node(dir.path());
    both.env(
        "TINYCLOUD_KEYS__LEGACY__KMS_URL",
        format!("https://localhost:{}", kms.port),
    )
    .env(
        "TINYCLOUD_KEYS__LEGACY__KMS_CA_CERT",
        base64::encode(&kms.ca_der),
    );
    let (code, log) = run_to_exit(both, dir.path());
    assert_refused(code, &log);
    assert!(log.contains("key_recovery_socket"), "{log}");
    assert_eq!(tee.agent.requests(), Vec::<String>::new());
    assert_eq!(tee.sidecar.requests(), Vec::<String>::new());
    let kms = kms.log();
    assert!(kms.requests.is_empty(), "{kms:#?}");
    assert!(kms.connection_errors.is_empty(), "{kms:#?}");
    assert_database_never_opened(dir.path());
}

/// No `root_wrap` blob and no transport: refused before any call to the
/// agent or the sidecar, with nothing written but the empty table.
#[test]
fn no_blob_and_no_transport_refuses_startup() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let dir = shipped_layout();
    let mut neither = tee.node(dir.path());
    neither.env_remove("TINYCLOUD_KEYS__LEGACY__KEY_RECOVERY_SOCKET");
    let (code, log) = run_to_exit(neither, dir.path());
    assert_refused(code, &log);
    assert!(log.contains("no root_wrap blob"), "{log}");
    assert!(log.contains("key_recovery_socket"), "{log}");
    assert_eq!(tee.agent.requests(), Vec::<String>::new());
    assert_eq!(tee.sidecar.requests(), Vec::<String>::new());
    assert!(!assert_only_root_wrap(dir.path()));
}

/// The first boot seals epoch 0's root in `root_wrap` under the wrap key
/// (`GetKey("tinycloud/keys/primary-wrap")`) and the pinned AAD. Later
/// boots open it and serve the same DID without calling the sidecar,
/// whether or not it is still configured. The seal and opened log lines are
/// the deploy gate for the sidecar-free compose.
#[test]
fn a_sealed_root_boots_without_the_sidecar() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let expected = epoch_did(0);
    let dir = shipped_layout();
    let first = start_node(tee.node(dir.path()), dir.path());
    assert_eq!(first.did, expected);
    let log = first.log();
    for line in [
        "fetched and verified the node root",
        "sealed the node root into root_wrap",
        "opened the node root from root_wrap",
    ] {
        assert!(log.contains(line), "{log}");
    }
    drop(first);
    tee.assert_sidecar_requests(1);
    assert!(tables(dir.path()).contains(&"renewal_identity".to_owned()));
    let (wrapped, node_did, epoch) =
        stored_root(dir.path()).expect("the first boot stored no root_wrap blob");
    assert_eq!((node_did.as_str(), epoch), (expected.as_str(), 0));
    let unsealed = root_wrap::unseal(
        &CURRENT_GET_KEY,
        &root_wrap::aad(&APP_ID, &expected),
        &wrapped,
    )
    .unwrap();
    assert_eq!(
        unsealed.as_slice(),
        legacy_get_key(&APP_KEYS[0], PRIMARY_KEY_PATH)
    );

    // Restart still on the sidecar compose: opened, nothing fetched or
    // sealed.
    let restart = start_node(tee.node(dir.path()), dir.path());
    assert_eq!(restart.did, expected);
    let log = restart.log();
    assert!(log.contains("opened the node root from root_wrap"), "{log}");
    for line in ["fetched and verified", "sealed the node root"] {
        assert!(!log.contains(line), "{log}");
    }
    drop(restart);

    let mut no_sidecar = tee.node(dir.path());
    no_sidecar.env_remove("TINYCLOUD_KEYS__LEGACY__KEY_RECOVERY_SOCKET");
    assert_eq!(start_node(no_sidecar, dir.path()).did, expected);
    tee.assert_sidecar_requests(1);
    assert_eq!(stored_root(dir.path()).unwrap().0, wrapped);
    tee.agent.assert_never_asked_for_the_node_key();
}

/// A tampered blob refuses startup. The node neither fetches the root
/// again nor falls back to the current root.
#[test]
fn a_tampered_blob_refuses_startup_without_fallback() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let dir = shipped_layout();
    start_node(tee.node(dir.path()), dir.path());
    let (mut wrapped, _, _) = stored_root(dir.path()).unwrap();
    wrapped[20] ^= 1;
    rusqlite::Connection::open(database(dir.path()))
        .unwrap()
        .execute(
            "UPDATE root_wrap SET wrapped = ?1 WHERE id = 1",
            rusqlite::params![wrapped],
        )
        .unwrap();

    let (code, log) = run_to_exit(tee.node(dir.path()), dir.path());
    assert_refused(code, &log);
    assert!(log.contains("root_wrap blob does not open"), "{log}");
    tee.assert_sidecar_requests(1);
    tee.agent.assert_never_asked_for_the_node_key();
}

/// A blob that opens under the wrap key and the pinned AAD but holds a root
/// with another DID refuses startup before any migration or renewal
/// identity write.
#[test]
fn an_unsealed_root_with_another_did_refuses_before_any_other_write() {
    let tee = SidecarTee::start(SidecarScenario::Happy);
    let dir = shipped_layout();
    seed_root_wrap(dir.path(), &legacy_get_key(&APP_KEYS[1], PRIMARY_KEY_PATH));
    let mut no_sidecar = tee.node(dir.path());
    no_sidecar.env_remove("TINYCLOUD_KEYS__LEGACY__KEY_RECOVERY_SOCKET");
    let (code, log) = run_to_exit(no_sidecar, dir.path());
    assert_refused(code, &log);
    assert!(
        log.contains("does not derive keys.legacy.expected_did"),
        "{log}"
    );
    assert!(assert_only_root_wrap(dir.path()));
    assert_eq!(tee.sidecar.requests(), Vec::<String>::new());
    tee.agent.assert_never_asked_for_the_node_key();
}
