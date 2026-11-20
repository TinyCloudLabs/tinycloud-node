//! TC-3554: fetch the app root of a historical dstack KMS root epoch from
//! inside the TEE, verify it fail-closed, and derive the node root the
//! guest agent's v0 `GetKey` would have derived from it.
//!
//! The protocol, the checks and their test vectors are specified in
//! `docs/tc-3554-kms-epoch-fetch.md`; OpenKey implements the same document.
//! Every failure is fatal. Nothing here falls back to the current epoch or to
//! the guest agent's `GetKey`.

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, ensure, Context, Result};
use hkdf::Hkdf;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use tinycloud_core::keys::StaticSecret;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::{Zeroize, Zeroizing};

use crate::config::LegacyKmsEpoch;

/// The guest agent path production's node root comes from.
const NODE_KEY_PATH: &[u8] = b"tinycloud/keys/primary";
/// dstack RA-TLS extensions: the raw TDX quote, the event log, and the
/// certificate's special usage.
const OID_TDX_QUOTE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 1];
const OID_EVENT_LOG: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 2];
const OID_SPECIAL_USAGE: &str = "1.3.6.1.4.1.62397.1.4";
/// The special-usage extension value of a KMS RPC certificate: the DER
/// OCTET STRING `kms:rpc`.
const KMS_RPC_USAGE: &[u8] = b"\x04\x07kms:rpc";
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 1 << 20;

static NODE_ROOT: tokio::sync::OnceCell<StaticSecret> = tokio::sync::OnceCell::const_new();

/// The verified node root for `config`, fetched from the KMS at most once
/// per process. A process serves one configuration.
pub async fn node_root(config: &LegacyKmsEpoch) -> Result<StaticSecret> {
    let socket = crate::dstack::socket_path();
    NODE_ROOT
        .get_or_try_init(|| fetch(config, &socket))
        .await
        .cloned()
}

/// The node root if this process already fetched it. Status probes use this
/// so they never call the KMS themselves.
pub fn fetched_node_root() -> Option<StaticSecret> {
    NODE_ROOT.get().cloned()
}

/// The parsed, pinned configuration.
struct Pins {
    host: String,
    port: u16,
    root_epoch: u32,
    kms_root: VerifyingKey,
    kms_ca: CertificateDer<'static>,
    app_id: [u8; 20],
    expected_did: String,
}

impl Pins {
    fn parse(config: &LegacyKmsEpoch) -> Result<Self> {
        let (host, port) = parse_origin(&config.kms_url)?;
        let kms_root = decode_hex("keys.legacy.kms_root_pubkey", &config.kms_root_pubkey)?;
        ensure!(
            kms_root.len() == 33,
            "keys.legacy.kms_root_pubkey must be a 33-byte compressed secp256k1 key, got {} bytes",
            kms_root.len()
        );
        let kms_root = VerifyingKey::from_sec1_bytes(&kms_root)
            .map_err(|_| anyhow!("keys.legacy.kms_root_pubkey is not a secp256k1 point"))?;
        let kms_ca = base64::decode(config.kms_ca_cert.trim())
            .context("keys.legacy.kms_ca_cert must be standard base64 of the CA's DER")?;
        let app_id: [u8; 20] = decode_hex("keys.legacy.app_id", &config.app_id)?
            .try_into()
            .map_err(|id: Vec<u8>| {
                anyhow!("keys.legacy.app_id must be 20 bytes, got {}", id.len())
            })?;
        ensure!(
            config.expected_did.starts_with("did:key:"),
            "keys.legacy.expected_did must be a did:key"
        );
        Ok(Self {
            host,
            port,
            root_epoch: config.root_epoch,
            kms_root,
            kms_ca: CertificateDer::from(kms_ca),
            app_id,
            expected_did: config.expected_did.clone(),
        })
    }
}

/// `https://host[:port]`, with no path, query or credentials.
fn parse_origin(url: &str) -> Result<(String, u16)> {
    let invalid = || anyhow!("keys.legacy.kms_url must be an origin, https://host[:port]");
    let authority = url.strip_prefix("https://").ok_or_else(invalid)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    ensure!(
        !authority.is_empty() && !authority.contains(['/', '?', '#', '@', '[', ']']),
        invalid()
    );
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| invalid())?),
        None => (authority, 443),
    };
    ensure!(!host.is_empty(), invalid());
    Ok((host.to_owned(), port))
}

fn decode_hex(name: &str, value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{name} is not hex"))
}

async fn fetch(config: &LegacyKmsEpoch, socket: &str) -> Result<StaticSecret> {
    let pins = Pins::parse(config)?;

    let info = crate::dstack::get_info()
        .await
        .context("reading the app id from the dstack guest agent")?;
    ensure!(
        decode_hex("guest agent app_id", &info.app_id)? == pins.app_id,
        "the guest agent reports app id {}, not keys.legacy.app_id {}",
        info.app_id,
        hex::encode(pins.app_id)
    );

    let temp_ca: TempCaResponse = serde_json::from_slice(
        &prpc(
            &pins,
            tls_config(&pins.kms_ca, None)?,
            "GetTempCaCert",
            b"{}",
        )
        .await?,
    )
    .context("parsing the KMS GetTempCaCert response")?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("generating the RA-TLS client key")?;
    let report_data = ra_tls_report_data(&key.public_key_der());
    let quote = crate::dstack::get_quote(socket, &report_data)
        .await
        .context("quoting the RA-TLS client key")?;
    let quote_bytes =
        hex::decode(quote.quote.trim_start_matches("0x")).context("decoding the quote")?;
    let chain = ra_tls_client_chain(
        &temp_ca.temp_ca_cert,
        &temp_ca.temp_ca_key,
        &key,
        &quote_bytes,
        quote.event_log.as_bytes(),
    )?;
    let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    drop(key);

    let request = serde_json::to_vec(&serde_json::json!({
        "api_version": 1,
        "vm_config": quote.vm_config,
        "root_epoch": pins.root_epoch,
        "launch_ticket": "",
    }))?;
    let raw = prpc(
        &pins,
        tls_config(&pins.kms_ca, Some((chain, client_key)))?,
        "GetAppKey",
        &request,
    )
    .await?;
    let response: AppKeyResponse =
        serde_json::from_slice(&raw).context("parsing the KMS GetAppKey response")?;
    drop(raw);

    let secret = verify_app_key(&response, &pins)?;
    ::tracing::info!(
        root_epoch = pins.root_epoch,
        node_did = %pins.expected_did,
        "fetched and verified the node root of a historical KMS root epoch"
    );
    Ok(secret)
}

#[derive(Deserialize)]
struct TempCaResponse {
    temp_ca_cert: String,
    temp_ca_key: String,
}

/// The `GetAppKey` fields the checks use; every other field is skipped
/// unparsed. dstack's prpc JSON emits every scalar, zeros included
/// (`#[derive(Serialize)]` with no `skip_serializing_if`, prpc-build 0.6.1
/// `enable_serde_extension`), so an absent epoch is a malformed answer.
#[derive(Deserialize)]
struct AppKeyResponse {
    #[serde(default)]
    k256_key: String,
    #[serde(default)]
    k256_signature: String,
    root_epoch: Option<u32>,
    app_epoch: Option<u32>,
}

impl Drop for AppKeyResponse {
    fn drop(&mut self) {
        self.k256_key.zeroize();
    }
}

/// Checks (a)–(c) of the spec; returns the node root.
fn verify_app_key(response: &AppKeyResponse, pins: &Pins) -> Result<StaticSecret> {
    // (a) The KMS says which root epoch issued the key.
    match response.root_epoch {
        Some(epoch) if epoch == pins.root_epoch => {}
        Some(epoch) => bail!(
            "the KMS answered root_epoch {epoch}, not keys.legacy.root_epoch {}; refusing the key",
            pins.root_epoch
        ),
        None => bail!("the KMS response has no root_epoch; refusing the key"),
    }
    // App epochs above 0 use a different issuance message.
    match response.app_epoch {
        Some(0) => {}
        Some(epoch) => bail!("the KMS answered app_epoch {epoch}; only app epoch 0 is supported"),
        None => bail!("the KMS response has no app_epoch; refusing the key"),
    }

    // (b) That epoch's KMS root signed this app key for this app.
    let app_root = Zeroizing::new(decode_hex("k256_key", &response.k256_key)?);
    ensure!(
        app_root.len() == 32,
        "k256_key must be 32 bytes, got {}",
        app_root.len()
    );
    let app_key = SigningKey::from_slice(&app_root)
        .map_err(|_| anyhow!("k256_key is not a secp256k1 key"))?;
    let app_pub = app_key.verifying_key().to_encoded_point(true);
    drop(app_key);
    let signature = decode_hex("k256_signature", &response.k256_signature)?;
    ensure!(
        signature.len() == 65,
        "k256_signature must be 65 bytes (r || s || v), got {}",
        signature.len()
    );
    let signature = Signature::from_slice(&signature[..64])
        .map_err(|_| anyhow!("k256_signature: r or s is out of range"))?;
    ensure!(
        signature.normalize_s().is_none(),
        "k256_signature is high-S; refusing it"
    );
    pins.kms_root
        .verify_prehash(&issued_digest(&pins.app_id, app_pub.as_bytes()), &signature)
        .map_err(|_| {
            anyhow!(
                "k256_signature does not verify under keys.legacy.kms_root_pubkey for root epoch {}",
                pins.root_epoch
            )
        })?;

    // (c) The root derives the expected identity.
    let root = legacy_get_key(&app_root, NODE_KEY_PATH);
    let secret = StaticSecret::new(root.to_vec()).map_err(|_| anyhow!("derived root is short"))?;
    let node_did = secret.node_did();
    ensure!(
        node_did == pins.expected_did,
        "the root of KMS root epoch {} derives node DID {node_did}, not keys.legacy.expected_did {}",
        pins.root_epoch,
        pins.expected_did
    );
    Ok(secret)
}

/// keccak256("dstack-kms-issued:" || app_id || compressed app public key).
fn issued_digest(app_id: &[u8; 20], app_pub: &[u8]) -> [u8; 32] {
    Keccak256::new()
        .chain_update(b"dstack-kms-issued:")
        .chain_update(app_id)
        .chain_update(app_pub)
        .finalize()
        .into()
}

/// The guest agent's v0 `GetKey(path)`: HKDF-SHA256, salt `RATLS`, keyed by
/// the app root.
fn legacy_get_key(app_root: &[u8], path: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"RATLS"), app_root)
        .expand(path, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// The REPORTDATA binding an RA-TLS certificate's key to its quote.
fn ra_tls_report_data(spki_der: &[u8]) -> [u8; 64] {
    Sha512::new()
        .chain_update(b"ratls-cert:")
        .chain_update(spki_der)
        .finalize()
        .into()
}

/// A DER OCTET STRING holding `content`.
fn der_octet_string(content: &[u8]) -> Vec<u8> {
    let mut der = vec![0x04];
    match content.len() {
        len @ 0..=0x7f => der.push(len as u8),
        len => {
            let bytes = len.to_be_bytes();
            let first = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            der.push(0x80 | (bytes.len() - first) as u8);
            der.extend_from_slice(&bytes[first..]);
        }
    }
    der.extend_from_slice(content);
    der
}

/// `[client certificate, temp CA certificate]`: an RA-TLS certificate for
/// `key` carrying `quote` and `event_log` in dstack's legacy extensions,
/// signed by the KMS temp CA.
fn ra_tls_client_chain(
    temp_ca_cert_pem: &str,
    temp_ca_key_pem: &str,
    key: &KeyPair,
    quote: &[u8],
    event_log: &[u8],
) -> Result<Vec<CertificateDer<'static>>> {
    let temp_ca_key = KeyPair::from_pem(temp_ca_key_pem).context("parsing the KMS temp CA key")?;
    let temp_ca_der = rustls_pemfile::certs(&mut temp_ca_cert_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow!("the KMS temp CA certificate is not PEM"))?
        .context("parsing the KMS temp CA certificate")?;
    let issuer = CertificateParams::from_ca_cert_der(&temp_ca_der)
        .context("parsing the KMS temp CA certificate")?
        .self_signed(&temp_ca_key)
        .context("loading the KMS temp CA")?;

    let mut params = CertificateParams::default();
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, "RA-TLS TEMP Cert");
    params.distinguished_name = subject;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::hours(1);
    params.custom_extensions = vec![
        CustomExtension::from_oid_content(OID_TDX_QUOTE, der_octet_string(quote)),
        CustomExtension::from_oid_content(OID_EVENT_LOG, der_octet_string(event_log)),
    ];
    let cert = params
        .signed_by(key, &issuer, &temp_ca_key)
        .context("signing the RA-TLS client certificate")?;
    Ok(vec![cert.der().clone(), temp_ca_der])
}

/// TLS to the KMS: `kms_ca` is the only trust anchor.
fn tls_config(
    kms_ca: &CertificateDer<'static>,
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(kms_ca.clone())
        .context("keys.legacy.kms_ca_cert is not a usable CA certificate")?;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configuring TLS")?
    .with_root_certificates(roots);
    let config = match client {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .context("loading the RA-TLS client certificate")?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// The server must hold a KMS RPC certificate issued directly by the
/// pinned KMS CA. webpki alone would accept a longer chain, and the KMS CA
/// also issues per-app CAs, whose holders could mint a leaf for the KMS
/// host that chains to the pin.
fn ensure_kms_rpc_cert(der: &[u8], kms_ca: &[u8]) -> Result<()> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| anyhow!("the KMS TLS certificate does not parse"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(kms_ca)
        .map_err(|_| anyhow!("keys.legacy.kms_ca_cert does not parse"))?;
    ensure!(
        cert.issuer() == ca.subject() && cert.verify_signature(Some(ca.public_key())).is_ok(),
        "the KMS TLS certificate is not issued directly by keys.legacy.kms_ca_cert"
    );
    let usage = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == OID_SPECIAL_USAGE)
        .ok_or_else(|| anyhow!("the KMS TLS certificate has no dstack special-usage extension"))?;
    ensure!(
        usage.value == KMS_RPC_USAGE,
        "the KMS TLS certificate is not a KMS RPC certificate"
    );
    Ok(())
}

/// `POST /prpc/{method}?json` to the KMS; the 2xx response body.
async fn prpc(
    pins: &Pins,
    tls: Arc<rustls::ClientConfig>,
    method: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    tokio::time::timeout(CALL_TIMEOUT, prpc_once(pins, tls, method, body))
        .await
        .map_err(|_| anyhow!("KMS {method} timed out"))?
}

async fn prpc_once(
    pins: &Pins,
    tls: Arc<rustls::ClientConfig>,
    method: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let tcp = TcpStream::connect((pins.host.as_str(), pins.port))
        .await
        .with_context(|| format!("connecting to the KMS for {method}"))?;
    let name = ServerName::try_from(pins.host.clone())
        .map_err(|_| anyhow!("keys.legacy.kms_url host is not a valid TLS name"))?;
    let mut stream = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .with_context(|| format!("TLS handshake with the KMS for {method}"))?;
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(|| anyhow!("the KMS presented no certificate"))?;
    ensure_kms_rpc_cert(leaf, &pins.kms_ca)?;

    let host = match pins.port {
        443 => pins.host.clone(),
        port => format!("{}:{port}", pins.host),
    };
    let head = format!(
        "POST /prpc/{method}?json HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    // Sized up front so the buffer holding key material never reallocates.
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        match stream.read(chunk.as_mut()).await {
            Ok(0) => break,
            Ok(n) => {
                ensure!(
                    raw.len() + n <= MAX_RESPONSE_BYTES,
                    "KMS {method} response is too large"
                );
                raw.extend_from_slice(&chunk[..n]);
            }
            // A peer that closes without close_notify; the body length
            // check below still catches truncation.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err).with_context(|| format!("reading KMS {method}")),
        }
    }
    http_body(method, &raw)
}

/// The body of a raw HTTP/1.1 response, or an error naming the refusal.
fn http_body(method: &str, raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("KMS {method}: malformed HTTP response"))?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| anyhow!("KMS {method}: malformed HTTP response"))?;
    let body = &raw[header_end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("KMS {method}: malformed HTTP status"))?;
    if !(200..300).contains(&status) {
        // A refusal carries the KMS's reason and no key material.
        bail!(
            "the KMS refused {method}: HTTP {status}: {}",
            String::from_utf8_lossy(&body[..body.len().min(512)])
        );
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| anyhow!("KMS {method}: bad Content-Length"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
    }
    if chunked {
        return dechunk(method, body);
    }
    match content_length {
        Some(len) => {
            ensure!(body.len() >= len, "KMS {method}: response is truncated");
            Ok(Zeroizing::new(body[..len].to_vec()))
        }
        None => Ok(Zeroizing::new(body.to_vec())),
    }
}

fn dechunk(method: &str, mut body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let malformed = || anyhow!("KMS {method}: malformed chunked response");
    let mut out = Zeroizing::new(Vec::with_capacity(body.len()));
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(malformed)?;
        let size = std::str::from_utf8(&body[..line_end]).map_err(|_| malformed())?;
        let size = size.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| malformed())?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        ensure!(body.len() >= size + 2, malformed());
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::RecoveryId;
    use x509_parser::prelude::FromDer;

    const APP_ID: [u8; 20] = [0x35; 20];
    const APP_ROOT: [u8; 32] = [0x01; 32];
    const VECTOR_DID: &str = "did:key:z6Mki14g4VZeY9fra5wUt8m5DmYkmAfWDtUKecu65Kd1uWU9";

    /// The test vectors in docs/tc-3554-kms-epoch-fetch.md, computed
    /// independently with scripts/key-escrow/decode_bundle.py.
    #[test]
    fn spec_vectors() {
        assert_eq!(
            hex::encode(Keccak256::digest(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        let app_pub = SigningKey::from_slice(&APP_ROOT)
            .unwrap()
            .verifying_key()
            .to_encoded_point(true);
        assert_eq!(
            hex::encode(app_pub.as_bytes()),
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
        );
        assert_eq!(
            hex::encode(issued_digest(&APP_ID, app_pub.as_bytes())),
            "b5e4fd2ef63b05285fe79190ddfb3e40efba1eef5a507bf4aed05da771847721"
        );
        let root = legacy_get_key(&APP_ROOT, NODE_KEY_PATH);
        assert_eq!(
            hex::encode(root.as_ref()),
            "bbeb1e02123fe7cfab8471656ab89eff4d0b517fabdd457aa624942d1d5e0b02"
        );
        assert_eq!(
            StaticSecret::new(root.to_vec()).unwrap().node_did(),
            VECTOR_DID
        );
    }

    fn kms_root(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn pins(root_epoch: u32, kms: &SigningKey) -> Pins {
        Pins {
            host: "localhost".into(),
            port: 443,
            root_epoch,
            kms_root: *kms.verifying_key(),
            kms_ca: CertificateDer::from(Vec::new()),
            app_id: APP_ID,
            expected_did: VECTOR_DID.into(),
        }
    }

    /// What the KMS returns for `APP_ROOT`, signed by `signer`.
    fn response(signer: &SigningKey, root_epoch: Option<u32>) -> AppKeyResponse {
        let app_pub = SigningKey::from_slice(&APP_ROOT)
            .unwrap()
            .verifying_key()
            .to_encoded_point(true);
        let (signature, recovery): (Signature, RecoveryId) = signer
            .sign_prehash_recoverable(&issued_digest(&APP_ID, app_pub.as_bytes()))
            .unwrap();
        let mut sig = signature.to_vec();
        sig.push(recovery.to_byte());
        AppKeyResponse {
            k256_key: hex::encode(APP_ROOT),
            k256_signature: hex::encode(sig),
            root_epoch,
            app_epoch: Some(0),
        }
    }

    fn refusal(response: &AppKeyResponse, pins: &Pins) -> String {
        format!(
            "{:#}",
            verify_app_key(response, pins).err().expect("refused")
        )
    }

    #[test]
    fn a_key_issued_by_the_pinned_epoch_root_derives_the_expected_did() {
        let kms = kms_root(7);
        let secret = verify_app_key(&response(&kms, Some(0)), &pins(0, &kms)).unwrap();
        assert_eq!(secret.node_did(), VECTOR_DID);
    }

    #[test]
    fn the_root_epoch_must_be_present_and_equal() {
        let kms = kms_root(7);
        assert!(refusal(&response(&kms, Some(1)), &pins(0, &kms)).contains("root_epoch 1"));
        assert!(refusal(&response(&kms, None), &pins(0, &kms)).contains("no root_epoch"));
        let mut later_app_epoch = response(&kms, Some(0));
        later_app_epoch.app_epoch = Some(1);
        assert!(refusal(&later_app_epoch, &pins(0, &kms)).contains("app_epoch 1"));
        later_app_epoch.app_epoch = None;
        assert!(refusal(&later_app_epoch, &pins(0, &kms)).contains("no app_epoch"));
    }

    #[test]
    fn a_signature_by_another_root_is_refused() {
        let (pinned, other) = (kms_root(7), kms_root(8));
        assert!(refusal(&response(&other, Some(0)), &pins(0, &pinned)).contains("does not verify"));
    }

    #[test]
    fn a_high_s_signature_is_refused() {
        let kms = kms_root(7);
        let mut high = response(&kms, Some(0));
        let mut sig = hex::decode(&high.k256_signature).unwrap();
        // s -> n - s turns the low-S signature into its high-S twin, which
        // plain ECDSA verification would still accept.
        let low = Signature::from_slice(&sig[..64]).unwrap();
        let (r, s) = low.split_scalars();
        let flipped = Signature::from_scalars(r, -*s).unwrap();
        assert!(flipped.normalize_s().is_some());
        sig[..64].copy_from_slice(&flipped.to_bytes());
        high.k256_signature = hex::encode(sig);
        assert!(refusal(&high, &pins(0, &kms)).contains("high-S"));
    }

    #[test]
    fn a_root_with_another_did_is_refused() {
        let kms = kms_root(7);
        let mut pinned = pins(0, &kms);
        pinned.expected_did = "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi".into();
        assert!(refusal(&response(&kms, Some(0)), &pinned).contains("derives node DID"));
    }

    #[test]
    fn kms_url_must_be_an_https_origin() {
        assert_eq!(
            parse_origin("https://kms.example:8000/").unwrap(),
            ("kms.example".to_owned(), 8000)
        );
        assert_eq!(
            parse_origin("https://kms.example").unwrap(),
            ("kms.example".to_owned(), 443)
        );
        for bad in [
            "http://kms.example",
            "https://kms.example/prpc",
            "https://user@kms.example",
            "https://",
            "https://kms.example:x",
        ] {
            assert!(parse_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn der_octet_string_matches_dstack_extension_encoding() {
        assert_eq!(der_octet_string(b"kms:rpc"), KMS_RPC_USAGE);
        let long = der_octet_string(&[0xaa; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(long.len(), 304);
    }

    /// The client certificate chains to the temp CA and carries the quote
    /// and event log where dstack's `from_ext_getter` reads them.
    #[test]
    fn the_client_certificate_is_a_temp_ca_signed_ra_tls_certificate() {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Dstack Temp CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let quote = vec![0x5a; 1000];
        let chain = ra_tls_client_chain(
            &ca.pem(),
            &ca_key.serialize_pem(),
            &key,
            &quote,
            b"[{\"imr\":3}]",
        )
        .unwrap();
        assert_eq!(chain[1], *ca.der());

        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(&chain[0]).unwrap();
        let (_, issuer) = x509_parser::certificate::X509Certificate::from_der(&chain[1]).unwrap();
        leaf.verify_signature(Some(issuer.public_key())).unwrap();
        assert_eq!(leaf.issuer(), issuer.subject());
        assert_eq!(leaf.public_key().raw, key.public_key_der().as_slice());
        let ext = |oid: &str| {
            leaf.extensions()
                .iter()
                .find(|ext| ext.oid.to_id_string() == oid)
                .unwrap()
                .value
                .to_vec()
        };
        assert_eq!(ext("1.3.6.1.4.1.62397.1.1"), der_octet_string(&quote));
        assert_eq!(
            ext("1.3.6.1.4.1.62397.1.2"),
            der_octet_string(b"[{\"imr\":3}]")
        );
    }

    #[test]
    fn http_bodies_are_length_checked_and_refusals_are_errors() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(http_body("M", ok).unwrap().as_slice(), b"{}");
        let truncated = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}";
        assert!(http_body("M", truncated).is_err());
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n";
        assert_eq!(http_body("M", chunked).unwrap().as_slice(), b"{}");
        let refused = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\nnot authorized!";
        let err = http_body("GetAppKey", refused).unwrap_err().to_string();
        assert!(
            err.contains("refused GetAppKey: HTTP 400: not authorized"),
            "{err}"
        );
    }
}
