//! TC-3554: fetch the app root of a historical dstack KMS root epoch from
//! inside the TEE, verify it fail-closed, and derive the node root the
//! guest agent's v0 `GetKey` would have derived from it.
//!
//! Two transports, chosen by configuration, never one falling back to the
//! other: Phala's dstack-key-recovery sidecar on a unix socket, or our own
//! RA-TLS client straight to the KMS. Both feed the same verifier.
//!
//! The protocol, the checks and their test vectors are specified in
//! `docs/tc-3554-kms-epoch-fetch.md`; OpenKey implements the same document.
//! Every failure is fatal. Nothing here falls back to the current epoch: the
//! guest agent's `GetKey` only derives the key that seals the fetched root in
//! the database (`root_wrap`), never the identity.

use std::{future::Future, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, ensure, Context, Result};
use hkdf::Hkdf;
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use tinycloud_core::{
    keys::StaticSecret,
    root_wrap::{self, WrappedRoot},
    sea_orm::{ConnectionTrait, TransactionTrait},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{LegacyKmsEpoch, RenewalReset};

/// The guest agent path production's node root comes from.
const NODE_KEY_PATH: &[u8] = b"tinycloud/keys/primary";
/// `NODE_KEY_PATH`, percent-encoded for a query string.
const NODE_KEY_QUERY: &str = "tinycloud%2Fkeys%2Fprimary";
/// The guest agent path of the key that seals the node root in `root_wrap`,
/// derived from the current KMS root.
const WRAP_KEY_PATH: &str = "tinycloud/keys/primary-wrap";
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
/// per process, or the root [`wrapped_node_root`] opened. A process serves
/// one configuration.
pub async fn node_root(config: &LegacyKmsEpoch) -> Result<StaticSecret> {
    let socket = crate::dstack::socket_path();
    NODE_ROOT
        .get_or_try_init(|| async {
            let pins = Pins::parse(config)?;
            let transport = pins.transport.as_ref().context(
                "keys.legacy configures no transport (key_recovery_socket, or kms_url with \
                 kms_ca_cert) to fetch the node root from",
            )?;
            fetch(&pins, transport, &socket).await
        })
        .await
        .cloned()
}

/// The node root if this process already fetched or unsealed it. Status
/// probes use this so they never call the KMS themselves.
pub fn fetched_node_root() -> Option<StaticSecret> {
    NODE_ROOT.get().cloned()
}

/// The node root from the database's `root_wrap` blob, opened with this
/// app's wrap key (dstack `GetKey(WRAP_KEY_PATH)` on the current KMS root),
/// so later boots need no historical epoch; and the database connection,
/// which `connect` opens.
///
/// With no blob, the root is fetched once through the configured transport
/// and fully verified, then sealed and stored (first writer wins); the
/// stored blob is read back and opened as on every later boot. Until the
/// identity check here passes, nothing touches the database but the
/// `root_wrap` table. Every failure refuses startup, and nothing falls back
/// to the current root as the identity.
pub async fn wrapped_node_root<C, F, Fut>(
    config: &LegacyKmsEpoch,
    connect: F,
) -> Result<(StaticSecret, C)>
where
    C: ConnectionTrait,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<C>>,
{
    let pins = Pins::parse(config)?;
    let db = connect().await?;
    root_wrap::ensure_table(&db)
        .await
        .context("creating the root_wrap table")?;
    let aad = root_wrap::aad(&pins.app_id, &pins.expected_did);
    let stored = match root_wrap::read(&db).await.context("reading root_wrap")? {
        Some(stored) => stored,
        None => {
            let Some(transport) = &pins.transport else {
                bail!(
                    "the database has no root_wrap blob, and keys.legacy configures no transport \
                     to fetch root epoch {} once and seal it: set key_recovery_socket (or kms_url \
                     with kms_ca_cert) for that boot; refusing to start",
                    pins.root_epoch
                );
            };
            let root = fetch(&pins, transport, &crate::dstack::socket_path()).await?;
            root_wrap::insert_if_absent(
                &db,
                &WrappedRoot {
                    wrapped: root_wrap::seal(&*wrap_key().await?, &aad, root.as_bytes()),
                    node_did: pins.expected_did.clone(),
                    kms_root_epoch: i32::try_from(pins.root_epoch)
                        .context("keys.legacy.root_epoch does not fit root_wrap")?,
                },
            )
            .await
            .context("storing the root_wrap blob")?;
            ::tracing::info!(
                root_epoch = pins.root_epoch,
                "sealed the node root into root_wrap"
            );
            root_wrap::read(&db)
                .await
                .context("reading root_wrap")?
                .context("root_wrap is empty after the blob was stored")?
        }
    };
    let secret = open_wrapped(&stored, &*wrap_key().await?, &aad, &pins)?;
    // A probe or an in-process caller of `node_root` gets this root.
    let _ = NODE_ROOT.set(secret.clone());
    Ok((secret, db))
}

/// The root sealing key: dstack `GetKey(WRAP_KEY_PATH)`, 32 bytes.
async fn wrap_key() -> Result<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(
        crate::dstack::get_key(WRAP_KEY_PATH)
            .await
            .context("deriving the root_wrap key with dstack GetKey")?,
    );
    Ok(Zeroizing::new(key.as_slice().try_into().map_err(|_| {
        anyhow!(
            "dstack GetKey({WRAP_KEY_PATH}) returned {} bytes, not 32",
            key.len()
        )
    })?))
}

/// The node root in a stored `root_wrap` row: the row names the pinned DID
/// and root epoch, the blob opens under `wrap_key` and `aad`, and the opened
/// root derives the pinned DID.
fn open_wrapped(
    stored: &WrappedRoot,
    wrap_key: &[u8; 32],
    aad: &[u8],
    pins: &Pins,
) -> Result<StaticSecret> {
    ensure!(
        stored.node_did == pins.expected_did,
        "the root_wrap row is not for keys.legacy.expected_did {}; refusing it",
        pins.expected_did
    );
    ensure!(
        u32::try_from(stored.kms_root_epoch).ok() == Some(pins.root_epoch),
        "the root_wrap row is for KMS root epoch {}, not keys.legacy.root_epoch {}; refusing it",
        stored.kms_root_epoch,
        pins.root_epoch
    );
    let root = root_wrap::unseal(wrap_key, aad, &stored.wrapped).map_err(|_| {
        anyhow!(
            "the root_wrap blob does not open under this app's wrap key for keys.legacy.app_id \
             and expected_did (tampered, or sealed by another app or for another identity); \
             refusing it"
        )
    })?;
    let secret =
        StaticSecret::new(root.to_vec()).map_err(|_| anyhow!("the unsealed root is short"))?;
    ensure!(
        secret.node_did() == pins.expected_did,
        "the root unsealed from root_wrap does not derive keys.legacy.expected_did {}; refusing it",
        pins.expected_did
    );
    Ok(secret)
}

/// The pinned one-shot renewer identity reset (TC-3554, [`RenewalReset`]):
/// after the identity checks and migrations, before the node initializes
/// its renewer identity from `root`.
pub async fn reset_renewal_identity<C: TransactionTrait + ConnectionTrait>(
    db: &C,
    root: &StaticSecret,
    reset: &RenewalReset,
) -> Result<()> {
    ensure!(
        reset.to_renewer_did == tinycloud_core::renewal::renewal_identity(root).0,
        "keys.legacy.renewal_reset.to_renewer_did is not this node's renewer; refusing to start"
    );
    let applied = tinycloud_core::renewal::reset_renewal_identity(
        db,
        (&reset.from_renewer_did, reset.from_epoch),
        (&reset.to_renewer_did, 1),
    )
    .await
    .context("resetting renewal_identity")?;
    ::tracing::info!(applied, "keys.legacy.renewal_reset checked");
    Ok(())
}

/// The parsed, pinned configuration.
struct Pins {
    /// `None` once the root is sealed in `root_wrap`: nothing to fetch.
    transport: Option<Transport>,
    root_epoch: u32,
    kms_root: VerifyingKey,
    app_id: [u8; 20],
    expected_did: String,
}

enum Transport {
    /// Phala's dstack-key-recovery sidecar, `serve --no-addr` on this socket.
    KeyRecovery { socket: String },
    /// Our RA-TLS client straight to the KMS.
    Kms(KmsEndpoint),
}

struct KmsEndpoint {
    host: String,
    port: u16,
    ca: CertificateDer<'static>,
}

impl Pins {
    fn parse(config: &LegacyKmsEpoch) -> Result<Self> {
        let kms_root = decode_hex("keys.legacy.kms_root_pubkey", &config.kms_root_pubkey)?;
        ensure!(
            kms_root.len() == 33,
            "keys.legacy.kms_root_pubkey must be a 33-byte compressed secp256k1 key, got {} bytes",
            kms_root.len()
        );
        let kms_root = VerifyingKey::from_sec1_bytes(&kms_root)
            .map_err(|_| anyhow!("keys.legacy.kms_root_pubkey is not a secp256k1 point"))?;
        let transport = match (
            &config.key_recovery_socket,
            &config.kms_url,
            &config.kms_ca_cert,
        ) {
            (Some(socket), None, None) => {
                ensure!(
                    socket.starts_with('/'),
                    "keys.legacy.key_recovery_socket must be an absolute path"
                );
                Some(Transport::KeyRecovery {
                    socket: socket.clone(),
                })
            }
            (None, Some(url), Some(ca)) => {
                let (host, port) = parse_origin(url)?;
                let ca = base64::decode(ca.trim())
                    .context("keys.legacy.kms_ca_cert must be standard base64 of the CA's DER")?;
                Some(Transport::Kms(KmsEndpoint {
                    host,
                    port,
                    ca: CertificateDer::from(ca),
                }))
            }
            // Only a boot that finds the root sealed in `root_wrap` can
            // start without one.
            (None, None, None) => None,
            _ => bail!(
                "keys.legacy takes at most one transport: key_recovery_socket, or kms_url \
                 with kms_ca_cert"
            ),
        };
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
            transport,
            root_epoch: config.root_epoch,
            kms_root,
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

async fn fetch(pins: &Pins, transport: &Transport, agent_socket: &str) -> Result<StaticSecret> {
    let info = crate::dstack::get_info()
        .await
        .context("reading the app id from the dstack guest agent")?;
    ensure!(
        decode_hex("guest agent app_id", &info.app_id)? == pins.app_id,
        "the guest agent reports app id {}, not keys.legacy.app_id {}",
        info.app_id,
        hex::encode(pins.app_id)
    );

    let (secret, transport) = match transport {
        Transport::KeyRecovery { socket } => {
            let raw = key_recovery_get(socket, pins.root_epoch).await?;
            let response: RecoveredKey = serde_json::from_slice(&raw)
                .context("parsing the key-recovery /v0/key response")?;
            drop(raw);
            (verify_recovered_key(&response, pins)?, "key-recovery")
        }
        Transport::Kms(kms) => (fetch_app_key(pins, kms, agent_socket).await?, "kms"),
    };
    ::tracing::info!(
        root_epoch = pins.root_epoch,
        transport,
        node_did = %pins.expected_did,
        "fetched and verified the node root of a historical KMS root epoch"
    );
    Ok(secret)
}

/// The KMS transport: our RA-TLS client, `GetAppKey` for the pinned epoch.
async fn fetch_app_key(pins: &Pins, kms: &KmsEndpoint, agent_socket: &str) -> Result<StaticSecret> {
    let temp_ca: TempCaResponse = serde_json::from_slice(
        &prpc(kms, tls_config(&kms.ca, None)?, "GetTempCaCert", b"{}").await?,
    )
    .context("parsing the KMS GetTempCaCert response")?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("generating the RA-TLS client key")?;
    let report_data = ra_tls_report_data(&key.public_key_der());
    let quote = crate::dstack::get_quote(agent_socket, &report_data)
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
        "app_epoch": 0,
        "launch_ticket": "",
    }))?;
    let raw = prpc(
        kms,
        tls_config(&kms.ca, Some((chain, client_key)))?,
        "GetAppKey",
        &request,
    )
    .await?;
    let response: AppKeyResponse =
        serde_json::from_slice(&raw).context("parsing the KMS GetAppKey response")?;
    drop(raw);
    verify_app_key(&response, pins)
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

/// The dstack-key-recovery `/v0/key` answer (its `KeyResult::to_json`).
/// Every field the checks use is required in substance; absent ones fail.
#[derive(Deserialize)]
struct RecoveredKey {
    #[serde(default)]
    api: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    signature_chain: Vec<String>,
    root_epoch: Option<u32>,
    app_epoch: Option<u32>,
}

impl Drop for RecoveredKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Checks (a)–(c) of the spec on a KMS `GetAppKey` answer; returns the node
/// root.
fn verify_app_key(response: &AppKeyResponse, pins: &Pins) -> Result<StaticSecret> {
    // (a) The KMS says which root epoch issued the key.
    check_epochs("the KMS", response.root_epoch, response.app_epoch, pins)?;

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
    verify_issuance(&response.k256_signature, app_pub.as_bytes(), pins)?;

    // (c) The root derives the expected identity.
    expected_identity(&legacy_get_key(&app_root, NODE_KEY_PATH), pins)
}

/// The spec's checks on a dstack-key-recovery answer, which carries the
/// derived key and its signature chain instead of the app root; returns the
/// node root.
///
/// `signature_chain[1]` is the KMS `k256_signature`, so (b) applies to the
/// app key that `signature_chain[0]` recovers. The chain proves the epoch
/// root issued that app key to this app and that the app key vouched for
/// `public_key`; it does not prove the path or the derivation. Only (c), the
/// DID, proves those.
fn verify_recovered_key(response: &RecoveredKey, pins: &Pins) -> Result<StaticSecret> {
    ensure!(
        response.api == "v0",
        "the key-recovery sidecar answered api {:?}, not v0; refusing the key",
        response.api
    );
    // (a)
    check_epochs(
        "the key-recovery sidecar",
        response.root_epoch,
        response.app_epoch,
        pins,
    )?;

    let key = Zeroizing::new(decode_hex("key-recovery key", &response.key)?);
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(
        key.as_slice()
            .try_into()
            .map_err(|_| anyhow!("the key-recovery key must be 32 bytes, got {}", key.len()))?,
    );
    let public_key = SigningKey::from_slice(key.as_ref())
        .map_err(|_| anyhow!("the key-recovery key is not a secp256k1 key"))?
        .verifying_key()
        .to_encoded_point(true);
    ensure!(
        decode_hex("key-recovery public_key", &response.public_key)? == public_key.as_bytes(),
        "the key-recovery public_key is not the public key of its key; refusing the key"
    );

    // (b) on the chain: the app key that signed `public_key` was issued to
    // this app by the pinned epoch root.
    let [link0, issued] = response.signature_chain.as_slice() else {
        bail!(
            "the key-recovery signature_chain must have 2 links, got {}",
            response.signature_chain.len()
        );
    };
    let app_pub = recover_app_pub(link0, public_key.as_bytes())?;
    verify_issuance(issued, app_pub.as_bytes(), pins)?;

    // (c)
    expected_identity(&key, pins)
}

/// (a): both epochs present, the root epoch the pinned one, the app epoch 0
/// (later app epochs use a different issuance message).
fn check_epochs(
    peer: &str,
    root_epoch: Option<u32>,
    app_epoch: Option<u32>,
    pins: &Pins,
) -> Result<()> {
    match root_epoch {
        Some(epoch) if epoch == pins.root_epoch => {}
        Some(epoch) => bail!(
            "{peer} answered root_epoch {epoch}, not keys.legacy.root_epoch {}; refusing the key",
            pins.root_epoch
        ),
        None => bail!("{peer}'s response has no root_epoch; refusing the key"),
    }
    match app_epoch {
        Some(0) => Ok(()),
        Some(epoch) => bail!("{peer} answered app_epoch {epoch}; only app epoch 0 is supported"),
        None => bail!("{peer}'s response has no app_epoch; refusing the key"),
    }
}

/// (b): `k256_signature` (65 bytes, low-S) by the pinned epoch root over
/// keccak256("dstack-kms-issued:" || app_id || app_pub).
fn verify_issuance(k256_signature: &str, app_pub: &[u8], pins: &Pins) -> Result<()> {
    let signature = decode_hex("k256_signature", k256_signature)?;
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
        .verify_prehash(&issued_digest(&pins.app_id, app_pub), &signature)
        .map_err(|_| {
            anyhow!(
                "k256_signature does not verify under keys.legacy.kms_root_pubkey for root epoch {}",
                pins.root_epoch
            )
        })
}

/// The app key behind `signature_chain[0]`: a recoverable signature (r || s
/// || v) over keccak256(purpose || ":" || hex(public_key)), purpose empty.
fn recover_app_pub(link0: &str, public_key: &[u8]) -> Result<k256::EncodedPoint> {
    let link0 = decode_hex("signature_chain[0]", link0)?;
    ensure!(
        link0.len() == 65,
        "signature_chain[0] must be 65 bytes (r || s || v), got {}",
        link0.len()
    );
    let signature = Signature::from_slice(&link0[..64])
        .map_err(|_| anyhow!("signature_chain[0]: r or s is out of range"))?;
    let recovery_id = RecoveryId::from_byte(link0[64])
        .ok_or_else(|| anyhow!("signature_chain[0] has recovery id {}", link0[64]))?;
    let digest: [u8; 32] = Keccak256::new()
        .chain_update(b":")
        .chain_update(hex::encode(public_key))
        .finalize()
        .into();
    let app_pub = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|_| anyhow!("signature_chain[0] recovers no app key"))?;
    Ok(app_pub.to_encoded_point(true))
}

/// (c): the node root derives `keys.legacy.expected_did`.
fn expected_identity(root: &[u8; 32], pins: &Pins) -> Result<StaticSecret> {
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
    kms: &KmsEndpoint,
    tls: Arc<rustls::ClientConfig>,
    method: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    tokio::time::timeout(CALL_TIMEOUT, prpc_once(kms, tls, method, body))
        .await
        .map_err(|_| anyhow!("KMS {method} timed out"))?
}

async fn prpc_once(
    kms: &KmsEndpoint,
    tls: Arc<rustls::ClientConfig>,
    method: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let tcp = TcpStream::connect((kms.host.as_str(), kms.port))
        .await
        .with_context(|| format!("connecting to the KMS for {method}"))?;
    let name = ServerName::try_from(kms.host.clone())
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
    ensure_kms_rpc_cert(leaf, &kms.ca)?;

    let host = match kms.port {
        443 => kms.host.clone(),
        port => format!("{}:{port}", kms.host),
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
    let call = format!("KMS {method}");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    http_exchange(&call, stream).await
}

/// The key-recovery sidecar's `GET /v0/key` for the node key path, the
/// pinned root epoch and app epoch 0; the 2xx response body.
async fn key_recovery_get(socket: &str, root_epoch: u32) -> Result<Zeroizing<Vec<u8>>> {
    let call = "key-recovery /v0/key";
    tokio::time::timeout(CALL_TIMEOUT, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to the key-recovery sidecar at {socket}"))?;
        stream
            .write_all(key_recovery_request(root_epoch).as_bytes())
            .await?;
        http_exchange(call, stream).await
    })
    .await
    .map_err(|_| anyhow!("{call} timed out"))?
}

fn key_recovery_request(root_epoch: u32) -> String {
    format!(
        "GET /v0/key?path={NODE_KEY_QUERY}&root_epoch={root_epoch}&app_epoch=0 HTTP/1.1\r\n\
         Host: key-recovery\r\n\
         Connection: close\r\n\
         \r\n"
    )
}

/// Flushes the written request, reads the response to EOF and returns its
/// 2xx body.
async fn http_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    call: &str,
    mut stream: S,
) -> Result<Zeroizing<Vec<u8>>> {
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
                    "{call} response is too large"
                );
                raw.extend_from_slice(&chunk[..n]);
            }
            // A TLS peer that closes without close_notify; the body length
            // check below still catches truncation.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err).with_context(|| format!("reading {call}")),
        }
    }
    http_body(call, &raw)
}

/// The body of a raw HTTP/1.1 response, or an error naming the refusal.
fn http_body(call: &str, raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("{call}: malformed HTTP response"))?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| anyhow!("{call}: malformed HTTP response"))?;
    let body = &raw[header_end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("{call}: malformed HTTP status"))?;
    if !(200..300).contains(&status) {
        // A refusal carries the peer's reason and no key material.
        bail!(
            "{call} refused: HTTP {status}: {}",
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
                    .map_err(|_| anyhow!("{call}: bad Content-Length"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
    }
    if chunked {
        return dechunk(call, body);
    }
    match content_length {
        Some(len) => {
            ensure!(body.len() >= len, "{call}: response is truncated");
            Ok(Zeroizing::new(body[..len].to_vec()))
        }
        None => Ok(Zeroizing::new(body.to_vec())),
    }
}

fn dechunk(call: &str, mut body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let malformed = || anyhow!("{call}: malformed chunked response");
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
        // The key-recovery chain over that root: its public key and the
        // digest `signature_chain[0]` signs.
        let public_key = SigningKey::from_slice(root.as_ref())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true);
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "0324658ea9452d044b7e5a70c79b352bb73968365b45bed193df98f6dde67a65e3"
        );
        assert_eq!(
            hex::encode(Keccak256::digest(format!(
                ":{}",
                hex::encode(public_key.as_bytes())
            ))),
            "aafcab4c272e0db55aac89ee9d441edb18b2a0a3742794205dcd013d08d25c98"
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
            transport: Some(Transport::KeyRecovery {
                socket: "/run/key-recovery/kr.sock".into(),
            }),
            root_epoch,
            kms_root: *kms.verifying_key(),
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

    /// What the key-recovery sidecar returns for the node path of
    /// `APP_ROOT`, issued by `signer`.
    fn recovered(signer: &SigningKey, root_epoch: Option<u32>) -> RecoveredKey {
        let key = legacy_get_key(&APP_ROOT, NODE_KEY_PATH);
        let public_key = SigningKey::from_slice(key.as_ref())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true);
        RecoveredKey {
            api: "v0".into(),
            key: hex::encode(key.as_ref()),
            public_key: hex::encode(public_key.as_bytes()),
            signature_chain: vec![
                chain_link(&APP_ROOT, public_key.as_bytes()),
                response(signer, root_epoch).k256_signature.clone(),
            ],
            root_epoch,
            app_epoch: Some(0),
        }
    }

    /// `signature_chain[0]` as dstack's `sign_recoverable_keccak256` builds
    /// it: the app key over keccak256(":" || hex(public_key)), r || s || v.
    fn chain_link(app_root: &[u8; 32], public_key: &[u8]) -> String {
        let digest = Keccak256::new()
            .chain_update(format!(":{}", hex::encode(public_key)))
            .finalize();
        let (signature, recovery) = SigningKey::from_slice(app_root)
            .unwrap()
            .sign_prehash_recoverable(&digest)
            .unwrap();
        let mut link = signature.to_vec();
        link.push(recovery.to_byte());
        hex::encode(link)
    }

    fn recovered_refusal(response: &RecoveredKey, pins: &Pins) -> String {
        format!(
            "{:#}",
            verify_recovered_key(response, pins).err().expect("refused")
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

    const WRAP_KEY: [u8; 32] = [0x42; 32];

    /// A `root_wrap` row sealing `root` under `WRAP_KEY` for `app_id` and
    /// the vector DID.
    fn wrapped(root: &[u8], app_id: &[u8; 20]) -> WrappedRoot {
        WrappedRoot {
            wrapped: root_wrap::seal(&WRAP_KEY, &root_wrap::aad(app_id, VECTOR_DID), root),
            node_did: VECTOR_DID.into(),
            kms_root_epoch: 0,
        }
    }

    #[test]
    fn a_wrapped_root_opens_to_the_pinned_identity() {
        let pins = pins(0, &kms_root(7));
        let root = legacy_get_key(&APP_ROOT, NODE_KEY_PATH);
        let aad = root_wrap::aad(&APP_ID, VECTOR_DID);
        let secret =
            open_wrapped(&wrapped(root.as_ref(), &APP_ID), &WRAP_KEY, &aad, &pins).unwrap();
        assert_eq!(secret.as_bytes(), &root[..]);
        assert_eq!(secret.node_did(), VECTOR_DID);
    }

    #[test]
    fn a_wrapped_root_is_refused_unless_every_check_passes() {
        let pins = pins(0, &kms_root(7));
        let root = legacy_get_key(&APP_ROOT, NODE_KEY_PATH);
        let aad = root_wrap::aad(&APP_ID, VECTOR_DID);
        let good = wrapped(root.as_ref(), &APP_ID);
        let refusal = |row: &WrappedRoot, key: &[u8; 32]| {
            let error = open_wrapped(row, key, &aad, &pins).err().expect("refused");
            format!("{error:#}")
        };

        let mut tampered = good.clone();
        tampered.wrapped[20] ^= 1;
        assert!(refusal(&tampered, &WRAP_KEY).contains("does not open"));
        assert!(refusal(&good, &[0x43; 32]).contains("does not open"));
        // Sealed by another app (another AAD).
        assert!(refusal(&wrapped(root.as_ref(), &[0x36; 20]), &WRAP_KEY).contains("does not open"));

        let mut other_did = good.clone();
        other_did.node_did = "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi".into();
        assert!(refusal(&other_did, &WRAP_KEY).contains("not for keys.legacy.expected_did"));
        let mut other_epoch = good.clone();
        other_epoch.kms_root_epoch = 1;
        assert!(refusal(&other_epoch, &WRAP_KEY).contains("root epoch 1"));

        // Authentic for this app and DID, but the root inside derives
        // another identity.
        let other_root = legacy_get_key(&[0x02; 32], NODE_KEY_PATH);
        assert!(refusal(&wrapped(other_root.as_ref(), &APP_ID), &WRAP_KEY)
            .contains("does not derive keys.legacy.expected_did"));
    }

    #[test]
    fn a_recovered_key_with_a_valid_chain_derives_the_expected_did() {
        let kms = kms_root(7);
        let secret = verify_recovered_key(&recovered(&kms, Some(0)), &pins(0, &kms)).unwrap();
        assert_eq!(secret.node_did(), VECTOR_DID);
    }

    #[test]
    fn a_recovered_key_is_refused_unless_every_check_passes() {
        let (kms, other) = (kms_root(7), kms_root(8));
        let pinned = pins(0, &kms);
        type Tamper = Box<dyn Fn(&mut RecoveredKey)>;
        let cases: [(&str, Tamper); 9] = [
            ("not v0", Box::new(|r| r.api = "v1".into())),
            ("root_epoch 1", Box::new(|r| r.root_epoch = Some(1))),
            ("no root_epoch", Box::new(|r| r.root_epoch = None)),
            ("app_epoch 1", Box::new(|r| r.app_epoch = Some(1))),
            ("no app_epoch", Box::new(|r| r.app_epoch = None)),
            (
                "not the public key of its key",
                Box::new(|r| r.public_key = hex::encode(app_pub(&[0x02; 32]))),
            ),
            (
                // The app key behind link 0 is not the one the root issued.
                "does not verify",
                Box::new(|r| {
                    let public_key = hex::decode(&r.public_key).unwrap();
                    r.signature_chain[0] = chain_link(&[0x02; 32], &public_key);
                }),
            ),
            (
                "2 links",
                Box::new(|r| {
                    r.signature_chain.pop();
                }),
            ),
            ("32 bytes", Box::new(|r| r.key = hex::encode([0x01; 31]))),
        ];
        for (expected, tamper) in cases {
            let mut response = recovered(&kms, Some(0));
            tamper(&mut response);
            let err = recovered_refusal(&response, &pinned);
            assert!(err.contains(expected), "{expected}: {err}");
        }
        assert!(recovered_refusal(&recovered(&other, Some(0)), &pinned).contains("does not verify"));
        let mut other_did = pins(0, &kms);
        other_did.expected_did = "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi".into();
        assert!(
            recovered_refusal(&recovered(&kms, Some(0)), &other_did).contains("derives node DID")
        );
    }

    fn app_pub(app_root: &[u8; 32]) -> Vec<u8> {
        SigningKey::from_slice(app_root)
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn the_key_recovery_request_names_the_node_path_and_both_epochs() {
        assert_eq!(NODE_KEY_QUERY.replace("%2F", "/").as_bytes(), NODE_KEY_PATH);
        assert_eq!(
            key_recovery_request(0),
            "GET /v0/key?path=tinycloud%2Fkeys%2Fprimary&root_epoch=0&app_epoch=0 HTTP/1.1\r\n\
             Host: key-recovery\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn at_most_one_transport_may_be_configured() {
        let kms = kms_root(7);
        let config = |socket: Option<&str>, url: Option<&str>, ca: Option<&str>| LegacyKmsEpoch {
            key_recovery_socket: socket.map(Into::into),
            kms_url: url.map(Into::into),
            kms_ca_cert: ca.map(Into::into),
            root_epoch: 0,
            kms_root_pubkey: hex::encode(kms.verifying_key().to_encoded_point(true).as_bytes()),
            app_id: hex::encode(APP_ID),
            expected_did: VECTOR_DID.into(),
            renewal_reset: None,
        };
        let (socket, url, ca) = (
            Some("/run/key-recovery/kr.sock"),
            Some("https://kms.example"),
            Some("AA=="),
        );
        assert!(matches!(
            Pins::parse(&config(socket, None, None)).unwrap().transport,
            Some(Transport::KeyRecovery { .. })
        ));
        assert!(matches!(
            Pins::parse(&config(None, url, ca)).unwrap().transport,
            Some(Transport::Kms(_))
        ));
        // Enough to open a sealed root; fetching refuses.
        assert!(Pins::parse(&config(None, None, None))
            .unwrap()
            .transport
            .is_none());
        for (socket, url, ca) in [
            (socket, url, ca),
            (socket, url, None),
            (None, url, None),
            (None, None, ca),
            (Some("kr.sock"), None, None),
        ] {
            assert!(Pins::parse(&config(socket, url, ca)).is_err());
        }
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
        let err = http_body("KMS GetAppKey", refused).unwrap_err().to_string();
        assert!(
            err.contains("KMS GetAppKey refused: HTTP 400: not authorized"),
            "{err}"
        );
    }
}
