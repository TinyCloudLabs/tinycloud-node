//! Offline attested root transport. This crate never persists a plaintext root.
//!
//! `prepare_target` publishes an unverified quote; both transfer operations always
//! call the offline DCAP verifier. The import callback is the integration boundary
//! for a real re-encryption job, not a database migration implementation.
use anyhow::{ensure, Context, Result};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod guest;
#[cfg(test)]
use guest::response_body;
pub use guest::GuestClient;
pub use tinycloud_attestation::{AttestationBundle, AttestationPolicy};

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha256;
const INFO: &[u8] = b"tinycloud/root-export/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDocument {
    pub attestation: AttestationBundle,
    /// Hex-encoded X25519 public key (32 bytes).
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferConfig {
    pub policy: AttestationPolicy,
    pub expected_old_did: String,
}

/// Public-safe transport; all binary fields are hexadecimal.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRoot {
    pub version: u32,
    pub enc: String,
    /// Ciphertext followed by the 16-byte AES-GCM authentication tag.
    pub ct: String,
    pub old_did: String,
    pub transcript_hash: String,
}

/// Borrowed only inside an import job. No raw-root accessor or serialization.
///
/// Derived keys are zeroizing too. Rust prevents returning a borrowed root from
/// the callback, but cannot prevent a caller deliberately copying derived secrets.
/// The caller must not log/persist derived material and owns job correctness.
pub struct LegacyRoot {
    bytes: Zeroizing<Vec<u8>>,
}

impl LegacyRoot {
    pub fn derive_key(&self, context: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_key(&self.bytes, context)
    }

    pub fn node_did(&self) -> Result<String> {
        node_did(&self.bytes)
    }
}

fn derive_key(root: &[u8], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(root);
    hasher.update(context);
    let digest = Zeroizing::new(hasher.finalize());
    Zeroizing::new(*digest.as_bytes())
}

/// Exact node derivation: Ed25519 seed = Blake3(full_root || identity context),
/// then did:key base58btc of the ed01 multicodec prefix and Ed25519 public key.
pub fn node_did(root: &[u8]) -> Result<String> {
    ensure!(root.len() >= 32, "root is shorter than 32 bytes");
    let seed = derive_key(root, b"tinycloud/node/identity");
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut encoded = [0u8; 34];
    encoded[..2].copy_from_slice(&[0xed, 0x01]);
    encoded[2..].copy_from_slice(signing.verifying_key().as_bytes());
    Ok(format!("did:key:z{}", bs58::encode(encoded).into_string()))
}

fn import_private_key(root: &[u8]) -> Result<<Kem as KemTrait>::PrivateKey> {
    ensure!(root.len() >= 32, "root is shorter than 32 bytes");
    let seed = derive_key(root, b"tinycloud/root-import/v1");
    // HPKE's X25519 private-key wrapper uses dalek's zeroize-on-drop StaticSecret.
    Ok(<Kem as KemTrait>::PrivateKey::from_bytes(seed.as_ref())?)
}

fn app_id(policy: &AttestationPolicy) -> Result<Vec<u8>> {
    let bytes = hex::decode(policy.app_id.strip_prefix("0x").unwrap_or(&policy.app_id))
        .context("invalid app_id hex")?;
    ensure!(!bytes.is_empty(), "app_id is empty");
    Ok(bytes)
}

/// SHA256(domain || public_key32 || decoded_app_id), zero-padded to REPORTDATA64.
pub fn report_binding(public_key: &[u8; 32], policy: &AttestationPolicy) -> Result<[u8; 64]> {
    let mut digest = Sha256::new();
    digest.update(b"tinycloud/root-import/v1\0");
    digest.update(public_key);
    digest.update(app_id(policy)?);
    let mut report = [0u8; 64];
    report[..32].copy_from_slice(&digest.finalize());
    Ok(report)
}

fn public_key(target: &TargetDocument) -> Result<[u8; 32]> {
    hex::decode(&target.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("target public key must be 32 bytes"))
}

fn verify_target(target: &TargetDocument, policy: &AttestationPolicy, now: u64) -> Result<()> {
    let binding = report_binding(&public_key(target)?, policy)?;
    tinycloud_attestation::verify(&target.attestation, policy, &binding, now)
        .context("target attestation rejected")
}

/// Publishes a quote and key, not a verification result. Collateral is provided
/// offline by the operator; no network endpoints are contacted by this crate.
pub fn prepare_target(
    guest: &GuestClient,
    policy: &AttestationPolicy,
    collateral: dcap_qvl::QuoteCollateralV3,
) -> Result<TargetDocument> {
    let root = guest.get_root()?;
    let private = import_private_key(&root)?;
    let public: [u8; 32] = Kem::sk_to_pk(&private).to_bytes().into();
    let binding = report_binding(&public, policy)?;
    let response = guest.get_quote(&binding)?;
    Ok(TargetDocument {
        public_key: hex::encode(public),
        attestation: AttestationBundle {
            quote: response.quote,
            event_log: serde_json::from_str(&response.event_log)
                .context("invalid quote event log")?,
            collateral,
        },
    })
}

pub fn export_root(
    guest: &GuestClient,
    target: &TargetDocument,
    config: &TransferConfig,
    now: u64,
) -> Result<SealedRoot> {
    let root = guest.get_root()?;
    ensure!(
        node_did(&root)? == config.expected_old_did,
        "source DID mismatch"
    );
    verify_target(target, &config.policy, now)?;
    seal_root(&root, target, &config.policy, &config.expected_old_did)
}

/// Verify the original target document, confirm its key is this guest's derived
/// key, authenticate the transcript, and expose the old root only to `job`.
/// There is intentionally no public 'already verified' path or verification seam.
pub fn import_for_job<T>(
    guest: &GuestClient,
    target: &TargetDocument,
    config: &TransferConfig,
    sealed: &SealedRoot,
    now: u64,
    job: impl for<'root> FnOnce(&'root LegacyRoot) -> Result<T>,
) -> Result<T> {
    verify_target(target, &config.policy, now)?;
    let root = guest.get_root()?;
    open_for_job(
        &root,
        target,
        &config.policy,
        &config.expected_old_did,
        sealed,
        job,
    )
}

/// AAD v1 = domain || frame(old_did UTF8) || frame(app_id bytes) ||
/// frame(SHA256(decoded quote)), where frame is u32 big-endian length || bytes.
/// Transcript hash is SHA256(AAD). HPKE info is the separate fixed INFO domain.
fn transcript(target: &TargetDocument, policy: &AttestationPolicy, did: &str) -> Result<Vec<u8>> {
    let quote = hex::decode(
        target
            .attestation
            .quote
            .strip_prefix("0x")
            .unwrap_or(&target.attestation.quote),
    )
    .context("invalid quote hex")?;
    let app = app_id(policy)?;
    let quote_hash = Sha256::digest(quote);
    let mut aad = b"tinycloud/root-export/aad/v1\0".to_vec();
    for field in [did.as_bytes(), app.as_slice(), &quote_hash[..]] {
        let length = u32::try_from(field.len()).context("transcript field too large")?;
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(field);
    }
    Ok(aad)
}

// Private helpers permit synthetic unit tests without creating any public DCAP bypass.
fn seal_root(
    root: &[u8],
    target: &TargetDocument,
    policy: &AttestationPolicy,
    did: &str,
) -> Result<SealedRoot> {
    ensure!(node_did(root)? == did, "source DID mismatch");
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&public_key(target)?)?;
    let aad = transcript(target, policy, did)?;
    let (enc, mut context) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &recipient,
        INFO,
        &mut rand::rngs::OsRng,
    )?;
    // Seal in a zeroizing buffer; no extra plaintext Vec inside HPKE's alloc API.
    let mut ciphertext = Zeroizing::new(root.to_vec());
    let tag = context.seal_in_place_detached(&mut ciphertext, &aad)?;
    ciphertext.extend_from_slice(&tag.to_bytes());
    Ok(SealedRoot {
        version: 1,
        enc: hex::encode(enc.to_bytes()),
        ct: hex::encode(&*ciphertext),
        old_did: did.to_owned(),
        transcript_hash: hex::encode(Sha256::digest(&aad)),
    })
}

fn open_for_job<T>(
    root: &[u8],
    target: &TargetDocument,
    policy: &AttestationPolicy,
    did: &str,
    sealed: &SealedRoot,
    job: impl for<'root> FnOnce(&'root LegacyRoot) -> Result<T>,
) -> Result<T> {
    ensure!(sealed.version == 1, "unsupported root-transfer version");
    ensure!(sealed.old_did == did, "sealed source DID mismatch");
    let private = import_private_key(root)?;
    ensure!(
        Kem::sk_to_pk(&private).to_bytes()[..] == public_key(target)?,
        "target key is not this guest's import key"
    );
    let aad = transcript(target, policy, did)?;
    ensure!(
        sealed.transcript_hash == hex::encode(Sha256::digest(&aad)),
        "transcript hash mismatch"
    );
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&hex::decode(&sealed.enc)?)?;
    let mut context = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private, &enc, INFO)?;
    let mut plaintext = Zeroizing::new(hex::decode(&sealed.ct)?);
    ensure!(plaintext.len() >= 16, "ciphertext is truncated");
    let tag_offset = plaintext.len() - 16;
    let tag = hpke::aead::AeadTag::<Aead>::from_bytes(&plaintext[tag_offset..])?;
    plaintext.truncate(tag_offset);
    context
        .open_in_place_detached(&mut plaintext, &aad, &tag)
        .map_err(|_| anyhow::anyhow!("root ciphertext authentication failed"))?;
    ensure!(node_did(&plaintext)? == did, "decrypted root DID mismatch");
    job(&LegacyRoot { bytes: plaintext })
}

#[cfg(test)]
mod tests;
