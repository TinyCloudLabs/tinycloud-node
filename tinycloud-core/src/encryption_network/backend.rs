//! Key backends for the encryption module.
//!
//! V1 ships the `LocalOneOfOneBackend`, which generates a single X25519 keypair
//! per network and stores the private key sealed with the same key material the
//! node uses for DB column encryption. Deletable named keys carry a per-key
//! random seed, sealed the same way. Future threshold backends must avoid
//! ever assembling the full network private key.

use std::collections::BTreeMap;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::encryption::{ColumnEncryption, EncryptionError};

use super::network_id::NetworkId;
use super::types::{ALG_X25519_AES256GCM, ALG_X25519_HKDF_AES256GCM};

#[derive(Debug, Error)]
pub enum KeyBackendError {
    #[error("migration_required: stored encryption keys require offline migration before serving")]
    MigrationRequired,
    #[error("private key material unavailable")]
    SealedKeyMissing,
    #[error("network private key could not be unsealed")]
    SealedKeyUnreadable,
    #[error("invalid sealed key length")]
    InvalidSealedKey,
    #[error("invalid public key length")]
    InvalidPublicKey,
    #[error("invalid wrapped key envelope")]
    InvalidWrappedKey,
    #[error("non-contributory key agreement")]
    NonContributory,
    #[error("aead error: {0}")]
    Aead(String),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
}

pub struct GeneratedKey {
    pub public_key: Vec<u8>,
    pub sealed_private_key: Vec<u8>,
    pub alg: String,
}

/// Wire format selected for newly written wraps; readers accept both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapVersion {
    V1,
    V2,
}

impl KeyWrapVersion {
    /// Algorithm identifier describing this wrap's bytes.
    pub fn alg(self) -> &'static str {
        match self {
            Self::V1 => ALG_X25519_AES256GCM,
            Self::V2 => ALG_X25519_HKDF_AES256GCM,
        }
    }
}

/// Intended recipient role, authenticated in a v2 wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyWrapPurpose {
    NetworkKey,
    ReceiverKey,
}

/// Authoritative context for a v2 wrap. `None` metadata authenticates the
/// carried map without comparing an outer map (the node has no payload).
#[derive(Debug, Clone, Copy)]
pub struct KeyWrapContext<'a> {
    pub purpose: KeyWrapPurpose,
    pub network_id: &'a str,
    pub key_path: &'a str,
    pub key_version: i64,
    pub metadata: Option<&'a BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WrapHeader {
    v: u32,
    alg: String,
    kdf: String,
    aead: String,
    salt: String,
    ephemeral_public_key: String,
    recipient_public_key: String,
    purpose: KeyWrapPurpose,
    network_id: String,
    key_path: String,
    key_version: i64,
    metadata: BTreeMap<String, String>,
}

const WRAP_V2_MAGIC: &[u8; 4] = b"TCW2";
const WRAP_V2_INFO: &[u8] = b"tinycloud.encryption.key-wrap/v2";
const MAX_WRAP_HEADER: usize = 64 * 1024;

// JSON.stringify uses UTF-16 key order. Keep this separate from the existing
// invocation canonicalizer, whose historical ordering must not change.
fn canonical_header_bytes(value: &serde_json::Value) -> Vec<u8> {
    fn write(value: &serde_json::Value, out: &mut Vec<u8>) {
        if let serde_json::Value::Object(map) = value {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_unstable_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).expect("JSON string serialization");
                out.push(b':');
                write(value, out);
            }
            out.push(b'}');
        } else {
            serde_json::to_writer(out, value).expect("JSON value serialization");
        }
    }
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

/// Identifies a wrap without falling back after the v2 magic is recognized.
pub fn wrapped_key_version(wrapped: &[u8]) -> KeyWrapVersion {
    if wrapped.starts_with(WRAP_V2_MAGIC) {
        KeyWrapVersion::V2
    } else {
        KeyWrapVersion::V1
    }
}

fn valid_context(context: &KeyWrapContext<'_>) -> bool {
    (1..=9_007_199_254_740_991).contains(&context.key_version)
        && (context.network_id.is_empty()
            || context
                .network_id
                .parse::<NetworkId>()
                .is_ok_and(|network| network.to_string() == context.network_id))
}

fn decode_header_key(encoded: &str) -> Result<[u8; 32], KeyBackendError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| KeyBackendError::InvalidWrappedKey)?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    bytes
        .try_into()
        .map_err(|_| KeyBackendError::InvalidWrappedKey)
}

fn wrap_cipher(
    shared: &[u8; 32],
    salt: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
) -> Aes256Gcm {
    let mut info = [0u8; WRAP_V2_INFO.len() + 64];
    info[..WRAP_V2_INFO.len()].copy_from_slice(WRAP_V2_INFO);
    info[WRAP_V2_INFO.len()..WRAP_V2_INFO.len() + 32].copy_from_slice(ephemeral);
    info[WRAP_V2_INFO.len() + 32..].copy_from_slice(recipient);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), shared)
        .expand(&info, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Aes256Gcm::new_from_slice(key.as_slice()).expect("32-byte AES-256 key")
}

/// Wrap to a network or receiver using the selected wire format.
pub fn wrap_to_public_key_with_context(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    context: &KeyWrapContext<'_>,
    version: KeyWrapVersion,
) -> Result<Vec<u8>, KeyBackendError> {
    if version == KeyWrapVersion::V1 {
        return wrap_to_public_key(recipient_public_key, plaintext);
    }
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    wrap_v2_with_material(
        recipient_public_key,
        plaintext,
        context,
        &ephemeral,
        &salt,
        &nonce,
    )
}

fn wrap_v2_with_material(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    context: &KeyWrapContext<'_>,
    ephemeral: &StaticSecret,
    salt: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, KeyBackendError> {
    if !valid_context(context) {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let recipient_bytes: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| KeyBackendError::InvalidPublicKey)?;
    let recipient = PublicKey::from(recipient_bytes);
    let ephemeral_public = PublicKey::from(ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(KeyBackendError::NonContributory);
    }
    let header = WrapHeader {
        v: 2,
        alg: ALG_X25519_HKDF_AES256GCM.into(),
        kdf: "hkdf-sha256".into(),
        aead: "aes-256-gcm".into(),
        salt: STANDARD.encode(salt),
        ephemeral_public_key: STANDARD.encode(ephemeral_public.as_bytes()),
        recipient_public_key: STANDARD.encode(recipient_public_key),
        purpose: context.purpose,
        network_id: context.network_id.into(),
        key_path: context.key_path.into(),
        key_version: context.key_version,
        metadata: context.metadata.cloned().unwrap_or_default(),
    };
    let value = serde_json::to_value(header).map_err(|_| KeyBackendError::InvalidWrappedKey)?;
    let header_bytes = canonical_header_bytes(&value);
    if header_bytes.len() > MAX_WRAP_HEADER {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let mut frame = Vec::with_capacity(8 + header_bytes.len() + 12 + plaintext.len() + 16);
    frame.extend_from_slice(WRAP_V2_MAGIC);
    frame.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&header_bytes);
    let cipher = wrap_cipher(
        shared.as_bytes(),
        salt,
        ephemeral_public.as_bytes(),
        &recipient_bytes,
    );
    let encrypted = cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &frame,
            },
        )
        .map_err(|e| KeyBackendError::Aead(e.to_string()))?;
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&encrypted);
    Ok(frame)
}

/// Open either wire format, checking all supplied v2 context before decrypting.
pub fn open_wrapped_key(
    secret: &StaticSecret,
    wrapped: &[u8],
    context: &KeyWrapContext<'_>,
) -> Result<Vec<u8>, KeyBackendError> {
    if wrapped_key_version(wrapped) == KeyWrapVersion::V1 {
        return unwrap_with_secret(secret, wrapped);
    }
    if wrapped.len() < 8 || !valid_context(context) {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let length = u32::from_be_bytes(wrapped[4..8].try_into().expect("four-byte length")) as usize;
    if length > MAX_WRAP_HEADER || wrapped.len() < 8 + length + 12 + 16 {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let end = 8 + length;
    let header: WrapHeader =
        serde_json::from_slice(&wrapped[8..end]).map_err(|_| KeyBackendError::InvalidWrappedKey)?;
    let value = serde_json::to_value(&header).map_err(|_| KeyBackendError::InvalidWrappedKey)?;
    if canonical_header_bytes(&value) != wrapped[8..end]
        || header.v != 2
        || header.alg != ALG_X25519_HKDF_AES256GCM
        || header.kdf != "hkdf-sha256"
        || header.aead != "aes-256-gcm"
        || header.purpose != context.purpose
        || header.network_id != context.network_id
        || header.key_path != context.key_path
        || header.key_version != context.key_version
        || context
            .metadata
            .is_some_and(|metadata| metadata != &header.metadata)
    {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let salt = decode_header_key(&header.salt)?;
    let ephemeral = decode_header_key(&header.ephemeral_public_key)?;
    let recipient = decode_header_key(&header.recipient_public_key)?;
    let actual_recipient = PublicKey::from(secret);
    if recipient != *actual_recipient.as_bytes() {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err(KeyBackendError::NonContributory);
    }
    let cipher = wrap_cipher(shared.as_bytes(), &salt, &ephemeral, &recipient);
    cipher
        .decrypt(
            &Nonce::from(
                <[u8; 12]>::try_from(&wrapped[end..end + 12])
                    .map_err(|_| KeyBackendError::InvalidWrappedKey)?,
            ),
            Payload {
                msg: &wrapped[end + 12..],
                aad: &wrapped[..end],
            },
        )
        .map_err(|e| KeyBackendError::Aead(e.to_string()))
}

/// Trait implemented by network key backends.
///
/// `unwrap` returns the raw symmetric key after decrypting the wrapped key with
/// the network private key. `rewrap` seals that key to a per-request receiver
/// public key for transport back to the client. Higher-level code is
/// responsible for never persisting the raw symmetric key.
pub trait KeyBackend: Send + Sync {
    fn kind(&self) -> super::types::KeyBackendKind;

    fn generate(&self, network_id: &str) -> Result<GeneratedKey, KeyBackendError>;

    fn unwrap(
        &self,
        sealed_private_key: &[u8],
        expected_public_key: &[u8],
        wrapped_key: &[u8],
        context: &KeyWrapContext<'_>,
    ) -> Result<Vec<u8>, KeyBackendError>;

    fn rewrap(
        &self,
        symmetric_key: &[u8],
        receiver_public_key: &[u8],
        context: &KeyWrapContext<'_>,
        version: KeyWrapVersion,
    ) -> Result<Vec<u8>, KeyBackendError>;

    /// Open a PK-bound v2 network seal. Legacy seals require migration.
    /// A failure here is a backend fault,
    /// reported separately from a failed unwrap.
    fn open_network_secret(
        &self,
        sealed_private_key: &[u8],
        network_id: &str,
        expected_public_key: &[u8],
    ) -> Result<StaticSecret, KeyBackendError>;

    /// Public key of the named key at `canonical_urn` under `network_secret`.
    /// `seed` is the per-key seed of a deletable key and `None` for a
    /// deterministic key.
    fn derive_named_public_key(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
        seed: Option<&KeySeed>,
    ) -> Result<Vec<u8>, KeyBackendError>;

    /// Unwrap a key wrapped to the named key at `canonical_urn` under
    /// `network_secret` and `seed`.
    fn unwrap_named(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
        seed: Option<&KeySeed>,
        wrapped_key: &[u8],
        context: &KeyWrapContext<'_>,
    ) -> Result<Vec<u8>, KeyBackendError>;

    /// A fresh 32-byte seed from the OS CSPRNG, with its sealed form for
    /// storage.
    fn generate_seed(
        &self,
        network_id: &str,
        key_path: &str,
    ) -> Result<(KeySeed, Vec<u8>), KeyBackendError>;

    /// Open only a PK-bound v2 seed containing exactly 32 bytes.
    /// Legacy seals require migration and are refused by serving paths.
    fn open_seed(
        &self,
        sealed_seed: &[u8],
        network_id: &str,
        key_path: &str,
    ) -> Result<KeySeed, KeyBackendError>;
}

fn valid_v1_ephemeral_prefix(public: &[u8]) -> bool {
    !public.starts_with(WRAP_V2_MAGIC)
}

/// X25519 ECIES-style key wrap backed by AES-256-GCM. Used both for wrapping to
/// the network public key (client side) and to the receiver public key (decrypt
/// response).
pub fn wrap_to_public_key(
    recipient_public_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyBackendError> {
    if recipient_public_key.len() != 32 {
        return Err(KeyBackendError::InvalidPublicKey);
    }
    let mut recipient_array = [0u8; 32];
    recipient_array.copy_from_slice(recipient_public_key);
    let recipient = PublicKey::from(recipient_array);

    let (ephemeral, ephemeral_pub) = loop {
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&ephemeral);
        if valid_v1_ephemeral_prefix(public.as_bytes()) {
            break (ephemeral, public);
        }
    };
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(KeyBackendError::NonContributory);
    }
    let cipher = ColumnEncryption::new(*shared.as_bytes());
    let mut envelope = Vec::with_capacity(32 + plaintext.len() + 32);
    envelope.extend_from_slice(ephemeral_pub.as_bytes());
    let ct = cipher.encrypt_legacy(plaintext);
    envelope.extend_from_slice(&ct);
    Ok(envelope)
}

/// Refuses a receiver public key that cannot receive a wrap: wrong length, or a low-order
/// point, where the agreement with any ephemeral key is all-zero.
pub fn validate_receiver_public_key(receiver_public_key: &[u8]) -> Result<(), KeyBackendError> {
    let recipient = PublicKey::from(
        <[u8; 32]>::try_from(receiver_public_key).map_err(|_| KeyBackendError::InvalidPublicKey)?,
    );
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    if ephemeral.diffie_hellman(&recipient).was_contributory() {
        Ok(())
    } else {
        Err(KeyBackendError::NonContributory)
    }
}

fn unwrap_with_secret(secret: &StaticSecret, wrapped: &[u8]) -> Result<Vec<u8>, KeyBackendError> {
    if wrapped.len() < 32 {
        return Err(KeyBackendError::InvalidWrappedKey);
    }
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&wrapped[..32]);
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(KeyBackendError::NonContributory);
    }
    let cipher = ColumnEncryption::new(*shared.as_bytes());
    Ok(cipher.decrypt_legacy(&wrapped[32..])?)
}

const NAMED_KEY_SALT: &[u8] = b"tinycloud.encryption.named-key/v1";
const DETERMINISTIC_INFO_PREFIX: &[u8] = b"deterministic\n";
const SEEDED_INFO_PREFIX: &[u8] = b"seeded\n";

/// Per-key seed of a deletable key. Zeroized on drop.
pub struct KeySeed(Zeroizing<[u8; 32]>);

impl KeySeed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Named-key secret. With no seed (deterministic key): HKDF-SHA256(ikm = raw
/// network secret, salt = fixed label, info = `deterministic\n` || canonical
/// key URN). With a seed (deletable key): the same with ikm = HKDF-Extract(
/// salt = seed, ikm = raw network secret) and info = `seeded\n` || URN.
fn named_key_secret(
    network_secret: &[u8; 32],
    canonical_urn: &str,
    seed: Option<&KeySeed>,
) -> StaticSecret {
    let prefix = if seed.is_some() {
        SEEDED_INFO_PREFIX
    } else {
        DETERMINISTIC_INFO_PREFIX
    };
    let mut info = Vec::with_capacity(prefix.len() + canonical_urn.len());
    info.extend_from_slice(prefix);
    info.extend_from_slice(canonical_urn.as_bytes());
    let mut okm = [0u8; 32];
    match seed {
        None => {
            Hkdf::<Sha256>::new(Some(NAMED_KEY_SALT), network_secret)
                .expand(&info, &mut okm)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
        }
        Some(seed) => {
            let (extracted, _) =
                Hkdf::<Sha256>::extract(Some(seed.as_bytes().as_slice()), network_secret);
            let mut prk: [u8; 32] = extracted.into();
            Hkdf::<Sha256>::new(Some(NAMED_KEY_SALT), &prk)
                .expand(&info, &mut okm)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            prk.zeroize();
        }
    }
    let secret = StaticSecret::from(okm);
    okm.zeroize();
    secret
}

/// Local one-of-one backend. The DB encryption key is reused to seal the
/// network private key at rest — the same protection used elsewhere for
/// sensitive DB columns.
pub struct LocalOneOfOneBackend {
    seal: ColumnEncryption,
}

impl LocalOneOfOneBackend {
    pub fn new(seal: ColumnEncryption) -> Self {
        Self { seal }
    }
}

impl KeyBackend for LocalOneOfOneBackend {
    fn kind(&self) -> super::types::KeyBackendKind {
        super::types::KeyBackendKind::LocalOneOfOne
    }

    fn open_network_secret(
        &self,
        sealed_private_key: &[u8],
        network_id: &str,
        expected_public_key: &[u8],
    ) -> Result<StaticSecret, KeyBackendError> {
        if sealed_private_key.first() == Some(&1) {
            return Err(KeyBackendError::MigrationRequired);
        }
        let pk = [network_id.as_bytes()];
        let binding =
            crate::encryption::RowBinding::new("encryption_network", "sealed_private_key", &pk);
        let opened = Zeroizing::new(self.seal.decrypt_v2(sealed_private_key, binding)?);
        if opened.len() != 32 {
            return Err(KeyBackendError::InvalidSealedKey);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&opened);
        let secret = StaticSecret::from(arr);
        arr.zeroize();
        if PublicKey::from(&secret).as_bytes().as_slice() != expected_public_key {
            return Err(KeyBackendError::InvalidSealedKey);
        }
        Ok(secret)
    }

    fn generate(&self, network_id: &str) -> Result<GeneratedKey, KeyBackendError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let pk = [network_id.as_bytes()];
        let sealed = self.seal.encrypt(
            secret.as_bytes(),
            crate::encryption::RowBinding::new("encryption_network", "sealed_private_key", &pk),
        );
        Ok(GeneratedKey {
            public_key: public.as_bytes().to_vec(),
            sealed_private_key: sealed,
            alg: ALG_X25519_AES256GCM.to_string(),
        })
    }

    fn unwrap(
        &self,
        sealed_private_key: &[u8],
        expected_public_key: &[u8],
        wrapped_key: &[u8],
        context: &KeyWrapContext<'_>,
    ) -> Result<Vec<u8>, KeyBackendError> {
        let secret = self
            .open_network_secret(sealed_private_key, context.network_id, expected_public_key)
            .map_err(|err| match err {
                KeyBackendError::MigrationRequired => err,
                _ => KeyBackendError::SealedKeyUnreadable,
            })?;
        open_wrapped_key(&secret, wrapped_key, context)
    }

    fn derive_named_public_key(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
        seed: Option<&KeySeed>,
    ) -> Result<Vec<u8>, KeyBackendError> {
        let secret = named_key_secret(network_secret.as_bytes(), canonical_urn, seed);
        Ok(PublicKey::from(&secret).as_bytes().to_vec())
    }

    fn unwrap_named(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
        seed: Option<&KeySeed>,
        wrapped_key: &[u8],
        context: &KeyWrapContext<'_>,
    ) -> Result<Vec<u8>, KeyBackendError> {
        let secret = named_key_secret(network_secret.as_bytes(), canonical_urn, seed);
        open_wrapped_key(&secret, wrapped_key, context)
    }

    fn generate_seed(
        &self,
        network_id: &str,
        key_path: &str,
    ) -> Result<(KeySeed, Vec<u8>), KeyBackendError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(bytes.as_mut_slice());
        let pk = [network_id.as_bytes(), key_path.as_bytes()];
        let sealed = self.seal.encrypt(
            bytes.as_slice(),
            crate::encryption::RowBinding::new("encryption_network_key", "sealed_seed", &pk),
        );
        Ok((KeySeed::from_bytes(*bytes), sealed))
    }

    fn open_seed(
        &self,
        sealed_seed: &[u8],
        network_id: &str,
        key_path: &str,
    ) -> Result<KeySeed, KeyBackendError> {
        if sealed_seed.first() == Some(&1) {
            return Err(KeyBackendError::MigrationRequired);
        }
        let pk = [network_id.as_bytes(), key_path.as_bytes()];
        let opened = Zeroizing::new(self.seal.decrypt_v2(
            sealed_seed,
            crate::encryption::RowBinding::new("encryption_network_key", "sealed_seed", &pk),
        )?);
        let bytes: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| KeyBackendError::InvalidSealedKey)?;
        Ok(KeySeed::from_bytes(bytes))
    }

    fn rewrap(
        &self,
        symmetric_key: &[u8],
        receiver_public_key: &[u8],
        context: &KeyWrapContext<'_>,
        version: KeyWrapVersion,
    ) -> Result<Vec<u8>, KeyBackendError> {
        wrap_to_public_key_with_context(receiver_public_key, symmetric_key, context, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NETWORK: &str = "urn:tinycloud:encryption:did:key:z6Mk:default";

    fn seal_key() -> ColumnEncryption {
        ColumnEncryption::new([7u8; 32])
    }

    fn legacy_context() -> KeyWrapContext<'static> {
        KeyWrapContext {
            purpose: KeyWrapPurpose::NetworkKey,
            network_id: NETWORK,
            key_path: "",
            key_version: 1,
            metadata: None,
        }
    }

    fn wrap_context<'a>(
        metadata: &'a std::collections::BTreeMap<String, String>,
    ) -> KeyWrapContext<'a> {
        KeyWrapContext {
            purpose: KeyWrapPurpose::NetworkKey,
            network_id: "urn:tinycloud:encryption:did:key:z6Mk:default",
            key_path: "docs/alpha",
            key_version: 1,
            metadata: Some(metadata),
        }
    }

    #[test]
    fn v1_ephemeral_prefix_excludes_v2_magic() {
        let mut public = [0u8; 32];
        public[..4].copy_from_slice(b"TCW2");
        assert!(!valid_v1_ephemeral_prefix(&public));
        public[3] = b'1';
        assert!(valid_v1_ephemeral_prefix(&public));
        let recipient = StaticSecret::from([9u8; 32]);
        let wrapped =
            wrap_to_public_key(PublicKey::from(&recipient).as_bytes(), &[42; 32]).unwrap();
        assert!(valid_v1_ephemeral_prefix(&wrapped[..32]));
        assert_eq!(unwrap_with_secret(&recipient, &wrapped).unwrap(), [42; 32]);
    }

    #[test]
    fn network_secrets_require_sealed_storage_and_new_seals_are_versioned() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        assert!(backend
            .open_network_secret(&[7u8; 32], NETWORK, &[0; 32])
            .is_err());
        let generated = backend.generate(NETWORK).unwrap();
        assert_eq!(generated.sealed_private_key[0], 0x02);
        assert!(backend
            .open_network_secret(
                &generated.sealed_private_key,
                NETWORK,
                &generated.public_key
            )
            .is_ok());
        let (_, seed) = backend.generate_seed(NETWORK, "seed-path").unwrap();
        assert_eq!(seed[0], 0x02);
        assert!(backend.open_seed(&seed, NETWORK, "seed-path").is_ok());
    }

    #[test]
    fn malformed_surrogates_are_rejected_at_header_parse_boundary() {
        let metadata = BTreeMap::from([("key".into(), "value".into())]);
        let secret = StaticSecret::from([9u8; 32]);
        let context = wrap_context(&metadata);
        let wrapped = wrap_to_public_key_with_context(
            PublicKey::from(&secret).as_bytes(),
            &[42; 32],
            &context,
            KeyWrapVersion::V2,
        )
        .unwrap();
        let length = u32::from_be_bytes(wrapped[4..8].try_into().unwrap()) as usize;
        let header = std::str::from_utf8(&wrapped[8..8 + length]).unwrap();
        for surrogate in [r#""\ud800""#, r#""\udfff""#] {
            for original in [r#""key""#, r#""value""#, r#""docs/alpha""#] {
                let malformed = header.replace(original, surrogate);
                assert!(serde_json::from_str::<WrapHeader>(&malformed).is_err());
                let mut frame = WRAP_V2_MAGIC.to_vec();
                frame.extend_from_slice(&(malformed.len() as u32).to_be_bytes());
                frame.extend_from_slice(malformed.as_bytes());
                frame.extend_from_slice(&wrapped[8 + length..]);
                assert!(matches!(
                    open_wrapped_key(&secret, &frame, &context),
                    Err(KeyBackendError::InvalidWrappedKey)
                ));
            }
        }
    }

    #[test]
    fn v2_wrap_binds_context_and_both_public_keys() {
        let metadata = std::collections::BTreeMap::from([
            ("contentType".into(), "text/plain".into()),
            ("\u{10000}".into(), "non-BMP".into()),
            ("\u{e000}".into(), "BMP".into()),
        ]);
        let empty = std::collections::BTreeMap::new();
        let context = wrap_context(&metadata);
        let secret = StaticSecret::from([9u8; 32]);
        let public = PublicKey::from(&secret);
        let wrapped = wrap_to_public_key_with_context(
            public.as_bytes(),
            &[0x42; 32],
            &context,
            KeyWrapVersion::V2,
        )
        .unwrap();
        assert!(wrapped.starts_with(b"TCW2"));
        assert_eq!(
            open_wrapped_key(&secret, &wrapped, &context).unwrap(),
            [0x42; 32]
        );
        for wrong in [
            KeyWrapContext {
                purpose: KeyWrapPurpose::ReceiverKey,
                ..context
            },
            KeyWrapContext {
                network_id: "urn:tinycloud:encryption:did:key:z6Mk:other",
                ..context
            },
            KeyWrapContext {
                key_path: "docs/beta",
                ..context
            },
            KeyWrapContext {
                key_version: 2,
                ..context
            },
            KeyWrapContext {
                metadata: Some(&empty),
                ..context
            },
        ] {
            assert!(open_wrapped_key(&secret, &wrapped, &wrong).is_err());
        }
        assert!(open_wrapped_key(&StaticSecret::from([8u8; 32]), &wrapped, &context).is_err());
        // The node authenticates carried metadata without an outer payload to compare.
        assert!(open_wrapped_key(
            &secret,
            &wrapped,
            &KeyWrapContext {
                metadata: None,
                ..context
            }
        )
        .is_ok());
        assert!(
            wrap_to_public_key_with_context(&[0; 32], &[1; 32], &context, KeyWrapVersion::V2)
                .is_err()
        );
        for key_version in [0, -1, 9_007_199_254_740_992] {
            let invalid = KeyWrapContext {
                key_version,
                ..context
            };
            assert!(wrap_to_public_key_with_context(
                public.as_bytes(),
                &[1; 32],
                &invalid,
                KeyWrapVersion::V2
            )
            .is_err());
        }
    }

    fn replace_v2_header(wrapped: &[u8], mutate: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let length = u32::from_be_bytes(wrapped[4..8].try_into().unwrap()) as usize;
        let mut header: serde_json::Value =
            serde_json::from_slice(&wrapped[8..8 + length]).unwrap();
        mutate(&mut header);
        let bytes = canonical_header_bytes(&header);
        let mut changed = b"TCW2".to_vec();
        changed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        changed.extend_from_slice(&bytes);
        changed.extend_from_slice(&wrapped[8 + length..]);
        changed
    }

    #[test]
    fn v2_rejects_tampering_noncanonical_and_truncated_frames() {
        use serde_json::json;
        let metadata = std::collections::BTreeMap::new();
        let context = wrap_context(&metadata);
        let secret = StaticSecret::from([9u8; 32]);
        let wrapped = wrap_to_public_key_with_context(
            PublicKey::from(&secret).as_bytes(),
            &[0x42; 32],
            &context,
            KeyWrapVersion::V2,
        )
        .unwrap();
        for (field, value) in [
            ("v", json!(3)),
            ("alg", json!("x25519-aes256gcm/v1")),
            ("kdf", json!("other")),
            ("aead", json!("other")),
            ("purpose", json!("receiver-key")),
            ("networkId", json!("other")),
            ("keyPath", json!("docs/beta")),
            ("keyVersion", json!(2)),
            ("metadata", json!({"different": "value"})),
            ("salt", json!(STANDARD.encode([3; 32]))),
            ("ephemeralPublicKey", json!(STANDARD.encode([0; 32]))),
            ("recipientPublicKey", json!(STANDARD.encode([3; 32]))),
            ("extra", json!(true)),
            ("v", json!("2")),
            ("keyVersion", json!(0)),
            ("keyVersion", json!(-1)),
            ("keyVersion", json!(1.5)),
            ("keyVersion", json!(9_007_199_254_740_992i64)),
            ("metadata", json!({"bad": 1})),
            ("metadata", json!([])),
            ("salt", json!("not-base64")),
            ("salt", json!(STANDARD.encode([1; 31]))),
            ("ephemeralPublicKey", json!(STANDARD.encode([1; 31]))),
            ("recipientPublicKey", json!(STANDARD.encode([1; 31]))),
            (
                "ephemeralPublicKey",
                json!(STANDARD.encode(PublicKey::from(&StaticSecret::from([7; 32])).as_bytes())),
            ),
        ] {
            let changed = replace_v2_header(&wrapped, |header| header[field] = value);
            assert!(
                open_wrapped_key(&secret, &changed, &context).is_err(),
                "{field}"
            );
        }
        let carried_metadata = replace_v2_header(&wrapped, |header| {
            header["metadata"] = json!({"carried": "changed"})
        });
        let node_context = KeyWrapContext {
            metadata: None,
            ..context
        };
        assert!(open_wrapped_key(&secret, &carried_metadata, &node_context).is_err());
        for field in ["metadata", "salt", "keyVersion", "purpose"] {
            let changed = replace_v2_header(&wrapped, |header| {
                header.as_object_mut().unwrap().remove(field);
            });
            assert!(
                open_wrapped_key(&secret, &changed, &context).is_err(),
                "missing {field}"
            );
        }
        for length in 4..wrapped.len() {
            assert!(
                open_wrapped_key(&secret, &wrapped[..length], &context).is_err(),
                "{length}"
            );
        }
        let mut oversized = b"TCW2".to_vec();
        oversized.extend_from_slice(&65537u32.to_be_bytes());
        assert!(open_wrapped_key(&secret, &oversized, &context).is_err());
        let header_len = u32::from_be_bytes(wrapped[4..8].try_into().unwrap()) as usize;
        let mut noncanonical = wrapped.clone();
        noncanonical.insert(8, b' ');
        noncanonical[4..8].copy_from_slice(&((header_len + 1) as u32).to_be_bytes());
        assert!(open_wrapped_key(&secret, &noncanonical, &context).is_err());
        for index in [8 + header_len, wrapped.len() - 1] {
            let mut changed = wrapped.clone();
            changed[index] ^= 1;
            assert!(open_wrapped_key(&secret, &changed, &context).is_err());
        }
    }

    #[test]
    fn v2_writes_use_fresh_material_and_v1_stays_available() {
        let metadata = BTreeMap::new();
        let context = wrap_context(&metadata);
        let secret = StaticSecret::from([9; 32]);
        let public = PublicKey::from(&secret);
        let first = wrap_to_public_key_with_context(
            public.as_bytes(),
            &[1; 32],
            &context,
            KeyWrapVersion::V2,
        )
        .unwrap();
        let second = wrap_to_public_key_with_context(
            public.as_bytes(),
            &[1; 32],
            &context,
            KeyWrapVersion::V2,
        )
        .unwrap();
        let parse = |frame: &[u8]| {
            let length = u32::from_be_bytes(frame[4..8].try_into().unwrap()) as usize;
            (
                serde_json::from_slice::<serde_json::Value>(&frame[8..8 + length]).unwrap(),
                frame[8 + length..8 + length + 12].to_vec(),
            )
        };
        let (first_header, first_nonce) = parse(&first);
        let (second_header, second_nonce) = parse(&second);
        assert_ne!(first_header["salt"], second_header["salt"]);
        assert_ne!(
            first_header["ephemeralPublicKey"],
            second_header["ephemeralPublicKey"]
        );
        assert_ne!(first_nonce, second_nonce);
        let legacy = wrap_to_public_key_with_context(
            public.as_bytes(),
            &[1; 32],
            &context,
            KeyWrapVersion::V1,
        )
        .unwrap();
        assert_eq!(legacy[32], 1);
        assert_eq!(
            open_wrapped_key(&secret, &legacy, &context).unwrap(),
            [1; 32]
        );
    }

    #[test]
    fn shared_key_wrap_vectors_open_and_reemit() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/key-wrap-v2.json")).unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let decode = |field: &str| STANDARD.decode(vector[field].as_str().unwrap()).unwrap();
            let secret =
                StaticSecret::from(<[u8; 32]>::try_from(decode("recipientPrivateKey")).unwrap());
            let ephemeral =
                StaticSecret::from(<[u8; 32]>::try_from(decode("ephemeralPrivateKey")).unwrap());
            let metadata = serde_json::from_value(vector["context"]["metadata"].clone()).unwrap();
            let context = KeyWrapContext {
                purpose: serde_json::from_value(vector["purpose"].clone()).unwrap(),
                network_id: vector["context"]["networkId"].as_str().unwrap(),
                key_path: vector["context"]["keyPath"].as_str().unwrap(),
                key_version: vector["context"]["keyVersion"].as_i64().unwrap(),
                metadata: Some(&metadata),
            };
            assert_eq!(
                PublicKey::from(&secret).as_bytes().as_slice(),
                decode("recipientPublicKey")
            );
            assert_eq!(
                PublicKey::from(&ephemeral).as_bytes().as_slice(),
                decode("ephemeralPublicKey")
            );
            let wrapped = decode("wrappedKey");
            let plaintext = decode("plaintext");
            assert_eq!(
                open_wrapped_key(&secret, &wrapped, &context).unwrap(),
                plaintext,
                "{}",
                vector["name"]
            );
            let nonce: [u8; 12] = decode("nonce").try_into().unwrap();
            let emitted = if vector["version"] == 2 {
                wrap_v2_with_material(
                    PublicKey::from(&secret).as_bytes(),
                    &plaintext,
                    &context,
                    &ephemeral,
                    &decode("salt").try_into().unwrap(),
                    &nonce,
                )
                .unwrap()
            } else {
                let shared = ephemeral.diffie_hellman(&PublicKey::from(&secret));
                let cipher = Aes256Gcm::new_from_slice(shared.as_bytes()).unwrap();
                let mut frame = PublicKey::from(&ephemeral).as_bytes().to_vec();
                frame.push(1);
                frame.extend_from_slice(&nonce);
                frame.extend_from_slice(
                    &cipher
                        .encrypt(&Nonce::from(nonce), plaintext.as_slice())
                        .unwrap(),
                );
                frame
            };
            assert_eq!(emitted, wrapped, "{}", vector["name"]);
        }
    }

    #[test]
    fn generate_and_unwrap_round_trip() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let gk = backend.generate(NETWORK).unwrap();
        let symmetric = [0xABu8; 32];
        let wrapped = wrap_to_public_key(&gk.public_key, &symmetric).unwrap();
        let recovered = backend
            .unwrap(
                &gk.sealed_private_key,
                &gk.public_key,
                &wrapped,
                &legacy_context(),
            )
            .unwrap();
        assert_eq!(recovered, symmetric);
    }

    #[test]
    fn network_key_opening_requires_an_authenticated_seal() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        assert!(backend
            .open_network_secret(&[0x42; 32], NETWORK, &[0; 32])
            .is_err());
        let generated = backend.generate(NETWORK).unwrap();
        assert_eq!(generated.sealed_private_key[0], 2);
        assert!(backend
            .open_network_secret(
                &generated.sealed_private_key,
                NETWORK,
                &generated.public_key
            )
            .is_ok());
    }

    #[test]
    fn rewrap_to_receiver_key() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let symmetric = [0x12u8; 32];

        let receiver_secret = StaticSecret::random_from_rng(OsRng);
        let receiver_pub = PublicKey::from(&receiver_secret);
        let rewrapped = backend
            .rewrap(
                &symmetric,
                receiver_pub.as_bytes(),
                &legacy_context(),
                KeyWrapVersion::V1,
            )
            .unwrap();
        let recovered = unwrap_with_secret(&receiver_secret, &rewrapped).unwrap();
        assert_eq!(recovered, symmetric);
    }

    #[test]
    fn unwrap_fails_when_sealed_key_corrupted() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let gk = backend.generate(NETWORK).unwrap();
        let wrapped = wrap_to_public_key(&gk.public_key, &[1u8; 32]).unwrap();
        let mut corrupted = gk.sealed_private_key.clone();
        corrupted[5] ^= 0xFF;
        assert!(backend
            .unwrap(&corrupted, &gk.public_key, &wrapped, &legacy_context())
            .is_err());
    }

    #[test]
    fn rejects_short_receiver_pubkey() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let err = backend
            .rewrap(
                &[0u8; 32],
                &[1u8; 10],
                &legacy_context(),
                KeyWrapVersion::V1,
            )
            .unwrap_err();
        assert!(matches!(err, KeyBackendError::InvalidPublicKey));
    }

    #[test]
    fn receiver_key_validation_refuses_wrong_length_and_low_order_points() {
        assert!(matches!(
            validate_receiver_public_key(&[0x11u8; 31]).unwrap_err(),
            KeyBackendError::InvalidPublicKey
        ));
        let mut one = [0u8; 32];
        one[0] = 1;
        // Order-8 torsion u-coordinates and non-canonical encodings of p-1, p, p+1, little-endian.
        let order_eight_a: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let order_eight_b: [u8; 32] = [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ];
        let mut p_minus_one = [0xffu8; 32];
        p_minus_one[0] = 0xec;
        p_minus_one[31] = 0x7f;
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        let mut p_plus_one = [0xffu8; 32];
        p_plus_one[0] = 0xee;
        p_plus_one[31] = 0x7f;
        for low_order in [
            [0u8; 32],
            one,
            order_eight_a,
            order_eight_b,
            p_minus_one,
            p,
            p_plus_one,
        ] {
            assert!(matches!(
                validate_receiver_public_key(&low_order).unwrap_err(),
                KeyBackendError::NonContributory
            ));
            assert!(matches!(
                wrap_to_public_key(&low_order, &[0x33u8; 32]).unwrap_err(),
                KeyBackendError::NonContributory
            ));
        }
        let receiver = StaticSecret::random_from_rng(OsRng);
        assert!(validate_receiver_public_key(PublicKey::from(&receiver).as_bytes()).is_ok());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Network secret bytes 0x00..=0x1f, used by the known-answer vectors.
    fn kat_network_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    const KAT_URN_NOTES: &str = "urn:tinycloud:encryption:did:key:z6Mk:default/apps/notes";
    const KAT_URN_A: &str = "urn:tinycloud:encryption:did:key:z6Mk:default/a";
    const KAT_URN_NOTES_A: &str = "urn:tinycloud:encryption:did:key:z6Mk:default/apps/notes/a";

    /// Seed bytes 0x20..=0x3f, used by the seeded known-answer vectors.
    fn kat_seed() -> KeySeed {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = 0x20 + i as u8;
        }
        KeySeed::from_bytes(s)
    }

    /// Known-answer vectors generated independently with Python `cryptography`:
    /// HKDF-SHA256(ikm = network secret, salt = "tinycloud.encryption.named-key/v1",
    /// info = "deterministic\n" || URN), then X25519 public-key derivation.
    #[test]
    fn named_key_secret_known_answer() {
        let cases = [
            (
                KAT_URN_NOTES,
                "17b2d3e78d724e69372c08b057a321e4dd921722aa39215d1b19ae743bf6b347",
                "f94cb3ced43d13a5e2ad0b43aed8a94f6fbe1310fd91522babca7edfd6d8b24b",
            ),
            (
                KAT_URN_A,
                "75730b74ced93657a55af78db14f682d6091c178e57397640da4b0e48eb36504",
                "af232ed21db69ec004cdf70ade3efa554ea2c4e603629d6a81f20e5353870519",
            ),
        ];
        for (urn, secret_hex, public_hex) in cases {
            let secret = named_key_secret(&kat_network_secret(), urn, None);
            assert_eq!(hex(secret.as_bytes()), secret_hex, "secret for {urn}");
            assert_eq!(
                hex(PublicKey::from(&secret).as_bytes()),
                public_hex,
                "public key for {urn}"
            );
        }
    }

    /// Seeded known-answer vectors generated independently with Python
    /// `cryptography`/`hmac`: prk = HKDF-Extract(salt = seed, ikm = network
    /// secret), then HKDF-SHA256(ikm = prk, salt =
    /// "tinycloud.encryption.named-key/v1", info = "seeded\n" || URN), then
    /// X25519 public-key derivation. Network secret bytes 0x00..=0x1f, seed
    /// bytes 0x20..=0x3f.
    #[test]
    fn seeded_named_key_secret_known_answer() {
        let cases = [
            (
                KAT_URN_NOTES,
                "6dfc78d8bfad5426a807a0d28d215b9d0724f399017b7208bcc0a0059d56699b",
                "a4ce43c1b98d2289215722623801c8ca0896122872427557e32547b6f393477f",
            ),
            (
                KAT_URN_A,
                "cb3f04c506504e1148d6e6d567a2cb7a4675297434bda9d30532b893259a8ed5",
                "d9dd603f57bbae80ba23995bc322f0dc2c8c681e8a049ac8fe5469d5ee4d5e65",
            ),
            (
                KAT_URN_NOTES_A,
                "5b66844f3beed84737dc6e3b5a389c313c92d9a22dd9311d3c4371aa904f5a3d",
                "55fea451945fed9ab2e6a3a7922f2e175dee1bb2c7e076caa8971a69aaf56f53",
            ),
        ];
        let seed = kat_seed();
        for (urn, secret_hex, public_hex) in cases {
            let secret = named_key_secret(&kat_network_secret(), urn, Some(&seed));
            assert_eq!(hex(secret.as_bytes()), secret_hex, "secret for {urn}");
            assert_eq!(
                hex(PublicKey::from(&secret).as_bytes()),
                public_hex,
                "public key for {urn}"
            );
        }
    }

    #[test]
    fn named_key_round_trip_and_isolation() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let gk = backend.generate(NETWORK).unwrap();
        let network = backend
            .open_network_secret(&gk.sealed_private_key, NETWORK, &gk.public_key)
            .unwrap();
        let named_pub = backend
            .derive_named_public_key(&network, KAT_URN_NOTES, None)
            .unwrap();
        let symmetric = [0x5Au8; 32];
        let wrapped = wrap_to_public_key(&named_pub, &symmetric).unwrap();
        let recovered = backend
            .unwrap_named(&network, KAT_URN_NOTES, None, &wrapped, &legacy_context())
            .unwrap();
        assert_eq!(recovered, symmetric);
        // Wrapped to the notes key: a sibling key and the root key cannot open it.
        assert!(backend
            .unwrap_named(&network, KAT_URN_A, None, &wrapped, &legacy_context())
            .is_err());
        assert!(backend
            .unwrap(
                &gk.sealed_private_key,
                &gk.public_key,
                &wrapped,
                &legacy_context()
            )
            .is_err());
    }

    #[test]
    fn seeded_key_round_trip_and_isolation() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let gk = backend.generate(NETWORK).unwrap();
        let network = backend
            .open_network_secret(&gk.sealed_private_key, NETWORK, &gk.public_key)
            .unwrap();
        let (seed, sealed_seed) = backend.generate_seed(NETWORK, "seed-path").unwrap();
        let (other_seed, _) = backend.generate_seed(NETWORK, "seed-path").unwrap();
        let opened = backend
            .open_seed(&sealed_seed, NETWORK, "seed-path")
            .unwrap();

        let public = backend
            .derive_named_public_key(&network, KAT_URN_NOTES, Some(&seed))
            .unwrap();
        let symmetric = [0x5Au8; 32];
        let wrapped = wrap_to_public_key(&public, &symmetric).unwrap();
        assert_eq!(
            backend
                .unwrap_named(
                    &network,
                    KAT_URN_NOTES,
                    Some(&opened),
                    &wrapped,
                    &legacy_context()
                )
                .unwrap(),
            symmetric
        );
        // Another seed, no seed, another URN and the network key cannot open it.
        assert!(backend
            .unwrap_named(
                &network,
                KAT_URN_NOTES,
                Some(&other_seed),
                &wrapped,
                &legacy_context()
            )
            .is_err());
        assert!(backend
            .unwrap_named(&network, KAT_URN_NOTES, None, &wrapped, &legacy_context())
            .is_err());
        assert!(backend
            .unwrap_named(
                &network,
                KAT_URN_A,
                Some(&seed),
                &wrapped,
                &legacy_context()
            )
            .is_err());
        assert!(backend
            .unwrap(
                &gk.sealed_private_key,
                &gk.public_key,
                &wrapped,
                &legacy_context()
            )
            .is_err());
        // The same URN with and without a seed names different keys.
        assert_ne!(
            public,
            backend
                .derive_named_public_key(&network, KAT_URN_NOTES, None)
                .unwrap()
        );
    }

    #[test]
    fn generated_seeds_differ_and_open_to_the_stored_bytes() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let (first, first_sealed) = backend.generate_seed(NETWORK, "seed-path").unwrap();
        let (second, second_sealed) = backend.generate_seed(NETWORK, "seed-path").unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        assert_ne!(first_sealed, second_sealed);
        assert_ne!(first.as_bytes(), &[0u8; 32]);
        assert_eq!(
            backend
                .open_seed(&first_sealed, NETWORK, "seed-path")
                .unwrap()
                .as_bytes(),
            first.as_bytes()
        );
    }

    #[test]
    fn seeds_open_only_through_the_strict_unseal() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        // A seed opens only when it is a versioned, authenticated sealed value
        // of exactly 32 bytes; an all-zero value of any length is refused.
        for refused in [
            vec![0u8; 32],
            vec![0u8; 45],
            vec![],
            vec![0x02; 60],
            vec![0x01; 10],
        ] {
            assert!(
                backend.open_seed(&refused, NETWORK, "seed-path").is_err(),
                "opened {} bytes",
                refused.len()
            );
        }
        // A sealed value that is not 32 bytes is refused.
        let short = ColumnEncryption::new([7u8; 32]).encrypt(
            &[1u8; 16],
            crate::encryption::RowBinding::new(
                "encryption_network_key",
                "sealed_seed",
                &[NETWORK.as_bytes(), b"seed-path"],
            ),
        );
        assert!(matches!(
            backend.open_seed(&short, NETWORK, "seed-path"),
            Err(KeyBackendError::InvalidSealedKey)
        ));
        // A seed sealed under another key does not open.
        let (_, other) = LocalOneOfOneBackend::new(ColumnEncryption::new([8u8; 32]))
            .generate_seed(NETWORK, "seed-path")
            .unwrap();
        assert!(backend.open_seed(&other, NETWORK, "seed-path").is_err());
    }

    #[test]
    fn unwrap_round_trip_with_known_receiver() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient);
        let wrapped = wrap_to_public_key(recipient_pub.as_bytes(), &[0x33u8; 32]).unwrap();
        assert_eq!(
            unwrap_with_secret(&recipient, &wrapped).unwrap(),
            vec![0x33u8; 32]
        );
    }

    #[test]
    fn unwrap_rejects_unversioned_payload() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let eph = StaticSecret::random_from_rng(OsRng);
        let mut wrapped = PublicKey::from(&eph).as_bytes().to_vec();
        wrapped.extend_from_slice(&[0x00; 48]);
        let err = unwrap_with_secret(&recipient, &wrapped).unwrap_err();
        assert!(matches!(
            err,
            KeyBackendError::Encryption(EncryptionError::UnsupportedVersion)
        ));
    }

    #[test]
    fn unwrap_rejects_non_contributory_peer() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let mut wrapped = vec![0u8; 32];
        wrapped.extend_from_slice(&[0x01; 48]);
        let err = unwrap_with_secret(&recipient, &wrapped).unwrap_err();
        assert!(matches!(err, KeyBackendError::NonContributory));
    }

    #[test]
    fn unwrap_refuses_other_version_byte() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let mut wrapped =
            wrap_to_public_key(PublicKey::from(&recipient).as_bytes(), &[0x33u8; 32]).unwrap();
        wrapped[32] = 0x02;
        let err = unwrap_with_secret(&recipient, &wrapped).unwrap_err();
        assert!(matches!(
            err,
            KeyBackendError::Encryption(EncryptionError::UnsupportedVersion)
        ));
    }

    #[test]
    fn unwrap_refuses_input_shorter_than_ephemeral_key() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let err = unwrap_with_secret(&recipient, &[0x01u8; 31]).unwrap_err();
        assert!(matches!(err, KeyBackendError::InvalidWrappedKey));
    }

    #[test]
    fn unwrap_refuses_truncated_ciphertext() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let wrapped =
            wrap_to_public_key(PublicKey::from(&recipient).as_bytes(), &[0x33u8; 32]).unwrap();
        // Keep eph + version + nonce, drop the rest: below the 29-byte minimum.
        let err = unwrap_with_secret(&recipient, &wrapped[..32 + 1 + 12]).unwrap_err();
        assert!(matches!(
            err,
            KeyBackendError::Encryption(EncryptionError::TooShort)
        ));
    }

    #[test]
    fn unwrap_refuses_tampered_tag() {
        let recipient = StaticSecret::random_from_rng(OsRng);
        let mut wrapped =
            wrap_to_public_key(PublicKey::from(&recipient).as_bytes(), &[0x33u8; 32]).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        let err = unwrap_with_secret(&recipient, &wrapped).unwrap_err();
        assert!(matches!(
            err,
            KeyBackendError::Encryption(EncryptionError::Decrypt(_))
        ));
    }
}

#[cfg(test)]
mod seal_binding_regression_tests {
    use super::*;
    #[test]
    fn persisted_seals_require_v2_and_never_fall_back_to_empty_pk() {
        let ring = ColumnEncryption::new([7; 32]);
        let backend = LocalOneOfOneBackend::new(ring.clone());
        let secret = StaticSecret::from([42; 32]);
        let public = PublicKey::from(&secret);
        let legacy = ring.encrypt_legacy(secret.as_bytes());
        assert!(backend
            .open_network_secret(&legacy, "network-a", public.as_bytes())
            .is_err());
        let legacy_seed = ring.encrypt_legacy(&[43; 32]);
        assert!(backend
            .open_seed(&legacy_seed, "network-a", "path-a")
            .is_err());
        assert!(backend
            .open_network_secret(&legacy, "network-a", &[0; 32])
            .is_err());
        let empty = ring.encrypt(
            secret.as_bytes(),
            crate::encryption::RowBinding::new("encryption_network", "sealed_private_key", &[]),
        );
        assert!(backend
            .open_network_secret(&empty, "network-a", public.as_bytes())
            .is_err());
        let empty_seed = ring.encrypt(
            &[43; 32],
            crate::encryption::RowBinding::new("encryption_network_key", "sealed_seed", &[]),
        );
        assert!(backend
            .open_seed(&empty_seed, "network-a", "path-a")
            .is_err());
    }
}
