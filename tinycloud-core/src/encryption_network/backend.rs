//! Key backends for the encryption module.
//!
//! V1 ships the `LocalOneOfOneBackend`, which generates a single X25519 keypair
//! per network and stores the private key sealed with the same key material the
//! node uses for DB column encryption. Future threshold backends must avoid
//! ever assembling the full network private key.

use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::encryption::{ColumnEncryption, EncryptionError};

use super::types::ALG_X25519_AES256GCM;

#[derive(Debug, Error)]
pub enum KeyBackendError {
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

/// Trait implemented by network key backends.
///
/// `unwrap` returns the raw symmetric key after decrypting the wrapped key with
/// the network private key. `rewrap` seals that key to a per-request receiver
/// public key for transport back to the client. Higher-level code is
/// responsible for never persisting the raw symmetric key.
pub trait KeyBackend: Send + Sync {
    fn kind(&self) -> super::types::KeyBackendKind;

    fn generate(&self) -> Result<GeneratedKey, KeyBackendError>;

    fn unwrap(
        &self,
        sealed_private_key: &[u8],
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, KeyBackendError>;

    fn rewrap(
        &self,
        symmetric_key: &[u8],
        receiver_public_key: &[u8],
    ) -> Result<Vec<u8>, KeyBackendError>;

    /// Unseal the network private key. A failure here is a backend fault,
    /// reported separately from a failed unwrap.
    fn open_network_secret(
        &self,
        sealed_private_key: &[u8],
    ) -> Result<StaticSecret, KeyBackendError>;

    /// Public key of the named key at `canonical_urn` under `network_secret`.
    fn derive_named_public_key(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
    ) -> Result<Vec<u8>, KeyBackendError>;

    /// Unwrap a key wrapped to the named key at `canonical_urn` under
    /// `network_secret`.
    fn unwrap_named(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, KeyBackendError>;
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

    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    let cipher = ColumnEncryption::new(*shared.as_bytes());
    let mut envelope = Vec::with_capacity(32 + plaintext.len() + 32);
    envelope.extend_from_slice(ephemeral_pub.as_bytes());
    let ct = cipher.encrypt(plaintext);
    envelope.extend_from_slice(&ct);
    Ok(envelope)
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
    Ok(cipher.decrypt_strict(&wrapped[32..])?)
}

const NAMED_KEY_SALT: &[u8] = b"tinycloud.encryption.named-key/v1";
const NAMED_KEY_INFO_PREFIX: &[u8] = b"deterministic\n";

/// Deterministic named-key secret = HKDF-SHA256(ikm = raw network secret,
/// salt = fixed label, info = `deterministic\n` || canonical key URN).
fn named_key_secret(network_secret: &[u8; 32], canonical_urn: &str) -> StaticSecret {
    let mut info = Vec::with_capacity(NAMED_KEY_INFO_PREFIX.len() + canonical_urn.len());
    info.extend_from_slice(NAMED_KEY_INFO_PREFIX);
    info.extend_from_slice(canonical_urn.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(NAMED_KEY_SALT), network_secret);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
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
    ) -> Result<StaticSecret, KeyBackendError> {
        let opened = Zeroizing::new(self.seal.decrypt(sealed_private_key)?);
        if opened.len() != 32 {
            return Err(KeyBackendError::InvalidSealedKey);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&opened);
        let secret = StaticSecret::from(arr);
        arr.zeroize();
        Ok(secret)
    }

    fn generate(&self) -> Result<GeneratedKey, KeyBackendError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sealed = self.seal.encrypt(secret.as_bytes());
        Ok(GeneratedKey {
            public_key: public.as_bytes().to_vec(),
            sealed_private_key: sealed,
            alg: ALG_X25519_AES256GCM.to_string(),
        })
    }

    fn unwrap(
        &self,
        sealed_private_key: &[u8],
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, KeyBackendError> {
        let secret = self
            .open_network_secret(sealed_private_key)
            .map_err(|_| KeyBackendError::SealedKeyUnreadable)?;
        unwrap_with_secret(&secret, wrapped_key)
    }

    fn derive_named_public_key(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
    ) -> Result<Vec<u8>, KeyBackendError> {
        let secret = named_key_secret(network_secret.as_bytes(), canonical_urn);
        Ok(PublicKey::from(&secret).as_bytes().to_vec())
    }

    fn unwrap_named(
        &self,
        network_secret: &StaticSecret,
        canonical_urn: &str,
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, KeyBackendError> {
        let secret = named_key_secret(network_secret.as_bytes(), canonical_urn);
        unwrap_with_secret(&secret, wrapped_key)
    }

    fn rewrap(
        &self,
        symmetric_key: &[u8],
        receiver_public_key: &[u8],
    ) -> Result<Vec<u8>, KeyBackendError> {
        wrap_to_public_key(receiver_public_key, symmetric_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_key() -> ColumnEncryption {
        ColumnEncryption::new([7u8; 32])
    }

    #[test]
    fn generate_and_unwrap_round_trip() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let gk = backend.generate().unwrap();
        let symmetric = [0xABu8; 32];
        let wrapped = wrap_to_public_key(&gk.public_key, &symmetric).unwrap();
        let recovered = backend.unwrap(&gk.sealed_private_key, &wrapped).unwrap();
        assert_eq!(recovered, symmetric);
    }

    #[test]
    fn rewrap_to_receiver_key() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let symmetric = [0x12u8; 32];

        let receiver_secret = StaticSecret::random_from_rng(OsRng);
        let receiver_pub = PublicKey::from(&receiver_secret);
        let rewrapped = backend.rewrap(&symmetric, receiver_pub.as_bytes()).unwrap();
        let recovered = unwrap_with_secret(&receiver_secret, &rewrapped).unwrap();
        assert_eq!(recovered, symmetric);
    }

    #[test]
    fn unwrap_fails_when_sealed_key_corrupted() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let gk = backend.generate().unwrap();
        let wrapped = wrap_to_public_key(&gk.public_key, &[1u8; 32]).unwrap();
        let mut corrupted = gk.sealed_private_key.clone();
        corrupted[5] ^= 0xFF;
        assert!(backend.unwrap(&corrupted, &wrapped).is_err());
    }

    #[test]
    fn rejects_short_receiver_pubkey() {
        let backend = LocalOneOfOneBackend::new(seal_key());
        let err = backend.rewrap(&[0u8; 32], &[1u8; 10]).unwrap_err();
        assert!(matches!(err, KeyBackendError::InvalidPublicKey));
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
            let secret = named_key_secret(&kat_network_secret(), urn);
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
        let gk = backend.generate().unwrap();
        let network = backend.open_network_secret(&gk.sealed_private_key).unwrap();
        let named_pub = backend
            .derive_named_public_key(&network, KAT_URN_NOTES)
            .unwrap();
        let symmetric = [0x5Au8; 32];
        let wrapped = wrap_to_public_key(&named_pub, &symmetric).unwrap();
        let recovered = backend
            .unwrap_named(&network, KAT_URN_NOTES, &wrapped)
            .unwrap();
        assert_eq!(recovered, symmetric);
        // Wrapped to the notes key: a sibling key and the root key cannot open it.
        assert!(backend.unwrap_named(&network, KAT_URN_A, &wrapped).is_err());
        assert!(backend.unwrap(&gk.sealed_private_key, &wrapped).is_err());
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
