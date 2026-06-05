//! Key backends for the encryption module.
//!
//! V1 ships the `LocalOneOfOneBackend`, which generates a single X25519 keypair
//! per network and stores the private key sealed with the same key material the
//! node uses for DB column encryption. Future threshold backends must avoid
//! ever assembling the full network private key.

use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::encryption::{ColumnEncryption, EncryptionError};

use super::types::ALG_X25519_AES256GCM;

#[derive(Debug, Error)]
pub enum KeyBackendError {
    #[error("private key material unavailable")]
    SealedKeyMissing,
    #[error("invalid sealed key length")]
    InvalidSealedKey,
    #[error("invalid public key length")]
    InvalidPublicKey,
    #[error("invalid wrapped key envelope")]
    InvalidWrappedKey,
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
    let peer_pub = PublicKey::from(peer);
    let shared = secret.diffie_hellman(&peer_pub);
    let cipher = ColumnEncryption::new(*shared.as_bytes());
    let pt = cipher.decrypt(&wrapped[32..])?;
    Ok(pt)
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

    fn open_private(&self, sealed: &[u8]) -> Result<StaticSecret, KeyBackendError> {
        let opened = self.seal.decrypt(sealed)?;
        if opened.len() != 32 {
            return Err(KeyBackendError::InvalidSealedKey);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&opened);
        Ok(StaticSecret::from(arr))
    }
}

impl KeyBackend for LocalOneOfOneBackend {
    fn kind(&self) -> super::types::KeyBackendKind {
        super::types::KeyBackendKind::LocalOneOfOne
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
        let secret = self.open_private(sealed_private_key)?;
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
}
