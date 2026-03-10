//! Application-level column encryption using AES-256-GCM.
//!
//! Encrypted values are prefixed with a version byte:
//! - `0x01` followed by 12-byte nonce, ciphertext, and 16-byte GCM tag
//! - Any other first byte is treated as legacy plaintext (existing data)
//!
//! This allows gradual migration: new writes are encrypted, old reads still work.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};

const VERSION_ENCRYPTED: u8 = 0x01;

#[derive(Clone)]
pub struct ColumnEncryption {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for ColumnEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColumnEncryption").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("encrypted data too short")]
    TooShort,
}

impl ColumnEncryption {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).expect("valid 32-byte key"),
        }
    }

    /// Encrypt plaintext. Returns: 0x01 || nonce(12B) || ciphertext || tag(16B)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .expect("encryption should not fail");
        let mut result = Vec::with_capacity(1 + 12 + ciphertext.len());
        result.push(VERSION_ENCRYPTED);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt data. Handles version dispatch:
    /// - 0x01: AES-256-GCM encrypted
    /// - Anything else: return as-is (legacy plaintext)
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.is_empty() {
            return Ok(data.to_vec());
        }
        if data[0] != VERSION_ENCRYPTED {
            // Legacy plaintext - return as-is
            return Ok(data.to_vec());
        }
        // Encrypted: 0x01 || nonce(12) || ciphertext+tag
        if data.len() < 1 + 12 + 16 {
            return Err(EncryptionError::TooShort);
        }
        let nonce_bytes: [u8; 12] = data[1..13].try_into().expect("slice is 12 bytes");
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = &data[13..];
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| EncryptionError::Decrypt(e.to_string()))
    }
}

/// Helper: encrypt if encryption is configured, otherwise return plaintext.
pub fn maybe_encrypt(enc: Option<&ColumnEncryption>, data: &[u8]) -> Vec<u8> {
    match enc {
        Some(e) => e.encrypt(data),
        None => data.to_vec(),
    }
}

/// Helper: decrypt if encryption is configured, otherwise return as-is.
pub fn maybe_decrypt(
    enc: Option<&ColumnEncryption>,
    data: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    match enc {
        Some(e) => e.decrypt(data),
        None => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn round_trip() {
        let enc = ColumnEncryption::new(test_key());
        let plaintext = b"hello world";
        let encrypted = enc.encrypt(plaintext);
        assert_eq!(encrypted[0], VERSION_ENCRYPTED);
        assert_ne!(&encrypted[1..], plaintext);
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn legacy_plaintext_passthrough() {
        let enc = ColumnEncryption::new(test_key());
        // CBOR starts with 0xa_, not 0x01
        let cbor_data = vec![0xa2, 0x01, 0x02, 0x03];
        let result = enc.decrypt(&cbor_data).unwrap();
        assert_eq!(result, cbor_data);
    }

    #[test]
    fn empty_data() {
        let enc = ColumnEncryption::new(test_key());
        let result = enc.decrypt(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let enc1 = ColumnEncryption::new([0x42u8; 32]);
        let enc2 = ColumnEncryption::new([0x43u8; 32]);
        let encrypted = enc1.encrypt(b"secret");
        assert!(enc2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn truncated_data_fails() {
        let enc = ColumnEncryption::new(test_key());
        let encrypted = enc.encrypt(b"test");
        // Truncate to just version + partial nonce
        assert!(enc.decrypt(&encrypted[..5]).is_err());
    }

    #[test]
    fn maybe_helpers_none() {
        let data = b"plaintext";
        assert_eq!(maybe_encrypt(None, data), data.to_vec());
        assert_eq!(maybe_decrypt(None, data).unwrap(), data.to_vec());
    }

    #[test]
    fn maybe_helpers_some() {
        let enc = ColumnEncryption::new(test_key());
        let plaintext = b"hello";
        let encrypted = maybe_encrypt(Some(&enc), plaintext);
        assert_eq!(encrypted[0], VERSION_ENCRYPTED);
        let decrypted = maybe_decrypt(Some(&enc), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
