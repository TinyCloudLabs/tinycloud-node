//! AES-256-GCM column keyrings. V2 is `0x02 || kid || nonce(12) || ciphertext || tag(16)`.
//! The authenticated header and length-delimited database identity match the
//! column re-encryption codec. Stored format metadata selects compatibility reads.

use std::{collections::BTreeMap, sync::Arc};

use aes_gcm::{
    aead::{consts::U12, Aead, AeadInPlace, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const VERSION_LEGACY: u8 = 0x01;
const VERSION_KEYRING: u8 = 0x02;

/// Persisted compatibility namespace for existing values.
pub const FORMAT_LEGACY: i16 = 0;
/// Persisted format for authenticated, row-bound v2 values.
pub const FORMAT_V2: i16 = 2;

/// Domain separation for storage keys derived from the existing root key.
#[derive(Clone, Copy, Debug)]
pub enum EncryptionPurpose {
    Columns,
    Webhooks,
    NetworkSeals,
}

/// Stable database identity; PK components are raw database bytes in PK order.
#[derive(Clone, Copy, Debug)]
pub struct RowBinding<'a> {
    pub table: &'a str,
    pub column: &'a str,
    pub pk: &'a [&'a [u8]],
}

impl<'a> RowBinding<'a> {
    pub const fn new(table: &'a str, column: &'a str, pk: &'a [&'a [u8]]) -> Self {
        Self { table, column, pk }
    }

    fn aad(self, kid: u8) -> Vec<u8> {
        let capacity = 2
            + 24
            + self.table.len()
            + self.column.len()
            + self
                .pk
                .iter()
                .map(|component| 8 + component.len())
                .sum::<usize>();
        let mut aad = Vec::with_capacity(capacity);
        aad.extend_from_slice(&[VERSION_KEYRING, kid]);
        for label in [self.table.as_bytes(), self.column.as_bytes()] {
            aad.extend_from_slice(&(label.len() as u64).to_be_bytes());
            aad.extend_from_slice(label);
        }
        aad.extend_from_slice(&(self.pk.len() as u64).to_be_bytes());
        for component in self.pk {
            aad.extend_from_slice(&(component.len() as u64).to_be_bytes());
            aad.extend_from_slice(component);
        }
        aad
    }
}

struct ReadKeys {
    v2: BTreeMap<u8, Aes256Gcm>,
    legacy_v1: Option<Aes256Gcm>,
}

/// Selected write generation and shared read keys. Debug never exposes keys.
#[derive(Clone)]
pub struct ColumnEncryption {
    write_kid: u8,
    keys: Arc<ReadKeys>,
    strict: bool,
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
    #[error("unsupported encryption format")]
    UnsupportedVersion,
    #[error("missing encryption key for generation {0}")]
    MissingKey(u8),
    #[error("duplicate encryption key for generation {0}")]
    DuplicateKey(u8),
    #[error("column encryption is required for the recorded format")]
    EncryptionRequired,
}

impl ColumnEncryption {
    /// Construct a generation-zero keyring. Column writes use v2.
    pub fn new(key: [u8; 32]) -> Self {
        Self::with_keys(0, [(0, key)]).expect("one generation-zero key")
    }

    /// Derive a purpose-specific v2 writer from storage root material, retaining
    /// a separately supplied old key for v1 reads.
    pub fn for_purpose(root: [u8; 32], legacy_key: [u8; 32], purpose: EncryptionPurpose) -> Self {
        Self::for_roots(1, [(1, root)], legacy_key, purpose).expect("one root")
    }

    /// Build purpose rings for an explicitly injected set of root generations.
    /// Existing serving generation is 1; callers retain its exact root source.
    pub fn for_roots(
        write_kid: u8,
        roots: impl IntoIterator<Item = (u8, [u8; 32])>,
        legacy_key: [u8; 32],
        purpose: EncryptionPurpose,
    ) -> Result<Self, EncryptionError> {
        let legacy_key = Zeroizing::new(legacy_key);
        let info: &[u8] = match purpose {
            EncryptionPurpose::Columns => b"tinycloud/columns",
            EncryptionPurpose::Webhooks => b"tinycloud/hooks/webhook-secrets",
            EncryptionPurpose::NetworkSeals => b"tinycloud/encryption/network-seal",
        };
        let mut keys = BTreeMap::new();
        for (kid, root) in roots {
            let root = Zeroizing::new(root);
            let mut derived = Zeroizing::new([0u8; 32]);
            Hkdf::<Sha256>::new(Some(b"tinycloud/column-encryption/v2"), root.as_ref())
                .expand(info, derived.as_mut())
                .expect("32-byte HKDF output");
            if keys
                .insert(
                    kid,
                    Aes256Gcm::new_from_slice(derived.as_ref()).expect("32 bytes"),
                )
                .is_some()
            {
                return Err(EncryptionError::DuplicateKey(kid));
            }
        }
        if matches!(purpose, EncryptionPurpose::NetworkSeals) {
            // Serving seals originally use this unmodified source as generation 0.
            // Keep v2 seals written before activation, as well as v1 seals, readable.
            if keys
                .insert(
                    0,
                    Aes256Gcm::new_from_slice(legacy_key.as_ref()).expect("32 bytes"),
                )
                .is_some()
            {
                return Err(EncryptionError::DuplicateKey(0));
            }
        }
        if !keys.contains_key(&write_kid) {
            return Err(EncryptionError::MissingKey(write_kid));
        }
        Ok(Self {
            write_kid,
            keys: Arc::new(ReadKeys {
                v2: keys,
                legacy_v1: Some(Aes256Gcm::new_from_slice(legacy_key.as_ref()).expect("32 bytes")),
            }),
            strict: false,
        })
    }

    /// Require authenticated envelopes even in the recorded legacy namespace.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Construct a keyring, refusing duplicate generations or a missing write key.
    pub fn with_keys(
        write_kid: u8,
        keys: impl IntoIterator<Item = (u8, [u8; 32])>,
    ) -> Result<Self, EncryptionError> {
        let mut ciphers = BTreeMap::new();
        for (kid, key) in keys {
            let key = Zeroizing::new(key);
            match ciphers.entry(kid) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(
                        Aes256Gcm::new_from_slice(key.as_ref()).expect("valid 32-byte key"),
                    );
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(EncryptionError::DuplicateKey(kid));
                }
            }
        }
        if !ciphers.contains_key(&write_kid) {
            return Err(EncryptionError::MissingKey(write_kid));
        }
        Ok(Self {
            write_kid,
            keys: Arc::new(ReadKeys {
                v2: ciphers,
                legacy_v1: None,
            }),
            strict: false,
        })
    }

    pub fn write_kid(&self) -> u8 {
        self.write_kid
    }

    pub fn has_key(&self, kid: u8) -> bool {
        self.keys.v2.contains_key(&kid)
    }

    /// Select a different writer while retaining every read key and read policy.
    pub fn for_kid(&self, kid: u8) -> Result<Self, EncryptionError> {
        if !self.has_key(kid) {
            return Err(EncryptionError::MissingKey(kid));
        }
        Ok(Self {
            write_kid: kid,
            keys: Arc::clone(&self.keys),
            strict: self.strict,
        })
    }

    /// Encrypt as `0x02 || kid || nonce(12) || ciphertext || tag(16)`.
    pub fn encrypt(&self, plaintext: &[u8], binding: RowBinding<'_>) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        self.encrypt_with_nonce(plaintext, &nonce, binding)
    }

    fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &Nonce<U12>,
        binding: RowBinding<'_>,
    ) -> Vec<u8> {
        let header = [VERSION_KEYRING, self.write_kid];
        let aad = binding.aad(self.write_kid);
        Self::seal(
            &self.keys.v2[&self.write_kid],
            plaintext,
            nonce,
            &header,
            &aad,
        )
    }

    /// Explicit unchanged v1 encoding for existing client and seal protocols.
    /// Requires a generation-zero protocol key, not a serving purpose ring.
    pub fn encrypt_legacy(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self
            .keys
            .v2
            .get(&0)
            .expect("legacy wire encryption requires generation zero");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        Self::seal(cipher, plaintext, &nonce, &[VERSION_LEGACY], &[])
    }

    fn seal(
        cipher: &Aes256Gcm,
        plaintext: &[u8],
        nonce: &Nonce<U12>,
        header: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let mut result = Vec::with_capacity(header.len() + 12 + plaintext.len() + 16);
        result.extend_from_slice(header);
        result.extend_from_slice(nonce);
        result.extend_from_slice(plaintext);
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut result[header.len() + 12..])
            .expect("encryption should not fail");
        result.extend_from_slice(&tag);
        result
    }

    /// Decode only the unchanged authenticated v1 protocol envelope.
    pub fn decrypt_legacy(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.first().copied() != Some(VERSION_LEGACY) {
            return Err(EncryptionError::UnsupportedVersion);
        }
        self.open(data, 0, 1, &[])
    }

    /// Decode authenticated v1 or v2. Plaintext requires recorded legacy metadata.
    pub fn decrypt(
        &self,
        data: &[u8],
        binding: RowBinding<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        let kid = match data.first().copied() {
            Some(VERSION_LEGACY) => return self.decrypt_legacy(data),
            Some(VERSION_KEYRING) => *data.get(1).ok_or(EncryptionError::TooShort)?,
            _ => return Err(EncryptionError::UnsupportedVersion),
        };
        let aad = binding.aad(kid);
        self.open(data, kid, 2, &aad)
    }

    /// Select compatibility by stored metadata, independently of the value prefix.
    /// Format 2 requires v2; strict mode also refuses plaintext in format 0.
    pub fn decrypt_recorded(
        &self,
        data: &[u8],
        binding: RowBinding<'_>,
        format: i16,
    ) -> Result<Vec<u8>, EncryptionError> {
        match format {
            FORMAT_V2 if data.first().copied() == Some(VERSION_KEYRING) => {
                self.decrypt(data, binding)
            }
            FORMAT_LEGACY => {
                if !self.strict
                    && !matches!(
                        data.first().copied(),
                        Some(VERSION_LEGACY | VERSION_KEYRING)
                    )
                {
                    Ok(data.to_vec())
                } else {
                    self.decrypt(data, binding)
                }
            }
            _ => Err(EncryptionError::UnsupportedVersion),
        }
    }

    fn open(
        &self,
        data: &[u8],
        kid: u8,
        header_len: usize,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < header_len + 12 + 16 {
            return Err(EncryptionError::TooShort);
        }
        let cipher = if header_len == 1 {
            self.keys
                .legacy_v1
                .as_ref()
                .or_else(|| self.keys.v2.get(&0))
        } else {
            self.keys.v2.get(&kid)
        }
        .ok_or(EncryptionError::MissingKey(kid))?;
        let nonce_bytes: [u8; 12] = data[header_len..header_len + 12]
            .try_into()
            .expect("validated nonce length");
        cipher
            .decrypt(
                &Nonce::from(nonce_bytes),
                Payload {
                    msg: &data[header_len + 12..],
                    aad,
                },
            )
            .map_err(|e| EncryptionError::Decrypt(e.to_string()))
    }
}

/// Encrypt when configured; callers persist format 2 with the resulting value.
pub fn maybe_encrypt(
    enc: Option<&ColumnEncryption>,
    data: &[u8],
    binding: RowBinding<'_>,
) -> Vec<u8> {
    match enc {
        Some(e) => e.encrypt(data, binding),
        None => data.to_vec(),
    }
}

/// Decode with the recorded format, requiring a key for recorded v2 values.
pub fn maybe_decrypt(
    enc: Option<&ColumnEncryption>,
    data: &[u8],
    binding: RowBinding<'_>,
    format: i16,
) -> Result<Vec<u8>, EncryptionError> {
    match enc {
        Some(e) => e.decrypt_recorded(data, binding, format),
        None if format == FORMAT_LEGACY => Ok(data.to_vec()),
        None if format == FORMAT_V2 => Err(EncryptionError::EncryptionRequired),
        None => Err(EncryptionError::UnsupportedVersion),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "01000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919";
    const V2_KID0: &str = "0200000102030405060708090a0b88cb335200fd8ff9c27852e5fd03de0cb6a3ed7253524a4c1b2b36f15e49bc75";
    const V2_KID1: &str = "0201000102030405060708090a0b4702d61bc5e5c21b8d41978bb1e9786dc3fe0e1bfee3e92116d273784dbb3e16";
    const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn keyring() -> ColumnEncryption {
        ColumnEncryption::with_keys(1, [(0, [0; 32]), (1, std::array::from_fn(|i| i as u8))])
            .unwrap()
    }

    #[test]
    fn second_root_keeps_purpose_and_legacy_reads() {
        for purpose in [EncryptionPurpose::Columns, EncryptionPurpose::Webhooks] {
            let old = ColumnEncryption::for_purpose([8; 32], [7; 32], purpose);
            let new =
                ColumnEncryption::for_roots(2, [(1, [8; 32]), (2, [9; 32])], [7; 32], purpose)
                    .unwrap();
            let bytes = old.encrypt(b"stored", binding());
            assert_eq!(
                new.decrypt_recorded(&bytes, binding(), FORMAT_V2).unwrap(),
                b"stored"
            );
            let legacy = ColumnEncryption::new([7; 32]).encrypt_legacy(b"legacy");
            assert_eq!(
                new.decrypt_recorded(&legacy, binding(), FORMAT_LEGACY)
                    .unwrap(),
                b"legacy"
            );
            assert_eq!(&new.encrypt(b"new", binding())[..2], &[2, 2]);
            assert!(old
                .decrypt(&new.encrypt(b"new", binding()), binding())
                .is_err());
        }
    }

    fn binding() -> RowBinding<'static> {
        RowBinding::new("delegation", "serialization", &[b"ab", b"c"])
    }

    #[test]
    fn new_column_writes_use_v2() {
        let ring = keyring();
        let encrypted = ring.encrypt(b"stored column", binding());
        assert_eq!(&encrypted[..2], &[2, 1]);
        assert_eq!(
            ring.decrypt_recorded(&encrypted, binding(), FORMAT_V2)
                .unwrap(),
            b"stored column"
        );
    }

    #[test]
    fn migration_known_answers_remain_compatible() {
        let ring = keyring();
        for expected in [V1, V2_KID0, V2_KID1] {
            assert_eq!(
                ring.decrypt_recorded(&unhex(expected), binding(), FORMAT_LEGACY)
                    .unwrap(),
                [0; 16]
            );
        }
        for (kid, expected) in [(0, V2_KID0), (1, V2_KID1)] {
            assert_eq!(
                ring.for_kid(kid).unwrap().encrypt_with_nonce(
                    &[0; 16],
                    &Nonce::from(NONCE),
                    binding()
                ),
                unhex(expected)
            );
        }
    }

    #[test]
    fn row_column_table_and_primary_key_tuple_are_bound() {
        let ring = keyring();
        let encrypted = ring.encrypt(b"secret", binding());
        for moved in [
            RowBinding::new("invocation", "serialization", &[b"ab", b"c"]),
            RowBinding::new("delegation", "other", &[b"ab", b"c"]),
            RowBinding::new("delegation", "serialization", &[b"ab", b"d"]),
            RowBinding::new("delegation", "serialization", &[b"a", b"bc"]),
            RowBinding::new("delegation", "serialization", &[b"abc"]),
            RowBinding::new("delegation", "serialization", &[b"c", b"ab"]),
            RowBinding::new("delegation", "serialization", &[b"ab", b"c", b""]),
        ] {
            assert!(ring.decrypt_recorded(&encrypted, moved, FORMAT_V2).is_err());
        }
    }

    #[test]
    fn purpose_keys_are_distinct_and_v1_reads_still_work() {
        let columns = ColumnEncryption::for_purpose([8; 32], [7; 32], EncryptionPurpose::Columns);
        let webhooks = ColumnEncryption::for_purpose([8; 32], [7; 32], EncryptionPurpose::Webhooks);
        for (writer, reader) in [(&columns, &webhooks), (&webhooks, &columns)] {
            let encrypted = writer.encrypt(b"secret", binding());
            assert!(reader
                .decrypt_recorded(&encrypted, binding(), FORMAT_V2)
                .is_err());
            assert_eq!(
                writer
                    .decrypt_recorded(&encrypted, binding(), FORMAT_V2)
                    .unwrap(),
                b"secret"
            );
            let legacy = ColumnEncryption::new([7; 32]).encrypt_legacy(b"old value");
            assert_eq!(
                reader
                    .decrypt_recorded(&legacy, binding(), FORMAT_LEGACY)
                    .unwrap(),
                b"old value"
            );
        }
    }

    #[test]
    fn purpose_keyrings_only_use_the_legacy_key_for_v1() {
        let old_v2 = ColumnEncryption::new([7; 32]).encrypt(b"old key", binding());
        for purpose in [EncryptionPurpose::Columns, EncryptionPurpose::Webhooks] {
            let ring = ColumnEncryption::for_purpose([8; 32], [7; 32], purpose);
            for format in [FORMAT_LEGACY, FORMAT_V2] {
                assert!(ring.decrypt_recorded(&old_v2, binding(), format).is_err());
            }
            assert!(ring.for_kid(0).is_err());
        }
    }

    #[test]
    fn recorded_v2_refuses_plaintext_legacy_and_unknown_formats() {
        let ring = keyring();
        for value in [b"".as_slice(), b"plaintext", &[0xa2, 1, 2], &unhex(V1)] {
            assert!(ring.decrypt_recorded(value, binding(), FORMAT_V2).is_err());
        }
        let value = ring.encrypt(b"secret", binding());
        assert!(ring.decrypt_recorded(&value, binding(), 3).is_err());
        assert!(maybe_decrypt(None, &value, binding(), FORMAT_V2).is_err());
        assert!(maybe_decrypt(None, b"plain", binding(), 3).is_err());
    }

    #[test]
    fn strict_refuses_legacy_plaintext_but_accepts_authenticated_formats() {
        let ring = keyring();
        for plain in [
            b"".as_slice(),
            b"JWT.payload.signature",
            b"{\"json\":true}",
            &[0xa2, 1, 2],
        ] {
            assert_eq!(
                ring.decrypt_recorded(plain, binding(), FORMAT_LEGACY)
                    .unwrap(),
                plain
            );
            assert!(ring
                .clone()
                .with_strict(true)
                .decrypt_recorded(plain, binding(), FORMAT_LEGACY)
                .is_err());
            assert!(ring.decrypt(plain, binding()).is_err());
        }
        for value in [V1, V2_KID0, V2_KID1] {
            assert_eq!(
                ring.clone()
                    .with_strict(true)
                    .decrypt_recorded(&unhex(value), binding(), FORMAT_LEGACY)
                    .unwrap(),
                [0; 16]
            );
        }
    }

    #[test]
    fn envelope_header_ciphertext_and_tag_are_authenticated() {
        let key = std::array::from_fn(|i| i as u8);
        let ring = ColumnEncryption::with_keys(1, [(0, key), (1, key)]).unwrap();
        let encrypted = unhex(V2_KID1);
        for index in [0, 1, 14, encrypted.len() - 1] {
            let mut changed = encrypted.clone();
            changed[index] ^= 1;
            assert!(ring
                .decrypt_recorded(&changed, binding(), FORMAT_V2)
                .is_err());
        }
        let wrong = ColumnEncryption::with_keys(1, [(1, [9; 32])]).unwrap();
        assert!(wrong.decrypt(&encrypted, binding()).is_err());
    }

    #[test]
    fn truncated_envelopes_never_pass_through() {
        let ring = keyring();
        for (input, minimum) in [(V1, 29), (V2_KID0, 30), (V2_KID1, 30)] {
            let encrypted = unhex(input);
            for length in 1..minimum {
                assert!(ring
                    .decrypt_recorded(&encrypted[..length], binding(), FORMAT_LEGACY)
                    .is_err());
            }
        }
    }

    #[test]
    fn keyring_requires_unique_keys_and_a_write_key() {
        assert!(matches!(
            ColumnEncryption::with_keys(1, [(0, [0; 32])]),
            Err(EncryptionError::MissingKey(1))
        ));
        assert!(matches!(
            ColumnEncryption::with_keys(0, [(0, [0; 32]), (0, [0; 32])]),
            Err(EncryptionError::DuplicateKey(0))
        ));
        assert!(matches!(
            keyring().for_kid(2),
            Err(EncryptionError::MissingKey(2))
        ));
        let ring = ColumnEncryption::with_keys(1, [(1, std::array::from_fn(|i| i as u8))]).unwrap();
        assert!(ring.decrypt(&unhex(V1), binding()).is_err());
        assert_eq!(ring.decrypt(&unhex(V2_KID1), binding()).unwrap(), [0; 16]);
    }
}
