//! Canonical record and session identity encodings.

use crate::dst::IDENTITY_PREFIX;
use crate::encoding::{Decoder, Encoder};
use crate::error::Error;
use crate::ids::{KeyPath, KeyVersion, NetworkUrn, WriteNonce};

const VERSION: u8 = 1;
const RECORD: u8 = 1;
const SESSION: u8 = 2;

/// An immutable identity with the exact version-one canonical bytes.
///
/// Record mode includes a write nonce. Session mode deliberately omits it;
/// enabling session mode and choosing nonce uniqueness are caller policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IbeIdentity {
    network: NetworkUrn,
    path: KeyPath,
    version: KeyVersion,
    nonce: Option<WriteNonce>,
    bytes: Vec<u8>,
}

impl IbeIdentity {
    /// Encode a record identity without normalizing the network or path.
    pub fn record(
        network: &NetworkUrn,
        path: &KeyPath,
        version: KeyVersion,
        nonce: &WriteNonce,
    ) -> Result<Self, Error> {
        Ok(Self::build(network, path, version, Some(*nonce)))
    }

    /// Encode a session identity without a write nonce.
    pub fn session(
        network: &NetworkUrn,
        path: &KeyPath,
        version: KeyVersion,
    ) -> Result<Self, Error> {
        Ok(Self::build(network, path, version, None))
    }

    fn build(
        network: &NetworkUrn,
        path: &KeyPath,
        version: KeyVersion,
        nonce: Option<WriteNonce>,
    ) -> Self {
        let mut encoder = Encoder::new();
        encoder.lp(IDENTITY_PREFIX);
        encoder.u8(VERSION);
        encoder.u8(if nonce.is_some() { RECORD } else { SESSION });
        encoder.lp(network.as_bytes());
        encoder.lp(path.as_bytes());
        encoder.u64(version.get());
        if let Some(nonce) = &nonce {
            encoder.fixed(nonce.as_bytes());
        }
        Self {
            network: network.clone(),
            path: path.clone(),
            version,
            nonce,
            bytes: encoder.finish(),
        }
    }

    /// Decode exactly one canonical identity, rejecting malformed or trailing bytes.
    ///
    /// Nested field caps are checked before UTF-8 strings are allocated.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes)?;
        if decoder.lp(IDENTITY_PREFIX.len())? != IDENTITY_PREFIX {
            return Err(Error::InvalidEncoding);
        }
        if decoder.u8()? != VERSION {
            return Err(Error::InvalidEncoding);
        }
        let mode = decoder.u8()?;
        if mode != RECORD && mode != SESSION {
            return Err(Error::InvalidEncoding);
        }
        let network =
            core::str::from_utf8(decoder.lp(1024)?).map_err(|_| Error::InvalidEncoding)?;
        let network = NetworkUrn::new(network)?;
        let path = core::str::from_utf8(decoder.lp(1024)?).map_err(|_| Error::InvalidEncoding)?;
        let path = KeyPath::new(path)?;
        let version = KeyVersion::new(decoder.u64()?);
        let nonce = if mode == RECORD {
            Some(WriteNonce::new(decoder.fixed()?))
        } else {
            None
        };
        decoder.finish()?;
        Ok(Self {
            network,
            path,
            version,
            nonce,
            bytes: bytes.to_vec(),
        })
    }

    /// Borrow the network encoded in this identity.
    pub fn network(&self) -> &NetworkUrn {
        &self.network
    }

    /// Borrow the exact canonical identity bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the encoded key path.
    pub fn key_path(&self) -> &KeyPath {
        &self.path
    }

    /// Return the encoded key version.
    pub fn key_version(&self) -> KeyVersion {
        self.version
    }

    /// Borrow the write nonce in record mode, or return `None` in session mode.
    pub fn nonce(&self) -> Option<&WriteNonce> {
        self.nonce.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn encoded(mode: u8, network: &[u8], path: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&26u32.to_be_bytes());
        bytes.extend_from_slice(b"TC-THRESHOLD-V1-IBE-ID-ENC");
        bytes.extend_from_slice(&[1, mode]);
        bytes.extend_from_slice(&(network.len() as u32).to_be_bytes());
        bytes.extend_from_slice(network);
        bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&7u64.to_be_bytes());
        if mode == 1 {
            bytes.extend_from_slice(&[9; 16]);
        }
        bytes
    }

    pub(super) fn identity(
        record: bool,
        network: &str,
        path: &str,
        version: u64,
        nonce: [u8; 16],
    ) -> IbeIdentity {
        let network = NetworkUrn::new(network).unwrap();
        let path = KeyPath::new(path).unwrap();
        if record {
            IbeIdentity::record(
                &network,
                &path,
                KeyVersion::new(version),
                &WriteNonce::new(nonce),
            )
            .unwrap()
        } else {
            IbeIdentity::session(&network, &path, KeyVersion::new(version)).unwrap()
        }
    }

    #[test]
    fn frozen_record_and_session_encoding_and_accessors() {
        for record in [false, true] {
            let id = identity(record, "net", "path", 7, [9; 16]);
            assert_eq!(
                id.as_bytes(),
                encoded(if record { 1 } else { 2 }, b"net", b"path")
            );
            assert_eq!(IbeIdentity::decode(id.as_bytes()), Ok(id.clone()));
            assert_eq!(id.network().as_str(), "net");
            assert_eq!(id.key_path().as_str(), "path");
            assert_eq!(id.key_version(), KeyVersion::new(7));
            assert_eq!(
                id.nonce().map(WriteNonce::as_bytes),
                record.then_some(&[9; 16])
            );
        }
    }

    #[test]
    fn adversarial_field_splits_are_distinct_or_refused() {
        assert_eq!(KeyPath::new(""), Err(Error::InvalidLength));
        assert!(IbeIdentity::decode(&encoded(2, b"a/b", b"")).is_err());
        let a = identity(false, "a/b", "c", 7, [9; 16]);
        let b = identity(false, "a", "/bc", 7, [9; 16]);
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(
            IbeIdentity::decode(&encoded(2, b"a", b"/b"))
                .unwrap()
                .key_path()
                .as_str(),
            "/b"
        );
    }

    #[test]
    fn identity_decoder_rejects_malformed_fields() {
        let valid = identity(true, "net", "path", 7, [9; 16]);
        let bytes = valid.as_bytes();
        for cut in 0..bytes.len() {
            assert!(IbeIdentity::decode(&bytes[..cut]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(IbeIdentity::decode(&trailing), Err(Error::InvalidEncoding));
        let prefix_end = 4 + b"TC-THRESHOLD-V1-IBE-ID-ENC".len();
        for (offset, value) in [
            (4, b'X'),
            (prefix_end, 2),
            (prefix_end + 1, 0),
            (prefix_end + 1, 3),
        ] {
            let mut bad = bytes.to_vec();
            bad[offset] = value;
            assert_eq!(IbeIdentity::decode(&bad), Err(Error::InvalidEncoding));
        }
        assert_eq!(
            IbeIdentity::decode(&encoded(2, &[0xff], b"p")),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            IbeIdentity::decode(&encoded(2, b"n", &[0xff])),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            IbeIdentity::decode(&encoded(2, b"", b"p")),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            IbeIdentity::decode(&encoded(2, b"n", b"")),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            IbeIdentity::decode(&encoded(2, &vec![b'n'; 1025], b"p")),
            Err(Error::LimitExceeded)
        );
        for offset in [0, prefix_end + 2, prefix_end + 2 + 4 + 3] {
            let mut bad = bytes.to_vec();
            bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert_eq!(IbeIdentity::decode(&bad), Err(Error::LimitExceeded));
        }
        assert_eq!(
            IbeIdentity::decode(&vec![0; 65537]),
            Err(Error::LimitExceeded)
        );
    }

    proptest! {
        #[test]
        fn identity_random_roundtrip_and_injectivity(
            n in ".{1,24}", p in ".{1,24}", n2 in ".{1,24}", p2 in ".{1,24}",
            v in any::<u64>(), v2 in any::<u64>(),
            nonce in any::<[u8; 16]>(), nonce2 in any::<[u8; 16]>(),
            record in any::<bool>(), record2 in any::<bool>(),
        ) {
            let a = identity(record, &n, &p, v, nonce);
            let b = identity(record2, &n2, &p2, v2, nonce2);
            prop_assert_eq!(IbeIdentity::decode(a.as_bytes()), Ok(a.clone()));
            prop_assert_eq!(a.as_bytes() == b.as_bytes(),
                n == n2 && p == p2 && v == v2 && record == record2 && (!record || nonce == nonce2));
        }

        #[test]
        fn identity_random_bytes_reject_or_canonical(bytes in prop::collection::vec(any::<u8>(), 0..70000)) {
            if let Ok(id) = IbeIdentity::decode(&bytes) {
                prop_assert_eq!(id.as_bytes(), bytes.as_slice());
                prop_assert!((1..=1024).contains(&id.network().as_bytes().len()));
                prop_assert!((1..=1024).contains(&id.key_path().as_bytes().len()));
            }
        }

        #[test]
        fn identity_structured_mutations_reject_or_canonical(
            n in ".{1,24}", p in ".{1,24}", v in any::<u64>(), nonce in any::<[u8;16]>(),
            record in any::<bool>(), offset in any::<usize>(), replacement in any::<u8>(), mutation in 0u8..3,
        ) {
            let id = identity(record, &n, &p, v, nonce);
            let mut bytes = id.as_bytes().to_vec();
            let position = offset % bytes.len();
            match mutation {
                0 => bytes[position] = replacement,
                1 => { bytes.remove(position); },
                _ => bytes.insert(position, replacement),
            }
            if let Ok(decoded) = IbeIdentity::decode(&bytes) {
                prop_assert_eq!(decoded.as_bytes(), bytes.as_slice());
                prop_assert_eq!(IbeIdentity::decode(decoded.as_bytes()), Ok(decoded.clone()));
            }
        }
    }
}

#[cfg(test)]
mod split_properties {
    use super::tests::identity;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn moving_separator_between_fields_never_collides(n in "[a-z]{1,24}", p in "[a-z]{1,24}") {
            let a = identity(false, &format!("{n}/"), &p, 7, [0;16]);
            let b = identity(false, &n, &format!("/{p}"), 7, [0;16]);
            prop_assert_ne!(a.as_bytes(), b.as_bytes());
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn maximum_utf8_fields_and_integer_values_roundtrip_in_both_modes() {
        let network = NetworkUrn::new("é".repeat(512)).unwrap();
        let path = KeyPath::new("p".repeat(1024)).unwrap();
        let version = KeyVersion::new(u64::MAX);
        let nonce = WriteNonce::new([u8::MAX; 16]);
        for id in [
            IbeIdentity::record(&network, &path, version, &nonce).unwrap(),
            IbeIdentity::session(&network, &path, version).unwrap(),
        ] {
            assert_eq!(IbeIdentity::decode(id.as_bytes()), Ok(id));
        }
    }
}
