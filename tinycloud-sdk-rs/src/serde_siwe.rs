pub mod address {
    use crate::util::{decode_eip55, encode_eip55};
    use serde::{
        de::{Deserialize, Deserializer, Error as DeErr},
        ser::{Serialize, Serializer},
    };
    use std::borrow::Cow;

    pub fn serialize<S>(addr: &[u8; 20], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("0x{}", encode_eip55(addr)).serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr = Cow::<'_, str>::deserialize(d)?;
        decode_eip55(addr.strip_prefix("0x").unwrap_or(&addr)).map_err(D::Error::custom)
    }
}

pub mod signature {
    use hex::{FromHex, ToHex};
    use serde::{
        de::{Deserialize, Deserializer, Error as DeErr},
        ser::{Serialize, Serializer},
    };
    use std::{borrow::Cow, ops::Deref};

    use tinycloud_auth::cacaos::siwe_cacao::Signature;

    pub fn serialize<S>(addr: &Signature, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("0x{}", addr.deref().encode_hex::<String>()).serialize(s)
    }

    /// Decode a 65-byte hex wallet signature, with an optional `0x` prefix.
    ///
    /// Uses the node's CACAO decoder: low-s signatures with recovery IDs
    /// `0/1` or `27/28` are accepted and stored as `27/28`; high-s signatures,
    /// invalid scalars, lengths, and recovery IDs are rejected.
    pub fn deserialize<'de, D>(d: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sig = Cow::<'_, str>::deserialize(d)?;
        let bytes = <[u8; 65]>::from_hex(sig.strip_prefix("0x").unwrap_or(&sig))
            .map_err(|e| D::Error::custom(format!("failed to parse SIWE signature: {e}")))?;
        Signature::decode(bytes).map_err(D::Error::custom)
    }
}
