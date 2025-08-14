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

    use tinycloud_lib::cacaos::siwe_cacao::Signature;

    pub fn serialize<S>(addr: &Signature, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("0x{}", addr.deref().encode_hex::<String>()).serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sig = Cow::<'_, str>::deserialize(d)?;
        <[u8; 65]>::from_hex(sig.strip_prefix("0x").unwrap_or(&sig))
            .map(Into::into)
            .map_err(|e| D::Error::custom(format!("failed to parse SIWE signature: {e}")))
    }
}
