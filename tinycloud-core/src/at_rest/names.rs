//! How a reader knows whether stored bytes are TCE1: from where they live
//! (S3 name namespace) or an explicit column, never from the bytes.

use super::envelope::{push_lp, EnvelopeError};
use super::key::ObjectNameKey;
use crate::hash::Hash;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// `database_artifact.payload_encoding` / `delta_encoding` (SMALLINT).
/// `NULL` is legacy plaintext; `g` in 1..=255 is TCE generation `g`, of which
/// this build reads only 1 (later ones are [`EnvelopeError::Unsupported`]).
/// Zero, negative and larger values are refused as invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadEncoding {
    LegacyPlaintext,
    Tce1,
}

impl PayloadEncoding {
    pub fn from_column(value: Option<i16>) -> Result<Self, EnvelopeError> {
        match value {
            None => Ok(Self::LegacyPlaintext),
            Some(1) => Ok(Self::Tce1),
            Some(v @ 2..=255) => Err(EnvelopeError::Unsupported { version: v as u8 }),
            Some(_) => Err(EnvelopeError::Header("invalid payload encoding")),
        }
    }

    pub fn to_column(self) -> Option<i16> {
        match self {
            Self::LegacyPlaintext => None,
            Self::Tce1 => Some(1),
        }
    }
}

/// Prefix of every sealed KV object name.
pub const SEALED_NAME_PREFIX: &str = "v1/";

fn hmac(nk: &ObjectNameKey, fields: &[&[u8]]) -> [u8; 32] {
    let mut msg = Vec::new();
    for f in fields {
        push_lp(&mut msg, f);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(nk.bytes()).expect("any key length");
    mac.update(&msg);
    mac.finalize().into_bytes().into()
}

/// Pseudonymous per-space name prefix: `b64url(HMAC(NK, lp("space") ‖ lp(space))[..16])`.
pub fn space_tag(nk: &ObjectNameKey, space: &str) -> String {
    URL_SAFE_NO_PAD.encode(&hmac(nk, &[b"space", space.as_bytes()])[..16])
}

/// `v1/{space_tag}/{b64url(HMAC(NK, lp("obj") ‖ lp(space) ‖ lp(multihash)))}`.
/// Legacy plaintext objects keep `{space}/{b64url(digest)}`, which never
/// starts with `v1/` because space ids start with `tinycloud:`.
pub fn sealed_object_name(nk: &ObjectNameKey, space: &str, hash: &Hash) -> String {
    let obj = hmac(nk, &[b"obj", space.as_bytes(), &Vec::<u8>::from(*hash)]);
    format!(
        "{SEALED_NAME_PREFIX}{}/{}",
        space_tag(nk, space),
        URL_SAFE_NO_PAD.encode(obj)
    )
}
