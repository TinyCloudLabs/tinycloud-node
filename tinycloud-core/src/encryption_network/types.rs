//! Shared data shapes for the encryption module.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::network_id::NetworkId;

pub const ALG_X25519_AES256GCM: &str = "x25519-aes256gcm/v1";

/// Lifecycle state of a network. V1 transitions: Pending → Generating → Active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkState {
    Pending,
    Generating,
    Active,
    Rotating,
    Revoked,
    Failed,
}

impl NetworkState {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkState::Pending => "pending",
            NetworkState::Generating => "generating",
            NetworkState::Active => "active",
            NetworkState::Rotating => "rotating",
            NetworkState::Revoked => "revoked",
            NetworkState::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => NetworkState::Pending,
            "generating" => NetworkState::Generating,
            "active" => NetworkState::Active,
            "rotating" => NetworkState::Rotating,
            "revoked" => NetworkState::Revoked,
            "failed" => NetworkState::Failed,
            _ => return None,
        })
    }
}

impl fmt::Display for NetworkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identifies which KeyBackend produced and holds the network key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyBackendKind {
    /// Local one-of-one: private key sealed with the node DB key.
    LocalOneOfOne,
    /// DStack-derived key management.
    Dstack,
    /// Future threshold backend (not implemented in v1).
    Threshold,
}

impl KeyBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyBackendKind::LocalOneOfOne => "local-one-of-one",
            KeyBackendKind::Dstack => "dstack",
            KeyBackendKind::Threshold => "threshold",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "local-one-of-one" => KeyBackendKind::LocalOneOfOne,
            "dstack" => KeyBackendKind::Dstack,
            "threshold" => KeyBackendKind::Threshold,
            _ => return None,
        })
    }
}

/// Public network descriptor.
///
/// `members` are node DIDs participating in key custody. V1 has exactly one
/// member matching this node. `threshold` is preserved in the data shape so
/// callers can distinguish V1 from future threshold deployments at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMemberDescriptor {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDescriptor {
    #[serde(rename = "networkId")]
    pub network_id: NetworkId,
    pub principal: String,
    pub name: String,
    pub members: Vec<NetworkMemberDescriptor>,
    pub threshold: Threshold,
    pub state: NetworkState,
    #[serde(rename = "publicEncryptionKey", with = "base64_bytes")]
    pub public_encryption_key: Vec<u8>,
    pub alg: String,
    #[serde(rename = "keyVersion")]
    pub key_version: i64,
    #[serde(rename = "keyBackend")]
    pub key_backend: KeyBackendKind,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Threshold {
    pub n: i32,
    pub t: i32,
}

impl Threshold {
    pub const fn one_of_one() -> Self {
        Self { n: 1, t: 1 }
    }
}

/// Inline encrypted envelope persisted alongside KV/SQL records.
///
/// Encryption shape (v1):
/// - `encryptedSymmetricKey` is the symmetric key sealed to the network public key.
/// - `ciphertext` is the AES-256-GCM payload (clients encrypt locally).
/// - `aad` is application-bound associated data; the node never reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineEnvelope {
    pub v: u32,
    #[serde(rename = "networkId")]
    pub network_id: NetworkId,
    pub alg: String,
    #[serde(rename = "keyVersion")]
    pub key_version: i64,
    #[serde(rename = "encryptedSymmetricKey", with = "base64_bytes")]
    pub encrypted_symmetric_key: Vec<u8>,
    #[serde(rename = "encryptedSymmetricKeyHash")]
    pub encrypted_symmetric_key_hash: String,
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub aad: Vec<u8>,
    #[serde(default)]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        STANDARD
            .decode(s)
            .map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}
