//! Authenticated, identity-free records stored outside space storage prefixes.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
#[error("invalid or unverifiable purge ledger record")]
pub struct LedgerError;

/// Keys remain available for the lifetime of records signed with their IDs.
/// This type deliberately does not implement Debug or serialization.
pub struct LedgerKeys {
    active_key_id: String,
    keys: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    pub version: u8,
    pub key_id: String,
    pub kind: String,
    pub target_hmac: String,
    pub operation_id: String,
    pub state: String,
    /// Unix seconds; this is signed metadata, not a replay-protection mechanism.
    pub timestamp: i64,
    pub mac: String,
}

#[derive(Serialize)]
struct SignedFields<'a> {
    version: u8,
    key_id: &'a str,
    kind: &'a str,
    target_hmac: &'a str,
    operation_id: &'a str,
    state: &'a str,
    timestamp: i64,
}

fn safe_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl LedgerRecord {
    fn fields(&self) -> SignedFields<'_> {
        SignedFields {
            version: self.version,
            key_id: &self.key_id,
            kind: &self.kind,
            target_hmac: &self.target_hmac,
            operation_id: &self.operation_id,
            state: &self.state,
            timestamp: self.timestamp,
        }
    }
    fn validate(&self) -> Result<(), LedgerError> {
        if self.version != 1
            || !safe_key_id(&self.key_id)
            || self.timestamp < 0
            || self.target_hmac.len() != 64
            || !self
                .target_hmac
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            || uuid::Uuid::parse_str(&self.operation_id).is_err()
            || !matches!(
                (self.kind.as_str(), self.state.as_str()),
                ("owner", "retired") | ("space" | "resource", "purging" | "complete")
            )
        {
            return Err(LedgerError);
        }
        Ok(())
    }
    pub fn object_key(&self) -> Result<String, LedgerError> {
        self.validate()?;
        if self.kind == "owner" {
            Ok(format!(
                "_purge-ledger/owners/{}/{}",
                self.key_id, self.target_hmac
            ))
        } else {
            Ok(format!(
                "_purge-ledger/{}/{}/{}/{}",
                if self.kind == "resource" {
                    "resources"
                } else {
                    "spaces"
                },
                self.key_id,
                self.target_hmac,
                self.state
            ))
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        serde_json::to_vec(self).map_err(|_| LedgerError)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyConfig {
    active_key_id: String,
    keys: BTreeMap<String, String>,
}
impl Drop for KeyConfig {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl LedgerKeys {
    /// TINYCLOUD_SPACE_TOMBSTONE_HMAC_KEY accepts a base64url key (>=32 bytes),
    /// or a JSON key ring {active_key_id,keys:{id:base64url}} retaining old keys.
    /// No identity-derived or generated fallback is used.
    pub fn from_config(raw: String) -> Result<Self, LedgerError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let raw = Zeroizing::new(raw);
        if raw.trim_start().starts_with('{') {
            let config: KeyConfig = serde_json::from_str(&raw).map_err(|_| LedgerError)?;
            let mut keys = BTreeMap::new();
            for (id, key) in &config.keys {
                keys.insert(
                    id.clone(),
                    Zeroizing::new(URL_SAFE_NO_PAD.decode(key).map_err(|_| LedgerError)?),
                );
            }
            Self::from_keys(config.active_key_id.clone(), keys)
        } else {
            let key = URL_SAFE_NO_PAD
                .decode(raw.trim())
                .map_err(|_| LedgerError)?;
            let id = hex::encode(Sha256::digest(&key));
            Self::new(id.clone(), BTreeMap::from([(id, key)]))
        }
    }
    pub fn new(
        active_key_id: String,
        keys: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, LedgerError> {
        let keys: BTreeMap<_, _> = keys
            .into_iter()
            .map(|(id, key)| (id, Zeroizing::new(key)))
            .collect();
        Self::from_keys(active_key_id, keys)
    }
    fn from_keys(
        active_key_id: String,
        keys: BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) -> Result<Self, LedgerError> {
        if !safe_key_id(&active_key_id)
            || !keys.contains_key(&active_key_id)
            || keys
                .iter()
                .any(|(id, key)| !safe_key_id(id) || key.len() < 32)
        {
            return Err(LedgerError);
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    pub fn nonce_hmac(
        &self,
        key_id: &str,
        owner: &str,
        nonce: &str,
    ) -> Result<Vec<u8>, LedgerError> {
        let mut mac = self.mac(key_id)?;
        mac.update(b"tinycloud-space-lifecycle-nonce-v1\0");
        mac.update(owner.as_bytes());
        mac.update(b"\0");
        mac.update(nonce.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
    fn mac(&self, key_id: &str) -> Result<HmacSha256, LedgerError> {
        HmacSha256::new_from_slice(self.keys.get(key_id).ok_or(LedgerError)?.as_slice())
            .map_err(|_| LedgerError)
    }
    /// Domain separation prevents owner and space identifiers from colliding.
    pub fn target_hmac(
        &self,
        key_id: &str,
        kind: &str,
        canonical_target: &str,
    ) -> Result<Vec<u8>, LedgerError> {
        let mut mac = self.mac(key_id)?;
        match kind {
            "owner" => mac.update(b"tinycloud-owner-tombstone-v1\0"),
            "space" => mac.update(b"tinycloud-space-tombstone-v1\0"),
            "resource" => mac.update(b"tinycloud-resource-tombstone-v1\0"),
            _ => return Err(LedgerError),
        }
        mac.update(canonical_target.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
    pub fn sign(
        &self,
        key_id: &str,
        kind: &str,
        target_hmac: &[u8],
        operation_id: &str,
        state: &str,
        timestamp: i64,
    ) -> Result<LedgerRecord, LedgerError> {
        let mut record = LedgerRecord {
            version: 1,
            key_id: key_id.into(),
            kind: kind.into(),
            target_hmac: hex::encode(target_hmac),
            operation_id: operation_id.into(),
            state: state.into(),
            timestamp,
            mac: String::new(),
        };
        record.validate()?;
        let mut mac = self.mac(key_id)?;
        mac.update(b"tinycloud-space-purge-ledger-v1\0");
        mac.update(&serde_json::to_vec(&record.fields()).map_err(|_| LedgerError)?);
        record.mac = hex::encode(mac.finalize().into_bytes());
        Ok(record)
    }
    /// The object key is authenticated by matching it to the verified fields.
    pub fn verify(&self, object_key: &str, body: &[u8]) -> Result<LedgerRecord, LedgerError> {
        let record: LedgerRecord = serde_json::from_slice(body).map_err(|_| LedgerError)?;
        if record.object_key()? != object_key {
            return Err(LedgerError);
        }
        let signature = hex::decode(&record.mac).map_err(|_| LedgerError)?;
        let mut mac = self.mac(&record.key_id)?;
        mac.update(b"tinycloud-space-purge-ledger-v1\0");
        mac.update(&serde_json::to_vec(&record.fields()).map_err(|_| LedgerError)?);
        mac.verify_slice(&signature).map_err(|_| LedgerError)?;
        Ok(record)
    }
}
