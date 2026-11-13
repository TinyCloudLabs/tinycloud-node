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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<PrefixHmac>,
    pub mac: String,
}

/// Store-relative physical namespace. Absolute deployment roots are never signed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PrefixHmac {
    pub store_kind: String,
    pub prefix_hmac: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    prefixes: Option<&'a [PrefixHmac]>,
}

fn safe_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn valid_store_kind(kind: &str) -> bool {
    matches!(
        kind,
        "kv-filesystem" | "kv-s3" | "sql-filesystem" | "sql-s3" | "sqlite-cache" | "duckdb-cache"
    )
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
            prefixes: (self.version == 2).then_some(self.prefixes.as_slice()),
        }
    }
    fn validate(&self) -> Result<(), LedgerError> {
        if !matches!(self.version, 1 | 2)
            || (self.version == 1 && !self.prefixes.is_empty())
            || (self.kind == "owner" && !self.prefixes.is_empty())
            || self.prefixes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.prefixes.iter().any(|prefix| {
                !valid_store_kind(&prefix.store_kind) || !hex_digest(&prefix.prefix_hmac)
            })
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
        let record = LedgerRecord {
            version: 1,
            key_id: key_id.into(),
            kind: kind.into(),
            target_hmac: hex::encode(target_hmac),
            operation_id: operation_id.into(),
            state: state.into(),
            timestamp,
            prefixes: Vec::new(),
            mac: String::new(),
        };
        self.authenticate(record)
    }
    fn authenticate(&self, mut record: LedgerRecord) -> Result<LedgerRecord, LedgerError> {
        record.validate()?;
        let mut mac = self.mac(&record.key_id)?;
        mac.update(if record.version == 2 {
            b"tinycloud-space-purge-ledger-v2\0"
        } else {
            b"tinycloud-space-purge-ledger-v1\0"
        });
        mac.update(&serde_json::to_vec(&record.fields()).map_err(|_| LedgerError)?);
        record.mac = hex::encode(mac.finalize().into_bytes());
        Ok(record)
    }
    /// Sign the complete authenticated acceptance prefix inventory. Completion
    /// callers must copy this inventory from verified acceptance, never re-list.
    pub fn with_prefixes(
        &self,
        mut record: LedgerRecord,
        mut prefixes: Vec<PrefixHmac>,
    ) -> Result<LedgerRecord, LedgerError> {
        self.verify(&record.object_key()?, &record.to_bytes()?)?;
        prefixes.sort();
        prefixes.dedup();
        record.version = 2;
        record.prefixes = prefixes;
        self.authenticate(record)
    }
    /// Preserve the authenticated acceptance inventory across terminal retries.
    pub fn completion_from_acceptance(
        &self,
        mut acceptance: LedgerRecord,
        timestamp: i64,
    ) -> Result<LedgerRecord, LedgerError> {
        self.verify(&acceptance.object_key()?, &acceptance.to_bytes()?)?;
        if acceptance.version != 2
            || acceptance.kind != "space"
            || acceptance.state != "purging"
            || timestamp < acceptance.timestamp
        {
            return Err(LedgerError);
        }
        acceptance.state = "complete".into();
        acceptance.timestamp = timestamp;
        self.authenticate(acceptance)
    }
    pub fn prefix_hmac(
        &self,
        key_id: &str,
        store_kind: &str,
        prefix: &str,
    ) -> Result<PrefixHmac, LedgerError> {
        if !valid_store_kind(store_kind)
            || prefix.is_empty()
            || prefix.starts_with('/')
            || !prefix.ends_with('/')
            || prefix.starts_with("_purge-ledger/")
            || prefix.split('/').any(|part| part == "." || part == "..")
            || prefix.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(LedgerError);
        }
        let mut mac = self.mac(key_id)?;
        mac.update(b"tinycloud-physical-purge-prefix-v1\0");
        mac.update(&(store_kind.len() as u64).to_be_bytes());
        mac.update(store_kind.as_bytes());
        mac.update(&(prefix.len() as u64).to_be_bytes());
        mac.update(prefix.as_bytes());
        Ok(PrefixHmac {
            store_kind: store_kind.into(),
            prefix_hmac: hex::encode(mac.finalize().into_bytes()),
        })
    }
    /// The object key is authenticated by matching it to the verified fields.
    pub fn verify(&self, object_key: &str, body: &[u8]) -> Result<LedgerRecord, LedgerError> {
        let record: LedgerRecord = serde_json::from_slice(body).map_err(|_| LedgerError)?;
        if record.object_key()? != object_key {
            return Err(LedgerError);
        }
        let signature = hex::decode(&record.mac).map_err(|_| LedgerError)?;
        let mut mac = self.mac(&record.key_id)?;
        mac.update(if record.version == 2 {
            b"tinycloud-space-purge-ledger-v2\0"
        } else {
            b"tinycloud-space-purge-ledger-v1\0"
        });
        mac.update(&serde_json::to_vec(&record.fields()).map_err(|_| LedgerError)?);
        mac.verify_slice(&signature).map_err(|_| LedgerError)?;
        Ok(record)
    }
}
