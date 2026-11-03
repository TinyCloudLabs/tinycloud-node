//! Owner-signed registry v2 hosting authorization. Details: TC-2481.

use crate::{types::Resource, util::Capability};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::Duration,
};
use tinycloud_auth::{
    identity::{canonicalize_did, parse_pkh_did},
    resource::SpaceId,
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Registry failures never grant hosting authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("registry_unavailable: current signed hosting authorization unavailable")]
    Unavailable,
    #[error("registry_hosting_denied: resource is not served here in the requested mode")]
    Denied,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Node {
    did: String,
    url: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Mode {
    #[serde(rename = "read-write")]
    ReadWrite,
    #[serde(rename = "read-only")]
    ReadOnly,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Member {
    did: String,
    mode: Mode,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Space {
    space: String,
    nodes: Vec<Member>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(d)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    subject: String,
    nodes: Vec<Node>,
    spaces: Vec<Space>,
    #[serde(rename = "encryptionNode", deserialize_with = "required_nullable")]
    encryption_node: Option<String>,
    updated_at: String,
    sequence: u64,
    #[serde(skip_serializing)]
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    record: Record,
}

#[derive(Debug)]
struct VerifiedRecord {
    record: Record,
    owner_key: String,
    payload: Vec<u8>,
}

fn ed_key(did: &str) -> Result<EdKey, RegistryError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or(RegistryError::Unavailable)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| RegistryError::Unavailable)?;
    if bytes.len() != 34
        || bytes[..2] != [0xed, 0x01]
        || bs58::encode(&bytes).into_string() != encoded
    {
        return Err(RegistryError::Unavailable);
    }
    let key = EdKey::from_bytes(
        bytes[2..]
            .try_into()
            .map_err(|_| RegistryError::Unavailable)?,
    )
    .map_err(|_| RegistryError::Unavailable)?;
    if key.is_weak() {
        return Err(RegistryError::Unavailable);
    }
    Ok(key)
}

fn owner_key(owner: &str, canonical: bool) -> Result<String, RegistryError> {
    if !owner.is_ascii() {
        return Err(RegistryError::Unavailable);
    }
    if let Some(pkh) = parse_pkh_did(owner).map_err(|_| RegistryError::Unavailable)? {
        if pkh.chain_id > MAX_SAFE_INTEGER
            || (canonical && canonicalize_did(owner).ok().as_deref() != Some(owner))
        {
            return Err(RegistryError::Unavailable);
        }
        Ok(pkh.address)
    } else {
        ed_key(owner)?;
        Ok(owner.to_owned())
    }
}

fn origin(value: &str) -> Result<reqwest::Url, RegistryError> {
    let url = reqwest::Url::parse(value).map_err(|_| RegistryError::Unavailable)?;
    let local = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
    if !value.is_ascii()
        || !matches!(url.scheme(), "https" | "http")
        || (url.scheme() == "http" && !local)
        || url.origin().ascii_serialization() != value
    {
        return Err(RegistryError::Unavailable);
    }
    Ok(url)
}

impl VerifiedRecord {
    #[cfg(test)]
    fn parse(bytes: &[u8]) -> Result<Self, RegistryError> {
        if bytes.len() > MAX_BYTES {
            return Err(RegistryError::Unavailable);
        }
        Self::verify(serde_json::from_slice(bytes).map_err(|_| RegistryError::Unavailable)?)
    }

    fn verify(mut record: Record) -> Result<Self, RegistryError> {
        let owner_key = owner_key(&record.subject, true)?;
        let date = &record.updated_at;
        if record.version != 2
            || record.sequence > MAX_SAFE_INTEGER
            || date.len() != 24
            || !date.is_ascii()
            || date.as_bytes()[10] != b'T'
            || date.as_bytes()[19] != b'.'
            || !date.ends_with('Z')
            || !date.as_bytes()[20..23].iter().all(u8::is_ascii_digit)
            || time::OffsetDateTime::parse(date, &time::format_description::well_known::Rfc3339)
                .is_err()
        {
            return Err(RegistryError::Unavailable);
        }
        let mut nodes = HashSet::new();
        let mut urls = HashSet::new();
        for node in &record.nodes {
            ed_key(&node.did)?;
            origin(&node.url)?;
            if !nodes.insert(node.did.as_str()) || !urls.insert(node.url.as_str()) {
                return Err(RegistryError::Unavailable);
            }
        }
        if record
            .encryption_node
            .as_ref()
            .is_some_and(|did| !nodes.contains(did.as_str()))
        {
            return Err(RegistryError::Unavailable);
        }
        let mut spaces = HashSet::new();
        for entry in &record.spaces {
            let space: SpaceId = entry
                .space
                .parse()
                .map_err(|_| RegistryError::Unavailable)?;
            if !entry.space.is_ascii()
                || owner_key != self::owner_key(space.did().as_str(), false)?
                || !spaces.insert(space)
            {
                return Err(RegistryError::Unavailable);
            }
            let mut members = HashSet::new();
            for member in &entry.nodes {
                if !nodes.contains(member.did.as_str()) || !members.insert(member.did.as_str()) {
                    return Err(RegistryError::Unavailable);
                }
            }
        }
        record.nodes.sort_unstable_by(|a, b| a.did.cmp(&b.did));
        record.spaces.sort_unstable_by(|a, b| a.space.cmp(&b.space));
        for entry in &mut record.spaces {
            entry.nodes.sort_unstable_by(|a, b| a.did.cmp(&b.did));
        }
        let payload = serde_json::to_vec(&record).map_err(|_| RegistryError::Unavailable)?;
        if record.subject.starts_with("did:pkh:") {
            let bytes = record
                .signature
                .strip_prefix("0x")
                .and_then(|s| hex::decode(s).ok())
                .filter(|s| s.len() == 65)
                .ok_or(RegistryError::Unavailable)?;
            let signature =
                Signature::from_slice(&bytes[..64]).map_err(|_| RegistryError::Unavailable)?;
            if signature.normalize_s().is_some() || !matches!(bytes[64], 27 | 28) {
                return Err(RegistryError::Unavailable);
            }
            let recovery =
                RecoveryId::try_from(bytes[64] - 27).map_err(|_| RegistryError::Unavailable)?;
            let mut hash = Keccak256::new();
            hash.update(format!("\x19Ethereum Signed Message:\n{}", payload.len()));
            hash.update(&payload);
            let key = VerifyingKey::recover_from_prehash(&hash.finalize(), &signature, recovery)
                .map_err(|_| RegistryError::Unavailable)?;
            let address = Keccak256::digest(&key.to_encoded_point(false).as_bytes()[1..]);
            if hex::encode(&address[12..]) != owner_key[2..].to_ascii_lowercase() {
                return Err(RegistryError::Unavailable);
            }
        } else {
            let signature = URL_SAFE_NO_PAD
                .decode(&record.signature)
                .map_err(|_| RegistryError::Unavailable)?;
            if URL_SAFE_NO_PAD.encode(&signature) != record.signature {
                return Err(RegistryError::Unavailable);
            }
            let signature =
                EdSignature::from_slice(&signature).map_err(|_| RegistryError::Unavailable)?;
            ed_key(&record.subject)?
                .verify_strict(&payload, &signature)
                .map_err(|_| RegistryError::Unavailable)?;
        }
        Ok(Self {
            record,
            owner_key,
            payload,
        })
    }

    fn allows_space(&self, space: &SpaceId, node: &str, write: bool) -> bool {
        self.record.spaces.iter().any(|entry| {
            entry.space.parse::<SpaceId>().ok().as_ref() == Some(space)
                && entry
                    .nodes
                    .iter()
                    .any(|member| member.did == node && (!write || member.mode == Mode::ReadWrite))
        })
    }
}

/// Fetches and verifies the current owner record. No cross-request record cache
/// or caller-provided proof is used; only the highest accepted sequence is kept.
#[derive(Debug)]
pub struct RegistryAdmission {
    base: reqwest::Url,
    node: String,
    client: reqwest::Client,
    sequences: Mutex<HashMap<String, (u64, [u8; 32])>>,
}

impl RegistryAdmission {
    /// Enable enforcement against an explicit HTTP(S) registry origin.
    pub fn new(base: &str, node: String) -> Result<Self, RegistryError> {
        ed_key(&node)?;
        Ok(Self {
            base: origin(base)?,
            node,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| RegistryError::Unavailable)?,
            sequences: Mutex::new(HashMap::new()),
        })
    }

    async fn current(&self, owner: &str) -> Result<VerifiedRecord, RegistryError> {
        let key = owner_key(owner, false)?;
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| RegistryError::Unavailable)?
            .extend(["v2", "locations", &key]);
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| RegistryError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(
                if self
                    .sequences
                    .lock()
                    .map_err(|_| RegistryError::Unavailable)?
                    .contains_key(&key)
                {
                    RegistryError::Unavailable
                } else {
                    RegistryError::Denied
                },
            );
        }
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BYTES as u64)
        {
            return Err(RegistryError::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RegistryError::Unavailable)?
        {
            if body.len() + chunk.len() > MAX_BYTES {
                return Err(RegistryError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let response: Response =
            serde_json::from_slice(&body).map_err(|_| RegistryError::Unavailable)?;
        let record = VerifiedRecord::verify(response.record)?;
        if record.owner_key != key {
            return Err(RegistryError::Unavailable);
        }
        let digest: [u8; 32] = sha2::Sha256::digest(&record.payload).into();
        let mut sequences = self
            .sequences
            .lock()
            .map_err(|_| RegistryError::Unavailable)?;
        if sequences.get(&key).is_some_and(|(seq, prior)| {
            record.record.sequence < *seq || (record.record.sequence == *seq && prior != &digest)
        }) {
            return Err(RegistryError::Unavailable);
        }
        sequences.insert(key, (record.record.sequence, digest));
        Ok(record)
    }

    /// Check a data resource, including public and ticket-authorized reads.
    pub async fn authorize_space(&self, space: &SpaceId, write: bool) -> Result<(), RegistryError> {
        let record = self.current(space.did().as_str()).await?;
        if record.allows_space(space, &self.node, write) {
            Ok(())
        } else {
            Err(RegistryError::Denied)
        }
    }

    /// Check a raw encryption network independently from data membership.
    pub async fn authorize_encryption(&self, owner: &str) -> Result<(), RegistryError> {
        let record = self.current(owner).await?;
        if record.record.encryption_node.as_deref() == Some(&self.node) {
            Ok(())
        } else {
            Err(RegistryError::Denied)
        }
    }

    /// Select only locally served data spaces for registration. The original
    /// signed grant is retained as proof; unserved spaces have no activation.
    pub async fn registration_spaces(
        &self,
        caps: &[Capability],
    ) -> Result<HashSet<SpaceId>, RegistryError> {
        let mut records = HashMap::new();
        let mut spaces = HashSet::new();
        let mut served = false;
        for cap in caps {
            let owner = match &cap.resource {
                Resource::TinyCloud(resource) => resource.space().did().as_str().to_owned(),
                Resource::Other(uri) if uri.as_str().starts_with("urn:tinycloud:encryption:") => {
                    crate::encryption_network::key_id::parse(uri.as_str())
                        .map_err(|_| RegistryError::Denied)?
                        .owner_did()
                        .to_owned()
                }
                _ => continue,
            };
            let key = owner_key(&owner, false)?;
            if !records.contains_key(&key) {
                records.insert(key.clone(), self.current(&owner).await?);
            }
            let record = &records[&key];
            if let Some(space) = cap.resource.space() {
                if record.allows_space(space, &self.node, false) {
                    spaces.insert(space.clone());
                    served = true;
                }
            } else if record.record.encryption_node.as_deref() == Some(&self.node) {
                served = true;
            }
        }
        if served {
            Ok(spaces)
        } else {
            Err(RegistryError::Denied)
        }
    }

    /// Every requested data/encryption action must be served here. A grant's
    /// broad authority never broadens this node's signed membership or mode.
    pub async fn authorize_capabilities(&self, caps: &[Capability]) -> Result<(), RegistryError> {
        let mut records = HashMap::new();
        for cap in caps {
            let owner = match &cap.resource {
                Resource::TinyCloud(resource) => resource.space().did().as_str().to_owned(),
                Resource::Other(uri) if uri.as_str().starts_with("urn:tinycloud:encryption:") => {
                    crate::encryption_network::key_id::parse(uri.as_str())
                        .map_err(|_| RegistryError::Denied)?
                        .owner_did()
                        .to_owned()
                }
                _ => continue,
            };
            let key = owner_key(&owner, false)?;
            if !records.contains_key(&key) {
                records.insert(key.clone(), self.current(&owner).await?);
            }
            let record = &records[&key];
            let allowed = if let Some(space) = cap.resource.space() {
                let read = matches!(
                    cap.ability.as_ref().as_ref(),
                    "tinycloud.kv/get"
                        | "tinycloud.kv/list"
                        | "tinycloud.kv/metadata"
                        | "tinycloud.kv/sync"
                        | "tinycloud.sql/read"
                        | "tinycloud.sql/select"
                        | "tinycloud.sql/export"
                        | "tinycloud.duckdb/read"
                        | "tinycloud.duckdb/select"
                        | "tinycloud.duckdb/export"
                        | "tinycloud.space/info"
                        | "tinycloud.capabilities/read"
                        | "tinycloud.capabilities/list"
                        | "tinycloud.hooks/list"
                        | "tinycloud.hooks/subscribe"
                );
                record.allows_space(space, &self.node, !read)
            } else {
                record.record.encryption_node.as_deref() == Some(&self.node)
            };
            if !allowed {
                return Err(RegistryError::Denied);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn frozen_owner_signatures_and_memberships() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/registry-v2.json")).unwrap();
        for case in fixture["records"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let expected = &case["expected"];
            let bytes = serde_json::to_vec(&case["record"]).unwrap();
            let result = VerifiedRecord::parse(&bytes);
            let valid = expected["schemaValid"] == true && expected["signatureValid"] == true;
            assert_eq!(result.is_ok(), valid, "{id}: {result:?}");
            let Ok(record) = result else { continue };
            assert_eq!(
                record.payload,
                case["canonicalPayload"].as_str().unwrap().as_bytes(),
                "{id}"
            );
            assert_eq!(
                record.owner_key,
                expected["lookupKey"].as_str().unwrap(),
                "{id}"
            );
            for check in expected["admission"].as_array().into_iter().flatten() {
                let node = check["nodeDid"].as_str().unwrap();
                let resource = check["resource"].as_str().unwrap();
                let allowed = if resource.starts_with("urn:") {
                    record.record.encryption_node.as_deref() == Some(node)
                } else {
                    record.allows_space(
                        &resource.parse().unwrap(),
                        node,
                        check["action"] == "write",
                    )
                };
                assert_eq!(allowed, check["allowed"] == true, "{id}: {check}");
            }
        }
    }

    #[test]
    fn rejects_duplicate_keys_and_nested_unknown_fields() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/registry-v2.json")).unwrap();
        let record = &fixture["records"][0]["record"];
        let encoded = serde_json::to_string(record).unwrap();
        let duplicate = encoded.replacen("\"version\":2", "\"version\":2,\"version\":2", 1);
        assert!(VerifiedRecord::parse(duplicate.as_bytes()).is_err());
        for pointer in ["/nodes/0", "/spaces/0", "/spaces/0/nodes/0"] {
            let mut malformed = record.clone();
            malformed.pointer_mut(pointer).unwrap()["extra"] = Value::Bool(true);
            assert!(VerifiedRecord::parse(&serde_json::to_vec(&malformed).unwrap()).is_err());
        }
    }
}
