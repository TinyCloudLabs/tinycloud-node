//! Owner-signed registry v2 hosting authorization. Details: TC-2481.

use crate::{types::Resource, util::Capability};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tinycloud_auth::{
    identity::{canonicalize_did, parse_pkh_did},
    resource::SpaceId,
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Longest outage window the record cache may be configured to (Sam: "~5 min max").
pub const MAX_OUTAGE_CACHE: Duration = Duration::from_secs(300);

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

/// What the node holds about one owner between requests.
#[derive(Debug)]
struct OwnerState {
    /// Highest accepted sequence and its payload digest: rollback memory, never lowered.
    sequence: u64,
    digest: [u8; 32],
    /// The record and the instant its lookup started, from the last successful
    /// confirmation; kept only while the outage cache is on.
    confirmed: Option<(Arc<VerifiedRecord>, Instant)>,
}

/// How one registry lookup ended.
enum Lookup {
    Record(Box<VerifiedRecord>),
    /// The registry could not be reached or answered 502/503/504: an outage.
    Outage,
    /// Any other answer, including absence and an invalid or older record.
    Refused(RegistryError),
}

/// Fetches and verifies the current owner record. Callers never supply a
/// record. With the outage cache on, the last successfully confirmed record
/// stands in for the registry only while the registry is unreachable, and only
/// for less than `outage_cache` after that confirmation began.
#[derive(Debug)]
pub struct RegistryAdmission {
    base: reqwest::Url,
    node: String,
    client: reqwest::Client,
    owners: Mutex<HashMap<String, OwnerState>>,
    outage_cache: Duration,
    /// Bumped by every refused lookup. A confirmation arms the cache only if no
    /// lookup was refused while it was in flight, so a late answer cannot undo
    /// a newer refusal.
    refusals: AtomicU64,
    #[cfg(feature = "test-util")]
    clock_offset: Mutex<Duration>,
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
            owners: Mutex::new(HashMap::new()),
            outage_cache: Duration::ZERO,
            refusals: AtomicU64::new(0),
            #[cfg(feature = "test-util")]
            clock_offset: Mutex::new(Duration::ZERO),
        })
    }

    /// While the registry is unreachable, keep admitting reads and writes from
    /// the last confirmed record for less than `window` after that confirmation
    /// began. Zero (the default) turns the cache off. At most [`MAX_OUTAGE_CACHE`].
    pub fn with_outage_cache(mut self, window: Duration) -> Result<Self, RegistryError> {
        if window > MAX_OUTAGE_CACHE {
            return Err(RegistryError::Unavailable);
        }
        self.outage_cache = window;
        Ok(self)
    }

    /// Move this instance's monotonic clock forward, for outage-window tests.
    #[cfg(feature = "test-util")]
    pub fn advance_clock(&self, by: Duration) {
        *self.clock_offset.lock().unwrap() += by;
    }

    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(feature = "test-util")]
        let now = now + *self.clock_offset.lock().unwrap();
        now
    }

    async fn lookup(&self, key: &str) -> Lookup {
        let mut url = self.base.clone();
        match url.path_segments_mut() {
            Ok(mut segments) => {
                segments.extend(["v2", "locations", key]);
            }
            Err(()) => return Lookup::Refused(RegistryError::Unavailable),
        }
        // A lookup that an HTTP cache in between answers with a stale record
        // would restart the outage lease from it: ask for the origin's answer.
        let Ok(mut response) = self
            .client
            .get(url)
            .header(reqwest::header::CACHE_CONTROL, "no-cache")
            .send()
            .await
        else {
            return Lookup::Outage;
        };
        match response.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT => return Lookup::Outage,
            reqwest::StatusCode::NOT_FOUND => {
                // Absence of an owner this node accepted before is not a clean
                // "not hosted here".
                let known = self
                    .owners
                    .lock()
                    .map_or(true, |owners| owners.contains_key(key));
                return Lookup::Refused(if known {
                    RegistryError::Unavailable
                } else {
                    RegistryError::Denied
                });
            }
            _ => return Lookup::Refused(RegistryError::Unavailable),
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BYTES as u64)
        {
            return Lookup::Refused(RegistryError::Unavailable);
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_BYTES => {
                    body.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                Ok(Some(_)) | Err(_) => return Lookup::Refused(RegistryError::Unavailable),
            }
        }
        let Ok(response) = serde_json::from_slice::<Response>(&body) else {
            return Lookup::Refused(RegistryError::Unavailable);
        };
        match VerifiedRecord::verify(response.record) {
            Ok(record) if record.owner_key == key => Lookup::Record(Box::new(record)),
            Ok(_) => Lookup::Refused(RegistryError::Unavailable),
            Err(error) => Lookup::Refused(error),
        }
    }

    /// The owner's current record. With `cached`, an outage falls back to the
    /// last confirmation while it is younger than the configured window.
    async fn current(
        &self,
        owner: &str,
        cached: bool,
    ) -> Result<Arc<VerifiedRecord>, RegistryError> {
        let key = owner_key(owner, false)?;
        let started = self.now();
        let refusals = self.refusals.load(Ordering::SeqCst);
        let lookup = self.lookup(&key).await;
        let mut owners = self.owners.lock().map_err(|_| RegistryError::Unavailable)?;
        let error = match lookup {
            Lookup::Record(record) => {
                let digest: [u8; 32] = sha2::Sha256::digest(&record.payload).into();
                let sequence = record.record.sequence;
                match owners.get_mut(&key) {
                    Some(state)
                        if sequence < state.sequence
                            || (sequence == state.sequence && state.digest != digest) =>
                    {
                        RegistryError::Unavailable
                    }
                    state => {
                        let record = Arc::<VerifiedRecord>::from(record);
                        let confirmed = (!self.outage_cache.is_zero()
                            && self.refusals.load(Ordering::SeqCst) == refusals)
                            .then(|| (record.clone(), started));
                        match state {
                            Some(state) => {
                                state.sequence = sequence;
                                state.digest = digest;
                                if confirmed.is_some() {
                                    state.confirmed = confirmed;
                                }
                            }
                            None => {
                                owners.insert(
                                    key,
                                    OwnerState {
                                        sequence,
                                        digest,
                                        confirmed,
                                    },
                                );
                            }
                        }
                        return Ok(record);
                    }
                }
            }
            Lookup::Outage => {
                let now = self.now();
                return owners
                    .get(&key)
                    .and_then(|state| state.confirmed.as_ref())
                    .filter(|(_, at)| {
                        cached && now.saturating_duration_since(*at) < self.outage_cache
                    })
                    .map(|(record, _)| record.clone())
                    .ok_or(RegistryError::Unavailable);
            }
            Lookup::Refused(error) => error,
        };
        // A refusal ends any use of the cached record; rollback memory stays.
        self.refusals.fetch_add(1, Ordering::SeqCst);
        if let Some(state) = owners.get_mut(&key) {
            state.confirmed = None;
        }
        Err(error)
    }

    /// Check a data resource, including public and ticket-authorized reads.
    pub async fn authorize_space(&self, space: &SpaceId, write: bool) -> Result<(), RegistryError> {
        let record = self.current(space.did().as_str(), true).await?;
        if record.allows_space(space, &self.node, write) {
            Ok(())
        } else {
            Err(RegistryError::Denied)
        }
    }

    /// Check a raw encryption network independently from data membership.
    pub async fn authorize_encryption(&self, owner: &str) -> Result<(), RegistryError> {
        let record = self.current(owner, true).await?;
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
                // Activating a replica for a new grant always needs the registry itself.
                records.insert(key.clone(), self.current(&owner, false).await?);
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
    ///
    /// One exception: the owner admits a threshold member (`member.admit` on
    /// a network URN) on any node, because a threshold network's members are
    /// not its 1-of-1 encryption node. The owner's current record must still
    /// exist.
    pub async fn authorize_capabilities(&self, caps: &[Capability]) -> Result<(), RegistryError> {
        use crate::encryption_network::{
            key_id::{self, EncryptionResource},
            protocol::MEMBER_ADMIT_ACTION,
        };
        let mut records = HashMap::new();
        for cap in caps {
            let mut member_admit = false;
            let owner = match &cap.resource {
                Resource::TinyCloud(resource) => resource.space().did().as_str().to_owned(),
                Resource::Other(uri) if uri.as_str().starts_with("urn:tinycloud:encryption:") => {
                    let resource =
                        key_id::parse(uri.as_str()).map_err(|_| RegistryError::Denied)?;
                    member_admit = cap.ability.as_ref().as_ref() == MEMBER_ADMIT_ACTION
                        && matches!(resource, EncryptionResource::Network(_));
                    resource.owner_did().to_owned()
                }
                _ => continue,
            };
            let key = owner_key(&owner, false)?;
            if !records.contains_key(&key) {
                records.insert(key.clone(), self.current(&owner, true).await?);
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
                member_admit || record.record.encryption_node.as_deref() == Some(&self.node)
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

    /// One scripted reply of the fake registry: an optional gate it waits on
    /// before answering, the status and the body.
    type Script = (Option<tokio::sync::oneshot::Receiver<()>>, u16, Vec<u8>);

    /// A fake registry that answers each connection with the next script, and
    /// reports each request as soon as it has read it.
    async fn scripted() -> (
        String,
        tokio::sync::mpsc::UnboundedSender<Script>,
        tokio::sync::mpsc::UnboundedReceiver<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Script>();
        let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let (gate, status, body) = rx.recv().await.unwrap();
                let seen = seen_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ = sock.read(&mut buf).await;
                    let _ = seen.send(());
                    if let Some(gate) = gate {
                        let _ = gate.await;
                    }
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        (origin, tx, seen_rx)
    }

    /// The fixture's first record: its owner, its node and a lookup body.
    fn first_record() -> (String, String, Vec<u8>) {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/registry-v2.json")).unwrap();
        let record = &fixture["records"][0]["record"];
        let body = serde_json::to_vec(&serde_json::json!({ "record": record })).unwrap();
        (
            record["subject"].as_str().unwrap().to_owned(),
            record["nodes"][0]["did"].as_str().unwrap().to_owned(),
            body,
        )
    }

    /// A confirmation whose lookup was in flight when a refusal for the same
    /// owner landed must not re-arm the outage cache: the withdrawn owner is
    /// not served from it.
    #[tokio::test]
    async fn a_success_that_lands_after_a_refusal_does_not_rearm_the_cache() {
        let (owner, node, body) = first_record();
        let (origin, script, mut seen) = scripted().await;
        let registry = Arc::new(
            RegistryAdmission::new(&origin, node)
                .unwrap()
                .with_outage_cache(Duration::from_secs(300))
                .unwrap(),
        );
        // Armed by a confirmation.
        script.send((None, 200, body.clone())).unwrap();
        registry.current(&owner, true).await.unwrap();
        seen.recv().await.unwrap();
        // A: a confirmation held in flight.
        let (release, gate) = tokio::sync::oneshot::channel();
        script.send((Some(gate), 200, body.clone())).unwrap();
        let a = tokio::spawn({
            let registry = registry.clone();
            let owner = owner.clone();
            async move { registry.current(&owner, true).await.map(|_| ()) }
        });
        seen.recv().await.unwrap();
        // B: the owner is withdrawn (404) while A is in flight.
        script.send((None, 404, b"{}".to_vec())).unwrap();
        assert_eq!(
            registry.current(&owner, true).await.unwrap_err(),
            RegistryError::Unavailable
        );
        seen.recv().await.unwrap();
        // A's stale confirmation lands after the refusal.
        release.send(()).unwrap();
        a.await.unwrap().unwrap();
        // C: an outage. The withdrawn owner is not served from the cache.
        script.send((None, 503, Vec::new())).unwrap();
        assert_eq!(
            registry.current(&owner, true).await.unwrap_err(),
            RegistryError::Unavailable
        );
    }

    /// `member.admit` on a network URN is served on any node of an owner
    /// with a current record; every other encryption action only on the
    /// record's encryption node.
    #[tokio::test]
    async fn member_admit_is_served_off_the_encryption_node() {
        use crate::encryption_network::{
            protocol::{MEMBER_ADMIT_ACTION, NETWORK_CREATE_ACTION},
            NetworkId,
        };
        let (owner, node, body) = first_record();
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/registry-v2.json")).unwrap();
        let encryption_node = fixture["records"][0]["record"]["encryptionNode"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(node, encryption_node);
        let network = NetworkId::new(owner, "vault").unwrap().to_string();
        let cap = |resource: &str, ability: &str| Capability {
            resource: resource.parse().unwrap(),
            ability: crate::types::Ability::try_from(ability.to_string()).unwrap(),
            caveats: Default::default(),
        };
        let (origin, script, _seen) = scripted().await;
        let member = RegistryAdmission::new(&origin, node).unwrap();

        script.send((None, 200, body.clone())).unwrap();
        member
            .authorize_capabilities(&[cap(&network, MEMBER_ADMIT_ACTION)])
            .await
            .unwrap();
        // Any other ability, or member.admit on a key, needs the encryption node.
        script.send((None, 200, body.clone())).unwrap();
        assert_eq!(
            member
                .authorize_capabilities(&[cap(&network, NETWORK_CREATE_ACTION)])
                .await
                .unwrap_err(),
            RegistryError::Denied
        );
        script.send((None, 200, body.clone())).unwrap();
        assert_eq!(
            member
                .authorize_capabilities(&[cap(&format!("{network}/docs/a"), MEMBER_ADMIT_ACTION)])
                .await
                .unwrap_err(),
            RegistryError::Denied
        );
        // Without a current owner record, member.admit is refused too.
        script.send((None, 404, b"{}".to_vec())).unwrap();
        assert!(member
            .authorize_capabilities(&[cap(&network, MEMBER_ADMIT_ACTION)])
            .await
            .is_err());

        let primary = RegistryAdmission::new(&origin, encryption_node).unwrap();
        script.send((None, 200, body)).unwrap();
        primary
            .authorize_capabilities(&[cap(&network, NETWORK_CREATE_ACTION)])
            .await
            .unwrap();
    }
}
