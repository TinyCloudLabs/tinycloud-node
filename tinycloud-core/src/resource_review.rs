//! Cryptographic review evidence only. Acceptance additionally requires a fresh
//! protected-ledger read and atomic one-use consumption with the durable fence.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
#[derive(Debug, thiserror::Error)]
#[error("invalid or unavailable resource review evidence")]
pub struct ReviewError;

/// Raw URNs and consumer identities never appear in these signed rows.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRow(pub String, pub u64, pub String, pub String);
#[derive(Clone, Serialize, Deserialize)]
pub struct HostRow(
    pub String,
    pub String,
    pub u64,
    pub Vec<String>,
    pub Vec<TargetRow>,
);
#[derive(Serialize, Deserialize)]
struct DecisionPayload(
    u8,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    Vec<HostRow>,
    i64,
);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionEnvelope {
    payload: DecisionPayload,
    signature: String,
}
#[derive(Serialize, Deserialize)]
struct RevocationPayload(
    u8,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationEnvelope {
    payload: RevocationPayload,
    signature: String,
}

pub struct ReviewVerifier {
    /// Exactly the current key per writer; old keys are not new authority.
    writers: BTreeMap<(String, String), VerifyingKey>,
    operators: BTreeMap<(String, String), VerifyingKey>,
    revoked: BTreeSet<(String, String)>,
}
pub struct ReviewExpectation<'a> {
    pub host_id: &'a str,
    pub owner_hmac: &'a str,
    pub target: &'a TargetRow,
    pub authoritative_hosts: &'a BTreeSet<String>,
}
/// Not sufficient for acceptance by itself: consume once in the acceptance TX.
pub struct VerifiedDecision {
    decision_id: String,
    job_id: String,
    canonical_payload: Vec<u8>,
}
impl VerifiedDecision {
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|id| id.hyphenated().to_string() == s)
}
fn text(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_control)
}
fn sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}
fn canonical<T: Serialize>(payload: &T) -> Result<Vec<u8>, ReviewError> {
    serde_jcs::to_vec(payload).map_err(|_| ReviewError)
}
fn verify<T: Serialize>(
    key: &VerifyingKey,
    domain: &[u8],
    payload: &T,
    raw_signature: &str,
) -> Result<Vec<u8>, ReviewError> {
    let canonical = canonical(payload)?;
    let signature = URL_SAFE_NO_PAD
        .decode(raw_signature)
        .map_err(|_| ReviewError)?;
    if URL_SAFE_NO_PAD.encode(&signature) != raw_signature {
        return Err(ReviewError);
    }
    let signature = Signature::from_slice(&signature).map_err(|_| ReviewError)?;
    let mut message = domain.to_vec();
    message.extend_from_slice(&canonical);
    key.verify_strict(&message, &signature)
        .map_err(|_| ReviewError)?;
    Ok(canonical)
}
impl ReviewVerifier {
    pub fn new(
        writers: BTreeMap<(String, String), [u8; 32]>,
        operators: BTreeMap<(String, String), [u8; 32]>,
        revoked: BTreeSet<(String, String)>,
    ) -> Result<Self, ReviewError> {
        fn keys(
            raw: BTreeMap<(String, String), [u8; 32]>,
        ) -> Result<BTreeMap<(String, String), VerifyingKey>, ReviewError> {
            raw.into_iter()
                .map(|((writer, key), bytes)| {
                    if !name(&writer) || !name(&key) {
                        return Err(ReviewError);
                    }
                    Ok((
                        (writer, key),
                        VerifyingKey::from_bytes(&bytes).map_err(|_| ReviewError)?,
                    ))
                })
                .collect()
        }
        let writers = keys(writers)?;
        let operators = keys(operators)?;
        if writers.is_empty()
            || operators.is_empty()
            || writers
                .values()
                .any(|writer| operators.values().any(|operator| writer == operator))
        {
            return Err(ReviewError);
        }
        let mut seen = BTreeSet::new();
        if writers.keys().any(|(writer, _)| !seen.insert(writer)) {
            return Err(ReviewError);
        }
        Ok(Self {
            writers,
            operators,
            revoked,
        })
    }
    /// `revocation_records` must come from a complete, current protected-ledger
    /// enumeration in this acceptance/check sequence; I/O failure is not empty.
    pub fn verify_decision(
        &self,
        raw: &[u8],
        revocation_records: &[Vec<u8>],
        expected: &ReviewExpectation<'_>,
        now: i64,
    ) -> Result<VerifiedDecision, ReviewError> {
        if raw.len() > 1_048_576 || now < 0 {
            return Err(ReviewError);
        }
        let envelope: DecisionEnvelope = serde_json::from_slice(raw).map_err(|_| ReviewError)?;
        let p = &envelope.payload;
        if p.0 != 1
            || !name(&p.1)
            || !name(&p.2)
            || !uuid(&p.3)
            || !uuid(&p.4)
            || p.5 != expected.host_id
            || p.6 != expected.owner_hmac
            || p.7 != expected.target.0
            || !digest(&p.6)
            || !digest(&p.7)
            || p.8 != "proceed"
            || !text(&p.9)
            || !text(&p.11)
            || p.10 < 0
            || p.10 > now
            || p.14 <= now
            || p.14 <= p.10
            || p.14 - p.10 > 172800
            || p.14 as u64 > MAX_SAFE_INTEGER
            || !digest(&p.12)
        {
            return Err(ReviewError);
        }
        let writer = (p.1.clone(), p.2.clone());
        if self.revoked.contains(&writer) {
            return Err(ReviewError);
        }
        for raw in revocation_records {
            if raw.len() > 65_536 {
                return Err(ReviewError);
            }
            let revocation: RevocationEnvelope =
                serde_json::from_slice(raw).map_err(|_| ReviewError)?;
            let r = &revocation.payload;
            let operator = self
                .operators
                .get(&(r.1.clone(), r.2.clone()))
                .ok_or(ReviewError)?;
            if r.0 != 1 || !uuid(&r.3) || r.7 < 0 || r.7 > now || r.7 as u64 > MAX_SAFE_INTEGER {
                return Err(ReviewError);
            }
            verify(
                operator,
                b"tinycloud-resource-review-revocation-v1\0",
                r,
                &revocation.signature,
            )?;
            match (r.4.as_str(), r.5.as_ref(), r.6.as_ref()) {
                ("all", None, None) => return Err(ReviewError),
                ("writer_key", Some(id), Some(key)) if name(id) && name(key) => {
                    if (&writer.0, &writer.1) == (id, key) {
                        return Err(ReviewError);
                    }
                }
                _ => return Err(ReviewError),
            }
        }
        let mut hosts = BTreeSet::new();
        let mut last_host: Option<&str> = None;
        let mut found = false;
        for row in &p.13 {
            if !name(&row.0)
                || row.0.len() > 63
                || !digest(&row.1)
                || row.2 > MAX_SAFE_INTEGER
                || row.2 != row.3.len() as u64
                || !sorted(&row.3)
                || row.3.iter().any(|h| !digest(h))
                || last_host.is_some_and(|last| last >= row.0.as_str())
            {
                return Err(ReviewError);
            }
            last_host = Some(&row.0);
            hosts.insert(row.0.clone());
            let mut last: Option<&str> = None;
            for target in &row.4 {
                if !digest(&target.0)
                    || target.1 > MAX_SAFE_INTEGER
                    || !digest(&target.2)
                    || !name(&target.3)
                    || last.is_some_and(|last| last >= target.0.as_str())
                {
                    return Err(ReviewError);
                }
                last = Some(&target.0);
                if row.0 == expected.host_id && target.0 == expected.target.0 {
                    if row.1 != expected.owner_hmac || target != expected.target {
                        return Err(ReviewError);
                    }
                    found = true;
                }
            }
            let resources: Vec<_> = row
                .4
                .iter()
                .filter(|target| target.1 > 0)
                .map(|target| target.0.clone())
                .collect();
            if resources != row.3 {
                return Err(ReviewError);
            }
        }
        if !found || &hosts != expected.authoritative_hosts {
            return Err(ReviewError);
        }
        let hash = hex::encode(Sha256::digest(canonical(&(1, &p.13))?));
        if hash != p.12 {
            return Err(ReviewError);
        }
        let key = self.writers.get(&writer).ok_or(ReviewError)?;
        let bytes = verify(
            key,
            b"tinycloud-resource-review-decision-v1\0",
            p,
            &envelope.signature,
        )?;
        Ok(VerifiedDecision {
            decision_id: p.3.clone(),
            job_id: p.4.clone(),
            canonical_payload: bytes,
        })
    }
}
