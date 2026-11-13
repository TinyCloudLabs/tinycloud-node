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
/// Typed HTTP carrier: deriving this directly rejects duplicate fields before
/// any intermediary JSON value can discard them. It is not verified authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionProof {
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
impl DecisionProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ReviewError> {
        serde_json::to_vec(self).map_err(|_| ReviewError)
    }
}

pub struct ReviewVerifier {
    /// Retained public keys; only the explicitly current key is new authority.
    writers: BTreeMap<(String, String), VerifyingKey>,
    current_keys: BTreeMap<String, String>,
    operators: BTreeMap<(String, String), VerifyingKey>,
    revoked: BTreeSet<(String, String)>,
}
pub struct ReviewExpectation<'a> {
    pub job_id: &'a str,
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
    authenticated_body: Vec<u8>,
    expires_at: i64,
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
    pub fn authenticated_body(&self) -> &[u8] {
        &self.authenticated_body
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
        let mut current = BTreeMap::new();
        for (writer, key) in writers.keys() {
            if current.insert(writer.clone(), key.clone()).is_some() {
                return Err(ReviewError);
            }
        }
        Self::with_history(writers, current, operators, revoked)
    }
    pub fn with_history(
        writers: BTreeMap<(String, String), [u8; 32]>,
        current_keys: BTreeMap<String, String>,
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
        let writer_ids: BTreeSet<_> = writers.keys().map(|(writer, _)| writer.as_str()).collect();
        if current_keys.len() != writer_ids.len()
            || current_keys
                .iter()
                .any(|(writer, key)| !writers.contains_key(&(writer.clone(), key.clone())))
        {
            return Err(ReviewError);
        }
        Ok(Self {
            writers,
            current_keys,
            operators,
            revoked,
        })
    }
    /// Audit signature verification with retained historical public keys.
    /// Returns no acceptance authority; current-key, revocation, binding and
    /// expiry checks are mandatory through verify_decision before any action.
    pub fn verify_retained_signature(&self, raw: &[u8]) -> Result<(), ReviewError> {
        if raw.len() > 1_048_576 {
            return Err(ReviewError);
        }
        let envelope: DecisionProof = serde_json::from_slice(raw).map_err(|_| ReviewError)?;
        let p = &envelope.payload;
        if p.0 != 1 || !name(&p.1) || !name(&p.2) || !uuid(&p.3) || !uuid(&p.4) {
            return Err(ReviewError);
        }
        let key = self
            .writers
            .get(&(p.1.clone(), p.2.clone()))
            .ok_or(ReviewError)?;
        verify(
            key,
            b"tinycloud-resource-review-decision-v1\0",
            p,
            &envelope.signature,
        )?;
        Ok(())
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
        let envelope: DecisionProof = serde_json::from_slice(raw).map_err(|_| ReviewError)?;
        let p = &envelope.payload;
        if p.0 != 1
            || !name(&p.1)
            || !name(&p.2)
            || !uuid(&p.3)
            || !uuid(&p.4)
            || p.4 != expected.job_id
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
        if self.revoked.contains(&writer) || self.current_keys.get(&p.1) != Some(&p.2) {
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
            authenticated_body: raw.to_vec(),
            expires_at: p.14,
        })
    }
}

/// Consume in the SAME acceptance transaction as the fence, job and signed
/// ledger-copy row. A matching original purge can resume but never spend twice.
pub async fn consume(
    tx: &crate::sea_orm::DatabaseTransaction,
    proof: &VerifiedDecision,
    purge_id: &str,
    now: time::OffsetDateTime,
) -> Result<ReviewUse, crate::sea_orm::DbErr> {
    use crate::sea_orm::sea_query::OnConflict;
    use crate::{
        models::resource_review_consumption as used,
        sea_orm::{ActiveValue::Set, EntityTrait},
    };
    if !uuid(purge_id) || now.unix_timestamp() >= proof.expires_at {
        return Err(crate::sea_orm::DbErr::Custom(
            "invalid review consumption".into(),
        ));
    }
    let result = used::Entity::insert(used::ActiveModel {
        decision_id: Set(proof.decision_id.clone()),
        purge_id: Set(purge_id.into()),
        authenticated_body: Set(proof.authenticated_body.clone()),
        consumed_at: Set(now),
    })
    .on_conflict(OnConflict::new().do_nothing().to_owned())
    .do_nothing()
    .exec(tx)
    .await?;
    let row = used::Entity::find_by_id(&proof.decision_id)
        .one(tx)
        .await?
        .ok_or_else(|| crate::sea_orm::DbErr::Custom("conflicting review consumption".into()))?;
    // Compare canonical parsed payloads so carrier whitespace cannot rebind a
    // decision. Stored bytes remain signed evidence for subsequent rechecking.
    let stored: DecisionProof = serde_json::from_slice(&row.authenticated_body)
        .map_err(|_| crate::sea_orm::DbErr::Custom("invalid stored review evidence".into()))?;
    let current: DecisionProof = serde_json::from_slice(&proof.authenticated_body)
        .map_err(|_| crate::sea_orm::DbErr::Custom("invalid review evidence".into()))?;
    if row.purge_id != purge_id
        || stored.signature != current.signature
        || canonical(&stored.payload)
            .map_err(|_| crate::sea_orm::DbErr::Custom("invalid stored review evidence".into()))?
            != proof.canonical_payload
    {
        return Err(crate::sea_orm::DbErr::Custom(
            "review decision already consumed".into(),
        ));
    }
    Ok(match result {
        crate::sea_orm::TryInsertResult::Inserted(_) => ReviewUse::Fresh,
        _ => ReviewUse::OriginalPurge,
    })
}
#[derive(Debug, PartialEq, Eq)]
pub enum ReviewUse {
    Fresh,
    OriginalPurge,
}
