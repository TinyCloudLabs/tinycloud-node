//! Policy-enforcement v1 authority kernel.
//!
//! This module intentionally owns no HTTP, evaluator, credential-verifier, or
//! attestation implementation. Those trust boundaries must produce the opaque
//! verified inputs below. The kernel owns the authorization graph equations,
//! attenuation rules, revocation traversal, and atomic persistence contract.

mod database;
mod verifier;

pub use database::{DatabaseAuthorityKernel, DatabaseAuthorityStore};
pub use verifier::{AuthorityArtifactVerifier, ConfiguredNodeRootSigner, NodeRootSigner};

use crate::policy_capability::{
    parse as parse_capability, requested_capabilities_hash_hex, PolicyCapability,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use unicode_normalization::UnicodeNormalization;

const POLICY_PREFIX: &str = "xyz.tinycloud.policy/";
const MAX_STATUS_AGE_SECONDS: i64 = 300;
const MAX_ANCESTRY_DEPTH: usize = 64;
const DECISION_CONTEXT_DOMAIN: &[u8] = b"xyz.tinycloud.policy/DecisionContext/v1\0";
const ISSUANCE_AUDIT_DOMAIN: &[u8] = b"xyz.tinycloud.policy/IssuanceAudit/v1\0";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const EIP191_SUITE: &str = "eip191-secp256k1-sha256-jcs-v1";
const ED25519_SUITE: &str = "eddsa-ed25519-sha256-jcs-v1";
const AUTHORITY_FACTS: &[&str] = &[
    "ownerDid",
    "policyId",
    "policyDigestHex",
    "capabilityCeilingHashHex",
];
const ENFORCEMENT_FACTS: &[&str] = &[
    "ownerDid",
    "policyId",
    "policyDigestHex",
    "capabilityCeilingHashHex",
    "enforcerDid",
    "nodeAudience",
    "attestationBindingDigestHex",
    "maxSessionTtlSeconds",
    "sessionMode",
    "maxRedelegationDepth",
    "auditProfile",
];
const SESSION_FACTS: &[&str] = &[
    "ownerDid",
    "policyId",
    "policyDigestHex",
    "capabilityCeilingHashHex",
    "capabilityHashHex",
    "enforcerDid",
    "nodeAudience",
    "rootClaimantDid",
    "sessionSubjectDid",
    "policyDelegationCid",
    "enforcementDelegationCid",
    "attestationBindingDigestHex",
    "claimInvocationDigestHex",
    "vpDigestHex",
    "decisionContextDigestHex",
    "issuanceAuditDigestHex",
    "issuanceId",
    "remainingRedelegationDepth",
    "auditProfile",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DelegationRole {
    PolicyAuthority,
    PolicyEnforcement,
    PolicySessionRoot,
    PolicySessionDescendant,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DelegationMode {
    PolicySource,
    ConditionalMint,
    Attenuable,
    Terminal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DelegationSignature {
    pub suite: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyDelegation {
    pub schema: String,
    pub role: DelegationRole,
    pub delegation_cid: String,
    pub issuer_did: String,
    pub audience_did: String,
    pub capabilities: Vec<Value>,
    pub proof_cids: Vec<String>,
    pub not_before: String,
    pub expires_at: String,
    pub delegation_mode: DelegationMode,
    pub facts: BTreeMap<String, String>,
    pub signature: DelegationSignature,
}

impl PolicyDelegation {
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let value = strict_json_value(bytes)?;
        let artifact: Self =
            serde_json::from_value(value).map_err(|_| AuthorityError::SchemaInvalid)?;
        artifact.validate_wire_shape()?;
        Ok(artifact)
    }

    fn validate_wire_shape(&self) -> Result<(), AuthorityError> {
        if self.schema != "xyz.tinycloud.policy/enforcement-delegation/v1"
            || self.delegation_cid.is_empty()
            || self.issuer_did.is_empty()
            || self.audience_did.is_empty()
            || self.capabilities.is_empty()
        {
            return Err(AuthorityError::SchemaInvalid);
        }
        canonical_time(&self.not_before)?;
        canonical_time(&self.expires_at)?;
        canonical_capabilities(&self.capabilities)?;
        let unique: HashSet<_> = self.proof_cids.iter().collect();
        if unique.len() != self.proof_cids.len() {
            return Err(AuthorityError::ProofSetUnmatched);
        }
        let (mode_ok, proof_count, mut fact_names, suite) = match self.role {
            DelegationRole::PolicyAuthority => (
                self.delegation_mode == DelegationMode::PolicySource,
                0,
                AUTHORITY_FACTS.to_vec(),
                EIP191_SUITE,
            ),
            DelegationRole::PolicyEnforcement => (
                self.delegation_mode == DelegationMode::ConditionalMint,
                0,
                ENFORCEMENT_FACTS.to_vec(),
                EIP191_SUITE,
            ),
            DelegationRole::PolicySessionRoot => (
                matches!(
                    self.delegation_mode,
                    DelegationMode::Attenuable | DelegationMode::Terminal
                ),
                2,
                SESSION_FACTS.to_vec(),
                ED25519_SUITE,
            ),
            DelegationRole::PolicySessionDescendant => (
                matches!(
                    self.delegation_mode,
                    DelegationMode::Attenuable | DelegationMode::Terminal
                ),
                1,
                SESSION_FACTS.to_vec(),
                ED25519_SUITE,
            ),
        };
        if self.role == DelegationRole::PolicySessionDescendant {
            fact_names.extend(["rootSessionDelegationCid", "immediateParentDelegationCid"]);
        }
        if !mode_ok || self.signature.suite != suite {
            return Err(AuthorityError::RoleModeMismatch);
        }
        if self.proof_cids.len() != proof_count {
            return Err(AuthorityError::ProofSetUnmatched);
        }
        let expected: HashSet<_> = fact_names
            .into_iter()
            .map(|name| format!("{POLICY_PREFIX}{name}"))
            .collect();
        if self.facts.keys().collect::<HashSet<_>>() != expected.iter().collect::<HashSet<_>>() {
            return Err(AuthorityError::FactsMismatch);
        }
        Ok(())
    }

    fn not_before(&self) -> Result<OffsetDateTime, AuthorityError> {
        canonical_time(&self.not_before)
    }

    fn expires_at(&self) -> Result<OffsetDateTime, AuthorityError> {
        canonical_time(&self.expires_at)
    }

    fn fact(&self, name: &'static str) -> Result<&str, AuthorityError> {
        self.facts
            .get(&format!("{POLICY_PREFIX}{name}"))
            .map(String::as_str)
            .ok_or(AuthorityError::FactsMismatch)
    }

    pub(crate) fn fact_value(&self, name: &'static str) -> Result<&str, AuthorityError> {
        self.fact(name)
    }

    fn depth(&self) -> Result<u8, AuthorityError> {
        self.fact("remainingRedelegationDepth")?
            .parse::<u8>()
            .ok()
            .filter(|depth| *depth <= 8)
            .ok_or(AuthorityError::SessionRedelegationInvalid)
    }

    fn capability_hash(&self) -> Result<String, AuthorityError> {
        let caps = canonical_capabilities(&self.capabilities)?;
        Ok(requested_capabilities_hash_hex(&caps))
    }
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("strict I-JSON")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
                    return Err(E::custom("unsafe-integer"));
                }
                Ok(StrictJson(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value > MAX_SAFE_JSON_INTEGER {
                    return Err(E::custom("unsafe-integer"));
                }
                Ok(StrictJson(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if !value.is_finite()
                    || (value.fract() == 0.0 && value.abs() > MAX_SAFE_JSON_INTEGER as f64)
                {
                    return Err(E::custom("unsafe-integer"));
                }
                serde_json::Number::from_f64(value)
                    .map(|number| StrictJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-I-JSON-number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.nfc().ne(value.chars()) {
                    return Err(E::custom("canonicalization-mismatch"));
                }
                Ok(StrictJson(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJson>()? {
                    values.push(value.0);
                }
                Ok(StrictJson(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key.nfc().ne(key.chars()) {
                        return Err(de::Error::custom("canonicalization-mismatch"));
                    }
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("duplicate-json-member"));
                    }
                    object.insert(key, map.next_value::<StrictJson>()?.0);
                }
                Ok(StrictJson(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn strict_json_value(bytes: &[u8]) -> Result<Value, AuthorityError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJson::deserialize(&mut deserializer).map_err(|error| {
        if error.to_string().contains("canonicalization-mismatch") {
            AuthorityError::CanonicalizationMismatch
        } else {
            AuthorityError::SchemaInvalid
        }
    })?;
    deserializer
        .end()
        .map_err(|_| AuthorityError::SchemaInvalid)?;
    Ok(value.0)
}

/// Artifact accepted by a cryptographic verifier. Construction is deliberately
/// unavailable on production code paths until the real verifier adapter lands.
#[derive(Clone, Debug)]
pub struct VerifiedDelegation(PolicyDelegation);

impl VerifiedDelegation {
    pub(crate) fn from_verified(artifact: PolicyDelegation) -> Self {
        Self(artifact)
    }

    pub fn artifact(&self) -> &PolicyDelegation {
        &self.0
    }

    #[cfg(test)]
    fn for_test(artifact: PolicyDelegation) -> Self {
        Self(artifact)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestedEnforcerBinding {
    binding_digest_hex: String,
    enforcer_did: String,
    node_audience: String,
    expires_at: OffsetDateTime,
}

impl VerifiedAttestedEnforcerBinding {
    #[cfg(test)]
    fn for_test(
        binding_digest_hex: impl Into<String>,
        enforcer_did: impl Into<String>,
        node_audience: impl Into<String>,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            binding_digest_hex: binding_digest_hex.into(),
            enforcer_did: enforcer_did.into(),
            node_audience: node_audience.into(),
            expires_at,
        }
    }
}

/// Opaque result of verifying the exact signed policy plus its operational
/// signing-key authorization and current status. Production construction is
/// intentionally reserved for the future verifier/status adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPolicyState {
    owner_did: String,
    policy_id: String,
    policy_digest_hex: String,
    capability_ceiling_hash_hex: String,
    grant_mode: PolicyGrantMode,
    max_ttl_seconds: u64,
    status_checked_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl VerifiedPolicyState {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn for_test(
        owner_did: impl Into<String>,
        policy_id: impl Into<String>,
        policy_digest_hex: impl Into<String>,
        capability_ceiling_hash_hex: impl Into<String>,
        grant_mode: PolicyGrantMode,
        max_ttl_seconds: u64,
        status_checked_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            owner_did: owner_did.into(),
            policy_id: policy_id.into(),
            policy_digest_hex: policy_digest_hex.into(),
            capability_ceiling_hash_hex: capability_ceiling_hash_hex.into(),
            grant_mode,
            max_ttl_seconds,
            status_checked_at,
            expires_at,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyGrantMode {
    Attenuable,
    Terminal,
}

impl PolicyGrantMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attenuable => "attenuable",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecisionContext {
    pub owner_did: String,
    pub policy_id: String,
    pub policy_digest_hex: String,
    pub capability_ceiling_hash_hex: String,
    pub enforcer_did: String,
    pub node_audience: String,
    pub claimant_did: String,
    pub challenge_id: String,
    pub challenge_nonce_hash_hex: String,
    pub requested_capabilities_hash_hex: String,
    pub claim_invocation_digest_hex: String,
    pub vp_digest_hex: String,
}

impl DecisionContext {
    pub fn digest_hex(&self) -> Result<String, AuthorityError> {
        let value = serde_json::to_value(self).map_err(|_| AuthorityError::SchemaInvalid)?;
        let mut digest = Sha256::new();
        digest.update(DECISION_CONTEXT_DOMAIN);
        digest.update(crate::policy_capability::jcs::canonicalize(&value));
        Ok(hex::encode(digest.finalize()))
    }
}

/// Opaque evaluator result. A JSON policy decision has no authority.
#[derive(Clone, Debug)]
pub struct TrustedPolicyDecision {
    context: DecisionContext,
    decision_context_digest_hex: String,
    evaluated_at: OffsetDateTime,
    valid_until: OffsetDateTime,
}

impl TrustedPolicyDecision {
    #[cfg(test)]
    fn allow_for_test(
        context: DecisionContext,
        evaluated_at: OffsetDateTime,
        valid_until: OffsetDateTime,
    ) -> Self {
        let decision_context_digest_hex = context.digest_hex().unwrap();
        Self {
            context,
            decision_context_digest_hex,
            evaluated_at,
            valid_until,
        }
    }
}

/// Opaque verified signed challenge plus its durable consumption state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeState {
    challenge_id: String,
    nonce_hash_hex: String,
    owner_did: String,
    policy_id: String,
    policy_digest_hex: String,
    policy_delegation_cid: String,
    enforcement_delegation_cid: String,
    enforcer_did: String,
    node_audience: String,
    claimant_did: String,
    requested_capabilities_hash_hex: String,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
}

/// Inputs bound by the future claim/challenge verifier adapter. Private fields
/// prevent production callers from fabricating a verified issuance context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceBindings {
    now: OffsetDateTime,
    claim_issued_at: OffsetDateTime,
    claim_expires_at: OffsetDateTime,
    challenge_id: String,
    challenge_nonce_hash_hex: String,
    claimant_did: String,
    requested_capabilities_hash_hex: String,
    claim_invocation_digest_hex: String,
    vp_digest_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssuanceAudit {
    schema: String,
    issuance_id: String,
    owner_did: String,
    policy_id: String,
    policy_digest_hex: String,
    policy_delegation_cid: String,
    enforcement_delegation_cid: String,
    enforcer_did: String,
    node_audience: String,
    claimant_did: String,
    capability_hash_hex: String,
    challenge_id: String,
    challenge_nonce_hash_hex: String,
    claim_invocation_digest_hex: String,
    vp_digest_hex: String,
    decision_context_digest_hex: String,
    decision: String,
    issued_at: String,
    expires_at: String,
    audit_digest_hex: String,
    session_delegation_cid: String,
}

impl IssuanceAudit {
    fn recompute_digest_hex(&self) -> Result<String, AuthorityError> {
        let mut value = serde_json::to_value(self).map_err(|_| AuthorityError::SchemaInvalid)?;
        let object = value.as_object_mut().ok_or(AuthorityError::SchemaInvalid)?;
        object.remove("auditDigestHex");
        object.remove("sessionDelegationCid");
        let mut digest = Sha256::new();
        digest.update(ISSUANCE_AUDIT_DOMAIN);
        digest.update(crate::policy_capability::jcs::canonicalize(&value));
        Ok(hex::encode(digest.finalize()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    Authority,
    Immediate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEdge {
    pub child_cid: String,
    pub parent_cid: String,
    pub kind: EdgeKind,
    pub position: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityStatus {
    checked_at: OffsetDateTime,
    sequence: u64,
    revoked_at: Option<OffsetDateTime>,
}

impl AuthorityStatus {
    #[cfg(test)]
    fn active_for_test(checked_at: OffsetDateTime, sequence: u64) -> Self {
        Self {
            checked_at,
            sequence,
            revoked_at: None,
        }
    }

    #[cfg(test)]
    fn revoked_for_test(checked_at: OffsetDateTime, sequence: u64) -> Self {
        Self {
            checked_at,
            sequence,
            revoked_at: Some(checked_at),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("schema-invalid")]
    SchemaInvalid,
    #[error("canonicalization-mismatch")]
    CanonicalizationMismatch,
    #[error("timestamp-noncanonical")]
    TimestampNoncanonical,
    #[error("capability-noncanonical")]
    CapabilityNoncanonical,
    #[error("proof-set-unmatched")]
    ProofSetUnmatched,
    #[error("role-mode-mismatch")]
    RoleModeMismatch,
    #[error("conditional-mint-not-parent")]
    ConditionalMintNotParent,
    #[error("owner-mismatch")]
    OwnerMismatch,
    #[error("policy-mismatch")]
    PolicyMismatch,
    #[error("facts-mismatch")]
    FactsMismatch,
    #[error("wrong-enforcer")]
    WrongEnforcer,
    #[error("wrong-audience")]
    WrongAudience,
    #[error("claimant-mismatch")]
    ClaimantMismatch,
    #[error("capability-hash-mismatch")]
    CapabilityHashMismatch,
    #[error("capability-broadened")]
    CapabilityBroadened,
    #[error("decision-context-mismatch")]
    DecisionContextMismatch,
    #[error("audit-digest-mismatch")]
    AuditDigestMismatch,
    #[error("policy-decision-expired")]
    PolicyDecisionExpired,
    #[error("attestation-binding-mismatch")]
    AttestationBindingMismatch,
    #[error("attestation-expired")]
    AttestationExpired,
    #[error("challenge-not-found")]
    ChallengeNotFound,
    #[error("challenge-nonce-consumed")]
    ChallengeConsumed,
    #[error("challenge-expired")]
    ChallengeExpired,
    #[error("session-time-invalid")]
    SessionTimeInvalid,
    #[error("session-redelegation-invalid")]
    SessionRedelegationInvalid,
    #[error("terminal-parent-cannot-redelegate")]
    TerminalParent,
    #[error("descendant-parent-mismatch")]
    DescendantParentMismatch,
    #[error("descendant-authority-roots-mismatch")]
    DescendantAuthorityRootsMismatch,
    #[error("authority-state-unavailable")]
    AuthorityStateUnavailable,
    #[error("delegation-revoked")]
    DelegationRevoked,
    #[error("delegation-ancestor-revoked")]
    DelegationAncestorRevoked,
    #[error("ancestry-too-deep")]
    AncestryTooDeep,
    #[error("transaction-failed")]
    TransactionFailed,
}

#[derive(Default)]
struct MemoryState {
    artifacts: HashMap<String, VerifiedDelegation>,
    edges: Vec<VerifiedEdge>,
    challenges: HashMap<String, ChallengeState>,
    audits: HashMap<String, IssuanceAudit>,
    statuses: HashMap<String, AuthorityStatus>,
    fail_next_transaction: bool,
}

/// In-memory reference store for semantic tests. The production SeaORM store
/// must preserve the same single-transaction method boundary.
#[derive(Clone, Default)]
pub struct MemoryAuthorityStore(Arc<Mutex<MemoryState>>);

impl MemoryAuthorityStore {
    pub fn insert_verified_authority(
        &self,
        artifact: VerifiedDelegation,
        status: AuthorityStatus,
    ) -> Result<(), AuthorityError> {
        let mut state = self.0.lock().expect("authority store poisoned");
        if state.artifacts.contains_key(&artifact.0.delegation_cid)
            || state.statuses.contains_key(&artifact.0.delegation_cid)
        {
            return Err(AuthorityError::AuthorityStateUnavailable);
        }
        state
            .statuses
            .insert(artifact.0.delegation_cid.clone(), status);
        state
            .artifacts
            .insert(artifact.0.delegation_cid.clone(), artifact);
        Ok(())
    }

    #[cfg(test)]
    fn replace_verified_authority_for_test(
        &self,
        artifact: VerifiedDelegation,
        status: AuthorityStatus,
    ) {
        let mut state = self.0.lock().expect("authority store poisoned");
        state
            .statuses
            .insert(artifact.0.delegation_cid.clone(), status);
        state
            .artifacts
            .insert(artifact.0.delegation_cid.clone(), artifact);
    }

    pub fn insert_challenge(&self, challenge: ChallengeState) -> Result<(), AuthorityError> {
        validate_challenge_lifetime(&challenge)?;
        let mut state = self.0.lock().expect("authority store poisoned");
        if state.challenges.contains_key(&challenge.challenge_id) {
            return Err(AuthorityError::ChallengeConsumed);
        }
        state
            .challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    #[cfg(test)]
    fn replace_challenge_for_test(&self, challenge: ChallengeState) {
        self.0
            .lock()
            .expect("authority store poisoned")
            .challenges
            .insert(challenge.challenge_id.clone(), challenge);
    }

    pub fn set_status(
        &self,
        cid: impl Into<String>,
        status: AuthorityStatus,
    ) -> Result<(), AuthorityError> {
        let mut state = self.0.lock().expect("authority store poisoned");
        let cid = cid.into();
        let previous = state
            .statuses
            .get(&cid)
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        validate_status_transition(previous, &status)?;
        state.statuses.insert(cid, status);
        Ok(())
    }

    #[cfg(test)]
    fn fail_next_transaction(&self) {
        self.0
            .lock()
            .expect("authority store poisoned")
            .fail_next_transaction = true;
    }

    pub fn challenge(&self, id: &str) -> Option<ChallengeState> {
        self.0
            .lock()
            .expect("authority store poisoned")
            .challenges
            .get(id)
            .cloned()
    }

    pub fn artifact(&self, cid: &str) -> Option<PolicyDelegation> {
        self.0
            .lock()
            .expect("authority store poisoned")
            .artifacts
            .get(cid)
            .map(|value| value.0.clone())
    }

    pub fn edges(&self, cid: &str) -> Vec<VerifiedEdge> {
        self.0
            .lock()
            .expect("authority store poisoned")
            .edges
            .iter()
            .filter(|edge| edge.child_cid == cid)
            .cloned()
            .collect()
    }

    pub fn audit(&self, issuance_id: &str) -> Option<IssuanceAudit> {
        self.0
            .lock()
            .expect("authority store poisoned")
            .audits
            .get(issuance_id)
            .cloned()
    }
}

pub struct AuthorityKernel {
    store: MemoryAuthorityStore,
    running_node_did: String,
}

impl AuthorityKernel {
    pub fn new(store: MemoryAuthorityStore, running_node_did: impl Into<String>) -> Self {
        Self {
            store,
            running_node_did: running_node_did.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_root(
        &self,
        policy_authority: &VerifiedDelegation,
        policy_enforcement: &VerifiedDelegation,
        policy_state: &VerifiedPolicyState,
        root: VerifiedDelegation,
        binding: &VerifiedAttestedEnforcerBinding,
        decision: &TrustedPolicyDecision,
        bindings: &IssuanceBindings,
    ) -> Result<(), AuthorityError> {
        let mut state = self.store.0.lock().expect("authority store poisoned");
        validate_authority_pair(
            &policy_authority.0,
            &policy_enforcement.0,
            policy_state,
            &self.running_node_did,
        )?;
        ensure_live_in_memory(
            &state,
            &policy_authority.0.delegation_cid,
            bindings.now,
            false,
        )?;
        ensure_live_in_memory(
            &state,
            &policy_enforcement.0.delegation_cid,
            bindings.now,
            false,
        )?;
        if state
            .artifacts
            .get(&policy_authority.0.delegation_cid)
            .map(|stored| &stored.0)
            != Some(&policy_authority.0)
            || state
                .artifacts
                .get(&policy_enforcement.0.delegation_cid)
                .map(|stored| &stored.0)
                != Some(&policy_enforcement.0)
        {
            return Err(AuthorityError::AuthorityStateUnavailable);
        }
        let challenge = state
            .challenges
            .get(&bindings.challenge_id)
            .ok_or(AuthorityError::ChallengeNotFound)?;
        if challenge.consumed_at.is_some() {
            return Err(AuthorityError::ChallengeConsumed);
        }
        let audit = validate_root(
            &policy_authority.0,
            &policy_enforcement.0,
            policy_state,
            challenge,
            &root.0,
            binding,
            decision,
            bindings,
            &self.running_node_did,
        )?;
        if state.fail_next_transaction {
            state.fail_next_transaction = false;
            return Err(AuthorityError::TransactionFailed);
        }
        let cid = root.0.delegation_cid.clone();
        let proofs = root.0.proof_cids.clone();
        state.artifacts.insert(cid.clone(), root);
        state.statuses.insert(
            cid.clone(),
            AuthorityStatus {
                checked_at: bindings.now,
                sequence: 0,
                revoked_at: None,
            },
        );
        state.edges.push(VerifiedEdge {
            child_cid: cid.clone(),
            parent_cid: proofs[0].clone(),
            kind: EdgeKind::Authority,
            position: 0,
        });
        state.edges.push(VerifiedEdge {
            child_cid: cid,
            parent_cid: proofs[1].clone(),
            kind: EdgeKind::Authority,
            position: 1,
        });
        state.audits.insert(audit.issuance_id.clone(), audit);
        state
            .challenges
            .get_mut(&bindings.challenge_id)
            .expect("challenge checked above")
            .consumed_at = Some(bindings.now);
        Ok(())
    }

    pub fn persist_descendant(
        &self,
        descendant: VerifiedDelegation,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let mut state = self.store.0.lock().expect("authority store poisoned");
        let parent_cid = descendant
            .0
            .proof_cids
            .first()
            .ok_or(AuthorityError::DescendantParentMismatch)?;
        let parent = state
            .artifacts
            .get(parent_cid)
            .map(|artifact| artifact.0.clone())
            .ok_or(AuthorityError::DescendantParentMismatch)?;
        if parent.delegation_mode == DelegationMode::ConditionalMint {
            return Err(AuthorityError::ConditionalMintNotParent);
        }
        let root_cid = if parent.role == DelegationRole::PolicySessionRoot {
            parent.delegation_cid.as_str()
        } else {
            parent.fact("rootSessionDelegationCid")?
        };
        let root = state
            .artifacts
            .get(root_cid)
            .map(|artifact| artifact.0.clone())
            .ok_or(AuthorityError::DescendantAuthorityRootsMismatch)?;
        validate_descendant(&descendant.0, &parent, &root)?;
        let mut visiting = HashSet::new();
        walk_memory_edges(&state, &parent.delegation_cid, now, false, 0, &mut visiting)?;
        if state.fail_next_transaction {
            state.fail_next_transaction = false;
            return Err(AuthorityError::TransactionFailed);
        }
        let cid = descendant.0.delegation_cid.clone();
        let parent_cid = descendant.0.proof_cids[0].clone();
        state.artifacts.insert(cid.clone(), descendant);
        state.statuses.insert(
            cid.clone(),
            AuthorityStatus {
                checked_at: now,
                sequence: 0,
                revoked_at: None,
            },
        );
        state.edges.push(VerifiedEdge {
            child_cid: cid,
            parent_cid,
            kind: EdgeKind::Immediate,
            position: 0,
        });
        Ok(())
    }

    pub fn validate_for_invocation(
        &self,
        cid: &str,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let mut visiting = HashSet::new();
        self.walk_verified_edges(cid, now, false, 0, &mut visiting)
    }

    fn ensure_live(
        &self,
        cid: &str,
        now: OffsetDateTime,
        ancestor: bool,
    ) -> Result<(), AuthorityError> {
        let state = self.state_guard();
        let artifact = state
            .artifacts
            .get(cid)
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        if now < artifact.0.not_before()? || now >= artifact.0.expires_at()? {
            return Err(AuthorityError::SessionTimeInvalid);
        }
        let status = state
            .statuses
            .get(cid)
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        if now - status.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
            || status.checked_at > now
            || status
                .revoked_at
                .is_some_and(|revoked_at| revoked_at > status.checked_at)
        {
            return Err(AuthorityError::AuthorityStateUnavailable);
        }
        if status.revoked_at.is_some_and(|revoked| revoked <= now) {
            return Err(if ancestor {
                AuthorityError::DelegationAncestorRevoked
            } else {
                AuthorityError::DelegationRevoked
            });
        }
        Ok(())
    }

    fn walk_verified_edges(
        &self,
        cid: &str,
        now: OffsetDateTime,
        ancestor: bool,
        depth: usize,
        visiting: &mut HashSet<String>,
    ) -> Result<(), AuthorityError> {
        if depth > MAX_ANCESTRY_DEPTH {
            return Err(AuthorityError::AncestryTooDeep);
        }
        self.ensure_live(cid, now, ancestor)?;
        if !visiting.insert(cid.to_string()) {
            return Err(AuthorityError::AncestryTooDeep);
        }
        let edges = self.store.edges(cid);
        let artifact = self
            .store
            .artifact(cid)
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        match artifact.role {
            DelegationRole::PolicySessionRoot => {
                if edges.len() != 2
                    || edges[0].kind != EdgeKind::Authority
                    || edges[0].position != 0
                    || edges[1].kind != EdgeKind::Authority
                    || edges[1].position != 1
                    || edges[0].parent_cid != artifact.proof_cids[0]
                    || edges[1].parent_cid != artifact.proof_cids[1]
                {
                    return Err(AuthorityError::AuthorityStateUnavailable);
                }
            }
            DelegationRole::PolicySessionDescendant => {
                if edges.len() != 1
                    || edges[0].kind != EdgeKind::Immediate
                    || edges[0].parent_cid != artifact.proof_cids[0]
                {
                    return Err(AuthorityError::AuthorityStateUnavailable);
                }
            }
            _ if !edges.is_empty() => return Err(AuthorityError::AuthorityStateUnavailable),
            _ => {}
        }
        for edge in edges {
            self.walk_verified_edges(&edge.parent_cid, now, true, depth + 1, visiting)?;
        }
        visiting.remove(cid);
        Ok(())
    }

    fn state_guard(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.store.0.lock().expect("authority store poisoned")
    }
}

fn ensure_live_in_memory(
    state: &MemoryState,
    cid: &str,
    now: OffsetDateTime,
    ancestor: bool,
) -> Result<(), AuthorityError> {
    let artifact = state
        .artifacts
        .get(cid)
        .ok_or(AuthorityError::AuthorityStateUnavailable)?;
    if now < artifact.0.not_before()? || now >= artifact.0.expires_at()? {
        return Err(AuthorityError::SessionTimeInvalid);
    }
    let status = state
        .statuses
        .get(cid)
        .ok_or(AuthorityError::AuthorityStateUnavailable)?;
    if now - status.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
        || status.checked_at > now
        || status
            .revoked_at
            .is_some_and(|revoked_at| revoked_at > status.checked_at)
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    if status.revoked_at.is_some_and(|revoked| revoked <= now) {
        return Err(if ancestor {
            AuthorityError::DelegationAncestorRevoked
        } else {
            AuthorityError::DelegationRevoked
        });
    }
    Ok(())
}

fn walk_memory_edges(
    state: &MemoryState,
    cid: &str,
    now: OffsetDateTime,
    ancestor: bool,
    depth: usize,
    visiting: &mut HashSet<String>,
) -> Result<(), AuthorityError> {
    if depth > MAX_ANCESTRY_DEPTH || !visiting.insert(cid.to_string()) {
        return Err(AuthorityError::AncestryTooDeep);
    }
    ensure_live_in_memory(state, cid, now, ancestor)?;
    let artifact = state
        .artifacts
        .get(cid)
        .ok_or(AuthorityError::AuthorityStateUnavailable)?;
    let mut edges = state
        .edges
        .iter()
        .filter(|edge| edge.child_cid == cid)
        .cloned()
        .collect::<Vec<_>>();
    edges.sort_by_key(|edge| edge.position);
    validate_persisted_edge_shape(&artifact.0, &edges)?;
    for edge in edges {
        walk_memory_edges(state, &edge.parent_cid, now, true, depth + 1, visiting)?;
    }
    visiting.remove(cid);
    Ok(())
}

fn validate_persisted_edge_shape(
    artifact: &PolicyDelegation,
    edges: &[VerifiedEdge],
) -> Result<(), AuthorityError> {
    match artifact.role {
        DelegationRole::PolicySessionRoot => {
            if edges.len() != 2
                || edges[0].kind != EdgeKind::Authority
                || edges[0].position != 0
                || edges[1].kind != EdgeKind::Authority
                || edges[1].position != 1
                || edges[0].parent_cid != artifact.proof_cids[0]
                || edges[1].parent_cid != artifact.proof_cids[1]
            {
                return Err(AuthorityError::AuthorityStateUnavailable);
            }
        }
        DelegationRole::PolicySessionDescendant => {
            if edges.len() != 1
                || edges[0].kind != EdgeKind::Immediate
                || edges[0].position != 0
                || edges[0].parent_cid != artifact.proof_cids[0]
            {
                return Err(AuthorityError::AuthorityStateUnavailable);
            }
        }
        _ if !edges.is_empty() => return Err(AuthorityError::AuthorityStateUnavailable),
        _ => {}
    }
    Ok(())
}

fn validate_status_transition(
    previous: &AuthorityStatus,
    next: &AuthorityStatus,
) -> Result<(), AuthorityError> {
    if next.sequence <= previous.sequence
        || next.checked_at < previous.checked_at
        || previous.revoked_at.is_some() && next.revoked_at != previous.revoked_at
        || next.revoked_at.is_some_and(|revoked_at| {
            revoked_at < previous.checked_at || revoked_at > next.checked_at
        })
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    Ok(())
}

fn validate_challenge_lifetime(challenge: &ChallengeState) -> Result<(), AuthorityError> {
    if challenge.consumed_at.is_some() {
        return Err(AuthorityError::ChallengeExpired);
    }
    validate_challenge_lifetime_for_read(challenge)
}

fn validate_challenge_lifetime_for_read(challenge: &ChallengeState) -> Result<(), AuthorityError> {
    if challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > time::Duration::seconds(300)
    {
        Err(AuthorityError::ChallengeExpired)
    } else {
        Ok(())
    }
}

fn validate_authority_pair(
    policy: &PolicyDelegation,
    enforcement: &PolicyDelegation,
    policy_state: &VerifiedPolicyState,
    running_node_did: &str,
) -> Result<(), AuthorityError> {
    policy.validate_wire_shape()?;
    enforcement.validate_wire_shape()?;
    if policy.role != DelegationRole::PolicyAuthority
        || policy.delegation_mode != DelegationMode::PolicySource
        || !policy.proof_cids.is_empty()
        || enforcement.role != DelegationRole::PolicyEnforcement
        || enforcement.delegation_mode != DelegationMode::ConditionalMint
        || !enforcement.proof_cids.is_empty()
    {
        return Err(AuthorityError::RoleModeMismatch);
    }
    if policy.issuer_did != enforcement.issuer_did
        || policy.fact("ownerDid")? != enforcement.fact("ownerDid")?
        || policy.issuer_did != policy.fact("ownerDid")?
    {
        return Err(AuthorityError::OwnerMismatch);
    }
    let policy_suffix = policy
        .fact("policyId")?
        .strip_prefix("pol_")
        .filter(|suffix| suffix.len() == 52)
        .ok_or(AuthorityError::PolicyMismatch)?;
    if policy.audience_did != format!("did:tinycloud:policy:{policy_suffix}") {
        return Err(AuthorityError::PolicyMismatch);
    }
    for fact in ["policyId", "policyDigestHex", "capabilityCeilingHashHex"] {
        if policy.fact(fact)? != enforcement.fact(fact)? {
            return Err(AuthorityError::PolicyMismatch);
        }
    }
    if policy.capabilities != enforcement.capabilities
        || policy.capability_hash()? != policy.fact("capabilityCeilingHashHex")?
    {
        return Err(AuthorityError::CapabilityHashMismatch);
    }
    if policy_state.owner_did != policy.fact("ownerDid")?
        || policy_state.policy_id != policy.fact("policyId")?
        || policy_state.policy_digest_hex != policy.fact("policyDigestHex")?
        || policy_state.capability_ceiling_hash_hex != policy.fact("capabilityCeilingHashHex")?
    {
        return Err(AuthorityError::PolicyMismatch);
    }
    if enforcement.audience_did != enforcement.fact("enforcerDid")?
        || enforcement.audience_did != enforcement.fact("nodeAudience")?
        || enforcement.audience_did != running_node_did
    {
        return Err(AuthorityError::WrongEnforcer);
    }
    let ttl = decimal_fact(enforcement, "maxSessionTtlSeconds")?;
    let depth = decimal_fact(enforcement, "maxRedelegationDepth")?;
    if !(1..=300).contains(&ttl) || depth > 8 || enforcement.fact("auditProfile")? != "vp-digest-v1"
    {
        return Err(AuthorityError::FactsMismatch);
    }
    if ttl > policy_state.max_ttl_seconds
        || enforcement.fact("sessionMode")? != policy_state.grant_mode.as_str()
        || (policy_state.grant_mode == PolicyGrantMode::Terminal && depth != 0)
    {
        return Err(AuthorityError::PolicyMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_root(
    policy: &PolicyDelegation,
    enforcement: &PolicyDelegation,
    policy_state: &VerifiedPolicyState,
    challenge: &ChallengeState,
    root: &PolicyDelegation,
    binding: &VerifiedAttestedEnforcerBinding,
    decision: &TrustedPolicyDecision,
    bindings: &IssuanceBindings,
    running_node_did: &str,
) -> Result<IssuanceAudit, AuthorityError> {
    root.validate_wire_shape()?;
    if policy_state.status_checked_at > bindings.now
        || bindings.now - policy_state.status_checked_at
            > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
        || bindings.now >= policy_state.expires_at
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    validate_challenge(challenge, policy, enforcement, bindings, running_node_did)?;
    if root.role != DelegationRole::PolicySessionRoot
        || root.proof_cids
            != [
                policy.delegation_cid.clone(),
                enforcement.delegation_cid.clone(),
            ]
    {
        return Err(AuthorityError::ProofSetUnmatched);
    }
    let depth = root.depth()?;
    if root.delegation_mode
        != if depth > 0 {
            DelegationMode::Attenuable
        } else {
            DelegationMode::Terminal
        }
        || depth as u64 != decimal_fact(enforcement, "maxRedelegationDepth")?
    {
        return Err(AuthorityError::SessionRedelegationInvalid);
    }
    if root.issuer_did != enforcement.audience_did
        || root.fact("enforcerDid")? != enforcement.audience_did
        || root.issuer_did != running_node_did
    {
        return Err(AuthorityError::WrongEnforcer);
    }
    if root.fact("nodeAudience")? != enforcement.fact("nodeAudience")?
        || root.fact("nodeAudience")? != running_node_did
    {
        return Err(AuthorityError::WrongAudience);
    }
    if root.audience_did != bindings.claimant_did
        || root.fact("rootClaimantDid")? != bindings.claimant_did
        || root.fact("sessionSubjectDid")? != bindings.claimant_did
    {
        return Err(AuthorityError::ClaimantMismatch);
    }
    for (name, expected) in [
        ("ownerDid", policy.fact("ownerDid")?),
        ("policyId", policy.fact("policyId")?),
        ("policyDigestHex", policy.fact("policyDigestHex")?),
        (
            "capabilityCeilingHashHex",
            policy.fact("capabilityCeilingHashHex")?,
        ),
        ("policyDelegationCid", &policy.delegation_cid),
        ("enforcementDelegationCid", &enforcement.delegation_cid),
        ("attestationBindingDigestHex", &binding.binding_digest_hex),
        (
            "claimInvocationDigestHex",
            &bindings.claim_invocation_digest_hex,
        ),
        ("vpDigestHex", &bindings.vp_digest_hex),
        (
            "decisionContextDigestHex",
            &decision.decision_context_digest_hex,
        ),
    ] {
        if root.fact(name)? != expected {
            return Err(AuthorityError::FactsMismatch);
        }
    }
    if root.capability_hash()? != root.fact("capabilityHashHex")?
        || root.capability_hash()? != bindings.requested_capabilities_hash_hex
        || !capability_set_contained(&root.capabilities, &policy.capabilities)?
        || !capability_set_contained(&root.capabilities, &enforcement.capabilities)?
    {
        return Err(AuthorityError::CapabilityBroadened);
    }
    if binding.enforcer_did != enforcement.audience_did
        || binding.node_audience != enforcement.fact("nodeAudience")?
        || binding.enforcer_did != running_node_did
        || binding.node_audience != running_node_did
        || binding.binding_digest_hex != enforcement.fact("attestationBindingDigestHex")?
    {
        return Err(AuthorityError::AttestationBindingMismatch);
    }
    if bindings.now >= binding.expires_at {
        return Err(AuthorityError::AttestationExpired);
    }
    let expected_context = DecisionContext {
        owner_did: policy.fact("ownerDid")?.to_string(),
        policy_id: policy.fact("policyId")?.to_string(),
        policy_digest_hex: policy.fact("policyDigestHex")?.to_string(),
        capability_ceiling_hash_hex: policy.fact("capabilityCeilingHashHex")?.to_string(),
        enforcer_did: running_node_did.to_string(),
        node_audience: running_node_did.to_string(),
        claimant_did: bindings.claimant_did.clone(),
        challenge_id: bindings.challenge_id.clone(),
        challenge_nonce_hash_hex: bindings.challenge_nonce_hash_hex.clone(),
        requested_capabilities_hash_hex: bindings.requested_capabilities_hash_hex.clone(),
        claim_invocation_digest_hex: bindings.claim_invocation_digest_hex.clone(),
        vp_digest_hex: bindings.vp_digest_hex.clone(),
    };
    if decision.context != expected_context
        || decision.decision_context_digest_hex != expected_context.digest_hex()?
    {
        return Err(AuthorityError::DecisionContextMismatch);
    }
    if decision.evaluated_at > bindings.now || bindings.now >= decision.valid_until {
        return Err(AuthorityError::PolicyDecisionExpired);
    }
    let not_before = root.not_before()?;
    let expires_at = root.expires_at()?;
    let ttl_seconds =
        decimal_fact(enforcement, "maxSessionTtlSeconds")?.min(policy_state.max_ttl_seconds);
    let ttl_end = not_before + time::Duration::seconds(ttl_seconds as i64);
    let maximum_expiry = [
        policy.expires_at()?,
        enforcement.expires_at()?,
        policy_state.expires_at,
        challenge.expires_at,
        bindings.claim_expires_at,
        decision.valid_until,
        ttl_end,
    ]
    .into_iter()
    .min()
    .expect("fixed nonempty bounds");
    if not_before < policy.not_before()?
        || not_before < enforcement.not_before()?
        || not_before < bindings.now
        || not_before < bindings.claim_issued_at
        || not_before < decision.evaluated_at
        || expires_at > maximum_expiry
        || not_before >= expires_at
    {
        return Err(AuthorityError::SessionTimeInvalid);
    }
    let issuance_id = root.fact("issuanceId")?.to_string();
    if !valid_prefixed_base32(&issuance_id, "peiss_", 26) {
        return Err(AuthorityError::SchemaInvalid);
    }
    let mut audit = IssuanceAudit {
        schema: "xyz.tinycloud.policy/issuance-audit/v1".into(),
        issuance_id,
        owner_did: policy.fact("ownerDid")?.into(),
        policy_id: policy.fact("policyId")?.into(),
        policy_digest_hex: policy.fact("policyDigestHex")?.into(),
        policy_delegation_cid: policy.delegation_cid.clone(),
        enforcement_delegation_cid: enforcement.delegation_cid.clone(),
        enforcer_did: running_node_did.into(),
        node_audience: running_node_did.into(),
        claimant_did: bindings.claimant_did.clone(),
        capability_hash_hex: root.fact("capabilityHashHex")?.into(),
        challenge_id: challenge.challenge_id.clone(),
        challenge_nonce_hash_hex: challenge.nonce_hash_hex.clone(),
        claim_invocation_digest_hex: bindings.claim_invocation_digest_hex.clone(),
        vp_digest_hex: bindings.vp_digest_hex.clone(),
        decision_context_digest_hex: decision.decision_context_digest_hex.clone(),
        decision: "allow".into(),
        issued_at: root.not_before.clone(),
        expires_at: root.expires_at.clone(),
        audit_digest_hex: String::new(),
        session_delegation_cid: root.delegation_cid.clone(),
    };
    audit.audit_digest_hex = audit.recompute_digest_hex()?;
    if root.fact("issuanceAuditDigestHex")? != audit.audit_digest_hex {
        return Err(AuthorityError::AuditDigestMismatch);
    }
    Ok(audit)
}

fn validate_challenge(
    challenge: &ChallengeState,
    policy: &PolicyDelegation,
    enforcement: &PolicyDelegation,
    bindings: &IssuanceBindings,
    running_node_did: &str,
) -> Result<(), AuthorityError> {
    if challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > time::Duration::seconds(300)
    {
        return Err(AuthorityError::ChallengeExpired);
    }
    if challenge.challenge_id != bindings.challenge_id
        || challenge.nonce_hash_hex != bindings.challenge_nonce_hash_hex
        || challenge.owner_did != policy.fact("ownerDid")?
        || challenge.policy_id != policy.fact("policyId")?
        || challenge.policy_digest_hex != policy.fact("policyDigestHex")?
        || challenge.policy_delegation_cid != policy.delegation_cid
        || challenge.enforcement_delegation_cid != enforcement.delegation_cid
        || challenge.enforcer_did != running_node_did
        || challenge.node_audience != running_node_did
        || challenge.claimant_did != bindings.claimant_did
        || challenge.requested_capabilities_hash_hex != bindings.requested_capabilities_hash_hex
    {
        return Err(AuthorityError::ChallengeNotFound);
    }
    if bindings.now < challenge.issued_at || bindings.now >= challenge.expires_at {
        return Err(AuthorityError::ChallengeExpired);
    }
    Ok(())
}

fn valid_prefixed_base32(value: &str, prefix: &str, suffix_len: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == suffix_len
            && suffix
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
    })
}

fn validate_descendant(
    child: &PolicyDelegation,
    parent: &PolicyDelegation,
    root: &PolicyDelegation,
) -> Result<(), AuthorityError> {
    child.validate_wire_shape()?;
    parent.validate_wire_shape()?;
    root.validate_wire_shape()?;
    if child.role != DelegationRole::PolicySessionDescendant
        || child.proof_cids != [parent.delegation_cid.clone()]
        || child.fact("immediateParentDelegationCid")? != parent.delegation_cid
    {
        return Err(AuthorityError::DescendantParentMismatch);
    }
    if parent.delegation_mode == DelegationMode::ConditionalMint {
        return Err(AuthorityError::ConditionalMintNotParent);
    }
    if parent.delegation_mode == DelegationMode::Terminal {
        return Err(AuthorityError::TerminalParent);
    }
    if !matches!(
        parent.role,
        DelegationRole::PolicySessionRoot | DelegationRole::PolicySessionDescendant
    ) {
        return Err(AuthorityError::RoleModeMismatch);
    }
    if child.issuer_did != parent.audience_did
        || child.audience_did != child.fact("sessionSubjectDid")?
    {
        return Err(AuthorityError::SessionRedelegationInvalid);
    }
    if child.fact("rootSessionDelegationCid")? != root.delegation_cid
        || child.fact("policyDelegationCid")? != root.fact("policyDelegationCid")?
        || child.fact("enforcementDelegationCid")? != root.fact("enforcementDelegationCid")?
    {
        return Err(AuthorityError::DescendantAuthorityRootsMismatch);
    }
    for (key, value) in &parent.facts {
        let mutable = [
            "capabilityHashHex",
            "sessionSubjectDid",
            "remainingRedelegationDepth",
            "rootSessionDelegationCid",
            "immediateParentDelegationCid",
        ]
        .iter()
        .any(|name| key == &format!("{POLICY_PREFIX}{name}"));
        if !mutable && child.facts.get(key) != Some(value) {
            return Err(AuthorityError::DescendantAuthorityRootsMismatch);
        }
    }
    let parent_depth = parent.depth()?;
    let child_depth = child.depth()?;
    if parent_depth == 0
        || child_depth + 1 != parent_depth
        || child.delegation_mode
            != if child_depth > 0 {
                DelegationMode::Attenuable
            } else {
                DelegationMode::Terminal
            }
    {
        return Err(AuthorityError::SessionRedelegationInvalid);
    }
    if child.capability_hash()? != child.fact("capabilityHashHex")?
        || !capability_set_contained(&child.capabilities, &parent.capabilities)?
    {
        return Err(AuthorityError::CapabilityBroadened);
    }
    if child.not_before()? <= parent.not_before()?
        || child.expires_at()? >= parent.expires_at()?
        || child.not_before()? >= child.expires_at()?
    {
        return Err(AuthorityError::SessionTimeInvalid);
    }
    Ok(())
}

fn canonical_capabilities(values: &[Value]) -> Result<Vec<PolicyCapability>, AuthorityError> {
    values
        .iter()
        .map(|value| {
            let capability =
                parse_capability(value).map_err(|_| AuthorityError::CapabilityNoncanonical)?;
            let action_allowed = |action: &str| match capability.service.as_str() {
                "tinycloud.kv" => matches!(
                    action,
                    "tinycloud.kv/get"
                        | "tinycloud.kv/list"
                        | "tinycloud.kv/metadata"
                        | "tinycloud.kv/put"
                        | "tinycloud.kv/delete"
                ),
                "tinycloud.sql" => matches!(
                    action,
                    "tinycloud.sql/read" | "tinycloud.sql/select" | "tinycloud.sql/write"
                ),
                "tinycloud.vfs" => matches!(
                    action,
                    "tinycloud.vfs/get"
                        | "tinycloud.vfs/list"
                        | "tinycloud.vfs/metadata"
                        | "tinycloud.vfs/put"
                        | "tinycloud.vfs/delete"
                ),
                _ => false,
            };
            if !capability
                .actions
                .iter()
                .all(|action| action_allowed(action))
            {
                return Err(AuthorityError::CapabilityNoncanonical);
            }
            if capability.canonical_value() != *value {
                return Err(AuthorityError::CapabilityNoncanonical);
            }
            Ok(capability)
        })
        .collect()
}

fn capability_set_contained(children: &[Value], parents: &[Value]) -> Result<bool, AuthorityError> {
    let children = canonical_capabilities(children)?;
    let parents = canonical_capabilities(parents)?;
    Ok(children
        .iter()
        .all(|child| parents.iter().any(|parent| parent.contains(child).is_ok())))
}

fn canonical_time(value: &str) -> Result<OffsetDateTime, AuthorityError> {
    if value.len() != 20 || !value.ends_with('Z') {
        return Err(AuthorityError::TimestampNoncanonical);
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AuthorityError::TimestampNoncanonical)
}

fn decimal_fact(delegation: &PolicyDelegation, name: &'static str) -> Result<u64, AuthorityError> {
    let value = delegation.fact(name)?;
    if value != "0" && value.starts_with('0') {
        return Err(AuthorityError::FactsMismatch);
    }
    value.parse().map_err(|_| AuthorityError::FactsMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OWNER: &str = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001";
    const ENFORCER: &str = "did:key:z6MkEnforcer";
    const CLAIMANT: &str = "did:key:z6MkClaimant";
    const POLICY_CID: &str = "bafkr4policy";
    const ENFORCE_CID: &str = "bafkr4enforce";
    const ROOT_CID: &str = "bafkr4root";
    const DESC_CID: &str = "bafkr4desc";
    const GRANDCHILD_CID: &str = "bafkr4grandchild";
    const CHALLENGE_ID: &str = "pec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ISSUANCE_ID: &str = "peiss_aaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn t(value: &str) -> OffsetDateTime {
        canonical_time(value).unwrap()
    }

    fn capability(actions: &[&str]) -> Value {
        json!({
            "actions": actions,
            "path": "profile",
            "service": "tinycloud.kv",
            "space": "did:key:z6MkSpace"
        })
    }

    fn facts(values: &[(&str, &str)]) -> BTreeMap<String, String> {
        values
            .iter()
            .map(|(key, value)| (format!("{POLICY_PREFIX}{key}"), (*value).to_string()))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn artifact(
        role: DelegationRole,
        cid: &str,
        issuer: &str,
        audience: &str,
        mode: DelegationMode,
        proofs: Vec<&str>,
        caps: Vec<Value>,
        facts: BTreeMap<String, String>,
        not_before: &str,
        expires_at: &str,
    ) -> VerifiedDelegation {
        VerifiedDelegation::for_test(PolicyDelegation {
            schema: "xyz.tinycloud.policy/enforcement-delegation/v1".into(),
            role,
            delegation_cid: cid.into(),
            issuer_did: issuer.into(),
            audience_did: audience.into(),
            capabilities: caps,
            proof_cids: proofs.into_iter().map(str::to_string).collect(),
            not_before: not_before.into(),
            expires_at: expires_at.into(),
            delegation_mode: mode,
            facts,
            signature: DelegationSignature {
                suite: if matches!(
                    role,
                    DelegationRole::PolicyAuthority | DelegationRole::PolicyEnforcement
                ) {
                    EIP191_SUITE.into()
                } else {
                    ED25519_SUITE.into()
                },
                value: "verified-in-test".into(),
            },
        })
    }

    struct Fixture {
        store: MemoryAuthorityStore,
        kernel: AuthorityKernel,
        policy: VerifiedDelegation,
        enforcement: VerifiedDelegation,
        policy_state: VerifiedPolicyState,
        root: VerifiedDelegation,
        binding: VerifiedAttestedEnforcerBinding,
        decision: TrustedPolicyDecision,
        bindings: IssuanceBindings,
        audit: IssuanceAudit,
    }

    fn fixture() -> Fixture {
        let caps = vec![capability(&["tinycloud.kv/get", "tinycloud.kv/put"])];
        let ceiling_hash = requested_capabilities_hash_hex(&canonical_capabilities(&caps).unwrap());
        let common = [
            ("ownerDid", OWNER),
            (
                "policyId",
                "pol_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("policyDigestHex", &"1".repeat(64)),
            ("capabilityCeilingHashHex", ceiling_hash.as_str()),
        ];
        let policy = artifact(
            DelegationRole::PolicyAuthority,
            POLICY_CID,
            OWNER,
            "did:tinycloud:policy:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DelegationMode::PolicySource,
            vec![],
            caps.clone(),
            facts(&common),
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        );
        let mut enforcement_facts = facts(&common);
        enforcement_facts.extend(facts(&[
            ("enforcerDid", ENFORCER),
            ("nodeAudience", ENFORCER),
            ("attestationBindingDigestHex", &"2".repeat(64)),
            ("maxSessionTtlSeconds", "300"),
            ("sessionMode", "attenuable"),
            ("maxRedelegationDepth", "2"),
            ("auditProfile", "vp-digest-v1"),
        ]));
        let enforcement = artifact(
            DelegationRole::PolicyEnforcement,
            ENFORCE_CID,
            OWNER,
            ENFORCER,
            DelegationMode::ConditionalMint,
            vec![],
            caps.clone(),
            enforcement_facts,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        );
        let now = t("2026-06-01T00:00:00Z");
        let root_caps = vec![capability(&["tinycloud.kv/get"])];
        let root_hash =
            requested_capabilities_hash_hex(&canonical_capabilities(&root_caps).unwrap());
        let context = DecisionContext {
            owner_did: OWNER.into(),
            policy_id: common[1].1.into(),
            policy_digest_hex: common[2].1.into(),
            capability_ceiling_hash_hex: ceiling_hash.clone(),
            enforcer_did: ENFORCER.into(),
            node_audience: ENFORCER.into(),
            claimant_did: CLAIMANT.into(),
            challenge_id: CHALLENGE_ID.into(),
            challenge_nonce_hash_hex: "3".repeat(64),
            requested_capabilities_hash_hex: root_hash.clone(),
            claim_invocation_digest_hex: "4".repeat(64),
            vp_digest_hex: "5".repeat(64),
        };
        let decision =
            TrustedPolicyDecision::allow_for_test(context, now, t("2026-06-01T00:04:00Z"));
        let mut audit = IssuanceAudit {
            schema: "xyz.tinycloud.policy/issuance-audit/v1".into(),
            issuance_id: ISSUANCE_ID.into(),
            owner_did: OWNER.into(),
            policy_id: common[1].1.into(),
            policy_digest_hex: common[2].1.into(),
            policy_delegation_cid: POLICY_CID.into(),
            enforcement_delegation_cid: ENFORCE_CID.into(),
            enforcer_did: ENFORCER.into(),
            node_audience: ENFORCER.into(),
            claimant_did: CLAIMANT.into(),
            capability_hash_hex: root_hash.clone(),
            challenge_id: CHALLENGE_ID.into(),
            challenge_nonce_hash_hex: "3".repeat(64),
            claim_invocation_digest_hex: "4".repeat(64),
            vp_digest_hex: "5".repeat(64),
            decision_context_digest_hex: decision.decision_context_digest_hex.clone(),
            decision: "allow".into(),
            issued_at: "2026-06-01T00:00:00Z".into(),
            expires_at: "2026-06-01T00:04:00Z".into(),
            audit_digest_hex: String::new(),
            session_delegation_cid: ROOT_CID.into(),
        };
        audit.audit_digest_hex = audit.recompute_digest_hex().unwrap();
        let mut root_facts = facts(&common);
        root_facts.extend(facts(&[
            ("capabilityHashHex", &root_hash),
            ("enforcerDid", ENFORCER),
            ("nodeAudience", ENFORCER),
            ("rootClaimantDid", CLAIMANT),
            ("sessionSubjectDid", CLAIMANT),
            ("policyDelegationCid", POLICY_CID),
            ("enforcementDelegationCid", ENFORCE_CID),
            ("attestationBindingDigestHex", &"2".repeat(64)),
            ("claimInvocationDigestHex", &"4".repeat(64)),
            ("vpDigestHex", &"5".repeat(64)),
            (
                "decisionContextDigestHex",
                &decision.decision_context_digest_hex,
            ),
            ("issuanceAuditDigestHex", &audit.audit_digest_hex),
            ("issuanceId", ISSUANCE_ID),
            ("remainingRedelegationDepth", "2"),
            ("auditProfile", "vp-digest-v1"),
        ]));
        let root = artifact(
            DelegationRole::PolicySessionRoot,
            ROOT_CID,
            ENFORCER,
            CLAIMANT,
            DelegationMode::Attenuable,
            vec![POLICY_CID, ENFORCE_CID],
            root_caps,
            root_facts,
            "2026-06-01T00:00:00Z",
            "2026-06-01T00:04:00Z",
        );
        let store = MemoryAuthorityStore::default();
        let status = AuthorityStatus::active_for_test(now, 1);
        store
            .insert_verified_authority(policy.clone(), status.clone())
            .unwrap();
        store
            .insert_verified_authority(enforcement.clone(), status)
            .unwrap();
        store
            .insert_challenge(ChallengeState {
                challenge_id: CHALLENGE_ID.into(),
                nonce_hash_hex: "3".repeat(64),
                owner_did: OWNER.into(),
                policy_id: common[1].1.into(),
                policy_digest_hex: common[2].1.into(),
                policy_delegation_cid: POLICY_CID.into(),
                enforcement_delegation_cid: ENFORCE_CID.into(),
                enforcer_did: ENFORCER.into(),
                node_audience: ENFORCER.into(),
                claimant_did: CLAIMANT.into(),
                requested_capabilities_hash_hex: root_hash.clone(),
                issued_at: now,
                expires_at: t("2026-06-01T00:05:00Z"),
                consumed_at: None,
            })
            .unwrap();
        let binding = VerifiedAttestedEnforcerBinding::for_test(
            "2".repeat(64),
            ENFORCER,
            ENFORCER,
            t("2026-06-01T00:05:00Z"),
        );
        let policy_state = VerifiedPolicyState::for_test(
            OWNER,
            common[1].1,
            common[2].1,
            ceiling_hash.clone(),
            PolicyGrantMode::Attenuable,
            300,
            now,
            t("2027-01-01T00:00:00Z"),
        );
        let bindings = IssuanceBindings {
            now,
            claim_issued_at: now,
            claim_expires_at: t("2026-06-01T00:05:00Z"),
            challenge_id: CHALLENGE_ID.into(),
            challenge_nonce_hash_hex: "3".repeat(64),
            claimant_did: CLAIMANT.into(),
            requested_capabilities_hash_hex: root_hash,
            claim_invocation_digest_hex: "4".repeat(64),
            vp_digest_hex: "5".repeat(64),
        };
        Fixture {
            kernel: AuthorityKernel::new(store.clone(), ENFORCER),
            store,
            policy,
            enforcement,
            policy_state,
            root,
            binding,
            decision,
            bindings,
            audit,
        }
    }

    fn issue(f: &Fixture) -> Result<(), AuthorityError> {
        f.kernel.issue_root(
            &f.policy,
            &f.enforcement,
            &f.policy_state,
            f.root.clone(),
            &f.binding,
            &f.decision,
            &f.bindings,
        )
    }

    async fn database_fixture(
        fixture: &Fixture,
    ) -> (
        sea_orm::DatabaseConnection,
        DatabaseAuthorityStore,
        DatabaseAuthorityKernel,
    ) {
        use sea_orm::Database;
        use sea_orm_migration::MigratorTrait;

        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let store = DatabaseAuthorityStore::new(db.clone());
        let status = AuthorityStatus::active_for_test(fixture.bindings.now, 1);
        store
            .insert_verified_authority(fixture.policy.clone(), status.clone())
            .await
            .unwrap();
        store
            .insert_verified_authority(fixture.enforcement.clone(), status)
            .await
            .unwrap();
        store
            .insert_challenge(
                fixture
                    .store
                    .challenge(&fixture.bindings.challenge_id)
                    .unwrap(),
            )
            .await
            .unwrap();
        let kernel = DatabaseAuthorityKernel::new(store.clone(), ENFORCER);
        (db, store, kernel)
    }

    async fn seed_database_fixture(store: &DatabaseAuthorityStore, fixture: &Fixture) {
        let status = AuthorityStatus::active_for_test(fixture.bindings.now, 1);
        store
            .insert_verified_authority(fixture.policy.clone(), status.clone())
            .await
            .unwrap();
        store
            .insert_verified_authority(fixture.enforcement.clone(), status)
            .await
            .unwrap();
        store
            .insert_challenge(
                fixture
                    .store
                    .challenge(&fixture.bindings.challenge_id)
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    async fn sqlite_two_store_fixture(
        fixture: &Fixture,
    ) -> (
        tempfile::TempDir,
        sea_orm::DatabaseConnection,
        DatabaseAuthorityStore,
        sea_orm::DatabaseConnection,
        DatabaseAuthorityStore,
    ) {
        use sea_orm::{ConnectOptions, Database};
        use sea_orm_migration::MigratorTrait;

        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("authority.sqlite").display()
        );
        let connect = || {
            let mut options = ConnectOptions::new(url.clone());
            options.max_connections(1).sqlx_logging(false);
            options
        };
        let first_db = Database::connect(connect()).await.unwrap();
        crate::migrations::Migrator::up(&first_db, None)
            .await
            .unwrap();
        let second_db = Database::connect(connect()).await.unwrap();
        let first = DatabaseAuthorityStore::new(first_db.clone());
        let second = DatabaseAuthorityStore::new(second_db.clone());
        seed_database_fixture(&first, fixture).await;
        (directory, first_db, first, second_db, second)
    }

    async fn postgres_two_store_fixture(
        admin: &sea_orm::DatabaseConnection,
        database_url: &str,
        fixture: &Fixture,
        scenario: &str,
    ) -> (
        String,
        sea_orm::DatabaseConnection,
        DatabaseAuthorityStore,
        DatabaseAuthorityStore,
    ) {
        use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
        use sea_orm_migration::MigratorTrait;

        let schema = format!(
            "tc225_{scenario}_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .expect("create isolated policy authority schema");
        let mut options = ConnectOptions::new(database_url.to_string());
        options
            .max_connections(4)
            .sqlx_logging(false)
            .set_schema_search_path(schema.clone());
        let db = Database::connect(options)
            .await
            .expect("connect to isolated policy authority schema");
        crate::migrations::Migrator::up(&db, None)
            .await
            .expect("migrate isolated policy authority schema");
        let first = DatabaseAuthorityStore::new(db.clone());
        let second = DatabaseAuthorityStore::new(db.clone());
        seed_database_fixture(&first, fixture).await;
        (schema, db, first, second)
    }

    async fn drop_postgres_schema(admin: &sea_orm::DatabaseConnection, schema: String) {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};

        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .expect("drop isolated policy authority schema");
    }

    #[tokio::test]
    async fn policy_authority_migration_round_trips_all_dedicated_tables() {
        use sea_orm::Database;
        use sea_orm_migration::{MigratorTrait, SchemaManager};

        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let schema = SchemaManager::new(&db);
        for table in [
            "policy_delegation",
            "policy_challenge",
            "policy_issuance_audit",
            "policy_edge",
        ] {
            assert!(schema.has_table(table).await.unwrap(), "missing {table}");
        }

        crate::migrations::Migrator::down(&db, Some(3))
            .await
            .unwrap();
        for table in [
            "policy_delegation",
            "policy_challenge",
            "policy_issuance_audit",
            "policy_edge",
        ] {
            assert!(!schema.has_table(table).await.unwrap(), "retained {table}");
        }
    }

    #[test]
    fn unknown_mode_and_unknown_fields_reject_without_fallback() {
        let raw = br#"{"schema":"xyz.tinycloud.policy/enforcement-delegation/v1","role":"policy-enforcement","delegationCid":"cid","issuerDid":"owner","audienceDid":"node","capabilities":[{}],"proofCids":[],"notBefore":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:01:00Z","delegationMode":"sometimes","facts":{},"signature":{"suite":"x","value":"x"}}"#;
        assert_eq!(
            PolicyDelegation::from_json(raw),
            Err(AuthorityError::SchemaInvalid)
        );
        let raw = String::from_utf8(raw.to_vec())
            .unwrap()
            .replace("\"signature\":", "\"unknown\":true,\"signature\":");
        assert_eq!(
            PolicyDelegation::from_json(raw.as_bytes()),
            Err(AuthorityError::SchemaInvalid)
        );
    }

    #[test]
    fn frozen_raw_json_strictness_vectors_are_enforced_recursively() {
        for raw in [
            br#"{"schema":"x","nested":{"value":1,"value":2}}"#.as_slice(),
            br#"{"schema":"x","value":9007199254740992}"#.as_slice(),
            br#"{"schema":"x","value":-9007199254740992}"#.as_slice(),
        ] {
            assert_eq!(strict_json_value(raw), Err(AuthorityError::SchemaInvalid));
        }
        for raw in [
            br#"{"schema":"x","path":"cafe\u0301"}"#.as_slice(),
            br#"{"schema":"x","cafe\u0301":"value"}"#.as_slice(),
            br#"{"schema":"x","nested":[{"path":"cafe\u0301"}]}"#.as_slice(),
        ] {
            assert_eq!(
                strict_json_value(raw),
                Err(AuthorityError::CanonicalizationMismatch)
            );
        }
        for (raw, expected) in [
            (br#"{"value":1.25}"#.as_slice(), r#"{"value":1.25}"#),
            (br#"{"value":0.000001}"#.as_slice(), r#"{"value":0.000001}"#),
            (br#"{"value":0.0000001}"#.as_slice(), r#"{"value":1e-7}"#),
            (b"{\n\t\"value\" : 1\r}".as_slice(), r#"{"value":1}"#),
        ] {
            let value = strict_json_value(raw).unwrap();
            assert_eq!(
                String::from_utf8(crate::policy_capability::jcs::canonicalize(&value)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn accepted_contract_state_from_2c692a6_crosses_strict_boundaries() {
        let accepted = strict_json_value(include_bytes!("contract_accepted.json")).unwrap();
        for key in [
            "policyAuthority",
            "policyEnforcement",
            "rootSession",
            "descendantSession",
            "grandchildSession",
        ] {
            let bytes = serde_json::to_vec(&accepted[key]).unwrap();
            PolicyDelegation::from_json(&bytes)
                .unwrap_or_else(|error| panic!("accepted {key} rejected: {error}"));
        }
        let audit: IssuanceAudit =
            serde_json::from_value(accepted["issuanceAudit"].clone()).unwrap();
        assert_eq!(audit.schema, "xyz.tinycloud.policy/issuance-audit/v1");
        assert_eq!(
            audit.recompute_digest_hex().unwrap(),
            audit.audit_digest_hex
        );
        let challenge = &accepted["challenge"]["value"];
        let issued_at = canonical_time(challenge["issuedAt"].as_str().unwrap()).unwrap();
        let expires_at = canonical_time(challenge["expiresAt"].as_str().unwrap()).unwrap();
        assert!(expires_at > issued_at);
        assert!(expires_at - issued_at <= time::Duration::seconds(300));
    }

    #[test]
    fn root_requires_exact_ordered_and_proofs() {
        for proofs in [
            vec![],
            vec![ENFORCE_CID, POLICY_CID],
            vec![POLICY_CID],
            vec![POLICY_CID, ENFORCE_CID, "extra"],
        ] {
            let f = fixture();
            let mut root = f.root.clone();
            root.0.proof_cids = proofs.into_iter().map(str::to_string).collect();
            assert_eq!(
                f.kernel.issue_root(
                    &f.policy,
                    &f.enforcement,
                    &f.policy_state,
                    root,
                    &f.binding,
                    &f.decision,
                    &f.bindings,
                ),
                Err(AuthorityError::ProofSetUnmatched)
            );
            assert!(f.store.artifact(ROOT_CID).is_none());
            assert!(f.store.edges(ROOT_CID).is_empty());
        }
    }

    #[test]
    fn root_transaction_is_atomic_and_stores_exact_and_edges() {
        let f = fixture();
        f.store.fail_next_transaction();
        assert_eq!(issue(&f), Err(AuthorityError::TransactionFailed));
        assert!(f.store.artifact(ROOT_CID).is_none());
        assert!(f.store.edges(ROOT_CID).is_empty());
        assert!(f.store.audit(ISSUANCE_ID).is_none());
        assert!(f
            .store
            .challenge(CHALLENGE_ID)
            .unwrap()
            .consumed_at
            .is_none());

        issue(&f).unwrap();
        assert!(f.store.artifact(ROOT_CID).is_some());
        assert!(f.store.audit(ISSUANCE_ID).is_some());
        assert!(f
            .store
            .challenge(CHALLENGE_ID)
            .unwrap()
            .consumed_at
            .is_some());
        assert_eq!(
            f.store.edges(ROOT_CID),
            vec![
                VerifiedEdge {
                    child_cid: ROOT_CID.into(),
                    parent_cid: POLICY_CID.into(),
                    kind: EdgeKind::Authority,
                    position: 0,
                },
                VerifiedEdge {
                    child_cid: ROOT_CID.into(),
                    parent_cid: ENFORCE_CID.into(),
                    kind: EdgeKind::Authority,
                    position: 1,
                },
            ]
        );
    }

    #[tokio::test]
    async fn database_store_persists_exact_edges_and_traverses_root_revocation() {
        let f = fixture();
        let (_db, store, kernel) = database_fixture(&f).await;
        kernel
            .issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                f.root.clone(),
                &f.binding,
                &f.decision,
                &f.bindings,
            )
            .await
            .unwrap();
        assert!(store
            .challenge(CHALLENGE_ID)
            .await
            .unwrap()
            .consumed_at
            .is_some());
        assert_eq!(store.audit(ISSUANCE_ID).await.unwrap(), f.audit);
        assert_eq!(
            store.edges(ROOT_CID).await.unwrap(),
            vec![
                VerifiedEdge {
                    child_cid: ROOT_CID.into(),
                    parent_cid: POLICY_CID.into(),
                    kind: EdgeKind::Authority,
                    position: 0,
                },
                VerifiedEdge {
                    child_cid: ROOT_CID.into(),
                    parent_cid: ENFORCE_CID.into(),
                    kind: EdgeKind::Authority,
                    position: 1,
                },
            ]
        );
        let child = descendant(&f);
        kernel
            .persist_descendant(child.clone(), f.bindings.now)
            .await
            .unwrap();
        kernel
            .persist_descendant(
                grandchild(&child),
                f.bindings.now + time::Duration::seconds(2),
            )
            .await
            .unwrap();
        let invocation_time = f.bindings.now + time::Duration::seconds(3);
        store
            .set_status(
                ENFORCE_CID,
                AuthorityStatus::revoked_for_test(invocation_time, 2),
            )
            .await
            .unwrap();
        assert_eq!(
            kernel
                .validate_for_invocation(GRANDCHILD_CID, invocation_time)
                .await,
            Err(AuthorityError::DelegationAncestorRevoked)
        );
    }

    #[tokio::test]
    async fn concurrent_root_issue_and_revoke_have_only_serial_outcomes() {
        let f = fixture();
        let (_db, store, kernel) = database_fixture(&f).await;
        let now = f.bindings.now;
        let issue = kernel.issue_root(
            &f.policy,
            &f.enforcement,
            &f.policy_state,
            f.root.clone(),
            &f.binding,
            &f.decision,
            &f.bindings,
        );
        let revoke = store.set_status(ENFORCE_CID, AuthorityStatus::revoked_for_test(now, 2));
        let (issued, revoked) = tokio::join!(issue, revoke);
        revoked.unwrap();
        match issued {
            Ok(()) => assert_eq!(
                kernel.validate_for_invocation(ROOT_CID, now).await,
                Err(AuthorityError::DelegationAncestorRevoked)
            ),
            Err(AuthorityError::DelegationRevoked) => assert_eq!(
                store.artifact(ROOT_CID).await,
                Err(AuthorityError::AuthorityStateUnavailable)
            ),
            other => panic!("non-serial root/revoke result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrent_descendant_issue_and_revoke_have_only_serial_outcomes() {
        let f = fixture();
        let (_db, store, kernel) = database_fixture(&f).await;
        kernel
            .issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                f.root.clone(),
                &f.binding,
                &f.decision,
                &f.bindings,
            )
            .await
            .unwrap();
        let now = f.bindings.now + time::Duration::seconds(1);
        let issue = kernel.persist_descendant(descendant(&f), now);
        let revoke = store.set_status(ENFORCE_CID, AuthorityStatus::revoked_for_test(now, 2));
        let (issued, revoked) = tokio::join!(issue, revoke);
        revoked.unwrap();
        match issued {
            Ok(()) => assert_eq!(
                kernel.validate_for_invocation(DESC_CID, now).await,
                Err(AuthorityError::DelegationAncestorRevoked)
            ),
            Err(AuthorityError::DelegationAncestorRevoked) => assert_eq!(
                store.artifact(DESC_CID).await,
                Err(AuthorityError::AuthorityStateUnavailable)
            ),
            other => panic!("non-serial descendant/revoke result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrent_claims_consume_one_challenge_exactly_once() {
        let f = fixture();
        let (_db, store, kernel) = database_fixture(&f).await;
        let first = kernel.issue_root(
            &f.policy,
            &f.enforcement,
            &f.policy_state,
            f.root.clone(),
            &f.binding,
            &f.decision,
            &f.bindings,
        );
        let second = kernel.issue_root(
            &f.policy,
            &f.enforcement,
            &f.policy_state,
            f.root.clone(),
            &f.binding,
            &f.decision,
            &f.bindings,
        );
        let results = tokio::join!(first, second);
        assert!(matches!(
            results,
            (Ok(()), Err(AuthorityError::ChallengeConsumed))
                | (Err(AuthorityError::ChallengeConsumed), Ok(()))
        ));
        assert!(store
            .challenge(CHALLENGE_ID)
            .await
            .unwrap()
            .consumed_at
            .is_some());
        assert_eq!(store.audit(ISSUANCE_ID).await.unwrap(), f.audit);
        assert_eq!(store.edges(ROOT_CID).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn authority_status_is_sequence_monotonic_and_revocation_irreversible() {
        let f = fixture();
        let (_db, store, _kernel) = database_fixture(&f).await;
        let later = f.bindings.now + time::Duration::seconds(1);
        store
            .set_status(ENFORCE_CID, AuthorityStatus::revoked_for_test(later, 2))
            .await
            .unwrap();
        for rollback in [
            AuthorityStatus::active_for_test(later, 3),
            AuthorityStatus::revoked_for_test(f.bindings.now, 3),
            AuthorityStatus::revoked_for_test(later, 2),
        ] {
            assert_eq!(
                store.set_status(ENFORCE_CID, rollback).await,
                Err(AuthorityError::AuthorityStateUnavailable)
            );
        }
    }

    #[tokio::test]
    async fn two_connection_status_race_preserves_sequence_and_permanent_revocation() {
        let f = fixture();
        let (_directory, _first_db, first, _second_db, second) = sqlite_two_store_fixture(&f).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let racing_first = first
            .clone()
            .with_race_barrier_for_test(Arc::clone(&barrier));
        let racing_second = second
            .clone()
            .with_race_barrier_for_test(Arc::clone(&barrier));
        let revoked_at = f.bindings.now + time::Duration::seconds(1);
        let active_at = f.bindings.now + time::Duration::seconds(2);

        let (revoked, active) = tokio::join!(
            racing_first.set_status(
                ENFORCE_CID,
                AuthorityStatus::revoked_for_test(revoked_at, 2)
            ),
            racing_second.set_status(ENFORCE_CID, AuthorityStatus::active_for_test(active_at, 3))
        );
        assert!(revoked.is_ok() || active.is_ok());
        let raced = first.status_for_test(ENFORCE_CID).await.unwrap();
        assert!(matches!(raced.sequence, 2 | 3));
        assert_eq!(raced.revoked_at.is_some(), raced.sequence == 2);

        let permanent = if raced.revoked_at.is_some() {
            raced
        } else {
            let checked_at = active_at + time::Duration::seconds(1);
            first
                .set_status(
                    ENFORCE_CID,
                    AuthorityStatus::revoked_for_test(checked_at, 4),
                )
                .await
                .unwrap();
            first.status_for_test(ENFORCE_CID).await.unwrap()
        };
        let rollback_at = permanent.checked_at + time::Duration::seconds(1);
        assert_eq!(
            second
                .set_status(
                    ENFORCE_CID,
                    AuthorityStatus::active_for_test(rollback_at, permanent.sequence + 1),
                )
                .await,
            Err(AuthorityError::AuthorityStateUnavailable)
        );
        assert_eq!(
            first.status_for_test(ENFORCE_CID).await.unwrap().revoked_at,
            permanent.revoked_at
        );
    }

    #[tokio::test]
    async fn two_connection_distinct_higher_status_sequences_converge_to_highest() {
        let f = fixture();
        let (_directory, _first_db, first, _second_db, second) = sqlite_two_store_fixture(&f).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let racing_first = first.with_race_barrier_for_test(Arc::clone(&barrier));
        let racing_second = second.with_race_barrier_for_test(Arc::clone(&barrier));

        let (second_sequence, third_sequence) = tokio::join!(
            racing_first.set_status(
                POLICY_CID,
                AuthorityStatus::active_for_test(f.bindings.now + time::Duration::seconds(1), 2,),
            ),
            racing_second.set_status(
                POLICY_CID,
                AuthorityStatus::active_for_test(f.bindings.now + time::Duration::seconds(2), 3,),
            )
        );
        assert!(second_sequence.is_ok() || third_sequence.is_ok());
        assert_eq!(
            racing_first.status_for_test(POLICY_CID).await.unwrap(),
            AuthorityStatus::active_for_test(f.bindings.now + time::Duration::seconds(2), 3,)
        );
    }

    #[tokio::test]
    async fn two_connection_root_and_revoke_leave_only_serial_artifacts() {
        let f = fixture();
        let (_directory, _first_db, first, _second_db, second) = sqlite_two_store_fixture(&f).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let issuing_store = first
            .clone()
            .with_race_barrier_for_test(Arc::clone(&barrier));
        let revoking_store = second.with_race_barrier_for_test(Arc::clone(&barrier));
        let kernel = DatabaseAuthorityKernel::new(issuing_store, ENFORCER);

        let (issued, revoked) = tokio::join!(
            kernel.issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                f.root.clone(),
                &f.binding,
                &f.decision,
                &f.bindings,
            ),
            revoking_store.set_status(
                ENFORCE_CID,
                AuthorityStatus::revoked_for_test(f.bindings.now, 2),
            )
        );
        revoked.unwrap();
        match issued {
            Ok(()) => assert_eq!(
                kernel
                    .validate_for_invocation(ROOT_CID, f.bindings.now)
                    .await,
                Err(AuthorityError::DelegationAncestorRevoked)
            ),
            Err(
                AuthorityError::TransactionFailed
                | AuthorityError::DelegationRevoked
                | AuthorityError::AuthorityStateUnavailable,
            ) => {
                assert_eq!(
                    first.artifact(ROOT_CID).await,
                    Err(AuthorityError::AuthorityStateUnavailable)
                );
                assert!(first.edges(ROOT_CID).await.unwrap().is_empty());
                assert_eq!(
                    first.audit(ISSUANCE_ID).await,
                    Err(AuthorityError::AuthorityStateUnavailable)
                );
                assert!(first
                    .challenge(CHALLENGE_ID)
                    .await
                    .unwrap()
                    .consumed_at
                    .is_none());
            }
            other => panic!("non-serial two-connection root/revoke result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_connection_descendant_and_ancestor_revoke_leave_only_serial_artifacts() {
        let f = fixture();
        let (_directory, _first_db, first, _second_db, second) = sqlite_two_store_fixture(&f).await;
        let initial_kernel = DatabaseAuthorityKernel::new(first.clone(), ENFORCER);
        initial_kernel
            .issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                f.root.clone(),
                &f.binding,
                &f.decision,
                &f.bindings,
            )
            .await
            .unwrap();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let issuing_store = first
            .clone()
            .with_race_barrier_for_test(Arc::clone(&barrier));
        let revoking_store = second.with_race_barrier_for_test(Arc::clone(&barrier));
        let kernel = DatabaseAuthorityKernel::new(issuing_store, ENFORCER);
        let now = f.bindings.now + time::Duration::seconds(1);
        let (issued, revoked) = tokio::join!(
            kernel.persist_descendant(descendant(&f), now),
            revoking_store.set_status(ENFORCE_CID, AuthorityStatus::revoked_for_test(now, 2),)
        );
        revoked.unwrap();
        match issued {
            Ok(()) => assert_eq!(
                kernel.validate_for_invocation(DESC_CID, now).await,
                Err(AuthorityError::DelegationAncestorRevoked)
            ),
            Err(
                AuthorityError::TransactionFailed
                | AuthorityError::DelegationAncestorRevoked
                | AuthorityError::AuthorityStateUnavailable,
            ) => {
                assert_eq!(
                    first.artifact(DESC_CID).await,
                    Err(AuthorityError::AuthorityStateUnavailable)
                );
                assert!(first.edges(DESC_CID).await.unwrap().is_empty());
            }
            other => panic!("non-serial two-connection descendant/revoke result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_connection_double_claim_consumes_once_without_partial_artifacts() {
        let f = fixture();
        let (_directory, _first_db, first, _second_db, second) = sqlite_two_store_fixture(&f).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let first_kernel = DatabaseAuthorityKernel::new(
            first
                .clone()
                .with_race_barrier_for_test(Arc::clone(&barrier)),
            ENFORCER,
        );
        let second_kernel = DatabaseAuthorityKernel::new(
            second.with_race_barrier_for_test(Arc::clone(&barrier)),
            ENFORCER,
        );

        let first_claim = first_kernel.issue_root(
            &f.policy,
            &f.enforcement,
            &f.policy_state,
            f.root.clone(),
            &f.binding,
            &f.decision,
            &f.bindings,
        );
        let second_claim = second_kernel.issue_root(
            &f.policy,
            &f.enforcement,
            &f.policy_state,
            f.root.clone(),
            &f.binding,
            &f.decision,
            &f.bindings,
        );
        let (first_result, second_result) = tokio::join!(first_claim, second_claim);
        assert_eq!(
            usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
            1
        );
        let rejected = match (first_result, second_result) {
            (Err(error), Ok(())) | (Ok(()), Err(error)) => error,
            other => panic!("expected exactly one rejected claim, got {other:?}"),
        };
        assert!(matches!(
            rejected,
            AuthorityError::ChallengeConsumed | AuthorityError::TransactionFailed
        ));
        assert!(first
            .challenge(CHALLENGE_ID)
            .await
            .unwrap()
            .consumed_at
            .is_some());
        assert_eq!(first.audit(ISSUANCE_ID).await.unwrap(), f.audit);
        assert_eq!(first.edges(ROOT_CID).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn postgres_policy_authority_concurrency_matrix_across_stores() {
        use sea_orm::{ConnectOptions, Database};

        let Ok(database_url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
            eprintln!(
                "skipping PostgreSQL policy authority test: TINYCLOUD_TEST_POSTGRES_URL is unset"
            );
            return;
        };
        let admin = Database::connect(ConnectOptions::new(database_url.clone()))
            .await
            .expect("connect to PostgreSQL test database");

        {
            let f = fixture();
            let (schema, db, first, second) =
                postgres_two_store_fixture(&admin, &database_url, &f, "status_revoke").await;
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let revoked_at = f.bindings.now + time::Duration::seconds(1);
            let active_at = f.bindings.now + time::Duration::seconds(2);
            let revoke = async {
                start.wait().await;
                first
                    .set_status(
                        ENFORCE_CID,
                        AuthorityStatus::revoked_for_test(revoked_at, 2),
                    )
                    .await
            };
            let stale_active = async {
                start.wait().await;
                second
                    .set_status(ENFORCE_CID, AuthorityStatus::active_for_test(active_at, 3))
                    .await
            };
            let (revoked, active) = tokio::join!(revoke, stale_active);
            assert!(revoked.is_ok() || active.is_ok());
            let raced = first.status_for_test(ENFORCE_CID).await.unwrap();
            assert!(matches!(raced.sequence, 2 | 3));
            assert_eq!(raced.revoked_at.is_some(), raced.sequence == 2);
            let permanent = if raced.revoked_at.is_some() {
                raced
            } else {
                let checked_at = active_at + time::Duration::seconds(1);
                first
                    .set_status(
                        ENFORCE_CID,
                        AuthorityStatus::revoked_for_test(checked_at, 4),
                    )
                    .await
                    .unwrap();
                first.status_for_test(ENFORCE_CID).await.unwrap()
            };
            assert_eq!(
                second
                    .set_status(
                        ENFORCE_CID,
                        AuthorityStatus::active_for_test(
                            permanent.checked_at + time::Duration::seconds(1),
                            permanent.sequence + 1,
                        ),
                    )
                    .await,
                Err(AuthorityError::AuthorityStateUnavailable)
            );
            drop(first);
            drop(second);
            db.close().await.unwrap();
            drop_postgres_schema(&admin, schema).await;
        }

        {
            let f = fixture();
            let (schema, db, first, second) =
                postgres_two_store_fixture(&admin, &database_url, &f, "status_order").await;
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let second_sequence = async {
                start.wait().await;
                first
                    .set_status(
                        POLICY_CID,
                        AuthorityStatus::active_for_test(
                            f.bindings.now + time::Duration::seconds(1),
                            2,
                        ),
                    )
                    .await
            };
            let third_sequence = async {
                start.wait().await;
                second
                    .set_status(
                        POLICY_CID,
                        AuthorityStatus::active_for_test(
                            f.bindings.now + time::Duration::seconds(2),
                            3,
                        ),
                    )
                    .await
            };
            let (lower, higher) = tokio::join!(second_sequence, third_sequence);
            assert!(lower.is_ok() || higher.is_ok());
            assert_eq!(
                first.status_for_test(POLICY_CID).await.unwrap(),
                AuthorityStatus::active_for_test(f.bindings.now + time::Duration::seconds(2), 3,)
            );
            drop(first);
            drop(second);
            db.close().await.unwrap();
            drop_postgres_schema(&admin, schema).await;
        }

        {
            let f = fixture();
            let (schema, db, first, second) =
                postgres_two_store_fixture(&admin, &database_url, &f, "root_revoke").await;
            let kernel = DatabaseAuthorityKernel::new(first.clone(), ENFORCER);
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let issue = async {
                start.wait().await;
                kernel
                    .issue_root(
                        &f.policy,
                        &f.enforcement,
                        &f.policy_state,
                        f.root.clone(),
                        &f.binding,
                        &f.decision,
                        &f.bindings,
                    )
                    .await
            };
            let revoke = async {
                start.wait().await;
                second
                    .set_status(
                        ENFORCE_CID,
                        AuthorityStatus::revoked_for_test(f.bindings.now, 2),
                    )
                    .await
            };
            let (issued, revoked) = tokio::join!(issue, revoke);
            revoked.unwrap();
            match issued {
                Ok(()) => assert_eq!(
                    kernel
                        .validate_for_invocation(ROOT_CID, f.bindings.now)
                        .await,
                    Err(AuthorityError::DelegationAncestorRevoked)
                ),
                Err(AuthorityError::DelegationRevoked) => {
                    assert_eq!(
                        first.artifact(ROOT_CID).await,
                        Err(AuthorityError::AuthorityStateUnavailable)
                    );
                    assert!(first.edges(ROOT_CID).await.unwrap().is_empty());
                    assert_eq!(
                        first.audit(ISSUANCE_ID).await,
                        Err(AuthorityError::AuthorityStateUnavailable)
                    );
                    assert!(first
                        .challenge(CHALLENGE_ID)
                        .await
                        .unwrap()
                        .consumed_at
                        .is_none());
                }
                other => panic!("non-serial PostgreSQL root/revoke result: {other:?}"),
            }
            drop(kernel);
            drop(first);
            drop(second);
            db.close().await.unwrap();
            drop_postgres_schema(&admin, schema).await;
        }

        {
            let f = fixture();
            let (schema, db, first, second) =
                postgres_two_store_fixture(&admin, &database_url, &f, "desc_revoke").await;
            let kernel = DatabaseAuthorityKernel::new(first.clone(), ENFORCER);
            kernel
                .issue_root(
                    &f.policy,
                    &f.enforcement,
                    &f.policy_state,
                    f.root.clone(),
                    &f.binding,
                    &f.decision,
                    &f.bindings,
                )
                .await
                .unwrap();
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let now = f.bindings.now + time::Duration::seconds(1);
            let issue = async {
                start.wait().await;
                kernel.persist_descendant(descendant(&f), now).await
            };
            let revoke = async {
                start.wait().await;
                second
                    .set_status(ENFORCE_CID, AuthorityStatus::revoked_for_test(now, 2))
                    .await
            };
            let (issued, revoked) = tokio::join!(issue, revoke);
            revoked.unwrap();
            match issued {
                Ok(()) => assert_eq!(
                    kernel.validate_for_invocation(DESC_CID, now).await,
                    Err(AuthorityError::DelegationAncestorRevoked)
                ),
                Err(AuthorityError::DelegationAncestorRevoked) => {
                    assert_eq!(
                        first.artifact(DESC_CID).await,
                        Err(AuthorityError::AuthorityStateUnavailable)
                    );
                    assert!(first.edges(DESC_CID).await.unwrap().is_empty());
                }
                other => panic!("non-serial PostgreSQL descendant/revoke result: {other:?}"),
            }
            drop(kernel);
            drop(first);
            drop(second);
            db.close().await.unwrap();
            drop_postgres_schema(&admin, schema).await;
        }

        {
            let f = fixture();
            let (schema, db, first, second) =
                postgres_two_store_fixture(&admin, &database_url, &f, "double_claim").await;
            let first_kernel = DatabaseAuthorityKernel::new(first.clone(), ENFORCER);
            let second_kernel = DatabaseAuthorityKernel::new(second.clone(), ENFORCER);
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let first_claim = async {
                start.wait().await;
                first_kernel
                    .issue_root(
                        &f.policy,
                        &f.enforcement,
                        &f.policy_state,
                        f.root.clone(),
                        &f.binding,
                        &f.decision,
                        &f.bindings,
                    )
                    .await
            };
            let second_claim = async {
                start.wait().await;
                second_kernel
                    .issue_root(
                        &f.policy,
                        &f.enforcement,
                        &f.policy_state,
                        f.root.clone(),
                        &f.binding,
                        &f.decision,
                        &f.bindings,
                    )
                    .await
            };
            let results = tokio::join!(first_claim, second_claim);
            assert!(matches!(
                results,
                (Ok(()), Err(AuthorityError::ChallengeConsumed))
                    | (Err(AuthorityError::ChallengeConsumed), Ok(()))
            ));
            assert!(first
                .challenge(CHALLENGE_ID)
                .await
                .unwrap()
                .consumed_at
                .is_some());
            assert_eq!(first.audit(ISSUANCE_ID).await.unwrap(), f.audit);
            assert_eq!(first.edges(ROOT_CID).await.unwrap().len(), 2);
            drop(first_kernel);
            drop(second_kernel);
            drop(first);
            drop(second);
            db.close().await.unwrap();
            drop_postgres_schema(&admin, schema).await;
        }
    }

    #[tokio::test]
    async fn database_late_audit_failure_rolls_back_challenge_session_and_edges() {
        use crate::models::policy_issuance_audit;
        use sea_orm::{ActiveModelTrait, Set};

        let f = fixture();
        let (db, store, kernel) = database_fixture(&f).await;
        policy_issuance_audit::ActiveModel {
            issuance_id: Set(f.audit.issuance_id.clone()),
            session_delegation_cid: Set(POLICY_CID.into()),
            audit_json: Set(serde_json::to_value(&f.audit).unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        assert_eq!(
            kernel
                .issue_root(
                    &f.policy,
                    &f.enforcement,
                    &f.policy_state,
                    f.root.clone(),
                    &f.binding,
                    &f.decision,
                    &f.bindings,
                )
                .await,
            Err(AuthorityError::TransactionFailed)
        );
        assert!(store
            .challenge(CHALLENGE_ID)
            .await
            .unwrap()
            .consumed_at
            .is_none());
        assert_eq!(
            store.artifact(ROOT_CID).await,
            Err(AuthorityError::AuthorityStateUnavailable)
        );
        assert!(store.edges(ROOT_CID).await.unwrap().is_empty());
    }

    fn descendant(f: &Fixture) -> VerifiedDelegation {
        let root = f.root.artifact();
        let mut child_facts = root.facts.clone();
        child_facts.insert(
            format!("{POLICY_PREFIX}capabilityHashHex"),
            root.capability_hash().unwrap(),
        );
        child_facts.insert(format!("{POLICY_PREFIX}sessionSubjectDid"), ENFORCER.into());
        child_facts.insert(
            format!("{POLICY_PREFIX}remainingRedelegationDepth"),
            "1".into(),
        );
        child_facts.insert(
            format!("{POLICY_PREFIX}rootSessionDelegationCid"),
            ROOT_CID.into(),
        );
        child_facts.insert(
            format!("{POLICY_PREFIX}immediateParentDelegationCid"),
            ROOT_CID.into(),
        );
        artifact(
            DelegationRole::PolicySessionDescendant,
            DESC_CID,
            CLAIMANT,
            ENFORCER,
            DelegationMode::Attenuable,
            vec![ROOT_CID],
            root.capabilities.clone(),
            child_facts,
            "2026-06-01T00:00:01Z",
            "2026-06-01T00:03:59Z",
        )
    }

    fn grandchild(child: &VerifiedDelegation) -> VerifiedDelegation {
        let parent = child.artifact();
        let mut facts = parent.facts.clone();
        facts.insert(format!("{POLICY_PREFIX}sessionSubjectDid"), CLAIMANT.into());
        facts.insert(
            format!("{POLICY_PREFIX}remainingRedelegationDepth"),
            "0".into(),
        );
        facts.insert(
            format!("{POLICY_PREFIX}immediateParentDelegationCid"),
            DESC_CID.into(),
        );
        artifact(
            DelegationRole::PolicySessionDescendant,
            GRANDCHILD_CID,
            ENFORCER,
            CLAIMANT,
            DelegationMode::Terminal,
            vec![DESC_CID],
            parent.capabilities.clone(),
            facts,
            "2026-06-01T00:00:02Z",
            "2026-06-01T00:03:58Z",
        )
    }

    #[test]
    fn descendant_strictly_attenuates_and_conditional_mint_is_never_generic_parent() {
        let f = fixture();
        issue(&f).unwrap();
        let child = descendant(&f);
        f.kernel
            .persist_descendant(child.clone(), f.bindings.now)
            .unwrap();
        assert_eq!(f.store.edges(DESC_CID).len(), 1);

        let mut bad = child.clone();
        bad.0.proof_cids = vec![ENFORCE_CID.into()];
        bad.0.facts.insert(
            format!("{POLICY_PREFIX}immediateParentDelegationCid"),
            ENFORCE_CID.into(),
        );
        assert!(matches!(
            f.kernel.persist_descendant(bad, f.bindings.now),
            Err(AuthorityError::ConditionalMintNotParent
                | AuthorityError::DescendantAuthorityRootsMismatch)
        ));

        let mut broad = child;
        broad.0.delegation_cid = "bafkr4broad".into();
        broad.0.capabilities = vec![capability(&["tinycloud.kv/get", "tinycloud.kv/put"])];
        broad.0.facts.insert(
            format!("{POLICY_PREFIX}capabilityHashHex"),
            broad.0.capability_hash().unwrap(),
        );
        assert_eq!(
            f.kernel.persist_descendant(broad, f.bindings.now),
            Err(AuthorityError::CapabilityBroadened)
        );
    }

    #[test]
    fn revoking_either_authority_invalidates_root_and_descendants() {
        for revoked_cid in [POLICY_CID, ENFORCE_CID] {
            let f = fixture();
            issue(&f).unwrap();
            let child = descendant(&f);
            f.kernel
                .persist_descendant(child.clone(), f.bindings.now)
                .unwrap();
            f.kernel
                .persist_descendant(
                    grandchild(&child),
                    f.bindings.now + time::Duration::seconds(2),
                )
                .unwrap();
            let invocation_time = f.bindings.now + time::Duration::seconds(3);
            f.store
                .set_status(
                    revoked_cid,
                    AuthorityStatus::revoked_for_test(invocation_time, 2),
                )
                .unwrap();
            assert_eq!(
                f.kernel.validate_for_invocation(ROOT_CID, invocation_time),
                Err(AuthorityError::DelegationAncestorRevoked)
            );
            assert_eq!(
                f.kernel.validate_for_invocation(DESC_CID, invocation_time),
                Err(AuthorityError::DelegationAncestorRevoked)
            );
            assert_eq!(
                f.kernel
                    .validate_for_invocation(GRANDCHILD_CID, invocation_time),
                Err(AuthorityError::DelegationAncestorRevoked)
            );
        }
    }

    #[test]
    fn tuple_context_time_and_depth_mutations_reject_before_persistence() {
        let mut f = fixture();
        f.policy_state.policy_digest_hex = "9".repeat(64);
        assert_eq!(issue(&f), Err(AuthorityError::PolicyMismatch));
        assert!(f.store.artifact(ROOT_CID).is_none());

        let mut f = fixture();
        f.policy_state.status_checked_at = t("2026-05-31T23:54:59Z");
        assert_eq!(issue(&f), Err(AuthorityError::AuthorityStateUnavailable));
        assert!(f.store.artifact(ROOT_CID).is_none());

        let mut f = fixture();
        f.decision.context.claimant_did = ENFORCER.into();
        assert_eq!(issue(&f), Err(AuthorityError::DecisionContextMismatch));
        assert!(f.store.artifact(ROOT_CID).is_none());

        let f = fixture();
        let mut root = f.root.clone();
        root.0.delegation_mode = DelegationMode::Terminal;
        assert_eq!(
            f.kernel.issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                root,
                &f.binding,
                &f.decision,
                &f.bindings,
            ),
            Err(AuthorityError::SessionRedelegationInvalid)
        );

        let f = fixture();
        let mut root = f.root.clone();
        root.0.expires_at = "2026-06-01T00:05:00Z".into();
        assert_eq!(
            f.kernel.issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                root,
                &f.binding,
                &f.decision,
                &f.bindings,
            ),
            Err(AuthorityError::SessionTimeInvalid)
        );
    }

    #[test]
    fn frozen_authority_kernel_rejects_from_contract_2c692a6() {
        let mut f = fixture();
        f.enforcement.0.issuer_did = CLAIMANT.into();
        assert_eq!(issue(&f), Err(AuthorityError::OwnerMismatch));

        let mut f = fixture();
        f.enforcement.0.facts.insert(
            format!("{POLICY_PREFIX}policyId"),
            "pol_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        );
        assert_eq!(issue(&f), Err(AuthorityError::PolicyMismatch));

        let mut f = fixture();
        f.policy.0.audience_did =
            "did:tinycloud:policy:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        assert_eq!(issue(&f), Err(AuthorityError::PolicyMismatch));

        let f = fixture();
        let wrong_node_kernel = AuthorityKernel::new(f.store.clone(), CLAIMANT);
        assert_eq!(
            wrong_node_kernel.issue_root(
                &f.policy,
                &f.enforcement,
                &f.policy_state,
                f.root.clone(),
                &f.binding,
                &f.decision,
                &f.bindings,
            ),
            Err(AuthorityError::WrongEnforcer)
        );

        let mut f = fixture();
        f.policy_state.max_ttl_seconds = 120;
        assert_eq!(issue(&f), Err(AuthorityError::PolicyMismatch));

        let mut f = fixture();
        f.enforcement
            .0
            .facts
            .insert(format!("{POLICY_PREFIX}maxSessionTtlSeconds"), "120".into());
        f.policy_state.max_ttl_seconds = 120;
        f.store.replace_verified_authority_for_test(
            f.enforcement.clone(),
            AuthorityStatus::active_for_test(f.bindings.now, 1),
        );
        assert_eq!(issue(&f), Err(AuthorityError::SessionTimeInvalid));

        let mut f = fixture();
        f.root.0.facts.insert(
            format!("{POLICY_PREFIX}remainingRedelegationDepth"),
            "1".into(),
        );
        assert_eq!(issue(&f), Err(AuthorityError::SessionRedelegationInvalid));

        let mut f = fixture();
        f.root
            .0
            .facts
            .insert(format!("{POLICY_PREFIX}nodeAudience"), CLAIMANT.into());
        assert_eq!(issue(&f), Err(AuthorityError::WrongAudience));

        let mut f = fixture();
        f.root.0.capabilities = vec![capability(&["tinycloud.kv/list"])];
        f.root.0.facts.insert(
            format!("{POLICY_PREFIX}capabilityHashHex"),
            f.root.0.capability_hash().unwrap(),
        );
        assert_eq!(issue(&f), Err(AuthorityError::CapabilityBroadened));

        let mut f = fixture();
        f.root.0.facts.insert(
            format!("{POLICY_PREFIX}issuanceAuditDigestHex"),
            "9".repeat(64),
        );
        assert_eq!(issue(&f), Err(AuthorityError::AuditDigestMismatch));

        let f = fixture();
        let mut wrong_challenge = f.store.challenge(CHALLENGE_ID).unwrap();
        wrong_challenge.node_audience = CLAIMANT.into();
        f.store.replace_challenge_for_test(wrong_challenge);
        assert_eq!(issue(&f), Err(AuthorityError::ChallengeNotFound));

        let f = fixture();
        let mut too_long = f.store.challenge(CHALLENGE_ID).unwrap();
        too_long.challenge_id = "pec_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        too_long.expires_at = too_long.issued_at + time::Duration::seconds(301);
        assert_eq!(
            f.store.insert_challenge(too_long),
            Err(AuthorityError::ChallengeExpired)
        );

        let f = fixture();
        let mut expired = f.store.challenge(CHALLENGE_ID).unwrap();
        expired.issued_at = f.bindings.now - time::Duration::seconds(300);
        expired.expires_at = f.bindings.now;
        f.store.replace_challenge_for_test(expired);
        assert_eq!(issue(&f), Err(AuthorityError::ChallengeExpired));
    }

    #[test]
    fn derived_audit_has_exact_frozen_shape_and_digest() {
        let f = fixture();
        issue(&f).unwrap();
        let audit = f.store.audit(ISSUANCE_ID).unwrap();
        assert_eq!(audit, f.audit);
        assert_eq!(
            audit.recompute_digest_hex().unwrap(),
            audit.audit_digest_hex
        );
        let object = serde_json::to_value(&audit).unwrap();
        let object = object.as_object().unwrap();
        assert_eq!(object.len(), 21);
        for key in [
            "schema",
            "issuanceId",
            "ownerDid",
            "policyId",
            "policyDigestHex",
            "policyDelegationCid",
            "enforcementDelegationCid",
            "enforcerDid",
            "nodeAudience",
            "claimantDid",
            "capabilityHashHex",
            "challengeId",
            "challengeNonceHashHex",
            "claimInvocationDigestHex",
            "vpDigestHex",
            "decisionContextDigestHex",
            "decision",
            "issuedAt",
            "expiresAt",
            "auditDigestHex",
            "sessionDelegationCid",
        ] {
            assert!(object.contains_key(key), "missing audit field {key}");
        }
    }
}
