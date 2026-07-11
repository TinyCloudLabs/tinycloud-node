//! Owner-side HTTP adapter for the M1 Policy Engine challenge/resolve path.
//!
//! `POST /policy/v0/challenge` and `POST /policy/v0/resolve` are production
//! service surface over the current `PolicyRuntime`. The active-cutoff route is
//! mounted only as disabled-by-default demo/operator surface: it cuts off grants
//! issued by this wrapper's configured grant issuer and does not claim the W1
//! node-confirmed `/revoke` receipt contract. Production node-confirmed cutoff
//! integration is intentionally deferred to a separate tinycloud-node ticket.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use opencredentials_verify::JWK;
use policy_core::{
    evaluate_operational_key_authorization, verify_signed_object, verify_signed_object_value,
    GrantChallenge, GrantPresentation, HolderBindingProof, HolderEnrollment,
    HolderEnrollmentStatus, OperationalKeyAuthorization, OperationalKeyRole, OperationalKeyStatus,
    OperationalKeyStatusTracker, Policy, PolicyCapability, PolicyStatus, PresentedEvidence,
    RevocationMode, Signature, SignatureSuite, SignedObjectError, VerifiedSignedObject,
};
use policy_evidence_vc::VcEvidenceVerifier;
use policy_runtime::{
    EvidenceProvenance, EvidenceSatisfaction, EvidenceVerifier, GrantIssueRequest, GrantIssuer,
    PolicyRuntime, PolicySpaceState, PortableDelegation, ProvenancedEvidenceSatisfaction,
    RuntimeConfig, RuntimeError, RuntimeEvidenceContext,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MIN_NONCE_LEN: usize = 16;
const MAX_NONCE_LEN: usize = 128;

type SharedRuntime = Arc<Mutex<PolicyEngineService>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParentCapabilityBound {
    pub policy_capability: PolicyCapability,
    pub native_resource: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedParentDelegateReceipt {
    pub delegation_id: String,
    pub delegatee_did: String,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub terminal: bool,
    pub capability_bounds: Vec<ParentCapabilityBound>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParentDelegationConfig {
    pub owner_did: String,
    /// Base64url-no-pad encoding of the exact DAG-CBOR bytes persisted by the owner flow.
    pub artifact_base64_url: String,
    pub expected_cid: String,
    pub audience: String,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub terminal: bool,
    pub capability_bounds: Vec<ParentCapabilityBound>,
    pub delegate_receipt: CapturedParentDelegateReceipt,
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub audience: String,
    pub challenge_ttl_seconds: i64,
    pub accepted_suites: Vec<SignatureSuite>,
    pub challenge_signer_seed: [u8; 32],
    pub grant_issuer_did: String,
    pub grant_issuer_signer_seed: [u8; 32],
    pub parent_delegations: Vec<ParentDelegationConfig>,
    pub issuer_keys: BTreeMap<String, JWK>,
    pub policies: Vec<Policy>,
    pub policy_statuses: Vec<PolicyStatus>,
    pub enrollment_statuses: Vec<HolderEnrollmentStatus>,
    pub policy_engine_records: Vec<policy_core::PolicyEngineRecord>,
    pub demo_operations_enabled: bool,
    pub demo_operations_bearer_token: Option<String>,
}

impl ServiceConfig {
    pub fn validate(&self) -> Result<(), StartupError> {
        self.validate_common(Utc::now())?;
        if self.has_authority_state() {
            return Err(StartupError::Invalid(
                "authority_state_requires_signed_objects",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_verified(&self) -> Result<(), StartupError> {
        self.validate_verified_at(Utc::now())
    }

    fn validate_verified_at(&self, now: DateTime<Utc>) -> Result<(), StartupError> {
        self.validate_common(now)?;
        self.validate_authority_state()
    }

    fn validate_common(&self, now: DateTime<Utc>) -> Result<(), StartupError> {
        if self.audience.trim().is_empty() {
            return Err(StartupError::Missing("audience"));
        }
        if self.challenge_ttl_seconds <= 0 {
            return Err(StartupError::Invalid("challenge_ttl_seconds"));
        }
        if self.accepted_suites.is_empty() {
            return Err(StartupError::Missing("accepted_suites"));
        }
        if !self
            .accepted_suites
            .iter()
            .any(|suite| suite == &SignatureSuite::EddsaEd25519Sha256JcsV1)
        {
            return Err(StartupError::Invalid("accepted_suites"));
        }
        if self.grant_issuer_did.trim().is_empty() {
            return Err(StartupError::Missing("grant_issuer_did"));
        }
        if did_key_from_ed25519(
            SigningKey::from_bytes(&self.grant_issuer_signer_seed)
                .verifying_key()
                .as_bytes(),
        ) != self.grant_issuer_did
        {
            return Err(StartupError::Invalid("grant_issuer_signer_seed"));
        }
        self.validate_parent_delegations(now)?;
        if self.issuer_keys.is_empty() {
            return Err(StartupError::Missing("issuer_keys"));
        }
        if self.demo_operations_enabled
            && self
                .demo_operations_bearer_token
                .as_deref()
                .is_none_or(|token| token.trim().is_empty())
        {
            return Err(StartupError::Missing("demo_operations_bearer_token"));
        }
        Ok(())
    }

    fn validate_parent_delegations(&self, now: DateTime<Utc>) -> Result<(), StartupError> {
        let mut parents = BTreeMap::new();
        for parent in &self.parent_delegations {
            if parent.owner_did.trim().is_empty() {
                return Err(StartupError::Missing("parent_delegations.owner_did"));
            }
            if parents.insert(parent.owner_did.as_str(), parent).is_some() {
                return Err(StartupError::Invalid("parent_delegations.owner_did"));
            }
            let artifact = URL_SAFE_NO_PAD
                .decode(&parent.artifact_base64_url)
                .map_err(|_| StartupError::Invalid("parent_delegations.artifact_base64_url"))?;
            if native_cid(&artifact) != parent.expected_cid {
                return Err(StartupError::Invalid("parent_delegations.expected_cid"));
            }
            if parent.audience != self.grant_issuer_did || parent.audience.contains('#') {
                return Err(StartupError::Invalid("parent_delegations.audience"));
            }
            if parent.terminal {
                return Err(StartupError::Invalid("parent_delegations.terminal"));
            }
            if parent.expires_at <= now
                || parent
                    .not_before
                    .is_some_and(|not_before| not_before > now || not_before >= parent.expires_at)
            {
                return Err(StartupError::Invalid("parent_delegations.validity"));
            }
            if parent.capability_bounds.is_empty()
                || parent.capability_bounds.iter().any(|bound| {
                    let owner_prefix = parent
                        .owner_did
                        .strip_prefix("did:")
                        .map(|owner| format!("tinycloud:{owner}:"));
                    let service = bound.policy_capability.service.strip_prefix("tinycloud.");
                    bound.native_resource.trim().is_empty()
                        || owner_prefix
                            .as_deref()
                            .is_none_or(|prefix| !bound.native_resource.starts_with(prefix))
                        || service.is_none_or(|service| {
                            !bound
                                .native_resource
                                .ends_with(&format!("/{service}/{}", bound.policy_capability.path))
                        })
                })
            {
                return Err(StartupError::Invalid(
                    "parent_delegations.capability_bounds",
                ));
            }
            let receipt = &parent.delegate_receipt;
            if receipt.delegation_id != parent.expected_cid
                || receipt.delegatee_did != parent.audience
                || receipt.not_before != parent.not_before
                || receipt.expires_at != parent.expires_at
                || receipt.terminal != parent.terminal
                || receipt.capability_bounds != parent.capability_bounds
            {
                return Err(StartupError::Invalid("parent_delegations.delegate_receipt"));
            }
        }

        for policy in &self.policies {
            if policy.grant.max_ttl_seconds > 300 {
                return Err(StartupError::Invalid("policies.grant.max_ttl_seconds"));
            }
            if !matches!(
                policy.grant.delegation_mode,
                policy_core::DelegationMode::Terminal
            ) {
                return Err(StartupError::Invalid("policies.grant.delegation_mode"));
            }
            let parent = parents
                .get(policy.owner_did.as_str())
                .ok_or(StartupError::Invalid("parent_delegations.policy_owner"))?;
            for capability in &policy.resource.permissions_ceiling {
                if matching_parent_bound(&parent.capability_bounds, capability).is_err() {
                    return Err(StartupError::Invalid(
                        "parent_delegations.policy_capability_bounds",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_authority_state(&self) -> Result<(), StartupError> {
        for record in &self.policy_engine_records {
            parse_rfc3339(&record.expires_at)
                .map_err(|_| StartupError::Invalid("policy_engine_record.expires_at"))?;
            if record.audience != self.audience {
                return Err(StartupError::Invalid("policy_engine_record.audience"));
            }
            if record.grant_issuer_did != self.grant_issuer_did {
                return Err(StartupError::Invalid(
                    "policy_engine_record.grant_issuer_did",
                ));
            }
        }
        for policy in &self.policies {
            parse_rfc3339(&policy.created_at)
                .map_err(|_| StartupError::Invalid("policy.created_at"))?;
            if let Some(expires_at) = &policy.expires_at {
                parse_rfc3339(expires_at)
                    .map_err(|_| StartupError::Invalid("policy.expires_at"))?;
            }
        }
        for status in &self.policy_statuses {
            parse_rfc3339(&status.effective_at)
                .map_err(|_| StartupError::Invalid("policy_status.effective_at"))?;
        }
        for status in &self.enrollment_statuses {
            parse_rfc3339(&status.effective_at)
                .map_err(|_| StartupError::Invalid("enrollment_status.effective_at"))?;
        }
        Ok(())
    }

    fn has_authority_state(&self) -> bool {
        !self.policies.is_empty()
            || !self.policy_statuses.is_empty()
            || !self.enrollment_statuses.is_empty()
            || !self.policy_engine_records.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("missing required config: {0}")]
    Missing(&'static str),
    #[error("invalid config: {0}")]
    Invalid(&'static str),
    #[error("unsupported signed object in startup load path: {0}")]
    UnsupportedSignedObject(&'static str),
    #[error("runtime seed failed: {0}")]
    Runtime(#[from] RuntimeError),
}

#[derive(Clone, Debug, Default)]
pub struct GrantIssuerState {
    issued: BTreeMap<String, PortableDelegation>,
    ledger_by_issuance_id: BTreeMap<String, IssuanceLedgerRecord>,
    issuance_id_by_encoded: BTreeMap<String, String>,
    issuance_id_by_cid: BTreeMap<String, String>,
    revoked: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceLedgerRecord {
    pub issuance_id: String,
    pub encoded: String,
    pub delegation_id: String,
}

#[derive(Clone, Debug)]
pub struct SharedGrantIssuer {
    issuer_did: String,
    signing_key: SigningKey,
    parents: BTreeMap<String, ParentDelegationConfig>,
    state: Arc<Mutex<GrantIssuerState>>,
}

impl SharedGrantIssuer {
    pub fn new(
        issuer_did: impl Into<String>,
        signing_key: SigningKey,
        parents: impl IntoIterator<Item = ParentDelegationConfig>,
    ) -> Self {
        Self {
            issuer_did: issuer_did.into(),
            signing_key,
            parents: parents
                .into_iter()
                .map(|parent| (parent.owner_did.clone(), parent))
                .collect(),
            state: Arc::new(Mutex::new(GrantIssuerState::default())),
        }
    }

    pub fn issued(&self, delegation_id: &str) -> Option<PortableDelegation> {
        self.state
            .lock()
            .expect("grant issuer state lock")
            .issued
            .get(delegation_id)
            .cloned()
    }

    pub fn is_revoked(&self, delegation_id: &str) -> bool {
        self.state
            .lock()
            .expect("grant issuer state lock")
            .revoked
            .contains(delegation_id)
    }

    pub fn issuance_link(&self, issuance_id: &str) -> Option<IssuanceLedgerRecord> {
        self.state
            .lock()
            .expect("grant issuer state lock")
            .ledger_by_issuance_id
            .get(issuance_id)
            .cloned()
    }

    fn issue_candidate(
        &mut self,
        request: GrantIssueRequest,
        issuance_id: String,
        facts: Option<Vec<Value>>,
    ) -> Result<PortableDelegation, RuntimeError> {
        let mut state = self.state.lock().expect("grant issuer state lock");
        let parent = self
            .parents
            .get(&request.policy.owner_did)
            .ok_or_else(|| grant_error("configured-parent-missing"))?;
        validate_issue_request(&request, parent)?;
        let facts = facts.unwrap_or_else(|| provenance_facts(&request, &issuance_id));
        let encoded = encode_ucan(
            &request,
            &self.issuer_did,
            &self.signing_key,
            parent,
            &issuance_id,
            facts,
        )?;
        let delegation_id = native_cid(encoded.as_bytes());
        let delegation = PortableDelegation {
            delegation_id: delegation_id.clone(),
            issuer_did: self.issuer_did.clone(),
            holder_did: request.holder_did.clone(),
            policy_id: request.policy.policy_id.clone(),
            capabilities: request.capabilities.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            terminal: request.terminal,
            encoded: encoded.clone(),
        };
        Self::commit(
            &mut state,
            IssuanceLedgerRecord {
                issuance_id,
                encoded,
                delegation_id,
            },
            delegation.clone(),
        )?;
        Ok(delegation)
    }

    fn commit(
        state: &mut GrantIssuerState,
        record: IssuanceLedgerRecord,
        delegation: PortableDelegation,
    ) -> Result<(), RuntimeError> {
        let audit_record = record.clone();
        if state
            .ledger_by_issuance_id
            .contains_key(&record.issuance_id)
        {
            return Err(grant_error("duplicate-issuance-id-conflict"));
        }
        if state.issuance_id_by_encoded.contains_key(&record.encoded) {
            return Err(grant_error("duplicate-encoded-delegation-conflict"));
        }
        if state.issuance_id_by_cid.contains_key(&record.delegation_id)
            || state.issued.contains_key(&record.delegation_id)
        {
            return Err(grant_error("duplicate-delegation-id-conflict"));
        }
        validate_ledger_record(&record, true)?;
        if delegation.delegation_id != record.delegation_id || delegation.encoded != record.encoded
        {
            return Err(grant_error("ledger-cid-mismatch"));
        }

        state
            .issuance_id_by_encoded
            .insert(record.encoded.clone(), record.issuance_id.clone());
        state
            .issuance_id_by_cid
            .insert(record.delegation_id.clone(), record.issuance_id.clone());
        state
            .issued
            .insert(record.delegation_id.clone(), delegation);
        state
            .ledger_by_issuance_id
            .insert(record.issuance_id.clone(), record);
        audit_ledger_linkage(state, &audit_record, true)
    }
}

impl GrantIssuer for SharedGrantIssuer {
    fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    fn issue(&mut self, request: GrantIssueRequest) -> Result<PortableDelegation, RuntimeError> {
        let issuance_id = new_issuance_id()?;
        self.issue_candidate(request, issuance_id, None)
    }

    fn revoke(&mut self, delegation_id: &str) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().expect("grant issuer state lock");
        if !state.issued.contains_key(delegation_id) {
            return Err(RuntimeError::ActiveCutoffFailed(delegation_id.to_string()));
        }
        state.revoked.insert(delegation_id.to_string());
        Ok(())
    }
}

fn validate_ledger_record(
    record: &IssuanceLedgerRecord,
    atomic_commit: bool,
) -> Result<(), RuntimeError> {
    if !atomic_commit {
        return Err(grant_error("issuance-linkage-not-atomic"));
    }
    if record.issuance_id.trim().is_empty()
        || record.encoded.trim().is_empty()
        || native_cid(record.encoded.as_bytes()) != record.delegation_id
    {
        return Err(grant_error("ledger-cid-mismatch"));
    }
    Ok(())
}

fn audit_ledger_linkage(
    state: &GrantIssuerState,
    record: &IssuanceLedgerRecord,
    atomic_commit: bool,
) -> Result<(), RuntimeError> {
    validate_ledger_record(record, atomic_commit)?;
    let stored = state
        .ledger_by_issuance_id
        .get(&record.issuance_id)
        .ok_or_else(|| grant_error("issuance-ledger-record-missing"))?;
    if stored != record
        || state.issuance_id_by_encoded.get(&record.encoded) != Some(&record.issuance_id)
        || state.issuance_id_by_cid.get(&record.delegation_id) != Some(&record.issuance_id)
        || state
            .issued
            .get(&record.delegation_id)
            .is_none_or(|delegation| {
                delegation.encoded != record.encoded
                    || delegation.delegation_id != record.delegation_id
            })
    {
        return Err(grant_error("ledger-cid-mismatch"));
    }
    Ok(())
}

fn grant_error(reason: &str) -> RuntimeError {
    RuntimeError::GrantIssuanceFailed(reason.to_string())
}

fn new_issuance_id() -> Result<String, RuntimeError> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| grant_error("issuance-id-generation-failed"))?;
    Ok(format!("iss_{}", data_encoding::HEXLOWER.encode(&random)))
}

fn native_cid(bytes: &[u8]) -> String {
    let mut cid = Vec::with_capacity(36);
    cid.extend_from_slice(&[0x01, 0x55, 0x1e, 0x20]);
    cid.extend_from_slice(blake3::hash(bytes).as_bytes());
    format!(
        "b{}",
        data_encoding::BASE32_NOPAD.encode(&cid).to_lowercase()
    )
}

fn matching_parent_bound<'a>(
    bounds: &'a [ParentCapabilityBound],
    capability: &PolicyCapability,
) -> Result<&'a ParentCapabilityBound, RuntimeError> {
    let matches = bounds
        .iter()
        .filter(|bound| bound.policy_capability.contains(capability).is_ok())
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [bound] => Ok(*bound),
        [] => Err(grant_error("issue-time-parent-containment-failure")),
        _ => Err(grant_error("ambiguous-parent-capability-bound")),
    }
}

fn native_resource_for(
    bound: &ParentCapabilityBound,
    capability: &PolicyCapability,
) -> Result<String, RuntimeError> {
    if bound.policy_capability.path == capability.path {
        return Ok(bound.native_resource.clone());
    }
    let prefix = bound
        .native_resource
        .strip_suffix(&bound.policy_capability.path)
        .ok_or_else(|| grant_error("parent-native-resource-mapping-invalid"))?;
    Ok(format!("{prefix}{}", capability.path))
}

fn validate_issue_request(
    request: &GrantIssueRequest,
    parent: &ParentDelegationConfig,
) -> Result<(), RuntimeError> {
    if !request.terminal
        || !matches!(
            request.policy.grant.delegation_mode,
            policy_core::DelegationMode::Terminal
        )
    {
        return Err(grant_error("missing-terminal-mode-fact"));
    }
    if !matches!(request.policy.grant.revocation, RevocationMode::RefreshOnly) {
        return Err(grant_error("unsupported-m1-revocation-mode"));
    }
    if request.expires_at <= request.issued_at
        || request.expires_at
            > request.issued_at
                + chrono::Duration::seconds(request.policy.grant.max_ttl_seconds as i64)
        || request.expires_at > parent.expires_at
        || request.expires_at > request.presentation_expires_at
        || parent
            .not_before
            .is_some_and(|not_before| request.issued_at < not_before)
    {
        return Err(grant_error("expiry-ceiling-exceeded"));
    }
    if let Some(policy_expires_at) = request.policy.expires_at.as_deref() {
        let policy_expires_at = DateTime::parse_from_rfc3339(policy_expires_at)
            .map_err(|_| grant_error("policy-expiry-invalid"))?
            .with_timezone(&Utc);
        if request.expires_at > policy_expires_at {
            return Err(grant_error("expiry-ceiling-exceeded"));
        }
    }
    if request.capabilities.is_empty() {
        return Err(grant_error("empty-capability-set"));
    }
    for capability in &request.capabilities {
        matching_parent_bound(&parent.capability_bounds, capability)?;
    }
    Ok(())
}

fn validate_provenance_facts(
    facts: &[Value],
    request: &GrantIssueRequest,
    issuance_id: &str,
) -> Result<(), RuntimeError> {
    if facts.len() != 1 {
        return Err(grant_error("duplicate-provenance-fact"));
    }
    let object = facts[0]
        .as_object()
        .ok_or_else(|| grant_error("malformed-provenance-fact"))?;
    let required = [
        "xyz.tinycloud.policy/capabilityHashHex",
        "xyz.tinycloud.policy/delegationMode",
        "xyz.tinycloud.policy/issuanceId",
        "xyz.tinycloud.policy/policyId",
        "xyz.tinycloud.policy/revocationMode",
    ];
    if object.len() != required.len()
        || required.iter().any(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        || object["xyz.tinycloud.policy/delegationMode"] != "terminal"
        || object["xyz.tinycloud.policy/revocationMode"] != "refresh_only"
        || object["xyz.tinycloud.policy/capabilityHashHex"]
            .as_str()
            .is_none_or(|hash| {
                hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(grant_error("malformed-provenance-fact"));
    }
    let expected_hash = if request.capabilities.len() == 1 {
        request.capabilities[0].capability_hash_hex()
    } else {
        policy_core::requested_capabilities_hash_hex(&request.capabilities)
    };
    if object["xyz.tinycloud.policy/policyId"] != request.policy.policy_id
        || object["xyz.tinycloud.policy/capabilityHashHex"] != expected_hash
        || object["xyz.tinycloud.policy/issuanceId"] != issuance_id
    {
        return Err(grant_error("malformed-provenance-fact"));
    }
    Ok(())
}

fn provenance_facts(request: &GrantIssueRequest, issuance_id: &str) -> Vec<Value> {
    let capability_hash = if request.capabilities.len() == 1 {
        request.capabilities[0].capability_hash_hex()
    } else {
        policy_core::requested_capabilities_hash_hex(&request.capabilities)
    };
    vec![serde_json::json!({
        "xyz.tinycloud.policy/capabilityHashHex": capability_hash,
        "xyz.tinycloud.policy/delegationMode": "terminal",
        "xyz.tinycloud.policy/issuanceId": issuance_id,
        "xyz.tinycloud.policy/policyId": request.policy.policy_id,
        "xyz.tinycloud.policy/revocationMode": "refresh_only",
    })]
}

fn encode_ucan(
    request: &GrantIssueRequest,
    issuer_did: &str,
    signing_key: &SigningKey,
    parent: &ParentDelegationConfig,
    issuance_id: &str,
    facts: Vec<Value>,
) -> Result<String, RuntimeError> {
    if did_key_from_ed25519(signing_key.verifying_key().as_bytes()) != issuer_did {
        return Err(grant_error("grant-issuer-signer-mismatch"));
    }
    let public = signing_key.verifying_key();
    let multibase = issuer_did
        .strip_prefix("did:key:")
        .ok_or_else(|| grant_error("grant-issuer-did-invalid"))?;
    let issuer_url = format!("{issuer_did}#{multibase}");
    let header = serde_json::json!({
        "alg": "EdDSA",
        "jwk": {
            "alg": "EdDSA",
            "crv": "Ed25519",
            "kty": "OKP",
            "x": URL_SAFE_NO_PAD.encode(public.as_bytes()),
        },
        "typ": "JWT",
        "ucv": "0.10.0",
    });

    let mut attenuation: BTreeMap<String, BTreeMap<String, Vec<Value>>> = BTreeMap::new();
    for capability in &request.capabilities {
        let bound = matching_parent_bound(&parent.capability_bounds, capability)?;
        let resource = native_resource_for(bound, capability)?;
        let abilities = attenuation.entry(resource).or_default();
        for action in &capability.actions {
            let nota_bene = vec![capability
                .caveats
                .clone()
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()))];
            if let Some(existing) = abilities.insert(action.clone(), nota_bene.clone()) {
                if existing != nota_bene {
                    return Err(grant_error("conflicting-capability-caveats"));
                }
            }
        }
    }
    validate_provenance_facts(&facts, request, issuance_id)?;
    let payload = serde_json::json!({
        "att": attenuation,
        "aud": request.holder_did,
        "exp": request.expires_at.timestamp(),
        "fct": facts,
        "iss": issuer_url,
        "nbf": request.issued_at.timestamp(),
        "nnc": issuance_id,
        "prf": [parent.expected_cid.clone()],
    });
    let header = URL_SAFE_NO_PAD.encode(policy_core::jcs::canonicalize(&header));
    let payload = URL_SAFE_NO_PAD.encode(policy_core::jcs::canonicalize(&payload));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(signing_input.as_bytes()).to_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

#[derive(Clone, Debug)]
pub struct SharedVcEvidenceVerifier {
    issuer_keys: Arc<Mutex<BTreeMap<String, JWK>>>,
}

impl SharedVcEvidenceVerifier {
    pub fn new(issuer_keys: BTreeMap<String, JWK>) -> Self {
        Self {
            issuer_keys: Arc::new(Mutex::new(issuer_keys)),
        }
    }

    fn verifier(&self) -> VcEvidenceVerifier {
        VcEvidenceVerifier::new(self.issuer_keys.lock().expect("issuer keys lock").clone())
    }
}

impl EvidenceVerifier for SharedVcEvidenceVerifier {
    fn verify(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        presentation: &Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<EvidenceSatisfaction, RuntimeError> {
        let satisfaction = self.verify_with_provenance(requirement, presentation, context)?;
        Ok(EvidenceSatisfaction {
            evidence_ids: satisfaction.evidence_ids,
            valid_until: satisfaction.valid_until,
            expiry_bound_required: satisfaction.expiry_bound_required,
        })
    }

    fn verify_with_provenance(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        presentation: &Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<ProvenancedEvidenceSatisfaction, RuntimeError> {
        let verifier = self.verifier();
        if requirement.freshness.is_some() && evidence_freshness_unestablishable(presentation) {
            return Err(RuntimeError::Evidence(
                "evidence-freshness-unestablishable".to_string(),
            ));
        }
        let vc_context = policy_evidence_vc::VerificationContext {
            policy: context.policy.clone(),
            eligible_subject_did: context.eligible_subject_did.clone(),
            holder_did: context.holder_did.clone(),
            requested_capabilities: context.requested_capabilities.clone(),
            now: context.now,
        };
        let normalized = normalize_evidence_presentation(presentation);
        let satisfaction = verifier
            .verify(requirement, &normalized, &vc_context)
            .map_err(|error| RuntimeError::Evidence(error.as_str().to_string()))?;
        Ok(ProvenancedEvidenceSatisfaction {
            requirement_id: requirement.requirement_id.clone(),
            evidence_ids: satisfaction.evidence_ids,
            provenance: EvidenceProvenance {
                family: satisfaction.evidence_provenance.family,
                source_evidence_id: satisfaction.evidence_provenance.source_evidence_id,
                attributes: satisfaction.evidence_provenance.attributes,
            },
            valid_until: Some(satisfaction.valid_until),
            expiry_bound_required: true,
        })
    }
}

fn evidence_freshness_unestablishable(_presentation: &Value) -> bool {
    true
}

fn normalize_evidence_presentation(presentation: &Value) -> Value {
    if presentation.get("sdJwt").is_some() {
        return presentation.clone();
    }
    presentation
        .get("value")
        .and_then(Value::as_str)
        .map(|sd_jwt| serde_json::json!({ "sdJwt": sd_jwt }))
        .unwrap_or_else(|| presentation.clone())
}

#[derive(Clone)]
struct ChallengeSigner {
    signing_key: SigningKey,
    signer_did: String,
}

impl ChallengeSigner {
    fn new(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let signer_did = did_key_from_ed25519(signing_key.verifying_key().as_bytes());
        Self {
            signing_key,
            signer_did,
        }
    }

    fn placeholder_signature(&self) -> Signature {
        Signature {
            suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
            signer_did: self.signer_did.clone(),
            value: String::new(),
        }
    }
}

impl policy_runtime::ChallengeSigner for ChallengeSigner {
    fn sign_challenge(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Signature, policy_runtime::ChallengeSigningError> {
        Ok(Signature {
            suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
            signer_did: self.signer_did.clone(),
            value: URL_SAFE_NO_PAD.encode(self.signing_key.sign(digest).to_bytes()),
        })
    }
}

fn did_key_from_ed25519(public_key: &[u8]) -> String {
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(public_key);
    format!("did:key:z{}", bs58::encode(multicodec).into_string())
}

pub struct PolicyEngineService {
    runtime: PolicyRuntime<SharedGrantIssuer, SharedVcEvidenceVerifier>,
    challenge_signer: ChallengeSigner,
    grant_issuer_did: String,
    authority_index: AuthorityIndex,
    policy_revocations: BTreeMap<String, RevocationMode>,
    demo_operations_enabled: bool,
    demo_operations_bearer_token: Option<String>,
    fixed_now: Option<DateTime<Utc>>,
}

impl PolicyEngineService {
    pub fn try_new(config: ServiceConfig) -> Result<Self, StartupError> {
        #[cfg(test)]
        if config.has_authority_state() {
            return Self::try_new_trusted_for_tests(config);
        }
        config.validate()?;
        Self::build_after_validation(config)
    }

    #[cfg(test)]
    fn try_new_trusted_for_tests(config: ServiceConfig) -> Result<Self, StartupError> {
        config.validate_verified()?;
        Self::build_after_validation(config)
    }

    fn build_after_validation(config: ServiceConfig) -> Result<Self, StartupError> {
        let grant_issuer_did = config.grant_issuer_did.clone();
        let policy_revocations = config
            .policies
            .iter()
            .map(|policy| (policy.policy_id.clone(), policy.grant.revocation.clone()))
            .collect();
        let grant_issuer = SharedGrantIssuer::new(
            grant_issuer_did.clone(),
            SigningKey::from_bytes(&config.grant_issuer_signer_seed),
            config.parent_delegations,
        );
        let evidence_verifier = SharedVcEvidenceVerifier::new(config.issuer_keys);
        let challenge_signer = ChallengeSigner::new(config.challenge_signer_seed);
        let runtime_config = RuntimeConfig {
            audience: config.audience,
            challenge_ttl_seconds: config.challenge_ttl_seconds,
            accepted_suites: config.accepted_suites,
            challenge_signature: challenge_signer.placeholder_signature(),
        };
        let mut state = PolicySpaceState::default();
        for policy in config.policies {
            state.insert_policy(policy);
        }
        for status in config.policy_statuses {
            state.insert_policy_status(status)?;
        }
        for status in config.enrollment_statuses {
            state
                .enrollment_tracker_mut()
                .apply_status(&status)
                .map_err(|error| RuntimeError::HolderBinding(error.as_str().to_string()))?;
        }
        Ok(Self {
            runtime: PolicyRuntime::new(
                runtime_config,
                state,
                evidence_verifier.clone(),
                grant_issuer.clone(),
            ),
            challenge_signer,
            grant_issuer_did,
            authority_index: AuthorityIndex::default(),
            policy_revocations,
            demo_operations_enabled: config.demo_operations_enabled,
            demo_operations_bearer_token: config.demo_operations_bearer_token,
            fixed_now: None,
        })
    }

    pub fn from_signed_objects(
        config: ServiceConfig,
        objects: impl IntoIterator<Item = Value>,
    ) -> Result<Self, StartupError> {
        Self::from_signed_objects_at(config, objects, Utc::now())
    }

    #[cfg(test)]
    fn from_signed_objects_at_for_tests(
        config: ServiceConfig,
        objects: impl IntoIterator<Item = Value>,
        validation_now: DateTime<Utc>,
    ) -> Result<Self, StartupError> {
        Self::from_signed_objects_at(config, objects, validation_now)
    }

    fn from_signed_objects_at(
        mut config: ServiceConfig,
        objects: impl IntoIterator<Item = Value>,
        validation_now: DateTime<Utc>,
    ) -> Result<Self, StartupError> {
        if !config.policies.is_empty()
            || !config.policy_statuses.is_empty()
            || !config.enrollment_statuses.is_empty()
            || !config.policy_engine_records.is_empty()
        {
            return Err(StartupError::Invalid("signed_objects.preloaded_state"));
        }

        let mut verified = Vec::new();
        for object in objects {
            verified.push(
                verify_signed_object_value(&object)
                    .map_err(|_| StartupError::Invalid("signed_objects"))?,
            );
        }
        let authority_index = AuthorityIndex::from_verified(&verified)?;
        let mut loaded_enrollments = BTreeMap::new();
        for object in verified {
            match object {
                VerifiedSignedObject::Policy(policy) => {
                    validate_policy_authority(&policy, &authority_index, validation_now)?;
                    config.policies.push(policy);
                }
                VerifiedSignedObject::PolicyStatus(status) => {
                    validate_policy_status_authority(
                        &status,
                        &config.policies,
                        &authority_index,
                        validation_now,
                    )?;
                    config.policy_statuses.push(status);
                }
                VerifiedSignedObject::HolderEnrollmentStatus(status) => {
                    validate_enrollment_status_authority(
                        &status,
                        &loaded_enrollments,
                        &authority_index,
                        validation_now,
                    )?;
                    config.enrollment_statuses.push(status)
                }
                VerifiedSignedObject::PolicyEngineRecord(record) => {
                    validate_policy_engine_record_authority(
                        &record,
                        &authority_index,
                        validation_now,
                    )?;
                    config.policy_engine_records.push(record)
                }
                VerifiedSignedObject::HolderEnrollment(enrollment) => {
                    validate_enrollment_authority(&enrollment, &authority_index, validation_now)?;
                    loaded_enrollments.insert(enrollment.enrollment_id.clone(), enrollment);
                }
                VerifiedSignedObject::OperationalKeyAuthorization(_)
                | VerifiedSignedObject::OperationalKeyStatus(_) => {}
                VerifiedSignedObject::GrantChallenge(_) => {
                    return Err(StartupError::UnsupportedSignedObject("GrantChallenge"));
                }
            }
        }
        validate_policy_engine_records_cover_policies(&config, &authority_index, validation_now)?;
        let mut service = Self::build_verified_at(config, validation_now)?;
        service.authority_index = authority_index;
        Ok(service)
    }

    fn build_verified_at(
        config: ServiceConfig,
        validation_now: DateTime<Utc>,
    ) -> Result<Self, StartupError> {
        config.validate_verified_at(validation_now)?;
        Self::build_after_validation(config)
    }

    pub fn router(self) -> Router {
        router(self)
    }

    pub fn with_fixed_now_for_tests(mut self, now: DateTime<Utc>) -> Self {
        self.fixed_now = Some(now);
        self
    }

    pub fn issuance(&self, delegation_id: &str) -> Option<&policy_runtime::IssuanceRecord> {
        self.runtime.state().issuance(delegation_id)
    }

    pub fn issuance_link(&self, issuance_id: &str) -> Option<IssuanceLedgerRecord> {
        self.runtime.grant_issuer().issuance_link(issuance_id)
    }

    fn issue_challenge(
        &mut self,
        request: ChallengeRequest,
    ) -> Result<GrantChallenge, AdapterError> {
        let now = self.now();
        Ok(self.runtime.issue_challenge_signed(
            &request.policy_id,
            now,
            &mut self.challenge_signer,
        )?)
    }

    #[cfg(test)]
    fn issue_challenge_with_nonce_for_tests(
        &mut self,
        policy_id: &str,
        nonce: String,
    ) -> Result<GrantChallenge, AdapterError> {
        let now = self.now();
        Ok(self.runtime.issue_challenge_with_nonce_signed(
            policy_id,
            now,
            nonce,
            &mut self.challenge_signer,
        )?)
    }

    fn resolve(&mut self, request: ResolveRequest) -> Result<PortableDelegation, AdapterError> {
        let now = self.now();
        let presentation = match request.into_presentation()? {
            ParsedPresentation::Valid(presentation) => presentation,
            ParsedPresentation::SchemaInvalid(presentation) => {
                validate_nonce(&presentation.nonce)?;
                self.consume_nonce_for_rejected_presentation(
                    &presentation,
                    now,
                    &AdapterError::SchemaInvalid,
                )?;
                return Err(AdapterError::SchemaInvalid);
            }
        };
        validate_nonce(&presentation.nonce)?;
        validate_requested_capabilities_hash_format(&presentation)?;
        if let Err(error) = validate_authority_dates(&presentation).and_then(|_| {
            validate_holder_enrollment_signature(&presentation, &self.authority_index, now)
        }) {
            self.consume_nonce_for_rejected_presentation(&presentation, now, &error)?;
            return Err(error);
        }
        let delegation = self.runtime.resolve(presentation, now)?;
        if delegation.issuer_did != self.grant_issuer_did {
            return Err(AdapterError::Runtime(RuntimeError::GrantIssuanceFailed(
                "grant-issuer-mismatch".to_string(),
            )));
        }
        Ok(delegation)
    }

    fn active_cutoff(
        &mut self,
        policy_id: &str,
        headers: &HeaderMap,
    ) -> Result<Vec<String>, AdapterError> {
        if !self.demo_operations_enabled {
            return Err(AdapterError::OperationalDenied);
        }
        self.require_demo_bearer(headers)?;
        let Some(revocation) = self.policy_revocations.get(policy_id) else {
            return Err(AdapterError::Runtime(RuntimeError::PolicyNotFound));
        };
        if revocation != &RevocationMode::ActiveCutoff {
            return Err(AdapterError::Runtime(RuntimeError::ActiveCutoffFailed(
                "policy-revocation-not-active-cutoff".to_string(),
            )));
        }
        if policy_id.trim().is_empty() {
            return Err(AdapterError::Runtime(RuntimeError::ActiveCutoffFailed(
                "policy-id-empty".to_string(),
            )));
        }
        Ok(self.runtime.active_cutoff_policy(policy_id)?)
    }

    fn now(&self) -> DateTime<Utc> {
        self.fixed_now.unwrap_or_else(Utc::now)
    }

    fn consume_nonce_for_rejected_presentation(
        &mut self,
        presentation: &GrantPresentation,
        now: DateTime<Utc>,
        _original_error: &AdapterError,
    ) -> Result<(), AdapterError> {
        let mut sabotaged = presentation.clone();
        sabotaged.audience = "__policy-engine-http-rejected-presentation__".to_string();
        match self.runtime.resolve(sabotaged, now) {
            Ok(_) => Err(AdapterError::Runtime(RuntimeError::GrantIssuanceFailed(
                "rejected-presentation-issued".to_string(),
            ))),
            Err(
                error @ (RuntimeError::PolicyNotFound
                | RuntimeError::PolicyInactive
                | RuntimeError::PolicyExpired
                | RuntimeError::PolicyStatusRollback
                | RuntimeError::ChallengeNotFound
                | RuntimeError::ChallengeNonceConsumed),
            ) => Err(AdapterError::Runtime(error)),
            Err(RuntimeError::Presentation(code)) if code == "challenge-expired" => {
                Err(AdapterError::Runtime(RuntimeError::Presentation(code)))
            }
            Err(_) => Ok(()),
        }
    }

    fn require_demo_bearer(&self, headers: &HeaderMap) -> Result<(), AdapterError> {
        let Some(expected) = self.demo_operations_bearer_token.as_deref() else {
            return Err(AdapterError::OperationalDenied);
        };
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if presented == Some(expected) {
            Ok(())
        } else {
            Err(AdapterError::OperationalDenied)
        }
    }
}

#[derive(Clone, Debug)]
struct AuthorizationEntry {
    authorization: OperationalKeyAuthorization,
    status: Option<OperationalKeyStatus>,
}

struct AuthorizationCheck<'a> {
    owner_did: &'a str,
    key_did: &'a str,
    required_role: OperationalKeyRole,
    signed_at: DateTime<Utc>,
    artifact_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
struct AuthorityIndex {
    policy_signers: BTreeMap<(String, String), Vec<AuthorizationEntry>>,
    grant_issuers: BTreeMap<(String, String), Vec<AuthorizationEntry>>,
}

impl AuthorityIndex {
    fn from_verified(objects: &[VerifiedSignedObject]) -> Result<Self, StartupError> {
        let mut index = Self::default();
        let mut authorizations = BTreeMap::new();
        for object in objects {
            if let VerifiedSignedObject::OperationalKeyAuthorization(authorization) = object {
                validate_operational_authorization_dates(authorization)?;
                if authorizations
                    .insert(
                        authorization.authorization_id.clone(),
                        authorization.clone(),
                    )
                    .is_some()
                {
                    return Err(StartupError::Invalid(
                        "operational_key_authorization.duplicate",
                    ));
                }
            }
        }

        let mut tracker = OperationalKeyStatusTracker::new();
        let mut statuses_by_authorization = BTreeMap::new();
        for object in objects {
            if let VerifiedSignedObject::OperationalKeyStatus(status) = object {
                validate_operational_status_authority(status, &authorizations)?;
                tracker
                    .apply_status(status)
                    .map_err(|_| StartupError::Invalid("operational_key_status.sequence"))?;
                statuses_by_authorization.insert(status.authorization_id.clone(), status.clone());
            }
        }

        for authorization in authorizations.values() {
            let entry = AuthorizationEntry {
                authorization: authorization.clone(),
                status: statuses_by_authorization
                    .get(&authorization.authorization_id)
                    .cloned(),
            };
            for role in &authorization.roles {
                match role {
                    OperationalKeyRole::PolicySigner => {
                        index
                            .policy_signers
                            .entry((
                                authorization.owner_did.clone(),
                                authorization.key_did.clone(),
                            ))
                            .or_default()
                            .push(entry.clone());
                    }
                    OperationalKeyRole::GrantIssuer => {
                        index
                            .grant_issuers
                            .entry((
                                authorization.owner_did.clone(),
                                authorization.key_did.clone(),
                            ))
                            .or_default()
                            .push(entry.clone());
                    }
                    OperationalKeyRole::TrustIssuer => {}
                }
            }
        }
        Ok(index)
    }

    fn policy_signer_authorized(
        &self,
        owner_did: &str,
        signer_did: &str,
        signed_at: DateTime<Utc>,
        artifact_expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> bool {
        owner_did == signer_did
            || self.role_authorized(
                &self.policy_signers,
                AuthorizationCheck {
                    owner_did,
                    key_did: signer_did,
                    required_role: OperationalKeyRole::PolicySigner,
                    signed_at,
                    artifact_expires_at,
                    now,
                },
            )
    }

    fn grant_issuer_authorized(
        &self,
        owner_did: &str,
        grant_issuer_did: &str,
        signed_at: DateTime<Utc>,
        artifact_expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> bool {
        self.role_authorized(
            &self.grant_issuers,
            AuthorizationCheck {
                owner_did,
                key_did: grant_issuer_did,
                required_role: OperationalKeyRole::GrantIssuer,
                signed_at,
                artifact_expires_at,
                now,
            },
        )
    }

    fn role_authorized(
        &self,
        entries: &BTreeMap<(String, String), Vec<AuthorizationEntry>>,
        check: AuthorizationCheck<'_>,
    ) -> bool {
        entries
            .get(&(check.owner_did.to_string(), check.key_did.to_string()))
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    evaluate_operational_key_authorization(
                        &entry.authorization,
                        check.required_role.clone(),
                        None,
                        entry.status.as_ref(),
                        check.signed_at,
                        check.artifact_expires_at,
                        check.now,
                    )
                    .is_ok()
                })
            })
    }
}

fn validate_operational_authorization_dates(
    authorization: &OperationalKeyAuthorization,
) -> Result<(), StartupError> {
    parse_rfc3339(&authorization.not_before)
        .map_err(|_| StartupError::Invalid("operational_key_authorization.not_before"))?;
    if let Some(expires_at) = &authorization.expires_at {
        parse_rfc3339(expires_at)
            .map_err(|_| StartupError::Invalid("operational_key_authorization.expires_at"))?;
    }
    Ok(())
}

fn validate_operational_status_authority(
    status: &OperationalKeyStatus,
    authorizations: &BTreeMap<String, OperationalKeyAuthorization>,
) -> Result<(), StartupError> {
    let authorization =
        authorizations
            .get(&status.authorization_id)
            .ok_or(StartupError::Invalid(
                "operational_key_status.authorization_id",
            ))?;
    if status.signature.signer_did != authorization.owner_did {
        return Err(StartupError::Invalid("operational_key_status.authority"));
    }
    parse_rfc3339(&status.effective_at)
        .map_err(|_| StartupError::Invalid("operational_key_status.effective_at"))?;
    Ok(())
}

fn validate_policy_authority(
    policy: &Policy,
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), StartupError> {
    let signed_at = parse_rfc3339(&policy.created_at)
        .map_err(|_| StartupError::Invalid("policy.created_at"))?;
    let artifact_expires_at = policy
        .expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|_| StartupError::Invalid("policy.expires_at"))?;
    if policy.signature.signer_did != policy.signing_key_did
        || !authority_index.policy_signer_authorized(
            &policy.owner_did,
            &policy.signing_key_did,
            signed_at,
            artifact_expires_at,
            now,
        )
    {
        return Err(StartupError::Invalid("policy.authority"));
    }
    Ok(())
}

fn validate_policy_status_authority(
    status: &PolicyStatus,
    policies: &[Policy],
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), StartupError> {
    let policy = policies
        .iter()
        .find(|policy| policy.policy_id == status.policy_id)
        .ok_or(StartupError::Invalid("policy_status.policy_id"))?;
    let signed_at = parse_rfc3339(&status.effective_at)
        .map_err(|_| StartupError::Invalid("policy_status.effective_at"))?;
    let artifact_expires_at = policy
        .expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|_| StartupError::Invalid("policy.expires_at"))?;
    if status.owner_did != policy.owner_did
        || status.signature.signer_did != status.signing_key_did
        || !authority_index.policy_signer_authorized(
            &status.owner_did,
            &status.signing_key_did,
            signed_at,
            artifact_expires_at,
            now,
        )
    {
        return Err(StartupError::Invalid("policy_status.authority"));
    }
    Ok(())
}

fn validate_policy_engine_record_authority(
    record: &policy_core::PolicyEngineRecord,
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), StartupError> {
    let artifact_expires_at = parse_rfc3339(&record.expires_at)
        .map_err(|_| StartupError::Invalid("policy_engine_record.expires_at"))?;
    if !authority_index.policy_signer_authorized(
        &record.owner_did,
        &record.signature.signer_did,
        now,
        Some(artifact_expires_at),
        now,
    ) {
        return Err(StartupError::Invalid("policy_engine_record.authority"));
    }
    if !authority_index.grant_issuer_authorized(
        &record.owner_did,
        &record.grant_issuer_did,
        now,
        Some(artifact_expires_at),
        now,
    ) {
        return Err(StartupError::Invalid(
            "policy_engine_record.grant_issuer_authority",
        ));
    }
    Ok(())
}

fn validate_policy_engine_records_cover_policies(
    config: &ServiceConfig,
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), StartupError> {
    for policy in &config.policies {
        let covered = config.policy_engine_records.iter().any(|record| {
            let Ok(record_expires_at) = parse_rfc3339(&record.expires_at) else {
                return false;
            };
            record.owner_did == policy.owner_did
                && record.audience == config.audience
                && record.grant_issuer_did == config.grant_issuer_did
                && record_expires_at >= now
                && authority_index.grant_issuer_authorized(
                    &record.owner_did,
                    &record.grant_issuer_did,
                    now,
                    Some(record_expires_at),
                    now,
                )
        });
        if !covered {
            return Err(StartupError::Invalid(
                "policy_engine_record.grant_issuer_authority",
            ));
        }
    }
    Ok(())
}

fn validate_enrollment_authority(
    enrollment: &HolderEnrollment,
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), StartupError> {
    let signed_at = parse_rfc3339(&enrollment.not_before)
        .map_err(|_| StartupError::Invalid("holder_enrollment.not_before"))?;
    let artifact_expires_at = enrollment
        .expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|_| StartupError::Invalid("holder_enrollment.expires_at"))?;
    if enrollment.signature.signer_did != enrollment.signing_key_did
        || !authority_index.policy_signer_authorized(
            &enrollment.eligible_subject_did,
            &enrollment.signing_key_did,
            signed_at,
            artifact_expires_at,
            now,
        )
    {
        return Err(StartupError::Invalid("holder_enrollment.authority"));
    }
    Ok(())
}

fn validate_enrollment_status_authority(
    status: &HolderEnrollmentStatus,
    enrollments: &BTreeMap<String, HolderEnrollment>,
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), StartupError> {
    let enrollment = enrollments
        .get(&status.enrollment_id)
        .ok_or(StartupError::Invalid(
            "holder_enrollment_status.enrollment_id",
        ))?;
    let signed_at = parse_rfc3339(&status.effective_at)
        .map_err(|_| StartupError::Invalid("holder_enrollment_status.effective_at"))?;
    let artifact_expires_at = enrollment
        .expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|_| StartupError::Invalid("holder_enrollment.expires_at"))?;
    if status.signature.signer_did != status.signing_key_did
        || !authority_index.policy_signer_authorized(
            &enrollment.eligible_subject_did,
            &status.signing_key_did,
            signed_at,
            artifact_expires_at,
            now,
        )
    {
        return Err(StartupError::Invalid("holder_enrollment_status.authority"));
    }
    Ok(())
}

fn validate_authority_dates(presentation: &GrantPresentation) -> Result<(), AdapterError> {
    parse_rfc3339(&presentation.expires_at).map_err(|_| {
        AdapterError::Runtime(RuntimeError::Presentation("presentation-expired".into()))
    })?;
    let HolderBindingProof::EnrolledAgent { enrollment, status } = &presentation.holder_binding;
    parse_rfc3339(&enrollment.not_before).map_err(|_| {
        AdapterError::Runtime(RuntimeError::HolderBinding(
            "enrollment-not-yet-valid".into(),
        ))
    })?;
    if let Some(expires_at) = &enrollment.expires_at {
        parse_rfc3339(expires_at).map_err(|_| {
            AdapterError::Runtime(RuntimeError::HolderBinding("enrollment-expired".into()))
        })?;
    }
    if let Some(status) = status {
        parse_rfc3339(&status.effective_at).map_err(|_| {
            AdapterError::Runtime(RuntimeError::HolderBinding(
                "enrollment-status-rollback".into(),
            ))
        })?;
    }
    Ok(())
}

fn validate_holder_enrollment_signature(
    presentation: &GrantPresentation,
    authority_index: &AuthorityIndex,
    now: DateTime<Utc>,
) -> Result<(), AdapterError> {
    let HolderBindingProof::EnrolledAgent { enrollment, status } = &presentation.holder_binding;
    verify_signed_object::<HolderEnrollment>(
        &serde_json::to_value(enrollment).map_err(|_| AdapterError::SchemaInvalid)?,
    )
    .map_err(AdapterError::HolderEnrollmentSignedObject)?;
    let signed_at = parse_rfc3339(&enrollment.not_before).map_err(|_| {
        AdapterError::Runtime(RuntimeError::HolderBinding(
            "enrollment-not-yet-valid".into(),
        ))
    })?;
    let artifact_expires_at = enrollment
        .expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|_| {
            AdapterError::Runtime(RuntimeError::HolderBinding("enrollment-expired".into()))
        })?;
    if enrollment.signature.signer_did != enrollment.signing_key_did
        || !authority_index.policy_signer_authorized(
            &enrollment.eligible_subject_did,
            &enrollment.signing_key_did,
            signed_at,
            artifact_expires_at,
            now,
        )
    {
        return Err(AdapterError::Runtime(RuntimeError::HolderBinding(
            "signer-not-authorized".to_string(),
        )));
    }
    if let Some(status) = status {
        verify_signed_object::<HolderEnrollmentStatus>(
            &serde_json::to_value(status).map_err(|_| AdapterError::SchemaInvalid)?,
        )
        .map_err(AdapterError::HolderEnrollmentSignedObject)?;
        let signed_at = parse_rfc3339(&status.effective_at).map_err(|_| {
            AdapterError::Runtime(RuntimeError::HolderBinding(
                "enrollment-status-rollback".into(),
            ))
        })?;
        if status.signature.signer_did != status.signing_key_did
            || !authority_index.policy_signer_authorized(
                &enrollment.eligible_subject_did,
                &status.signing_key_did,
                signed_at,
                artifact_expires_at,
                now,
            )
        {
            return Err(AdapterError::Runtime(RuntimeError::HolderBinding(
                "signer-not-authorized".to_string(),
            )));
        }
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), AdapterError> {
    if !(MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce.len()) {
        return Err(AdapterError::Runtime(RuntimeError::ChallengeNotFound));
    }
    Ok(())
}

fn validate_requested_capabilities_hash_format(
    presentation: &GrantPresentation,
) -> Result<(), AdapterError> {
    let hash = presentation.requested_capabilities_hash.as_bytes();
    if hash.len() == 64
        && hash
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Ok(())
    } else {
        Err(AdapterError::BadRequest(
            "requestedCapabilitiesHash must be 64 lowercase hex characters".to_string(),
        ))
    }
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

pub fn router(service: PolicyEngineService) -> Router {
    Router::new()
        .route("/policy/v0/challenge", post(handle_challenge))
        .route("/policy/v0/resolve", post(handle_resolve))
        .route(
            "/policy/v0/policies/{policy_id}/active-cutoff",
            post(handle_active_cutoff),
        )
        .with_state(Arc::new(Mutex::new(service)))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeRequest {
    pub policy_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge: GrantChallenge,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolveRequest {
    pub presentation: Value,
}

impl ResolveRequest {
    fn into_presentation(self) -> Result<ParsedPresentation, AdapterError> {
        let presentation =
            serde_json::from_value::<ConsumableGrantPresentation>(self.presentation.clone())
                .map(GrantPresentation::from)
                .map_err(|_| AdapterError::SchemaInvalid)?;
        if serde_json::from_value::<StrictGrantPresentation>(self.presentation).is_ok() {
            Ok(ParsedPresentation::Valid(presentation))
        } else {
            Ok(ParsedPresentation::SchemaInvalid(presentation))
        }
    }
}

#[derive(Clone, Debug)]
enum ParsedPresentation {
    Valid(GrantPresentation),
    SchemaInvalid(GrantPresentation),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsumableGrantPresentation {
    schema: String,
    policy_id: String,
    eligible_subject_did: String,
    holder_did: String,
    holder_binding: HolderBindingProof,
    requested_capabilities: Vec<PolicyCapability>,
    requested_capabilities_hash: String,
    audience: String,
    nonce: String,
    expires_at: String,
    evidence: Option<Vec<PresentedEvidence>>,
    holder_signature: Signature,
}

impl From<ConsumableGrantPresentation> for GrantPresentation {
    fn from(value: ConsumableGrantPresentation) -> Self {
        Self {
            schema: value.schema,
            policy_id: value.policy_id,
            eligible_subject_did: value.eligible_subject_did,
            holder_did: value.holder_did,
            holder_binding: value.holder_binding,
            requested_capabilities: value.requested_capabilities,
            requested_capabilities_hash: value.requested_capabilities_hash,
            audience: value.audience,
            nonce: value.nonce,
            expires_at: value.expires_at,
            evidence: value.evidence,
            holder_signature: value.holder_signature,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct StrictGrantPresentation {
    schema: String,
    policy_id: String,
    eligible_subject_did: String,
    holder_did: String,
    holder_binding: StrictHolderBindingProof,
    requested_capabilities: Vec<PolicyCapability>,
    requested_capabilities_hash: String,
    audience: String,
    nonce: String,
    expires_at: String,
    evidence: Option<Vec<PresentedEvidence>>,
    holder_signature: Signature,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct StrictHolderBindingProof {
    #[serde(rename = "type")]
    binding_type: StrictHolderBindingType,
    enrollment: HolderEnrollment,
    status: Option<HolderEnrollmentStatus>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StrictHolderBindingType {
    EnrolledAgent,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveResponse {
    pub delegation: PortableDelegation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveCutoffResponse {
    pub revoked_delegation_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub error: ErrorEnvelope,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("{0}")]
    BadRequest(String),
    #[error("schema-invalid")]
    SchemaInvalid,
    #[error("frozen-contract-gap: {0}")]
    FrozenContractGap(&'static str),
    #[error("active-cutoff-failed")]
    OperationalDenied,
    #[error("{0}")]
    SignedObject(String),
    #[error("{0}")]
    HolderEnrollmentSignedObject(SignedObjectError),
    #[error("{0}")]
    Runtime(RuntimeError),
}

impl AdapterError {
    fn from_runtime(error: RuntimeError) -> Self {
        match &error {
            RuntimeError::Evidence(inner)
            | RuntimeError::Presentation(inner)
            | RuntimeError::HolderBinding(inner)
                if !is_frozen_wrapped_runtime_code(inner) =>
            {
                Self::FrozenContractGap(unfrozen_runtime_code_name(inner))
            }
            _ => Self::Runtime(error),
        }
    }

    fn code(&self) -> String {
        match self {
            Self::BadRequest(_) => "schema-invalid".to_string(),
            Self::SchemaInvalid => "schema-invalid".to_string(),
            Self::FrozenContractGap(_) => "grant-issuance-failed".to_string(),
            Self::OperationalDenied => "active-cutoff-failed".to_string(),
            Self::SignedObject(_) => "schema-invalid".to_string(),
            Self::HolderEnrollmentSignedObject(error) => {
                debug_assert!(is_frozen_signed_object_code(error.as_str()));
                error.as_str().to_string()
            }
            Self::Runtime(RuntimeError::Evidence(inner))
                if is_frozen_wrapped_runtime_code(inner) =>
            {
                inner.clone()
            }
            Self::Runtime(RuntimeError::Presentation(inner))
                if is_frozen_wrapped_runtime_code(inner) =>
            {
                inner.clone()
            }
            Self::Runtime(RuntimeError::HolderBinding(inner))
                if is_frozen_wrapped_runtime_code(inner) =>
            {
                inner.clone()
            }
            Self::Runtime(error) => error.as_str().to_string(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::SchemaInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::FrozenContractGap(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::OperationalDenied => StatusCode::FORBIDDEN,
            Self::SignedObject(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::HolderEnrollmentSignedObject(_) => StatusCode::FORBIDDEN,
            Self::Runtime(RuntimeError::PolicyNotFound | RuntimeError::ChallengeNotFound) => {
                StatusCode::NOT_FOUND
            }
            Self::Runtime(RuntimeError::Presentation(inner)) if inner == "challenge-not-found" => {
                StatusCode::NOT_FOUND
            }
            Self::Runtime(
                RuntimeError::ChallengeNonceConsumed | RuntimeError::PolicyStatusRollback,
            ) => StatusCode::CONFLICT,
            Self::Runtime(RuntimeError::Presentation(inner))
                if inner == "challenge-nonce-consumed" =>
            {
                StatusCode::CONFLICT
            }
            Self::Runtime(
                RuntimeError::PolicyInactive
                | RuntimeError::PolicyExpired
                | RuntimeError::HolderBinding(_)
                | RuntimeError::PolicyNotSatisfied
                | RuntimeError::GrantInactive
                | RuntimeError::GrantExpired
                | RuntimeError::EvidenceRevoked(_)
                | RuntimeError::EvidenceRevocationStateMissing(_),
            ) => StatusCode::FORBIDDEN,
            Self::Runtime(RuntimeError::Presentation(inner)) if inner == "policy-not-satisfied" => {
                StatusCode::FORBIDDEN
            }
            Self::Runtime(RuntimeError::Presentation(_) | RuntimeError::Evidence(_)) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::Runtime(
                RuntimeError::GrantIssuanceFailed(_)
                | RuntimeError::ActiveCutoffFailed(_)
                | RuntimeError::GrantNotFound
                | RuntimeError::PolicyStatusRefreshFailed(_)
                | RuntimeError::ChallengeSigningFailed(_)
                | RuntimeError::ChallengeSignatureSuiteNotAccepted
                | RuntimeError::ChallengeSignatureInvalid(_),
            ) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<RuntimeError> for AdapterError {
    fn from(error: RuntimeError) -> Self {
        Self::from_runtime(error)
    }
}

fn unfrozen_runtime_code_name(code: &str) -> &'static str {
    match code {
        "requested-capabilities-hash-mismatch" => "requested-capabilities-hash-mismatch",
        _ => "unfrozen-wrapped-runtime-code",
    }
}

fn is_frozen_wrapped_runtime_code(code: &str) -> bool {
    is_frozen_presentation_code(code)
        || is_frozen_evidence_code(code)
        || is_frozen_holder_binding_code(code)
        || code == "policy-not-satisfied"
}

fn is_frozen_evidence_code(code: &str) -> bool {
    matches!(
        code,
        "evidence-authority-missing"
            | "evidence-credential-invalid"
            | "evidence-domain-invalid"
            | "evidence-domain-missing"
            | "evidence-freshness-expired"
            | "evidence-freshness-unestablishable"
            | "evidence-issuer-missing"
            | "evidence-issuer-untrusted"
            | "evidence-presentation-invalid"
            | "evidence-requirements-invalid"
            | "evidence-verifier-unsupported"
    )
}

fn is_frozen_signed_object_code(code: &str) -> bool {
    matches!(
        code,
        "canonicalization-mismatch"
            | "digest-mismatch"
            | "id-mismatch"
            | "schema-invalid"
            | "signature-invalid"
            | "signer-not-authorized"
    )
}

fn is_frozen_presentation_code(code: &str) -> bool {
    matches!(
        code,
        "challenge-not-found"
            | "challenge-expired"
            | "challenge-nonce-consumed"
            | "evidence-requirement-duplicate"
            | "evidence-requirement-unknown"
            | "holder-signature-invalid"
            | "holder-signature-signer-mismatch"
            | "presentation-audience-mismatch"
            | "presentation-evidence-missing"
            | "presentation-expired"
            | "requested-capabilities-exceeded"
            | "requested-capabilities-hash-mismatch"
    )
}

fn is_frozen_holder_binding_code(code: &str) -> bool {
    matches!(
        code,
        "enrollment-binding-mismatch"
            | "enrollment-expired"
            | "enrollment-not-yet-valid"
            | "enrollment-out-of-scope"
            | "enrollment-revoked"
            | "enrollment-revoked-irreversible"
            | "enrollment-status-rollback"
            | "signature-invalid"
            | "signer-not-authorized"
    )
}

impl IntoResponse for AdapterError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let body = ErrorBody {
            error: ErrorEnvelope {
                code: code.clone(),
                message: code,
            },
        };
        (status, Json(body)).into_response()
    }
}

async fn handle_challenge(
    State(service): State<SharedRuntime>,
    payload: Result<Json<ChallengeRequest>, JsonRejection>,
) -> Result<Json<ChallengeResponse>, AdapterError> {
    let request = payload.map_err(json_rejection)?;
    let mut service = service.lock().expect("policy engine service lock");
    let challenge = service.issue_challenge(request.0)?;
    Ok(Json(ChallengeResponse { challenge }))
}

async fn handle_resolve(
    State(service): State<SharedRuntime>,
    payload: Result<Json<ResolveRequest>, JsonRejection>,
) -> Result<Json<ResolveResponse>, AdapterError> {
    let request = payload.map_err(json_rejection)?;
    let mut service = service.lock().expect("policy engine service lock");
    let delegation = service.resolve(request.0)?;
    Ok(Json(ResolveResponse { delegation }))
}

async fn handle_active_cutoff(
    State(service): State<SharedRuntime>,
    Path(policy_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ActiveCutoffResponse>, AdapterError> {
    let mut service = service.lock().expect("policy engine service lock");
    let revoked_delegation_ids = service.active_cutoff(&policy_id, &headers)?;
    Ok(Json(ActiveCutoffResponse {
        revoked_delegation_ids,
    }))
}

fn json_rejection(rejection: JsonRejection) -> AdapterError {
    match rejection {
        JsonRejection::JsonSyntaxError(_)
        | JsonRejection::JsonDataError(_)
        | JsonRejection::MissingJsonContentType(_) => AdapterError::SchemaInvalid,
        other => AdapterError::BadRequest(other.body_text()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use chrono::TimeZone;
    use policy_core::{
        compute_signed_object_id, requested_capabilities_hash_hex, AllOfExpression, Audit,
        AuditIssuance, DelegationMode, DenialDisclosure, Disclosure, EvalError, EvidenceAuthority,
        EvidenceExpression, EvidenceRequirement, GrantOutput, GrantTemplate, HolderBindingProof,
        HolderEnrollment, HolderEnrollmentDisposition, HolderEnrollmentScope,
        HolderEnrollmentStatus, PolicyCapability, PolicyDisposition, PolicyResource, PolicyStatus,
        PresentedEvidence, RevocationMode, SignedObjectType, SubjectExpression, SubjectRequirement,
        GRANT_PRESENTATION_SCHEMA, POLICY_SCHEMA,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{fs, path::Path};
    use tower::ServiceExt;

    const VECTOR_COMMIT_SHA: &str = "ce40178f08e907f6aa2e82aacfcf4d0839746bd2";
    const LAUNCH_PROFILE_ACCEPT: &str =
        include_str!("../../../test-vectors/launch-credential-profile/accept.json");
    const LAUNCH_PROFILE_REJECT: &str =
        include_str!("../../../test-vectors/launch-credential-profile/reject.json");
    const GRANT_PRESENTATION_REJECT: &str =
        include_str!("../../../test-vectors/grant-presentation/reject.json");
    const HOLDER_ENROLLMENT_ROLLBACK: &str =
        include_str!("../../../test-vectors/holder-enrollment/rollback-through-issuance.json");
    const SIGNED_OBJECT_PROFILE_OBJECTS: &str =
        include_str!("../../../test-vectors/signed-object-profile/objects.json");
    const SIGNATURE_SUITES: &str =
        include_str!("../../../test-vectors/signed-object-profile/signature-suites.json");
    const GRANT_OUTPUT_ACCEPT: &str =
        include_str!("../../../test-vectors/grant-output/accept.json");
    const GRANT_OUTPUT_PRODUCER_REJECT: &str =
        include_str!("../../../test-vectors/grant-output/producer-reject.json");
    const GRANT_OUTPUT_AUDIT_REJECT: &str =
        include_str!("../../../test-vectors/grant-output/audit-reject.json");

    async fn decode_and_verify_with_pinned_ssi(encoded: &str) -> ssi_ucan::Ucan<Value> {
        let ucan = ssi_ucan::Ucan::<Value>::decode(encoded)
            .unwrap_or_else(|error| panic!("pinned SSI Ucan::decode rejected token: {error:?}"));
        ucan.verify_signature(&did_method_key::DIDKey)
            .await
            .unwrap_or_else(|error| panic!("pinned SSI signature verification failed: {error:?}"));
        ucan
    }

    fn sign_test_ucan(header: &Value, payload: &Value, key: &SigningKey) -> String {
        let header = URL_SAFE_NO_PAD.encode(policy_core::jcs::canonicalize(header));
        let payload = URL_SAFE_NO_PAD.encode(policy_core::jcs::canonicalize(payload));
        let input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
        format!("{input}.{signature}")
    }

    fn sign_test_ucan_raw(header: &str, payload: &str, key: &SigningKey) -> String {
        let header = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
        format!("{input}.{signature}")
    }

    fn oracle_fixture() -> (String, Value, Value, SigningKey) {
        let (_, delegation, _) = issue_python_accept_vector_semantics(false);
        let segments = delegation.encoded.split('.').collect::<Vec<_>>();
        let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let payload =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        (
            delegation.encoded,
            header,
            payload,
            SigningKey::from_bytes(&[0x22_u8; 32]),
        )
    }

    fn assert_oracle_decode_rejects(case: &str, token: &str) {
        assert!(
            ssi_ucan::Ucan::<Value>::decode(token).is_err(),
            "pinned SSI unexpectedly decoded oracle case {case}"
        );
    }

    async fn assert_oracle_signature_rejects(case: &str, token: &str) {
        let decoded = ssi_ucan::Ucan::<Value>::decode(token)
            .unwrap_or_else(|error| panic!("{case} must reach signature verification: {error:?}"));
        assert!(
            decoded
                .verify_signature(&did_method_key::DIDKey)
                .await
                .is_err(),
            "pinned SSI unexpectedly verified oracle case {case}"
        );
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OracleProvenanceFact {
        #[serde(rename = "xyz.tinycloud.policy/capabilityHashHex")]
        capability_hash_hex: String,
        #[serde(rename = "xyz.tinycloud.policy/delegationMode")]
        delegation_mode: String,
        #[serde(rename = "xyz.tinycloud.policy/issuanceId")]
        issuance_id: String,
        #[serde(rename = "xyz.tinycloud.policy/policyId")]
        policy_id: String,
        #[serde(rename = "xyz.tinycloud.policy/revocationMode")]
        revocation_mode: String,
    }

    fn config(policy: Policy) -> ServiceConfig {
        let parent = parent_for_policy(&policy, &grant_issuer_did());
        ServiceConfig {
            audience: "https://policy-engine.example/v0".to_string(),
            challenge_ttl_seconds: 300,
            accepted_suites: vec![SignatureSuite::EddsaEd25519Sha256JcsV1],
            challenge_signer_seed: [4_u8; 32],
            grant_issuer_did: grant_issuer_did(),
            grant_issuer_signer_seed: grant_issuer_signing_key().to_bytes(),
            parent_delegations: vec![parent],
            issuer_keys: BTreeMap::from([("did:web:issuer.credentials.org".to_string(), jwk())]),
            policies: vec![policy],
            policy_statuses: Vec::new(),
            enrollment_statuses: Vec::new(),
            policy_engine_records: Vec::new(),
            demo_operations_enabled: false,
            demo_operations_bearer_token: None,
        }
    }

    fn parent_for_policy(policy: &Policy, audience: &str) -> ParentDelegationConfig {
        let artifact = format!("test-parent-artifact:{}", policy.owner_did).into_bytes();
        let bounds = policy
            .resource
            .permissions_ceiling
            .iter()
            .map(|capability| ParentCapabilityBound {
                policy_capability: capability.clone(),
                native_resource: format!(
                    "tinycloud:{}:default/{}/{}",
                    policy.owner_did.strip_prefix("did:").unwrap(),
                    capability
                        .service
                        .strip_prefix("tinycloud.")
                        .unwrap_or(&capability.service),
                    capability.path
                ),
            })
            .collect::<Vec<_>>();
        let expected_cid = native_cid(&artifact);
        let expires_at = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).single().unwrap();
        ParentDelegationConfig {
            owner_did: policy.owner_did.clone(),
            artifact_base64_url: URL_SAFE_NO_PAD.encode(artifact),
            expected_cid: expected_cid.clone(),
            audience: audience.to_string(),
            not_before: None,
            expires_at,
            terminal: false,
            capability_bounds: bounds.clone(),
            delegate_receipt: CapturedParentDelegateReceipt {
                delegation_id: expected_cid,
                delegatee_did: audience.to_string(),
                not_before: None,
                expires_at,
                terminal: false,
                capability_bounds: bounds,
            },
        }
    }

    fn jwk() -> JWK {
        serde_json::from_value(json!({
            "params": {
                "OKP": {
                    "public_key": vec![0_u8; 32],
                    "private_key": vec![0_u8; 32]
                }
            }
        }))
        .unwrap()
    }

    fn launch_issuer_jwk(file: &Value) -> JWK {
        let public_key = hex_decode(
            file["profile"]["issuerJwk"]["public_key_hex"]
                .as_str()
                .unwrap(),
        );
        let private_key = hex_decode(
            file["profile"]["issuerJwk"]["private_key_hex"]
                .as_str()
                .unwrap(),
        );
        serde_json::from_value(json!({
            "params": {
                "OKP": {
                    "public_key": public_key,
                    "private_key": private_key
                }
            }
        }))
        .unwrap()
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn seed_from_hex(value: &str) -> [u8; 32] {
        hex_decode(value).try_into().unwrap()
    }

    fn holder_key() -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let did = did_key_from_ed25519(key.verifying_key().as_bytes());
        (key, did)
    }

    fn grant_issuer_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[5_u8; 32])
    }

    fn grant_issuer_did() -> String {
        did_key_from_ed25519(grant_issuer_signing_key().verifying_key().as_bytes())
    }

    fn vector_policy_signing_key() -> SigningKey {
        let suites: Value = serde_json::from_str(SIGNATURE_SUITES).unwrap();
        SigningKey::from_bytes(&seed_from_hex(
            suites["ed25519"]["policy_signer"]["seed_hex"]
                .as_str()
                .unwrap(),
        ))
    }

    fn vector_holder_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x33_u8; 32])
    }

    fn fixed_test_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, 0, 3, 0).single().unwrap()
    }

    fn from_signed_objects_for_tests(
        config: ServiceConfig,
        objects: impl IntoIterator<Item = Value>,
    ) -> Result<PolicyEngineService, StartupError> {
        PolicyEngineService::from_signed_objects_at_for_tests(config, objects, fixed_test_now())
    }

    fn capability() -> PolicyCapability {
        policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.sql",
            "space": "applications",
            "path": "xyz.tinycloud.listen/conversations",
            "actions": ["tinycloud.sql/read"]
        }))
        .unwrap()
    }

    fn other_capability() -> PolicyCapability {
        policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.sql",
            "space": "applications",
            "path": "xyz.tinycloud.listen/other",
            "actions": ["tinycloud.sql/read"]
        }))
        .unwrap()
    }

    fn policy(policy_id: &str, cap: PolicyCapability, subject_did: &str) -> Policy {
        Policy {
            schema: POLICY_SCHEMA.to_string(),
            policy_id: policy_id.to_string(),
            owner_did: subject_did.to_string(),
            signing_key_did: subject_did.to_string(),
            created_at: "2026-06-01T00:00:00Z".to_string(),
            expires_at: None,
            resource: PolicyResource {
                resource_type: "listen-transcript".to_string(),
                resource_id: "conv_456".to_string(),
                permissions_ceiling: vec![cap],
            },
            when: policy_core::Expression::Subject(SubjectExpression {
                subject: SubjectRequirement {
                    did: subject_did.to_string(),
                },
            }),
            grant: GrantTemplate {
                output: GrantOutput::PortableDelegation,
                max_ttl_seconds: 300,
                delegation_mode: DelegationMode::Terminal,
                revocation: RevocationMode::RefreshOnly,
            },
            disclosure: Some(Disclosure {
                denial: DenialDisclosure::Code,
            }),
            audit: Some(Audit {
                issuance: AuditIssuance::Security,
            }),
            signature: Signature {
                suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                signer_did: subject_did.to_string(),
                value: String::new(),
            },
        }
    }

    fn sign_enrollment(
        mut enrollment: HolderEnrollment,
        signing_key: &SigningKey,
    ) -> HolderEnrollment {
        enrollment.signature.value.clear();
        let digest = policy_core::digest_signed_object(&enrollment).unwrap();
        enrollment.enrollment_id =
            compute_signed_object_id(SignedObjectType::HolderEnrollment, &digest);
        enrollment.signature.value = URL_SAFE_NO_PAD.encode(signing_key.sign(&digest).to_bytes());
        enrollment
    }

    fn sign_enrollment_status(
        mut status: HolderEnrollmentStatus,
        signing_key: &SigningKey,
    ) -> HolderEnrollmentStatus {
        status.signature.value.clear();
        let digest = policy_core::digest_signed_object(&status).unwrap();
        status.status_id =
            compute_signed_object_id(SignedObjectType::HolderEnrollmentStatus, &digest);
        status.signature.value = URL_SAFE_NO_PAD.encode(signing_key.sign(&digest).to_bytes());
        status
    }

    fn enrollment(holder_did: &str, signing_key: &SigningKey) -> HolderEnrollment {
        sign_enrollment(
            HolderEnrollment {
                schema: policy_core::HOLDER_ENROLLMENT_SCHEMA.to_string(),
                enrollment_id: "henr_test".to_string(),
                eligible_subject_did: holder_did.to_string(),
                holder_did: holder_did.to_string(),
                scope: None,
                not_before: "2026-06-01T00:00:00Z".to_string(),
                expires_at: Some("2026-07-01T00:00:00Z".to_string()),
                signing_key_did: holder_did.to_string(),
                signature: Signature {
                    suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                    signer_did: holder_did.to_string(),
                    value: String::new(),
                },
            },
            signing_key,
        )
    }

    fn sign_policy_engine_record(
        mut record: policy_core::PolicyEngineRecord,
        signing_key: &SigningKey,
    ) -> policy_core::PolicyEngineRecord {
        record.signature.value.clear();
        let digest = policy_core::digest_signed_object(&record).unwrap();
        record.engine_record_id =
            compute_signed_object_id(SignedObjectType::PolicyEngineRecord, &digest);
        record.signature.value = URL_SAFE_NO_PAD.encode(signing_key.sign(&digest).to_bytes());
        record
    }

    fn enrollment_status(enrollment_id: &str, signing_key: &SigningKey) -> HolderEnrollmentStatus {
        sign_enrollment_status(
            HolderEnrollmentStatus {
                schema: policy_core::HOLDER_ENROLLMENT_STATUS_SCHEMA.to_string(),
                status_id: "henrst_test".to_string(),
                enrollment_id: enrollment_id.to_string(),
                sequence: 1,
                disposition: HolderEnrollmentDisposition::Active,
                effective_at: "2026-06-01T00:00:00Z".to_string(),
                signing_key_did: did_key_from_ed25519(signing_key.verifying_key().as_bytes()),
                signature: Signature {
                    suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                    signer_did: did_key_from_ed25519(signing_key.verifying_key().as_bytes()),
                    value: String::new(),
                },
            },
            signing_key,
        )
    }

    fn presentation(
        challenge: &GrantChallenge,
        signing_key: &SigningKey,
        holder_did: &str,
        cap: PolicyCapability,
    ) -> GrantPresentation {
        let mut presentation = GrantPresentation {
            schema: GRANT_PRESENTATION_SCHEMA.to_string(),
            policy_id: challenge.policy_id.clone(),
            eligible_subject_did: holder_did.to_string(),
            holder_did: holder_did.to_string(),
            holder_binding: HolderBindingProof::EnrolledAgent {
                enrollment: enrollment(holder_did, signing_key),
                status: None,
            },
            requested_capabilities_hash: requested_capabilities_hash_hex(std::slice::from_ref(
                &cap,
            )),
            requested_capabilities: vec![cap],
            audience: challenge.audience.clone(),
            nonce: challenge.nonce.clone(),
            expires_at: "2026-06-12T00:04:30Z".to_string(),
            evidence: None::<Vec<PresentedEvidence>>,
            holder_signature: Signature {
                suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                signer_did: holder_did.to_string(),
                value: String::new(),
            },
        };
        let digest = policy_core::signed_object::digest_grant_presentation(&presentation).unwrap();
        presentation.holder_signature.value =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&digest).to_bytes());
        presentation
    }

    fn resign_presentation(presentation: &mut GrantPresentation, signing_key: &SigningKey) {
        presentation.holder_signature.value.clear();
        let digest = policy_core::signed_object::digest_grant_presentation(presentation).unwrap();
        presentation.holder_signature.value =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&digest).to_bytes());
    }

    fn launch_policy_from_presentation(
        presentation: &GrantPresentation,
        requirement: EvidenceRequirement,
    ) -> Policy {
        Policy {
            schema: POLICY_SCHEMA.to_string(),
            policy_id: presentation.policy_id.clone(),
            owner_did: presentation.eligible_subject_did.clone(),
            signing_key_did: presentation.eligible_subject_did.clone(),
            created_at: "2026-06-01T00:00:00Z".to_string(),
            expires_at: None,
            resource: PolicyResource {
                resource_type: "listen-transcript".to_string(),
                resource_id: "conv_456".to_string(),
                permissions_ceiling: presentation.requested_capabilities.clone(),
            },
            when: policy_core::Expression::AllOf(AllOfExpression {
                all_of: vec![
                    policy_core::Expression::Subject(SubjectExpression {
                        subject: SubjectRequirement {
                            did: presentation.eligible_subject_did.clone(),
                        },
                    }),
                    policy_core::Expression::Evidence(EvidenceExpression {
                        evidence: requirement,
                    }),
                ],
            }),
            grant: GrantTemplate {
                output: GrantOutput::PortableDelegation,
                max_ttl_seconds: 300,
                delegation_mode: DelegationMode::Terminal,
                revocation: RevocationMode::RefreshOnly,
            },
            disclosure: Some(Disclosure {
                denial: DenialDisclosure::Code,
            }),
            audit: Some(Audit {
                issuance: AuditIssuance::Security,
            }),
            signature: Signature {
                suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                signer_did: presentation.eligible_subject_did.clone(),
                value: String::new(),
            },
        }
    }

    fn subject_policy_from_presentation(presentation: &GrantPresentation) -> Policy {
        Policy {
            schema: POLICY_SCHEMA.to_string(),
            policy_id: presentation.policy_id.clone(),
            owner_did: presentation.eligible_subject_did.clone(),
            signing_key_did: presentation.eligible_subject_did.clone(),
            created_at: "2026-06-01T00:00:00Z".to_string(),
            expires_at: None,
            resource: PolicyResource {
                resource_type: "listen-transcript".to_string(),
                resource_id: "conv_456".to_string(),
                permissions_ceiling: presentation.requested_capabilities.clone(),
            },
            when: policy_core::Expression::Subject(SubjectExpression {
                subject: SubjectRequirement {
                    did: presentation.eligible_subject_did.clone(),
                },
            }),
            grant: GrantTemplate {
                output: GrantOutput::PortableDelegation,
                max_ttl_seconds: 300,
                delegation_mode: DelegationMode::Terminal,
                revocation: RevocationMode::RefreshOnly,
            },
            disclosure: Some(Disclosure {
                denial: DenialDisclosure::Code,
            }),
            audit: Some(Audit {
                issuance: AuditIssuance::Security,
            }),
            signature: Signature {
                suite: SignatureSuite::Eip191Secp256k1Sha256JcsV1,
                signer_did: presentation.eligible_subject_did.clone(),
                value: String::new(),
            },
        }
    }

    fn evidence_policy(policy_id: &str, cap: PolicyCapability, subject_did: &str) -> Policy {
        Policy {
            when: policy_core::Expression::AllOf(AllOfExpression {
                all_of: vec![
                    policy_core::Expression::Subject(SubjectExpression {
                        subject: SubjectRequirement {
                            did: subject_did.to_string(),
                        },
                    }),
                    policy_core::Expression::Evidence(EvidenceExpression {
                        evidence: EvidenceRequirement {
                            requirement_id: "email-domain".to_string(),
                            verifier: "w3c.vc/credential/v1".to_string(),
                            requirements: json!({
                                "type": "opencredentials.email/v1",
                                "emailDomains": ["credentials.org"]
                            }),
                            authority: None,
                            freshness: None,
                        },
                    }),
                ],
            }),
            ..policy(policy_id, cap, subject_did)
        }
    }

    fn launch_service_config(file: &Value, policy: Policy) -> ServiceConfig {
        let issuer = file["profile"]["sdkDefaultAcceptedIssuers"][0]
            .as_str()
            .unwrap()
            .to_string();
        ServiceConfig {
            issuer_keys: BTreeMap::from([(issuer, launch_issuer_jwk(file))]),
            ..config(policy)
        }
    }

    fn signed_profile_objects(object_type: &str) -> Vec<Value> {
        let file: Value = serde_json::from_str(SIGNED_OBJECT_PROFILE_OBJECTS).unwrap();
        file["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["object_type"] == object_type)
            .map(signed_profile_object)
            .collect()
    }

    fn signed_profile_object(entry: &Value) -> Value {
        let mut object = entry["unsigned"].as_object().unwrap().clone();
        let id_field = match entry["object_type"].as_str().unwrap() {
            "Policy" => "policyId",
            "PolicyStatus" => "statusId",
            "PolicyEngineRecord" => "engineRecordId",
            "OperationalKeyAuthorization" => "authorizationId",
            "OperationalKeyStatus" => "statusId",
            "HolderEnrollment" => "enrollmentId",
            "HolderEnrollmentStatus" => "statusId",
            "GrantChallenge" => "challengeId",
            other => panic!("unexpected object type {other}"),
        };
        object.insert(id_field.to_string(), entry["id"].clone());
        object.insert("signature".to_string(), entry["signature"].clone());
        Value::Object(object)
    }

    fn vector_authority_config() -> ServiceConfig {
        let suites: Value = serde_json::from_str(SIGNATURE_SUITES).unwrap();
        let mut cfg = config(policy(
            "pol_placeholder",
            capability(),
            "did:key:z6Mksubject",
        ));
        cfg.policies.clear();
        cfg.audience = suites["engine_audience"].as_str().unwrap().to_string();
        cfg.grant_issuer_did = suites["ed25519"]["grant_issuer"]["did"]
            .as_str()
            .unwrap()
            .to_string();
        cfg.grant_issuer_signer_seed = seed_from_hex(
            suites["ed25519"]["grant_issuer"]["seed_hex"]
                .as_str()
                .unwrap(),
        );
        let loaded_policies = signed_profile_objects("Policy")
            .into_iter()
            .map(|value| serde_json::from_value::<Policy>(value).unwrap())
            .collect::<Vec<_>>();
        let mut parent = parent_for_policy(
            loaded_policies.first().expect("signed profile policy"),
            &cfg.grant_issuer_did,
        );
        for policy in loaded_policies.iter().skip(1) {
            assert_eq!(policy.owner_did, parent.owner_did);
            parent
                .capability_bounds
                .extend(parent_for_policy(policy, &cfg.grant_issuer_did).capability_bounds);
        }
        parent.delegate_receipt.capability_bounds = parent.capability_bounds.clone();
        cfg.parent_delegations = vec![parent];
        cfg
    }

    fn parse_time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn decode_signed_delegation(encoded: &str) -> Value {
        let segments = encoded.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3, "compact JWS segment count");
        let bytes = URL_SAFE_NO_PAD.decode(segments[1]).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn post(app: Router, uri: &str, body: Value) -> (StatusCode, Value) {
        let (status, value, _) = post_observed(app, uri, body).await;
        (status, value)
    }

    async fn post_observed(app: Router, uri: &str, body: Value) -> (StatusCode, Value, Vec<u8>) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap();
        (status, value, bytes.to_vec())
    }

    async fn post_raw(app: Router, uri: &str, body: &str) -> (StatusCode, Value, Vec<u8>) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap();
        (status, value, bytes.to_vec())
    }

    async fn post_with_auth(
        app: Router,
        uri: &str,
        body: Value,
        token: &str,
    ) -> (StatusCode, Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap();
        (status, value)
    }

    #[derive(Debug, Deserialize)]
    struct DenialMatrixRow {
        code: String,
        layer: String,
        #[serde(rename = "httpStatus")]
        http_status: Option<u16>,
        #[serde(rename = "producingModule")]
        producing_module: String,
        #[serde(rename = "section65Mapping")]
        section65_mapping: String,
        #[serde(rename = "testRef")]
        test_ref: Option<String>,
        reachability: Option<String>,
        #[serde(rename = "cpFRecord")]
        cp_f_record: Option<String>,
        #[serde(rename = "libraryTestRefs")]
        library_test_refs: Option<Vec<String>>,
        #[serde(rename = "enforcedAt")]
        enforced_at: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct WireFixtureManifest {
        #[serde(rename = "producerCommit")]
        producer_commit: String,
        label: String,
        fixtures: BTreeMap<String, WireFixtureEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct WireFixtureEntry {
        code: String,
        sha256: String,
        #[serde(rename = "testRef")]
        test_ref: String,
    }

    fn denial_matrix_rows() -> Vec<DenialMatrixRow> {
        serde_json::from_str(include_str!("../conformance/denial-matrix-v0.json")).unwrap()
    }

    fn runtime_denial_status(code: &str) -> StatusCode {
        let status = denial_matrix_rows()
            .into_iter()
            .find(|row| row.layer == "E" && row.code == code)
            .and_then(|row| row.http_status)
            .unwrap_or_else(|| panic!("{code} must be a runtime denial row"));
        StatusCode::from_u16(status).unwrap()
    }

    fn runtime_test_source(path: &str) -> Option<&'static str> {
        match path {
            "crates/policy-runtime/tests/challenge_signing.rs" => Some(include_str!(
                "../../policy-runtime/tests/challenge_signing.rs"
            )),
            "crates/policy-runtime/tests/evidence_provenance.rs" => Some(include_str!(
                "../../policy-runtime/tests/evidence_provenance.rs"
            )),
            "crates/policy-runtime/tests/refresh_active_cutoff.rs" => Some(include_str!(
                "../../policy-runtime/tests/refresh_active_cutoff.rs"
            )),
            "crates/policy-runtime/tests/tracked_revocation.rs" => Some(include_str!(
                "../../policy-runtime/tests/tracked_revocation.rs"
            )),
            "crates/policy-runtime/tests/valid_until_capping.rs" => Some(include_str!(
                "../../policy-runtime/tests/valid_until_capping.rs"
            )),
            _ => None,
        }
    }

    fn runtime_test_ref_exists(test_ref: &str) -> bool {
        let Some((path, test_name)) = test_ref.split_once("::") else {
            return false;
        };
        let Some(source) = runtime_test_source(path) else {
            return false;
        };
        let fn_line = format!("fn {test_name}(");
        let mut previous_non_empty = None;
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(&fn_line) {
                return matches!(previous_non_empty, Some("#[test]"));
            }
            if !trimmed.is_empty() {
                previous_non_empty = Some(trimmed);
            }
        }
        false
    }

    fn adapter_frozen_denial_vocabulary() -> BTreeSet<&'static str> {
        BTreeSet::from([
            "active-cutoff-failed",
            "canonicalization-mismatch",
            "challenge-expired",
            "challenge-nonce-consumed",
            "challenge-not-found",
            "digest-mismatch",
            "evidence-authority-missing",
            "evidence-credential-invalid",
            "evidence-domain-invalid",
            "evidence-domain-missing",
            "evidence-freshness-expired",
            "evidence-freshness-unestablishable",
            "evidence-issuer-missing",
            "evidence-issuer-untrusted",
            "evidence-presentation-invalid",
            "evidence-requirement-duplicate",
            "evidence-requirement-unknown",
            "evidence-requirements-invalid",
            "evidence-revocation-state-missing",
            "evidence-revoked",
            "evidence-verifier-unsupported",
            "enrollment-binding-mismatch",
            "enrollment-expired",
            "enrollment-not-yet-valid",
            "enrollment-out-of-scope",
            "enrollment-revoked",
            "enrollment-revoked-irreversible",
            "enrollment-status-rollback",
            "grant-expired",
            "grant-issuance-failed",
            "grant-inactive",
            "grant-not-found",
            "holder-signature-invalid",
            "holder-signature-signer-mismatch",
            "id-mismatch",
            "policy-expired",
            "policy-inactive",
            "policy-not-found",
            "policy-not-satisfied",
            "policy-status-rollback",
            "presentation-audience-mismatch",
            "presentation-evidence-missing",
            "presentation-expired",
            "requested-capabilities-exceeded",
            "requested-capabilities-hash-mismatch",
            "schema-invalid",
            "signature-invalid",
            "signer-not-authorized",
        ])
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn observed_wire_fixture_bytes(status: StatusCode, body_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"{\"body\":");
        bytes.extend_from_slice(body_bytes);
        bytes.extend_from_slice(format!(",\"status\":{}}}\n", status.as_u16()).as_bytes());
        bytes
    }

    fn assert_observed_denial_fixture(
        code: &str,
        expected_status: StatusCode,
        status: StatusCode,
        body_bytes: &[u8],
        value: &Value,
    ) {
        assert_eq!(status, expected_status, "{code}: {value:?}");
        assert_eq!(value["error"]["code"].as_str(), Some(code));
        assert_eq!(value["error"]["message"].as_str(), Some(code));
        assert_denial_fixture_matches_observed_response(code, status, body_bytes);
    }

    fn assert_denial_fixture_matches_observed_response(
        code: &str,
        status: StatusCode,
        body: &[u8],
    ) {
        let value: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(value["error"]["code"].as_str(), Some(code));
        assert_eq!(value["error"]["message"].as_str(), Some(code));

        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("conformance/wire-denials")
            .join(format!("{code}.json"));
        let fixture = fs::read(fixture_path).unwrap();
        assert_eq!(
            fixture,
            observed_wire_fixture_bytes(status, body),
            "{code} fixture must match mounted-handler response"
        );
    }

    fn policy_status(
        policy_id: &str,
        owner_did: &str,
        sequence: u64,
        disposition: PolicyDisposition,
    ) -> PolicyStatus {
        PolicyStatus {
            schema: policy_core::POLICY_STATUS_SCHEMA.to_string(),
            status_id: format!("polst_test_{sequence}"),
            policy_id: policy_id.to_string(),
            owner_did: owner_did.to_string(),
            sequence,
            disposition,
            effective_at: "2026-06-01T00:00:00Z".to_string(),
            reason_code: None,
            signing_key_did: owner_did.to_string(),
            signature: Signature {
                suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                signer_did: owner_did.to_string(),
                value: String::new(),
            },
        }
    }

    struct StaticPolicyStatusRefresh {
        expected_policy_id: String,
        status: PolicyStatus,
    }

    impl policy_runtime::PolicyStatusRefresher for StaticPolicyStatusRefresh {
        fn refresh_policy_status(
            &mut self,
            policy_id: &str,
            _now: DateTime<Utc>,
        ) -> Result<Option<PolicyStatus>, RuntimeError> {
            assert_eq!(policy_id, self.expected_policy_id);
            Ok(Some(self.status.clone()))
        }
    }

    #[tokio::test]
    async fn challenge_and_resolve_replay_conflict() {
        let cap = capability();
        let policy_id = "pol_http_subject_only";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );

        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        verify_signed_object_value(&challenge_body["challenge"]).unwrap();

        let presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let body = json!({ "presentation": presentation });

        let (status, value) = post(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{value:?}");
        assert_eq!(value["delegation"]["policyId"], policy_id);
        let encoded = value["delegation"]["encoded"].as_str().unwrap();
        decode_and_verify_with_pinned_ssi(encoded).await;
        let signed = decode_signed_delegation(encoded);
        assert!(signed.get("evidenceIds").is_none());
        assert!(signed.get("evidenceProvenance").is_none());
        assert_eq!(
            native_cid(encoded.as_bytes()),
            value["delegation"]["delegationId"].as_str().unwrap()
        );
        assert!(signed["iss"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}#", grant_issuer_did())));
        let facts = signed["fct"].as_array().unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0]["xyz.tinycloud.policy/delegationMode"], "terminal");
        assert_eq!(facts[0]["xyz.tinycloud.policy/policyId"], policy_id);
        assert_eq!(
            facts[0]["xyz.tinycloud.policy/revocationMode"],
            "refresh_only"
        );
        let issuance_id = facts[0]["xyz.tinycloud.policy/issuanceId"]
            .as_str()
            .unwrap();
        assert!(!issuance_id.is_empty());

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(
            replay_value["error"]["code"],
            RuntimeError::ChallengeNonceConsumed.as_str()
        );
    }

    #[tokio::test]
    async fn errors_use_envelope_and_unknown_fields_fail_closed() {
        let cap = capability();
        let app = router(
            PolicyEngineService::try_new(config(policy("pol_http", cap, "did:key:z6Mksubject")))
                .unwrap(),
        );
        let (status, value) = post(
            app,
            "/policy/v0/challenge",
            json!({ "policyId": "pol_http", "extra": true }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["error"]["code"], "schema-invalid");
    }

    #[tokio::test]
    async fn malformed_json_and_type_mismatch_use_schema_invalid_envelope() {
        let cap = capability();
        let app = router(
            PolicyEngineService::try_new(config(policy("pol_http", cap, "did:key:z6Mksubject")))
                .unwrap(),
        );

        let (syntax_status, syntax_value, syntax_body) =
            post_raw(app.clone(), "/policy/v0/challenge", "{").await;
        assert_observed_denial_fixture(
            "schema-invalid",
            StatusCode::UNPROCESSABLE_ENTITY,
            syntax_status,
            &syntax_body,
            &syntax_value,
        );

        let (type_status, type_value) = post(
            app,
            "/policy/v0/challenge",
            json!({ "policyId": ["not", "a", "string"] }),
        )
        .await;
        assert_eq!(type_status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(type_value["error"]["code"], "schema-invalid");
    }

    #[tokio::test]
    async fn caller_supplied_challenge_nonce_is_unknown_field_schema_invalid() {
        let cap = capability();
        let app = router(
            PolicyEngineService::try_new(config(policy("pol_http", cap, "did:key:z6Mksubject")))
                .unwrap(),
        );
        let (status, value) = post(
            app,
            "/policy/v0/challenge",
            json!({ "policyId": "pol_http", "nonce": "1234567890123456" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["error"]["code"], "schema-invalid");
    }

    #[tokio::test]
    async fn policy_lifecycle_denials_use_frozen_codes() {
        let cap = capability();
        let app = router(
            PolicyEngineService::try_new(config(policy(
                "pol_http_lifecycle",
                cap.clone(),
                "did:key:z6Mksubject",
            )))
            .unwrap(),
        );
        let (missing_status, missing_value, missing_body) = post_observed(
            app,
            "/policy/v0/challenge",
            json!({ "policyId": "pol_missing" }),
        )
        .await;
        assert_observed_denial_fixture(
            "policy-not-found",
            StatusCode::NOT_FOUND,
            missing_status,
            &missing_body,
            &missing_value,
        );

        let mut expired_policy = policy("pol_http_expired", cap.clone(), "did:key:z6Mksubject");
        expired_policy.expires_at = Some("2026-01-01T00:00:00Z".to_string());
        let expired_app = router(
            PolicyEngineService::try_new(config(expired_policy))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (expired_status, expired_value, expired_body) = post_observed(
            expired_app,
            "/policy/v0/challenge",
            json!({ "policyId": "pol_http_expired" }),
        )
        .await;
        assert_observed_denial_fixture(
            "policy-expired",
            StatusCode::FORBIDDEN,
            expired_status,
            &expired_body,
            &expired_value,
        );

        let mut inactive_cfg = config(policy(
            "pol_http_inactive",
            cap.clone(),
            "did:key:z6Mksubject",
        ));
        inactive_cfg.policy_statuses.push(PolicyStatus {
            schema: policy_core::POLICY_STATUS_SCHEMA.to_string(),
            status_id: "polst_test".to_string(),
            policy_id: "pol_http_inactive".to_string(),
            owner_did: "did:key:z6Mksubject".to_string(),
            sequence: 1,
            disposition: PolicyDisposition::Revoked,
            effective_at: "2026-06-01T00:00:00Z".to_string(),
            reason_code: None,
            signing_key_did: "did:key:z6Mksubject".to_string(),
            signature: Signature {
                suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                signer_did: "did:key:z6Mksubject".to_string(),
                value: String::new(),
            },
        });
        let inactive_app = router(PolicyEngineService::try_new(inactive_cfg).unwrap());
        let (inactive_status, inactive_value, inactive_body) = post_observed(
            inactive_app,
            "/policy/v0/challenge",
            json!({ "policyId": "pol_http_inactive" }),
        )
        .await;
        assert_observed_denial_fixture(
            "policy-inactive",
            StatusCode::FORBIDDEN,
            inactive_status,
            &inactive_body,
            &inactive_value,
        );
    }

    #[tokio::test]
    async fn grant_presentation_denials_use_frozen_codes_through_http() {
        let cap = capability();
        let policy_id = "pol_http_presentation_denials";
        let (holder_key, holder_did) = holder_key();

        async fn resolve_case(
            policy: Policy,
            cap: PolicyCapability,
            holder_key: &SigningKey,
            holder_did: &str,
            mutate: impl FnOnce(&mut GrantPresentation, &SigningKey),
        ) -> (StatusCode, Value, Vec<u8>) {
            let policy_id = policy.policy_id.clone();
            let app = router(
                PolicyEngineService::try_new(config(policy))
                    .unwrap()
                    .with_fixed_now_for_tests(fixed_test_now()),
            );
            let (challenge_status, challenge_body) = post(
                app.clone(),
                "/policy/v0/challenge",
                json!({ "policyId": policy_id }),
            )
            .await;
            assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
            let challenge: GrantChallenge =
                serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
            let mut presentation = presentation(&challenge, holder_key, holder_did, cap);
            mutate(&mut presentation, holder_key);
            post_observed(
                app,
                "/policy/v0/resolve",
                json!({ "presentation": presentation }),
            )
            .await
        }

        let (audience_status, audience_value, audience_body) = resolve_case(
            policy(policy_id, cap.clone(), &holder_did),
            cap.clone(),
            &holder_key,
            &holder_did,
            |presentation, signing_key| {
                presentation.audience = "https://other.example/v0".to_string();
                resign_presentation(presentation, signing_key);
            },
        )
        .await;
        assert_observed_denial_fixture(
            "presentation-audience-mismatch",
            StatusCode::UNPROCESSABLE_ENTITY,
            audience_status,
            &audience_body,
            &audience_value,
        );

        let (signer_status, signer_value, signer_body) = resolve_case(
            policy(policy_id, cap.clone(), &holder_did),
            cap.clone(),
            &holder_key,
            &holder_did,
            |presentation, _| {
                presentation.holder_signature.signer_did = "did:key:z6Mkother".to_string();
            },
        )
        .await;
        assert_observed_denial_fixture(
            "holder-signature-signer-mismatch",
            StatusCode::UNPROCESSABLE_ENTITY,
            signer_status,
            &signer_body,
            &signer_value,
        );

        let (cap_status, cap_value, cap_body) = resolve_case(
            policy(policy_id, cap.clone(), &holder_did),
            other_capability(),
            &holder_key,
            &holder_did,
            |presentation, signing_key| {
                presentation.requested_capabilities_hash =
                    requested_capabilities_hash_hex(&presentation.requested_capabilities);
                resign_presentation(presentation, signing_key);
            },
        )
        .await;
        assert_observed_denial_fixture(
            "requested-capabilities-exceeded",
            StatusCode::UNPROCESSABLE_ENTITY,
            cap_status,
            &cap_body,
            &cap_value,
        );

        let hash_policy_id = "pol_http_presentation_hash_mismatch";
        let app = router(
            PolicyEngineService::try_new(config(policy(hash_policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": hash_policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut malformed_presentation =
            presentation(&challenge, &holder_key, &holder_did, cap.clone());
        malformed_presentation.requested_capabilities_hash = "not-canonical".to_string();
        resign_presentation(&mut malformed_presentation, &holder_key);

        let malformed_body = json!({ "presentation": malformed_presentation });
        let (hash_status, hash_value) =
            post(app.clone(), "/policy/v0/resolve", malformed_body.clone()).await;
        assert_eq!(hash_status, StatusCode::BAD_REQUEST);
        assert_eq!(hash_value["error"]["code"], "schema-invalid");

        let valid_after_malformed = presentation(&challenge, &holder_key, &holder_did, cap.clone());
        let (hash_retry_status, hash_retry_value) = post(
            app,
            "/policy/v0/resolve",
            json!({ "presentation": valid_after_malformed }),
        )
        .await;
        assert_eq!(hash_retry_status, StatusCode::OK, "{hash_retry_value:?}");

        let well_formed_hash_policy_id = "pol_http_presentation_well_formed_hash_mismatch";
        let app = router(
            PolicyEngineService::try_new(config(policy(
                well_formed_hash_policy_id,
                cap.clone(),
                &holder_did,
            )))
            .unwrap()
            .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": well_formed_hash_policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut mismatched_presentation =
            presentation(&challenge, &holder_key, &holder_did, cap.clone());
        mismatched_presentation.requested_capabilities_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        resign_presentation(&mut mismatched_presentation, &holder_key);

        let mismatched_body = json!({ "presentation": mismatched_presentation });
        let (hash_status, hash_value, hash_body) =
            post_observed(app.clone(), "/policy/v0/resolve", mismatched_body.clone()).await;
        assert_observed_denial_fixture(
            "requested-capabilities-hash-mismatch",
            StatusCode::UNPROCESSABLE_ENTITY,
            hash_status,
            &hash_body,
            &hash_value,
        );

        let (hash_replay_status, hash_replay_value) =
            post(app, "/policy/v0/resolve", mismatched_body).await;
        assert_eq!(hash_replay_status, StatusCode::CONFLICT);
        assert_eq!(
            hash_replay_value["error"]["code"],
            "challenge-nonce-consumed"
        );

        let evidence_required = evidence_policy(policy_id, cap.clone(), &holder_did);
        let (missing_evidence_status, missing_evidence_value, missing_evidence_body) =
            resolve_case(
                evidence_required.clone(),
                cap.clone(),
                &holder_key,
                &holder_did,
                |presentation, signing_key| {
                    presentation.evidence = None;
                    resign_presentation(presentation, signing_key);
                },
            )
            .await;
        assert_observed_denial_fixture(
            "presentation-evidence-missing",
            StatusCode::UNPROCESSABLE_ENTITY,
            missing_evidence_status,
            &missing_evidence_body,
            &missing_evidence_value,
        );

        let (unknown_evidence_status, unknown_evidence_value, unknown_evidence_body) =
            resolve_case(
                evidence_required.clone(),
                cap.clone(),
                &holder_key,
                &holder_did,
                |presentation, signing_key| {
                    presentation.evidence = Some(vec![PresentedEvidence {
                        requirement_id: "unknown".to_string(),
                        presentation: json!({ "sdJwt": "not-used" }),
                    }]);
                    resign_presentation(presentation, signing_key);
                },
            )
            .await;
        assert_observed_denial_fixture(
            "evidence-requirement-unknown",
            StatusCode::UNPROCESSABLE_ENTITY,
            unknown_evidence_status,
            &unknown_evidence_body,
            &unknown_evidence_value,
        );

        let (duplicate_evidence_status, duplicate_evidence_value, duplicate_evidence_body) =
            resolve_case(
                evidence_required,
                cap,
                &holder_key,
                &holder_did,
                |presentation, signing_key| {
                    presentation.evidence = Some(vec![
                        PresentedEvidence {
                            requirement_id: "email-domain".to_string(),
                            presentation: json!({ "sdJwt": "not-used" }),
                        },
                        PresentedEvidence {
                            requirement_id: "email-domain".to_string(),
                            presentation: json!({ "sdJwt": "not-used" }),
                        },
                    ]);
                    resign_presentation(presentation, signing_key);
                },
            )
            .await;
        assert_observed_denial_fixture(
            "evidence-requirement-duplicate",
            StatusCode::UNPROCESSABLE_ENTITY,
            duplicate_evidence_status,
            &duplicate_evidence_body,
            &duplicate_evidence_value,
        );
    }

    #[tokio::test]
    async fn cross_policy_nonce_surfaces_challenge_not_found_without_generic_code() {
        let cap = capability();
        let (holder_key, holder_did) = holder_key();
        let mut cfg = config(policy("pol_http_a", cap.clone(), &holder_did));
        cfg.policies
            .push(policy("pol_http_b", cap.clone(), &holder_did));
        let app = router(
            PolicyEngineService::try_new(cfg)
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );

        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": "pol_http_a" }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        presentation.policy_id = "pol_http_b".to_string();
        resign_presentation(&mut presentation, &holder_key);

        let (status, value) = post(
            app,
            "/policy/v0/resolve",
            json!({ "presentation": presentation }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"]["code"], "challenge-not-found");
    }

    #[tokio::test]
    async fn runtime_evidence_requirement_unknown_surfaces_frozen_code() {
        let cap = capability();
        let policy_id = "pol_http_runtime_evidence_unknown";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        presentation.evidence = Some(vec![PresentedEvidence {
            requirement_id: "unknown".to_string(),
            presentation: json!({ "sdJwt": "not-used" }),
        }]);
        resign_presentation(&mut presentation, &holder_key);

        let (status, value) = post(
            app,
            "/policy/v0/resolve",
            json!({ "presentation": presentation }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["error"]["code"], "evidence-requirement-unknown");
    }

    #[tokio::test]
    async fn evidence_denial_matrix_contract_cases() {
        async fn evidence_case(expected_code: &str, mutate: impl FnOnce(&mut EvidenceRequirement)) {
            let file: Value = serde_json::from_str(LAUNCH_PROFILE_ACCEPT).unwrap();
            let case = &file["cases"][0];
            let presentation: GrantPresentation =
                serde_json::from_value(case["grantPresentation"].clone()).unwrap();
            let mut requirement: EvidenceRequirement =
                serde_json::from_value(case["requirement"].clone()).unwrap();
            mutate(&mut requirement);
            let policy = launch_policy_from_presentation(&presentation, requirement);
            let now = parse_time(case["context"]["now"].as_str().unwrap());
            let mut service = PolicyEngineService::try_new(launch_service_config(&file, policy))
                .unwrap()
                .with_fixed_now_for_tests(now);
            service
                .issue_challenge_with_nonce_for_tests(
                    &presentation.policy_id,
                    presentation.nonce.clone(),
                )
                .unwrap();
            let app = router(service);
            let (status, value, body) = post_observed(
                app,
                "/policy/v0/resolve",
                json!({ "presentation": serde_json::to_value(&presentation).unwrap() }),
            )
            .await;
            assert_observed_denial_fixture(
                expected_code,
                StatusCode::UNPROCESSABLE_ENTITY,
                status,
                &body,
                &value,
            );
        }

        evidence_case("evidence-authority-missing", |requirement| {
            requirement.authority = None;
        })
        .await;
        evidence_case("evidence-domain-invalid", |requirement| {
            requirement.requirements = json!({
                "type": "opencredentials.email/v1",
                "emailDomains": ["t\u{00ed}nycloud.xyz"]
            });
        })
        .await;
        evidence_case("evidence-domain-missing", |requirement| {
            requirement.requirements = json!({
                "type": "opencredentials.email/v1",
                "emailDomains": []
            });
        })
        .await;
        evidence_case("evidence-issuer-missing", |requirement| {
            requirement.authority = Some(EvidenceAuthority {
                profile: None,
                accepted_issuers: Some(Vec::new()),
                allow_owner_authorized_issuer: None,
            });
        })
        .await;
        evidence_case("evidence-requirements-invalid", |requirement| {
            requirement.requirements = json!({
                "type": "opencredentials.email/v1",
                "emailDomains": ["tinycloud.xyz"],
                "unexpected": true
            });
        })
        .await;
        evidence_case("evidence-verifier-unsupported", |requirement| {
            requirement.verifier = "unsupported/verifier".to_string();
        })
        .await;
    }

    #[tokio::test]
    async fn enrollment_scope_denials_use_frozen_codes_through_http() {
        let cap = capability();
        let policy_id = "pol_http_enrollment_scope";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.scope = Some(HolderEnrollmentScope {
            policy_ids: Some(vec!["pol_other".to_string()]),
            resource_ids: None,
        });
        *enrollment = sign_enrollment(enrollment.clone(), &holder_key);
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value, observed_body) =
            post_observed(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_observed_denial_fixture(
            "enrollment-out-of-scope",
            StatusCode::FORBIDDEN,
            status,
            &observed_body,
            &value,
        );

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn policy_not_satisfied_uses_frozen_code_through_http() {
        let cap = capability();
        let policy_id = "pol_http_not_satisfied";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(
                policy_id,
                cap.clone(),
                "did:key:z6Mkunmatchedsubject",
            )))
            .unwrap()
            .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let body = json!({ "presentation": presentation });

        let (status, value, observed_body) =
            post_observed(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_observed_denial_fixture(
            "policy-not-satisfied",
            StatusCode::FORBIDDEN,
            status,
            &observed_body,
            &value,
        );

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn policy_status_rollback_uses_frozen_code_through_mounted_challenge() {
        let cap = capability();
        let policy_id = "pol_http_policy_status_rollback";
        let owner_did = "did:key:z6Mksubject";
        let mut cfg = config(policy(policy_id, cap, owner_did));
        cfg.policy_statuses.push(policy_status(
            policy_id,
            owner_did,
            2,
            PolicyDisposition::Active,
        ));
        let stale_status = policy_status(policy_id, owner_did, 1, PolicyDisposition::Active);
        let mut service = PolicyEngineService::try_new(cfg).unwrap();
        service
            .runtime
            .set_policy_status_refresher(StaticPolicyStatusRefresh {
                expected_policy_id: policy_id.to_string(),
                status: stale_status,
            });

        let (status, value, body) = post_observed(
            router(service),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_observed_denial_fixture(
            "policy-status-rollback",
            StatusCode::CONFLICT,
            status,
            &body,
            &value,
        );
    }

    #[test]
    fn canonicalization_mismatch_is_frozen_vocabulary_nonruntime_code() {
        assert_eq!(
            SignedObjectError::CanonicalizationMismatch.as_str(),
            "canonicalization-mismatch"
        );
    }

    #[test]
    fn signed_object_loader_reject_vectors_fail_with_frozen_codes() {
        for (error, code, status) in [
            (
                AdapterError::HolderEnrollmentSignedObject(
                    SignedObjectError::CanonicalizationMismatch,
                ),
                "canonicalization-mismatch",
                StatusCode::FORBIDDEN,
            ),
            (
                AdapterError::HolderEnrollmentSignedObject(SignedObjectError::DigestMismatch),
                "digest-mismatch",
                StatusCode::FORBIDDEN,
            ),
            (
                AdapterError::HolderEnrollmentSignedObject(SignedObjectError::IdMismatch),
                "id-mismatch",
                StatusCode::FORBIDDEN,
            ),
        ] {
            assert_eq!(error.code(), code);
            assert_eq!(error.status(), status);
        }
    }

    #[test]
    fn adapter_wrapped_runtime_errors_do_not_collapse_to_category_generics() {
        let cases = [
            (
                AdapterError::from(RuntimeError::Presentation("challenge-not-found".into())),
                "challenge-not-found",
                StatusCode::NOT_FOUND,
            ),
            (
                AdapterError::from(RuntimeError::Evidence(
                    "evidence-requirement-unknown".into(),
                )),
                "evidence-requirement-unknown",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                AdapterError::from(RuntimeError::Presentation("policy-not-satisfied".into())),
                "policy-not-satisfied",
                StatusCode::FORBIDDEN,
            ),
            (
                AdapterError::from(RuntimeError::Presentation(
                    EvalError::RequestedCapabilitiesHashMismatch
                        .as_str()
                        .to_string(),
                )),
                "requested-capabilities-hash-mismatch",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ];

        for (error, code, status) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.status(), status);
            assert!(!matches!(
                error.code().as_str(),
                "presentation-invalid" | "evidence-invalid" | "holder-not-authorized"
            ));
        }
    }

    #[test]
    fn adapter_frozen_denial_vocabulary_excludes_suppressed_generics() {
        let frozen = BTreeSet::from([
            "active-cutoff-failed",
            "canonicalization-mismatch",
            "challenge-expired",
            "challenge-nonce-consumed",
            "challenge-not-found",
            "digest-mismatch",
            "evidence-authority-missing",
            "evidence-credential-invalid",
            "evidence-domain-invalid",
            "evidence-domain-missing",
            "evidence-freshness-expired",
            "evidence-freshness-unestablishable",
            "evidence-issuer-missing",
            "evidence-issuer-untrusted",
            "evidence-presentation-invalid",
            "evidence-requirement-duplicate",
            "evidence-requirement-unknown",
            "evidence-requirements-invalid",
            "evidence-revocation-state-missing",
            "evidence-revoked",
            "evidence-verifier-unsupported",
            "enrollment-binding-mismatch",
            "enrollment-expired",
            "enrollment-not-yet-valid",
            "enrollment-out-of-scope",
            "enrollment-revoked",
            "enrollment-revoked-irreversible",
            "enrollment-status-rollback",
            "grant-expired",
            "grant-issuance-failed",
            "grant-inactive",
            "grant-not-found",
            "holder-signature-invalid",
            "holder-signature-signer-mismatch",
            "id-mismatch",
            "policy-expired",
            "policy-inactive",
            "policy-not-found",
            "policy-not-satisfied",
            "policy-status-rollback",
            "presentation-audience-mismatch",
            "presentation-evidence-missing",
            "presentation-expired",
            "requested-capabilities-exceeded",
            "requested-capabilities-hash-mismatch",
            "schema-invalid",
            "signature-invalid",
            "signer-not-authorized",
        ]);
        let adapter_codes = BTreeSet::from([
            "active-cutoff-failed",
            "canonicalization-mismatch",
            "challenge-expired",
            "challenge-nonce-consumed",
            "challenge-not-found",
            "digest-mismatch",
            "evidence-authority-missing",
            "evidence-credential-invalid",
            "evidence-domain-invalid",
            "evidence-domain-missing",
            "evidence-freshness-expired",
            "evidence-freshness-unestablishable",
            "evidence-issuer-missing",
            "evidence-issuer-untrusted",
            "evidence-presentation-invalid",
            "evidence-requirement-duplicate",
            "evidence-requirement-unknown",
            "evidence-requirements-invalid",
            "evidence-revocation-state-missing",
            "evidence-revoked",
            "evidence-verifier-unsupported",
            "enrollment-binding-mismatch",
            "enrollment-expired",
            "enrollment-not-yet-valid",
            "enrollment-out-of-scope",
            "enrollment-revoked",
            "enrollment-revoked-irreversible",
            "enrollment-status-rollback",
            "grant-expired",
            "grant-issuance-failed",
            "grant-inactive",
            "grant-not-found",
            "holder-signature-invalid",
            "holder-signature-signer-mismatch",
            "id-mismatch",
            "policy-expired",
            "policy-inactive",
            "policy-not-found",
            "policy-not-satisfied",
            "policy-status-rollback",
            "presentation-audience-mismatch",
            "presentation-evidence-missing",
            "presentation-expired",
            "requested-capabilities-exceeded",
            "requested-capabilities-hash-mismatch",
            "schema-invalid",
            "signature-invalid",
            "signer-not-authorized",
        ]);

        for code in &adapter_codes {
            assert!(frozen.contains(code), "unfrozen adapter code {code}");
        }
        for generic in [
            "presentation-invalid",
            "evidence-invalid",
            "holder-not-authorized",
        ] {
            assert!(!adapter_codes.contains(generic));
        }
    }

    #[test]
    fn denial_matrix_classified_rows_match_adapter_frozen_set() {
        let rows = denial_matrix_rows();
        let frozen_vocabulary = adapter_frozen_denial_vocabulary();
        let table_vocabulary = rows
            .iter()
            .filter(|row| {
                matches!(
                    row.layer.as_str(),
                    "E" | "S" | "PROVISIONAL-S" | "FROZEN-VOCABULARY"
                )
            })
            .filter(|row| frozen_vocabulary.contains(row.code.as_str()))
            .map(|row| row.code.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(table_vocabulary, frozen_vocabulary);
        for row in rows.iter().filter(|row| row.layer == "E") {
            assert!(
                row.http_status.is_some(),
                "{} must carry httpStatus",
                row.code
            );
            assert!(
                row.test_ref.is_some(),
                "{} must carry mounted testRef",
                row.code
            );
            assert_eq!(
                row.reachability.as_deref(),
                Some("mounted-runtime"),
                "{} runtime reachability",
                row.code
            );
        }
    }

    #[test]
    fn denial_matrix_frozen_vocabulary_nonruntime_rows_are_disjoint_from_runtime_denials() {
        let rows = denial_matrix_rows();
        let runtime_denials = rows
            .iter()
            .filter(|row| row.layer == "E")
            .map(|row| row.code.as_str())
            .collect::<BTreeSet<_>>();
        let frozen_vocabulary_nonruntime = rows
            .iter()
            .filter(|row| row.layer == "FROZEN-VOCABULARY")
            .map(|row| row.code.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            frozen_vocabulary_nonruntime,
            BTreeSet::from(["canonicalization-mismatch", "evidence-freshness-expired"])
        );
        assert!(runtime_denials.is_disjoint(&frozen_vocabulary_nonruntime));

        for row in rows.iter().filter(|row| row.layer == "FROZEN-VOCABULARY") {
            assert!(
                row.http_status.is_none(),
                "{} frozen vocabulary row must not carry mounted HTTP status",
                row.code
            );
            assert!(
                row.test_ref.is_none(),
                "{} frozen vocabulary row must not carry mounted testRef",
                row.code
            );
            assert_eq!(
                row.reachability.as_deref(),
                Some("FROZEN-VOCABULARY/UNREACHABLE"),
                "{} reachability",
                row.code
            );
            assert!(!row.producing_module.is_empty(), "{} citation", row.code);
            assert!(
                row.cp_f_record
                    .as_deref()
                    .is_some_and(|record| record.contains("CP-F") && record.contains("revisit")),
                "{} CP-F record",
                row.code
            );
            assert!(
                row.library_test_refs
                    .as_ref()
                    .is_some_and(|refs| !refs.is_empty()),
                "{} libraryTestRefs",
                row.code
            );
        }
    }

    #[test]
    fn denial_matrix_suppressed_generics_are_never_emitted() {
        let rows = denial_matrix_rows();
        let emitted = adapter_frozen_denial_vocabulary();
        let suppressed = rows
            .iter()
            .filter(|row| row.layer == "SUPPRESSED")
            .map(|row| row.code.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            suppressed,
            BTreeSet::from([
                "evidence-invalid",
                "holder-not-authorized",
                "presentation-invalid"
            ])
        );
        assert!(suppressed.is_disjoint(&emitted));
    }

    #[test]
    fn denial_matrix_server_side_rows_are_classified_without_emitted_membership_claim() {
        let rows = denial_matrix_rows();
        for row in rows
            .iter()
            .filter(|row| matches!(row.layer.as_str(), "S" | "PROVISIONAL-S"))
        {
            assert!(!row.producing_module.is_empty(), "{} module", row.code);
            assert!(!row.section65_mapping.is_empty(), "{} mapping", row.code);
            let test_ref = row.test_ref.as_deref().unwrap_or("");
            assert!(!test_ref.is_empty(), "{} testRef", row.code);
            assert!(
                runtime_test_ref_exists(test_ref),
                "{} testRef must resolve to an existing runtime test: {}",
                row.code,
                test_ref
            );
            assert!(
                row.http_status.is_none(),
                "{} must not carry httpStatus",
                row.code
            );
        }

        for row in rows.iter().filter(|row| row.layer == "N") {
            assert_eq!(row.enforced_at.as_deref(), Some("tinycloud-node"));
        }
    }

    #[test]
    fn denial_matrix_covers_section_65_minimum_denials() {
        let rows = denial_matrix_rows();
        let by_code = rows
            .iter()
            .map(|row| (row.code.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let expected = [
            (
                "policy-not-found",
                ["policy-not-found"].as_slice(),
                "policy-not-found=VERBATIM",
            ),
            (
                "policy-invalid",
                [
                    "schema-invalid",
                    "digest-mismatch",
                    "canonicalization-mismatch",
                    "signature-invalid",
                ]
                .as_slice(),
                "policy-invalid=REFINED",
            ),
            (
                "policy-inactive",
                ["policy-inactive"].as_slice(),
                "policy-inactive=VERBATIM",
            ),
            (
                "policy-expired",
                ["policy-expired"].as_slice(),
                "policy-expired=VERBATIM",
            ),
            (
                "verifier-unsupported",
                ["evidence-verifier-unsupported"].as_slice(),
                "verifier-unsupported=REFINED",
            ),
            (
                "challenge-invalid",
                [
                    "challenge-not-found",
                    "challenge-expired",
                    "challenge-nonce-consumed",
                ]
                .as_slice(),
                "challenge-invalid=REFINED",
            ),
            (
                "challenge-expired",
                ["challenge-expired"].as_slice(),
                "challenge-expired=VERBATIM",
            ),
            (
                "presentation-invalid",
                ["presentation-invalid"].as_slice(),
                "presentation-invalid=SUPPRESSED-GENERIC",
            ),
            (
                "eligible-subject-not-authorized",
                ["enrollment-out-of-scope", "enrollment-binding-mismatch"].as_slice(),
                "eligible-subject-not-authorized=REFINED",
            ),
            (
                "holder-not-authorized",
                ["holder-not-authorized"].as_slice(),
                "holder-not-authorized=SUPPRESSED-GENERIC",
            ),
            (
                "evidence-invalid",
                ["evidence-invalid"].as_slice(),
                "evidence-invalid=SUPPRESSED-GENERIC",
            ),
            (
                "evidence-expired",
                ["evidence-credential-invalid"].as_slice(),
                "evidence-expired=REFINED_BY_CASE",
            ),
            (
                "evidence-revoked",
                ["evidence-revoked"].as_slice(),
                "evidence-revoked=VERBATIM(PROVISIONAL-S reachability)",
            ),
            (
                "evidence-status-stale",
                [
                    "evidence-revocation-state-missing",
                    "evidence-freshness-unestablishable",
                ]
                .as_slice(),
                "evidence-status-stale=REFINED",
            ),
            (
                "requested-capabilities-exceeded",
                ["requested-capabilities-exceeded"].as_slice(),
                "requested-capabilities-exceeded=VERBATIM",
            ),
            (
                "parent-authority-insufficient",
                [
                    "terminal-parent-cannot-redelegate",
                    "delegation-ancestor-revoked",
                ]
                .as_slice(),
                "parent-authority-insufficient=LAYER-N",
            ),
            (
                "materialization-failed",
                ["grant-issuance-failed"].as_slice(),
                "materialization-failed=REFINED",
            ),
            (
                "active-cutoff-failed",
                ["active-cutoff-failed"].as_slice(),
                "active-cutoff-failed=VERBATIM",
            ),
        ];

        for (minimum, codes, mapping) in expected {
            for code in codes {
                let row = by_code
                    .get(code)
                    .unwrap_or_else(|| panic!("{minimum} missing mapped row {code}"));
                assert!(
                    row.section65_mapping.contains(mapping),
                    "{minimum}/{code} expected mapping {mapping}, got {}",
                    row.section65_mapping
                );
                if mapping.ends_with("LAYER-N") {
                    assert_eq!(row.layer, "N", "{minimum}/{code}");
                    assert_eq!(row.enforced_at.as_deref(), Some("tinycloud-node"));
                }
            }
        }
    }

    #[test]
    fn denial_wire_fixture_package_is_complete_and_hashed() {
        let rows = denial_matrix_rows();
        let e_rows = rows
            .iter()
            .filter(|row| row.layer == "E")
            .collect::<Vec<_>>();
        let mounted_http_test_refs = BTreeSet::from([
            "evidence_denial_matrix_contract_cases",
            "enrollment_date_fields_reject_before_signature_verification",
            "enrollment_scope_denials_use_frozen_codes_through_http",
            "grant_presentation_denials_use_frozen_codes_through_http",
            "grant_presentation_reject_vectors_fail_through_http",
            "holder_enrollment_rollback_vectors_fail_through_http",
            "holder_enrollment_signed_object_digest_mismatch_uses_frozen_code_and_consumes_nonce",
            "holder_enrollment_signed_object_id_mismatch_uses_frozen_code_and_consumes_nonce",
            "launch_profile_freshness_cannot_be_bypassed_with_spoofed_status_fields",
            "launch_profile_reject_vectors_fail_through_http_without_mutating_fixtures",
            "malformed_json_and_type_mismatch_use_schema_invalid_envelope",
            "policy_lifecycle_denials_use_frozen_codes",
            "policy_not_satisfied_uses_frozen_code_through_http",
            "policy_status_rollback_uses_frozen_code_through_mounted_challenge",
            "pre_runtime_rejections_still_consume_nonce_once",
            "unauthorized_enrollment_signer_uses_frozen_code_and_consumes_nonce",
        ]);
        let manifest: WireFixtureManifest =
            serde_json::from_str(include_str!("../conformance/wire-denials/manifest.json"))
                .unwrap();
        let producer_commit = "8c4cabbf56e51c7e37484c060ffd4a6d51521101";
        assert_eq!(manifest.producer_commit, producer_commit);
        assert_eq!(
            manifest.label,
            format!("confirmed from code: policy-engine-http handlers @ {producer_commit}")
        );
        assert_eq!(manifest.fixtures.len(), e_rows.len());

        let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/wire-denials");
        let e_codes = e_rows
            .iter()
            .map(|row| row.code.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            e_codes.len(),
            e_rows.len(),
            "runtimeDenials rows must be unique by code"
        );
        let fixture_files = fs::read_dir(&fixture_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "manifest.json")
            .collect::<BTreeSet<_>>();
        let manifest_files = manifest.fixtures.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            fixture_files, manifest_files,
            "wire-denials directory must contain only manifest-listed runtimeDenials fixtures"
        );

        for row in e_rows {
            let file_name = format!("{}.json", row.code);
            assert_eq!(
                row.reachability.as_deref(),
                Some("mounted-runtime"),
                "{} fixture row reachability",
                row.code
            );
            let entry = manifest
                .fixtures
                .get(&file_name)
                .unwrap_or_else(|| panic!("missing manifest entry for {}", row.code));
            assert_eq!(entry.code, row.code);
            let test_ref = row.test_ref.as_deref().expect("E row testRef");
            assert_eq!(entry.test_ref, test_ref);
            assert!(
                mounted_http_test_refs.contains(test_ref),
                "{} must be covered by a mounted HTTP negative test, got {}",
                row.code,
                test_ref
            );

            let bytes = fs::read(fixture_dir.join(&file_name)).unwrap();
            assert_eq!(sha256_hex(&bytes), entry.sha256, "{}", row.code);
            let fixture: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(fixture["status"], row.http_status.unwrap());
            assert_eq!(
                fixture["body"]["error"]["code"].as_str(),
                Some(row.code.as_str())
            );
            assert_eq!(
                fixture["body"]["error"]["message"].as_str(),
                Some(row.code.as_str())
            );
        }

        for (file_name, entry) in &manifest.fixtures {
            assert!(
                e_codes.contains(entry.code.as_str()),
                "{file_name} fixture must correspond to one runtimeDenials row"
            );
            let expected_file = format!("{}.json", entry.code);
            assert_eq!(
                file_name, &expected_file,
                "{} fixture file name",
                entry.code
            );
        }
    }

    #[tokio::test]
    async fn grant_presentation_reject_vectors_fail_through_http() {
        let reject_file: Value = serde_json::from_str(GRANT_PRESENTATION_REJECT).unwrap();
        let accept_file: Value = serde_json::from_str(include_str!(
            "../../../test-vectors/grant-presentation/accept.json"
        ))
        .unwrap();
        let base_presentation: GrantPresentation =
            serde_json::from_value(accept_file["cases"][0]["presentation"].clone()).unwrap();
        let base_ceiling = base_presentation.requested_capabilities.clone();

        for case in reject_file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let presentation: GrantPresentation =
                serde_json::from_value(case["presentation"].clone()).unwrap();
            let mut policy = match name {
                "presentation-evidence-missing"
                | "evidence-requirement-unknown"
                | "evidence-requirement-duplicate" => launch_policy_from_presentation(
                    &presentation,
                    EvidenceRequirement {
                        requirement_id: "email-domain-allowed".to_string(),
                        verifier: "w3c.vc/credential/v1".to_string(),
                        requirements: json!({
                            "type": "opencredentials.email/v1",
                            "emailDomains": ["tinycloud.xyz"]
                        }),
                        authority: Some(policy_core::EvidenceAuthority {
                            profile: None,
                            accepted_issuers: Some(vec![
                                "did:web:issuer.credentials.org".to_string()
                            ]),
                            allow_owner_authorized_issuer: None,
                        }),
                        freshness: None,
                    },
                ),
                _ => subject_policy_from_presentation(&presentation),
            };
            if name == "requestedCapabilities-not-subset-of-ceiling" {
                policy.resource.permissions_ceiling = base_ceiling.clone();
            }

            let mut service = PolicyEngineService::try_new(config(policy))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now());
            if name != "challenge-not-found" {
                service
                    .issue_challenge_with_nonce_for_tests(
                        &presentation.policy_id,
                        presentation.nonce.clone(),
                    )
                    .unwrap();
            }
            if name == "challenge-expired" {
                service.fixed_now = Some(parse_time(
                    reject_file["now_for_expired_tests"].as_str().unwrap(),
                ));
            }
            if name == "presentation-expired" {
                service.fixed_now = Some(parse_time("2026-06-12T00:04:31Z"));
            }

            let app = router(service);
            let body = json!({ "presentation": case["presentation"].clone() });
            if name == "challenge-nonce-consumed" {
                let mut first_presentation = presentation.clone();
                first_presentation.evidence = None;
                resign_presentation(&mut first_presentation, &vector_holder_signing_key());
                let (first_status, first_value) = post(
                    app.clone(),
                    "/policy/v0/resolve",
                    json!({ "presentation": first_presentation }),
                )
                .await;
                assert_eq!(first_status, StatusCode::OK, "{name}: {first_value:?}");
            }
            let (status, value, observed_body) =
                post_observed(app, "/policy/v0/resolve", body).await;
            assert_ne!(status, StatusCode::OK, "{name}: {value:?}");
            let expected_code = case["rejection_code"].as_str().unwrap();
            assert_observed_denial_fixture(
                expected_code,
                runtime_denial_status(expected_code),
                status,
                &observed_body,
                &value,
            );
        }
    }

    #[tokio::test]
    async fn empty_and_oversized_resolve_nonces_reject_with_challenge_not_found() {
        let cap = capability();
        let policy_id = "pol_http_nonce_bounds";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);

        for nonce in ["", "n".repeat(MAX_NONCE_LEN + 1).as_str()] {
            presentation.nonce = nonce.to_string();
            resign_presentation(&mut presentation, &holder_key);
            let (status, value) = post(
                app.clone(),
                "/policy/v0/resolve",
                json!({ "presentation": presentation }),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(value["error"]["code"], "challenge-not-found");
        }
    }

    #[tokio::test]
    async fn truncated_holder_signature_maps_to_holder_signature_invalid() {
        let cap = capability();
        let policy_id = "pol_http_truncated_sig";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        presentation.holder_signature.value = "abc".to_string();

        let body = json!({ "presentation": presentation });
        let (status, value) = post(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["error"]["code"], "holder-signature-invalid");
    }

    #[tokio::test]
    async fn nested_holder_binding_unknown_fields_fail_closed() {
        let cap = capability();
        let policy_id = "pol_http_nested_unknown";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let mut body = json!({ "presentation": presentation });
        body["presentation"]["holderBinding"]["unexpectedAuthorityField"] = json!(true);

        let (status, value) = post(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["error"]["code"], "schema-invalid");

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn active_cutoff_requires_demo_auth_and_active_cutoff_cannot_emit_m1_grant() {
        let cap = capability();
        let policy_id = "pol_http_cutoff";
        let (holder_key, holder_did) = holder_key();
        let mut active_policy = policy(policy_id, cap.clone(), &holder_did);
        active_policy.grant.revocation = RevocationMode::ActiveCutoff;
        let mut cfg = config(active_policy);
        cfg.demo_operations_enabled = true;
        cfg.demo_operations_bearer_token = Some("demo-token".to_string());
        let app = router(
            PolicyEngineService::try_new(cfg)
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );

        let (unauth_status, unauth_value) = post(
            app.clone(),
            "/policy/v0/policies/pol_http_cutoff/active-cutoff",
            json!({}),
        )
        .await;
        assert_eq!(unauth_status, StatusCode::FORBIDDEN);
        assert_eq!(unauth_value["error"]["code"], "active-cutoff-failed");

        let (missing_status, missing_value) = post_with_auth(
            app.clone(),
            "/policy/v0/policies/pol_missing/active-cutoff",
            json!({}),
            "demo-token",
        )
        .await;
        assert_eq!(missing_status, StatusCode::NOT_FOUND);
        assert_eq!(missing_value["error"]["code"], "policy-not-found");

        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let (resolve_status, resolve_value) = post(
            app.clone(),
            "/policy/v0/resolve",
            json!({ "presentation": presentation }),
        )
        .await;
        assert_eq!(
            resolve_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{resolve_value:?}"
        );
        assert_eq!(resolve_value["error"]["code"], "grant-issuance-failed");

        let (status, value) = post_with_auth(
            app,
            "/policy/v0/policies/pol_http_cutoff/active-cutoff",
            json!({}),
            "demo-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value:?}");
        assert_eq!(value["revokedDelegationIds"], json!([]));
    }

    #[tokio::test]
    async fn active_cutoff_rejects_refresh_only_policy() {
        let cap = capability();
        let policy_id = "pol_http_refresh_only";
        let (_holder_key, holder_did) = holder_key();
        let mut refresh_policy = policy(policy_id, cap, &holder_did);
        refresh_policy.grant.revocation = RevocationMode::RefreshOnly;
        let mut cfg = config(refresh_policy);
        cfg.demo_operations_enabled = true;
        cfg.demo_operations_bearer_token = Some("demo-token".to_string());
        let app = router(PolicyEngineService::try_new(cfg).unwrap());

        let (status, value) = post_with_auth(
            app,
            "/policy/v0/policies/pol_http_refresh_only/active-cutoff",
            json!({}),
            "demo-token",
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(value["error"]["code"], "active-cutoff-failed");
    }

    #[tokio::test]
    async fn launch_profile_accept_vector_is_consumed_without_mutating_fixture() {
        let file: Value = serde_json::from_str(LAUNCH_PROFILE_ACCEPT).unwrap();
        let case = &file["cases"][0];
        let presentation: GrantPresentation =
            serde_json::from_value(case["grantPresentation"].clone()).unwrap();
        let requirement: EvidenceRequirement =
            serde_json::from_value(case["requirement"].clone()).unwrap();
        let policy = launch_policy_from_presentation(&presentation, requirement.clone());
        let now = parse_time(case["context"]["now"].as_str().unwrap());
        let mut service =
            PolicyEngineService::try_new(launch_service_config(&file, policy.clone()))
                .unwrap()
                .with_fixed_now_for_tests(now);
        service
            .issue_challenge_with_nonce_for_tests(
                &presentation.policy_id,
                presentation.nonce.clone(),
            )
            .unwrap();
        let app = router(service);

        validate_authority_dates(&presentation).unwrap();
        validate_holder_enrollment_signature(&presentation, &AuthorityIndex::default(), now)
            .unwrap();
        let verifier = SharedVcEvidenceVerifier::new(BTreeMap::from([(
            file["profile"]["sdkDefaultAcceptedIssuers"][0]
                .as_str()
                .unwrap()
                .to_string(),
            launch_issuer_jwk(&file),
        )]));
        verifier
            .verify(
                &requirement,
                &case["grantPresentation"]["evidence"][0]["presentation"],
                &RuntimeEvidenceContext {
                    policy,
                    eligible_subject_did: presentation.eligible_subject_did.clone(),
                    holder_did: presentation.holder_did.clone(),
                    requested_capabilities: presentation.requested_capabilities.clone(),
                    now,
                },
            )
            .unwrap();

        let (status, value) = post(
            app,
            "/policy/v0/resolve",
            json!({ "presentation": case["grantPresentation"].clone() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value:?}");
        assert_eq!(
            value["delegation"]["policyId"],
            case["grantPresentation"]["policyId"]
        );
        assert_eq!(
            value["delegation"]["holderDid"],
            case["grantPresentation"]["holderDid"]
        );
    }

    #[test]
    fn launch_profile_issuance_retains_evidence_provenance_attributes() {
        let file: Value = serde_json::from_str(LAUNCH_PROFILE_ACCEPT).unwrap();
        let case = &file["cases"][0];
        let presentation: GrantPresentation =
            serde_json::from_value(case["grantPresentation"].clone()).unwrap();
        let requirement: EvidenceRequirement =
            serde_json::from_value(case["requirement"].clone()).unwrap();
        let policy = launch_policy_from_presentation(&presentation, requirement);
        let now = parse_time(case["context"]["now"].as_str().unwrap());
        let mut service = PolicyEngineService::try_new(launch_service_config(&file, policy))
            .unwrap()
            .with_fixed_now_for_tests(now);
        service
            .issue_challenge_with_nonce_for_tests(
                &presentation.policy_id,
                presentation.nonce.clone(),
            )
            .unwrap();

        let delegation = service
            .resolve(ResolveRequest {
                presentation: case["grantPresentation"].clone(),
            })
            .unwrap();
        let record = service
            .issuance(&delegation.delegation_id)
            .expect("issuance record retained");
        let provenance = record
            .evidence_provenance
            .first()
            .expect("evidence provenance retained");
        assert_eq!(provenance.family, policy_evidence_vc::VC_EVIDENCE_FAMILY);
        assert_eq!(
            provenance.attributes.get("issuer").map(String::as_str),
            file["profile"]["sdkDefaultAcceptedIssuers"][0].as_str()
        );
        assert_eq!(
            record.tracked_evidence[0]
                .provenance
                .attributes
                .get(opencredentials_verify::EMAIL_DOMAIN_CLAIM)
                .map(String::as_str),
            Some("credentials.org")
        );
    }

    #[tokio::test]
    async fn launch_profile_reject_vectors_fail_through_http_without_mutating_fixtures() {
        let accept_file: Value = serde_json::from_str(LAUNCH_PROFILE_ACCEPT).unwrap();
        let reject_file: Value = serde_json::from_str(LAUNCH_PROFILE_REJECT).unwrap();
        let accept_case = &accept_file["cases"][0];
        let base_presentation: GrantPresentation =
            serde_json::from_value(accept_case["grantPresentation"].clone()).unwrap();
        for case in reject_file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| {
                case["rejection_code"].as_str().is_some_and(|code| {
                    code.starts_with("evidence-") || code.starts_with("enrollment-")
                })
            })
        {
            let presentation = if case.get("grantPresentation").is_some() {
                serde_json::from_value::<GrantPresentation>(case["grantPresentation"].clone())
                    .unwrap()
            } else {
                let mut presentation = base_presentation.clone();
                presentation.evidence = Some(vec![PresentedEvidence {
                    requirement_id: "launch-email-domain".to_string(),
                    presentation: case["evidencePresentation"].clone(),
                }]);
                resign_presentation(&mut presentation, &vector_holder_signing_key());
                presentation
            };
            let requirement: EvidenceRequirement =
                serde_json::from_value(case["requirement"].clone()).unwrap();
            let policy = launch_policy_from_presentation(&presentation, requirement);
            let now = parse_time(case["context"]["now"].as_str().unwrap());
            let mut service =
                PolicyEngineService::try_new(launch_service_config(&reject_file, policy))
                    .unwrap()
                    .with_fixed_now_for_tests(now);
            service
                .issue_challenge_with_nonce_for_tests(
                    &presentation.policy_id,
                    presentation.nonce.clone(),
                )
                .unwrap();
            let app = router(service);
            let (status, value, observed_body) = post_observed(
                app,
                "/policy/v0/resolve",
                json!({ "presentation": serde_json::to_value(&presentation).unwrap() }),
            )
            .await;
            assert_ne!(status, StatusCode::OK, "{}", case["name"]);
            let expected_code = case["rejection_code"].as_str().unwrap();
            assert_observed_denial_fixture(
                expected_code,
                runtime_denial_status(expected_code),
                status,
                &observed_body,
                &value,
            );
        }
    }

    #[tokio::test]
    async fn launch_profile_freshness_cannot_be_bypassed_with_spoofed_status_fields() {
        let accept_file: Value = serde_json::from_str(LAUNCH_PROFILE_ACCEPT).unwrap();
        let reject_file: Value = serde_json::from_str(LAUNCH_PROFILE_REJECT).unwrap();
        let freshness_case = reject_file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "freshness-unestablishable-status-required")
            .unwrap();
        let accept_case = &accept_file["cases"][0];
        let mut presentation: GrantPresentation =
            serde_json::from_value(accept_case["grantPresentation"].clone()).unwrap();
        let mut spoofed_evidence = freshness_case["evidencePresentation"].clone();
        spoofed_evidence["status"] = json!({ "state": "active" });
        spoofed_evidence["statusCheckedAt"] = json!("2026-06-12T00:02:00Z");
        presentation.evidence = Some(vec![PresentedEvidence {
            requirement_id: "launch-email-domain".to_string(),
            presentation: spoofed_evidence,
        }]);
        resign_presentation(&mut presentation, &vector_holder_signing_key());
        let requirement: EvidenceRequirement =
            serde_json::from_value(freshness_case["requirement"].clone()).unwrap();
        let policy = launch_policy_from_presentation(&presentation, requirement);
        let now = parse_time(freshness_case["context"]["now"].as_str().unwrap());
        let mut service = PolicyEngineService::try_new(launch_service_config(&reject_file, policy))
            .unwrap()
            .with_fixed_now_for_tests(now);
        service
            .issue_challenge_with_nonce_for_tests(
                &presentation.policy_id,
                presentation.nonce.clone(),
            )
            .unwrap();

        let (status, value, observed_body) = post_observed(
            router(service),
            "/policy/v0/resolve",
            json!({ "presentation": serde_json::to_value(&presentation).unwrap() }),
        )
        .await;
        assert_observed_denial_fixture(
            "evidence-freshness-unestablishable",
            StatusCode::UNPROCESSABLE_ENTITY,
            status,
            &observed_body,
            &value,
        );
    }

    #[tokio::test]
    async fn holder_enrollment_rollback_vectors_fail_through_http() {
        let vector: Value = serde_json::from_str(HOLDER_ENROLLMENT_ROLLBACK).unwrap();

        for case in vector["cases"].as_array().unwrap() {
            let presentation: GrantPresentation = if let Some(presentation) =
                case.get("presentation")
            {
                serde_json::from_value(presentation.clone()).unwrap()
            } else {
                let mut presentation: GrantPresentation =
                    serde_json::from_value(vector["cases"][1]["presentation"].clone()).unwrap();
                let HolderBindingProof::EnrolledAgent { status, .. } =
                    &mut presentation.holder_binding;
                *status = Some(
                    serde_json::from_value(case["later_active_status_envelope"].clone()).unwrap(),
                );
                presentation.nonce = "l3JvbGxiYWNrLWlycmV2ZXJzaWJsZS1ub25jZQ".to_string();
                resign_presentation(&mut presentation, &vector_holder_signing_key());
                presentation
            };
            let mut cfg = config(subject_policy_from_presentation(&presentation));
            cfg.enrollment_statuses = vector["engine_observed_statuses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|status| serde_json::from_value(status.clone()).unwrap())
                .collect();
            let mut service = PolicyEngineService::try_new(cfg)
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now());
            service
                .issue_challenge_with_nonce_for_tests(
                    &presentation.policy_id,
                    presentation.nonce.clone(),
                )
                .unwrap();
            let app = router(service);
            let (status, value, observed_body) = post_observed(
                app,
                "/policy/v0/resolve",
                json!({ "presentation": serde_json::to_value(&presentation).unwrap() }),
            )
            .await;
            assert_ne!(status, StatusCode::OK, "{}", case["name"]);
            let expected_code = case["rejection_code"].as_str().unwrap();
            assert_observed_denial_fixture(
                expected_code,
                runtime_denial_status(expected_code),
                status,
                &observed_body,
                &value,
            );
        }
    }

    #[test]
    fn missing_config_refuses_to_start() {
        let mut cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        cfg.issuer_keys.clear();
        assert!(matches!(
            PolicyEngineService::try_new(cfg),
            Err(StartupError::Missing("issuer_keys"))
        ));
    }

    #[test]
    fn raw_authority_state_requires_signed_objects() {
        let cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid(
                "authority_state_requires_signed_objects"
            ))
        ));
    }

    #[test]
    fn demo_operations_require_configured_bearer_token() {
        let mut cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        cfg.demo_operations_enabled = true;
        assert!(matches!(
            PolicyEngineService::try_new(cfg),
            Err(StartupError::Missing("demo_operations_bearer_token"))
        ));
    }

    #[test]
    fn grant_issuer_signer_mismatch_refuses_to_start() {
        let mut cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        cfg.grant_issuer_signer_seed = [6_u8; 32];
        assert!(matches!(
            PolicyEngineService::try_new(cfg),
            Err(StartupError::Invalid("grant_issuer_signer_seed"))
        ));
    }

    #[test]
    fn policy_engine_record_grant_issuer_mismatch_refuses_to_start() {
        let mut cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        cfg.policy_engine_records
            .push(policy_core::PolicyEngineRecord {
                schema: policy_core::POLICY_ENGINE_RECORD_SCHEMA.to_string(),
                engine_record_id: "peng_test".to_string(),
                owner_did: "did:key:z6Mkowner".to_string(),
                endpoint: "https://policy-engine.example/v0".to_string(),
                audience: cfg.audience.clone(),
                supported_policy_versions: vec![policy_core::POLICY_SCHEMA.to_string()],
                supported_evidence_verifiers: vec!["w3c.vc/credential/v1".to_string()],
                grant_issuer_did: "did:key:z6Mkdifferent".to_string(),
                expires_at: "2026-07-01T00:00:00Z".to_string(),
                signature: Signature {
                    suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                    signer_did: "did:key:z6Mkowner".to_string(),
                    value: String::new(),
                },
            });
        assert!(matches!(
            PolicyEngineService::try_new(cfg),
            Err(StartupError::Invalid(
                "policy_engine_record.grant_issuer_did"
            ))
        ));
    }

    #[test]
    fn signed_object_loader_rejects_generically_signed_wrong_authority_state() {
        let owner_key = SigningKey::from_bytes(&[9_u8; 32]);
        let owner_did = did_key_from_ed25519(owner_key.verifying_key().as_bytes());
        let other_key = SigningKey::from_bytes(&[10_u8; 32]);
        let other_did = did_key_from_ed25519(other_key.verifying_key().as_bytes());
        let record = sign_policy_engine_record(
            policy_core::PolicyEngineRecord {
                schema: policy_core::POLICY_ENGINE_RECORD_SCHEMA.to_string(),
                engine_record_id: "peng_test".to_string(),
                owner_did,
                endpoint: "https://policy-engine.example/v0".to_string(),
                audience: "https://policy-engine.example/v0".to_string(),
                supported_policy_versions: vec![policy_core::POLICY_SCHEMA.to_string()],
                supported_evidence_verifiers: vec!["w3c.vc/credential/v1".to_string()],
                grant_issuer_did: grant_issuer_did(),
                expires_at: "2026-07-01T00:00:00Z".to_string(),
                signature: Signature {
                    suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                    signer_did: other_did,
                    value: String::new(),
                },
            },
            &other_key,
        );

        let mut cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        cfg.policies.clear();
        assert!(matches!(
            from_signed_objects_for_tests(cfg, [serde_json::to_value(record).unwrap()]),
            Err(StartupError::Invalid("policy_engine_record.authority"))
        ));
    }

    #[test]
    fn signed_object_loader_rejects_preloaded_authority_state() {
        let cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        assert!(matches!(
            from_signed_objects_for_tests(cfg, Vec::<Value>::new()),
            Err(StartupError::Invalid("signed_objects.preloaded_state"))
        ));
    }

    #[test]
    fn signed_object_loader_rejects_grant_challenge_signed_object() {
        let challenge = signed_profile_objects("GrantChallenge")
            .into_iter()
            .next()
            .expect("signed GrantChallenge vector");

        assert!(matches!(
            from_signed_objects_for_tests(vector_authority_config(), [challenge]),
            Err(StartupError::UnsupportedSignedObject("GrantChallenge"))
        ));
    }

    #[test]
    fn signed_object_loader_accepts_operational_key_grant_issuer_chain() {
        let mut objects = signed_profile_objects("OperationalKeyAuthorization");
        objects.extend(
            signed_profile_objects("OperationalKeyStatus")
                .into_iter()
                .filter(|object| object["disposition"] == "active"),
        );
        objects.extend(signed_profile_objects("Policy"));
        objects.extend(signed_profile_objects("PolicyEngineRecord"));

        let service = from_signed_objects_for_tests(vector_authority_config(), objects)
            .expect("canonical signed-object authority chain loads");
        assert!(service
            .policy_revocations
            .values()
            .any(|revocation| revocation == &RevocationMode::ActiveCutoff));
    }

    #[tokio::test]
    async fn signed_object_loader_never_seeds_resolvable_challenges() {
        let mut objects = signed_profile_objects("OperationalKeyAuthorization");
        objects.extend(
            signed_profile_objects("OperationalKeyStatus")
                .into_iter()
                .filter(|object| object["disposition"] == "active"),
        );
        objects.extend(signed_profile_objects("Policy"));
        objects.extend(signed_profile_objects("PolicyEngineRecord"));
        let service = from_signed_objects_for_tests(vector_authority_config(), objects)
            .expect("authority objects load without challenges")
            .with_fixed_now_for_tests(fixed_test_now());

        let challenge_value = signed_profile_objects("GrantChallenge")
            .into_iter()
            .find(|challenge| {
                challenge["policyId"] == "pol_zkeogyy27jzggzg2bnl5rrvnhcqz55szsemlbjzpkqrgdgoe7pga"
            })
            .expect("subject-only challenge vector");
        let challenge: GrantChallenge = serde_json::from_value(challenge_value).unwrap();
        let signer = vector_policy_signing_key();
        let signer_did = did_key_from_ed25519(signer.verifying_key().as_bytes());
        let owner_did = "did:pkh:eip155:1:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        let cap: PolicyCapability = serde_json::from_value(json!({
            "service": "tinycloud.kv",
            "space": "applications",
            "path": "notebooks/nb_project_notes/docs/",
            "actions": ["tinycloud.kv/get"]
        }))
        .unwrap();
        let mut presentation = presentation(&challenge, &signer, owner_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.signing_key_did = signer_did.clone();
        enrollment.signature.signer_did = signer_did.clone();
        *enrollment = sign_enrollment(enrollment.clone(), &signer);
        resign_presentation(&mut presentation, &signer);

        let (status, value) = post(
            router(service),
            "/policy/v0/resolve",
            json!({ "presentation": presentation }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"]["code"], "challenge-not-found");
        assert_ne!(signer_did, owner_did);
    }

    #[test]
    fn signed_object_loader_rejects_record_without_grant_issuer_authorization() {
        let mut objects = signed_profile_objects("OperationalKeyAuthorization")
            .into_iter()
            .filter(|object| {
                !object["roles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|role| role == "grant-issuer")
            })
            .collect::<Vec<_>>();
        objects.extend(signed_profile_objects("PolicyEngineRecord"));

        assert!(matches!(
            from_signed_objects_for_tests(vector_authority_config(), objects),
            Err(StartupError::Invalid(
                "policy_engine_record.grant_issuer_authority"
            ))
        ));
    }

    #[test]
    fn signed_object_loader_rejects_retired_policy_signer_status() {
        let mut objects = signed_profile_objects("OperationalKeyAuthorization");
        objects.extend(
            signed_profile_objects("OperationalKeyStatus")
                .into_iter()
                .filter(|object| {
                    let authorization_id = object["authorizationId"].as_str().unwrap();
                    let disposition = object["disposition"].as_str().unwrap();
                    let sequence = object["sequence"].as_u64().unwrap();
                    (authorization_id
                        == "opka_akvffwprvvuqzqyeu24vtnphzj3xncpxmhd2yzlkl7uoggi6hptq"
                        && (disposition == "active" || disposition == "retired" && sequence == 2))
                        || authorization_id
                            == "opka_qoxwouy7n4hve5ychhovbeuazsll3rrmj3gydx3vmcomswa3efca"
                }),
        );
        objects.extend(signed_profile_objects("Policy"));
        objects.extend(signed_profile_objects("PolicyEngineRecord"));

        assert!(matches!(
            from_signed_objects_for_tests(vector_authority_config(), objects),
            Err(StartupError::Invalid("policy_engine_record.authority"))
        ));
    }

    #[test]
    fn signed_object_loader_rejects_compromised_policy_signer_status() {
        let mut objects = signed_profile_objects("OperationalKeyAuthorization");
        objects.extend(
            signed_profile_objects("OperationalKeyStatus")
                .into_iter()
                .filter(|object| {
                    let authorization_id = object["authorizationId"].as_str().unwrap();
                    let disposition = object["disposition"].as_str().unwrap();
                    (authorization_id
                        == "opka_akvffwprvvuqzqyeu24vtnphzj3xncpxmhd2yzlkl7uoggi6hptq"
                        && (disposition == "active" || disposition == "compromised"))
                        || authorization_id
                            == "opka_qoxwouy7n4hve5ychhovbeuazsll3rrmj3gydx3vmcomswa3efca"
                }),
        );
        objects.extend(signed_profile_objects("Policy"));
        objects.extend(signed_profile_objects("PolicyEngineRecord"));

        assert!(matches!(
            from_signed_objects_for_tests(vector_authority_config(), objects),
            Err(StartupError::Invalid("policy.authority"))
        ));
    }

    #[test]
    fn launch_profile_fixtures_are_canonical_and_pinned() {
        assert!(serde_json::from_str::<Value>(LAUNCH_PROFILE_ACCEPT).unwrap()["cases"].is_array());
        assert!(serde_json::from_str::<Value>(LAUNCH_PROFILE_REJECT).unwrap()["cases"].is_array());
        assert_eq!(VECTOR_COMMIT_SHA.len(), 40);
    }

    #[test]
    fn date_fields_reject_before_signature_shortcut_code_is_lost() {
        let cap = capability();
        let policy_id = "pol_http_dates";
        let (holder_key, holder_did) = holder_key();
        let mut svc =
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now());
        let challenge = svc
            .issue_challenge(ChallengeRequest {
                policy_id: policy_id.to_string(),
            })
            .unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        presentation.expires_at = "not-rfc3339".to_string();
        let err = svc
            .resolve(ResolveRequest {
                presentation: serde_json::to_value(presentation).unwrap(),
            })
            .expect_err("bad date rejects");
        assert_eq!(err.code(), "presentation-expired");
    }

    #[tokio::test]
    async fn enrollment_date_fields_reject_before_signature_verification() {
        async fn enrollment_date_case(
            policy_id: &str,
            expected_code: &str,
            mutate: impl FnOnce(&mut HolderEnrollment),
        ) {
            let cap = capability();
            let (holder_key, holder_did) = holder_key();
            let app = router(
                PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                    .unwrap()
                    .with_fixed_now_for_tests(fixed_test_now()),
            );
            let (challenge_status, challenge_body) = post(
                app.clone(),
                "/policy/v0/challenge",
                json!({ "policyId": policy_id }),
            )
            .await;
            assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
            let challenge: GrantChallenge =
                serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
            let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
            let HolderBindingProof::EnrolledAgent { enrollment, .. } =
                &mut presentation.holder_binding;
            mutate(enrollment);
            *enrollment = sign_enrollment(enrollment.clone(), &holder_key);
            resign_presentation(&mut presentation, &holder_key);

            let body = json!({ "presentation": presentation });
            let (status, value, observed_body) =
                post_observed(app, "/policy/v0/resolve", body).await;
            assert_observed_denial_fixture(
                expected_code,
                StatusCode::FORBIDDEN,
                status,
                &observed_body,
                &value,
            );
        }

        enrollment_date_case(
            "pol_http_enrollment_not_before_date",
            "enrollment-not-yet-valid",
            |enrollment| {
                enrollment.not_before = "not-rfc3339".to_string();
            },
        )
        .await;
        enrollment_date_case(
            "pol_http_enrollment_expires_at_date",
            "enrollment-expired",
            |enrollment| {
                enrollment.expires_at = Some("not-rfc3339".to_string());
            },
        )
        .await;
    }

    #[tokio::test]
    async fn enrollment_status_date_fields_reject_before_signature_verification() {
        let cap = capability();
        let policy_id = "pol_http_enrollment_status_dates";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, status } =
            &mut presentation.holder_binding;
        let mut active_status = enrollment_status(&enrollment.enrollment_id, &holder_key);
        active_status.effective_at = "not-rfc3339".to_string();
        *status = Some(sign_enrollment_status(active_status, &holder_key));
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value) = post(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(value["error"]["code"], "enrollment-status-rollback");

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn pre_runtime_rejections_still_consume_nonce_once() {
        let cap = capability();
        let policy_id = "pol_http_pre_runtime_consume";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.signature.value = "truncated".to_string();
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value, observed_body) =
            post_observed(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_observed_denial_fixture(
            "signature-invalid",
            StatusCode::FORBIDDEN,
            status,
            &observed_body,
            &value,
        );

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn unauthorized_enrollment_signer_uses_frozen_code_and_consumes_nonce() {
        let cap = capability();
        let policy_id = "pol_http_unauthorized_enrollment_signer";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let other_key = SigningKey::from_bytes(&[11_u8; 32]);
        let other_did = did_key_from_ed25519(other_key.verifying_key().as_bytes());
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.signing_key_did = other_did.clone();
        enrollment.signature.signer_did = other_did;
        *enrollment = sign_enrollment(enrollment.clone(), &other_key);
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value, observed_body) =
            post_observed(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_observed_denial_fixture(
            "signer-not-authorized",
            StatusCode::FORBIDDEN,
            status,
            &observed_body,
            &value,
        );

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn holder_enrollment_signed_object_digest_mismatch_uses_frozen_code_and_consumes_nonce() {
        let cap = capability();
        let policy_id = "pol_http_enrollment_digest_mismatch";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.not_before = "2026-05-31T00:00:00Z".to_string();
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value, observed_body) =
            post_observed(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_observed_denial_fixture(
            "digest-mismatch",
            StatusCode::FORBIDDEN,
            status,
            &observed_body,
            &value,
        );

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn holder_enrollment_signed_object_id_mismatch_uses_frozen_code_and_consumes_nonce() {
        let cap = capability();
        let policy_id = "pol_http_enrollment_id_mismatch";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.enrollment_id = "not-a-holder-enrollment-id".to_string();
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value, observed_body) =
            post_observed(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_observed_denial_fixture(
            "id-mismatch",
            StatusCode::FORBIDDEN,
            status,
            &observed_body,
            &value,
        );

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn holder_enrollment_signed_object_signer_mismatch_uses_frozen_code_and_consumes_nonce() {
        let cap = capability();
        let policy_id = "pol_http_enrollment_signed_object_signer_mismatch";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let other_key = SigningKey::from_bytes(&[12_u8; 32]);
        let other_did = did_key_from_ed25519(other_key.verifying_key().as_bytes());
        let HolderBindingProof::EnrolledAgent { enrollment, .. } = &mut presentation.holder_binding;
        enrollment.signature.signer_did = other_did;
        *enrollment = sign_enrollment(enrollment.clone(), &holder_key);
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value) = post(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(value["error"]["code"], "signer-not-authorized");

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[tokio::test]
    async fn holder_enrollment_status_signed_object_signature_invalid_uses_frozen_code() {
        let cap = capability();
        let policy_id = "pol_http_enrollment_status_signature_invalid";
        let (holder_key, holder_did) = holder_key();
        let app = router(
            PolicyEngineService::try_new(config(policy(policy_id, cap.clone(), &holder_did)))
                .unwrap()
                .with_fixed_now_for_tests(fixed_test_now()),
        );
        let (challenge_status, challenge_body) = post(
            app.clone(),
            "/policy/v0/challenge",
            json!({ "policyId": policy_id }),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::OK, "{challenge_body:?}");
        let challenge: GrantChallenge =
            serde_json::from_value(challenge_body["challenge"].clone()).unwrap();
        let mut presentation = presentation(&challenge, &holder_key, &holder_did, cap);
        let HolderBindingProof::EnrolledAgent { enrollment, status } =
            &mut presentation.holder_binding;
        let mut active_status = enrollment_status(&enrollment.enrollment_id, &holder_key);
        active_status.signature.value = "truncated".to_string();
        *status = Some(active_status);
        resign_presentation(&mut presentation, &holder_key);

        let body = json!({ "presentation": presentation });
        let (status, value) = post(app.clone(), "/policy/v0/resolve", body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(value["error"]["code"], "signature-invalid");

        let (replay_status, replay_value) = post(app, "/policy/v0/resolve", body).await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_value["error"]["code"], "challenge-nonce-consumed");
    }

    #[test]
    fn malformed_policy_date_refuses_to_start() {
        let mut cfg = config(policy("pol_http", capability(), "did:key:z6Mksubject"));
        cfg.policies[0].created_at = "not-rfc3339".to_string();
        assert!(matches!(
            PolicyEngineService::try_new(cfg),
            Err(StartupError::Invalid("policy.created_at"))
        ));
    }

    #[test]
    fn evidence_wrapper_accepts_launch_wire_presentation_shape() {
        let verifier = SharedVcEvidenceVerifier::new(BTreeMap::from([(
            "did:web:issuer.credentials.org".to_string(),
            jwk(),
        )]));
        let normalized = normalize_evidence_presentation(&json!({
            "format": "sd-jwt+jwt",
            "value": "abc.def.ghi"
        }));
        assert_eq!(normalized, json!({ "sdJwt": "abc.def.ghi" }));
        drop(verifier);
    }

    #[test]
    fn evidence_policy_is_available_for_http_tests() {
        let cap = capability();
        let _policy = Policy {
            when: policy_core::Expression::AllOf(AllOfExpression {
                all_of: vec![policy_core::Expression::Evidence(EvidenceExpression {
                    evidence: EvidenceRequirement {
                        requirement_id: "launch-email-domain".to_string(),
                        verifier: "w3c.vc/credential/v1".to_string(),
                        requirements: json!({
                            "type": "opencredentials.email/v1",
                            "emailDomains": ["credentials.org"]
                        }),
                        authority: None,
                        freshness: None,
                    },
                })],
            }),
            ..policy("pol_evidence", cap, "did:key:z6Mksubject")
        };
    }

    fn direct_issued_grant(policy: Policy) -> (SharedGrantIssuer, PortableDelegation, String) {
        let parent = parent_for_policy(&policy, &grant_issuer_did());
        let mut issuer =
            SharedGrantIssuer::new(grant_issuer_did(), grant_issuer_signing_key(), [parent]);
        let now = fixed_test_now();
        let delegation = issuer
            .issue(GrantIssueRequest {
                holder_did: "did:key:z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5".to_string(),
                capabilities: policy.resource.permissions_ceiling.clone(),
                issued_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                presentation_expires_at: now + chrono::Duration::minutes(5),
                terminal: true,
                evidence_ids: vec!["must-not-leak".to_string()],
                evidence_provenance: Vec::new(),
                policy,
            })
            .unwrap();
        let facts = decode_signed_delegation(&delegation.encoded)["fct"]
            .as_array()
            .unwrap()
            .clone();
        let issuance_id = facts[0]["xyz.tinycloud.policy/issuanceId"]
            .as_str()
            .unwrap()
            .to_string();
        (issuer, delegation, issuance_id)
    }

    fn issue_python_accept_vector_semantics(
        empty_parent_caveats: bool,
    ) -> (SharedGrantIssuer, PortableDelegation, Value) {
        let vectors: Value = serde_json::from_str(GRANT_OUTPUT_ACCEPT).unwrap();
        let vector = &vectors["cases"][0];
        let vector_payload = &vector["ucan"]["payload"];
        let expected = &vector["expectedExtractedCapability"];
        let capability = policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.sql",
            "space": "applications",
            "path": expected["resource"]
                .as_str()
                .unwrap()
                .split_once("/sql/")
                .unwrap()
                .1,
            "actions": [expected["ability"].as_str().unwrap()],
            "caveats": expected["notaBene"]["0"].clone(),
        }))
        .unwrap();
        let owner = vectors["parentFormatVector"]["issuer"].as_str().unwrap();
        let mut policy = policy(
            vector_payload["fct"][0]["xyz.tinycloud.policy/policyId"]
                .as_str()
                .unwrap(),
            capability.clone(),
            owner,
        );
        policy.grant.revocation = RevocationMode::RefreshOnly;

        let signing_key = SigningKey::from_bytes(&[0x22_u8; 32]);
        let issuer_did = did_key_from_ed25519(signing_key.verifying_key().as_bytes());
        let artifact_base64_url = vectors["parentFormatVector"]["dagCborBase64Url"]
            .as_str()
            .unwrap()
            .to_string();
        let expected_cid = vectors["parentFormatVector"]["expectedCid"]
            .as_str()
            .unwrap()
            .to_string();
        let not_before = Some(
            DateTime::parse_from_rfc3339(
                vectors["parentFormatVector"]["issuedAt"].as_str().unwrap(),
            )
            .unwrap()
            .with_timezone(&Utc),
        );
        let expires_at = DateTime::parse_from_rfc3339(
            vectors["parentFormatVector"]["expiresAt"].as_str().unwrap(),
        )
        .unwrap()
        .with_timezone(&Utc);
        let bound = ParentCapabilityBound {
            policy_capability: if empty_parent_caveats {
                PolicyCapability {
                    caveats: None,
                    ..capability.clone()
                }
            } else {
                capability.clone()
            },
            native_resource: expected["resource"].as_str().unwrap().to_string(),
        };
        let parent = ParentDelegationConfig {
            owner_did: owner.to_string(),
            artifact_base64_url,
            expected_cid: expected_cid.clone(),
            audience: issuer_did.clone(),
            not_before,
            expires_at,
            terminal: false,
            capability_bounds: vec![bound.clone()],
            delegate_receipt: CapturedParentDelegateReceipt {
                delegation_id: expected_cid,
                delegatee_did: issuer_did.clone(),
                not_before,
                expires_at,
                terminal: false,
                capability_bounds: vec![bound],
            },
        };
        let mut issuer = SharedGrantIssuer::new(issuer_did, signing_key, [parent]);
        let issued_at =
            DateTime::from_timestamp(vector_payload["nbf"].as_i64().unwrap(), 0).unwrap();
        let delegation = issuer
            .issue(GrantIssueRequest {
                holder_did: vector_payload["aud"].as_str().unwrap().to_string(),
                capabilities: vec![capability],
                issued_at,
                expires_at: DateTime::from_timestamp(vector_payload["exp"].as_i64().unwrap(), 0)
                    .unwrap(),
                presentation_expires_at: DateTime::from_timestamp(
                    vector_payload["exp"].as_i64().unwrap(),
                    0,
                )
                .unwrap(),
                terminal: true,
                evidence_ids: Vec::new(),
                evidence_provenance: Vec::new(),
                policy,
            })
            .unwrap();
        (issuer, delegation, vectors)
    }

    #[tokio::test]
    async fn production_ucan_semantics_and_python_vector_verify_with_independent_pinned_ssi() {
        // Semantic-interoperability test: the production issuance ID is random,
        // so byte equality with the independently generated Python token is not asserted.
        let (_, delegation, vectors) = issue_python_accept_vector_semantics(false);
        let accept_cases = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| case["case"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            accept_cases,
            BTreeSet::from([
                "deterministic-native-identity-and-ledger-link",
                "empty-parent-caveats-permit-child-narrowing",
                "valid-bounded-node-native-ucan",
            ])
        );
        let production = decode_and_verify_with_pinned_ssi(&delegation.encoded).await;
        assert_eq!(production.payload().proof.len(), 1);
        assert!(production.payload().issuer.as_str().contains('#'));
        assert!(production.payload().audience.as_str().starts_with("did:"));
        assert!(production.payload().not_before.is_some());
        assert_eq!(production.payload().facts.as_ref().unwrap().len(), 1);

        let python_token = vectors["cases"][0]["ucan"]["encoded"].as_str().unwrap();
        let python = decode_and_verify_with_pinned_ssi(python_token).await;
        assert_eq!(python.payload().proof.len(), 1);
        assert_eq!(python.payload().facts.as_ref().unwrap().len(), 1);
        assert_eq!(
            native_cid(python_token.as_bytes()),
            vectors["cases"][1]["issuanceRecord"]["delegationId"]
        );

        let segments = delegation.encoded.split('.').collect::<Vec<_>>();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["ucv"], "0.10.0");
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");
        assert!(payload["nbf"].is_i64() && payload["exp"].is_i64());
        assert!(payload["att"]
            .as_object()
            .unwrap()
            .values()
            .all(|abilities| {
                abilities.as_object().unwrap().values().all(|nota_bene| {
                    !nota_bene.as_array().unwrap().is_empty()
                        && nota_bene.as_array().unwrap().iter().all(Value::is_object)
                })
            }));
        let vector = &vectors["cases"][0];
        let expected = &vector["expectedExtractedCapability"];
        assert_eq!(
            payload["att"][expected["resource"].as_str().unwrap()]
                [expected["ability"].as_str().unwrap()][0],
            expected["notaBene"]["0"]
        );
        assert_eq!(
            payload["fct"][0]["xyz.tinycloud.policy/capabilityHashHex"],
            vector["ucan"]["payload"]["fct"][0]["xyz.tinycloud.policy/capabilityHashHex"]
        );
        assert_eq!(payload["prf"], vector["ucan"]["payload"]["prf"]);
        assert_eq!(payload["aud"], vector["ucan"]["payload"]["aud"]);
        assert_eq!(payload["nbf"], vector["ucan"]["payload"]["nbf"]);
        assert_eq!(payload["exp"], vector["ucan"]["payload"]["exp"]);
        assert_eq!(
            payload["fct"][0]["xyz.tinycloud.policy/policyId"],
            vector["ucan"]["payload"]["fct"][0]["xyz.tinycloud.policy/policyId"]
        );
        assert_eq!(
            payload["fct"][0]["xyz.tinycloud.policy/revocationMode"],
            "refresh_only"
        );
        assert_eq!(
            payload["fct"][0]["xyz.tinycloud.policy/delegationMode"],
            "terminal"
        );
        assert_eq!(
            delegation.issuer_did,
            vector["portableDelegation"]["issuerDid"]
        );
        assert_eq!(
            delegation.holder_did,
            vector["portableDelegation"]["holderDid"]
        );
        assert_eq!(
            delegation.policy_id,
            vector["portableDelegation"]["policyId"]
        );
        assert_eq!(
            delegation.terminal,
            vector["portableDelegation"]["terminal"]
        );
    }

    #[tokio::test]
    async fn pinned_ssi_oracle_protected_header_requirements_and_variants() {
        // Semantic-interoperability case; exact production header bytes are checked
        // as decoded fields, while alternate valid JSON ordering is not byte-compared.
        let (encoded, mut header, payload, key) = oracle_fixture();
        decode_and_verify_with_pinned_ssi(&encoded).await;
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["ucv"], "0.10.0");
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");

        let valid = header.clone();
        header.as_object_mut().unwrap().remove("typ");
        assert_oracle_decode_rejects(
            "protected-header-missing-typ",
            &sign_test_ucan(&header, &payload, &key),
        );
        header = valid.clone();
        header["typ"] = json!("UCAN");
        assert_oracle_decode_rejects(
            "protected-header-wrong-typ",
            &sign_test_ucan(&header, &payload, &key),
        );
        header = valid.clone();
        header.as_object_mut().unwrap().remove("ucv");
        assert_oracle_decode_rejects(
            "protected-header-missing-ucv",
            &sign_test_ucan(&header, &payload, &key),
        );
        header = valid.clone();
        header["ucv"] = json!("0.9.1");
        assert_oracle_decode_rejects(
            "protected-header-wrong-ucv",
            &sign_test_ucan(&header, &payload, &key),
        );
        header = valid.clone();
        header["alg"] = json!("not-a-supported-jose-algorithm");
        assert_oracle_decode_rejects(
            "protected-header-wrong-alg",
            &sign_test_ucan(&header, &payload, &key),
        );

        // The pinned oracle can resolve a did:key without the embedded JWK. The
        // frozen producer contract is stricter, so production's JWK assertion above
        // is byte-shape conformance rather than an oracle-enforced requirement.
        header = valid;
        header.as_object_mut().unwrap().remove("jwk");
        decode_and_verify_with_pinned_ssi(&sign_test_ucan(&header, &payload, &key)).await;
    }

    #[test]
    fn pinned_ssi_oracle_base64url_rules() {
        let (encoded, _, _, _) = oracle_fixture();
        let segments = encoded.split('.').collect::<Vec<_>>();
        assert_oracle_decode_rejects(
            "base64url-padding",
            &format!("{}=.{}.{}", segments[0], segments[1], segments[2]),
        );
        assert_oracle_decode_rejects(
            "base64url-invalid-alphabet",
            &format!("*.{}.{}", segments[1], segments[2]),
        );
        assert!(segments.iter().all(|segment| !segment.contains('=')));
    }

    #[test]
    fn pinned_ssi_oracle_numeric_dates() {
        let (_, header, mut payload, key) = oracle_fixture();
        assert!(payload["nbf"].is_i64() && payload["exp"].is_i64());
        payload["exp"] = json!("1783685100");
        assert_oracle_decode_rejects("string-exp", &sign_test_ucan(&header, &payload, &key));
        let (_, header, mut payload, key) = oracle_fixture();
        payload["nbf"] = json!("1783684800");
        assert_oracle_decode_rejects("string-nbf", &sign_test_ucan(&header, &payload, &key));
    }

    #[tokio::test]
    async fn pinned_ssi_oracle_did_and_did_url_issuer_forms() {
        let (encoded, header, mut payload, key) = oracle_fixture();
        assert!(payload["iss"].as_str().unwrap().contains('#'));
        decode_and_verify_with_pinned_ssi(&encoded).await;

        payload["iss"] = json!(did_key_from_ed25519(key.verifying_key().as_bytes()));
        decode_and_verify_with_pinned_ssi(&sign_test_ucan(&header, &payload, &key)).await;

        payload["iss"] = json!("https://issuer.invalid");
        assert_oracle_decode_rejects("issuer-not-did", &sign_test_ucan(&header, &payload, &key));
        payload["iss"] = json!(format!(
            "{}#not-the-verification-method",
            did_key_from_ed25519(key.verifying_key().as_bytes())
        ));
        assert_oracle_signature_rejects(
            "issuer-did-url-wrong-fragment",
            &sign_test_ucan(&header, &payload, &key),
        )
        .await;
    }

    #[test]
    fn pinned_ssi_oracle_proof_shape() {
        let (_, header, mut payload, key) = oracle_fixture();
        assert_eq!(payload["prf"].as_array().unwrap().len(), 1);
        payload["prf"] = json!("not-an-array");
        assert_oracle_decode_rejects("proof-not-array", &sign_test_ucan(&header, &payload, &key));
        payload["prf"] = json!(["not-a-cid"]);
        assert_oracle_decode_rejects(
            "proof-invalid-cid",
            &sign_test_ucan(&header, &payload, &key),
        );
    }

    #[test]
    fn pinned_ssi_oracle_capability_and_nota_bene_shape() {
        let (_, header, mut payload, key) = oracle_fixture();
        payload["att"] = json!([]);
        assert_oracle_decode_rejects(
            "capability-not-object",
            &sign_test_ucan(&header, &payload, &key),
        );

        let (_, header, mut payload, key) = oracle_fixture();
        let nota_bene = payload["att"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        *nota_bene = json!([]);
        assert_oracle_decode_rejects("nota-bene-empty", &sign_test_ucan(&header, &payload, &key));

        let (_, header, mut payload, key) = oracle_fixture();
        let nota_bene = payload["att"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        *nota_bene = json!("not-an-array");
        assert_oracle_decode_rejects(
            "nota-bene-not-array",
            &sign_test_ucan(&header, &payload, &key),
        );
    }

    #[test]
    fn pinned_ssi_oracle_fact_shape_and_failures() {
        let (encoded, header, mut payload, key) = oracle_fixture();
        ssi_ucan::Ucan::<OracleProvenanceFact, Value>::decode(&encoded).unwrap();

        payload["fct"] = json!({});
        assert!(
            ssi_ucan::Ucan::<OracleProvenanceFact, Value>::decode(&sign_test_ucan(
                &header, &payload, &key
            ))
            .is_err()
        );
        payload["fct"] = json!([{"xyz.tinycloud.policy/policyId": "pol_only"}]);
        assert!(
            ssi_ucan::Ucan::<OracleProvenanceFact, Value>::decode(&sign_test_ucan(
                &header, &payload, &key
            ))
            .is_err()
        );
        payload["fct"] = json!([1]);
        assert!(
            ssi_ucan::Ucan::<OracleProvenanceFact, Value>::decode(&sign_test_ucan(
                &header, &payload, &key
            ))
            .is_err()
        );
    }

    #[test]
    fn pinned_ssi_oracle_duplicate_json_claim_behavior_is_explicit() {
        let (encoded, header, payload, key) = oracle_fixture();
        let emitted_payload = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(encoded.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(emitted_payload.matches("\"exp\"").count(), 1);

        let payload_json = serde_json::to_string(&payload).unwrap();
        let duplicate_payload = format!(
            "{{\"exp\":{},{}",
            payload["exp"],
            payload_json.strip_prefix('{').unwrap()
        );
        let token = sign_test_ucan_raw(
            &serde_json::to_string(&header).unwrap(),
            &duplicate_payload,
            &key,
        );
        assert_oracle_decode_rejects("duplicate-exp-claim", &token);
    }

    #[test]
    fn pinned_ssi_oracle_malformed_segments() {
        let (encoded, _, _, _) = oracle_fixture();
        let segments = encoded.split('.').collect::<Vec<_>>();
        for (case, token) in [
            ("two-segments", "only.two".to_string()),
            ("four-segments", format!("{encoded}.extra")),
            ("empty-header", format!(".{}.{}", segments[1], segments[2])),
            ("empty-payload", format!("{}..{}", segments[0], segments[2])),
        ] {
            assert_oracle_decode_rejects(case, &token);
        }
    }

    #[tokio::test]
    async fn pinned_ssi_oracle_signature_bytes() {
        let (encoded, _, _, _) = oracle_fixture();
        let segments = encoded.split('.').collect::<Vec<_>>();
        assert_oracle_signature_rejects(
            "empty-signature",
            &format!("{}.{}.", segments[0], segments[1]),
        )
        .await;
        assert_oracle_signature_rejects(
            "zero-signature",
            &format!(
                "{}.{}.{}",
                segments[0],
                segments[1],
                URL_SAFE_NO_PAD.encode([0_u8; 64])
            ),
        )
        .await;
        assert_oracle_signature_rejects(
            "truncated-signature",
            &format!(
                "{}.{}.{}",
                segments[0],
                segments[1],
                URL_SAFE_NO_PAD.encode([0_u8; 63])
            ),
        )
        .await;
        let mut altered = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
        altered[0] ^= 1;
        assert_oracle_signature_rejects(
            "altered-signature",
            &format!(
                "{}.{}.{}",
                segments[0],
                segments[1],
                URL_SAFE_NO_PAD.encode(altered)
            ),
        )
        .await;
    }

    #[test]
    fn bounded_parent_config_fails_closed_on_local_identity_and_receipt_mismatch() {
        let base = config(policy(
            "pol_parent",
            capability(),
            "did:pkh:eip155:1:0xparent",
        ));

        let mut cfg = base.clone();
        cfg.parent_delegations[0].expected_cid = native_cid(b"different");
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid("parent_delegations.expected_cid"))
        ));

        let mut cfg = base.clone();
        cfg.parent_delegations[0].audience = "did:key:z6Mkwrong".to_string();
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid("parent_delegations.audience"))
        ));

        let mut cfg = base.clone();
        cfg.parent_delegations[0].terminal = true;
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid("parent_delegations.terminal"))
        ));

        let mut cfg = base.clone();
        cfg.parent_delegations[0].delegate_receipt.delegatee_did = "did:key:z6Mkwrong".to_string();
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid("parent_delegations.delegate_receipt"))
        ));

        let mut cfg = base.clone();
        cfg.parent_delegations.clear();
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid("parent_delegations.policy_owner"))
        ));

        let mut cfg = base;
        cfg.parent_delegations[0].capability_bounds[0].policy_capability = other_capability();
        cfg.parent_delegations[0].capability_bounds[0].native_resource = cfg.parent_delegations[0]
            .capability_bounds[0]
            .native_resource
            .replace(
                "xyz.tinycloud.listen/conversations",
                "xyz.tinycloud.listen/other",
            );
        cfg.parent_delegations[0].delegate_receipt.capability_bounds =
            cfg.parent_delegations[0].capability_bounds.clone();
        assert!(matches!(
            cfg.validate(),
            Err(StartupError::Invalid(
                "parent_delegations.policy_capability_bounds"
            ))
        ));
    }

    #[test]
    fn startup_parent_validation_rejects_expired_parent_with_typed_error() {
        let now = fixed_test_now();
        let mut cfg = config(policy(
            "pol_parent_expired",
            capability(),
            "did:pkh:eip155:1:0xparent",
        ));
        cfg.parent_delegations[0].expires_at = now;
        cfg.parent_delegations[0].delegate_receipt.expires_at = now;

        assert!(matches!(
            cfg.validate_parent_delegations(now),
            Err(StartupError::Invalid("parent_delegations.validity"))
        ));
    }

    #[test]
    fn startup_parent_validation_rejects_not_yet_valid_parent_with_typed_error() {
        let now = fixed_test_now();
        let not_before = now + chrono::Duration::seconds(1);
        let mut cfg = config(policy(
            "pol_parent_not_yet_valid",
            capability(),
            "did:pkh:eip155:1:0xparent",
        ));
        cfg.parent_delegations[0].not_before = Some(not_before);
        cfg.parent_delegations[0].delegate_receipt.not_before = Some(not_before);

        assert!(matches!(
            cfg.validate_parent_delegations(now),
            Err(StartupError::Invalid("parent_delegations.validity"))
        ));
    }

    #[test]
    fn producer_reject_vectors_use_startup_and_issue_paths_without_emission() {
        let vectors: Value = serde_json::from_str(GRANT_OUTPUT_PRODUCER_REJECT).unwrap();
        let vector_cases = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| case["case"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        for required in [
            "grant-issuer-config-record-mismatch",
            "owner-impersonation",
            "missing-terminal-mode-fact",
            "expiry-beyond-policy-presentation-or-ttl-ceiling",
            "expiry-beyond-policy-ceiling",
            "expiry-beyond-presentation-validity",
            "malformed-or-duplicate-provenance-facts",
            "malformed-provenance-fact",
            "capability-exceeds-configured-parent-bounds",
        ] {
            assert!(vector_cases.contains(required));
        }
        let vector_case = |name: &str| {
            vectors["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["case"] == name)
                .unwrap()
        };
        let policy = policy(
            "pol_producer_reject",
            capability(),
            "did:pkh:eip155:1:0xparent",
        );
        let parent = parent_for_policy(&policy, &grant_issuer_did());
        let now = fixed_test_now();
        let request = GrantIssueRequest {
            policy: policy.clone(),
            holder_did: "did:key:z6Mkholder".to_string(),
            capabilities: policy.resource.permissions_ceiling.clone(),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            presentation_expires_at: now + chrono::Duration::minutes(5),
            terminal: true,
            evidence_ids: Vec::new(),
            evidence_provenance: Vec::new(),
        };
        let mut issuer = SharedGrantIssuer::new(
            grant_issuer_did(),
            grant_issuer_signing_key(),
            [parent.clone()],
        );

        // grant-issuer-config-record-mismatch and owner-impersonation both die
        // on the real startup path before an issuer can be constructed.
        let mut mismatched_record = config(policy.clone());
        mismatched_record
            .policy_engine_records
            .push(policy_core::PolicyEngineRecord {
                schema: policy_core::POLICY_ENGINE_RECORD_SCHEMA.to_string(),
                engine_record_id: "peng_vector_mismatch".to_string(),
                owner_did: policy.owner_did.clone(),
                endpoint: "https://policy-engine.example/v0".to_string(),
                audience: mismatched_record.audience.clone(),
                supported_policy_versions: vec![policy_core::POLICY_SCHEMA.to_string()],
                supported_evidence_verifiers: vec!["w3c.vc/credential/v1".to_string()],
                grant_issuer_did: "did:key:z6Mkdifferent".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                signature: Signature {
                    suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                    signer_did: policy.owner_did.clone(),
                    value: String::new(),
                },
            });
        assert!(matches!(
            PolicyEngineService::try_new(mismatched_record),
            Err(StartupError::Invalid(
                "policy_engine_record.grant_issuer_did"
            ))
        ));
        let mut owner_impersonation = config(policy.clone());
        owner_impersonation.grant_issuer_did = policy.owner_did.clone();
        assert!(matches!(
            PolicyEngineService::try_new(owner_impersonation),
            Err(StartupError::Invalid("grant_issuer_signer_seed"))
        ));

        let mut invalid = request.clone();
        invalid.policy.grant.revocation = RevocationMode::ActiveCutoff;
        assert!(matches!(
            issuer.issue(invalid),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "unsupported-m1-revocation-mode"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());

        let presentation_vector = vector_case("expiry-beyond-presentation-validity");
        let mut invalid = request.clone();
        invalid.issued_at = DateTime::from_timestamp(
            presentation_vector["ucan"]["payload"]["nbf"]
                .as_i64()
                .unwrap(),
            0,
        )
        .unwrap();
        invalid.expires_at = DateTime::from_timestamp(
            presentation_vector["ucan"]["payload"]["exp"]
                .as_i64()
                .unwrap(),
            0,
        )
        .unwrap();
        invalid.presentation_expires_at = DateTime::from_timestamp(
            presentation_vector["ceilings"]["presentationEpochSeconds"]
                .as_i64()
                .unwrap(),
            0,
        )
        .unwrap();
        assert!(matches!(
            issuer.issue(invalid),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "expiry-ceiling-exceeded"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());

        let mut invalid = request.clone();
        invalid.terminal = false;
        assert_eq!(
            issuer.issue(invalid).unwrap_err().as_str(),
            "grant-issuance-failed"
        );
        assert!(issuer.state.lock().unwrap().issued.is_empty());

        let ttl_vector = vector_case("expiry-beyond-policy-presentation-or-ttl-ceiling");
        let mut invalid = request.clone();
        invalid.issued_at =
            DateTime::from_timestamp(ttl_vector["ucan"]["payload"]["nbf"].as_i64().unwrap(), 0)
                .unwrap();
        invalid.expires_at =
            DateTime::from_timestamp(ttl_vector["ucan"]["payload"]["exp"].as_i64().unwrap(), 0)
                .unwrap();
        assert!(matches!(
            issuer.issue(invalid),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "expiry-ceiling-exceeded"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());

        let policy_ceiling_vector = vector_case("expiry-beyond-policy-ceiling");
        let mut invalid = request.clone();
        invalid.issued_at = DateTime::from_timestamp(
            policy_ceiling_vector["ucan"]["payload"]["nbf"]
                .as_i64()
                .unwrap(),
            0,
        )
        .unwrap();
        invalid.expires_at = DateTime::from_timestamp(
            policy_ceiling_vector["ucan"]["payload"]["exp"]
                .as_i64()
                .unwrap(),
            0,
        )
        .unwrap();
        invalid.policy.expires_at = Some(
            DateTime::from_timestamp(
                policy_ceiling_vector["ceilings"]["policyEpochSeconds"]
                    .as_i64()
                    .unwrap(),
                0,
            )
            .unwrap()
            .to_rfc3339(),
        );
        assert!(matches!(
            issuer.issue(invalid),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "expiry-ceiling-exceeded"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());

        let mut invalid = request.clone();
        invalid.capabilities = vec![other_capability()];
        assert!(matches!(
            issuer.issue(invalid),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "issue-time-parent-containment-failure"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());

        let duplicate_facts = vector_case("malformed-or-duplicate-provenance-facts")["ucan"]
            ["payload"]["fct"]
            .as_array()
            .unwrap()
            .clone();
        assert!(matches!(
            issuer.issue_candidate(
                request.clone(),
                "iss_m1g06_00000001".to_string(),
                Some(duplicate_facts),
            ),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "duplicate-provenance-fact"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());
        let malformed_facts = vector_case("malformed-provenance-fact")["ucan"]["payload"]["fct"]
            .as_array()
            .unwrap()
            .clone();
        assert!(matches!(
            issuer.issue_candidate(
                request.clone(),
                "iss_m1g06_00000001".to_string(),
                Some(malformed_facts),
            ),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "malformed-provenance-fact"
        ));
        assert!(issuer.state.lock().unwrap().issued.is_empty());
        let mut forbidden_revocation = provenance_facts(&request, "iss_1").remove(0);
        forbidden_revocation["xyz.tinycloud.policy/revocationMode"] = json!("active_cutoff");
        assert!(matches!(
            issuer.issue_candidate(
                request.clone(),
                "iss_forbidden_revocation".to_string(),
                Some(vec![forbidden_revocation.clone()]),
            ),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "malformed-provenance-fact"
        ));
        forbidden_revocation["xyz.tinycloud.policy/revocationMode"] = json!("refresh_only");
        issuer
            .issue_candidate(
                request,
                "iss_1".to_string(),
                Some(vec![forbidden_revocation]),
            )
            .unwrap();
    }

    #[test]
    fn issuance_ledger_atomically_links_id_exact_bytes_and_native_cid() {
        let vectors: Value = serde_json::from_str(GRANT_OUTPUT_AUDIT_REJECT).unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        let record_from = |value: &Value| {
            let encoded = value["encoded"].as_str().unwrap().to_string();
            IssuanceLedgerRecord {
                issuance_id: value["issuanceId"].as_str().unwrap().to_string(),
                delegation_id: value["delegationId"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| native_cid(encoded.as_bytes())),
                encoded,
            }
        };

        let missing = cases
            .iter()
            .find(|case| case["case"] == "issuance-id-without-ledger-record")
            .unwrap();
        let missing_record = IssuanceLedgerRecord {
            issuance_id: missing["ucan"]["payload"]["fct"][0]["xyz.tinycloud.policy/issuanceId"]
                .as_str()
                .unwrap()
                .to_string(),
            encoded: missing["ucan"]["encoded"].as_str().unwrap().to_string(),
            delegation_id: native_cid(missing["ucan"]["encoded"].as_str().unwrap().as_bytes()),
        };
        assert!(matches!(
            audit_ledger_linkage(&GrantIssuerState::default(), &missing_record, true),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "issuance-ledger-record-missing"
        ));

        let (mut issuer, delegation, issuance_id) = direct_issued_grant(policy(
            "pol_ledger",
            capability(),
            "did:pkh:eip155:1:0xparent",
        ));
        let link = issuer.issuance_link(&issuance_id).unwrap();
        assert_eq!(link.encoded, delegation.encoded);
        assert_eq!(link.delegation_id, delegation.delegation_id);
        assert_eq!(link.delegation_id, native_cid(link.encoded.as_bytes()));
        assert!(!issuer.is_revoked(&delegation.delegation_id));
        issuer.revoke(&delegation.delegation_id).unwrap();
        assert!(issuer.is_revoked(&delegation.delegation_id));
        let state = issuer.state.lock().unwrap();
        assert_eq!(state.ledger_by_issuance_id.len(), 1);
        assert_eq!(state.issuance_id_by_encoded[&link.encoded], issuance_id);
        assert_eq!(state.issuance_id_by_cid[&link.delegation_id], issuance_id);
        assert_eq!(state.issued[&link.delegation_id], delegation);
        audit_ledger_linkage(&state, &link, true).unwrap();
        drop(state);
        assert!(issuer.issuance_link("iss_missing").is_none());

        let mut state = issuer.state.lock().unwrap();
        let duplicate =
            SharedGrantIssuer::commit(&mut state, link, delegation.clone()).unwrap_err();
        assert!(matches!(
            duplicate,
            RuntimeError::GrantIssuanceFailed(reason) if reason == "duplicate-issuance-id-conflict"
        ));
        assert_eq!(state.ledger_by_issuance_id.len(), 1);

        let mismatch = cases
            .iter()
            .find(|case| case["case"] == "ledger-record-points-to-different-cid")
            .unwrap();
        let mismatch_record = record_from(&mismatch["ledgerRecord"]);
        assert!(matches!(
            validate_ledger_record(&mismatch_record, true),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "ledger-cid-mismatch"
        ));

        let duplicate_vector = cases
            .iter()
            .find(|case| case["case"] == "duplicate-issuance-id-different-signed-bytes")
            .unwrap();
        let vector_issuance_id = duplicate_vector["ledgerRecords"][0]["issuanceId"]
            .as_str()
            .unwrap()
            .to_string();
        let vector_policy = policy(
            "pol_vector_duplicate",
            capability(),
            "did:pkh:eip155:1:0xvector",
        );
        let vector_parent = parent_for_policy(&vector_policy, &grant_issuer_did());
        let mut vector_issuer = SharedGrantIssuer::new(
            grant_issuer_did(),
            grant_issuer_signing_key(),
            [vector_parent],
        );
        let now = fixed_test_now();
        let mut vector_request = GrantIssueRequest {
            holder_did: "did:key:z6Mkfirst".to_string(),
            capabilities: vector_policy.resource.permissions_ceiling.clone(),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            presentation_expires_at: now + chrono::Duration::minutes(5),
            terminal: true,
            evidence_ids: Vec::new(),
            evidence_provenance: Vec::new(),
            policy: vector_policy,
        };
        vector_issuer
            .issue_candidate(vector_request.clone(), vector_issuance_id.clone(), None)
            .unwrap();
        vector_request.holder_did = "did:key:z6Mksecond".to_string();
        assert!(matches!(
            vector_issuer.issue_candidate(vector_request, vector_issuance_id, None),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "duplicate-issuance-id-conflict"
        ));
        assert_eq!(vector_issuer.state.lock().unwrap().issued.len(), 1);

        let non_atomic = cases
            .iter()
            .find(|case| case["case"] == "response-before-atomically-durable-linkage")
            .unwrap();
        let non_atomic_record = record_from(&non_atomic["ledgerRecord"]);
        assert!(matches!(
            validate_ledger_record(&non_atomic_record, false),
            Err(RuntimeError::GrantIssuanceFailed(reason)) if reason == "issuance-linkage-not-atomic"
        ));
    }

    #[tokio::test]
    async fn accept_semantics_cover_identity_and_empty_parent_caveat_narrowing() {
        let owner = "did:pkh:eip155:1:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        let caveat = json!({
            "mode": "constrained-statements",
            "readOnly": true,
            "statements": [{
                "name": "listen.getConversation",
                "sql": "SELECT id FROM conversation WHERE id = ?",
                "fixedParams": [{"index": 0, "value": "conv_456"}]
            }]
        });
        let child_capability = policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.sql",
            "space": "applications",
            "path": "xyz.tinycloud.listen/conversations",
            "actions": ["tinycloud.sql/read"],
            "caveats": caveat
        }))
        .unwrap();
        let mut narrowed_policy = policy("pol_narrowed", child_capability.clone(), owner);
        narrowed_policy.grant.revocation = RevocationMode::RefreshOnly;
        let mut parent = parent_for_policy(&narrowed_policy, &grant_issuer_did());
        parent.capability_bounds[0].policy_capability.caveats = None;
        parent.delegate_receipt.capability_bounds = parent.capability_bounds.clone();
        let now = fixed_test_now();
        let request = GrantIssueRequest {
            policy: narrowed_policy,
            holder_did: "did:key:z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5".to_string(),
            capabilities: vec![child_capability],
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            presentation_expires_at: now + chrono::Duration::minutes(5),
            terminal: true,
            evidence_ids: Vec::new(),
            evidence_provenance: Vec::new(),
        };
        let issue_once = || {
            let mut issuer = SharedGrantIssuer::new(
                grant_issuer_did(),
                grant_issuer_signing_key(),
                [parent.clone()],
            );
            issuer.issue(request.clone()).unwrap()
        };
        let first = issue_once();
        let second = issue_once();
        assert_ne!(first.encoded, second.encoded);
        assert_ne!(first.delegation_id, second.delegation_id);
        assert_eq!(first.delegation_id, native_cid(first.encoded.as_bytes()));
        assert_eq!(second.delegation_id, native_cid(second.encoded.as_bytes()));
        decode_and_verify_with_pinned_ssi(&first.encoded).await;
        let payload = decode_signed_delegation(&first.encoded);
        let nota_bene = payload["att"].as_object().unwrap().values().next().unwrap()
            ["tinycloud.sql/read"][0]
            .clone();
        assert_eq!(nota_bene, caveat);
        assert_eq!(payload["prf"], json!([parent.expected_cid]));

        let (_, vector_narrowed, vectors) = issue_python_accept_vector_semantics(true);
        decode_and_verify_with_pinned_ssi(&vector_narrowed.encoded).await;
        let vector_payload = decode_signed_delegation(&vector_narrowed.encoded);
        let expected = &vectors["cases"][0]["expectedExtractedCapability"];
        assert_eq!(
            vector_payload["att"][expected["resource"].as_str().unwrap()]
                [expected["ability"].as_str().unwrap()][0],
            expected["notaBene"]["0"]
        );
        assert_eq!(vector_payload["prf"][0], vectors["cases"][2]["parentCid"]);
    }

    #[tokio::test]
    async fn capability_mapping_is_semantically_equal_to_g05a_normalization() {
        let owner = "did:pkh:eip155:1:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        let sql = capability();
        let kv = policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.kv",
            "space": "applications",
            "path": "xyz.tinycloud.listen/conversations",
            "actions": ["tinycloud.kv/get"]
        }))
        .unwrap();
        let mut differential_policy = policy("pol_differential", sql.clone(), owner);
        differential_policy.grant.revocation = RevocationMode::RefreshOnly;
        differential_policy
            .resource
            .permissions_ceiling
            .push(kv.clone());
        let (_, delegation, _) = direct_issued_grant(differential_policy);
        decode_and_verify_with_pinned_ssi(&delegation.encoded).await;
        let payload = decode_signed_delegation(&delegation.encoded);

        let mut expected = BTreeSet::new();
        for capability in [&sql, &kv] {
            // Independent reproduction of g-05a's SpaceId::to_resource mapping:
            // owner DID suffix + default store + normalized service + auth path.
            let resource = format!(
                "tinycloud:{}:default/{}/{}",
                owner.strip_prefix("did:").unwrap(),
                capability.service.strip_prefix("tinycloud.").unwrap(),
                capability.path
            );
            for ability in &capability.actions {
                expected.insert((
                    resource.clone(),
                    ability.clone(),
                    capability
                        .caveats
                        .clone()
                        .unwrap_or_else(|| json!({}))
                        .to_string(),
                ));
            }
        }
        let mut observed = BTreeSet::new();
        for (resource, abilities) in payload["att"].as_object().unwrap() {
            for (ability, nota_bene) in abilities.as_object().unwrap() {
                observed.insert((
                    resource.clone(),
                    ability.clone(),
                    nota_bene[0].clone().to_string(),
                ));
            }
        }
        assert_eq!(observed, expected);
        assert_eq!(
            payload["fct"][0]["xyz.tinycloud.policy/capabilityHashHex"],
            requested_capabilities_hash_hex(&[sql, kv])
        );
        assert_eq!(payload["aud"], delegation.holder_did);
        assert_eq!(
            payload["exp"].as_i64().unwrap() - payload["nbf"].as_i64().unwrap(),
            300
        );
        assert_eq!(
            payload["fct"][0]["xyz.tinycloud.policy/delegationMode"],
            "terminal"
        );
        assert_eq!(payload["prf"].as_array().unwrap().len(), 1);
    }
}
