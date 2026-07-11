use std::collections::{BTreeMap, HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use policy_core::{
    evaluate_expression, validate_enrolled_agent_binding, validate_grant_presentation,
    ChallengeState, EnrollmentStatusTracker, GrantChallenge, GrantOutput, GrantPresentation,
    Policy, PolicyCapability, PolicyDisposition, PolicyStatus, RevocationMode, Signature,
    SignatureSuite,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub audience: String,
    pub challenge_ttl_seconds: i64,
    pub accepted_suites: Vec<SignatureSuite>,
    /// Fixture-grade challenge signature used by the legacy harness path.
    ///
    /// Services should use [`PolicyRuntime::issue_challenge_signed`] or
    /// [`PolicyRuntime::issue_challenge_with_nonce_signed`] with a
    /// [`ChallengeSigner`] so each challenge carries a real signature over the
    /// frozen signed-object profile digest.
    pub challenge_signature: Signature,
}

#[derive(Clone, Debug, Default)]
pub struct PolicySpaceState {
    policies: HashMap<String, Policy>,
    policy_statuses: HashMap<String, PolicyStatus>,
    challenges: HashMap<String, StoredChallenge>,
    consumed_nonces: HashSet<String>,
    issuances: BTreeMap<String, IssuanceRecord>,
    enrollment_tracker: EnrollmentStatusTracker,
}

impl PolicySpaceState {
    pub fn insert_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    pub fn insert_policy_status(&mut self, status: PolicyStatus) -> Result<(), RuntimeError> {
        if let Some(previous) = self.policy_statuses.get(&status.policy_id) {
            if status.sequence <= previous.sequence {
                return Err(RuntimeError::PolicyStatusRollback);
            }
        }
        self.policy_statuses
            .insert(status.policy_id.clone(), status);
        Ok(())
    }

    pub fn apply_refreshed_policy_status(
        &mut self,
        status: PolicyStatus,
    ) -> Result<(), RuntimeError> {
        if let Some(previous) = self.policy_statuses.get(&status.policy_id) {
            if status.sequence < previous.sequence {
                return Err(RuntimeError::PolicyStatusRollback);
            }
            if status.sequence == previous.sequence {
                if previous == &status {
                    return Ok(());
                }
                return Err(RuntimeError::PolicyStatusRollback);
            }
        }
        self.policy_statuses
            .insert(status.policy_id.clone(), status);
        Ok(())
    }

    pub fn enrollment_tracker_mut(&mut self) -> &mut EnrollmentStatusTracker {
        &mut self.enrollment_tracker
    }

    pub fn issuance(&self, delegation_id: &str) -> Option<&IssuanceRecord> {
        self.issuances.get(delegation_id)
    }
}

#[derive(Clone, Debug)]
struct StoredChallenge {
    challenge: GrantChallenge,
    consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableDelegation {
    pub delegation_id: String,
    pub issuer_did: String,
    pub holder_did: String,
    pub policy_id: String,
    pub capabilities: Vec<PolicyCapability>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub terminal: bool,
    pub encoded: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantIssueRequest {
    pub policy: Policy,
    pub holder_did: String,
    pub capabilities: Vec<PolicyCapability>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The independently validated presentation ceiling. The issuer checks this
    /// again so a future runtime caller cannot bypass the producer boundary.
    pub presentation_expires_at: DateTime<Utc>,
    pub terminal: bool,
    pub evidence_ids: Vec<String>,
    pub evidence_provenance: Vec<EvidenceProvenance>,
}

pub trait GrantIssuer {
    fn issuer_did(&self) -> &str;
    fn issue(&mut self, request: GrantIssueRequest) -> Result<PortableDelegation, RuntimeError>;
    fn revoke(&mut self, delegation_id: &str) -> Result<(), RuntimeError>;
}

/// Long-term service seam for signing policy-engine grant challenges.
///
/// Implementations receive the frozen signed-object-profile digest of the
/// unsigned [`GrantChallenge`] and must return a signature over that digest.
/// The runtime validates the returned suite and signature before issuing or
/// tracking the challenge.
pub trait ChallengeSigner {
    fn sign_challenge(&mut self, digest: &[u8; 32]) -> Result<Signature, ChallengeSigningError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ChallengeSigningError {
    #[error("{0}")]
    Failed(String),
}

impl ChallengeSigningError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEvidenceContext {
    pub policy: Policy,
    pub eligible_subject_did: String,
    pub holder_did: String,
    pub requested_capabilities: Vec<PolicyCapability>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceProvenance {
    pub family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl EvidenceProvenance {
    pub fn new(family: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            source_evidence_id: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_source_evidence_id(mut self, source_evidence_id: impl Into<String>) -> Self {
        self.source_evidence_id = Some(source_evidence_id.into());
        self
    }

    pub fn with_attributes(mut self, attributes: BTreeMap<String, String>) -> Self {
        self.attributes = attributes;
        self
    }

    pub fn from_requirement(
        requirement: &policy_core::EvidenceRequirement,
        presentation: &serde_json::Value,
    ) -> Self {
        let family = requirement
            .authority
            .as_ref()
            .and_then(|authority| authority.profile.as_deref())
            .unwrap_or(&requirement.verifier);
        let mut provenance = Self::new(family);
        provenance.source_evidence_id = presentation
            .get("sourceEvidenceId")
            .or_else(|| presentation.get("source_evidence_id"))
            .or_else(|| presentation.get("id"))
            .or_else(|| presentation.get("jti"))
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        provenance
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSatisfaction {
    pub evidence_ids: Vec<String>,
    pub valid_until: Option<DateTime<Utc>>,
    pub expiry_bound_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedEvidence {
    pub requirement_id: String,
    pub evidence_ids: Vec<String>,
    pub provenance: EvidenceProvenance,
    pub valid_until: Option<DateTime<Utc>>,
    pub expiry_bound_required: bool,
}

impl TrackedEvidence {
    pub fn revocation_evidence_id(&self) -> Option<&str> {
        self.provenance.source_evidence_id.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackedEvidenceStatus {
    Active,
    Revoked,
}

pub trait TrackedEvidenceStatusVerifier {
    fn check_tracked_evidence_status(
        &mut self,
        evidence: &TrackedEvidence,
        now: DateTime<Utc>,
    ) -> Result<TrackedEvidenceStatus, RuntimeError>;
}

impl<F> TrackedEvidenceStatusVerifier for F
where
    F: FnMut(&TrackedEvidence, DateTime<Utc>) -> Result<TrackedEvidenceStatus, RuntimeError>,
{
    fn check_tracked_evidence_status(
        &mut self,
        evidence: &TrackedEvidence,
        now: DateTime<Utc>,
    ) -> Result<TrackedEvidenceStatus, RuntimeError> {
        self(evidence, now)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenancedEvidenceSatisfaction {
    pub requirement_id: String,
    pub evidence_ids: Vec<String>,
    pub provenance: EvidenceProvenance,
    pub valid_until: Option<DateTime<Utc>>,
    pub expiry_bound_required: bool,
}

impl ProvenancedEvidenceSatisfaction {
    pub fn new(satisfaction: EvidenceSatisfaction, provenance: EvidenceProvenance) -> Self {
        Self {
            requirement_id: String::new(),
            evidence_ids: satisfaction.evidence_ids,
            provenance,
            valid_until: satisfaction.valid_until,
            expiry_bound_required: satisfaction.expiry_bound_required,
        }
    }

    pub fn with_requirement_id(mut self, requirement_id: impl Into<String>) -> Self {
        self.requirement_id = requirement_id.into();
        self
    }

    pub fn tracked_evidence(&self) -> TrackedEvidence {
        TrackedEvidence {
            requirement_id: self.requirement_id.clone(),
            evidence_ids: self.evidence_ids.clone(),
            provenance: self.provenance.clone(),
            valid_until: self.valid_until,
            expiry_bound_required: self.expiry_bound_required,
        }
    }
}

pub trait EvidenceVerifier {
    fn verify(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        presentation: &serde_json::Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<EvidenceSatisfaction, RuntimeError>;

    fn verify_with_provenance(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        presentation: &serde_json::Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<ProvenancedEvidenceSatisfaction, RuntimeError> {
        let satisfaction = self.verify(requirement, presentation, context)?;
        Ok(ProvenancedEvidenceSatisfaction::new(
            satisfaction,
            EvidenceProvenance::from_requirement(requirement, presentation),
        )
        .with_requirement_id(requirement.requirement_id.clone()))
    }
}

pub trait PolicyStatusRefresher {
    fn refresh_policy_status(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<PolicyStatus>, RuntimeError>;
}

impl<F> PolicyStatusRefresher for F
where
    F: FnMut(&str, DateTime<Utc>) -> Result<Option<PolicyStatus>, RuntimeError>,
{
    fn refresh_policy_status(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<PolicyStatus>, RuntimeError> {
        self(policy_id, now)
    }
}

#[cfg(feature = "vc-evidence")]
impl EvidenceVerifier for policy_evidence_vc::VcEvidenceVerifier {
    fn verify(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        presentation: &serde_json::Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<EvidenceSatisfaction, RuntimeError> {
        let context = policy_evidence_vc::VerificationContext {
            policy: context.policy.clone(),
            eligible_subject_did: context.eligible_subject_did.clone(),
            holder_did: context.holder_did.clone(),
            requested_capabilities: context.requested_capabilities.clone(),
            now: context.now,
        };
        let satisfaction = self
            .verify(requirement, presentation, &context)
            .map_err(|error| RuntimeError::Evidence(error.as_str().to_string()))?;
        Ok(EvidenceSatisfaction {
            evidence_ids: satisfaction.evidence_ids,
            valid_until: Some(satisfaction.valid_until),
            expiry_bound_required: true,
        })
    }

    fn verify_with_provenance(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        presentation: &serde_json::Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<ProvenancedEvidenceSatisfaction, RuntimeError> {
        let context = policy_evidence_vc::VerificationContext {
            policy: context.policy.clone(),
            eligible_subject_did: context.eligible_subject_did.clone(),
            holder_did: context.holder_did.clone(),
            requested_capabilities: context.requested_capabilities.clone(),
            now: context.now,
        };
        let satisfaction = self
            .verify(requirement, presentation, &context)
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRecord {
    pub policy_id: String,
    pub eligible_subject_did: String,
    pub holder_did: String,
    pub resource_id: String,
    pub delegation_id: String,
    pub evidence_ids: Vec<String>,
    pub evidence_provenance: Vec<EvidenceProvenance>,
    pub tracked_evidence: Vec<TrackedEvidence>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation: RevocationMode,
    pub active: bool,
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("policy-not-found")]
    PolicyNotFound,
    #[error("policy-inactive")]
    PolicyInactive,
    #[error("policy-expired")]
    PolicyExpired,
    #[error("policy-status-rollback")]
    PolicyStatusRollback,
    #[error("policy-status-refresh-failed: {0}")]
    PolicyStatusRefreshFailed(String),
    #[error("challenge-not-found")]
    ChallengeNotFound,
    #[error("challenge-nonce-consumed")]
    ChallengeNonceConsumed,
    #[error("challenge-signing-failed: {0}")]
    ChallengeSigningFailed(String),
    #[error("challenge-signature-suite-not-accepted")]
    ChallengeSignatureSuiteNotAccepted,
    #[error("challenge-signature-invalid: {0}")]
    ChallengeSignatureInvalid(String),
    #[error("presentation-invalid: {0}")]
    Presentation(String),
    #[error("holder-not-authorized: {0}")]
    HolderBinding(String),
    #[error("evidence-invalid: {0}")]
    Evidence(String),
    #[error("policy-not-satisfied")]
    PolicyNotSatisfied,
    #[error("grant-issuance-failed: {0}")]
    GrantIssuanceFailed(String),
    #[error("active-cutoff-failed: {0}")]
    ActiveCutoffFailed(String),
    #[error("grant-not-found")]
    GrantNotFound,
    #[error("grant-inactive")]
    GrantInactive,
    #[error("grant-expired")]
    GrantExpired,
    #[error("evidence-revoked: {0}")]
    EvidenceRevoked(String),
    #[error("evidence-revocation-state-missing: {0}")]
    EvidenceRevocationStateMissing(String),
}

impl RuntimeError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyNotFound => "policy-not-found",
            Self::PolicyInactive => "policy-inactive",
            Self::PolicyExpired => "policy-expired",
            Self::PolicyStatusRollback => "policy-status-rollback",
            Self::PolicyStatusRefreshFailed(_) => "policy-status-refresh-failed",
            Self::ChallengeNotFound => "challenge-not-found",
            Self::ChallengeNonceConsumed => "challenge-nonce-consumed",
            Self::ChallengeSigningFailed(_) => "challenge-signing-failed",
            Self::ChallengeSignatureSuiteNotAccepted => "challenge-signature-suite-not-accepted",
            Self::ChallengeSignatureInvalid(_) => "challenge-signature-invalid",
            Self::Presentation(_) => "presentation-invalid",
            Self::HolderBinding(_) => "holder-not-authorized",
            Self::Evidence(_) => "evidence-invalid",
            Self::PolicyNotSatisfied => "policy-not-satisfied",
            Self::GrantIssuanceFailed(_) => "grant-issuance-failed",
            Self::ActiveCutoffFailed(_) => "active-cutoff-failed",
            Self::GrantNotFound => "grant-not-found",
            Self::GrantInactive => "grant-inactive",
            Self::GrantExpired => "grant-expired",
            Self::EvidenceRevoked(_) => "evidence-revoked",
            Self::EvidenceRevocationStateMissing(_) => "evidence-revocation-state-missing",
        }
    }
}

pub struct PolicyRuntime<I: GrantIssuer, E: EvidenceVerifier> {
    config: RuntimeConfig,
    state: PolicySpaceState,
    evidence_verifier: E,
    grant_issuer: I,
    policy_status_refresher: Option<Box<dyn PolicyStatusRefresher + Send + Sync>>,
}

impl<I: GrantIssuer, E: EvidenceVerifier> PolicyRuntime<I, E> {
    pub fn new(
        config: RuntimeConfig,
        state: PolicySpaceState,
        evidence_verifier: E,
        grant_issuer: I,
    ) -> Self {
        Self {
            config,
            state,
            evidence_verifier,
            grant_issuer,
            policy_status_refresher: None,
        }
    }

    pub fn with_policy_status_refresher<R>(mut self, refresher: R) -> Self
    where
        R: PolicyStatusRefresher + Send + Sync + 'static,
    {
        self.set_policy_status_refresher(refresher);
        self
    }

    pub fn set_policy_status_refresher<R>(&mut self, refresher: R)
    where
        R: PolicyStatusRefresher + Send + Sync + 'static,
    {
        self.policy_status_refresher = Some(Box::new(refresher));
    }

    pub fn clear_policy_status_refresher(&mut self) {
        self.policy_status_refresher = None;
    }

    pub fn state(&self) -> &PolicySpaceState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut PolicySpaceState {
        &mut self.state
    }

    pub fn grant_issuer(&self) -> &I {
        &self.grant_issuer
    }

    pub fn grant_issuer_mut(&mut self) -> &mut I {
        &mut self.grant_issuer
    }

    pub fn refresh_policy_status(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<PolicyStatus>, RuntimeError> {
        let Some(refresher) = self.policy_status_refresher.as_mut() else {
            return Ok(None);
        };
        let Some(status) = refresher.refresh_policy_status(policy_id, now)? else {
            return Ok(None);
        };
        if status.policy_id != policy_id {
            return Err(RuntimeError::PolicyStatusRefreshFailed(
                "policy-status-policy-mismatch".to_string(),
            ));
        }
        self.state.apply_refreshed_policy_status(status.clone())?;
        Ok(Some(status))
    }

    pub fn issue_challenge(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
    ) -> Result<GrantChallenge, RuntimeError> {
        let policy = self.active_policy(policy_id, now)?;
        let nonce = random_nonce()?;
        let challenge = self.build_challenge(policy, nonce.clone(), now);
        self.state.challenges.insert(
            nonce,
            StoredChallenge {
                challenge: challenge.clone(),
                consumed: false,
            },
        );
        Ok(challenge)
    }

    pub fn issue_challenge_signed<S>(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
        signer: &mut S,
    ) -> Result<GrantChallenge, RuntimeError>
    where
        S: ChallengeSigner + ?Sized,
    {
        let nonce = random_nonce()?;
        self.issue_challenge_with_nonce_signed(policy_id, now, nonce, signer)
    }

    pub fn issue_challenge_with_nonce_signed<S>(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
        nonce: impl Into<String>,
        signer: &mut S,
    ) -> Result<GrantChallenge, RuntimeError>
    where
        S: ChallengeSigner + ?Sized,
    {
        let policy = self.active_policy(policy_id, now)?;
        let nonce = nonce.into();
        let mut challenge = self.build_challenge(policy, nonce.clone(), now);
        let digest = policy_core::digest_signed_object(&challenge)
            .map_err(|error| RuntimeError::ChallengeSignatureInvalid(error.as_str().to_string()))?;
        let signature = signer
            .sign_challenge(&digest)
            .map_err(|error| RuntimeError::ChallengeSigningFailed(error.to_string()))?;

        if !challenge.accepted_suites.contains(&signature.suite) {
            return Err(RuntimeError::ChallengeSignatureSuiteNotAccepted);
        }

        challenge.signature = signature;
        challenge.challenge_id = policy_core::compute_signed_object_id(
            policy_core::SignedObjectType::GrantChallenge,
            &digest,
        );
        let value = serde_json::to_value(&challenge)
            .map_err(|error| RuntimeError::ChallengeSignatureInvalid(error.to_string()))?;
        policy_core::verify_signed_object::<GrantChallenge>(&value)
            .map_err(|error| RuntimeError::ChallengeSignatureInvalid(error.as_str().to_string()))?;

        self.state.challenges.insert(
            nonce,
            StoredChallenge {
                challenge: challenge.clone(),
                consumed: false,
            },
        );
        Ok(challenge)
    }

    pub fn resolve(
        &mut self,
        presentation: GrantPresentation,
        now: DateTime<Utc>,
    ) -> Result<PortableDelegation, RuntimeError> {
        let policy = self.active_policy(&presentation.policy_id, now)?;
        let challenge = self.consume_challenge(&presentation.nonce)?;

        validate_grant_presentation(
            &policy,
            &presentation,
            ChallengeState::Available(&challenge),
            &self.config.audience,
            now,
        )
        .map_err(|error| RuntimeError::Presentation(error.as_str().to_string()))?;

        validate_enrolled_agent_binding(
            &presentation,
            &policy,
            &self.state.enrollment_tracker,
            now,
        )
        .map_err(|error| RuntimeError::HolderBinding(error.as_str().to_string()))?;

        let satisfactions = self.verify_evidence(&policy, &presentation, now)?;
        let satisfied_ids = satisfactions
            .iter()
            .flat_map(|satisfaction| satisfaction.evidence_ids.iter().cloned())
            .collect::<HashSet<_>>();
        if !evaluate_expression(
            &policy.when,
            &presentation.eligible_subject_did,
            &satisfied_ids,
        ) {
            return Err(RuntimeError::PolicyNotSatisfied);
        }

        let expires_at = grant_expires_at(&policy, &challenge, &presentation, &satisfactions, now)?;
        let evidence_ids = satisfied_ids.into_iter().collect::<Vec<_>>();
        let evidence_provenance = satisfactions
            .iter()
            .map(|satisfaction| satisfaction.provenance.clone())
            .collect::<Vec<_>>();
        let tracked_evidence = satisfactions
            .iter()
            .map(ProvenancedEvidenceSatisfaction::tracked_evidence)
            .collect::<Vec<_>>();
        let delegation = self.grant_issuer.issue(GrantIssueRequest {
            policy: policy.clone(),
            holder_did: presentation.holder_did.clone(),
            capabilities: presentation.requested_capabilities.clone(),
            issued_at: now,
            expires_at,
            presentation_expires_at: DateTime::parse_from_rfc3339(&presentation.expires_at)
                .map_err(|_| RuntimeError::Presentation("presentation-expired".to_string()))?
                .with_timezone(&Utc),
            terminal: matches!(
                policy.grant.delegation_mode,
                policy_core::DelegationMode::Terminal
            ),
            evidence_ids: evidence_ids.clone(),
            evidence_provenance: evidence_provenance.clone(),
        })?;

        self.state.issuances.insert(
            delegation.delegation_id.clone(),
            IssuanceRecord {
                policy_id: policy.policy_id,
                eligible_subject_did: presentation.eligible_subject_did,
                holder_did: presentation.holder_did,
                resource_id: policy.resource.resource_id,
                delegation_id: delegation.delegation_id.clone(),
                evidence_ids,
                evidence_provenance,
                tracked_evidence,
                issued_at: now,
                expires_at,
                revocation: policy.grant.revocation,
                active: true,
            },
        );

        Ok(delegation)
    }

    pub fn active_cutoff_policy(&mut self, policy_id: &str) -> Result<Vec<String>, RuntimeError> {
        let live = self
            .state
            .issuances
            .values()
            .filter(|record| {
                record.policy_id == policy_id
                    && record.active
                    && record.revocation == RevocationMode::ActiveCutoff
            })
            .map(|record| record.delegation_id.clone())
            .collect::<Vec<_>>();

        for delegation_id in &live {
            self.grant_issuer.revoke(delegation_id)?;
            let Some(record) = self.state.issuances.get_mut(delegation_id) else {
                return Err(RuntimeError::ActiveCutoffFailed(delegation_id.clone()));
            };
            record.active = false;
        }

        Ok(live)
    }

    pub fn refresh_tracked_evidence_statuses<V>(
        &mut self,
        delegation_id: &str,
        verifier: &mut V,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeError>
    where
        V: TrackedEvidenceStatusVerifier,
    {
        let tracked_evidence = {
            let record = self
                .state
                .issuances
                .get(delegation_id)
                .ok_or(RuntimeError::GrantNotFound)?;
            if !record.active {
                return Err(RuntimeError::GrantInactive);
            }
            if !record.evidence_ids.is_empty() && record.tracked_evidence.is_empty() {
                return Err(RuntimeError::EvidenceRevocationStateMissing(
                    delegation_id.to_string(),
                ));
            }
            record.tracked_evidence.clone()
        };

        for evidence in tracked_evidence {
            if evidence.expiry_bound_required && evidence.revocation_evidence_id().is_none() {
                self.invalidate_issuance(delegation_id)?;
                return Err(RuntimeError::EvidenceRevocationStateMissing(
                    evidence.requirement_id,
                ));
            }

            match verifier.check_tracked_evidence_status(&evidence, now)? {
                TrackedEvidenceStatus::Active => {}
                TrackedEvidenceStatus::Revoked => {
                    self.invalidate_issuance(delegation_id)?;
                    let evidence_id = evidence
                        .revocation_evidence_id()
                        .unwrap_or(&evidence.requirement_id)
                        .to_string();
                    return Err(RuntimeError::EvidenceRevoked(evidence_id));
                }
            }
        }

        Ok(())
    }

    pub fn validate_continued_use<V>(
        &mut self,
        delegation_id: &str,
        verifier: &mut V,
        now: DateTime<Utc>,
    ) -> Result<IssuanceRecord, RuntimeError>
    where
        V: TrackedEvidenceStatusVerifier,
    {
        let policy_id = {
            let record = self
                .state
                .issuances
                .get(delegation_id)
                .ok_or(RuntimeError::GrantNotFound)?;
            if !record.active {
                return Err(RuntimeError::GrantInactive);
            }
            if now > record.expires_at {
                return Err(RuntimeError::GrantExpired);
            }
            record.policy_id.clone()
        };

        self.active_policy(&policy_id, now)?;
        self.refresh_tracked_evidence_statuses(delegation_id, verifier, now)?;
        self.state
            .issuances
            .get(delegation_id)
            .cloned()
            .ok_or(RuntimeError::GrantNotFound)
    }

    fn active_policy(
        &mut self,
        policy_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Policy, RuntimeError> {
        self.refresh_policy_status(policy_id, now)?;
        let policy = self
            .state
            .policies
            .get(policy_id)
            .cloned()
            .ok_or(RuntimeError::PolicyNotFound)?;
        if let Some(status) = self.state.policy_statuses.get(policy_id) {
            if status.disposition != PolicyDisposition::Active {
                return Err(RuntimeError::PolicyInactive);
            }
        }
        if let Some(expires_at) = &policy.expires_at {
            let expires_at = DateTime::parse_from_rfc3339(expires_at)
                .map_err(|_| RuntimeError::PolicyExpired)?
                .with_timezone(&Utc);
            if now > expires_at {
                return Err(RuntimeError::PolicyExpired);
            }
        }
        Ok(policy)
    }

    fn build_challenge(&self, policy: Policy, nonce: String, now: DateTime<Utc>) -> GrantChallenge {
        GrantChallenge {
            schema: policy_core::GRANT_CHALLENGE_SCHEMA.to_string(),
            challenge_id: format!("chal_{nonce}"),
            policy_id: policy.policy_id,
            audience: self.config.audience.clone(),
            nonce,
            challenge_expires_at: (now + Duration::seconds(self.config.challenge_ttl_seconds))
                .to_rfc3339(),
            accepted_suites: self.config.accepted_suites.clone(),
            requested_capabilities_template: None,
            signature: self.config.challenge_signature.clone(),
        }
    }

    fn consume_challenge(&mut self, nonce: &str) -> Result<GrantChallenge, RuntimeError> {
        if self.state.consumed_nonces.contains(nonce) {
            return Err(RuntimeError::ChallengeNonceConsumed);
        }
        let Some(stored) = self.state.challenges.get_mut(nonce) else {
            return Err(RuntimeError::ChallengeNotFound);
        };
        if stored.consumed {
            return Err(RuntimeError::ChallengeNonceConsumed);
        }
        stored.consumed = true;
        self.state.consumed_nonces.insert(nonce.to_string());
        Ok(stored.challenge.clone())
    }

    fn verify_evidence(
        &self,
        policy: &Policy,
        presentation: &GrantPresentation,
        now: DateTime<Utc>,
    ) -> Result<Vec<ProvenancedEvidenceSatisfaction>, RuntimeError> {
        let Some(evidence) = &presentation.evidence else {
            return Ok(Vec::new());
        };
        let requirements = evidence_requirements(policy);
        let mut satisfactions = Vec::new();
        let context = RuntimeEvidenceContext {
            policy: policy.clone(),
            eligible_subject_did: presentation.eligible_subject_did.clone(),
            holder_did: presentation.holder_did.clone(),
            requested_capabilities: presentation.requested_capabilities.clone(),
            now,
        };
        for item in evidence {
            let requirement = requirements
                .get(&item.requirement_id)
                .ok_or_else(|| RuntimeError::Evidence("evidence-requirement-unknown".into()))?;
            let satisfaction = self.evidence_verifier.verify_with_provenance(
                requirement,
                &item.presentation,
                &context,
            )?;
            let satisfaction = satisfaction.with_requirement_id(requirement.requirement_id.clone());
            satisfactions.push(satisfaction);
        }
        Ok(satisfactions)
    }

    fn invalidate_issuance(&mut self, delegation_id: &str) -> Result<(), RuntimeError> {
        let Some(record) = self.state.issuances.get(delegation_id) else {
            return Err(RuntimeError::GrantNotFound);
        };
        let should_revoke = record.active && record.revocation == RevocationMode::ActiveCutoff;

        if should_revoke {
            self.grant_issuer.revoke(delegation_id)?;
        }

        let Some(record) = self.state.issuances.get_mut(delegation_id) else {
            return Err(RuntimeError::GrantNotFound);
        };
        record.active = false;
        Ok(())
    }
}

fn evidence_requirements(policy: &Policy) -> HashMap<String, policy_core::EvidenceRequirement> {
    let mut out = HashMap::new();
    collect_evidence_requirements(&policy.when, &mut out);
    out
}

fn collect_evidence_requirements(
    expression: &policy_core::Expression,
    out: &mut HashMap<String, policy_core::EvidenceRequirement>,
) {
    match expression {
        policy_core::Expression::AllOf(expr) => {
            for child in &expr.all_of {
                collect_evidence_requirements(child, out);
            }
        }
        policy_core::Expression::AnyOf(expr) => {
            for child in &expr.any_of {
                collect_evidence_requirements(child, out);
            }
        }
        policy_core::Expression::Subject(_) => {}
        policy_core::Expression::Evidence(expr) => {
            out.insert(expr.evidence.requirement_id.clone(), expr.evidence.clone());
        }
    }
}

fn grant_expires_at(
    policy: &Policy,
    challenge: &GrantChallenge,
    presentation: &GrantPresentation,
    satisfactions: &[ProvenancedEvidenceSatisfaction],
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, RuntimeError> {
    if policy.grant.output != GrantOutput::PortableDelegation {
        return Err(RuntimeError::GrantIssuanceFailed(
            "unsupported-grant-output".to_string(),
        ));
    }
    let mut expires_at = now + Duration::seconds(policy.grant.max_ttl_seconds as i64);
    if let Some(policy_expires_at) = &policy.expires_at {
        let policy_expires_at = DateTime::parse_from_rfc3339(policy_expires_at)
            .map_err(|_| RuntimeError::PolicyExpired)?
            .with_timezone(&Utc);
        expires_at = expires_at.min(policy_expires_at);
    }
    let challenge_expires_at = DateTime::parse_from_rfc3339(&challenge.challenge_expires_at)
        .map_err(|_| RuntimeError::Presentation("challenge-expired".to_string()))?
        .with_timezone(&Utc);
    expires_at = expires_at.min(challenge_expires_at);
    let presentation_expires_at = DateTime::parse_from_rfc3339(&presentation.expires_at)
        .map_err(|_| RuntimeError::Presentation("presentation-expired".to_string()))?
        .with_timezone(&Utc);
    expires_at = expires_at.min(presentation_expires_at);
    for satisfaction in satisfactions {
        match satisfaction.valid_until {
            Some(valid_until) => expires_at = expires_at.min(valid_until),
            None if satisfaction.expiry_bound_required => {
                return Err(RuntimeError::Evidence(
                    "evidence-valid-until-missing".to_string(),
                ));
            }
            None => {}
        }
    }
    Ok(expires_at)
}

fn random_nonce() -> Result<String, RuntimeError> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| RuntimeError::GrantIssuanceFailed(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use opencredentials_verify::{
        present_email_domain, EmailCredentialIssuer, EmailCredentialRequest, JWK,
    };
    use policy_core::{
        requested_capabilities_hash_hex, Audit, AuditIssuance, DelegationMode, DenialDisclosure,
        Disclosure, EvidenceAuthority, EvidenceExpression, EvidenceRequirement, GrantTemplate,
        HolderBindingProof, HolderEnrollment, HolderEnrollmentDisposition, HolderEnrollmentStatus,
        PolicyResource, PresentedEvidence, SignatureSuite,
    };
    use policy_evidence_vc::{VcEvidenceVerifier, VC_CREDENTIAL_PROFILE};

    const ISSUER: &str = "did:web:issuer.tinycloud.xyz";
    const SUBJECT: &str = "did:key:z6Mksubject";
    const GRANT_ISSUER: &str = "did:key:z6Mkgrantissuer";
    const ISSUED_AT: i64 = 1_800_000_000;

    struct HolderKey {
        signing_key: SigningKey,
        did: String,
    }

    impl HolderKey {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&[7u8; 32]);
            let mut multicodec = vec![0xed, 0x01];
            multicodec.extend_from_slice(signing_key.verifying_key().as_bytes());
            Self {
                signing_key,
                did: format!("did:key:z{}", bs58::encode(multicodec).into_string()),
            }
        }

        fn sign(&self, digest: &[u8; 32]) -> Signature {
            Signature {
                suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
                signer_did: self.did.clone(),
                value: URL_SAFE_NO_PAD.encode(self.signing_key.sign(digest).to_bytes()),
            }
        }
    }

    #[derive(Default)]
    struct FakeNativeNode {
        issued: BTreeMap<String, PortableDelegation>,
        revoked: HashSet<String>,
        next_id: u64,
    }

    impl FakeNativeNode {
        fn native_read(&self, delegation_id: &str) -> Result<&'static str, &'static str> {
            let delegation = self.issued.get(delegation_id).ok_or("not-found")?;
            if self.revoked.contains(delegation_id) {
                return Err("delegation-revoked");
            }
            if !delegation.terminal {
                return Err("not-terminal");
            }
            Ok("native transcript row")
        }
    }

    impl GrantIssuer for FakeNativeNode {
        fn issuer_did(&self) -> &str {
            GRANT_ISSUER
        }

        fn issue(
            &mut self,
            request: GrantIssueRequest,
        ) -> Result<PortableDelegation, RuntimeError> {
            self.next_id += 1;
            let delegation_id = format!("bafygrant{}", self.next_id);
            let delegation = PortableDelegation {
                delegation_id: delegation_id.clone(),
                issuer_did: self.issuer_did().to_string(),
                holder_did: request.holder_did,
                policy_id: request.policy.policy_id,
                capabilities: request.capabilities,
                issued_at: request.issued_at,
                expires_at: request.expires_at,
                terminal: request.terminal,
                encoded: format!("portable:{delegation_id}"),
            };
            self.issued
                .insert(delegation_id.clone(), delegation.clone());
            Ok(delegation)
        }

        fn revoke(&mut self, delegation_id: &str) -> Result<(), RuntimeError> {
            if !self.issued.contains_key(delegation_id) {
                return Err(RuntimeError::ActiveCutoffFailed(delegation_id.to_string()));
            }
            self.revoked.insert(delegation_id.to_string());
            Ok(())
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(ISSUED_AT + 60, 0).single().unwrap()
    }

    fn signature(signer: &str) -> Signature {
        Signature {
            suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
            signer_did: signer.to_string(),
            value: "unused".to_string(),
        }
    }

    fn capability() -> PolicyCapability {
        policy_core::parse_policy_capability(&serde_json::json!({
            "service": "tinycloud.sql",
            "space": "did:pkh:eip155:1:0xowner/listen",
            "path": "/transcripts.sqlite",
            "actions": ["tinycloud.sql/read"],
            "caveats": {
                "mode": "constrained-statements",
                "readOnly": true,
                "statements": [{
                    "name": "conversation",
                    "sql": "SELECT * FROM transcript WHERE conversation_id = ?",
                    "fixedParams": [{ "index": 1, "value": "conv_456" }]
                }]
            }
        }))
        .unwrap()
    }

    fn policy() -> Policy {
        Policy {
            schema: policy_core::POLICY_SCHEMA.to_string(),
            policy_id: "pol_email_domain".to_string(),
            owner_did: "did:pkh:eip155:1:0xowner".to_string(),
            signing_key_did: "did:key:z6Mkpolicy".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            resource: PolicyResource {
                resource_type: "listen-transcript".to_string(),
                resource_id: "conv_456".to_string(),
                permissions_ceiling: vec![capability()],
            },
            when: policy_core::Expression::Evidence(EvidenceExpression {
                evidence: EvidenceRequirement {
                    requirement_id: "email-domain".to_string(),
                    verifier: VC_CREDENTIAL_PROFILE.to_string(),
                    requirements: serde_json::json!({
                        "type": policy_evidence_vc::OPEN_CREDENTIALS_EMAIL_V1,
                        "emailDomains": ["tinycloud.xyz"]
                    }),
                    authority: Some(EvidenceAuthority {
                        profile: None,
                        accepted_issuers: Some(vec![ISSUER.to_string()]),
                        allow_owner_authorized_issuer: None,
                    }),
                    freshness: None,
                },
            }),
            grant: GrantTemplate {
                output: GrantOutput::PortableDelegation,
                max_ttl_seconds: 3600,
                delegation_mode: DelegationMode::Terminal,
                revocation: RevocationMode::ActiveCutoff,
            },
            disclosure: Some(Disclosure {
                denial: DenialDisclosure::Code,
            }),
            audit: Some(Audit {
                issuance: AuditIssuance::Security,
            }),
            signature: signature("did:key:z6Mkpolicy"),
        }
    }

    fn active_status() -> PolicyStatus {
        PolicyStatus {
            schema: policy_core::POLICY_STATUS_SCHEMA.to_string(),
            status_id: "pstat_1".to_string(),
            policy_id: "pol_email_domain".to_string(),
            owner_did: "did:pkh:eip155:1:0xowner".to_string(),
            sequence: 1,
            disposition: PolicyDisposition::Active,
            effective_at: "2026-01-01T00:00:00Z".to_string(),
            reason_code: None,
            signing_key_did: "did:key:z6Mkpolicy".to_string(),
            signature: signature("did:key:z6Mkpolicy"),
        }
    }

    fn enrollment(holder_did: &str) -> HolderEnrollment {
        HolderEnrollment {
            schema: policy_core::HOLDER_ENROLLMENT_SCHEMA.to_string(),
            enrollment_id: "henr_test".to_string(),
            eligible_subject_did: SUBJECT.to_string(),
            holder_did: holder_did.to_string(),
            scope: None,
            not_before: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            signing_key_did: SUBJECT.to_string(),
            signature: signature(SUBJECT),
        }
    }

    fn enrollment_status() -> HolderEnrollmentStatus {
        HolderEnrollmentStatus {
            schema: policy_core::HOLDER_ENROLLMENT_STATUS_SCHEMA.to_string(),
            status_id: "henrst_test".to_string(),
            enrollment_id: "henr_test".to_string(),
            sequence: 1,
            disposition: HolderEnrollmentDisposition::Active,
            effective_at: "2026-01-01T00:00:00Z".to_string(),
            signing_key_did: SUBJECT.to_string(),
            signature: signature(SUBJECT),
        }
    }

    fn unsigned_presentation(
        challenge: &GrantChallenge,
        sd_jwt: String,
        holder: &HolderKey,
    ) -> GrantPresentation {
        let caps = vec![capability()];
        let mut presentation = GrantPresentation {
            schema: policy_core::GRANT_PRESENTATION_SCHEMA.to_string(),
            policy_id: "pol_email_domain".to_string(),
            eligible_subject_did: SUBJECT.to_string(),
            holder_did: holder.did.clone(),
            holder_binding: HolderBindingProof::EnrolledAgent {
                enrollment: enrollment(&holder.did),
                status: Some(enrollment_status()),
            },
            requested_capabilities_hash: requested_capabilities_hash_hex(&caps),
            requested_capabilities: caps,
            audience: "policy-engine:test".to_string(),
            nonce: challenge.nonce.clone(),
            expires_at: (now() + Duration::minutes(30)).to_rfc3339(),
            evidence: Some(vec![PresentedEvidence {
                requirement_id: "email-domain".to_string(),
                presentation: serde_json::json!({ "sdJwt": sd_jwt }),
            }]),
            holder_signature: signature(&holder.did),
        };
        let digest = policy_core::signed_object::digest_grant_presentation(&presentation)
            .expect("presentation digest");
        presentation.holder_signature = holder.sign(&digest);
        presentation
    }

    #[test]
    fn challenge_resolve_native_read_then_active_cutoff_denies() {
        let issuer_jwk = JWK::generate_ed25519().unwrap();
        let holder = HolderKey::new();
        let issuer = EmailCredentialIssuer::new_ed25519(ISSUER, &issuer_jwk).unwrap();
        let verifier = VcEvidenceVerifier::new(BTreeMap::from([(ISSUER.to_string(), issuer_jwk)]));
        let issued = issuer
            .issue(
                EmailCredentialRequest::new(SUBJECT, "sam@tinycloud.xyz")
                    .with_issued_at(ISSUED_AT)
                    .with_ttl_seconds(3600),
            )
            .unwrap();
        let email_domain_presentation = present_email_domain(&issued).unwrap();

        let mut state = PolicySpaceState::default();
        state.insert_policy(policy());
        state.insert_policy_status(active_status()).unwrap();

        let config = RuntimeConfig {
            audience: "policy-engine:test".to_string(),
            challenge_ttl_seconds: 120,
            accepted_suites: vec![SignatureSuite::EddsaEd25519Sha256JcsV1],
            challenge_signature: signature("did:key:z6Mkengine"),
        };
        let mut runtime = PolicyRuntime::new(config, state, verifier, FakeNativeNode::default());
        let challenge = runtime
            .issue_challenge("pol_email_domain", now())
            .expect("challenge");
        let presentation = unsigned_presentation(&challenge, email_domain_presentation, &holder);

        let delegation = runtime
            .resolve(presentation, now())
            .expect("resolved grant");

        assert!(delegation.terminal);
        assert_eq!(delegation.holder_did, holder.did);
        assert_eq!(
            runtime
                .grant_issuer()
                .native_read(&delegation.delegation_id),
            Ok("native transcript row")
        );

        let revoked = runtime
            .active_cutoff_policy("pol_email_domain")
            .expect("active cutoff");
        assert_eq!(revoked, vec![delegation.delegation_id.clone()]);
        assert_eq!(
            runtime
                .grant_issuer()
                .native_read(&delegation.delegation_id),
            Err("delegation-revoked")
        );
        assert_eq!(
            runtime
                .state()
                .issuance(&delegation.delegation_id)
                .map(|record| record.active),
            Some(false)
        );
    }
}
