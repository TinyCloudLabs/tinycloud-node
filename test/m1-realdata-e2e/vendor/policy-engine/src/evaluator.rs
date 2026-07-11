use crate::capability::{requested_capabilities_hash_hex, CapabilityRejection};
use crate::enrollment::EnrollmentRejection;
use crate::signed_object::{
    digest_grant_presentation, digest_hex, verify_grant_presentation_holder_signature,
    SignedObjectError,
};
use crate::types::{
    EvidenceExpression, Expression, GrantChallenge, GrantPresentation, Policy, PresentedEvidence,
};
use chrono::{DateTime, Utc};
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeState<'a> {
    Missing,
    Consumed,
    Available(&'a GrantChallenge),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvalError {
    #[error("challenge-not-found")]
    ChallengeNotFound,
    #[error("challenge-expired")]
    ChallengeExpired,
    #[error("challenge-nonce-consumed")]
    ChallengeNonceConsumed,
    #[error("presentation-expired")]
    PresentationExpired,
    #[error("presentation-audience-mismatch")]
    PresentationAudienceMismatch,
    #[error("presentation-evidence-missing")]
    PresentationEvidenceMissing,
    #[error("evidence-requirement-unknown")]
    EvidenceRequirementUnknown,
    #[error("evidence-requirement-duplicate")]
    EvidenceRequirementDuplicate,
    #[error("holder-signature-invalid")]
    HolderSignatureInvalid,
    #[error("holder-signature-signer-mismatch")]
    HolderSignatureSignerMismatch,
    #[error("requested-capabilities-exceeded")]
    RequestedCapabilitiesExceeded,
    #[error("requested-capabilities-hash-mismatch")]
    RequestedCapabilitiesHashMismatch,
    #[error("policy-not-satisfied")]
    PolicyNotSatisfied,
    #[error("{0}")]
    Capability(#[from] CapabilityRejection),
    #[error("{0}")]
    Enrollment(#[from] EnrollmentRejection),
}

impl EvalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChallengeNotFound => "challenge-not-found",
            Self::ChallengeExpired => "challenge-expired",
            Self::ChallengeNonceConsumed => "challenge-nonce-consumed",
            Self::PresentationExpired => "presentation-expired",
            Self::PresentationAudienceMismatch => "presentation-audience-mismatch",
            Self::PresentationEvidenceMissing => "presentation-evidence-missing",
            Self::EvidenceRequirementUnknown => "evidence-requirement-unknown",
            Self::EvidenceRequirementDuplicate => "evidence-requirement-duplicate",
            Self::HolderSignatureInvalid => "holder-signature-invalid",
            Self::HolderSignatureSignerMismatch => "holder-signature-signer-mismatch",
            Self::RequestedCapabilitiesExceeded => "requested-capabilities-exceeded",
            Self::RequestedCapabilitiesHashMismatch => "requested-capabilities-hash-mismatch",
            Self::PolicyNotSatisfied => "policy-not-satisfied",
            Self::Capability(error) => error.as_str(),
            Self::Enrollment(error) => error.as_str(),
        }
    }
}

pub fn evaluate_expression(
    expression: &Expression,
    eligible_subject_did: &str,
    satisfied_evidence: &HashSet<String>,
) -> bool {
    match expression {
        Expression::AllOf(expr) => expr
            .all_of
            .iter()
            .all(|child| evaluate_expression(child, eligible_subject_did, satisfied_evidence)),
        Expression::AnyOf(expr) => expr
            .any_of
            .iter()
            .any(|child| evaluate_expression(child, eligible_subject_did, satisfied_evidence)),
        Expression::Subject(expr) => expr.subject.did == eligible_subject_did,
        Expression::Evidence(EvidenceExpression { evidence }) => {
            satisfied_evidence.contains(&evidence.requirement_id)
        }
    }
}

pub fn validate_grant_presentation(
    policy: &Policy,
    presentation: &GrantPresentation,
    challenge_state: ChallengeState<'_>,
    audience: &str,
    now: DateTime<Utc>,
) -> Result<(), EvalError> {
    let challenge = match challenge_state {
        ChallengeState::Missing => return Err(EvalError::ChallengeNotFound),
        ChallengeState::Consumed => return Err(EvalError::ChallengeNonceConsumed),
        ChallengeState::Available(challenge) => challenge,
    };

    if challenge.nonce != presentation.nonce || challenge.policy_id != presentation.policy_id {
        return Err(EvalError::ChallengeNotFound);
    }

    if now > parse_time(&challenge.challenge_expires_at).map_err(|_| EvalError::ChallengeExpired)? {
        return Err(EvalError::ChallengeExpired);
    }
    if now > parse_time(&presentation.expires_at).map_err(|_| EvalError::PresentationExpired)? {
        return Err(EvalError::PresentationExpired);
    }
    if presentation.audience != audience || challenge.audience != audience {
        return Err(EvalError::PresentationAudienceMismatch);
    }

    validate_evidence_shape(policy, presentation.evidence.as_deref())?;
    validate_requested_capabilities_hash(presentation)?;

    if presentation.holder_signature.signer_did != presentation.holder_did {
        return Err(EvalError::HolderSignatureSignerMismatch);
    }
    if !challenge
        .accepted_suites
        .iter()
        .any(|suite| suite == &presentation.holder_signature.suite)
    {
        return Err(EvalError::HolderSignatureInvalid);
    }
    verify_grant_presentation_holder_signature(presentation)
        .map_err(|_| EvalError::HolderSignatureInvalid)?;

    for requested in &presentation.requested_capabilities {
        let contained = policy
            .resource
            .permissions_ceiling
            .iter()
            .any(|ceiling| ceiling.contains(requested).is_ok());
        if !contained {
            return Err(EvalError::RequestedCapabilitiesExceeded);
        }
    }

    let evidence_ids = presentation
        .evidence
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|evidence| evidence.requirement_id.clone())
        .collect::<HashSet<_>>();
    if !evaluate_expression(
        &policy.when,
        &presentation.eligible_subject_did,
        &evidence_ids,
    ) {
        return Err(EvalError::PolicyNotSatisfied);
    }

    Ok(())
}

pub fn validate_requested_capabilities_hash(
    presentation: &GrantPresentation,
) -> Result<(), EvalError> {
    let expected = requested_capabilities_hash_hex(&presentation.requested_capabilities);
    if expected == presentation.requested_capabilities_hash {
        Ok(())
    } else {
        Err(EvalError::RequestedCapabilitiesHashMismatch)
    }
}

pub fn presentation_digest_hex(
    presentation: &GrantPresentation,
) -> Result<String, SignedObjectError> {
    Ok(digest_hex(&digest_grant_presentation(presentation)?))
}

fn validate_evidence_shape(
    policy: &Policy,
    evidence: Option<&[PresentedEvidence]>,
) -> Result<(), EvalError> {
    let required = evidence_requirement_ids(&policy.when);
    if required.is_empty() {
        return Ok(());
    }
    let Some(evidence) = evidence else {
        return Err(EvalError::PresentationEvidenceMissing);
    };
    if evidence.is_empty() {
        return Err(EvalError::PresentationEvidenceMissing);
    }

    let mut seen = BTreeSet::new();
    for item in evidence {
        if !required.contains(&item.requirement_id) {
            return Err(EvalError::EvidenceRequirementUnknown);
        }
        if !seen.insert(item.requirement_id.clone()) {
            return Err(EvalError::EvidenceRequirementDuplicate);
        }
    }
    Ok(())
}

pub fn evidence_requirement_ids(expression: &Expression) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    collect_evidence_requirement_ids(expression, &mut ids);
    ids
}

fn collect_evidence_requirement_ids(expression: &Expression, ids: &mut BTreeSet<String>) {
    match expression {
        Expression::AllOf(expr) => {
            for child in &expr.all_of {
                collect_evidence_requirement_ids(child, ids);
            }
        }
        Expression::AnyOf(expr) => {
            for child in &expr.any_of {
                collect_evidence_requirement_ids(child, ids);
            }
        }
        Expression::Subject(_) => {}
        Expression::Evidence(expr) => {
            ids.insert(expr.evidence.requirement_id.clone());
        }
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}
