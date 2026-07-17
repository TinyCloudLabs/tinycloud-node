use crate::types::{
    GrantPresentation, HolderBindingProof, HolderEnrollment, HolderEnrollmentDisposition,
    HolderEnrollmentScope, HolderEnrollmentStatus, Policy,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentRejection {
    #[error("enrollment-status-rollback")]
    EnrollmentStatusRollback,
    #[error("enrollment-revoked-irreversible")]
    EnrollmentRevokedIrreversible,
    #[error("enrollment-revoked")]
    EnrollmentRevoked,
    #[error("enrollment-out-of-scope")]
    EnrollmentOutOfScope,
    #[error("enrollment-binding-mismatch")]
    EnrollmentBindingMismatch,
    #[error("enrollment-not-yet-valid")]
    EnrollmentNotYetValid,
    #[error("enrollment-expired")]
    EnrollmentExpired,
}

impl EnrollmentRejection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EnrollmentStatusRollback => "enrollment-status-rollback",
            Self::EnrollmentRevokedIrreversible => "enrollment-revoked-irreversible",
            Self::EnrollmentRevoked => "enrollment-revoked",
            Self::EnrollmentOutOfScope => "enrollment-out-of-scope",
            Self::EnrollmentBindingMismatch => "enrollment-binding-mismatch",
            Self::EnrollmentNotYetValid => "enrollment-not-yet-valid",
            Self::EnrollmentExpired => "enrollment-expired",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnrollmentStatusState {
    pub last_accepted_sequence: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default)]
pub struct EnrollmentStatusTracker {
    states: HashMap<String, EnrollmentStatusState>,
}

impl EnrollmentStatusTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_state(&mut self, enrollment_id: impl Into<String>, state: EnrollmentStatusState) {
        self.states.insert(enrollment_id.into(), state);
    }

    pub fn state(&self, enrollment_id: &str) -> EnrollmentStatusState {
        self.states.get(enrollment_id).cloned().unwrap_or_default()
    }

    pub fn apply_status(
        &mut self,
        status: &HolderEnrollmentStatus,
    ) -> Result<(), EnrollmentRejection> {
        let mut state = self.state(&status.enrollment_id);
        if status.sequence <= state.last_accepted_sequence {
            return Err(EnrollmentRejection::EnrollmentStatusRollback);
        }
        if state.revoked && status.disposition == HolderEnrollmentDisposition::Active {
            return Err(EnrollmentRejection::EnrollmentRevokedIrreversible);
        }
        state.last_accepted_sequence = status.sequence;
        if status.disposition == HolderEnrollmentDisposition::Revoked {
            state.revoked = true;
        }
        self.states.insert(status.enrollment_id.clone(), state);
        Ok(())
    }
}

pub fn check_enrollment_scope(
    scope: Option<&HolderEnrollmentScope>,
    policy_id: &str,
    resource_id: &str,
) -> Result<(), EnrollmentRejection> {
    let Some(scope) = scope else {
        return Ok(());
    };
    if let Some(policy_ids) = &scope.policy_ids {
        if !policy_ids.iter().any(|candidate| candidate == policy_id) {
            return Err(EnrollmentRejection::EnrollmentOutOfScope);
        }
    }
    if let Some(resource_ids) = &scope.resource_ids {
        if !resource_ids
            .iter()
            .any(|candidate| candidate == resource_id)
        {
            return Err(EnrollmentRejection::EnrollmentOutOfScope);
        }
    }
    Ok(())
}

pub fn validate_enrolled_agent_binding(
    presentation: &GrantPresentation,
    policy: &Policy,
    tracker: &EnrollmentStatusTracker,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentRejection> {
    let HolderBindingProof::EnrolledAgent { enrollment, status } = &presentation.holder_binding;
    validate_enrollment_identity(presentation, enrollment)?;
    validate_enrollment_time(enrollment, now)?;
    check_enrollment_scope(
        enrollment.scope.as_ref(),
        &presentation.policy_id,
        &policy.resource.resource_id,
    )?;
    validate_enrollment_status(enrollment, status.as_ref(), tracker)
}

fn validate_enrollment_identity(
    presentation: &GrantPresentation,
    enrollment: &HolderEnrollment,
) -> Result<(), EnrollmentRejection> {
    if enrollment.eligible_subject_did != presentation.eligible_subject_did
        || enrollment.holder_did != presentation.holder_did
    {
        return Err(EnrollmentRejection::EnrollmentBindingMismatch);
    }
    Ok(())
}

fn validate_enrollment_time(
    enrollment: &HolderEnrollment,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentRejection> {
    let not_before = parse_time(&enrollment.not_before)
        .map_err(|_| EnrollmentRejection::EnrollmentNotYetValid)?;
    if now < not_before {
        return Err(EnrollmentRejection::EnrollmentNotYetValid);
    }
    if let Some(expires_at) = &enrollment.expires_at {
        let expires_at =
            parse_time(expires_at).map_err(|_| EnrollmentRejection::EnrollmentExpired)?;
        if now > expires_at {
            return Err(EnrollmentRejection::EnrollmentExpired);
        }
    }
    Ok(())
}

fn validate_enrollment_status(
    enrollment: &HolderEnrollment,
    status: Option<&HolderEnrollmentStatus>,
    tracker: &EnrollmentStatusTracker,
) -> Result<(), EnrollmentRejection> {
    let state = tracker.state(&enrollment.enrollment_id);
    if state.revoked {
        let Some(status) = status else {
            return Err(EnrollmentRejection::EnrollmentRevoked);
        };
        if status.sequence <= state.last_accepted_sequence {
            return Err(EnrollmentRejection::EnrollmentStatusRollback);
        }
        if status.disposition == HolderEnrollmentDisposition::Active {
            return Err(EnrollmentRejection::EnrollmentRevokedIrreversible);
        }
        return Err(EnrollmentRejection::EnrollmentRevoked);
    }

    if let Some(status) = status {
        if status.enrollment_id != enrollment.enrollment_id {
            return Err(EnrollmentRejection::EnrollmentBindingMismatch);
        }
        if status.sequence < state.last_accepted_sequence {
            return Err(EnrollmentRejection::EnrollmentStatusRollback);
        }
        if status.disposition != HolderEnrollmentDisposition::Active {
            return Err(EnrollmentRejection::EnrollmentRevoked);
        }
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}
