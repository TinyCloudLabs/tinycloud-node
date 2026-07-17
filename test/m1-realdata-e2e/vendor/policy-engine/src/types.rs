use crate::capability::PolicyCapability;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const POLICY_SCHEMA: &str = "xyz.tinycloud.policy/policy/v0";
pub const POLICY_STATUS_SCHEMA: &str = "xyz.tinycloud.policy/status/v0";
pub const POLICY_ENGINE_RECORD_SCHEMA: &str = "xyz.tinycloud.policy/engine-record/v0";
pub const OPERATIONAL_KEY_AUTHORIZATION_SCHEMA: &str = "xyz.tinycloud.auth/key-authorization/v0";
pub const OPERATIONAL_KEY_STATUS_SCHEMA: &str = "xyz.tinycloud.auth/key-status/v0";
pub const HOLDER_ENROLLMENT_SCHEMA: &str = "xyz.tinycloud.policy/holder-enrollment/v0";
pub const HOLDER_ENROLLMENT_STATUS_SCHEMA: &str =
    "xyz.tinycloud.policy/holder-enrollment-status/v0";
pub const GRANT_CHALLENGE_SCHEMA: &str = "xyz.tinycloud.policy/challenge/v0";
pub const GRANT_PRESENTATION_SCHEMA: &str = "xyz.tinycloud.policy/presentation/v0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureSuite {
    #[serde(rename = "eddsa-ed25519-sha256-jcs-v1")]
    EddsaEd25519Sha256JcsV1,
    #[serde(rename = "eip191-secp256k1-sha256-jcs-v1")]
    Eip191Secp256k1Sha256JcsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signature {
    pub suite: SignatureSuite,
    pub signer_did: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelegationMode {
    Terminal,
    Attenuable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    RefreshOnly,
    ActiveCutoff,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub policy_id: String,
    pub owner_did: String,
    pub signing_key_did: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub resource: PolicyResource,
    pub when: Expression,
    pub grant: GrantTemplate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<Disclosure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<Audit>,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyResource {
    pub resource_type: String,
    pub resource_id: String,
    pub permissions_ceiling: Vec<PolicyCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantTemplate {
    pub output: GrantOutput,
    pub max_ttl_seconds: u64,
    pub delegation_mode: DelegationMode,
    pub revocation: RevocationMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantOutput {
    PortableDelegation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Disclosure {
    pub denial: DenialDisclosure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialDisclosure {
    None,
    Code,
    Debug,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Audit {
    pub issuance: AuditIssuance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditIssuance {
    Off,
    Security,
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expression {
    AllOf(AllOfExpression),
    AnyOf(AnyOfExpression),
    Subject(SubjectExpression),
    Evidence(EvidenceExpression),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllOfExpression {
    pub all_of: Vec<Expression>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnyOfExpression {
    pub any_of: Vec<Expression>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectExpression {
    pub subject: SubjectRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectRequirement {
    pub did: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceExpression {
    pub evidence: EvidenceRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequirement {
    pub requirement_id: String,
    pub verifier: String,
    pub requirements: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<EvidenceAuthority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<EvidenceFreshness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuthority {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_issuers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_owner_authorized_issuer: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceFreshness {
    pub max_status_age_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyStatus {
    pub schema: String,
    pub status_id: String,
    pub policy_id: String,
    pub owner_did: String,
    pub sequence: u64,
    pub disposition: PolicyDisposition,
    pub effective_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    pub signing_key_did: String,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyDisposition {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalKeyAuthorization {
    pub schema: String,
    pub authorization_id: String,
    pub owner_did: String,
    pub key_did: String,
    pub roles: Vec<OperationalKeyRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_issuer_scope: Option<TrustIssuerScope>,
    pub not_before: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustIssuerScope {
    pub context_prefixes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalKeyRole {
    PolicySigner,
    TrustIssuer,
    GrantIssuer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalKeyStatus {
    pub schema: String,
    pub status_id: String,
    pub authorization_id: String,
    pub sequence: u64,
    pub disposition: OperationalKeyDisposition,
    pub effective_at: String,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalKeyDisposition {
    Active,
    Retired,
    Compromised,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationalKeyRejection {
    #[error("operational-key-role-unauthorized")]
    OperationalKeyRoleUnauthorized,
    #[error("trust-issuer-context-out-of-scope")]
    TrustIssuerContextOutOfScope,
    #[error("operational-key-status-binding-mismatch")]
    OperationalKeyStatusBindingMismatch,
    #[error("operational-key-status-rollback")]
    OperationalKeyStatusRollback,
    #[error("operational-key-compromised-irreversible")]
    OperationalKeyCompromisedIrreversible,
    #[error("operational-key-retired-irreversible")]
    OperationalKeyRetiredIrreversible,
    #[error("operational-key-not-yet-valid")]
    OperationalKeyNotYetValid,
    #[error("operational-key-expired")]
    OperationalKeyExpired,
    #[error("operational-key-retired")]
    OperationalKeyRetired,
    #[error("operational-key-compromised")]
    OperationalKeyCompromised,
    #[error("operational-key-artifact-expired")]
    OperationalKeyArtifactExpired,
}

impl OperationalKeyRejection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OperationalKeyRoleUnauthorized => "operational-key-role-unauthorized",
            Self::TrustIssuerContextOutOfScope => "trust-issuer-context-out-of-scope",
            Self::OperationalKeyStatusBindingMismatch => "operational-key-status-binding-mismatch",
            Self::OperationalKeyStatusRollback => "operational-key-status-rollback",
            Self::OperationalKeyCompromisedIrreversible => {
                "operational-key-compromised-irreversible"
            }
            Self::OperationalKeyRetiredIrreversible => "operational-key-retired-irreversible",
            Self::OperationalKeyNotYetValid => "operational-key-not-yet-valid",
            Self::OperationalKeyExpired => "operational-key-expired",
            Self::OperationalKeyRetired => "operational-key-retired",
            Self::OperationalKeyCompromised => "operational-key-compromised",
            Self::OperationalKeyArtifactExpired => "operational-key-artifact-expired",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationalKeyStatusState {
    pub last_accepted_sequence: u64,
    pub disposition: Option<OperationalKeyDisposition>,
    pub effective_at: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct OperationalKeyStatusTracker {
    states: HashMap<String, OperationalKeyStatusState>,
}

impl OperationalKeyStatusTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_state(
        &mut self,
        authorization_id: impl Into<String>,
        state: OperationalKeyStatusState,
    ) {
        self.states.insert(authorization_id.into(), state);
    }

    pub fn state(&self, authorization_id: &str) -> OperationalKeyStatusState {
        self.states
            .get(authorization_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn apply_status(
        &mut self,
        status: &OperationalKeyStatus,
    ) -> Result<(), OperationalKeyRejection> {
        let mut state = self.state(&status.authorization_id);
        if status.sequence <= state.last_accepted_sequence {
            return Err(OperationalKeyRejection::OperationalKeyStatusRollback);
        }
        if state.disposition == Some(OperationalKeyDisposition::Compromised)
            && status.disposition != OperationalKeyDisposition::Compromised
        {
            return Err(OperationalKeyRejection::OperationalKeyCompromisedIrreversible);
        }
        if state.disposition == Some(OperationalKeyDisposition::Retired)
            && status.disposition == OperationalKeyDisposition::Active
        {
            return Err(OperationalKeyRejection::OperationalKeyRetiredIrreversible);
        }
        if state.disposition == Some(OperationalKeyDisposition::Retired)
            && status.disposition == OperationalKeyDisposition::Retired
        {
            let Some(current_effective_at) = &state.effective_at else {
                return Err(OperationalKeyRejection::OperationalKeyRetiredIrreversible);
            };
            let current_retired_at = parse_time(current_effective_at)
                .map_err(|_| OperationalKeyRejection::OperationalKeyRetiredIrreversible)?;
            let candidate_retired_at = parse_time(&status.effective_at)
                .map_err(|_| OperationalKeyRejection::OperationalKeyRetiredIrreversible)?;
            if candidate_retired_at > current_retired_at {
                return Err(OperationalKeyRejection::OperationalKeyRetiredIrreversible);
            }
        }
        state.last_accepted_sequence = status.sequence;
        state.disposition = Some(status.disposition.clone());
        state.effective_at = Some(status.effective_at.clone());
        self.states.insert(status.authorization_id.clone(), state);
        Ok(())
    }
}

pub fn check_trust_issuer_scope(
    authorization: &OperationalKeyAuthorization,
    context: &str,
) -> Result<(), OperationalKeyRejection> {
    if !authorization
        .roles
        .iter()
        .any(|role| role == &OperationalKeyRole::TrustIssuer)
    {
        return Err(OperationalKeyRejection::OperationalKeyRoleUnauthorized);
    }

    let Some(scope) = &authorization.trust_issuer_scope else {
        return Ok(());
    };
    if scope
        .context_prefixes
        .iter()
        .any(|prefix| slash_boundary_prefix_matches(prefix, context))
    {
        Ok(())
    } else {
        Err(OperationalKeyRejection::TrustIssuerContextOutOfScope)
    }
}

pub fn evaluate_operational_key_authorization(
    authorization: &OperationalKeyAuthorization,
    required_role: OperationalKeyRole,
    context: Option<&str>,
    status: Option<&OperationalKeyStatus>,
    signed_at: DateTime<Utc>,
    artifact_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), OperationalKeyRejection> {
    if !authorization
        .roles
        .iter()
        .any(|role| role == &required_role)
    {
        return Err(OperationalKeyRejection::OperationalKeyRoleUnauthorized);
    }

    if required_role == OperationalKeyRole::TrustIssuer {
        check_trust_issuer_scope(authorization, context.unwrap_or_default())?;
    }

    let not_before = parse_time(&authorization.not_before)
        .map_err(|_| OperationalKeyRejection::OperationalKeyNotYetValid)?;
    if signed_at < not_before {
        return Err(OperationalKeyRejection::OperationalKeyNotYetValid);
    }
    if let Some(expires_at) = &authorization.expires_at {
        let expires_at =
            parse_time(expires_at).map_err(|_| OperationalKeyRejection::OperationalKeyExpired)?;
        if signed_at > expires_at {
            return Err(OperationalKeyRejection::OperationalKeyExpired);
        }
    }

    let Some(status) = status else {
        return Ok(());
    };
    if status.authorization_id != authorization.authorization_id {
        return Err(OperationalKeyRejection::OperationalKeyStatusBindingMismatch);
    }

    match status.disposition {
        OperationalKeyDisposition::Active => Ok(()),
        OperationalKeyDisposition::Retired => {
            let retired_at = parse_time(&status.effective_at)
                .map_err(|_| OperationalKeyRejection::OperationalKeyRetired)?;
            if signed_at >= retired_at {
                return Err(OperationalKeyRejection::OperationalKeyRetired);
            }
            if let Some(expires_at) = artifact_expires_at {
                if now > expires_at {
                    return Err(OperationalKeyRejection::OperationalKeyArtifactExpired);
                }
            }
            Ok(())
        }
        OperationalKeyDisposition::Compromised => {
            Err(OperationalKeyRejection::OperationalKeyCompromised)
        }
    }
}

pub fn slash_boundary_prefix_matches(prefix: &str, context: &str) -> bool {
    if prefix.is_empty() || context.is_empty() {
        return false;
    }
    if prefix == context {
        return true;
    }
    if prefix == "/" {
        return context.starts_with('/');
    }

    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return false;
    }
    context
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyEngineRecord {
    pub schema: String,
    pub engine_record_id: String,
    pub owner_did: String,
    pub endpoint: String,
    pub audience: String,
    pub supported_policy_versions: Vec<String>,
    pub supported_evidence_verifiers: Vec<String>,
    pub grant_issuer_did: String,
    pub expires_at: String,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolderEnrollment {
    pub schema: String,
    pub enrollment_id: String,
    pub eligible_subject_did: String,
    pub holder_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<HolderEnrollmentScope>,
    pub not_before: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub signing_key_did: String,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolderEnrollmentScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolderEnrollmentStatus {
    pub schema: String,
    pub status_id: String,
    pub enrollment_id: String,
    pub sequence: u64,
    pub disposition: HolderEnrollmentDisposition,
    pub effective_at: String,
    pub signing_key_did: String,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HolderEnrollmentDisposition {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantChallenge {
    pub schema: String,
    pub challenge_id: String,
    pub policy_id: String,
    pub audience: String,
    pub nonce: String,
    pub challenge_expires_at: String,
    pub accepted_suites: Vec<SignatureSuite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_capabilities_template: Option<Vec<PolicyCapability>>,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantPresentation {
    pub schema: String,
    pub policy_id: String,
    pub eligible_subject_did: String,
    pub holder_did: String,
    pub holder_binding: HolderBindingProof,
    pub requested_capabilities: Vec<PolicyCapability>,
    pub requested_capabilities_hash: String,
    pub audience: String,
    pub nonce: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<PresentedEvidence>>,
    pub holder_signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HolderBindingProof {
    #[serde(rename_all = "camelCase")]
    EnrolledAgent {
        enrollment: HolderEnrollment,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<HolderEnrollmentStatus>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresentedEvidence {
    pub requirement_id: String,
    pub presentation: Value,
}

pub trait SchemaBound {
    fn schema_value(&self) -> &str;
    fn expected_schema() -> &'static str;
}

macro_rules! impl_schema_bound {
    ($ty:ty, $schema:expr) => {
        impl SchemaBound for $ty {
            fn schema_value(&self) -> &str {
                &self.schema
            }

            fn expected_schema() -> &'static str {
                $schema
            }
        }
    };
}

impl_schema_bound!(Policy, POLICY_SCHEMA);
impl_schema_bound!(PolicyStatus, POLICY_STATUS_SCHEMA);
impl_schema_bound!(PolicyEngineRecord, POLICY_ENGINE_RECORD_SCHEMA);
impl_schema_bound!(
    OperationalKeyAuthorization,
    OPERATIONAL_KEY_AUTHORIZATION_SCHEMA
);
impl_schema_bound!(OperationalKeyStatus, OPERATIONAL_KEY_STATUS_SCHEMA);
impl_schema_bound!(HolderEnrollment, HOLDER_ENROLLMENT_SCHEMA);
impl_schema_bound!(HolderEnrollmentStatus, HOLDER_ENROLLMENT_STATUS_SCHEMA);
impl_schema_bound!(GrantChallenge, GRANT_CHALLENGE_SCHEMA);
impl_schema_bound!(GrantPresentation, GRANT_PRESENTATION_SCHEMA);
