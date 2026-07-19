//! Exact-email OpenCredentials verifier and the narrow #117 authority bridge.
//!
//! This module has no route, configuration, persistence, or capability
//! composition.  A successful credential check produces evidence only; the
//! authority kernel remains responsible for policy ancestry, revocation,
//! nonce/JTI consumption, sessions, and reads.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;

use super::{ports::*, types::*};
use tinycloud_auth::share_email_evidence::{
    enforce_holder_equation, verify_holder_binding_artifact, verify_sd_jwt, CredentialScope,
    EvidenceError, IssuerTrustRegistry, VerificationTime, VerifiedEmailEvidence,
    HOLDER_BINDING_TYPE,
};

pub const EMAIL_VCT: &str = "opencredentials.email/v1";

/// Privacy-safe counters: callers may export totals, but no email, DID, JTI,
/// issuer, or stable request identifier is ever attached to a rejection.
#[derive(Debug, Default)]
pub struct VerificationMetrics {
    rejected: AtomicU64,
    accepted: AtomicU64,
}

impl VerificationMetrics {
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct ExactEmailVerifier {
    issuer_trust: IssuerTrustRegistry,
    expected_email: String,
    evaluation_time: i64,
    clock_skew_seconds: i64,
    expected_credential_expiry: Option<i64>,
    metrics: std::sync::Arc<VerificationMetrics>,
}

impl ExactEmailVerifier {
    pub fn new(
        issuer_trust: IssuerTrustRegistry,
        expected_email: impl Into<String>,
        evaluation_time: i64,
        clock_skew_seconds: i64,
    ) -> Self {
        Self {
            issuer_trust,
            expected_email: expected_email.into(),
            evaluation_time,
            clock_skew_seconds,
            expected_credential_expiry: None,
            metrics: std::sync::Arc::new(VerificationMetrics::default()),
        }
    }

    pub fn with_expected_credential_expiry(mut self, expiry: i64) -> Self {
        self.expected_credential_expiry = Some(expiry);
        self
    }

    pub fn with_metrics(mut self, metrics: std::sync::Arc<VerificationMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn metrics(&self) -> &VerificationMetrics {
        &self.metrics
    }

    pub fn verify_exact_email(
        &self,
        credential: &[u8],
        expected_scope: &ShareScope,
        expected_holder: &DidKey,
    ) -> Result<CredentialVerificationEvidence, PortError> {
        let evidence = self
            .verify_inner(credential, expected_scope, expected_holder)
            .map_err(|_| {
                self.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                PortError::Denied
            })?;
        self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(evidence)
    }

    fn verify_inner(
        &self,
        credential: &[u8],
        expected_scope: &ShareScope,
        expected_holder: &DidKey,
    ) -> Result<CredentialVerificationEvidence, EvidenceError> {
        let scope = credential_scope(expected_scope);
        let verified = verify_sd_jwt(
            credential,
            &self.issuer_trust,
            &scope,
            expected_holder.as_str(),
            &self.expected_email,
            VerificationTime {
                evaluation_time: self.evaluation_time,
                clock_skew_seconds: self.clock_skew_seconds,
                expected_expiry: self.expected_credential_expiry,
            },
        )?;
        convert_evidence(verified)
    }

    /// Verify the domain-separated, canonical holder binding before handing
    /// the equality result to the authority transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_holder_binding(
        &self,
        artifact: &[u8],
        expected_scope: &ShareScope,
        expected_email_hash: &str,
        presentation_holder: &DidKey,
        presentation_signer: &DidKey,
        policy_session_holder: &DidKey,
        read_signer: &DidKey,
    ) -> Result<HolderEquation, PortError> {
        let message = verify_holder_binding_artifact(artifact, presentation_holder.as_str())
            .map_err(|_| PortError::Denied)?;
        validate_holder_binding_message(
            &message,
            expected_scope,
            expected_email_hash,
            presentation_holder,
        )
        .map_err(|_| PortError::Denied)?;
        enforce_holder_equation([
            message
                .get("holderDid")
                .and_then(Value::as_str)
                .ok_or(PortError::Denied)?,
            presentation_holder.as_str(),
            presentation_signer.as_str(),
            policy_session_holder.as_str(),
            read_signer.as_str(),
        ])
        .map_err(|_| PortError::Denied)?;
        Ok(HolderEquation {
            credential_subject: expected_holder_from_message(&message)?,
            presentation_holder: presentation_holder.clone(),
            presentation_signer: presentation_signer.clone(),
            policy_session_holder: policy_session_holder.clone(),
            read_signer: read_signer.clone(),
        })
    }
}

#[async_trait]
impl CredentialVerifier for ExactEmailVerifier {
    async fn verify_credential(
        &self,
        credential: &[u8],
        expected_scope: &ShareScope,
        expected_holder: &DidKey,
    ) -> Result<CredentialVerificationEvidence, PortError> {
        self.verify_exact_email(credential, expected_scope, expected_holder)
    }
}

/// The only composition point from exact-email protocol data into #117.  It
/// never creates authority records and never treats a verified credential,
/// session handle, or read request as authorization by itself.
pub struct AuthorityBridge117<A, V> {
    authority: A,
    verifier: V,
}

impl<A, V> AuthorityBridge117<A, V> {
    pub fn new(authority: A, verifier: V) -> Self {
        Self {
            authority,
            verifier,
        }
    }

    pub fn authority(&self) -> &A {
        &self.authority
    }

    pub fn verifier(&self) -> &V {
        &self.verifier
    }
}

impl<A, V> AuthorityBridge117<A, V>
where
    A: PolicyAuthorityTransaction117,
    V: CredentialVerifier,
{
    pub async fn establish_session_from_credential(
        &self,
        credential: &[u8],
        request: PolicySessionRequest,
        expected_holder: &DidKey,
        now: OffsetDateTime,
    ) -> Result<PolicySession, PortError> {
        let evidence = self
            .verifier
            .verify_credential(credential, &request.scope, expected_holder)
            .await?;
        if DidKey::parse(evidence.credential_subject.as_str())
            .ok()
            .as_ref()
            != Some(expected_holder)
        {
            return Err(PortError::Denied);
        }
        self.authority.establish_session(request, now).await
    }

    pub async fn authorize_read(
        &self,
        request: ReadAuthorizationRequest,
        now: OffsetDateTime,
    ) -> Result<AuthorizedRead, PortError> {
        // #117 revalidates complete ancestry/revocation and consumes the read
        // JTI atomically.  This delegation is intentionally the entire read
        // path here.
        self.authority.authorize_read(request, now).await
    }
}

fn credential_scope(scope: &ShareScope) -> CredentialScope<'_> {
    CredentialScope {
        share_cid: scope.share_cid.as_str(),
        share_id: scope.share_id.as_str(),
        policy_cid: scope.policy_cid.as_str(),
        node_audience: scope.node_audience.as_str(),
    }
}

fn convert_evidence(
    evidence: VerifiedEmailEvidence,
) -> Result<CredentialVerificationEvidence, EvidenceError> {
    Ok(CredentialVerificationEvidence {
        issuer_did: Did::parse(evidence.issuer_did).map_err(|_| EvidenceError::Invalid)?,
        credential_subject: DidKey::parse(evidence.credential_subject)
            .map_err(|_| EvidenceError::Invalid)?,
        disclosed_email: evidence.disclosed_email,
        credential_digest: Sha256Digest::from_bytes(evidence.credential_digest),
    })
}

fn validate_holder_binding_message(
    message: &Value,
    scope: &ShareScope,
    expected_email_hash: &str,
    expected_holder: &DidKey,
) -> Result<(), EvidenceError> {
    let object = message
        .as_object()
        .ok_or(EvidenceError::InvalidHolderProof)?;
    let expected = [
        "type",
        "version",
        "redemptionId",
        "invitationId",
        "claimNonce",
        "shareCid",
        "shareId",
        "policyCid",
        "contentSource",
        "contentSourceDigest",
        "emailHash",
        "holderDid",
        "targetOrigin",
        "nodeAudience",
        "requestOrigin",
        "issuedAt",
        "expiresAt",
        "jti",
    ];
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(EvidenceError::InvalidHolderProof);
    }
    if object.get("type").and_then(Value::as_str) != Some(HOLDER_BINDING_TYPE)
        || object.get("version").and_then(Value::as_i64) != Some(1)
        || object.get("holderDid").and_then(Value::as_str) != Some(expected_holder.as_str())
        || object.get("shareCid").and_then(Value::as_str) != Some(scope.share_cid.as_str())
        || object.get("shareId").and_then(Value::as_str) != Some(scope.share_id.as_str())
        || object.get("policyCid").and_then(Value::as_str) != Some(scope.policy_cid.as_str())
        || object.get("contentSourceDigest").and_then(Value::as_str)
            != Some(scope.content_source_digest.as_str())
        || object.get("emailHash").and_then(Value::as_str) != Some(expected_email_hash)
        || object.get("targetOrigin").and_then(Value::as_str) != Some(scope.target_origin.as_str())
        || object.get("nodeAudience").and_then(Value::as_str) != Some(scope.node_audience.as_str())
        || object.get("contentSource")
            != Some(
                &serde_json::to_value(&scope.content_source)
                    .map_err(|_| EvidenceError::InvalidHolderProof)?,
            )
    {
        return Err(EvidenceError::ScopeMismatch);
    }
    Ok(())
}

fn expected_holder_from_message(message: &Value) -> Result<DidKey, PortError> {
    DidKey::parse(
        message
            .get("holderDid")
            .and_then(Value::as_str)
            .ok_or(PortError::Denied)?,
    )
    .map_err(|_| PortError::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_not_keyed_by_private_evidence() {
        let metrics = VerificationMetrics::default();
        metrics.rejected.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.rejected(), 1);
        assert_eq!(metrics.accepted(), 0);
    }
}
