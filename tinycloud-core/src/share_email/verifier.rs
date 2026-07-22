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
    enforce_holder_equation, normalized_email_hash, verify_holder_binding_artifact, verify_sd_jwt,
    CredentialScope, EvidenceError, IssuerTrustRegistry, VerificationTime, VerifiedEmailEvidence,
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
    issuer_did: String,
    evaluation_time: i64,
    clock_skew_seconds: i64,
    expected_credential_expiry: Option<i64>,
    metrics: std::sync::Arc<VerificationMetrics>,
}

impl ExactEmailVerifier {
    pub fn new(
        issuer_trust: IssuerTrustRegistry,
        issuer_did: impl Into<String>,
        evaluation_time: i64,
        clock_skew_seconds: i64,
    ) -> Self {
        Self {
            issuer_trust,
            issuer_did: issuer_did.into(),
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

    /// Return the same trust policy evaluated at the supplied request time.
    /// Production HTTP composition must not freeze credential freshness at
    /// process startup.
    pub fn at_time(&self, evaluation_time: i64) -> Self {
        let mut verifier = self.clone();
        verifier.evaluation_time = evaluation_time;
        verifier
    }

    pub fn with_metrics(mut self, metrics: std::sync::Arc<VerificationMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn metrics(&self) -> &VerificationMetrics {
        &self.metrics
    }

    pub fn verify_exact_email_for(
        &self,
        credential: &[u8],
        expected_scope: &ShareScope,
        expected_holder: &DidKey,
        expected_email: &str,
        expected_expiry: i64,
    ) -> Result<CredentialVerificationEvidence, PortError> {
        let evidence = self
            .verify_inner(
                credential,
                expected_scope,
                expected_holder,
                expected_email,
                expected_expiry,
            )
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
        expected_email: &str,
        expected_expiry: i64,
    ) -> Result<CredentialVerificationEvidence, EvidenceError> {
        let scope = credential_scope(expected_scope);
        if self
            .expected_credential_expiry
            .is_some_and(|configured| configured != expected_expiry)
        {
            return Err(EvidenceError::CredentialExpired);
        }
        let verified = verify_sd_jwt(
            credential,
            &self.issuer_trust,
            &scope,
            expected_holder.as_str(),
            expected_email,
            &self.issuer_did,
            VerificationTime {
                evaluation_time: self.evaluation_time,
                clock_skew_seconds: self.clock_skew_seconds,
                expected_expiry: Some(expected_expiry),
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
        expected_credential_digest: &Sha256Digest,
        expected_challenge_id: &str,
        expected_challenge_nonce: &ProtocolNonce,
        expected_challenge_request_digest: &Sha256Digest,
        expected_enforcer: &DidKey,
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
            expected_credential_digest,
            expected_challenge_id,
            expected_challenge_nonce,
            expected_challenge_request_digest,
            expected_enforcer,
            presentation_holder,
        )
        .map_err(|_| PortError::Denied)?;
        let holder_binding_expires_at =
            validate_holder_binding_time(&message, self.evaluation_time, self.clock_skew_seconds)
                .map_err(|_| PortError::Denied)?;
        let holder_binding_jti = ProtocolJti::parse(
            message
                .get("jti")
                .and_then(Value::as_str)
                .ok_or(PortError::Denied)?,
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
            holder_binding_jti,
            holder_binding_expires_at,
        })
    }

    /// Convert a wire session request into the opaque authority admission
    /// only after exact credential and signed holder-binding verification.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_session_admission(
        &self,
        credential: &[u8],
        request: PolicySessionRequest,
        claimed_credential_digest: &Sha256Digest,
        holder_binding: &[u8],
        expected_email: &str,
        expected_expiry: i64,
        expected_enforcer: &DidKey,
        presentation_signer: &DidKey,
        read_signer: &DidKey,
    ) -> Result<VerifiedSessionAdmission, PortError> {
        let evidence = self.verify_exact_email_for(
            credential,
            &request.scope,
            &request.holder,
            expected_email,
            expected_expiry,
        )?;
        if evidence.credential_subject != request.holder || evidence.expires_at != expected_expiry {
            return Err(PortError::Denied);
        }
        let verified_credential_digest =
            credential_digest_from_evidence(&evidence, claimed_credential_digest)?;
        let email_hash =
            normalized_email_hash(&evidence.disclosed_email).map_err(|_| PortError::Denied)?;
        let equation = self.verify_holder_binding(
            holder_binding,
            &request.scope,
            &email_hash,
            &verified_credential_digest,
            &request.challenge_id,
            &request.nonce,
            &request.challenge_request_digest,
            expected_enforcer,
            &request.holder,
            presentation_signer,
            &request.holder,
            read_signer,
        )?;
        if equation.credential_subject != evidence.credential_subject
            || equation.holder_binding_expires_at > expected_expiry
        {
            return Err(PortError::Denied);
        }
        Ok(VerifiedSessionAdmission::from_verified(
            request,
            evidence.disclosed_email,
            verified_credential_digest,
            equation,
        ))
    }
}

fn credential_digest_from_evidence(
    evidence: &CredentialVerificationEvidence,
    claimed_credential_digest: &Sha256Digest,
) -> Result<Sha256Digest, PortError> {
    if evidence.credential_digest != *claimed_credential_digest {
        return Err(PortError::Denied);
    }
    Ok(evidence.credential_digest.clone())
}

#[async_trait]
impl CredentialVerifier for ExactEmailVerifier {
    async fn verify_credential_for(
        &self,
        credential: &[u8],
        expected_scope: &ShareScope,
        expected_holder: &DidKey,
        expected_email: &str,
        expected_expiry: i64,
    ) -> Result<CredentialVerificationEvidence, PortError> {
        self.verify_exact_email_for(
            credential,
            expected_scope,
            expected_holder,
            expected_email,
            expected_expiry,
        )
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

impl<A> AuthorityBridge117<A, ExactEmailVerifier>
where
    A: PolicyAuthorityTransaction117,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn establish_session_from_credential(
        &self,
        credential: &[u8],
        request: PolicySessionRequest,
        claimed_credential_digest: &Sha256Digest,
        expected_email: &str,
        expected_expiry: i64,
        holder_binding: &[u8],
        expected_enforcer: &DidKey,
        presentation_signer: &DidKey,
        read_signer: &DidKey,
        now: OffsetDateTime,
    ) -> Result<PolicySession, PortError> {
        let admission = self.verifier.verify_session_admission(
            credential,
            request,
            claimed_credential_digest,
            holder_binding,
            expected_email,
            expected_expiry,
            expected_enforcer,
            presentation_signer,
            read_signer,
        )?;
        self.authority.establish_session(admission, now).await
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
        expires_at: evidence.expires_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_holder_binding_message(
    message: &Value,
    scope: &ShareScope,
    expected_email_hash: &str,
    expected_credential_digest: &Sha256Digest,
    expected_challenge_id: &str,
    expected_challenge_nonce: &ProtocolNonce,
    expected_challenge_request_digest: &Sha256Digest,
    expected_enforcer: &DidKey,
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
        "credentialDigest",
        "targetOrigin",
        "nodeAudience",
        "audience",
        "enforcerDid",
        "requestOrigin",
        "challengeId",
        "challengeNonce",
        "challengeRequestDigest",
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
        || object.get("credentialDigest").and_then(Value::as_str)
            != Some(expected_credential_digest.as_str())
        || object.get("targetOrigin").and_then(Value::as_str) != Some(scope.target_origin.as_str())
        || object.get("nodeAudience").and_then(Value::as_str) != Some(scope.node_audience.as_str())
        || object.get("audience").and_then(Value::as_str) != Some(scope.node_audience.as_str())
        || object.get("enforcerDid").and_then(Value::as_str) != Some(expected_enforcer.as_str())
        || object.get("requestOrigin").and_then(Value::as_str) != Some(scope.target_origin.as_str())
        || object.get("invitationId").and_then(Value::as_str) != Some(scope.share_cid.as_str())
        || object.get("redemptionId").and_then(Value::as_str) != Some(scope.share_id.as_str())
        || object.get("claimNonce").and_then(Value::as_str)
            != Some(expected_challenge_nonce.as_str())
        || object.get("challengeId").and_then(Value::as_str) != Some(expected_challenge_id)
        || object.get("challengeNonce").and_then(Value::as_str)
            != Some(expected_challenge_nonce.as_str())
        || object.get("challengeRequestDigest").and_then(Value::as_str)
            != Some(expected_challenge_request_digest.as_str())
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

fn validate_holder_binding_time(
    message: &Value,
    evaluation_time: i64,
    clock_skew_seconds: i64,
) -> Result<i64, EvidenceError> {
    if clock_skew_seconds < 0 {
        return Err(EvidenceError::InvalidHolderProof);
    }
    let issued_at = message
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or(EvidenceError::InvalidHolderProof)?;
    let expires_at = message
        .get("expiresAt")
        .and_then(Value::as_str)
        .ok_or(EvidenceError::InvalidHolderProof)?;
    let issued_at =
        OffsetDateTime::parse(issued_at, &time::format_description::well_known::Rfc3339)
            .map_err(|_| EvidenceError::InvalidHolderProof)?
            .unix_timestamp();
    let expires_at =
        OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .map_err(|_| EvidenceError::InvalidHolderProof)?
            .unix_timestamp();
    if issued_at > evaluation_time.saturating_add(clock_skew_seconds)
        || expires_at <= evaluation_time.saturating_sub(clock_skew_seconds)
        || expires_at <= issued_at
        || message
            .get("jti")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(EvidenceError::InvalidHolderProof);
    }
    Ok(expires_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn holder() -> DidKey {
        DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw").unwrap()
    }

    fn binding_scope() -> ShareScope {
        let path = Path::parse("documents/plan.md").unwrap();
        let source = ContentSource::Kv {
            action: KvGetAction::Get,
            space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                .unwrap(),
            path: path.clone(),
        };
        ShareScope {
            share_cid: ShareCid::parse(KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("redemption-01").unwrap(),
            delegation_cid: Some(
                ShareDelegationCid::parse(
                    "bafkreihhkhfgdqltz6ivbwcj7pq4idmzv7nsrbz6atilby3ymovnfquwam",
                )
                .unwrap(),
            ),
            authority_material_handle: AuthorityMaterialHandle::parse("amh_kv_001").unwrap(),
            authority_material_digest: Sha256Digest::from_bytes([1; 32]),
            policy_cid: PolicyCid::parse(KV_POLICY_CID).unwrap(),
            node_audience: Did::parse("did:web:node.example").unwrap(),
            target_origin: TargetOrigin::parse("https://node.example").unwrap(),
            action: ShareAction::KvGet,
            resource: ExactResource::Kv { path },
            content_source: source,
            content_source_digest: Sha256Digest::from_bytes([2; 32]),
        }
    }

    fn valid_holder_binding(scope: &ShareScope, digest: &Sha256Digest) -> Value {
        let holder = holder();
        json!({
            "type": HOLDER_BINDING_TYPE,
            "version": 1,
            "redemptionId": scope.share_id.as_str(),
            "invitationId": scope.share_cid.as_str(),
            "claimNonce": ProtocolNonce::from_bytes([3; 32]).as_str(),
            "shareCid": scope.share_cid.as_str(),
            "shareId": scope.share_id.as_str(),
            "policyCid": scope.policy_cid.as_str(),
            "contentSource": serde_json::to_value(&scope.content_source).unwrap(),
            "contentSourceDigest": scope.content_source_digest.as_str(),
            "emailHash": "email-hash",
            "holderDid": holder.as_str(),
            "credentialDigest": digest.as_str(),
            "targetOrigin": scope.target_origin.as_str(),
            "nodeAudience": scope.node_audience.as_str(),
            "audience": scope.node_audience.as_str(),
            "enforcerDid": holder.as_str(),
            "requestOrigin": scope.target_origin.as_str(),
            "challengeId": "challenge-01",
            "challengeNonce": ProtocolNonce::from_bytes([3; 32]).as_str(),
            "challengeRequestDigest": Sha256Digest::from_bytes([4; 32]).as_str(),
            "issuedAt": "2026-07-20T00:00:00Z",
            "expiresAt": "2026-07-20T00:05:00Z",
            "jti": ProtocolJti::from_bytes([7; 16]).as_str(),
        })
    }

    #[test]
    fn metrics_are_not_keyed_by_private_evidence() {
        let metrics = VerificationMetrics::default();
        metrics.rejected.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.rejected(), 1);
        assert_eq!(metrics.accepted(), 0);
    }

    #[test]
    fn caller_selected_credential_digest_cannot_replace_verified_evidence() {
        let evidence = CredentialVerificationEvidence {
            issuer_did: Did::parse("did:web:issuer.example").unwrap(),
            credential_subject: holder(),
            disclosed_email: "holder@example.com".to_owned(),
            credential_digest: Sha256Digest::from_bytes([5; 32]),
            expires_at: 1,
        };
        assert_eq!(
            credential_digest_from_evidence(&evidence, &Sha256Digest::from_bytes([5; 32])).unwrap(),
            Sha256Digest::from_bytes([5; 32])
        );
        assert_eq!(
            credential_digest_from_evidence(&evidence, &Sha256Digest::from_bytes([6; 32])),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn holder_binding_accepts_live_context_and_rejects_rebindings() {
        let scope = binding_scope();
        let digest = Sha256Digest::from_bytes([5; 32]);
        let nonce = ProtocolNonce::from_bytes([3; 32]);
        let request_digest = Sha256Digest::from_bytes([4; 32]);
        let enforcer = holder();
        let valid = valid_holder_binding(&scope, &digest);
        assert!(validate_holder_binding_message(
            &valid,
            &scope,
            "email-hash",
            &digest,
            "challenge-01",
            &nonce,
            &request_digest,
            &enforcer,
            &enforcer,
        )
        .is_ok());

        for field in [
            "redemptionId",
            "invitationId",
            "claimNonce",
            "requestOrigin",
            "audience",
            "enforcerDid",
            "credentialDigest",
            "challengeId",
            "challengeNonce",
            "challengeRequestDigest",
        ] {
            let mut forged = valid.clone();
            forged[field] = json!("forged");
            assert!(
                validate_holder_binding_message(
                    &forged,
                    &scope,
                    "email-hash",
                    &digest,
                    "challenge-01",
                    &nonce,
                    &request_digest,
                    &enforcer,
                    &enforcer,
                )
                .is_err(),
                "forged {field} was accepted"
            );
        }
    }
}
