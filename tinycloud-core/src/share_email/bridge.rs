//! N4 integration: the sole concrete [`PolicyAuthorityTransaction117`]
//! bridge from exact-email protocol state into the refreshed #117 authority
//! kernel.
//!
//! Both effects of each method (the #117 ancestry/revocation revalidation
//! and this protocol's nonce/JTI/session-handle persistence) run inside one
//! shared [`sea_orm::DatabaseTransaction`] and commit or roll back together.
//! Neither side ever authorizes a request by itself: a session handle or
//! read JTI alone is meaningless unless #117 still validates the referenced
//! `policy_cid` at the moment of use.
//!
//! This bridge never mints a new #117 delegation. `policy_cid` must already
//! reference an existing, live #117 authority chain established by the
//! sharer's own policy-authority flow; this module only revalidates that
//! chain and layers opaque, privacy-safe protocol state on top of it.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    models::{share_policy_presentation_jti, share_session_handle},
    policy_authority::{
        AuthorityArtifactVerifier, AuthorityError, AuthorityStatusObservation,
        DatabaseAuthorityKernel, DatabaseAuthorityStore, DecisionContext, DelegationMode,
        DelegationRole, DelegationSignature, IssuanceAudit, IssuanceBindings, NodeRootSigner,
        PolicyDelegation, TrustedPolicyDecision, VerifiedAttestedEnforcerBinding,
        VerifiedPolicyState,
    },
    policy_capability::{jcs, parse as parse_capability, PolicyCapability},
};

use super::{
    ports::{
        AttestationEnrollmentProvider, AuthorityMaterialProvider, FreshAuthenticatedStatusProvider,
        PolicyAuthorityTransaction117, PortError,
    },
    state::{
        parse_timestamp, timestamp, AuditEvent, HolderReadJti, ProtocolStateRepository,
        SessionHandleMapping, StateError, READ_JTI_TTL, SESSION_TTL,
    },
    types::{
        AuthorizedRead, Did, DidKey, NodeDelegationCid, PolicySession, PolicySessionRequest,
        ReadAuthorizationRequest, ReadInvocation, SessionHandle, Sha256Digest, ShareScope,
        TargetOrigin,
    },
};

/// The only #117 composition point exact-email code may hold. It shares one
/// database connection with [`DatabaseAuthorityStore`] so both stores'
/// effects are transactionally atomic per call.
#[derive(Clone)]
pub struct DatabaseAuthorityBridge117 {
    conn: DatabaseConnection,
    authority: DatabaseAuthorityStore,
    authority_material: Option<Arc<dyn AuthorityMaterialProvider>>,
    status_provider: Option<Arc<dyn FreshAuthenticatedStatusProvider>>,
    attestation_provider: Option<Arc<dyn AttestationEnrollmentProvider>>,
    root_signer: Option<Arc<dyn NodeRootSigner>>,
}

impl DatabaseAuthorityBridge117 {
    async fn issue_root_in_transaction(
        &self,
        tx: &sea_orm::DatabaseTransaction,
        request: &PolicySessionRequest,
        now: OffsetDateTime,
        policy_expiry: OffsetDateTime,
        credential_expiry: OffsetDateTime,
    ) -> Result<String, PortError> {
        let policy_cid = request
            .scope
            .delegation_cid
            .as_ref()
            .ok_or(PortError::Denied)?;
        let provider = self
            .authority_material
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let bundle = provider
            .resolve_exact(
                &request.scope.policy_cid,
                policy_cid,
                &request.scope.authority_material_handle,
                &request.scope.authority_material_digest,
            )
            .await?;
        let verifier = AuthorityArtifactVerifier;
        let policy = verifier
            .verify(&bundle.policy_authority)
            .map_err(map_authority_error)?;
        let enforcement = verifier
            .verify(&bundle.policy_enforcement)
            .map_err(map_authority_error)?;
        let status_provider = self
            .status_provider
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let status = parse_status(
            &status_provider
                .refresh(&bundle.internal_policy_authority_cid)
                .await?,
            &bundle.internal_policy_authority_cid,
            now,
        )?;
        let policy_state = VerifiedPolicyState::from_verified(
            policy.artifact(),
            enforcement.artifact(),
            status.checked_at,
            policy_expiry.min(credential_expiry),
        )
        .map_err(map_authority_error)?;
        let parsed_capabilities = policy
            .artifact()
            .capabilities
            .iter()
            .map(parse_capability)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PortError::Denied)?;
        let capability_hash =
            crate::policy_capability::requested_capabilities_hash_hex(&parsed_capabilities);
        let enforcer = enforcement
            .artifact()
            .fact_value("enforcerDid")
            .map_err(|_| PortError::Denied)?;
        let audience = enforcement
            .artifact()
            .fact_value("nodeAudience")
            .map_err(|_| PortError::Denied)?;
        let nonce_hash = digest_string(request.nonce.as_str());
        let claimant = request.holder.as_str().to_owned();
        let challenge_expires = now + SESSION_TTL;
        let challenge = crate::policy_authority::ChallengeState::from_verified(
            request.challenge_id.clone(),
            nonce_hash.as_str(),
            policy
                .artifact()
                .fact_value("ownerDid")
                .map_err(|_| PortError::Denied)?,
            policy
                .artifact()
                .fact_value("policyId")
                .map_err(|_| PortError::Denied)?,
            policy
                .artifact()
                .fact_value("policyDigestHex")
                .map_err(|_| PortError::Denied)?,
            policy.artifact().delegation_cid.clone(),
            enforcement.artifact().delegation_cid.clone(),
            enforcer,
            audience,
            claimant.clone(),
            capability_hash.clone(),
            now,
            challenge_expires,
        )
        .map_err(map_authority_error)?;
        self.authority
            .insert_challenge_in_transaction(tx, challenge)
            .await
            .map_err(map_authority_error)?;
        let decision_context = DecisionContext {
            owner_did: policy
                .artifact()
                .fact_value("ownerDid")
                .map_err(|_| PortError::Denied)?
                .to_owned(),
            policy_id: policy
                .artifact()
                .fact_value("policyId")
                .map_err(|_| PortError::Denied)?
                .to_owned(),
            policy_digest_hex: policy
                .artifact()
                .fact_value("policyDigestHex")
                .map_err(|_| PortError::Denied)?
                .to_owned(),
            capability_ceiling_hash_hex: policy
                .artifact()
                .fact_value("capabilityCeilingHashHex")
                .map_err(|_| PortError::Denied)?
                .to_owned(),
            enforcer_did: enforcer.to_owned(),
            node_audience: audience.to_owned(),
            claimant_did: claimant.clone(),
            challenge_id: request.challenge_id.clone(),
            challenge_nonce_hash_hex: nonce_hash.as_str().to_owned(),
            requested_capabilities_hash_hex: capability_hash.clone(),
            claim_invocation_digest_hex: request.challenge_request_digest.as_str().to_owned(),
            vp_digest_hex: request.credential_digest.as_str().to_owned(),
        };
        let decision =
            TrustedPolicyDecision::allow_from_verified(decision_context, now, now + SESSION_TTL)
                .map_err(map_authority_error)?;
        let bindings = IssuanceBindings::from_verified(
            now,
            now,
            credential_expiry,
            request.challenge_id.clone(),
            nonce_hash.as_str(),
            claimant.clone(),
            capability_hash.clone(),
            request.challenge_request_digest.as_str(),
            request.credential_digest.as_str(),
        );
        let binding = VerifiedAttestedEnforcerBinding::from_verified(
            enforcement
                .artifact()
                .fact_value("attestationBindingDigestHex")
                .map_err(|_| PortError::Denied)?,
            enforcer,
            audience,
            policy_expiry.min(
                enforcement
                    .artifact()
                    .expires_at()
                    .map_err(map_authority_error)?,
            ),
        );
        let issuance_id = next_issuance_id();
        let expires_at = [
            now + SESSION_TTL,
            policy_expiry,
            credential_expiry,
            enforcement
                .artifact()
                .expires_at()
                .map_err(map_authority_error)?,
        ]
        .into_iter()
        .min()
        .ok_or(PortError::Denied)?;
        let audit = IssuanceAudit::build_verified(
            issuance_id.clone(),
            policy.artifact(),
            enforcement.artifact(),
            claimant.clone(),
            capability_hash.clone(),
            request.challenge_id.clone(),
            nonce_hash.as_str(),
            request.challenge_request_digest.as_str(),
            request.credential_digest.as_str(),
            decision.decision_context_digest_hex(),
            now,
            expires_at,
        )
        .map_err(map_authority_error)?;
        let mut facts = policy.artifact().facts.clone();
        for (name, value) in [
            ("capabilityHashHex", capability_hash),
            ("enforcerDid", enforcer.to_owned()),
            ("nodeAudience", audience.to_owned()),
            ("rootClaimantDid", claimant.clone()),
            ("sessionSubjectDid", claimant),
            (
                "policyDelegationCid",
                policy.artifact().delegation_cid.clone(),
            ),
            (
                "enforcementDelegationCid",
                enforcement.artifact().delegation_cid.clone(),
            ),
            (
                "attestationBindingDigestHex",
                binding.binding_digest_hex().to_owned(),
            ),
            (
                "claimInvocationDigestHex",
                request.challenge_request_digest.as_str().to_owned(),
            ),
            ("vpDigestHex", request.credential_digest.as_str().to_owned()),
            (
                "decisionContextDigestHex",
                decision.decision_context_digest_hex().to_owned(),
            ),
            (
                "issuanceAuditDigestHex",
                audit.audit_digest_hex().to_owned(),
            ),
            ("issuanceId", issuance_id),
            (
                "remainingRedelegationDepth",
                enforcement
                    .artifact()
                    .fact_value("maxRedelegationDepth")
                    .map_err(|_| PortError::Denied)?
                    .to_owned(),
            ),
            ("auditProfile", "vp-digest-v1".to_owned()),
        ] {
            facts.insert(format!("xyz.tinycloud.policy/{name}"), value);
        }
        let root = PolicyDelegation {
            schema: "xyz.tinycloud.policy/enforcement-delegation/v1".to_owned(),
            role: DelegationRole::PolicySessionRoot,
            delegation_cid: String::new(),
            issuer_did: enforcer.to_owned(),
            audience_did: request.holder.as_str().to_owned(),
            capabilities: enforcement.artifact().capabilities.clone(),
            proof_cids: vec![
                policy.artifact().delegation_cid.clone(),
                enforcement.artifact().delegation_cid.clone(),
            ],
            not_before: timestamp(now).map_err(|_| PortError::Denied)?,
            expires_at: timestamp(expires_at).map_err(|_| PortError::Denied)?,
            delegation_mode: if enforcement
                .artifact()
                .fact_value("maxRedelegationDepth")
                .map_err(|_| PortError::Denied)?
                .parse::<u8>()
                .map_err(|_| PortError::Denied)?
                > 0
            {
                DelegationMode::Attenuable
            } else {
                DelegationMode::Terminal
            },
            facts,
            signature: DelegationSignature {
                suite: "eddsa-ed25519-sha256-jcs-v1".to_owned(),
                value: String::new(),
            },
        };
        let signer = self.root_signer.as_ref().ok_or(PortError::Unavailable)?;
        let preview = verifier
            .sign_and_verify_root(root.clone(), signer.as_ref())
            .map_err(map_authority_error)?;
        DatabaseAuthorityKernel::new(
            self.authority.clone(),
            enforcement.artifact().audience_did.clone(),
        )
        .sign_and_issue_root_in_transaction(
            tx,
            &policy,
            &enforcement,
            &policy_state,
            root,
            signer.as_ref(),
            &binding,
            &decision,
            &bindings,
        )
        .await
        .map_err(map_authority_error)?;
        Ok(preview.artifact().delegation_cid.clone())
    }

    /// `conn` and `authority` must share the same underlying database so a
    /// transaction begun on `conn` is visible to `authority`'s row locks.
    pub fn new(conn: DatabaseConnection, authority: DatabaseAuthorityStore) -> Self {
        Self {
            conn,
            authority,
            authority_material: None,
            status_provider: None,
            attestation_provider: None,
            root_signer: None,
        }
    }

    pub fn with_authority_providers(
        mut self,
        authority_material: Arc<dyn AuthorityMaterialProvider>,
        status_provider: Arc<dyn FreshAuthenticatedStatusProvider>,
        attestation_provider: Arc<dyn AttestationEnrollmentProvider>,
    ) -> Self {
        self.authority_material = Some(authority_material);
        self.status_provider = Some(status_provider);
        self.attestation_provider = Some(attestation_provider);
        self
    }

    pub fn with_root_signer(mut self, signer: Arc<dyn NodeRootSigner>) -> Self {
        self.root_signer = Some(signer);
        self
    }

    pub fn ready(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        self.authority_material
            .as_ref()
            .is_some_and(|provider| provider.healthy_at(now))
            && self
                .status_provider
                .as_ref()
                .is_some_and(|provider| provider.healthy_at(now))
            && self
                .attestation_provider
                .as_ref()
                .is_some_and(|provider| provider.healthy_at(now))
            && self.root_signer.is_some()
    }

    /// Performs the cheap end-to-end readiness probe used by mounted callers:
    /// all authenticated inputs are current and the shared authority database
    /// can open and close a transaction.  No request data participates.
    pub async fn self_check(&self) -> bool {
        if !self.ready() {
            return false;
        }
        let transaction = match self.conn.begin().await {
            Ok(transaction) => transaction,
            Err(_) => return false,
        };
        transaction.rollback().await.is_ok()
    }
}

/// The durable content bound to an opaque session handle. Stored verbatim so
/// every later read can be revalidated against the exact scope and
/// credential digest the session was established for, never against
/// whatever a caller currently claims.
#[derive(Serialize, Deserialize)]
struct SessionBinding {
    scope_digest: Sha256Digest,
    delegation_cid: super::types::ShareDelegationCid,
    credential_digest: Sha256Digest,
}

#[async_trait]
impl PolicyAuthorityTransaction117 for DatabaseAuthorityBridge117 {
    async fn establish_session(
        &self,
        request: PolicySessionRequest,
        now: OffsetDateTime,
    ) -> Result<PolicySession, PortError> {
        let tx = self.conn.begin().await.map_err(|_| PortError::Storage)?;

        let (policy_expiry, policy_recipient, sql_statement, _internal_delegation_cid) = self
            .validate_scope_in_transaction(&tx, &request.scope, now)
            .await?;
        let recipient_digest = digest_string(&policy_recipient);
        if recipient_digest != request.policy_recipient_digest {
            return Err(PortError::Denied);
        }
        let credential_expiry = OffsetDateTime::from_unix_timestamp(request.credential_expires_at)
            .map_err(|_| PortError::Denied)?;
        if credential_expiry != policy_expiry {
            return Err(PortError::Denied);
        }
        ProtocolStateRepository::consume_anonymous_challenge_in_transaction(
            &tx,
            &request.challenge_id,
            request.challenge_request_digest.as_str(),
            &request.challenge_binding,
            digest_string(request.nonce.as_str()).as_str(),
            now,
        )
        .await
        .map_err(map_state_error)?;

        let already_used =
            share_policy_presentation_jti::Entity::find_by_id(request.presentation_jti.as_str())
                .one(&tx)
                .await
                .map_err(|_| PortError::Storage)?
                .is_some()
                || share_policy_presentation_jti::Entity::find()
                    .filter(share_policy_presentation_jti::Column::Nonce.eq(request.nonce.as_str()))
                    .one(&tx)
                    .await
                    .map_err(|_| PortError::Storage)?
                    .is_some();
        if already_used {
            return Err(PortError::Replay);
        }

        let authority_session_cid = self
            .issue_root_in_transaction(&tx, &request, now, policy_expiry, credential_expiry)
            .await?;

        let mut handle_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut handle_bytes);
        let handle = SessionHandle::from_bytes(handle_bytes);
        let expires_at = (now + SESSION_TTL)
            .min(credential_expiry)
            .min(policy_expiry);
        if expires_at <= now {
            return Err(PortError::Denied);
        }

        share_policy_presentation_jti::ActiveModel {
            presentation_jti: Set(request.presentation_jti.as_str().to_owned()),
            nonce: Set(request.nonce.as_str().to_owned()),
            policy_cid: Set(request.scope.policy_cid.as_str().to_owned()),
            session_handle: Set(handle.as_str().to_owned()),
            issued_at: Set(timestamp(now).map_err(map_state_error)?),
            expires_at: Set(timestamp(expires_at).map_err(map_state_error)?),
        }
        .insert(&tx)
        .await
        .map_err(|_| PortError::Replay)?;

        let binding = SessionBinding {
            scope_digest: scope_digest(&request.scope),
            delegation_cid: request
                .scope
                .delegation_cid
                .clone()
                .ok_or(PortError::Denied)?,
            credential_digest: request.credential_digest.clone(),
        };
        let binding_json = serde_json::to_value(&binding).map_err(|_| PortError::Storage)?;
        let mapping = SessionHandleMapping {
            handle: handle.as_str().to_owned(),
            authority_session_cid,
            binding_json,
            holder_digest: holder_digest(&request.holder),
            issued_at: now,
            expires_at,
        };
        let audit = AuditEvent {
            audit_id: format!("share-email-session-{}", handle.as_str()),
            event_kind: "share_email.session_established".to_owned(),
            outcome: "accepted".to_owned(),
            share_digest: digest_string(request.scope.share_cid.as_str())
                .as_str()
                .to_owned(),
            origin_digest: digest_string(request.scope.target_origin.as_str())
                .as_str()
                .to_owned(),
            holder_digest: Some(holder_digest(&request.holder)),
            request_digest: request.credential_digest.as_str().to_owned(),
        };

        ProtocolStateRepository::commit_session_in_transaction(&tx, mapping, audit, now)
            .await
            .map_err(map_state_error)?;

        tx.commit().await.map_err(|_| PortError::Storage)?;

        Ok(PolicySession {
            handle,
            scope: request.scope,
            holder: request.holder,
            credential_digest: request.credential_digest,
            sql_statement,
        })
    }

    async fn authorize_read(
        &self,
        request: ReadAuthorizationRequest,
        now: OffsetDateTime,
    ) -> Result<AuthorizedRead, PortError> {
        let tx = self.conn.begin().await.map_err(|_| PortError::Storage)?;

        let session_row = share_session_handle::Entity::find_by_id(request.session.as_str())
            .one(&tx)
            .await
            .map_err(|_| PortError::Storage)?
            .ok_or(PortError::Denied)?;

        if session_row.revoked_at.is_some() {
            return Err(PortError::Denied);
        }
        let session_expires_at =
            parse_timestamp(&session_row.expires_at).map_err(map_state_error)?;
        if session_expires_at <= now {
            return Err(PortError::Denied);
        }
        if session_row.holder_digest != holder_digest(&request.holder) {
            return Err(PortError::Denied);
        }
        let binding: SessionBinding = serde_json::from_value(session_row.binding_json.clone())
            .map_err(|_| PortError::Storage)?;
        let mut scope = request.scope.clone();
        if scope.delegation_cid.is_none() {
            scope.delegation_cid = Some(binding.delegation_cid.clone());
        }
        if scope_digest(&scope) != binding.scope_digest {
            return Err(PortError::Denied);
        }

        let (_, _, sql_statement, _) = self.validate_scope_in_transaction(&tx, &scope, now).await?;

        self.authority
            .validate_for_invocation_in_transaction(&tx, &session_row.authority_session_cid, now)
            .await
            .map_err(map_authority_error)?;

        let read = HolderReadJti {
            jti: request.jti.as_str().to_owned(),
            session_handle: request.session.as_str().to_owned(),
            invocation_digest: request.request_body_digest.as_str().to_owned(),
            binding_json: serde_json::to_value(&request.scope).map_err(|_| PortError::Storage)?,
            issued_at: now,
            expires_at: now + READ_JTI_TTL,
        };

        ProtocolStateRepository::consume_holder_read_jti_in_transaction(&tx, read, now)
            .await
            .map_err(map_state_error)?;

        tx.commit().await.map_err(|_| PortError::Storage)?;

        let session = PolicySession {
            handle: request.session.clone(),
            scope: scope.clone(),
            holder: request.holder.clone(),
            credential_digest: binding.credential_digest,
            sql_statement,
        };
        let invocation = ReadInvocation {
            session: request.session,
            jti: request.jti,
            scope,
            holder: request.holder,
            request_body_digest: request.request_body_digest,
        };
        Ok(AuthorizedRead::from_parts(session, invocation))
    }
}

impl DatabaseAuthorityBridge117 {
    pub async fn policy_recipient_and_expiry(
        &self,
        policy_cid: &str,
        delegation_cid: &str,
        handle: &super::types::AuthorityMaterialHandle,
        material_digest: &Sha256Digest,
        now: OffsetDateTime,
    ) -> Result<(String, OffsetDateTime), PortError> {
        let policy = super::types::PolicyCid::parse(policy_cid).map_err(|_| PortError::Denied)?;
        let delegation = super::types::ShareDelegationCid::parse(delegation_cid)
            .map_err(|_| PortError::Denied)?;
        let provider = self
            .authority_material
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let bundle = provider
            .resolve_exact(&policy, &delegation, handle, material_digest)
            .await?;
        let signed_policy = AuthorityArtifactVerifier
            .verify(&bundle.policy_authority)
            .map_err(map_authority_error)?;
        if signed_policy.artifact().delegation_cid != bundle.internal_policy_authority_cid.as_str()
        {
            return Err(PortError::Denied);
        }
        let tx = self.conn.begin().await.map_err(|_| PortError::Storage)?;
        let result = self
            .authority
            .artifact_in_transaction(&tx, bundle.internal_policy_authority_cid.as_str())
            .await
            .map_err(map_authority_error)
            .and_then(|artifact| {
                let (recipient, expiry) = policy_metadata(&artifact, Some(&bundle.policy_state))
                    .map_err(|_| PortError::Denied)?;
                if now < expiry {
                    Ok((recipient, expiry))
                } else {
                    Err(PortError::Denied)
                }
            });
        tx.rollback().await.map_err(|_| PortError::Storage)?;
        result
    }

    pub async fn validate_scope(
        &self,
        scope: &ShareScope,
        now: OffsetDateTime,
    ) -> Result<(), PortError> {
        let tx = self.conn.begin().await.map_err(|_| PortError::Storage)?;
        let result = self.validate_scope_in_transaction(&tx, scope, now).await;
        match result {
            Ok(_) => {
                tx.commit().await.map_err(|_| PortError::Storage)?;
                Ok(())
            }
            Err(error) => {
                tx.rollback().await.map_err(|_| PortError::Storage)?;
                Err(error)
            }
        }
    }

    /// The sender proof is only useful when it names the authority owner that
    /// issued the live policy.  Keep this check in the #117-backed bridge so
    /// the HTTP layer cannot turn a valid did:key signature into a sender
    /// authorization for somebody else's share.
    pub async fn validate_sender_for_policy(
        &self,
        policy_cid: &str,
        delegation_cid: &str,
        handle: &super::types::AuthorityMaterialHandle,
        material_digest: &Sha256Digest,
        sender_did: &str,
    ) -> Result<(), PortError> {
        let policy = super::types::PolicyCid::parse(policy_cid).map_err(|_| PortError::Denied)?;
        let delegation = super::types::ShareDelegationCid::parse(delegation_cid)
            .map_err(|_| PortError::Denied)?;
        let provider = self
            .authority_material
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let bundle = provider
            .resolve_exact(&policy, &delegation, handle, material_digest)
            .await?;
        let signed_policy = AuthorityArtifactVerifier
            .verify(&bundle.policy_authority)
            .map_err(map_authority_error)?;
        if signed_policy.artifact().delegation_cid != bundle.internal_policy_authority_cid.as_str()
        {
            return Err(PortError::Denied);
        }
        let owner = signed_policy
            .artifact()
            .facts
            .iter()
            .find(|(key, _)| key.ends_with("/ownerDid") || key.as_str() == "ownerDid")
            .map(|(_, value)| value.as_str())
            .unwrap_or(signed_policy.artifact().issuer_did.as_str());
        if owner == sender_did || signed_policy.artifact().issuer_did == sender_did {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }

    async fn validate_scope_in_transaction(
        &self,
        tx: &sea_orm::DatabaseTransaction,
        scope: &ShareScope,
        now: OffsetDateTime,
    ) -> Result<
        (
            OffsetDateTime,
            String,
            Option<super::data_plane::PinnedNamedStatement>,
            NodeDelegationCid,
        ),
        PortError,
    > {
        let share_delegation_cid = scope.delegation_cid.as_ref().ok_or(PortError::Denied)?;
        let material_provider = self
            .authority_material
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let status_provider = self
            .status_provider
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let attestation_provider = self
            .attestation_provider
            .as_ref()
            .filter(|provider| provider.healthy())
            .ok_or(PortError::Unavailable)?;
        let bundle = material_provider
            .resolve_exact(
                &scope.policy_cid,
                share_delegation_cid,
                &scope.authority_material_handle,
                &scope.authority_material_digest,
            )
            .await?;
        validate_share_policy_state(&bundle.policy_state, scope)?;
        let verifier = AuthorityArtifactVerifier;
        let signed_policy = verifier
            .verify(&bundle.policy_authority)
            .map_err(map_authority_error)?;
        let signed_enforcement = verifier
            .verify(&bundle.policy_enforcement)
            .map_err(map_authority_error)?;
        if signed_policy.artifact().delegation_cid != bundle.internal_policy_authority_cid.as_str()
            || signed_enforcement.artifact().delegation_cid
                != bundle.internal_policy_enforcement_cid.as_str()
        {
            return Err(PortError::Denied);
        }
        let enforcer = DidKey::parse(
            signed_enforcement
                .artifact()
                .fact_value("enforcerDid")
                .map_err(|_| PortError::Denied)?,
        )
        .map_err(|_| PortError::Denied)?;
        let status_bytes = status_provider
            .refresh(&bundle.internal_policy_authority_cid)
            .await?;
        let status = parse_status(&status_bytes, &bundle.internal_policy_authority_cid, now)?;
        self.authority
            .admit_verified_authority_in_transaction(tx, signed_policy.clone(), &status, now)
            .await
            .map_err(map_authority_error)?;
        let enforcement_status_bytes = status_provider
            .refresh(&bundle.internal_policy_enforcement_cid)
            .await?;
        let enforcement_status = parse_status(
            &enforcement_status_bytes,
            &bundle.internal_policy_enforcement_cid,
            now,
        )?;
        self.authority
            .admit_verified_authority_in_transaction(
                tx,
                signed_enforcement.clone(),
                &enforcement_status,
                now,
            )
            .await
            .map_err(map_authority_error)?;
        let attestation = attestation_provider
            .attest(&scope.node_audience, &enforcer)
            .await?;
        validate_attestation(
            &attestation,
            &scope.target_origin,
            &scope.node_audience,
            &enforcer,
            signed_enforcement
                .artifact()
                .fact_value("attestationBindingDigestHex")
                .map_err(|_| PortError::Denied)?,
            &signed_enforcement.artifact().expires_at,
            now,
        )?;
        let policy_cid = bundle.internal_policy_authority_cid;
        let delegation_cid = bundle.internal_delegation_cid.clone();
        self.authority
            .validate_for_invocation_in_transaction(tx, policy_cid.as_str(), now)
            .await
            .map_err(map_authority_error)?;
        self.authority
            .validate_for_invocation_in_transaction(tx, delegation_cid.as_str(), now)
            .await
            .map_err(map_authority_error)?;
        let policy = self
            .authority
            .artifact_in_transaction(tx, policy_cid.as_str())
            .await
            .map_err(map_authority_error)?;
        let delegation = self
            .authority
            .artifact_in_transaction(tx, delegation_cid.as_str())
            .await
            .map_err(map_authority_error)?;
        if delegation_cid.as_str() != policy_cid.as_str()
            && !delegation
                .proof_cids
                .iter()
                .any(|cid| cid == policy_cid.as_str())
            && delegation
                .facts
                .get("policyDelegationCid")
                .map(String::as_str)
                != Some(policy_cid.as_str())
        {
            return Err(PortError::Denied);
        }
        let (recipient, expiry) =
            policy_metadata(&policy, Some(&bundle.policy_state)).map_err(|_| PortError::Denied)?;
        let statement = authorized_statement(scope, &policy, &delegation)?;
        Ok((expiry, recipient, statement, bundle.internal_delegation_cid))
    }
}

fn scope_digest(scope: &ShareScope) -> Sha256Digest {
    let bytes = crate::policy_capability::jcs::canonicalize(
        &serde_json::to_value(scope).expect("validated share scope serializes"),
    );
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn digest_string(value: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value.as_bytes()).into())
}

fn policy_metadata(
    artifact: &crate::policy_authority::PolicyDelegation,
    share_policy: Option<&[u8]>,
) -> Result<(String, OffsetDateTime), ()> {
    fn find_email(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::Object(object) => object
                .get("recipientEmail")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .or_else(|| object.values().find_map(find_email)),
            serde_json::Value::Array(values) => values.iter().find_map(find_email),
            _ => None,
        }
    }
    let recipient = share_policy
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
        .and_then(|value| find_email(&value))
        .or_else(|| {
            artifact
                .facts
                .iter()
                .find(|(key, _)| {
                    key.ends_with("/recipientEmail") || key.as_str() == "recipientEmail"
                })
                .map(|(_, value)| value.clone())
                .or_else(|| artifact.capabilities.iter().find_map(find_email))
        })
        .ok_or(())?;
    let recipient =
        tinycloud_auth::share_email_evidence::normalize_email(&recipient).map_err(|_| ())?;
    let expiry = OffsetDateTime::parse(
        &artifact.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| ())?;
    let share_expiry = share_policy
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
        .and_then(|value| {
            value
                .get("expiresAt")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|value| {
            OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339).ok()
        });
    Ok((
        recipient,
        share_expiry.map_or(expiry, |value| value.min(expiry)),
    ))
}

fn validate_share_policy_state(bytes: &[u8], scope: &ShareScope) -> Result<(), PortError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| PortError::Denied)?;
    let source = serde_json::to_value(&scope.content_source).map_err(|_| PortError::Denied)?;
    let action = match scope.action {
        super::types::ShareAction::KvGet => super::types::KV_GET_ACTION,
        super::types::ShareAction::SqlRead => super::types::SQL_READ_ACTION,
    };
    let resource = match &scope.resource {
        super::types::ExactResource::Kv { path }
        | super::types::ExactResource::Sql { path, .. } => path.as_str(),
    };
    if value.get("type").and_then(serde_json::Value::as_str) != Some("TinyCloudSharePolicy")
        || value.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || value.get("contentSource") != Some(&source)
        || value
            .get("contentSourceDigest")
            .and_then(serde_json::Value::as_str)
            != Some(scope.content_source_digest.as_str())
        || value.get("action").and_then(serde_json::Value::as_str) != Some(action)
        || value.get("resource").and_then(serde_json::Value::as_str) != Some(resource)
    {
        return Err(PortError::Denied);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthorityStatusWire {
    #[serde(rename = "type")]
    kind: String,
    version: u8,
    authority_cid: String,
    sequence: u64,
    state: String,
    issued_at: String,
    fresh_until: String,
    revoked_at: Option<String>,
}

fn parse_status(
    bytes: &[u8],
    expected_cid: &NodeDelegationCid,
    now: OffsetDateTime,
) -> Result<AuthorityStatusObservation, PortError> {
    let status: AuthorityStatusWire =
        serde_json::from_slice(bytes).map_err(|_| PortError::Denied)?;
    if status.kind != "PolicyAuthorityStatus"
        || status.version != 1
        || status.authority_cid != expected_cid.as_str()
        || !matches!(status.state.as_str(), "active" | "revoked")
    {
        return Err(PortError::Denied);
    }
    let checked_at = OffsetDateTime::parse(
        &status.issued_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| PortError::Denied)?;
    let fresh_until = OffsetDateTime::parse(
        &status.fresh_until,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| PortError::Denied)?;
    let revoked_at = status
        .revoked_at
        .as_deref()
        .map(|value| OffsetDateTime::parse(value, &Rfc3339))
        .transpose()
        .map_err(|_| PortError::Denied)?;
    if (status.state == "revoked") != revoked_at.is_some()
        || checked_at > now
        || fresh_until <= now
        || revoked_at.is_some_and(|value| value < checked_at || value > now)
    {
        return Err(PortError::Denied);
    }
    Ok(AuthorityStatusObservation {
        checked_at,
        sequence: status.sequence,
        revoked_at,
        fresh_until,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AttestationWire {
    #[serde(rename = "type")]
    kind: String,
    version: u8,
    origin: String,
    audience: String,
    enforcer_kid: String,
    key_version: u64,
    measurement: String,
    digest: String,
    issued_at: String,
    expires_at: String,
    enrollment_digest: String,
}

fn validate_attestation(
    bytes: &[u8],
    origin: &TargetOrigin,
    audience: &Did,
    enforcer: &DidKey,
    expected_binding_digest_hex: &str,
    enforcement_expires_at: &str,
    now: OffsetDateTime,
) -> Result<(), PortError> {
    let attestation: AttestationWire =
        serde_json::from_slice(bytes).map_err(|_| PortError::Denied)?;
    let issued_at = OffsetDateTime::parse(
        &attestation.issued_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| PortError::Denied)?;
    let expires_at = OffsetDateTime::parse(
        &attestation.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| PortError::Denied)?;
    let enforcement_expires_at = OffsetDateTime::parse(
        enforcement_expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| PortError::Denied)?;
    let canonical = jcs::canonicalize(
        &serde_json::from_slice::<serde_json::Value>(bytes).map_err(|_| PortError::Denied)?,
    );
    let actual_binding_digest = hex::encode(Sha256::digest(canonical));
    if attestation.kind != "PolicyEnforcerAttestation"
        || attestation.version != 1
        || attestation.origin != origin.as_str()
        || attestation.audience != audience.as_str()
        || !attestation.enforcer_kid.starts_with(enforcer.as_str())
        || attestation.key_version == 0
        || attestation.measurement.is_empty()
        || attestation.digest.is_empty()
        || attestation.enrollment_digest.is_empty()
        || actual_binding_digest != expected_binding_digest_hex
        || issued_at > now
        || expires_at <= now
        || expires_at > enforcement_expires_at
        || expires_at <= issued_at
        || expires_at - issued_at > time::Duration::seconds(300)
    {
        return Err(PortError::Denied);
    }
    Ok(())
}

fn authorized_statement(
    scope: &ShareScope,
    policy: &crate::policy_authority::PolicyDelegation,
    delegation: &crate::policy_authority::PolicyDelegation,
) -> Result<Option<super::data_plane::PinnedNamedStatement>, PortError> {
    let request = requested_capability(scope)?;
    let grants = policy
        .capabilities
        .iter()
        .map(parse_capability)
        .chain(delegation.capabilities.iter().map(parse_capability))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PortError::Denied)?;
    let policy_count = policy.capabilities.len();
    let mut policy_matched = false;
    let mut delegation_matched = false;
    let mut statement = None;
    for (index, grant) in grants.iter().enumerate() {
        let request_for_grant = if matches!(scope.action, super::types::ShareAction::SqlRead) {
            let statement = statement_from_grant(grant, scope)?.ok_or(PortError::Denied)?;
            let mut request = request.clone();
            request.caveats = Some(serde_json::json!({
                "mode":"constrained-statements",
                "readOnly":true,
                "statements":[statement.statement]
            }));
            request
        } else {
            request.clone()
        };
        if grant.contains(&request_for_grant).is_ok() {
            if index < policy_count {
                policy_matched = true;
            } else {
                delegation_matched = true;
            }
            if statement.is_none() {
                statement = statement_from_grant(grant, scope)?;
            }
        }
    }
    if policy_matched && delegation_matched {
        Ok(statement)
    } else {
        Err(PortError::Denied)
    }
}

fn requested_capability(scope: &ShareScope) -> Result<PolicyCapability, PortError> {
    let (service, path, action, caveats) = match &scope.content_source {
        super::types::ContentSource::Kv { path, .. } => (
            "tinycloud.kv".to_owned(),
            path.as_str().to_owned(),
            super::types::KV_GET_ACTION.to_owned(),
            None,
        ),
        super::types::ContentSource::Sql { path, .. } => (
            "tinycloud.sql".to_owned(),
            path.as_str().to_owned(),
            super::types::SQL_READ_ACTION.to_owned(),
            None,
        ),
    };
    let mut value = serde_json::json!({
        "service": service,
        "space": match &scope.content_source {
            super::types::ContentSource::Kv { space, .. } | super::types::ContentSource::Sql { space, .. } => space.as_str(),
        },
        "path": path,
        "actions": [action]
    });
    if let Some(caveats) = caveats {
        value["caveats"] = caveats;
    }
    parse_capability(&value).map_err(|_| PortError::Denied)
}

fn statement_from_grant(
    grant: &PolicyCapability,
    scope: &ShareScope,
) -> Result<Option<super::data_plane::PinnedNamedStatement>, PortError> {
    let super::types::ContentSource::Sql {
        database,
        path,
        statement,
        arguments,
        ..
    } = &scope.content_source
    else {
        return Ok(None);
    };
    let caveat = grant
        .caveats
        .as_ref()
        .and_then(|value| crate::policy_capability::sql_caveat::parse(value).ok())
        .ok_or(PortError::Denied)?;
    let constrained = caveat
        .statements
        .iter()
        .find(|candidate| candidate.name == statement.as_str())
        .ok_or(PortError::Denied)?;
    if constrained.fixed_params.len() != arguments.len()
        || constrained.fixed_params.iter().any(|fixed| {
            fixed.index < 0
                || arguments
                    .values()
                    .nth(fixed.index as usize)
                    .map(|value| fixed.value != value.get())
                    .unwrap_or(true)
        })
    {
        return Err(PortError::Denied);
    }
    Ok(Some(super::data_plane::PinnedNamedStatement {
        database: database.clone(),
        path: path.clone(),
        statement: constrained.clone(),
    }))
}

fn map_authority_error(error: AuthorityError) -> PortError {
    match error {
        AuthorityError::AuthorityStateUnavailable | AuthorityError::TransactionFailed => {
            PortError::Storage
        }
        _ => PortError::Denied,
    }
}

fn map_state_error(error: StateError) -> PortError {
    match error {
        StateError::Storage => PortError::Storage,
        StateError::Replay => PortError::Replay,
        StateError::BodyTooLarge
        | StateError::QuotaExceeded
        | StateError::Invalid
        | StateError::Expired => PortError::Denied,
    }
}

fn holder_digest(holder: &DidKey) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(holder.as_str().as_bytes()))
}

fn next_issuance_id() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut output = String::from("peiss_");
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 && output.len() < 32 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    while output.len() < 32 {
        output.push('a');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::super::types::*;
    use super::*;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use serde_json::json;

    fn scope(policy_cid: &str) -> ShareScope {
        ShareScope {
            share_cid: ShareCid::parse(super::super::types::KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-1").unwrap(),
            delegation_cid: Some(
                super::super::types::ShareDelegationCid::parse(policy_cid).unwrap(),
            ),
            authority_material_handle: AuthorityMaterialHandle::parse("amh_kv_001").unwrap(),
            authority_material_digest: Sha256Digest::from_bytes([0; 32]),
            policy_cid: PolicyCid::parse(policy_cid).unwrap(),
            node_audience: Did::parse("did:web:node.example").unwrap(),
            target_origin: TargetOrigin::parse("https://node.example").unwrap(),
            action: ShareAction::KvGet,
            resource: ExactResource::Kv {
                path: Path::parse("documents/plan.md").unwrap(),
            },
            content_source: ContentSource::Kv {
                action: KvGetAction::Get,
                space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                    .unwrap(),
                path: Path::parse("documents/plan.md").unwrap(),
            },
            content_source_digest: Sha256Digest::from_bytes([0; 32]),
        }
    }

    fn holder() -> DidKey {
        DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw").unwrap()
    }

    async fn bridge_with_root(root_cid: &str, now: OffsetDateTime) -> DatabaseAuthorityBridge117 {
        let _ = (root_cid, now);
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let authority = DatabaseAuthorityStore::new(db.clone());
        DatabaseAuthorityBridge117::new(db, authority)
    }

    #[tokio::test]
    async fn establish_session_stays_fail_closed_without_authority_providers() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let root_cid = super::super::types::KV_POLICY_CID;
        let bridge = bridge_with_root(root_cid, now).await;

        let request = PolicySessionRequest {
            scope: scope(root_cid),
            holder: holder(),
            credential_digest: Sha256Digest::from_bytes([9; 32]),
            nonce: ProtocolNonce::from_bytes([1; 32]),
            presentation_jti: ProtocolJti::from_bytes([2; 16]),
            challenge_id: String::new(),
            challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
            challenge_binding: json!(null),
            policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
            credential_expires_at: 0,
        };
        assert_eq!(
            bridge.establish_session(request, now).await,
            Err(PortError::Unavailable)
        );
    }

    #[tokio::test]
    async fn authorize_read_cannot_use_fabricated_rows() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let root_cid = super::super::types::KV_POLICY_CID;
        let bridge = bridge_with_root(root_cid, now).await;
        assert_eq!(
            bridge
                .establish_session(
                    PolicySessionRequest {
                        scope: scope(root_cid),
                        holder: holder(),
                        credential_digest: Sha256Digest::from_bytes([9; 32]),
                        nonce: ProtocolNonce::from_bytes([5; 32]),
                        presentation_jti: ProtocolJti::from_bytes([6; 16]),
                        challenge_id: String::new(),
                        challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
                        challenge_binding: json!(null),
                        policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
                        credential_expires_at: 0,
                    },
                    now,
                )
                .await,
            Err(PortError::Unavailable)
        );
    }

    #[tokio::test]
    async fn revoking_a_fabricated_session_root_never_authorizes() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let root_cid = super::super::types::KV_POLICY_CID;
        let bridge = bridge_with_root(root_cid, now).await;
        assert_eq!(
            bridge
                .establish_session(
                    PolicySessionRequest {
                        scope: scope(root_cid),
                        holder: holder(),
                        credential_digest: Sha256Digest::from_bytes([9; 32]),
                        nonce: ProtocolNonce::from_bytes([14; 32]),
                        presentation_jti: ProtocolJti::from_bytes([15; 16]),
                        challenge_id: String::new(),
                        challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
                        challenge_binding: json!(null),
                        policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
                        credential_expires_at: 0,
                    },
                    now,
                )
                .await,
            Err(PortError::Unavailable)
        );
    }

    #[tokio::test]
    async fn establish_session_denies_unknown_policy_cid() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let authority = DatabaseAuthorityStore::new(db.clone());
        let bridge = DatabaseAuthorityBridge117::new(db, authority);
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();

        let result = bridge
            .establish_session(
                PolicySessionRequest {
                    scope: scope("bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4"),
                    holder: holder(),
                    credential_digest: Sha256Digest::from_bytes([9; 32]),
                    nonce: ProtocolNonce::from_bytes([16; 32]),
                    presentation_jti: ProtocolJti::from_bytes([17; 16]),
                    challenge_id: String::new(),
                    challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
                    challenge_binding: json!(null),
                    policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
                    credential_expires_at: 0,
                },
                now,
            )
            .await;
        assert!(matches!(result, Err(PortError::Unavailable)));
    }
}
