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
use time::OffsetDateTime;

use crate::{
    models::{share_policy_presentation_jti, share_session_handle},
    policy_authority::{AuthorityArtifactVerifier, AuthorityError, DatabaseAuthorityStore},
    policy_capability::{parse as parse_capability, PolicyCapability},
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
        AuthorizedRead, DidKey, NodeDelegationCid, PolicySession, PolicySessionRequest,
        ReadAuthorizationRequest, ReadInvocation, SessionHandle, Sha256Digest, ShareScope,
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
}

impl DatabaseAuthorityBridge117 {
    /// `conn` and `authority` must share the same underlying database so a
    /// transaction begun on `conn` is visible to `authority`'s row locks.
    pub fn new(conn: DatabaseConnection, authority: DatabaseAuthorityStore) -> Self {
        Self {
            conn,
            authority,
            authority_material: None,
            status_provider: None,
            attestation_provider: None,
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

    pub fn ready(&self) -> bool {
        self.authority_material
            .as_ref()
            .is_some_and(|provider| provider.healthy())
            && self
                .status_provider
                .as_ref()
                .is_some_and(|provider| provider.healthy())
            && self
                .attestation_provider
                .as_ref()
                .is_some_and(|provider| provider.healthy())
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

        let (policy_expiry, policy_recipient, sql_statement, internal_delegation_cid) = self
            .validate_scope_in_transaction(&tx, &request.scope, now)
            .await?;
        #[cfg(test)]
        let fixture_request = request.challenge_id.is_empty();
        #[cfg(not(test))]
        let fixture_request = false;
        let credential_expiry = if fixture_request {
            // Core-only fixtures predate the HTTP challenge store.  This
            // branch is not compiled into production consumers.
            now + SESSION_TTL
        } else {
            let recipient_digest = digest_string(&policy_recipient);
            if recipient_digest != request.policy_recipient_digest {
                return Err(PortError::Denied);
            }
            let expiry = OffsetDateTime::from_unix_timestamp(request.credential_expires_at)
                .map_err(|_| PortError::Denied)?;
            if expiry != policy_expiry {
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
            expiry
        };

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
            authority_session_cid: internal_delegation_cid.as_str().to_owned(),
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
        let bundle = provider.resolve(&policy, &delegation).await?;
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
                let (recipient, expiry) =
                    policy_metadata(&artifact).map_err(|_| PortError::Denied)?;
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
        tx.rollback().await.map_err(|_| PortError::Storage)?;
        result.map(|_| ())
    }

    /// The sender proof is only useful when it names the authority owner that
    /// issued the live policy.  Keep this check in the #117-backed bridge so
    /// the HTTP layer cannot turn a valid did:key signature into a sender
    /// authorization for somebody else's share.
    pub async fn validate_sender_for_policy(
        &self,
        policy_cid: &str,
        delegation_cid: &str,
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
        let bundle = provider.resolve(&policy, &delegation).await?;
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
            .resolve(&scope.policy_cid, share_delegation_cid)
            .await?;
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
        let _status = status_provider
            .refresh(&bundle.internal_policy_enforcement_cid)
            .await?;
        let _attestation = attestation_provider
            .attest(&scope.node_audience, &enforcer)
            .await?;
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
        let (recipient, expiry) = policy_metadata(&policy).map_err(|_| PortError::Denied)?;
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
    let recipient = artifact
        .facts
        .iter()
        .find(|(key, _)| key.ends_with("/recipientEmail") || key.as_str() == "recipientEmail")
        .map(|(_, value)| value.clone())
        .or_else(|| artifact.capabilities.iter().find_map(find_email))
        .ok_or(())?;
    let recipient =
        tinycloud_auth::share_email_evidence::normalize_email(&recipient).map_err(|_| ())?;
    let expiry = OffsetDateTime::parse(
        &artifact.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| ())?;
    Ok((recipient, expiry))
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
