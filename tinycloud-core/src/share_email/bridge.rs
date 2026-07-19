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
use time::OffsetDateTime;

use crate::{
    models::{share_policy_presentation_jti, share_session_handle},
    policy_authority::{AuthorityError, DatabaseAuthorityStore},
};

use super::{
    ports::{PolicyAuthorityTransaction117, PortError},
    state::{
        parse_timestamp, timestamp, AuditEvent, HolderReadJti, ProtocolStateRepository,
        SessionHandleMapping, StateError, READ_JTI_TTL, SESSION_TTL,
    },
    types::{
        AuthorizedRead, DidKey, PolicySession, PolicySessionRequest, ReadAuthorizationRequest,
        ReadInvocation, SessionHandle, Sha256Digest, ShareScope,
    },
};

/// The only #117 composition point exact-email code may hold. It shares one
/// database connection with [`DatabaseAuthorityStore`] so both stores'
/// effects are transactionally atomic per call.
#[derive(Clone)]
pub struct DatabaseAuthorityBridge117 {
    conn: DatabaseConnection,
    authority: DatabaseAuthorityStore,
}

impl DatabaseAuthorityBridge117 {
    /// `conn` and `authority` must share the same underlying database so a
    /// transaction begun on `conn` is visible to `authority`'s row locks.
    pub fn new(conn: DatabaseConnection, authority: DatabaseAuthorityStore) -> Self {
        Self { conn, authority }
    }
}

/// The durable content bound to an opaque session handle. Stored verbatim so
/// every later read can be revalidated against the exact scope and
/// credential digest the session was established for, never against
/// whatever a caller currently claims.
#[derive(Serialize, Deserialize)]
struct SessionBinding {
    scope: ShareScope,
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

        self.authority
            .validate_for_invocation_in_transaction(&tx, request.scope.policy_cid.as_str(), now)
            .await
            .map_err(map_authority_error)?;

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
        let expires_at = now + SESSION_TTL;

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
            scope: request.scope.clone(),
            credential_digest: request.credential_digest.clone(),
        };
        let binding_json = serde_json::to_value(&binding).map_err(|_| PortError::Storage)?;
        let mapping = SessionHandleMapping {
            handle: handle.as_str().to_owned(),
            authority_session_cid: request.scope.policy_cid.as_str().to_owned(),
            binding_json,
            holder_digest: holder_digest(&request.holder),
            issued_at: now,
            expires_at,
        };
        let audit = AuditEvent {
            audit_id: format!("share-email-session-{}", handle.as_str()),
            event_kind: "share_email.session_established".to_owned(),
            outcome: "accepted".to_owned(),
            share_digest: request.scope.share_cid.as_str().to_owned(),
            origin_digest: request.scope.target_origin.as_str().to_owned(),
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
        if binding.scope != request.scope {
            return Err(PortError::Denied);
        }

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
            scope: request.scope.clone(),
            holder: request.holder.clone(),
            credential_digest: binding.credential_digest,
        };
        let invocation = ReadInvocation {
            session: request.session,
            jti: request.jti,
            scope: request.scope,
            holder: request.holder,
            request_body_digest: request.request_body_digest,
        };
        Ok(AuthorizedRead::from_parts(session, invocation))
    }
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
    use crate::{
        models::{policy_delegation, policy_edge},
        policy_authority::{DelegationMode, DelegationRole, DelegationSignature, PolicyDelegation},
    };
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use serde_json::json;
    use time::format_description::well_known::Rfc3339;

    /// Directly seeds a syntactically valid, live `PolicySessionRoot` chain
    /// (two `PolicyAuthority` parents plus the session root and its two
    /// `Authority` edges) without going through #117's own issuance
    /// machinery, mirroring how `policy_authority`'s own tests seed rows for
    /// [`crate::policy_authority::DatabaseAuthorityStore`]. Only wire-shape
    /// and liveness matter for [`super::DatabaseAuthorityBridge117`]; deeper
    /// capability-ceiling semantics belong to #117's issuance path, not this
    /// bridge.
    async fn seed_session_root(
        db: &sea_orm::DatabaseConnection,
        root_cid: &str,
        now: OffsetDateTime,
    ) {
        let rfc3339 = |value: OffsetDateTime| value.format(&Rfc3339).unwrap();
        let not_before = rfc3339(now - time::Duration::days(1));
        let expires_at = rfc3339(now + time::Duration::days(1));
        let capability = json!({
            "actions": ["tinycloud.kv/get"],
            "path": "profile",
            "service": "tinycloud.kv",
            "space": "did:key:z6MkSpace",
        });

        let parent_cids = ["bridge-test-parent-0", "bridge-test-parent-1"];
        for parent_cid in parent_cids {
            let facts = [
                (
                    "ownerDid",
                    "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
                ),
                ("policyId", "pol_test"),
                ("policyDigestHex", &"1".repeat(64)),
                ("capabilityCeilingHashHex", &"2".repeat(64)),
            ]
            .into_iter()
            .map(|(key, value)| (format!("xyz.tinycloud.policy/{key}"), value.to_owned()))
            .collect();
            let artifact = PolicyDelegation {
                schema: "xyz.tinycloud.policy/enforcement-delegation/v1".to_owned(),
                role: DelegationRole::PolicyAuthority,
                delegation_cid: parent_cid.to_owned(),
                issuer_did: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
                    .to_owned(),
                audience_did: "did:tinycloud:policy:test".to_owned(),
                capabilities: vec![capability.clone()],
                proof_cids: vec![],
                not_before: not_before.clone(),
                expires_at: expires_at.clone(),
                delegation_mode: DelegationMode::PolicySource,
                facts,
                signature: DelegationSignature {
                    suite: "eip191-secp256k1-sha256-jcs-v1".to_owned(),
                    value: "test".to_owned(),
                },
            };
            insert_delegation(db, &artifact, &not_before, &expires_at, now).await;
        }

        let session_facts = [
            (
                "ownerDid",
                "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
            ),
            ("policyId", "pol_test"),
            ("policyDigestHex", &"1".repeat(64)),
            ("capabilityCeilingHashHex", &"2".repeat(64)),
            ("capabilityHashHex", &"3".repeat(64)),
            ("enforcerDid", "did:web:node.example"),
            ("nodeAudience", "did:web:node.example"),
            (
                "rootClaimantDid",
                "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            ),
            (
                "sessionSubjectDid",
                "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            ),
            ("policyDelegationCid", parent_cids[0]),
            ("enforcementDelegationCid", parent_cids[1]),
            ("attestationBindingDigestHex", &"4".repeat(64)),
            ("claimInvocationDigestHex", &"5".repeat(64)),
            ("vpDigestHex", &"6".repeat(64)),
            ("decisionContextDigestHex", &"7".repeat(64)),
            ("issuanceAuditDigestHex", &"8".repeat(64)),
            ("issuanceId", "issuance-test"),
            ("remainingRedelegationDepth", "2"),
            ("auditProfile", "vp-digest-v1"),
        ]
        .into_iter()
        .map(|(key, value)| (format!("xyz.tinycloud.policy/{key}"), value.to_owned()))
        .collect();
        let root = PolicyDelegation {
            schema: "xyz.tinycloud.policy/enforcement-delegation/v1".to_owned(),
            role: DelegationRole::PolicySessionRoot,
            delegation_cid: root_cid.to_owned(),
            issuer_did: "did:web:node.example".to_owned(),
            audience_did: "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw".to_owned(),
            capabilities: vec![capability],
            proof_cids: parent_cids.iter().map(|cid| cid.to_string()).collect(),
            not_before: not_before.clone(),
            expires_at: expires_at.clone(),
            delegation_mode: DelegationMode::Attenuable,
            facts: session_facts,
            signature: DelegationSignature {
                suite: "eddsa-ed25519-sha256-jcs-v1".to_owned(),
                value: "test".to_owned(),
            },
        };
        insert_delegation(db, &root, &not_before, &expires_at, now).await;

        for (position, parent_cid) in parent_cids.iter().enumerate() {
            policy_edge::ActiveModel {
                child_cid: Set(root_cid.to_owned()),
                position: Set(position as i32),
                parent_cid: Set((*parent_cid).to_owned()),
                edge_kind: Set("authority".to_owned()),
            }
            .insert(db)
            .await
            .unwrap();
        }
    }

    async fn insert_delegation(
        db: &sea_orm::DatabaseConnection,
        artifact: &PolicyDelegation,
        not_before: &str,
        expires_at: &str,
        checked_at: OffsetDateTime,
    ) {
        let role = serde_json::to_value(artifact.role)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let mode = serde_json::to_value(artifact.delegation_mode)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        policy_delegation::ActiveModel {
            delegation_cid: Set(artifact.delegation_cid.clone()),
            role: Set(role),
            delegation_mode: Set(mode),
            artifact_json: Set(serde_json::to_value(artifact).unwrap()),
            not_before: Set(not_before.to_owned()),
            expires_at: Set(expires_at.to_owned()),
            status_checked_at: Set(checked_at.format(&Rfc3339).unwrap()),
            status_sequence: Set(1),
            revoked_at: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn revoke(db: &sea_orm::DatabaseConnection, cid: &str, revoked_at: OffsetDateTime) {
        use sea_orm::{ActiveModelTrait, EntityTrait};
        let mut model: policy_delegation::ActiveModel = policy_delegation::Entity::find_by_id(cid)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .into();
        model.revoked_at = Set(Some(revoked_at.format(&Rfc3339).unwrap()));
        model.status_sequence = Set(2);
        model.update(db).await.unwrap();
    }

    fn scope(policy_cid: &str) -> ShareScope {
        ShareScope {
            share_cid: ShareCid::parse(super::super::types::KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-1").unwrap(),
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
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        seed_session_root(&db, root_cid, now).await;
        let authority = DatabaseAuthorityStore::new(db.clone());
        DatabaseAuthorityBridge117::new(db, authority)
    }

    #[tokio::test]
    async fn establish_session_and_authorize_read_are_atomic_and_replay_safe() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let root_cid = super::super::types::KV_POLICY_CID;
        let bridge = bridge_with_root(root_cid, now).await;

        let request = PolicySessionRequest {
            scope: scope(root_cid),
            holder: holder(),
            credential_digest: Sha256Digest::from_bytes([9; 32]),
            nonce: ProtocolNonce::from_bytes([1; 32]),
            presentation_jti: ProtocolJti::from_bytes([2; 16]),
        };
        let session = bridge
            .establish_session(request.clone(), now)
            .await
            .expect("live session root establishes a session");

        // Replaying the same nonce/presentation JTI must fail even with a
        // fresh session handle attempt; the JTI table alone stops it.
        let replay = PolicySessionRequest {
            presentation_jti: ProtocolJti::from_bytes([2; 16]),
            ..request
        };
        assert_eq!(
            bridge.establish_session(replay, now).await,
            Err(PortError::Replay)
        );

        let read_request = ReadAuthorizationRequest {
            session: session.handle.clone(),
            jti: ProtocolJti::from_bytes([3; 16]),
            scope: scope(root_cid),
            holder: holder(),
            request_body_digest: Sha256Digest::from_bytes([4; 32]),
        };
        bridge
            .authorize_read(read_request.clone(), now)
            .await
            .expect("live session authorizes a read");

        // The read JTI is one-use even for an otherwise identical request.
        assert_eq!(
            bridge.authorize_read(read_request, now).await,
            Err(PortError::Replay)
        );
    }

    #[tokio::test]
    async fn authorize_read_denies_wrong_holder() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let root_cid = super::super::types::KV_POLICY_CID;
        let bridge = bridge_with_root(root_cid, now).await;
        let session = bridge
            .establish_session(
                PolicySessionRequest {
                    scope: scope(root_cid),
                    holder: holder(),
                    credential_digest: Sha256Digest::from_bytes([9; 32]),
                    nonce: ProtocolNonce::from_bytes([5; 32]),
                    presentation_jti: ProtocolJti::from_bytes([6; 16]),
                },
                now,
            )
            .await
            .unwrap();

        let wrong_holder =
            DidKey::parse("did:key:z6MkvUu5vJctdt2i9RcgFmdELbLK9xB4nQqsbXpxrDJZfgFV").unwrap();
        let request = ReadAuthorizationRequest {
            session: session.handle,
            jti: ProtocolJti::from_bytes([7; 16]),
            scope: scope(root_cid),
            holder: wrong_holder,
            request_body_digest: Sha256Digest::from_bytes([8; 32]),
        };
        assert_eq!(
            bridge.authorize_read(request, now).await,
            Err(PortError::Denied)
        );
    }

    #[tokio::test]
    async fn revoking_a_session_root_ancestor_blocks_new_and_existing_authorization() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let root_cid = super::super::types::KV_POLICY_CID;
        let bridge = bridge_with_root(root_cid, now).await;
        let session = bridge
            .establish_session(
                PolicySessionRequest {
                    scope: scope(root_cid),
                    holder: holder(),
                    credential_digest: Sha256Digest::from_bytes([9; 32]),
                    nonce: ProtocolNonce::from_bytes([10; 32]),
                    presentation_jti: ProtocolJti::from_bytes([11; 16]),
                },
                now,
            )
            .await
            .unwrap();

        revoke(&bridge.conn, "bridge-test-parent-0", now).await;

        let request = ReadAuthorizationRequest {
            session: session.handle,
            jti: ProtocolJti::from_bytes([12; 16]),
            scope: scope(root_cid),
            holder: holder(),
            request_body_digest: Sha256Digest::from_bytes([13; 32]),
        };
        assert_eq!(
            bridge.authorize_read(request, now).await,
            Err(PortError::Denied)
        );

        // A brand-new session over the same now-revoked ancestor chain must
        // also fail; the session handle is never authority by itself.
        assert_eq!(
            bridge
                .establish_session(
                    PolicySessionRequest {
                        scope: scope(root_cid),
                        holder: holder(),
                        credential_digest: Sha256Digest::from_bytes([9; 32]),
                        nonce: ProtocolNonce::from_bytes([14; 32]),
                        presentation_jti: ProtocolJti::from_bytes([15; 16]),
                    },
                    now,
                )
                .await,
            Err(PortError::Denied)
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
                },
                now,
            )
            .await;
        assert!(matches!(
            result,
            Err(PortError::Denied) | Err(PortError::Storage)
        ));
    }
}
