//! Fail-closed defaults for uncomposed N1, N2, and N3 boundaries.

use async_trait::async_trait;
use time::OffsetDateTime;

use super::{ports::*, types::*};

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableCredentialVerifier;

#[async_trait]
impl CredentialVerifier for UnavailableCredentialVerifier {
    async fn verify_credential(
        &self,
        _: &[u8],
        _: &ShareScope,
        _: &DidKey,
    ) -> Result<CredentialVerificationEvidence, PortError> {
        Err(PortError::Unavailable)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailablePolicyAuthorityBridge;

#[async_trait]
impl PolicyAuthorityTransaction117 for UnavailablePolicyAuthorityBridge {
    async fn establish_session(
        &self,
        _: PolicySessionRequest,
        _: OffsetDateTime,
    ) -> Result<PolicySession, PortError> {
        Err(PortError::Unavailable)
    }

    async fn authorize_read(
        &self,
        _: ReadAuthorizationRequest,
        _: OffsetDateTime,
    ) -> Result<AuthorizedRead, PortError> {
        Err(PortError::Unavailable)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableKvReadAdapter;

#[async_trait]
impl KvReadAdapter for UnavailableKvReadAdapter {
    async fn read_markdown(&self, _: AuthorizedRead) -> Result<MarkdownDocument, PortError> {
        Err(PortError::Unavailable)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableNamedSqlReadAdapter;

#[async_trait]
impl NamedSqlReadAdapter for UnavailableNamedSqlReadAdapter {
    async fn read_markdown(&self, _: AuthorizedRead) -> Result<MarkdownDocument, PortError> {
        Err(PortError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    fn kv_scope() -> ShareScope {
        ShareScope {
            share_cid: ShareCid::parse(KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-1").unwrap(),
            delegation_cid: None,
            authority_material_handle: AuthorityMaterialHandle::parse("amh_kv_001").unwrap(),
            authority_material_digest: Sha256Digest::from_bytes([0; 32]),
            policy_cid: PolicyCid::parse(KV_POLICY_CID).unwrap(),
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

    fn sql_scope() -> ShareScope {
        let database = DatabaseName::parse("content_db").unwrap();
        let path = Path::parse("documents/plan.md").unwrap();
        let statement = NamedStatement::parse("read_markdown").unwrap();
        ShareScope {
            share_cid: ShareCid::parse(SQL_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-1").unwrap(),
            delegation_cid: None,
            authority_material_handle: AuthorityMaterialHandle::parse("amh_sql_001").unwrap(),
            authority_material_digest: Sha256Digest::from_bytes([0; 32]),
            policy_cid: PolicyCid::parse(SQL_POLICY_CID).unwrap(),
            node_audience: Did::parse("did:web:node.example").unwrap(),
            target_origin: TargetOrigin::parse("https://node.example").unwrap(),
            action: ShareAction::SqlRead,
            resource: ExactResource::Sql {
                database: database.clone(),
                path: path.clone(),
                statement: statement.clone(),
            },
            content_source: ContentSource::Sql {
                action: SqlReadAction::Read,
                space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                    .unwrap(),
                database,
                path,
                statement,
                arguments: BTreeMap::from([(
                    "limit".to_owned(),
                    SafeJsonInteger::parse(1).unwrap(),
                )]),
                arguments_digest: Sha256Digest::from_bytes([0; 32]),
            },
            content_source_digest: Sha256Digest::from_bytes([0; 32]),
        }
    }

    fn authorized_read() -> AuthorizedRead {
        let holder =
            DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw").unwrap();
        let session = PolicySession {
            handle: SessionHandle::from_bytes([0; 16]),
            scope: kv_scope(),
            holder: holder.clone(),
            credential_digest: Sha256Digest::from_bytes([0; 32]),
            sql_statement: None,
        };
        AuthorizedRead::from_parts(
            session.clone(),
            ReadInvocation {
                session: session.handle.clone(),
                jti: ProtocolJti::from_bytes([0; 16]),
                scope: session.scope.clone(),
                holder,
                request_body_digest: Sha256Digest::from_bytes([0; 32]),
            },
        )
    }

    #[tokio::test]
    async fn every_default_is_fail_closed() {
        assert_eq!(
            UnavailableCredentialVerifier
                .verify_credential(
                    b"credential",
                    &kv_scope(),
                    &DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",)
                        .unwrap()
                )
                .await,
            Err(PortError::Unavailable)
        );
        assert_eq!(
            UnavailablePolicyAuthorityBridge
                .establish_session(
                    PolicySessionRequest {
                        scope: kv_scope(),
                        holder: DidKey::parse(
                            "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                        )
                        .unwrap(),
                        credential_digest: Sha256Digest::from_bytes([0; 32]),
                        nonce: ProtocolNonce::from_bytes([0; 32]),
                        presentation_jti: ProtocolJti::from_bytes([1; 16]),
                        challenge_id: String::new(),
                        challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
                        challenge_binding: serde_json::Value::Null,
                        policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
                        credential_expires_at: 0,
                    },
                    OffsetDateTime::UNIX_EPOCH,
                )
                .await,
            Err(PortError::Unavailable)
        );
        assert_eq!(
            UnavailablePolicyAuthorityBridge
                .authorize_read(
                    ReadAuthorizationRequest {
                        session: SessionHandle::from_bytes([0; 16]),
                        jti: ProtocolJti::from_bytes([0; 16]),
                        scope: kv_scope(),
                        holder: DidKey::parse(
                            "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                        )
                        .unwrap(),
                        request_body_digest: Sha256Digest::from_bytes([0; 32]),
                    },
                    OffsetDateTime::UNIX_EPOCH
                )
                .await,
            Err(PortError::Unavailable)
        );
        assert_eq!(
            UnavailableKvReadAdapter
                .read_markdown(authorized_read())
                .await,
            Err(PortError::Unavailable)
        );
        assert_eq!(
            UnavailableNamedSqlReadAdapter
                .read_markdown(authorized_read())
                .await,
            Err(PortError::Unavailable)
        );
    }

    #[derive(Clone, Default)]
    struct AtomicProbe {
        session_calls: Arc<Mutex<Vec<PolicySessionRequest>>>,
        read_calls: Arc<Mutex<Vec<ReadAuthorizationRequest>>>,
    }

    #[async_trait]
    impl PolicyAuthorityTransaction117 for AtomicProbe {
        async fn establish_session(
            &self,
            request: PolicySessionRequest,
            _: OffsetDateTime,
        ) -> Result<PolicySession, PortError> {
            self.session_calls.lock().unwrap().push(request);
            Err(PortError::Denied)
        }

        async fn authorize_read(
            &self,
            request: ReadAuthorizationRequest,
            _: OffsetDateTime,
        ) -> Result<AuthorizedRead, PortError> {
            self.read_calls.lock().unwrap().push(request);
            Err(PortError::Denied)
        }
    }

    #[tokio::test]
    async fn authority_has_separate_atomic_session_and_read_boundaries() {
        let probe = AtomicProbe {
            session_calls: Arc::new(Mutex::new(Vec::new())),
            read_calls: Arc::new(Mutex::new(Vec::new())),
        };
        let holder =
            DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw").unwrap();
        let session_request = PolicySessionRequest {
            scope: kv_scope(),
            holder: holder.clone(),
            credential_digest: Sha256Digest::from_bytes([1; 32]),
            nonce: ProtocolNonce::from_bytes([2; 32]),
            presentation_jti: ProtocolJti::from_bytes([3; 16]),
            challenge_id: String::new(),
            challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
            challenge_binding: serde_json::Value::Null,
            policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
            credential_expires_at: 0,
        };
        assert_eq!(
            probe
                .establish_session(session_request, OffsetDateTime::UNIX_EPOCH)
                .await,
            Err(PortError::Denied)
        );
        {
            let session_calls = probe.session_calls.lock().unwrap();
            assert_eq!(session_calls.len(), 1);
            assert_eq!(session_calls[0].nonce, ProtocolNonce::from_bytes([2; 32]));
            assert_eq!(
                session_calls[0].presentation_jti,
                ProtocolJti::from_bytes([3; 16])
            );
        }
        let read_request = ReadAuthorizationRequest {
            session: SessionHandle::from_bytes([5; 16]),
            jti: ProtocolJti::from_bytes([6; 16]),
            scope: kv_scope(),
            holder,
            request_body_digest: Sha256Digest::from_bytes([4; 32]),
        };
        assert_eq!(
            probe
                .authorize_read(read_request, OffsetDateTime::UNIX_EPOCH)
                .await,
            Err(PortError::Denied)
        );
        let read_calls = probe.read_calls.lock().unwrap();
        assert_eq!(read_calls.len(), 1);
        assert_eq!(read_calls[0].jti, ProtocolJti::from_bytes([6; 16]));
        assert_eq!(read_calls[0].scope.resource, kv_scope().resource);
    }

    #[test]
    fn fake_scopes_use_the_pinned_source_specific_manifest_pairs() {
        let kv = kv_scope();
        assert_eq!(kv.share_cid.as_str(), KV_SHARE_CID);
        assert_eq!(kv.policy_cid.as_str(), KV_POLICY_CID);
        assert!(matches!(kv.content_source, ContentSource::Kv { .. }));

        let sql = sql_scope();
        assert_eq!(sql.share_cid.as_str(), SQL_SHARE_CID);
        assert_eq!(sql.policy_cid.as_str(), SQL_POLICY_CID);
        assert!(matches!(sql.content_source, ContentSource::Sql { .. }));
        assert_ne!(kv.share_cid, sql.share_cid);
        assert_ne!(kv.policy_cid, sql.policy_cid);
    }
}
