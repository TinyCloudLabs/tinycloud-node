//! Fail-closed defaults for uncomposed N1, N2, and N3 boundaries.

use async_trait::async_trait;
use time::OffsetDateTime;

use super::{ports::*, types::*};

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableCredentialVerifier;

#[async_trait]
impl CredentialVerifier for UnavailableCredentialVerifier {
    async fn verify_credential_for(
        &self,
        _: &[u8],
        _: &ShareScope,
        _: &DidKey,
        _: &str,
        _: i64,
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
        _: VerifiedSessionAdmission,
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
            allowed_actions: vec![ShareAction::KvGet],
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

    fn authorized_read() -> AuthorizedRead {
        let holder =
            DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw").unwrap();
        let session = PolicySession {
            handle: SessionHandle::from_bytes([0; 16]),
            scope: kv_scope(),
            holder: holder.clone(),
            credential_digest: Sha256Digest::from_bytes([0; 32]),
            expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(5),
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
                .verify_credential_for(
                    b"credential",
                    &kv_scope(),
                    &DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",)
                        .unwrap(),
                    "holder@example.com",
                    1,
                )
                .await,
            Err(PortError::Unavailable)
        );
        assert_eq!(
            UnavailablePolicyAuthorityBridge
                .establish_session(
                    VerifiedSessionAdmission::for_test(
                        PolicySessionRequest {
                            scope: kv_scope(),
                            holder: DidKey::parse(
                                "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                            )
                            .unwrap(),
                            nonce: ProtocolNonce::from_bytes([0; 32]),
                            presentation_jti: ProtocolJti::from_bytes([1; 16]),
                            challenge_id: String::new(),
                            challenge_request_digest: Sha256Digest::from_bytes([0; 32]),
                            challenge_binding: serde_json::Value::Null,
                            policy_recipient_digest: Sha256Digest::from_bytes([0; 32]),
                            credential_expires_at: 0,
                        },
                        DidKey::parse("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",)
                            .unwrap()
                    ),
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
}
