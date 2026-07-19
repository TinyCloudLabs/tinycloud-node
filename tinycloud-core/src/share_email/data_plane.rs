//! Holder-bound, Markdown-only data-plane primitives for exact-email shares.
//!
//! This module deliberately stops at the N0a ports.  The authority bridge is
//! the only component allowed to turn the request into an [`AuthorizedRead`];
//! a session handle and an adapter configuration never authorize a read by
//! themselves.  The concrete backends below accept only typed, exact source
//! values so the integration owner can connect them to the existing KV and
//! #117 constrained named-statement paths without adding a second registry.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libp2p::identity::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, sync::Arc};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    policy_capability::{jcs, sql_caveat},
    sql::SqlValue,
};

use super::{ports::*, types::*};

/// The frozen signed-read domain from the email-claim contract.
pub const READ_INVOCATION_DOMAIN: &[u8] = b"xyz.tinycloud.share/read-invocation/v1\0";
/// The response media type is intentionally not negotiated or inferred.
pub const MARKDOWN_CACHE_CONTROL: &str = "no-store";
/// Holder read signatures are short-lived even when the share itself lives longer.
pub const MAX_READ_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DataPlaneError {
    #[error("read request denied")]
    Denied,
    #[error("read proof is invalid")]
    InvalidProof,
    #[error("read proof is expired")]
    Expired,
    #[error("read request replayed")]
    Replay,
    #[error("read body is not valid UTF-8 Markdown")]
    InvalidEncoding,
    #[error("read body exceeds the Markdown limit")]
    Oversized,
    #[error("read source is not an exact Markdown source")]
    InvalidSource,
    #[error("SQL result is not exactly one markdown row")]
    InvalidSqlResult,
    #[error("read storage is unavailable")]
    Storage,
}

impl From<PortError> for DataPlaneError {
    fn from(error: PortError) -> Self {
        match error {
            PortError::Replay => Self::Replay,
            PortError::Storage | PortError::Unavailable => Self::Storage,
            PortError::Denied => Self::Denied,
        }
    }
}

/// A holder signature and its independently checked lifetime/JTI.
#[derive(Clone, PartialEq, Eq)]
pub struct HolderReadProof {
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub jti: ProtocolJti,
    pub signer: DidKey,
    pub signature: Vec<u8>,
}

impl fmt::Debug for HolderReadProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HolderReadProof { [REDACTED] }")
    }
}

impl HolderReadProof {
    pub fn from_base64(
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        jti: ProtocolJti,
        signer: DidKey,
        signature: &str,
    ) -> Result<Self, DataPlaneError> {
        let signature = URL_SAFE_NO_PAD
            .decode(signature.as_bytes())
            .map_err(|_| DataPlaneError::InvalidProof)?;
        if signature.len() != 64 {
            return Err(DataPlaneError::InvalidProof);
        }
        Ok(Self {
            issued_at,
            expires_at,
            jti,
            signer,
            signature,
        })
    }
}

/// The complete request sent to the data plane.  There is no token-only
/// constructor: callers must provide the holder signature and its unique JTI.
#[derive(Clone, PartialEq, Eq)]
pub struct HolderReadRequest {
    pub session: SessionHandle,
    pub jti: ProtocolJti,
    pub scope: ShareScope,
    pub holder: DidKey,
    pub request_body_digest: Sha256Digest,
    pub proof: HolderReadProof,
}

impl fmt::Debug for HolderReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HolderReadRequest { [REDACTED] }")
    }
}

impl HolderReadRequest {
    fn authorization(&self) -> ReadAuthorizationRequest {
        ReadAuthorizationRequest {
            session: self.session.clone(),
            jti: self.jti.clone(),
            scope: self.scope.clone(),
            holder: self.holder.clone(),
            request_body_digest: self.request_body_digest.clone(),
        }
    }
}

/// A typed response boundary for HTTP composition.  It contains no redirect,
/// sniffing, or cache negotiation knobs for the caller to alter.
#[derive(Clone, PartialEq, Eq)]
pub struct MarkdownResponse {
    pub document: MarkdownDocument,
    pub body_digest: Sha256Digest,
    pub media_type: &'static str,
    pub cache_control: &'static str,
}

impl fmt::Debug for MarkdownResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MarkdownResponse { [REDACTED] }")
    }
}

/// A single immutable statement binding supplied by the #117 integration.
/// There is intentionally no map or mutator here: a process may compose one
/// adapter per exact source, but N3 never looks up caller-controlled SQL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedNamedStatement {
    pub database: DatabaseName,
    pub path: Path,
    pub statement: sql_caveat::ConstrainedStatement,
}

/// The result shape exposed by the existing named-statement executor.
#[derive(Clone, Debug, PartialEq)]
pub struct NamedSqlRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlValue>>,
}

/// A typed KV backend adapter.  The implementation behind this trait should
/// call the existing `SpaceDatabase::kv_get` path; it cannot receive a query,
/// prefix, redirect, or alternate action.
#[async_trait]
pub trait ExactKvStore: Send + Sync {
    async fn get_exact(&self, space: &Did, path: &Path) -> Result<Option<Vec<u8>>, PortError>;
}

/// A typed SQL backend adapter.  Implementations must delegate to the live
/// #117 constrained `ExecuteStatement` path using the supplied pinned
/// statement.  Raw SQL is not representable in this method's request.
#[async_trait]
pub trait ConstrainedNamedSqlStore: Send + Sync {
    async fn execute_named(
        &self,
        source: &SqlReadSource,
        statement: &PinnedNamedStatement,
    ) -> Result<NamedSqlRows, PortError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlReadSource {
    pub space: Did,
    pub database: DatabaseName,
    pub path: Path,
    pub statement: NamedStatement,
    pub arguments: BTreeMap<String, SafeJsonInteger>,
    pub arguments_digest: Sha256Digest,
}

/// KV adapter that enforces the Markdown response boundary before returning
/// data to the protocol layer.
pub struct MarkdownKvAdapter<S> {
    store: Arc<S>,
}

impl<S> Clone for MarkdownKvAdapter<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
        }
    }
}

impl<S> MarkdownKvAdapter<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<S: ExactKvStore> KvReadAdapter for MarkdownKvAdapter<S> {
    async fn read_markdown(
        &self,
        authorized: AuthorizedRead,
    ) -> Result<MarkdownDocument, PortError> {
        let ContentSource::Kv {
            action,
            space,
            path,
        } = &authorized.session().scope.content_source
        else {
            return Err(PortError::Denied);
        };
        if !matches!(action, KvGetAction::Get)
            || authorized.session().scope.action != ShareAction::KvGet
            || !matches!(&authorized.session().scope.resource, ExactResource::Kv { path: p } if p == path)
        {
            return Err(PortError::Denied);
        }
        let Some(bytes) = self.store.get_exact(space, path).await? else {
            return Err(PortError::Denied);
        };
        markdown_document(bytes).map_err(|error| match error {
            DataPlaneError::InvalidEncoding | DataPlaneError::Oversized => PortError::Denied,
            _ => PortError::Storage,
        })
    }
}

/// SQL adapter that enforces exact database/path/statement identity and the
/// one-row/one-column Markdown result shape.
pub struct MarkdownSqlAdapter<S> {
    store: Arc<S>,
}

impl<S> Clone for MarkdownSqlAdapter<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
        }
    }
}

impl<S> MarkdownSqlAdapter<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<S: ConstrainedNamedSqlStore> NamedSqlReadAdapter for MarkdownSqlAdapter<S> {
    async fn read_markdown(
        &self,
        authorized: AuthorizedRead,
    ) -> Result<MarkdownDocument, PortError> {
        let ContentSource::Sql {
            space,
            database,
            path,
            statement,
            arguments,
            arguments_digest,
            action,
        } = &authorized.session().scope.content_source
        else {
            return Err(PortError::Denied);
        };
        if !matches!(action, SqlReadAction::Read)
            || authorized.session().scope.action != ShareAction::SqlRead
            || !matches!(
                &authorized.session().scope.resource,
                ExactResource::Sql { database: d, path: p, statement: s }
                    if d == database && p == path && s == statement
            )
            || statement.as_str()
                != authorized
                    .session()
                    .sql_statement
                    .as_ref()
                    .map(|s| s.statement.name.as_str())
                    .unwrap_or_default()
        {
            return Err(PortError::Denied);
        }
        if digest_arguments(arguments).as_str() != arguments_digest.as_str() {
            return Err(PortError::Denied);
        }
        let source = SqlReadSource {
            space: space.clone(),
            database: database.clone(),
            path: path.clone(),
            statement: statement.clone(),
            arguments: arguments.clone(),
            arguments_digest: arguments_digest.clone(),
        };
        let pinned = authorized
            .session()
            .sql_statement
            .as_ref()
            .ok_or(PortError::Denied)?;
        let result = self.store.execute_named(&source, pinned).await?;
        let [row] = result.rows.as_slice() else {
            return Err(PortError::Denied);
        };
        if result.columns.len() != 1 || result.columns[0] != "markdown" || row.len() != 1 {
            return Err(PortError::Denied);
        }
        let SqlValue::Text(markdown) = &row[0] else {
            return Err(PortError::Denied);
        };
        markdown_document(markdown.as_bytes().to_vec()).map_err(|error| match error {
            DataPlaneError::InvalidEncoding | DataPlaneError::Oversized => PortError::Denied,
            _ => PortError::Storage,
        })
    }
}

/// The N3 coordinator.  It verifies the holder proof before entering the
/// authority bridge, then asks that bridge to consume the JTI and revalidate
/// #117 ancestry/revocation atomically before touching content storage.
pub struct HolderBoundDataPlane<A, K, S> {
    authority: Arc<A>,
    kv: Arc<K>,
    sql: Arc<S>,
}

impl<A, K, S> Clone for HolderBoundDataPlane<A, K, S> {
    fn clone(&self) -> Self {
        Self {
            authority: Arc::clone(&self.authority),
            kv: Arc::clone(&self.kv),
            sql: Arc::clone(&self.sql),
        }
    }
}

impl<A, K, S> HolderBoundDataPlane<A, K, S> {
    pub fn new(authority: Arc<A>, kv: Arc<K>, sql: Arc<S>) -> Self {
        Self { authority, kv, sql }
    }
}

impl<A, K, S> HolderBoundDataPlane<A, K, S>
where
    A: PolicyAuthorityTransaction117,
    K: KvReadAdapter,
    S: NamedSqlReadAdapter,
{
    pub async fn read(
        &self,
        request: HolderReadRequest,
        now: OffsetDateTime,
    ) -> Result<MarkdownResponse, DataPlaneError> {
        verify_request(&request, now)?;
        let authorized = self
            .authority
            .authorize_read(request.authorization(), now)
            .await
            .map_err(DataPlaneError::from)?;
        if !same_scope_except_delegation(&authorized.session().scope, &request.scope)
            || authorized.session().holder != request.holder
            || authorized.invocation().jti != request.jti
            || authorized.invocation().request_body_digest != request.request_body_digest
        {
            return Err(DataPlaneError::Denied);
        }
        let document = match request.scope.content_source {
            ContentSource::Kv { .. } => self
                .kv
                .read_markdown(authorized)
                .await
                .map_err(DataPlaneError::from)?,
            ContentSource::Sql { .. } => self
                .sql
                .read_markdown(authorized)
                .await
                .map_err(DataPlaneError::from)?,
        };
        response(document, &request.scope.content_source_digest)
    }
}

fn same_scope_except_delegation(left: &ShareScope, right: &ShareScope) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.delegation_cid = None;
    right.delegation_cid = None;
    left == right
}

fn verify_request(request: &HolderReadRequest, now: OffsetDateTime) -> Result<(), DataPlaneError> {
    if request.jti != request.proof.jti
        || request.holder != request.proof.signer
        || request.proof.expires_at <= request.proof.issued_at
        || request.proof.expires_at - request.proof.issued_at
            > time::Duration::seconds(MAX_READ_TTL_SECONDS)
        || now < request.proof.issued_at
        || now >= request.proof.expires_at
    {
        return Err(if now >= request.proof.expires_at {
            DataPlaneError::Expired
        } else {
            DataPlaneError::InvalidProof
        });
    }
    validate_scope(&request.scope)?;
    let signer = did_key_public_key(request.proof.signer.as_str())?;
    let message = signed_read_bytes(request)?;
    if !signer.verify(&message, &request.proof.signature) {
        return Err(DataPlaneError::InvalidProof);
    }
    Ok(())
}

fn validate_scope(scope: &ShareScope) -> Result<(), DataPlaneError> {
    let source_value =
        serde_json::to_value(&scope.content_source).map_err(|_| DataPlaneError::InvalidSource)?;
    let source_digest = sha256_digest(&jcs::canonicalize(&source_value));
    if source_digest != scope.content_source_digest {
        return Err(DataPlaneError::InvalidSource);
    }
    match (&scope.action, &scope.resource, &scope.content_source) {
        (
            ShareAction::KvGet,
            ExactResource::Kv {
                path: resource_path,
            },
            ContentSource::Kv {
                action: KvGetAction::Get,
                path,
                ..
            },
        ) if resource_path == path => Ok(()),
        (
            ShareAction::SqlRead,
            ExactResource::Sql {
                database: resource_database,
                path: resource_path,
                statement: resource_statement,
            },
            ContentSource::Sql {
                action: SqlReadAction::Read,
                database,
                path,
                statement,
                arguments,
                arguments_digest,
                ..
            },
        ) if resource_database == database
            && resource_path == path
            && resource_statement == statement
            && digest_arguments(arguments) == *arguments_digest =>
        {
            Ok(())
        }
        _ => Err(DataPlaneError::InvalidSource),
    }
}

fn signed_read_bytes(request: &HolderReadRequest) -> Result<Vec<u8>, DataPlaneError> {
    let source = serde_json::to_value(&request.scope.content_source)
        .map_err(|_| DataPlaneError::InvalidProof)?;
    let value = json!({
        "type": "TinyCloudShareReadInvocation",
        "version": 1,
        "sessionId": request.session.as_str(),
        "shareCid": request.scope.share_cid.as_str(),
        "shareId": request.scope.share_id.as_str(),
        "policyCid": request.scope.policy_cid.as_str(),
        "contentSource": source,
        "contentSourceDigest": request.scope.content_source_digest.as_str(),
        "holderDid": request.holder.as_str(),
        "targetOrigin": request.scope.target_origin.as_str(),
        "nodeAudience": request.scope.node_audience.as_str(),
        "action": action_name(request.scope.action),
        "resource": resource_name(&request.scope.resource),
        "requestBodyDigest": request.request_body_digest.as_str(),
        "issuedAt": timestamp(request.proof.issued_at)?,
        "expiresAt": timestamp(request.proof.expires_at)?,
        "jti": request.jti.as_str(),
    });
    let mut signed = READ_INVOCATION_DOMAIN.to_vec();
    signed.extend(jcs::canonicalize(&value));
    Ok(signed)
}

fn response(
    document: MarkdownDocument,
    expected_source: &Sha256Digest,
) -> Result<MarkdownResponse, DataPlaneError> {
    let body = document.as_bytes();
    if body.len() > MAX_MARKDOWN_BYTES {
        return Err(DataPlaneError::Oversized);
    }
    if std::str::from_utf8(body).is_err() {
        return Err(DataPlaneError::InvalidEncoding);
    }
    let body_digest = sha256_digest(body);
    if expected_source.as_str().is_empty() {
        return Err(DataPlaneError::InvalidSource);
    }
    Ok(MarkdownResponse {
        document,
        body_digest,
        media_type: MARKDOWN_MEDIA_TYPE,
        cache_control: MARKDOWN_CACHE_CONTROL,
    })
}

fn markdown_document(bytes: Vec<u8>) -> Result<MarkdownDocument, DataPlaneError> {
    if bytes.len() > MAX_MARKDOWN_BYTES {
        return Err(DataPlaneError::Oversized);
    }
    std::str::from_utf8(&bytes).map_err(|_| DataPlaneError::InvalidEncoding)?;
    Ok(MarkdownDocument::from_bytes(bytes))
}

fn digest_arguments(arguments: &BTreeMap<String, SafeJsonInteger>) -> Sha256Digest {
    let value = serde_json::to_value(arguments).unwrap_or(Value::Null);
    sha256_digest(&jcs::canonicalize(&value))
}

fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(bytes);
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn action_name(action: ShareAction) -> &'static str {
    match action {
        ShareAction::KvGet => KV_GET_ACTION,
        ShareAction::SqlRead => SQL_READ_ACTION,
    }
}

fn resource_name(resource: &ExactResource) -> &str {
    match resource {
        ExactResource::Kv { path } => path.as_str(),
        ExactResource::Sql { path, .. } => path.as_str(),
    }
}

fn timestamp(value: OffsetDateTime) -> Result<String, DataPlaneError> {
    let rendered = value
        .format(&Rfc3339)
        .map_err(|_| DataPlaneError::InvalidProof)?;
    if rendered.ends_with('Z') && !rendered[..rendered.len() - 1].contains('.') {
        Ok(format!(
            "{}.{:03}Z",
            &rendered[..rendered.len() - 1],
            value.nanosecond() / 1_000_000
        ))
    } else {
        Ok(rendered)
    }
}

fn did_key_public_key(did: &str) -> Result<PublicKey, DataPlaneError> {
    let encoded = did
        .strip_prefix("did:key:")
        .ok_or(DataPlaneError::InvalidProof)?;
    let (_, bytes) = tinycloud_auth::ipld_core::cid::multibase::decode(encoded)
        .map_err(|_| DataPlaneError::InvalidProof)?;
    let key_bytes = match bytes.as_slice() {
        [0xed, rest @ ..] if rest.len() == 32 => rest,
        [0xed, 0x01, rest @ ..] if rest.len() == 32 => rest,
        _ => return Err(DataPlaneError::InvalidProof),
    };
    let key = libp2p::identity::ed25519::PublicKey::try_from_bytes(key_bytes)
        .map_err(|_| DataPlaneError::InvalidProof)?;
    Ok(key.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const HOLDER: &str = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

    fn scope() -> ShareScope {
        let space =
            Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111").unwrap();
        let path = Path::parse("documents/plan.md").unwrap();
        let source = ContentSource::Kv {
            action: KvGetAction::Get,
            space,
            path: path.clone(),
        };
        let digest = sha256_digest(&jcs::canonicalize(&serde_json::to_value(&source).unwrap()));
        ShareScope {
            share_cid: ShareCid::parse(KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-kv-001").unwrap(),
            delegation_cid: None,
            policy_cid: PolicyCid::parse(KV_POLICY_CID).unwrap(),
            node_audience: Did::parse("did:web:node.example").unwrap(),
            target_origin: TargetOrigin::parse("https://node.example").unwrap(),
            action: ShareAction::KvGet,
            resource: ExactResource::Kv { path },
            content_source: source,
            content_source_digest: digest,
        }
    }

    #[test]
    fn frozen_kv_source_digest_and_response_digest_are_exact() {
        let source = ContentSource::Kv {
            action: KvGetAction::Get,
            space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                .unwrap(),
            path: Path::parse("documents/plan.md").unwrap(),
        };
        assert_eq!(
            sha256_digest(&jcs::canonicalize(&serde_json::to_value(source).unwrap())).as_str(),
            "B-O75gHmIx2CyOm9cOdHJivP-kupRtNWcUPXuZbEnZ4"
        );
        assert_eq!(
            sha256_digest(b"# Project plan\n").as_str(),
            "I5g9jFq8hn03TSW-98W-Df2kP5KiNmyR1r-I9ZfPd4s"
        );
    }

    #[test]
    fn bounds_and_encoding_fail_closed() {
        assert!(matches!(
            markdown_document(vec![0xff]),
            Err(DataPlaneError::InvalidEncoding)
        ));
        assert!(matches!(
            markdown_document(vec![b'a'; MAX_MARKDOWN_BYTES + 1]),
            Err(DataPlaneError::Oversized)
        ));
    }

    #[test]
    fn source_mutations_are_rejected() {
        let mut changed = scope();
        changed.content_source_digest = Sha256Digest::from_bytes([0; 32]);
        assert_eq!(validate_scope(&changed), Err(DataPlaneError::InvalidSource));
        let mut wrong_action = scope();
        wrong_action.action = ShareAction::SqlRead;
        assert_eq!(
            validate_scope(&wrong_action),
            Err(DataPlaneError::InvalidSource)
        );
        let mut wrong_path = scope();
        wrong_path.resource = ExactResource::Kv {
            path: Path::parse("documents/other.md").unwrap(),
        };
        assert_eq!(
            validate_scope(&wrong_path),
            Err(DataPlaneError::InvalidSource)
        );
    }

    #[test]
    fn frozen_sql_arguments_digest_is_rfc8785_over_the_arguments_object() {
        let arguments = BTreeMap::from([(
            "document_id".to_owned(),
            SafeJsonInteger::parse(123).unwrap(),
        )]);
        assert_eq!(
            digest_arguments(&arguments).as_str(),
            "Wvt9ycf107Id2Qe58i0BnWykVBsdjhyS03P2psS0bSg"
        );
    }

    #[test]
    fn timestamp_matches_frozen_millisecond_shape() {
        let value = OffsetDateTime::from_unix_timestamp(1_784_203_200).unwrap();
        assert_eq!(timestamp(value).unwrap(), "2026-07-16T12:00:00.000Z");
    }

    #[test]
    fn sql_rows_require_one_markdown_string() {
        assert!(matches!(
            [vec![SqlValue::Text("# ok".to_owned())]].as_slice(),
            [row] if row.len() == 1
        ));
        assert!(!matches!(
            [vec![SqlValue::Integer(1)]].as_slice(),
            [row] if matches!(row[0], SqlValue::Text(_))
        ));
    }

    #[test]
    fn public_request_cannot_be_authorized_without_a_signature() {
        let request = HolderReadRequest {
            session: SessionHandle::from_bytes([1; 16]),
            jti: ProtocolJti::from_bytes([2; 16]),
            scope: scope(),
            holder: DidKey::parse(HOLDER).unwrap(),
            request_body_digest: Sha256Digest::from_bytes([3; 32]),
            proof: HolderReadProof {
                issued_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(1),
                jti: ProtocolJti::from_bytes([2; 16]),
                signer: DidKey::parse(HOLDER).unwrap(),
                signature: vec![],
            },
        };
        assert_eq!(
            verify_request(&request, OffsetDateTime::UNIX_EPOCH),
            Err(DataPlaneError::InvalidProof)
        );
    }

    #[test]
    fn expired_and_rebound_body_or_jti_proofs_fail_before_authority() {
        let mut request = HolderReadRequest {
            session: SessionHandle::from_bytes([1; 16]),
            jti: ProtocolJti::from_bytes([2; 16]),
            scope: scope(),
            holder: DidKey::parse(HOLDER).unwrap(),
            request_body_digest: Sha256Digest::from_bytes([3; 32]),
            proof: HolderReadProof {
                issued_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(1),
                jti: ProtocolJti::from_bytes([2; 16]),
                signer: DidKey::parse(HOLDER).unwrap(),
                signature: vec![0; 64],
            },
        };
        assert_eq!(
            verify_request(
                &request,
                OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2)
            ),
            Err(DataPlaneError::Expired)
        );
        request.request_body_digest = Sha256Digest::from_bytes([4; 32]);
        assert_eq!(
            verify_request(&request, OffsetDateTime::UNIX_EPOCH),
            Err(DataPlaneError::InvalidProof)
        );
        request.jti = ProtocolJti::from_bytes([5; 16]);
        assert_eq!(
            verify_request(&request, OffsetDateTime::UNIX_EPOCH),
            Err(DataPlaneError::InvalidProof)
        );
    }

    #[test]
    fn concurrent_consumption_is_delegated_to_the_atomic_authority_port() {
        let calls = AtomicUsize::new(0);
        assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 1);
    }
}
