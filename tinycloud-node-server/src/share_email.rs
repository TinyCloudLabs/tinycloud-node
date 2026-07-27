//! Production composition for the exact-email claim node surface.
//!
//! This module is deliberately the only HTTP composition point for the N1/N2
//! and N3 leaves.  It contains no test adapters: production reads go through
//! `SpaceDatabase` and the existing constrained `SqlService`, while authority
//! state goes through `DatabaseAuthorityBridge117`.

use async_trait::async_trait;
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use hmac::{Hmac, Mac};
use rocket::{
    data::{Data, ToByteUnit},
    http::Status,
    request::{FromRequest, Outcome},
    response::status::Custom,
    response::Responder,
    serde::json::Json,
    State,
};
use rocket::{http::Header, Request};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tokio::io::AsyncReadExt as TokioAsyncReadExt;

use tinycloud_auth::multihash_codetable::MultihashDigest;
use tinycloud_auth::share_email_evidence::{IssuerKey, IssuerTrustRegistry};
use tinycloud_core::{
    policy_authority::DatabaseAuthorityStore,
    policy_capability::jcs,
    sea_orm::DatabaseConnection,
    share_email::{
        data_plane::{
            ConstrainedNamedSqlStore, DataPlaneError, ExactKvStore, HolderBoundDataPlane,
            HolderReadProof, HolderReadRequest, MarkdownKvAdapter, MarkdownSqlAdapter,
            NamedSqlRows, PinnedNamedStatement, SqlReadSource,
        },
        invitation::{
            issue_invitation_authorization_for, CanonicalEmail, DocumentName,
            Ed25519InvitationSigner, Ed25519InvitationVerifier, InvitationAuthorizationInput,
            InvitationSigner, SenderTrust,
        },
        state::{AnonymousChallengeRequest, ProtocolStateRepository, StateError},
        types::{
            validate_share_path, AuthorityMaterialHandle, ContentSource, Did, DidKey,
            ExactResource, Path, PolicyCid, PolicySessionRequest as AuthorityPolicySessionRequest,
            ProtocolJti, ProtocolNonce, RecipientMatcher, SessionHandle, ShareAction, ShareCid,
            ShareCursor, ShareDelegationCid, ShareId, SharePolicyResource, SharePolicyV2,
            ShareScope, TargetOrigin,
        },
        verifier::ExactEmailVerifier,
        AuthenticatedAuthorityMaterialProvider, AuthorityTrustDescriptor,
        DatabaseAuthorityBridge117, PolicyAuthorityTransaction117, PortError,
    },
    sql::{caveats::PreparedStatement, SqlCaveats, SqlRequest, SqlResponse, SqlService, SqlValue},
    storage::ImmutableStaging,
};

use crate::{config::ShareEmailConfig, TinyCloud};

const POLICY_CHALLENGE_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy-challenge/v1\0";
const POLICY_SESSION_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy-session/v1\0";
pub const READ_RESPONSE_DOMAIN: &[u8] = b"xyz.tinycloud.share/read-response/v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedProof {
    pub alg: String,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChallengeRequest {
    #[serde(rename = "shareCid")]
    pub share_cid: tinycloud_core::share_email::ShareCid,
    #[serde(rename = "shareId")]
    pub share_id: tinycloud_core::share_email::ShareId,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "policyCid")]
    pub policy_cid: PolicyCid,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "holderDid")]
    pub holder_did: DidKey,
    #[serde(rename = "targetOrigin")]
    pub target_origin: TargetOrigin,
    #[serde(rename = "nodeAudience")]
    pub node_audience: Did,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChallenge {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    #[serde(rename = "challengeId")]
    pub challenge_id: ProtocolNonce,
    pub nonce: ProtocolNonce,
    #[serde(rename = "shareCid")]
    pub share_cid: tinycloud_core::share_email::ShareCid,
    #[serde(rename = "shareId")]
    pub share_id: tinycloud_core::share_email::ShareId,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "policyCid")]
    pub policy_cid: PolicyCid,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "holderDid")]
    pub holder_did: DidKey,
    #[serde(rename = "targetOrigin")]
    pub target_origin: TargetOrigin,
    #[serde(rename = "nodeAudience")]
    pub node_audience: Did,
    #[serde(rename = "enforcerDid")]
    pub enforcer_did: DidKey,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPresentation {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    #[serde(rename = "challengeId")]
    pub challenge_id: ProtocolNonce,
    pub nonce: ProtocolNonce,
    #[serde(rename = "shareCid")]
    pub share_cid: tinycloud_core::share_email::ShareCid,
    #[serde(rename = "shareId")]
    pub share_id: tinycloud_core::share_email::ShareId,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "policyCid")]
    pub policy_cid: PolicyCid,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "holderDid")]
    pub holder_did: DidKey,
    #[serde(rename = "targetOrigin")]
    pub target_origin: TargetOrigin,
    #[serde(rename = "nodeAudience")]
    pub node_audience: Did,
    #[serde(rename = "enforcerDid")]
    pub enforcer_did: DidKey,
    #[serde(rename = "credentialDigest")]
    pub credential_digest: tinycloud_core::share_email::Sha256Digest,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub jti: ProtocolJti,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySessionRequest {
    pub presentation: PolicyPresentation,
    pub credential: String,
    pub proof: DetachedProof,
    #[serde(rename = "holderBinding")]
    pub holder_binding: Value,
    #[serde(rename = "readSignerDid")]
    pub read_signer_did: DidKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySession {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    #[serde(rename = "sessionId")]
    pub session_id: SessionHandle,
    #[serde(rename = "shareCid")]
    pub share_cid: tinycloud_core::share_email::ShareCid,
    #[serde(rename = "shareId")]
    pub share_id: tinycloud_core::share_email::ShareId,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "policyCid")]
    pub policy_cid: PolicyCid,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "holderDid")]
    pub holder_did: DidKey,
    #[serde(rename = "targetOrigin")]
    pub target_origin: TargetOrigin,
    #[serde(rename = "nodeAudience")]
    pub node_audience: Did,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "credentialDigest")]
    pub credential_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadInvocation {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    #[serde(rename = "sessionId")]
    pub session_id: SessionHandle,
    #[serde(rename = "shareCid")]
    pub share_cid: tinycloud_core::share_email::ShareCid,
    #[serde(rename = "shareId")]
    pub share_id: tinycloud_core::share_email::ShareId,
    #[serde(rename = "policyCid")]
    pub policy_cid: PolicyCid,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "holderDid")]
    pub holder_did: DidKey,
    #[serde(rename = "targetOrigin")]
    pub target_origin: TargetOrigin,
    #[serde(rename = "nodeAudience")]
    pub node_audience: Did,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(
        rename = "bodyDigest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub body_digest: Option<tinycloud_core::share_email::Sha256Digest>,
    #[serde(rename = "ifMatch", default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<String>,
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub jti: ProtocolJti,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    #[serde(rename = "sessionId")]
    pub session_id: SessionHandle,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    pub invocation: ReadInvocation,
    pub proof: DetachedProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeInvokeEnvelope {
    pub request: ReadRequest,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(rename = "bodyDigest", default)]
    pub body_digest: Option<tinycloud_core::share_email::Sha256Digest>,
    #[serde(rename = "ifMatch", default)]
    pub if_match: Option<String>,
    #[serde(rename = "contentType", default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadResponse {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    pub session_id: SessionHandle,
    pub request_jti: ProtocolJti,
    pub read_jti: ProtocolJti,
    pub audience: Did,
    pub holder_did: DidKey,
    pub credential_digest: tinycloud_core::share_email::Sha256Digest,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(rename = "mediaType")]
    pub media_type: &'static str,
    pub content: String,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    pub action: ShareAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "bodyDigest")]
    pub body_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "delegationCid")]
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    pub proof: DetachedProof,
}

pub struct NoStoreJson<T>(pub T);

impl<'r, T: Serialize + 'static> Responder<'r, 'static> for NoStoreJson<T> {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Json(self.0).respond_to(request)?;
        response.set_header(Header::new("Cache-Control", "no-store"));
        response.set_header(Header::new("Pragma", "no-cache"));
        Ok(response)
    }
}

pub struct NativeJson<T>(T, Option<Header<'static>>);

impl<'r, T: Serialize + 'static> Responder<'r, 'static> for NativeJson<T> {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Json(self.0).respond_to(request)?;
        if let Some(header) = self.1 {
            response.set_header(header);
        }
        Ok(response)
    }
}

#[derive(Debug, Serialize)]
pub struct CapabilityDescriptor {
    pub id: &'static str,
    pub version: u8,
    pub origin: String,
    #[serde(rename = "returnOrigin")]
    pub return_origin: String,
    pub routes: [&'static str; 4],
    #[serde(rename = "contentKinds")]
    pub content_kinds: [&'static str; 2],
    #[serde(rename = "mailProvider")]
    pub mail_provider: &'static str,
    pub status: &'static str,
}

/// Public trust metadata passed from Node composition to a real Share host.
/// This is intentionally separate from the frozen capability descriptor: the
/// four-route public profile is immutable, while host setup still needs the
/// authenticated issuer and authority trust tuple. No private key material is
/// present here.
#[derive(Debug, Clone, Serialize)]
pub struct ShareEmailHostTrustDescriptor {
    pub authority: AuthorityTrustDescriptor,
    #[serde(rename = "issuerDid")]
    pub issuer_did: String,
    #[serde(rename = "issuerVct")]
    pub issuer_vct: String,
    #[serde(rename = "issuerKid")]
    pub issuer_kid: String,
    #[serde(rename = "issuerPublicKey")]
    pub issuer_public_key: String,
}

/// The public Node capability is deliberately identical to the frozen Share
/// node profile. Delivery finalization is an OpenCredentials transaction; it
/// is not a fifth Node protocol operation.
pub const NODE_CAPABILITY_ROUTES: [&str; 4] = [
    "/share/v1/invitations/authorize",
    "/share/v1/policy/challenges",
    "/share/v1/policy/session",
    "/share/v1/read",
];

/// Mount the complete public Node protocol surface from one composition point.
/// Invitation authorization is a reservation boundary; there is no public
/// receipt-consume callback for delivery workers to invoke.
pub fn public_routes() -> Vec<rocket::Route> {
    rocket::routes![
        addressed_delegate,
        authorize_invitation,
        policy_challenge,
        policy_session,
        read,
        native_invoke
    ]
}

/// Authenticated Node-native addressed delegation authoring on the existing
/// `/delegate` address.  Legacy callers continue to use the ordinary
/// Authorization header route; the media type selects this closed v2
/// contract.  The authority bundle remains the source of persisted policy
/// truth, so this route never creates a second policy service.
#[post(
    "/delegate",
    rank = 2,
    format = "application/vnd.tinycloud.delegation+json",
    data = "<data>"
)]
pub async fn addressed_delegate(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
    _origin: ShareOriginGuard,
) -> ApiResult<Value> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let value = read_bounded_json(data).await?;
    let envelope: AddressedDelegationAuthoringEnvelope = serde_json::from_value(value)
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    let request = envelope.request;
    if request.version != 2
        || request.target_origin.as_str() != runtime.config.target_origin
        || request.node_audience.as_str() != runtime.config.node_audience
        || !request.recipient_matcher.is_canonical()
    {
        return Err(error(Status::Forbidden, "delegation_authorization_invalid"));
    }
    let request_value = serde_json::to_value(&request)
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    verify_request_body_digest(&request_value, &request.request_body_digest)
        .map_err(|failure| {
            tracing::error!(failure = ?failure, stage = "authority_material_for", "addressed delegation authorization failed");
            error(Status::Forbidden, "delegation_authorization_invalid")
        })?;
    verify_did_key_signature(
        &request.sender_did,
        &envelope.proof,
        b"xyz.tinycloud.share/delegation-authoring/v2\0",
        &request_value,
    )
    .map_err(|_| error(Status::Forbidden, "delegation_authorization_invalid"))?;

    let source_action = match &request.content_source {
        ContentSource::Kv { action, .. } => match action {
            tinycloud_core::share_email::types::KvGetAction::Get => ShareAction::KvGet,
            tinycloud_core::share_email::types::KvGetAction::List => ShareAction::KvList,
            tinycloud_core::share_email::types::KvGetAction::Put => ShareAction::KvPut,
        },
        ContentSource::Sql { .. } => ShareAction::SqlRead,
    };
    let resource_is_prefix = matches!(
        request.resource.kind,
        tinycloud_core::share_email::types::SharePolicyResourceKind::Prefix
    );
    let validation_action = if resource_is_prefix
        && matches!(source_action, ShareAction::KvGet)
        && request.actions.contains(&ShareAction::KvList)
    {
        ShareAction::KvList
    } else {
        source_action
    };
    validate_action_set(Some(&request.actions), validation_action)
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    if matches!(validation_action, ShareAction::KvList) != resource_is_prefix {
        return Err(error(
            Status::BadRequest,
            "delegation_authorization_invalid",
        ));
    }
    let sender = Did::parse(request.sender_did.as_str())
        .map_err(|failure| {
            tracing::error!(failure = ?failure, stage = "validate_sender_for_policy", "addressed delegation authorization failed");
            error(Status::Forbidden, "delegation_authorization_invalid")
        })?;
    let policy = SharePolicyV2 {
        artifact_type: "TinyCloudSharePolicy".to_owned(),
        version: 2,
        recipient_matcher: request.recipient_matcher.clone(),
        content_source: request.content_source.clone(),
        content_source_digest: request.content_source_digest.clone(),
        actions: request.actions.clone(),
        resource: request.resource.clone(),
        expires_at: request.expires_at.clone(),
        issuer_did: sender,
    };
    policy
        .validate()
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    let policy_value = serde_json::to_value(&policy)
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    let policy_bytes = jcs::canonicalize(&policy_value);
    let policy_digest = digest_bytes(&policy_bytes);
    let policy_cid = PolicyCid::parse(
        tinycloud_auth::ipld_core::cid::Cid::new_v1(
            0x55,
            tinycloud_auth::multihash_codetable::Code::Sha2_256.digest(&policy_bytes),
        )
        .to_string(),
    )
    .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;

    let bundle = runtime
        .bridge
        .authority_material_for(
            &policy_cid,
            &request.delegation_cid,
            &request.authority_material_handle,
            &request.authority_material_digest,
        )
        .await
        .map_err(|failure| {
            tracing::error!(failure = ?failure, stage = "validate_scope", "addressed delegation authorization failed");
            error(Status::Forbidden, "delegation_authorization_invalid")
        })?;
    if bundle.policy_state != policy_bytes {
        return Err(error(Status::Forbidden, "delegation_authorization_invalid"));
    }
    runtime
        .bridge
        .validate_sender_for_policy(
            policy_cid.as_str(),
            request.delegation_cid.as_str(),
            &request.authority_material_handle,
            &request.authority_material_digest,
            request.sender_did.as_str(),
        )
        .await
        .map_err(|_| error(Status::Forbidden, "delegation_authorization_invalid"))?;
    let resource = Path::parse(request.resource.value.clone())
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    let scope = scope_from_request(
        &PolicyChallengeRequest {
            share_cid: request.share_cid.clone(),
            share_id: request.share_id.clone(),
            delegation_cid: request.delegation_cid.clone(),
            authority_material_handle: request.authority_material_handle.clone(),
            authority_material_digest: request.authority_material_digest.clone(),
            policy_cid: policy_cid.clone(),
            content_source: request.content_source.clone(),
            content_source_digest: request.content_source_digest.clone(),
            holder_did: request.sender_did.clone(),
            target_origin: request.target_origin.clone(),
            node_audience: request.node_audience.clone(),
            action: validation_action,
            actions: Some(request.actions.clone()),
            resource,
            request_body_digest: request.request_body_digest.clone(),
        },
        &runtime.config,
    )
    .map_err(|_| error(Status::Forbidden, "delegation_authorization_invalid"))?;
    let now = OffsetDateTime::now_utc();
    let expires_at = OffsetDateTime::parse(&request.expires_at, &Rfc3339)
        .map_err(|_| error(Status::BadRequest, "delegation_authorization_invalid"))?;
    if expires_at <= now {
        return Err(error(Status::Forbidden, "delegation_authorization_invalid"));
    }
    let authoring_expires_at = expires_at.min(now + Duration::seconds(300));
    runtime
        .bridge
        .validate_scope(&scope, now)
        .await
        .map_err(|_| error(Status::Forbidden, "delegation_authorization_invalid"))?;
    runtime
        .state
        .reserve_authoring_jti(
            &request.jti,
            &request.request_body_digest,
            json!({
                "policyCid": scope.policy_cid.as_str(),
                "delegationCid": scope
                    .delegation_cid
                    .as_ref()
                    .map(|cid| cid.as_str()),
                "authorityMaterialHandle": scope.authority_material_handle.as_str(),
                "authorityMaterialDigest": scope.authority_material_digest.as_str(),
                "nonce": request.nonce.as_str(),
            }),
            now,
            authoring_expires_at,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "delegation_authorization_invalid"))?;

    let mut response = AddressedDelegationAuthoringResponse {
        artifact_type: "TinyCloudShareAddressedDelegation",
        version: 2,
        nonce: request.nonce,
        jti: request.jti,
        policy_cid,
        policy_bytes: encode_config(&policy_bytes, URL_SAFE_NO_PAD),
        policy_digest,
        delegation_cid: request.delegation_cid,
        delegation_bytes: encode_config(&bundle.policy_enforcement, URL_SAFE_NO_PAD),
        delegation_digest: digest_bytes(&bundle.policy_enforcement),
        authority_material_handle: request.authority_material_handle,
        authority_material_digest: request.authority_material_digest,
        actions: request.actions,
        resource: request.resource,
        expires_at: request.expires_at,
        proof: DetachedProof {
            alg: String::new(),
            kid: String::new(),
            signature: String::new(),
        },
    };
    let mut response_value = serde_json::to_value(&response)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    response_value
        .as_object_mut()
        .ok_or(error(Status::InternalServerError, "capability_unavailable"))?
        .remove("proof");
    response.proof = sign(
        &runtime.signer,
        b"xyz.tinycloud.share/delegation-authoring-response/v2\0",
        &response_value,
    )
    .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    Ok(Json(serde_json::to_value(response).map_err(|_| {
        error(Status::InternalServerError, "capability_unavailable")
    })?))
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub error: ApiError,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: &'static str,
}

pub type ApiResult<T> = Result<Json<T>, Custom<Json<ApiErrorBody>>>;

/// Enforce the environment-owned browser host boundary when a browser sends
/// an Origin header. Server-to-server callers may omit Origin, but a supplied
/// origin must be the one authenticated by configuration.
pub struct ShareOriginGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ShareOriginGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(origin) = request.headers().get_one("Origin") else {
            return Outcome::Success(Self);
        };
        let allowed = request
            .rocket()
            .state::<Option<ShareEmailRuntime>>()
            .and_then(|runtime| runtime.as_ref())
            .and_then(|runtime| runtime.config.allowed_origins.first());
        if allowed.is_some_and(|allowed| allowed == origin) {
            Outcome::Success(Self)
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

pub struct ShareCursorHeader(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ShareCursorHeader {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(
            request
                .headers()
                .get_one("x-tinycloud-cursor")
                .map(str::to_owned),
        ))
    }
}

pub struct IfMatchHeader(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IfMatchHeader {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(
            request.headers().get_one("If-Match").map(str::to_owned),
        ))
    }
}

fn error(status: Status, code: &'static str) -> Custom<Json<ApiErrorBody>> {
    Custom(
        status,
        Json(ApiErrorBody {
            error: ApiError { code },
        }),
    )
}

fn generic(error_kind: &'static str) -> Custom<Json<ApiErrorBody>> {
    error(Status::BadRequest, error_kind)
}

fn body_is_bounded<T: Serialize>(value: &T) -> bool {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() <= tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES)
        .unwrap_or(false)
}

async fn read_bounded_json(data: Data<'_>) -> Result<Value, Custom<Json<ApiErrorBody>>> {
    read_bounded_json_with_limit(
        data,
        tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES,
    )
    .await
}

async fn read_bounded_json_with_limit(
    data: Data<'_>,
    limit: usize,
) -> Result<Value, Custom<Json<ApiErrorBody>>> {
    let mut bytes = Vec::new();
    let mut reader = data.open((limit + 1).bytes());
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| error(Status::BadRequest, "invalid_content_source"))?;
    if bytes.len() > limit {
        return Err(error(Status::PayloadTooLarge, "invalid_content_source"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error(Status::BadRequest, "invalid_content_source"))
}

#[derive(Clone)]
pub struct TinyCloudKvStore {
    pub tinycloud: Arc<TinyCloud>,
    pub space_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeListEntry {
    path: Path,
    kind: &'static str,
}

#[async_trait]
impl ExactKvStore for TinyCloudKvStore {
    async fn get_exact(&self, space: &Did, path: &Path) -> Result<Option<Vec<u8>>, PortError> {
        let did = space.as_str().parse().map_err(|_| PortError::Denied)?;
        let name = self.space_name.parse().map_err(|_| PortError::Denied)?;
        let space_id = tinycloud_auth::resource::SpaceId::new(did, name);
        let auth_path = path.as_str().parse().map_err(|_| PortError::Denied)?;
        let Some((_, _, content)) = self
            .tinycloud
            .kv_get(&space_id, &auth_path)
            .await
            .map_err(|_| PortError::Storage)?
        else {
            return Ok(None);
        };
        let (_, mut reader) = content.into_inner();
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| PortError::Storage)?;
        if bytes.len() > tinycloud_core::share_email::MAX_NATIVE_SHARE_CONTENT_BYTES {
            return Err(PortError::Denied);
        }
        Ok(Some(bytes))
    }
}

impl TinyCloudKvStore {
    async fn get_exact_bytes(
        &self,
        space: &Did,
        path: &Path,
    ) -> Result<Option<(Vec<u8>, String)>, PortError> {
        let did = space.as_str().parse().map_err(|_| PortError::Denied)?;
        let name = self.space_name.parse().map_err(|_| PortError::Denied)?;
        let space_id = tinycloud_auth::resource::SpaceId::new(did, name);
        let auth_path = path.as_str().parse().map_err(|_| PortError::Denied)?;
        let Some((metadata, _, content)) = self
            .tinycloud
            .kv_get(&space_id, &auth_path)
            .await
            .map_err(|_| PortError::Storage)?
        else {
            return Ok(None);
        };
        let (_, mut reader) = content.into_inner();
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| PortError::Storage)?;
        if bytes.len() > tinycloud_core::share_email::MAX_NATIVE_SHARE_CONTENT_BYTES {
            return Err(PortError::Denied);
        }
        let media_type = metadata
            .0
            .get("content-type")
            .cloned()
            // Exact-email shares are Markdown-only. Existing persisted KV
            // entries may predate content-type metadata, so the constrained
            // share boundary supplies the only safe default here.
            .unwrap_or_else(|| "text/markdown; charset=utf-8".to_owned());
        if media_type.is_empty()
            || media_type.len() > 128
            || !media_type.is_ascii()
            || media_type.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(PortError::Denied);
        }
        Ok(Some((bytes, media_type)))
    }

    async fn current_etag(&self, space: &Did, path: &Path) -> Result<Option<String>, PortError> {
        let did = space.as_str().parse().map_err(|_| PortError::Denied)?;
        let name = self.space_name.parse().map_err(|_| PortError::Denied)?;
        let space_id = tinycloud_auth::resource::SpaceId::new(did, name);
        let auth_path = path.as_str().parse().map_err(|_| PortError::Denied)?;
        Ok(self
            .tinycloud
            .kv_get(&space_id, &auth_path)
            .await
            .map_err(|_| PortError::Storage)?
            .map(|(_, hash, _)| format!("\"blake3-{}\"", hex::encode(hash.as_ref()))))
    }

    async fn list_direct_children(
        &self,
        space: &Did,
        prefix: &Path,
        limit: usize,
        after: Option<&Path>,
    ) -> Result<(Vec<NativeListEntry>, bool, Option<Path>), PortError> {
        let did = space.as_str().parse().map_err(|_| PortError::Denied)?;
        let name = self.space_name.parse().map_err(|_| PortError::Denied)?;
        let space_id = tinycloud_auth::resource::SpaceId::new(did, name);
        let prefix: tinycloud_auth::resource::Path =
            prefix.as_str().parse().map_err(|_| PortError::Denied)?;
        let after = after
            .map(|path| path.as_str().parse())
            .transpose()
            .map_err(|_| PortError::Denied)?;
        let (paths, truncated, next) = self
            .tinycloud
            .list_direct_children_bounded(&space_id, &prefix, limit, after.as_ref())
            .await
            .map_err(|_| PortError::Storage)?;
        let paths = paths
            .into_iter()
            .map(|path| Path::parse(path.as_str()).map_err(|_| PortError::Storage))
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries = Vec::with_capacity(paths.len());
        for path in paths {
            let kind = self.entry_kind(space, &path).await?;
            entries.push(NativeListEntry { path, kind });
        }
        let next = next
            .map(|path| Path::parse(path.as_str()).map_err(|_| PortError::Storage))
            .transpose()?;
        Ok((entries, truncated, next))
    }

    async fn entry_kind(&self, space: &Did, path: &Path) -> Result<&'static str, PortError> {
        let did = space.as_str().parse().map_err(|_| PortError::Denied)?;
        let name = self.space_name.parse().map_err(|_| PortError::Denied)?;
        let space_id = tinycloud_auth::resource::SpaceId::new(did, name);
        let auth_path = path.as_str().parse().map_err(|_| PortError::Denied)?;
        Ok(
            if self
                .tinycloud
                .kv_get(&space_id, &auth_path)
                .await
                .map_err(|_| PortError::Storage)?
                .is_some()
            {
                "file"
            } else {
                "folder"
            },
        )
    }
}

#[derive(Clone)]
pub struct SqlNamedStore {
    pub service: Arc<SqlService>,
    pub space_name: String,
}

#[async_trait]
impl ConstrainedNamedSqlStore for SqlNamedStore {
    async fn execute_named(
        &self,
        source: &SqlReadSource,
        statement: &PinnedNamedStatement,
    ) -> Result<NamedSqlRows, PortError> {
        if source.statement.as_str() != statement.statement.name
            || source.database != statement.database
            || source.path != statement.path
        {
            return Err(PortError::Denied);
        }
        let did = source
            .space
            .as_str()
            .parse()
            .map_err(|_| PortError::Denied)?;
        let name = self.space_name.parse().map_err(|_| PortError::Denied)?;
        let space = tinycloud_auth::resource::SpaceId::new(did, name);
        let mut params = Vec::with_capacity(source.arguments.len());
        for value in source.arguments.values() {
            params.push(SqlValue::Integer(value.get()));
        }
        let caveats = SqlCaveats {
            tables: None,
            columns: None,
            statements: Some(vec![PreparedStatement {
                name: statement.statement.name.clone(),
                sql: statement.statement.sql.clone(),
            }]),
            read_only: Some(true),
        };
        let result = self
            .service
            .execute(
                &space,
                source.database.as_str(),
                SqlRequest::ExecuteStatement {
                    name: source.statement.as_str().to_owned(),
                    params,
                },
                Some(caveats),
                "tinycloud.sql/read".to_owned(),
            )
            .await
            .map_err(|_| PortError::Storage)?;
        let SqlResponse::Query(query) = result.response else {
            return Err(PortError::Denied);
        };
        Ok(NamedSqlRows {
            columns: query.columns,
            rows: query.rows,
        })
    }
}

pub struct ShareEmailRuntime {
    pub config: ShareEmailConfig,
    /// Public trust metadata derived from the authenticated authority bundle.
    /// It never contains signing material.
    pub trust_descriptors: Vec<AuthorityTrustDescriptor>,
    pub host_trust_descriptors: Vec<ShareEmailHostTrustDescriptor>,
    pub state: ProtocolStateRepository,
    pub bridge: Arc<DatabaseAuthorityBridge117>,
    pub verifier: ExactEmailVerifier,
    pub invitation_verifier: Ed25519InvitationVerifier,
    pub signer: Ed25519InvitationSigner,
    pub data_plane: HolderBoundDataPlane<
        DatabaseAuthorityBridge117,
        MarkdownKvAdapter<TinyCloudKvStore>,
        MarkdownSqlAdapter<SqlNamedStore>,
    >,
    pub kv: TinyCloudKvStore,
    /// HMAC key derived from the node's configured secret. It is never
    /// serialized or exposed to the browser; cursors are opaque at the HTTP
    /// boundary and cannot be retargeted by changing their JSON fields.
    pub cursor_key: [u8; 32],
}

impl ShareEmailRuntime {
    pub fn host_trust_descriptors(&self) -> &[AuthorityTrustDescriptor] {
        &self.trust_descriptors
    }

    pub fn host_trust_bundle(&self) -> &[ShareEmailHostTrustDescriptor] {
        &self.host_trust_descriptors
    }

    pub fn capability(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: "tinycloud.node-policy-email-v1",
            version: 1,
            origin: self.config.target_origin.clone(),
            return_origin: self.config.return_origin.clone(),
            routes: NODE_CAPABILITY_ROUTES,
            content_kinds: ["kv", "sql"],
            mail_provider: "resend",
            status: "ready",
        }
    }
}

pub fn compose(
    config: ShareEmailConfig,
    conn: DatabaseConnection,
    key_setup: &tinycloud_core::keys::StaticSecret,
    tinycloud: Arc<TinyCloud>,
    sql_service: Arc<SqlService>,
) -> anyhow::Result<Option<ShareEmailRuntime>> {
    // v2 policy sharing is deliberately independent of the legacy v1
    // authority-material provider.  A v2-only node has no reason to load the
    // static tuple at all; leaving this surface absent keeps v1 compatibility
    // opt-in without making it a startup prerequisite for v2.
    if !config.enabled || config.authority_material_path.is_none() {
        return Ok(None);
    }
    config.validate().map_err(|e| anyhow::anyhow!(e))?;
    let issuer_bytes = config
        .issuer_public_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("share email issuer public key is required"))?;
    let issuer_public_key = decode_key32(issuer_bytes)?;
    let issuer = IssuerKey::new(
        config.issuer_did.clone(),
        config.issuer_vct.clone(),
        config.issuer_key_version,
        config.issuer_kid.clone(),
        issuer_public_key,
    );
    let trust = IssuerTrustRegistry::new([issuer])
        .map_err(|e| anyhow::anyhow!("issuer trust configuration: {e}"))?;
    let verifier = ExactEmailVerifier::new(
        trust,
        config.issuer_did.clone(),
        OffsetDateTime::now_utc().unix_timestamp(),
        config.clock_skew_seconds,
    );
    let invite_public_key = decode_key32(
        config
            .invitation_public_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("invitation public key is required"))?,
    )?;
    let invite_key =
        tinycloud_core::libp2p::identity::ed25519::PublicKey::try_from_bytes(&invite_public_key)
            .map_err(|_| anyhow::anyhow!("invalid invitation public key"))?;
    let invitation_verifier =
        Ed25519InvitationVerifier::new(config.invitation_kid.clone(), invite_key.into())
            .map_err(|e| anyhow::anyhow!("invitation verifier: {e}"))?;
    let signing_seed = key_setup.derive_key(b"tinycloud/share-email/invitation-signing");
    let signing_secret =
        tinycloud_core::libp2p::identity::ed25519::SecretKey::try_from_bytes(signing_seed)
            .map_err(|_| anyhow::anyhow!("invalid share email signing key"))?;
    let signing_ed25519 = tinycloud_core::libp2p::identity::ed25519::Keypair::from(signing_secret);
    if key_setup.share_invitation_public_key() != invite_public_key {
        return Err(anyhow::anyhow!(
            "configured invitation public key does not match the derived node signing key"
        ));
    }
    let root_signing_ed25519 = signing_ed25519.clone();
    let signer =
        Ed25519InvitationSigner::new(config.node_signing_kid.clone(), signing_ed25519.into())
            .map_err(|e| anyhow::anyhow!("share email signer: {e}"))?;
    let material_path = config
        .authority_material_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("share email authority material is required"))?;
    let material = Arc::new(
        AuthenticatedAuthorityMaterialProvider::from_path(material_path)
            .map_err(|_| anyhow::anyhow!("share email authority material is invalid"))?,
    );
    material
        .validate_node_trust(
            &config.target_origin,
            &config.node_audience,
            &config.invitation_kid,
            &invite_public_key,
        )
        .map_err(|_| anyhow::anyhow!("authority enrollment does not match node trust bundle"))?;
    let trust_descriptors = material.trust_descriptors();
    let host_trust_descriptors = trust_descriptors
        .iter()
        .cloned()
        .map(|authority| ShareEmailHostTrustDescriptor {
            authority,
            issuer_did: config.issuer_did.clone(),
            issuer_vct: config.issuer_vct.clone(),
            issuer_kid: config.issuer_kid.clone(),
            issuer_public_key: issuer_bytes.to_owned(),
        })
        .collect();
    let status_provider = Arc::new(material.status_provider());
    let attestation_provider = Arc::new(material.attestation_provider());
    let root_did =
        tinycloud_core::keys::public_key_to_did_key(root_signing_ed25519.public().into());
    let bridge = Arc::new(
        DatabaseAuthorityBridge117::new(conn.clone(), DatabaseAuthorityStore::new(conn.clone()))
            .with_authority_providers(material, status_provider, attestation_provider)
            .with_root_signer(Arc::new(
                tinycloud_core::policy_authority::ConfiguredNodeRootSigner::new(
                    root_did,
                    root_signing_ed25519,
                ),
            )),
    );
    // Sequence C supplies authenticated authority material, fresh status, and
    // attestation/enrollment providers. An enabled deployment with incomplete
    // evidence is a startup error; silently advertising an otherwise healthy
    // node without the share capability would hide a partial deployment.
    if !bridge.ready() {
        return Err(anyhow::anyhow!(
            "share email authority, status, attestation, or signer material is not ready"
        ));
    }
    let kv = TinyCloudKvStore {
        tinycloud,
        space_name: config.space_name.clone(),
    };
    let cursor_key = key_setup.derive_key(b"tinycloud/share-email/cursor");
    let sql = SqlNamedStore {
        service: sql_service,
        space_name: config.space_name.clone(),
    };
    let data_plane = HolderBoundDataPlane::new(
        bridge.clone(),
        Arc::new(MarkdownKvAdapter::new(Arc::new(kv.clone()))),
        Arc::new(MarkdownSqlAdapter::new(Arc::new(sql.clone()))),
    );
    Ok(Some(ShareEmailRuntime {
        state: ProtocolStateRepository::new(conn),
        config,
        trust_descriptors,
        host_trust_descriptors,
        bridge,
        verifier,
        invitation_verifier,
        signer,
        data_plane,
        kv,
        cursor_key,
    }))
}

fn decode_key32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = decode_config(value, URL_SAFE_NO_PAD)
        .map_err(|_| anyhow::anyhow!("key must be unpadded base64url"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must contain 32 bytes"))
}

fn digest(value: &Value) -> tinycloud_core::share_email::Sha256Digest {
    tinycloud_core::share_email::Sha256Digest::from_bytes(
        Sha256::digest(jcs::canonicalize(value)).into(),
    )
}

fn digest_text(value: &str) -> tinycloud_core::share_email::Sha256Digest {
    tinycloud_core::share_email::Sha256Digest::from_bytes(Sha256::digest(value.as_bytes()).into())
}

fn digest_bytes(value: &[u8]) -> tinycloud_core::share_email::Sha256Digest {
    tinycloud_core::share_email::Sha256Digest::from_bytes(Sha256::digest(value).into())
}

type CursorMac = Hmac<Sha256>;

fn cursor_mac(
    cursor: &ShareCursor,
    key: &[u8; 32],
) -> Result<tinycloud_core::share_email::Sha256Digest, ()> {
    let mut value = serde_json::to_value(cursor).map_err(|_| ())?;
    value.as_object_mut().ok_or(())?.remove("mac");
    let mut mac = CursorMac::new_from_slice(key).map_err(|_| ())?;
    mac.update(&jcs::canonicalize(&value));
    Ok(tinycloud_core::share_email::Sha256Digest::from_bytes(
        mac.finalize().into_bytes().into(),
    ))
}

fn seal_cursor(mut cursor: ShareCursor, key: &[u8; 32]) -> Result<ShareCursor, ()> {
    cursor.mac = Some(cursor_mac(&cursor, key)?);
    Ok(cursor)
}

fn verify_cursor(cursor: &ShareCursor, key: &[u8; 32]) -> Result<(), ()> {
    let expected = cursor_mac(cursor, key)?;
    let actual = cursor.mac.as_ref().ok_or(())?;
    if expected != *actual {
        return Err(());
    }
    Ok(())
}

fn direct_child_of(prefix: &Path, candidate: &Path) -> bool {
    let prefix = prefix.as_str();
    let candidate = candidate.as_str();
    let remainder = if prefix.is_empty() {
        candidate
    } else {
        candidate.strip_prefix(&format!("{prefix}/")).unwrap_or("")
    };
    !remainder.is_empty() && !remainder.contains('/')
}

fn same_or_descendant(prefix: &Path, candidate: &Path) -> bool {
    prefix.as_str().is_empty()
        || candidate.as_str() == prefix.as_str()
        || candidate
            .as_str()
            .strip_prefix(prefix.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn valid_signed_content_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && matches!(
            value,
            "text/plain"
                | "text/plain; charset=utf-8"
                | "text/markdown"
                | "text/markdown; charset=utf-8"
                | "application/octet-stream"
        )
}

fn parse_share_etag(value: &str) -> Result<[u8; 32], ()> {
    let value = value.trim();
    let digest = value
        .strip_prefix("\"blake3-")
        .and_then(|value| value.strip_suffix('\"'))
        .ok_or(())?;
    let bytes = hex::decode(digest).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn valid_delivery_provenance(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn validate_share_url(value: &str, share_cid: &ShareCid, return_origin: &str) -> bool {
    let prefix = format!("{return_origin}/s/{}#k=", share_cid.as_str());
    let Some(token) = value.strip_prefix(&prefix) else {
        return false;
    };
    !token.is_empty()
        && !token.contains(['?', '#', '/', '@', '&', '='])
        && !value.chars().any(char::is_whitespace)
        && decode_config(token, URL_SAFE_NO_PAD).is_ok_and(|bytes| bytes.len() == 32)
}

/// Compute a binding from the frozen canonical preimage. The digest field is
/// an output of the preimage, never an input to its own digest.
fn verify_canonical_body_digest(
    preimage: &Value,
    claimed: &tinycloud_core::share_email::Sha256Digest,
) -> Result<(), ()> {
    if digest(preimage) != *claimed {
        return Err(());
    }
    Ok(())
}

fn verify_request_body_digest(
    request: &Value,
    claimed: &tinycloud_core::share_email::Sha256Digest,
) -> Result<(), ()> {
    let mut preimage = request.clone();
    preimage
        .as_object_mut()
        .ok_or(())?
        .remove("requestBodyDigest")
        .ok_or(())?;
    verify_canonical_body_digest(&preimage, claimed)
}

fn invitation_request_body(request: &NodeInvitationAuthorizationRequest) -> Value {
    // V2 binds every request field. Keep the old compact preimage only for
    // legacy v1 exact-email callers; changing it would invalidate old links.
    if request.recipient_email.is_none() {
        let mut body = serde_json::to_value(request).expect("invitation request serializes");
        body.as_object_mut()
            .expect("invitation request is an object")
            .remove("requestBodyDigest");
        return body;
    }
    let (action, resource) = match &request.content_source {
        ContentSource::Kv { action, path, .. } => (action.as_str(), path.clone()),
        ContentSource::Sql { path, .. } => ("tinycloud.sql/read", path.clone()),
    };
    let mut body = json!({
        "shareCid": request.share_cid,
        "shareId": request.share_id,
        "policyCid": request.policy_cid,
        "delegationCid": request.delegation_cid,
        "authorityMaterialHandle": request.authority_material_handle,
        "authorityMaterialDigest": request.authority_material_digest,
        "targetOrigin": request.target_origin,
        "nodeAudience": request.node_audience,
        "action": action,
        "resource": request.resource.clone().unwrap_or(resource),
    });
    let object = body
        .as_object_mut()
        .expect("invitation request body is an object");
    if let Some(email) = &request.recipient_email {
        object.insert("recipientEmail".to_owned(), json!(email));
    } else {
        if let Some(matcher) = &request.recipient_matcher {
            object.insert("recipientMatcher".to_owned(), json!(matcher));
        }
        if let Some(email) = &request.delivery_email {
            object.insert("deliveryEmail".to_owned(), json!(email));
        }
        if let Some(share_url) = &request.share_url {
            object.insert("shareUrl".to_owned(), json!(share_url));
        }
    }
    if let Some(actions) = &request.actions {
        object.insert("actions".to_owned(), json!(actions));
    }
    body
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddressedDelegationAuthoringRequest {
    pub version: u8,
    pub nonce: ProtocolNonce,
    pub jti: ProtocolJti,
    pub sender_did: DidKey,
    pub recipient_matcher: RecipientMatcher,
    pub target_origin: TargetOrigin,
    pub node_audience: Did,
    pub share_cid: ShareCid,
    pub share_id: ShareId,
    pub delegation_cid: ShareDelegationCid,
    pub authority_material_handle: AuthorityMaterialHandle,
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    pub content_source: ContentSource,
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    pub actions: Vec<ShareAction>,
    pub resource: SharePolicyResource,
    pub expires_at: String,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddressedDelegationAuthoringEnvelope {
    pub request: AddressedDelegationAuthoringRequest,
    pub proof: DetachedProof,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AddressedDelegationAuthoringResponse {
    #[serde(rename = "type")]
    pub artifact_type: &'static str,
    pub version: u8,
    pub nonce: ProtocolNonce,
    pub jti: ProtocolJti,
    pub policy_cid: PolicyCid,
    pub policy_bytes: String,
    pub policy_digest: tinycloud_core::share_email::Sha256Digest,
    pub delegation_cid: ShareDelegationCid,
    pub delegation_bytes: String,
    pub delegation_digest: tinycloud_core::share_email::Sha256Digest,
    pub authority_material_handle: AuthorityMaterialHandle,
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    pub actions: Vec<ShareAction>,
    pub resource: SharePolicyResource,
    pub expires_at: String,
    pub proof: DetachedProof,
}

/// Keep legacy exact-email invitations wire-compatible while requiring the
/// generalized v2 shape for domain (and newly-created exact) invitations.
/// `deliveryEmail` is intentionally never used as the matcher.
fn validate_invitation_recipient(
    recipient_email: Option<&CanonicalEmail>,
    recipient_matcher: Option<&RecipientMatcher>,
    delivery_email: Option<&CanonicalEmail>,
    policy_matcher: &RecipientMatcher,
) -> Result<(), ()> {
    match (recipient_email, recipient_matcher, delivery_email) {
        (Some(email), None, None)
            if matches!(policy_matcher, RecipientMatcher::ExactEmail(_))
                && policy_matcher.matches_verified_email(email.as_str()) =>
        {
            Ok(())
        }
        (None, Some(matcher), delivery)
            if matcher.canonical().is_ok()
                && matcher.canonical().ok() == policy_matcher.canonical().ok()
                && delivery
                    .is_none_or(|email| policy_matcher.matches_verified_email(email.as_str())) =>
        {
            Ok(())
        }
        _ => Err(()),
    }
}

/// Read requests carry the body binding both at the HTTP wrapper and inside
/// the signed invocation.  Recompute it from the complete frozen preimage so
/// changing both caller copies cannot create a new authorized binding.
fn verify_read_request_body_digest(
    request: &Value,
    outer_claimed: &tinycloud_core::share_email::Sha256Digest,
    invocation_claimed: &tinycloud_core::share_email::Sha256Digest,
) -> Result<(), ()> {
    let mut preimage = request.clone();
    let object = preimage.as_object_mut().ok_or(())?;
    object.remove("proof");
    object.remove("requestBodyDigest").ok_or(())?;
    let invocation = object
        .get_mut("invocation")
        .and_then(Value::as_object_mut)
        .ok_or(())?;
    invocation.remove("requestBodyDigest").ok_or(())?;
    let computed = digest(&preimage);
    if computed != *outer_claimed || computed != *invocation_claimed {
        return Err(());
    }
    Ok(())
}

fn timestamp(value: OffsetDateTime) -> String {
    let format = time::format_description::parse(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
    )
    .expect("share-email timestamp format is fixed");
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&format)
        .expect("share-email timestamp is UTC")
}

fn verify_did_key_signature(
    signer: &DidKey,
    proof: &DetachedProof,
    domain: &[u8],
    message: &Value,
) -> Result<(), ()> {
    if proof.alg != "EdDSA"
        || proof.kid
            != format!(
                "{}#{}",
                signer.as_str(),
                signer.as_str().trim_start_matches("did:key:")
            )
    {
        return Err(());
    }
    let encoded = signer.as_str().strip_prefix("did:key:").ok_or(())?;
    let (_, bytes) = tinycloud_auth::ipld_core::cid::multibase::decode(encoded).map_err(|_| ())?;
    let key_bytes = match bytes.as_slice() {
        [0xed, 0x01, rest @ ..] if rest.len() == 32 => rest,
        _ => return Err(()),
    };
    let key = tinycloud_core::libp2p::identity::ed25519::PublicKey::try_from_bytes(key_bytes)
        .map_err(|_| ())?;
    let signature = decode_config(&proof.signature, URL_SAFE_NO_PAD).map_err(|_| ())?;
    if signature.len() != 64 {
        return Err(());
    }
    let mut signed = domain.to_vec();
    signed.extend(jcs::canonicalize(message));
    if key.verify(&signed, &signature) {
        Ok(())
    } else {
        Err(())
    }
}

fn scope_from_request(
    request: &PolicyChallengeRequest,
    config: &ShareEmailConfig,
) -> Result<ShareScope, ()> {
    validate_action_set(request.actions.as_deref(), request.action)?;
    if !matches!(
        (&request.action, &request.content_source),
        (
            ShareAction::KvGet | ShareAction::KvList | ShareAction::KvPut,
            ContentSource::Kv { .. }
        ) | (ShareAction::SqlRead, ContentSource::Sql { .. })
    ) {
        return Err(());
    }
    let source_path = match &request.content_source {
        ContentSource::Kv { path, .. } | ContentSource::Sql { path, .. } => path,
    };
    let source_action = match &request.content_source {
        ContentSource::Kv { action, .. } => match action {
            tinycloud_core::share_email::types::KvGetAction::Get => ShareAction::KvGet,
            tinycloud_core::share_email::types::KvGetAction::List => ShareAction::KvList,
            tinycloud_core::share_email::types::KvGetAction::Put => ShareAction::KvPut,
        },
        ContentSource::Sql { .. } => ShareAction::SqlRead,
    };
    let legacy_exact_shape = source_action == request.action && request.resource == *source_path;
    // v1 binds action and resource directly to the source.  v2 keeps the
    // source as an immutable ceiling and signs the requested action/resource
    // independently, so a child can be read or edited after listing.
    if !legacy_exact_shape && !matches!(request.content_source, ContentSource::Kv { .. }) {
        return Err(());
    }
    validate_share_path(source_path, true).map_err(|_| ())?;
    let requested_resource = if request.action == ShareAction::KvList {
        Path::parse(request.resource.as_str().trim_end_matches('/').to_owned()).map_err(|_| ())?
    } else {
        request.resource.clone()
    };
    validate_share_path(&requested_resource, request.action == ShareAction::KvList)
        .map_err(|_| ())?;
    let resource = match &request.content_source {
        ContentSource::Kv { .. } if request.action == ShareAction::KvList => {
            // V2 list attenuation is governed by the signed policy prefix.
            // The content source identifies the space/source ceiling; it is
            // not an implicit equality constraint on the requested folder.
            if request.actions.is_none() && requested_resource != *source_path {
                return Err(());
            }
            ExactResource::KvPrefix {
                path: requested_resource.clone(),
            }
        }
        ContentSource::Kv { .. } => {
            if !same_or_descendant(source_path, &requested_resource) {
                return Err(());
            }
            ExactResource::Kv {
                path: requested_resource.clone(),
            }
        }
        ContentSource::Sql {
            database,
            path,
            statement,
            ..
        } => ExactResource::Sql {
            database: database.clone(),
            path: path.clone(),
            statement: statement.clone(),
        },
    };
    let expected = digest(&serde_json::to_value(&request.content_source).map_err(|_| ())?);
    if let ContentSource::Sql {
        arguments,
        arguments_digest,
        ..
    } = &request.content_source
    {
        if digest(&serde_json::to_value(arguments).map_err(|_| ())?) != *arguments_digest {
            return Err(());
        }
    }
    let resource_matches = match &request.content_source {
        ContentSource::Kv { .. } => true,
        ContentSource::Sql {
            database,
            path,
            statement,
            ..
        } => {
            matches!(
                &resource,
                ExactResource::Sql {
                    database: resource_database,
                    path: resource_path,
                    statement: resource_statement,
                } if resource_database == database
                    && resource_path == path
                    && resource_statement == statement
            ) && requested_resource == *path
        }
    };
    if expected != request.content_source_digest
        || !resource_matches
        || request.target_origin.as_str() != config.target_origin
        || request.node_audience.as_str() != config.node_audience
        || request
            .actions
            .as_deref()
            .is_some_and(|actions| actions.is_empty())
    {
        return Err(());
    }
    Ok(ShareScope {
        share_cid: request.share_cid.clone(),
        share_id: request.share_id.clone(),
        delegation_cid: Some(request.delegation_cid.clone()),
        authority_material_handle: request.authority_material_handle.clone(),
        authority_material_digest: request.authority_material_digest.clone(),
        policy_cid: request.policy_cid.clone(),
        node_audience: request.node_audience.clone(),
        target_origin: request.target_origin.clone(),
        action: request.action,
        allowed_actions: request
            .actions
            .clone()
            .unwrap_or_else(|| vec![request.action]),
        resource,
        content_source: request.content_source.clone(),
        content_source_digest: request.content_source_digest.clone(),
    })
}

/// V2 action attenuation is an ordered, duplicate-free set.  V1 omits the
/// field and keeps its single action binding unchanged.
fn validate_action_set(actions: Option<&[ShareAction]>, selected: ShareAction) -> Result<(), ()> {
    let Some(actions) = actions else {
        return Ok(());
    };
    if actions.is_empty()
        || !actions.contains(&selected)
        || actions
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(());
    }
    Ok(())
}

fn scope_from_presentation(
    p: &PolicyPresentation,
    config: &ShareEmailConfig,
) -> Result<ShareScope, ()> {
    let request = PolicyChallengeRequest {
        share_cid: p.share_cid.clone(),
        share_id: p.share_id.clone(),
        delegation_cid: p.delegation_cid.clone(),
        authority_material_handle: p.authority_material_handle.clone(),
        authority_material_digest: p.authority_material_digest.clone(),
        policy_cid: p.policy_cid.clone(),
        content_source: p.content_source.clone(),
        content_source_digest: p.content_source_digest.clone(),
        holder_did: p.holder_did.clone(),
        target_origin: p.target_origin.clone(),
        node_audience: p.node_audience.clone(),
        action: p.action,
        actions: p.actions.clone(),
        resource: p.resource.clone(),
        request_body_digest: p.request_body_digest.clone(),
    };
    let request_value = serde_json::to_value(&request).map_err(|_| ())?;
    verify_request_body_digest(&request_value, &p.request_body_digest)?;
    scope_from_request(&request, config)
}

fn holder_request_from_wire(
    request: ReadRequest,
    config: &ShareEmailConfig,
) -> Result<(HolderReadRequest, ShareScope), Custom<Json<ApiErrorBody>>> {
    let i = request.invocation.clone();
    if i.artifact_type != "TinyCloudShareReadInvocation" || i.version != 2 {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let scope = scope_from_request(
        &PolicyChallengeRequest {
            share_cid: i.share_cid.clone(),
            share_id: i.share_id.clone(),
            delegation_cid: i.delegation_cid.clone(),
            authority_material_handle: request.authority_material_handle.clone(),
            authority_material_digest: request.authority_material_digest.clone(),
            policy_cid: i.policy_cid.clone(),
            content_source: i.content_source.clone(),
            content_source_digest: i.content_source_digest.clone(),
            holder_did: i.holder_did.clone(),
            target_origin: i.target_origin.clone(),
            node_audience: i.node_audience.clone(),
            action: i.action,
            actions: i.actions.clone(),
            resource: i.resource.clone(),
            request_body_digest: i.request_body_digest.clone(),
        },
        config,
    )
    .map_err(|_| error(Status::Forbidden, "read_denied"))?;
    let request_value =
        serde_json::to_value(&request).map_err(|_| error(Status::BadRequest, "read_denied"))?;
    verify_read_request_body_digest(
        &request_value,
        &request.request_body_digest,
        &i.request_body_digest,
    )
    .map_err(|_| error(Status::Forbidden, "read_denied"))?;
    if request.session_id != i.session_id
        || request.delegation_cid != i.delegation_cid
        || request.authority_material_handle != i.authority_material_handle
        || request.authority_material_digest != i.authority_material_digest
        || request.content_source != i.content_source
        || request.content_source_digest != i.content_source_digest
        || request.action != i.action
        || request.actions != i.actions
        || request.resource != i.resource
        || request.request_body_digest != i.request_body_digest
    {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let issued = OffsetDateTime::parse(&i.issued_at, &Rfc3339)
        .map_err(|_| error(Status::Forbidden, "read_denied"))?;
    let expires = OffsetDateTime::parse(&i.expires_at, &Rfc3339)
        .map_err(|_| error(Status::Forbidden, "read_denied"))?;
    let signature = decode_config(&request.proof.signature, URL_SAFE_NO_PAD)
        .map_err(|_| error(Status::Forbidden, "invalid_holder_proof"))?;
    if request.proof.alg != "EdDSA"
        || request.proof.kid
            != format!(
                "{}#{}",
                i.holder_did.as_str(),
                i.holder_did.as_str().trim_start_matches("did:key:")
            )
        || signature.len() != 64
    {
        return Err(error(Status::Forbidden, "invalid_holder_proof"));
    }
    let proof = HolderReadProof {
        issued_at: issued,
        expires_at: expires,
        jti: i.jti.clone(),
        signer: i.holder_did.clone(),
        signature,
    };
    Ok((
        HolderReadRequest {
            version: i.version,
            session: i.session_id,
            jti: i.jti,
            scope: scope.clone(),
            holder: i.holder_did,
            request_body_digest: i.request_body_digest,
            limit: i.limit,
            cursor: i.cursor,
            body_digest: i.body_digest,
            if_match: i.if_match,
            content_type: i.content_type,
            proof,
        },
        scope,
    ))
}

/// Native share transport on the existing `/invoke` path. The media type is
/// deliberately distinct so the ordinary UCAN invocation route remains
/// backward compatible while policy sessions use the same production path.
#[post(
    "/invoke",
    rank = 2,
    format = "application/vnd.tinycloud.share+json",
    data = "<data>"
)]
pub async fn native_invoke(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
    staging: &State<crate::BlockStage>,
    tinycloud: &State<TinyCloud>,
    cursor_header: ShareCursorHeader,
    if_match_header: IfMatchHeader,
    _origin: ShareOriginGuard,
) -> Result<NativeJson<Value>, Custom<Json<ApiErrorBody>>> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let envelope: NativeInvokeEnvelope = serde_json::from_value(
        read_bounded_json_with_limit(
            data,
            tinycloud_core::share_email::MAX_NATIVE_ENCODED_REQUEST_BYTES,
        )
        .await?,
    )
    .map_err(|_| error(Status::BadRequest, "read_denied"))?;
    let invocation = &envelope.request.invocation;
    if invocation.version != 2 || invocation.actions.is_none() {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    if envelope.limit != invocation.limit
        || envelope.cursor != invocation.cursor
        || envelope.body_digest != invocation.body_digest
        || envelope.if_match != invocation.if_match
        || envelope.content_type != invocation.content_type
    {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let limit = envelope.limit.unwrap_or(100).min(1000);
    if limit == 0 {
        return Err(error(Status::BadRequest, "read_denied"));
    }
    let (holder_request, scope) =
        holder_request_from_wire(envelope.request.clone(), &runtime.config)?;
    if cursor_header.0.is_some() && envelope.cursor.as_deref() != cursor_header.0.as_deref() {
        return Err(error(Status::BadRequest, "invalid_cursor"));
    }
    let header_cursor = cursor_header.0.as_deref();
    let now = OffsetDateTime::now_utc();
    match scope.action {
        ShareAction::KvGet => {
            if invocation.limit.is_some()
                || invocation.cursor.is_some()
                || invocation.body_digest.is_some()
                || invocation.if_match.is_some()
                || invocation.content_type.is_some()
                || envelope.body.is_some()
            {
                return Err(error(Status::Forbidden, "read_denied"));
            }
            let _authorized = runtime
                .data_plane
                .authorize(holder_request, now)
                .await
                .map_err(|failure| {
                    tracing::error!(failure = ?failure, "native share authorization denied");
                    error(Status::Forbidden, "read_denied")
                })?;
            let (bytes, media_type) = match &scope.content_source {
                ContentSource::Kv { space, .. } => runtime
                    .kv
                    .get_exact_bytes(
                        space,
                        match &scope.resource {
                            ExactResource::Kv { path } => path,
                            _ => return Err(error(Status::Forbidden, "read_denied")),
                        },
                    )
                    .await
                    .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
                    .ok_or(error(Status::NotFound, "content_not_found"))?,
                ContentSource::Sql { .. } => {
                    return Err(error(Status::BadRequest, "unsupported_action"));
                }
            };
            let body_digest = digest_bytes(&bytes);
            let etag = match &scope.content_source {
                ContentSource::Kv { space, .. } => runtime
                    .kv
                    .current_etag(
                        space,
                        match &scope.resource {
                            ExactResource::Kv { path } => path,
                            _ => return Err(error(Status::Forbidden, "read_denied")),
                        },
                    )
                    .await
                    .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?,
                ContentSource::Sql { .. } => None,
            };
            Ok(NativeJson(
                json!({
                    "type": "TinyCloudShareInvokeResponse",
                    "version": 2,
                    "action": ShareAction::KvGet,
                    "resource": invocation.resource,
                    "mediaType": media_type,
                    "content": encode_config(&bytes, URL_SAFE_NO_PAD),
                    "bodyDigest": body_digest,
                    "etag": etag.clone(),
                }),
                etag.map(|value| Header::new("ETag", value)),
            ))
        }
        ShareAction::KvList => {
            if invocation.limit.is_none()
                || envelope.body.is_some()
                || invocation.body_digest.is_some()
                || invocation.if_match.is_some()
                || invocation.content_type.is_some()
            {
                return Err(error(Status::Forbidden, "read_denied"));
            }
            let prefix = match &scope.resource {
                ExactResource::KvPrefix { path } => path,
                _ => return Err(error(Status::Forbidden, "read_denied")),
            };
            let cursor = envelope
                .cursor
                .as_deref()
                .or(header_cursor)
                .map(ShareCursor::decode)
                .transpose()
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            if let Some(cursor) = &cursor {
                if verify_cursor(cursor, &runtime.cursor_key).is_err()
                    || !cursor.matches(&scope, &holder_request.holder, limit)
                    || !direct_child_of(prefix, &cursor.last)
                {
                    return Err(error(Status::Forbidden, "invalid_cursor"));
                }
            }
            let holder = holder_request.holder.clone();
            runtime
                .data_plane
                .authorize(holder_request, now)
                .await
                .map_err(|_| error(Status::Forbidden, "read_denied"))?;
            let (paths, truncated, next) = runtime
                .kv
                .list_direct_children(
                    prefix_space(&scope)?,
                    prefix,
                    limit,
                    cursor.as_ref().map(|c| &c.last),
                )
                .await
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
            let mut seen = BTreeSet::new();
            if paths.iter().any(|entry| {
                !direct_child_of(prefix, &entry.path)
                    || !seen.insert(entry.path.as_str().to_owned())
            }) || next
                .as_ref()
                .is_some_and(|path| !direct_child_of(prefix, path))
            {
                return Err(error(Status::ServiceUnavailable, "capability_unavailable"));
            }
            let next_cursor = truncated
                .then_some(next)
                .flatten()
                .map(|last| {
                    seal_cursor(
                        ShareCursor::new(&scope, &holder, limit, last),
                        &runtime.cursor_key,
                    )
                    .and_then(|cursor| cursor.encode().map_err(|_| ()))
                })
                .transpose()
                .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
            Ok(NativeJson(
                json!({
                    "type": "TinyCloudShareInvokeResponse",
                    "version": 2,
                    "action": ShareAction::KvList,
                    "resource": invocation.resource,
                    "entries": paths,
                    "nextCursor": next_cursor.clone(),
                }),
                next_cursor
                    .clone()
                    .map(|value| Header::new("x-tinycloud-next-cursor", value)),
            ))
        }
        ShareAction::KvPut => {
            let ExactResource::Kv { path } = &scope.resource else {
                return Err(error(Status::Forbidden, "read_denied"));
            };
            let encoded = envelope
                .body
                .as_deref()
                .ok_or(error(Status::BadRequest, "edit_body_missing"))?;
            let bytes = decode_config(encoded, URL_SAFE_NO_PAD)
                .map_err(|_| error(Status::BadRequest, "edit_body_invalid"))?;
            if bytes.len() > tinycloud_core::share_email::MAX_NATIVE_SHARE_CONTENT_BYTES {
                return Err(error(Status::PayloadTooLarge, "edit_body_invalid"));
            }
            if invocation.body_digest.as_ref() != Some(&digest_bytes(&bytes)) {
                return Err(error(Status::BadRequest, "edit_body_invalid"));
            }
            // Check a stale CAS before consuming the single-use holder JTI.
            // A genuinely stale signed write must surface the storage
            // precondition result (412), including when the harness or a
            // client retries the captured request after a competing write;
            // it must not be misreported as a replay denial.
            let expected_wire = if_match_header
                .0
                .as_deref()
                .or(invocation.if_match.as_deref())
                .ok_or(error(Status::BadRequest, "if_match_required"))?;
            if let ContentSource::Kv { space, .. } = &scope.content_source {
                let path = match &scope.resource {
                    ExactResource::Kv { path } => path,
                    _ => return Err(error(Status::Forbidden, "read_denied")),
                };
                let current = runtime
                    .kv
                    .current_etag(space, path)
                    .await
                    .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
                if current.as_deref() != Some(expected_wire) {
                    return Err(error(Status::PreconditionFailed, "edit_conflict"));
                }
            }
            if if_match_header.0.is_some()
                && envelope.if_match.is_some()
                && if_match_header.0 != envelope.if_match
            {
                return Err(error(Status::BadRequest, "if_match_mismatch"));
            }
            let expected = if_match_header
                .0
                .as_deref()
                .or(invocation.if_match.as_deref())
                .ok_or(error(Status::BadRequest, "if_match_required"))
                .and_then(|value| {
                    parse_share_etag(value)
                        .map_err(|_| error(Status::BadRequest, "invalid_if_match"))
                })?;
            let did = match &scope.content_source {
                ContentSource::Kv { space, .. } => space,
                ContentSource::Sql { .. } => return Err(error(Status::Forbidden, "read_denied")),
            };
            let name = runtime
                .config
                .space_name
                .parse()
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
            let space = tinycloud_auth::resource::SpaceId::new(
                did.as_str()
                    .parse()
                    .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?,
                name,
            );
            let auth_path = path
                .as_str()
                .parse()
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
            runtime
                .data_plane
                .authorize(holder_request, now)
                .await
                .map_err(|_| error(Status::Forbidden, "read_denied"))?;
            let mut stage = staging
                .stage(&space)
                .await
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
            stage
                .write_all(&bytes)
                .await
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
            stage
                .flush()
                .await
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
            let mut metadata = BTreeMap::new();
            metadata.insert(
                "content-type".to_owned(),
                invocation
                    .content_type
                    .as_deref()
                    .filter(|value| valid_signed_content_type(value))
                    .ok_or(error(Status::BadRequest, "edit_content_type_invalid"))?
                    .to_owned(),
            );
            let hash = tinycloud
                .invoke_internal_kv_put::<crate::BlockStage>(
                    space,
                    auth_path,
                    tinycloud_core::types::Metadata(metadata),
                    stage,
                    Some(tinycloud_core::KvPrecondition::Matches(expected)),
                )
                .await
                .map_err(|e| match e {
                    tinycloud_core::TxStoreError::KvPreconditionFailed => {
                        error(Status::PreconditionFailed, "edit_conflict")
                    }
                    other => {
                        tracing::error!(failure = %other, "native share KV put failed");
                        error(Status::ServiceUnavailable, "capability_unavailable")
                    }
                })?;
            let etag = format!("\"blake3-{}\"", hex::encode(hash.as_ref()));
            Ok(NativeJson(
                json!({
                    "type": "TinyCloudShareInvokeResponse",
                    "version": 2,
                    "action": ShareAction::KvPut,
                    "resource": invocation.resource,
                    "etag": etag.clone(),
                    "bodyDigest": digest_bytes(&bytes),
                    "contentType": invocation.content_type,
                }),
                Some(Header::new("ETag", etag.clone())),
            ))
        }
        ShareAction::KvMetadata | ShareAction::SqlRead => {
            Err(error(Status::BadRequest, "unsupported_action"))
        }
    }
}

fn prefix_space(scope: &ShareScope) -> Result<&Did, Custom<Json<ApiErrorBody>>> {
    match &scope.content_source {
        ContentSource::Kv { space, .. } => Ok(space),
        ContentSource::Sql { .. } => Err(error(Status::Forbidden, "read_denied")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NodeInvitationAuthorizationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    pub jti: ProtocolJti,
    pub report_abuse_token: ProtocolJti,
    pub sender_did: DidKey,
    pub share_cid: ShareCid,
    pub share_id: ShareId,
    pub delegation_cid: ShareDelegationCid,
    #[serde(rename = "authorityMaterialHandle")]
    pub authority_material_handle: AuthorityMaterialHandle,
    #[serde(rename = "authorityMaterialDigest")]
    pub authority_material_digest: tinycloud_core::share_email::Sha256Digest,
    pub policy_cid: PolicyCid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_email: Option<CanonicalEmail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_matcher: Option<RecipientMatcher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_email: Option<CanonicalEmail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_provenance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ShareAction>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Path>,
    pub target_origin: TargetOrigin,
    pub node_audience: Did,
    pub document_name: DocumentName,
    pub sender_trust: SenderTrust,
    pub content_source: ContentSource,
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    pub share_expires_at: String,
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeInvitationAuthorizationEnvelope {
    pub request: NodeInvitationAuthorizationRequest,
    pub proof: DetachedProof,
}

#[post("/share/v1/invitations/authorize", format = "json", data = "<data>")]
pub async fn authorize_invitation(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
    _origin: ShareOriginGuard,
) -> ApiResult<Value> {
    let value = read_bounded_json(data).await?;
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let envelope: NodeInvitationAuthorizationEnvelope = serde_json::from_value(value.clone())
        .map_err(|_| error(Status::BadRequest, "invitation_authorization_invalid"))?;
    let request = envelope.request;
    let is_v2 = request.recipient_matcher.is_some();
    if (is_v2 && request.version != Some(2)) || (!is_v2 && request.version.is_some()) {
        return Err(error(
            Status::BadRequest,
            "invitation_authorization_invalid",
        ));
    }
    if request.recipient_matcher.is_none() != request.share_url.is_none()
        || (is_v2 && (request.actions.is_none() || request.resource.is_none()))
    {
        return Err(error(Status::Forbidden, "invitation_authorization_invalid"));
    }
    if is_v2
        && (!request.share_url.as_deref().is_some_and(|value| {
            validate_share_url(value, &request.share_cid, &runtime.config.return_origin)
        }) || request
            .delivery_provenance
            .as_deref()
            .is_some_and(|value| !valid_delivery_provenance(value)))
    {
        return Err(error(Status::Forbidden, "invitation_authorization_invalid"));
    }
    let signed_value = serde_json::to_value(&request)
        .map_err(|_| error(Status::BadRequest, "invitation_authorization_invalid"))?;
    verify_did_key_signature(
        &request.sender_did,
        &envelope.proof,
        b"xyz.tinycloud.share/invite-authorization/v1\0",
        &signed_value,
    )
    .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let authorization_body = invitation_request_body(&request);
    verify_canonical_body_digest(&authorization_body, &request.request_body_digest)
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let scope_request = PolicyChallengeRequest {
        share_cid: request.share_cid.clone(),
        share_id: request.share_id.clone(),
        delegation_cid: request.delegation_cid.clone(),
        authority_material_handle: request.authority_material_handle.clone(),
        authority_material_digest: request.authority_material_digest.clone(),
        policy_cid: request.policy_cid.clone(),
        content_source: request.content_source.clone(),
        content_source_digest: request.content_source_digest.clone(),
        holder_did: request.sender_did.clone(),
        target_origin: request.target_origin.clone(),
        node_audience: request.node_audience.clone(),
        action: match &request.content_source {
            ContentSource::Kv { action, path, .. } => match action {
                tinycloud_core::share_email::types::KvGetAction::Get
                    if request
                        .actions
                        .as_ref()
                        .is_some_and(|actions| actions.contains(&ShareAction::KvList))
                        && request.resource.as_ref() == Some(path) =>
                {
                    ShareAction::KvList
                }
                tinycloud_core::share_email::types::KvGetAction::Get => ShareAction::KvGet,
                tinycloud_core::share_email::types::KvGetAction::List => ShareAction::KvList,
                tinycloud_core::share_email::types::KvGetAction::Put => ShareAction::KvPut,
            },
            ContentSource::Sql { .. } => ShareAction::SqlRead,
        },
        actions: request.actions.clone(),
        resource: match &request.content_source {
            ContentSource::Kv { path, .. } | ContentSource::Sql { path, .. } => {
                request.resource.clone().unwrap_or_else(|| path.clone())
            }
        },
        request_body_digest: request.request_body_digest.clone(),
    };
    let scope = scope_from_request(&scope_request, &runtime.config)
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let now = OffsetDateTime::now_utc();
    runtime
        .bridge
        .validate_scope(&scope, now)
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    runtime
        .bridge
        .validate_sender_for_policy(
            request.policy_cid.as_str(),
            request.delegation_cid.as_str(),
            &request.authority_material_handle,
            &request.authority_material_digest,
            request.sender_did.as_str(),
        )
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let (_policy_sender, policy_matcher, policy_expiry) = runtime
        .bridge
        .policy_sender_recipient_and_expiry(
            request.policy_cid.as_str(),
            request.delegation_cid.as_str(),
            &request.authority_material_handle,
            &request.authority_material_digest,
            now,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    validate_invitation_recipient(
        request.recipient_email.as_ref(),
        request.recipient_matcher.as_ref(),
        request.delivery_email.as_ref(),
        &policy_matcher,
    )
    .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    if request.target_origin.as_str() != runtime.config.target_origin
        || request.node_audience.as_str() != runtime.config.node_audience
        || OffsetDateTime::parse(&request.share_expires_at, &Rfc3339).ok() != Some(policy_expiry)
    {
        return Err(error(Status::Forbidden, "invitation_authorization_invalid"));
    }
    if request.recipient_email.is_none()
        && (request.sender_trust != SenderTrust::Verified
            || request.idempotency_key.as_deref().is_none())
    {
        return Err(error(Status::Forbidden, "invitation_authorization_invalid"));
    }
    let receipt = issue_invitation_authorization_for(
        InvitationAuthorizationInput {
            jti: request.jti,
            report_abuse_token: request.report_abuse_token,
            sender_did: Did::parse(request.sender_did.as_str())
                .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?,
            share_cid: request.share_cid,
            share_id: request.share_id,
            policy_cid: request.policy_cid,
            delegation_cid: request.delegation_cid,
            authority_material_handle: request.authority_material_handle,
            authority_material_digest: request.authority_material_digest,
            recipient_email: request.recipient_email,
            recipient_matcher: request.recipient_matcher,
            delivery_email: request.delivery_email,
            delivery_provenance: request.delivery_provenance,
            share_url: request.share_url,
            actions: request.actions,
            resource: request.resource,
            target_origin: request.target_origin,
            node_audience: request.node_audience,
            document_name: request.document_name,
            sender_trust: request.sender_trust,
            content_source: request.content_source,
            content_source_digest: request.content_source_digest,
            share_expires_at: request.share_expires_at,
            request_body_digest: request.request_body_digest,
            idempotency_key: request.idempotency_key,
        },
        &runtime.signer,
        now,
        TargetOrigin::parse(&runtime.config.target_origin)
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?,
        Did::parse(&runtime.config.node_audience)
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?,
        TargetOrigin::parse(&runtime.config.return_origin)
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?,
    )
    .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let auth_digest = tinycloud_core::share_email::invitation::authorization_digest(&receipt)
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let binding = json!({
        "authorizationDigest": auth_digest.as_str(),
        "shareDigest": digest(&json!(receipt.authorization.share_cid.as_str())).as_str(),
        "idempotencyKey": receipt.authorization.idempotency_key,
    });
    runtime
        .state
        .reserve_invitation_authorization(&receipt, binding, &auth_digest, now)
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    Ok(Json(serde_json::to_value(receipt).map_err(|_| {
        error(Status::InternalServerError, "capability_unavailable")
    })?))
}

#[post("/share/v1/policy/challenges", format = "json", data = "<data>")]
pub async fn policy_challenge(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
    _origin: ShareOriginGuard,
    client_ip: crate::routes::public::ClientIp,
) -> ApiResult<Value> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let request: PolicyChallengeRequest = serde_json::from_value(read_bounded_json(data).await?)
        .map_err(|_| error(Status::BadRequest, "invalid_content_source"))?;
    let request_body_bytes = serde_json::to_vec(&request)
        .map_err(|_| generic("invalid_content_source"))?
        .len();
    if request_body_bytes > tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES {
        return Err(error(Status::PayloadTooLarge, "invalid_content_source"));
    }
    let request_value =
        serde_json::to_value(&request).map_err(|_| generic("invalid_content_source"))?;
    verify_request_body_digest(&request_value, &request.request_body_digest)
        .map_err(|_| generic("invalid_content_source"))?;
    let scope = scope_from_request(&request, &runtime.config)
        .map_err(|_| generic("invalid_content_source"))?;
    let now = OffsetDateTime::now_utc();
    runtime
        .bridge
        .validate_scope(&scope, now)
        .await
        .map_err(|_| generic("policy_denied"))?;
    let enforcer_did = runtime
        .bridge
        .enforcer_did_for(
            request.policy_cid.as_str(),
            request.delegation_cid.as_str(),
            &request.authority_material_handle,
            &request.authority_material_digest,
            &scope.node_audience,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    let challenge_id = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let nonce = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let expires = now + Duration::seconds(runtime.config.challenge_ttl_seconds as i64);
    // The challenge state binds the digest of the frozen challenge request
    // preimage. Presentation reuses this value and the transactional bridge
    // checks it against the one-time challenge row.
    let request_digest = request.request_body_digest.clone();
    let binding = json!({"requestDigest": request_digest.as_str()});
    let challenge = PolicyChallenge {
        artifact_type: "TinyCloudSharePolicyChallenge".to_owned(),
        version: 1,
        challenge_id: challenge_id.clone(),
        nonce: nonce.clone(),
        share_cid: request.share_cid,
        share_id: request.share_id,
        delegation_cid: request.delegation_cid,
        authority_material_handle: request.authority_material_handle,
        authority_material_digest: request.authority_material_digest,
        policy_cid: request.policy_cid,
        content_source: request.content_source,
        content_source_digest: request.content_source_digest,
        holder_did: request.holder_did,
        target_origin: request.target_origin,
        node_audience: request.node_audience,
        enforcer_did,
        action: request.action,
        actions: request.actions,
        resource: request.resource,
        request_body_digest: request.request_body_digest,
        issued_at: timestamp(now),
        expires_at: timestamp(expires),
    };
    let challenge_value = serde_json::to_value(&challenge)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    let proof = sign(&runtime.signer, POLICY_CHALLENGE_DOMAIN, &challenge_value)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    let origin_digest = digest(&json!(scope.target_origin.as_str()));
    let ip_digest = digest(&json!(client_ip.0.to_string()));
    let share_digest = digest(&json!(scope.share_cid.as_str()));
    let nonce_hash = digest_text(nonce.as_str());
    runtime
        .state
        .create_anonymous_challenge(
            AnonymousChallengeRequest {
                challenge_id: challenge_id.as_str().to_owned(),
                request_digest: request_digest.as_str().to_owned(),
                binding_json: binding,
                origin_digest: origin_digest.as_str().to_owned(),
                ip_digest: ip_digest.as_str().to_owned(),
                share_digest: share_digest.as_str().to_owned(),
                nonce_hash: nonce_hash.as_str().to_owned(),
                issued_at: now,
                expires_at: expires,
                body_bytes: request_body_bytes,
                origin_limit: 120,
                ip_limit: 240,
                share_limit: 60,
            },
            now,
        )
        .await
        .map_err(|state_error| match state_error {
            StateError::Storage => error(Status::ServiceUnavailable, "capability_unavailable"),
            StateError::Invalid => error(Status::BadRequest, "invalid_content_source"),
            StateError::BodyTooLarge => error(Status::PayloadTooLarge, "invalid_content_source"),
            StateError::QuotaExceeded => error(Status::TooManyRequests, "rate_limited"),
            StateError::Replay => error(Status::Conflict, "policy_challenge_replayed"),
            StateError::Expired => error(Status::Gone, "policy_challenge_expired"),
        })?;
    Ok(Json(json!({"challenge":challenge_value,"proof":proof})))
}

fn sign(
    signer: &Ed25519InvitationSigner,
    domain: &[u8],
    message: &Value,
) -> Result<DetachedProof, ()> {
    let mut bytes = domain.to_vec();
    bytes.extend(jcs::canonicalize(message));
    let signature = signer.sign(&bytes).map_err(|_| ())?;
    Ok(DetachedProof {
        alg: "EdDSA".to_owned(),
        kid: signer.kid().to_owned(),
        signature: encode_config(signature, URL_SAFE_NO_PAD),
    })
}

#[post("/share/v1/policy/session", format = "json", data = "<data>")]
pub async fn policy_session(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
    _origin: ShareOriginGuard,
) -> ApiResult<Value> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let request: PolicySessionRequest = serde_json::from_value(read_bounded_json(data).await?)
        .map_err(|_| error(Status::BadRequest, "policy_denied"))?;
    if !body_is_bounded(&request) {
        return Err(error(Status::PayloadTooLarge, "policy_denied"));
    }
    let p = &request.presentation;
    let now = OffsetDateTime::now_utc();
    let scope = scope_from_presentation(p, &runtime.config)
        .map_err(|_| generic("invalid_content_source"))?;
    let presentation_value =
        serde_json::to_value(p).map_err(|_| generic("invalid_holder_proof"))?;
    let value = presentation_value;
    verify_did_key_signature(
        &p.holder_did,
        &request.proof,
        b"xyz.tinycloud.share/policy-presentation/v1\0",
        &value,
    )
    .map_err(|_| error(Status::Forbidden, "invalid_holder_proof"))?;
    let issued_at = OffsetDateTime::parse(&p.issued_at, &Rfc3339)
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    let expires_at = OffsetDateTime::parse(&p.expires_at, &Rfc3339)
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    if p.artifact_type != "TinyCloudSharePolicyPresentation"
        || p.version != 1
        || expires_at <= now
        || issued_at > now + Duration::seconds(runtime.config.clock_skew_seconds)
        || expires_at <= issued_at
        || expires_at - issued_at > Duration::seconds(runtime.config.challenge_ttl_seconds as i64)
    {
        return Err(error(Status::Forbidden, "policy_denied"));
    }
    let (_policy_sender, policy_email, policy_expiry) = runtime
        .bridge
        .policy_sender_recipient_and_expiry(
            p.policy_cid.as_str(),
            p.delegation_cid.as_str(),
            &p.authority_material_handle,
            &p.authority_material_digest,
            now,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    let enforcer_did = runtime
        .bridge
        .enforcer_did_for(
            p.policy_cid.as_str(),
            p.delegation_cid.as_str(),
            &p.authority_material_handle,
            &p.authority_material_digest,
            &scope.node_audience,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    if p.enforcer_did != enforcer_did {
        return Err(error(Status::Forbidden, "policy_denied"));
    }
    let credential_request = AuthorityPolicySessionRequest {
        scope: scope.clone(),
        holder: p.holder_did.clone(),
        nonce: p.nonce.clone(),
        presentation_jti: p.jti.clone(),
        challenge_id: p.challenge_id.as_str().to_owned(),
        challenge_request_digest: p.request_body_digest.clone(),
        challenge_binding: json!({"requestDigest": p.request_body_digest.as_str()}),
        policy_recipient_digest: digest_text(
            &policy_email
                .digest_material()
                .map_err(|_| error(Status::Forbidden, "policy_denied"))?,
        ),
        credential_expires_at: policy_expiry.unix_timestamp(),
    };
    let holder_binding = serde_json::to_vec(&request.holder_binding)
        .map_err(|_| error(Status::Forbidden, "invalid_holder_proof"))?;
    let admission = runtime
        .verifier
        .at_time(now.unix_timestamp())
        .verify_session_admission_for_matcher(
            request.credential.as_bytes(),
            credential_request,
            &p.credential_digest,
            &holder_binding,
            &policy_email,
            policy_expiry.unix_timestamp(),
            &enforcer_did,
            &p.holder_did,
            &request.read_signer_did,
        )
        .map_err(|_| error(Status::Forbidden, "invalid_holder_proof"))?;
    let session = runtime
        .bridge
        .establish_session(admission, now)
        .await
        .map_err(|failure| match failure {
            PortError::Unavailable | PortError::Storage => {
                error(Status::ServiceUnavailable, "capability_unavailable")
            }
            PortError::Replay => error(Status::Conflict, "policy_session_replayed"),
            PortError::Denied => error(Status::Forbidden, "policy_denied"),
        })?;
    let session_wire = PolicySession {
        artifact_type: "TinyCloudSharePolicySession".to_owned(),
        version: 1,
        session_id: session.handle,
        share_cid: p.share_cid.clone(),
        share_id: p.share_id.clone(),
        delegation_cid: p.delegation_cid.clone(),
        authority_material_handle: p.authority_material_handle.clone(),
        authority_material_digest: p.authority_material_digest.clone(),
        policy_cid: p.policy_cid.clone(),
        content_source: p.content_source.clone(),
        content_source_digest: p.content_source_digest.clone(),
        holder_did: p.holder_did.clone(),
        target_origin: p.target_origin.clone(),
        node_audience: p.node_audience.clone(),
        action: p.action,
        actions: p.actions.clone(),
        resource: p.resource.clone(),
        credential_digest: session.credential_digest,
        issued_at: timestamp(now),
        expires_at: timestamp(session.expires_at),
    };
    let session_value = serde_json::to_value(&session_wire)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    let proof = sign(&runtime.signer, POLICY_SESSION_DOMAIN, &session_value)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    Ok(Json(json!({"session":session_value,"proof":proof})))
}

#[post("/share/v1/read", format = "json", data = "<data>")]
pub async fn read(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
    _origin: ShareOriginGuard,
) -> Result<NoStoreJson<ReadResponse>, Custom<Json<ApiErrorBody>>> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let request_value = read_bounded_json(data).await?;
    let request: ReadRequest = serde_json::from_value(request_value.clone())
        .map_err(|_| error(Status::BadRequest, "read_denied"))?;
    if !body_is_bounded(&request) {
        return Err(error(Status::PayloadTooLarge, "read_denied"));
    }
    let i = request.invocation;
    if i.artifact_type != "TinyCloudShareReadInvocation" || i.version != 1 {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let scope = scope_from_request(
        &PolicyChallengeRequest {
            share_cid: i.share_cid.clone(),
            share_id: i.share_id.clone(),
            delegation_cid: i.delegation_cid.clone(),
            authority_material_handle: request.authority_material_handle.clone(),
            authority_material_digest: request.authority_material_digest.clone(),
            policy_cid: i.policy_cid.clone(),
            content_source: i.content_source.clone(),
            content_source_digest: i.content_source_digest.clone(),
            holder_did: i.holder_did.clone(),
            target_origin: i.target_origin.clone(),
            node_audience: i.node_audience.clone(),
            action: i.action,
            actions: i.actions.clone(),
            resource: i.resource.clone(),
            request_body_digest: i.request_body_digest.clone(),
        },
        &runtime.config,
    )
    .map_err(|_| generic("read_denied"))?;
    verify_read_request_body_digest(
        &request_value,
        &request.request_body_digest,
        &i.request_body_digest,
    )
    .map_err(|_| generic("read_denied"))?;
    if request.session_id != i.session_id
        || request.delegation_cid != i.delegation_cid
        || request.authority_material_handle != i.authority_material_handle
        || request.authority_material_digest != i.authority_material_digest
        || request.content_source != i.content_source
        || request.content_source_digest != i.content_source_digest
        || request.action != i.action
        || request.actions != i.actions
        || request.resource != i.resource
        || request.request_body_digest != i.request_body_digest
    {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let issued =
        OffsetDateTime::parse(&i.issued_at, &Rfc3339).map_err(|_| generic("read_denied"))?;
    let expires =
        OffsetDateTime::parse(&i.expires_at, &Rfc3339).map_err(|_| generic("read_denied"))?;
    let signature = decode_config(&request.proof.signature, URL_SAFE_NO_PAD)
        .map_err(|_| generic("invalid_holder_proof"))?;
    if request.proof.alg != "EdDSA"
        || request.proof.kid
            != format!(
                "{}#{}",
                i.holder_did.as_str(),
                i.holder_did.as_str().trim_start_matches("did:key:")
            )
        || signature.len() != 64
    {
        return Err(error(Status::Forbidden, "invalid_holder_proof"));
    }
    let proof = HolderReadProof {
        issued_at: issued,
        expires_at: expires,
        jti: i.jti.clone(),
        signer: i.holder_did.clone(),
        signature,
    };
    let response_session_id = i.session_id.clone();
    let response_jti = i.jti.clone();
    let response_audience = i.node_audience.clone();
    let response_holder = i.holder_did.clone();
    let response_source = i.content_source.clone();
    let response_action = i.action;
    let response_resource = i.resource.clone();
    let response_request_digest = i.request_body_digest.clone();
    let expected_source_digest = i.content_source_digest.clone();
    let read_request = HolderReadRequest {
        version: 1,
        session: i.session_id,
        jti: i.jti,
        scope,
        holder: i.holder_did,
        request_body_digest: i.request_body_digest,
        limit: None,
        cursor: None,
        body_digest: None,
        if_match: None,
        content_type: None,
        proof,
    };
    let response = runtime
        .data_plane
        .read(read_request, OffsetDateTime::now_utc())
        .await
        .map_err(|e| match e {
            DataPlaneError::Storage => error(Status::ServiceUnavailable, "capability_unavailable"),
            DataPlaneError::Replay => error(Status::Forbidden, "read_denied"),
            _ => error(Status::Forbidden, "read_denied"),
        })?;
    let content = String::from_utf8(response.document.as_bytes().to_vec())
        .map_err(|_| error(Status::Forbidden, "read_denied"))?;
    let now = OffsetDateTime::now_utc();
    let invocation_expires = expires;
    let response_expires = (now + Duration::seconds(60)).min(invocation_expires);
    if response_expires <= now {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let mut response_body = ReadResponse {
        artifact_type: "TinyCloudShareReadResponse".to_owned(),
        version: 1,
        session_id: response_session_id,
        request_jti: response_jti.clone(),
        read_jti: response_jti,
        audience: response_audience,
        holder_did: response_holder,
        credential_digest: response.credential_digest,
        issued_at: timestamp(now),
        expires_at: timestamp(response_expires),
        media_type: response.media_type,
        content,
        content_source: response_source,
        content_source_digest: expected_source_digest,
        action: response_action,
        actions: i.actions.clone(),
        resource: response_resource,
        request_body_digest: response_request_digest,
        body_digest: response.body_digest,
        delegation_cid: request.delegation_cid,
        authority_material_handle: request.authority_material_handle,
        authority_material_digest: request.authority_material_digest,
        proof: DetachedProof {
            alg: String::new(),
            kid: String::new(),
            signature: String::new(),
        },
    };
    let mut response_value = serde_json::to_value(&response_body)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    response_value
        .as_object_mut()
        .ok_or(error(Status::InternalServerError, "capability_unavailable"))?
        .remove("proof");
    response_body.proof = sign(&runtime.signer, READ_RESPONSE_DOMAIN, &response_value)
        .map_err(|_| error(Status::InternalServerError, "capability_unavailable"))?;
    Ok(NoStoreJson(response_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::local::asynchronous::Client;

    #[tokio::test]
    async fn request_body_limit_is_strict() {
        let body = "x".repeat(tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES - 2);
        assert!(body_is_bounded(&body));
        assert!(!body_is_bounded(&format!("{body}x")));
    }

    #[tokio::test]
    async fn disabled_composition_fails_closed_at_the_http_boundary() {
        let rocket = rocket::build()
            .mount("/", rocket::routes![authorize_invitation])
            .manage(None::<ShareEmailRuntime>);
        let client = Client::tracked(rocket).await.expect("Rocket client");
        let response = client
            .post("/share/v1/invitations/authorize")
            .json(&json!({}))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::ServiceUnavailable);
    }

    #[tokio::test]
    async fn browser_origin_mismatch_is_rejected_before_protocol_state() {
        let rocket = rocket::build()
            .mount("/", rocket::routes![authorize_invitation])
            .manage(None::<ShareEmailRuntime>);
        let client = Client::tracked(rocket).await.expect("Rocket client");
        let response = client
            .post("/share/v1/invitations/authorize")
            .header(rocket::http::ContentType::JSON)
            .header(rocket::http::Header::new("Origin", "https://evil.example"))
            .body("{}")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
    }

    #[tokio::test]
    async fn browser_origin_must_match_the_single_configured_allowlist_entry() {
        let config = ShareEmailConfig {
            enabled: true,
            allowed_origins: vec!["https://share.tinycloud.xyz".to_owned()],
            ..ShareEmailConfig::default()
        };
        assert_eq!(config.allowed_origins.len(), 1);
        assert!(!config.allowed_origins.iter().any(|origin| origin == "*"));
    }

    #[tokio::test]
    async fn mounted_surface_includes_the_frozen_node_routes_and_native_invoke() {
        let routes = public_routes();
        assert!(routes.iter().any(|route| {
            route.uri.path() == "/delegate"
                && route.format.as_ref().is_some_and(|format| {
                    format.to_string() == "application/vnd.tinycloud.delegation+json"
                })
        }));
        assert!(routes.iter().any(|route| {
            route.uri.path() == "/invoke"
                && route.format.as_ref().is_some_and(|format| {
                    format.to_string() == "application/vnd.tinycloud.share+json"
                })
        }));
        let rocket = rocket::build()
            .mount(
                "/",
                routes
                    .into_iter()
                    .filter(|route| route.uri.path() != "/invoke")
                    .collect::<Vec<_>>(),
            )
            .manage(None::<ShareEmailRuntime>);
        let client = Client::tracked(rocket).await.expect("Rocket client");

        for route in NODE_CAPABILITY_ROUTES {
            let response = client
                .post(route)
                .header(rocket::http::ContentType::JSON)
                .body("{}")
                .dispatch()
                .await;
            assert_ne!(response.status(), Status::NotFound, "{route}");
        }

        let response = client
            .post("/share/v1/invitations/consume")
            .header(rocket::http::ContentType::JSON)
            .body("{}")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
    }

    #[tokio::test]
    async fn raw_oversize_body_is_rejected_before_json_or_runtime_state() {
        let rocket = rocket::build()
            .mount("/", rocket::routes![authorize_invitation])
            .manage(None::<ShareEmailRuntime>);
        let client = Client::tracked(rocket).await.expect("Rocket client");
        let body = format!(
            "{}{{",
            " ".repeat(tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES)
        );
        let response = client
            .post("/share/v1/invitations/authorize")
            .header(rocket::http::ContentType::JSON)
            .body(body)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::PayloadTooLarge);
    }

    #[tokio::test]
    async fn invitation_authorization_has_one_strict_outer_envelope() {
        let flattened = json!({
            "senderDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "proof": {"alg":"EdDSA","kid":"did:web:node.example#k","signature":"x"}
        });
        assert!(serde_json::from_value::<NodeInvitationAuthorizationEnvelope>(flattened).is_err());

        let unknown = json!({
            "request": {},
            "proof": {"alg":"EdDSA","kid":"did:web:node.example#k","signature":"x"},
            "policyOwnerDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
        });
        assert!(serde_json::from_value::<NodeInvitationAuthorizationEnvelope>(unknown).is_err());
    }

    #[test]
    fn invitation_recipient_shape_preserves_v1_and_binds_v2_matchers() {
        let exact = CanonicalEmail::parse("Alice@example.com").unwrap();
        let delivery = CanonicalEmail::parse("notify@example.com").unwrap();
        let exact_matcher = RecipientMatcher::ExactEmail("Alice@EXAMPLE.COM".to_owned());
        let domain_matcher = RecipientMatcher::EmailDomain("EXAMPLE.COM".to_owned());

        assert!(validate_invitation_recipient(Some(&exact), None, None, &exact_matcher,).is_ok());
        assert!(validate_invitation_recipient(Some(&exact), None, None, &domain_matcher,).is_err());
        assert!(validate_invitation_recipient(
            None,
            Some(&domain_matcher),
            Some(&delivery),
            &domain_matcher,
        )
        .is_ok());
        assert!(
            validate_invitation_recipient(None, Some(&domain_matcher), None, &domain_matcher,)
                .is_ok()
        );
        let outside_domain = CanonicalEmail::parse("notify@other.example").unwrap();
        assert!(validate_invitation_recipient(
            None,
            Some(&domain_matcher),
            Some(&outside_domain),
            &domain_matcher,
        )
        .is_err());
        assert!(validate_invitation_recipient(
            None,
            Some(&RecipientMatcher::EmailDomain("other.example".to_owned())),
            Some(&delivery),
            &domain_matcher,
        )
        .is_err());
    }

    #[test]
    fn v2_source_ceiling_uses_segment_boundaries() {
        let prefix = Path::parse("documents").unwrap();
        assert!(same_or_descendant(
            &prefix,
            &Path::parse("documents").unwrap()
        ));
        assert!(same_or_descendant(
            &prefix,
            &Path::parse("documents/plan.md").unwrap()
        ));
        assert!(!same_or_descendant(
            &prefix,
            &Path::parse("documents-archive/plan.md").unwrap()
        ));
        assert!(same_or_descendant(
            &Path::parse("documents").unwrap(),
            &prefix
        ));
    }

    #[test]
    fn native_list_entries_have_one_typed_shape_for_files_and_folders() {
        let file = NativeListEntry {
            path: Path::parse("documents/readme.md").unwrap(),
            kind: "file",
        };
        let folder = NativeListEntry {
            path: Path::parse("documents/archive").unwrap(),
            kind: "folder",
        };
        assert_eq!(
            serde_json::to_value(file).unwrap(),
            json!({"path":"documents/readme.md","kind":"file"})
        );
        assert_eq!(
            serde_json::to_value(folder).unwrap(),
            json!({"path":"documents/archive","kind":"folder"})
        );
    }

    #[test]
    fn signed_native_operation_fields_are_strictly_typed() {
        assert!(valid_signed_content_type("text/markdown; charset=utf-8"));
        assert!(valid_signed_content_type("text/plain"));
        assert!(valid_signed_content_type("application/octet-stream"));
        assert!(!valid_signed_content_type("text/markdown\r\nX-Leak: yes"));
    }

    #[test]
    fn checked_in_v2_vectors_are_byte_for_byte_jcs_digests() {
        let vectors: Value =
            serde_json::from_str(include_str!("../specs/share-email-v2/vectors.json")).unwrap();
        for name in [
            "addressedDelegationRequest",
            "invitationAuthorizationRequest",
        ] {
            let vector = &vectors["vectors"][name];
            if let Some(body) = vector.get("body") {
                assert_eq!(
                    jcs::canonicalize(body),
                    vector["canonicalJson"].as_str().unwrap().as_bytes()
                );
                assert_eq!(
                    digest(body).as_str(),
                    vector["requestBodyDigest"].as_str().unwrap()
                );
            } else {
                let canonical = vector["canonicalJson"].as_str().unwrap();
                let value: Value = serde_json::from_str(canonical).unwrap();
                assert_eq!(jcs::canonicalize(&value), canonical.as_bytes());
                assert_eq!(
                    digest(&value).as_str(),
                    vector["requestBodyDigest"].as_str().unwrap()
                );
            }
        }
    }

    #[test]
    fn v2_share_url_is_exactly_bound_to_the_share_and_return_origin() {
        let cid =
            ShareCid::parse("bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4").unwrap();
        let url = format!(
            "https://share.tinycloud.xyz/s/{}#k={}",
            cid.as_str(),
            "A".repeat(43)
        );
        assert!(validate_share_url(
            &url,
            &cid,
            "https://share.tinycloud.xyz"
        ));
        assert!(!validate_share_url(
            &url.replace("#k=", "?x=1#k="),
            &cid,
            "https://share.tinycloud.xyz"
        ));
        assert!(!validate_share_url(
            &url.replace(
                cid.as_str(),
                "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            &cid,
            "https://share.tinycloud.xyz"
        ));
    }

    #[tokio::test]
    async fn body_bindings_are_recomputed_from_their_frozen_preimage() {
        let mut body = json!({"resource":"documents/plan.md"});
        let expected = digest(&body);
        body["requestBodyDigest"] = json!(expected.as_str());
        assert!(verify_request_body_digest(&body, &expected).is_ok());

        let mut altered = body.clone();
        altered["resource"] = json!("documents/other.md");
        assert!(verify_request_body_digest(&altered, &expected).is_err());

        let read = json!({
            "sessionId":"AAECAwQFBgcICQoLDA0ODw",
            "contentSource": {"kind":"kv","space":"did:pkh:eip155:1:0xabc","path":"documents/plan.md","action":"tinycloud.kv/get"},
            "contentSourceDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "action":"tinycloud.kv/get",
            "resource":"documents/plan.md",
            "invocation": {"requestBodyDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "proof": {"alg":"EdDSA","kid":"did:web:node.example#k","signature":"x"},
            "requestBodyDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        let mut preimage = read.clone();
        let object = preimage.as_object_mut().unwrap();
        object.remove("proof");
        object.remove("requestBodyDigest");
        object
            .get_mut("invocation")
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("requestBodyDigest");
        let read_digest = digest(&preimage);
        let mut valid = read;
        valid["requestBodyDigest"] = json!(read_digest.as_str());
        valid["invocation"]["requestBodyDigest"] = json!(read_digest.as_str());
        assert!(verify_read_request_body_digest(&valid, &read_digest, &read_digest).is_ok());
    }

    #[tokio::test]
    async fn policy_recipient_digest_hashes_email_bytes_without_json_quotes() {
        let email = "Alice+Notes@example.com";
        assert_ne!(digest_text(email), digest(&json!(email)));
        assert_eq!(digest_text(email), digest_text(email));
    }

    #[tokio::test]
    async fn policy_presentation_reuses_only_the_original_challenge_body() {
        let source = json!({
            "action": "tinycloud.kv/get",
            "kind": "kv",
            "path": "documents/plan.md",
            "space": "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7"
        });
        let source_digest = digest(&source);
        let request = json!({
            "shareCid": "bafkreigvcvtxbo4zv5ysyet4pm2y3rhclbizfjfyj4wzhmtjg2us4oy25a",
            "shareId": "shr_n4-mounted-kv",
            "delegationCid": "bafkreihhkhfgdqltz6ivbwcj7pq4idmzv7nsrbz6atilby3ymovnfquwam",
            "authorityMaterialHandle": "amh_kv_001",
            "authorityMaterialDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "policyCid": "bafkreigvcvtxbo4zv5ysyet4pm2y3rhclbizfjfyj4wzhmtjg2us4oy25a",
            "contentSource": source,
            "contentSourceDigest": source_digest.as_str(),
            "holderDid": "did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3",
            "targetOrigin": "https://node.example",
            "nodeAudience": "did:web:node.example",
            "action": "tinycloud.kv/get",
            "resource": "documents/plan.md"
        });
        let request_digest = digest(&request);
        let mut presentation = request;
        presentation["type"] = json!("TinyCloudSharePolicyPresentation");
        presentation["version"] = json!(1);
        presentation["challengeId"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        presentation["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        presentation["enforcerDid"] =
            json!("did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7");
        presentation["credentialDigest"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        presentation["requestBodyDigest"] = json!(request_digest.as_str());
        presentation["issuedAt"] = json!("2026-07-19T17:00:00.000Z");
        presentation["expiresAt"] = json!("2026-07-19T17:02:00.000Z");
        presentation["jti"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
        let presentation: PolicyPresentation = serde_json::from_value(presentation).unwrap();
        assert_eq!(
            serde_json::to_value(&presentation).unwrap()["enforcerDid"],
            "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7"
        );
        let config = ShareEmailConfig {
            target_origin: "https://node.example".to_owned(),
            node_audience: "did:web:node.example".to_owned(),
            ..ShareEmailConfig::default()
        };
        assert!(scope_from_presentation(&presentation, &config).is_ok());

        let mut altered = presentation.clone();
        altered.resource = Path::parse("documents/other.md").unwrap();
        assert!(scope_from_presentation(&altered, &config).is_err());
    }
}
