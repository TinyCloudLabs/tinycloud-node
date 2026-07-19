//! Production composition for the exact-email claim node surface.
//!
//! This module is deliberately the only HTTP composition point for the N1/N2
//! and N3 leaves.  It contains no test adapters: production reads go through
//! `SpaceDatabase` and the existing constrained `SqlService`, while authority
//! state goes through `DatabaseAuthorityBridge117`.

use async_trait::async_trait;
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use futures::io::AsyncReadExt;
use rocket::{
    data::{Data, ToByteUnit},
    http::Status,
    response::status::Custom,
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tokio::io::AsyncReadExt as TokioAsyncReadExt;

use tinycloud_auth::share_email_evidence::{IssuerKey, IssuerTrustRegistry, EMAIL_VCT};
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
            decode_share_url_token, issue_invitation_authorization_for,
            verify_invitation_authorization_for, CanonicalEmail, DocumentName,
            Ed25519InvitationSigner, Ed25519InvitationVerifier, InvitationAuthorizationInput,
            InvitationAuthorizationReceipt, InvitationSigner, SenderTrust,
        },
        state::{AnonymousChallengeRequest, ProtocolStateRepository},
        types::{
            ContentSource, Did, DidKey, ExactResource, Path, PolicyCid,
            PolicySessionRequest as AuthorityPolicySessionRequest, ProtocolJti, ProtocolNonce,
            SessionHandle, ShareAction, ShareCid, ShareDelegationCid, ShareId, ShareScope,
            TargetOrigin,
        },
        verifier::ExactEmailVerifier,
        AuthenticatedAuthorityMaterialProvider, DatabaseAuthorityBridge117,
        PolicyAuthorityTransaction117, PortError,
    },
    sql::{caveats::PreparedStatement, SqlCaveats, SqlRequest, SqlResponse, SqlService, SqlValue},
};

use crate::{config::ShareEmailConfig, TinyCloud};

const POLICY_CHALLENGE_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy-challenge/v1\0";
const POLICY_SESSION_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy-session/v1\0";

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
    #[serde(rename = "credentialDigest")]
    pub credential_digest: tinycloud_core::share_email::Sha256Digest,
    pub action: ShareAction,
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
pub struct ReadRequest {
    #[serde(rename = "sessionId")]
    pub session_id: SessionHandle,
    #[serde(rename = "contentSource")]
    pub content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    pub action: ShareAction,
    pub resource: Path,
    #[serde(rename = "requestBodyDigest")]
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    pub invocation: ReadInvocation,
    pub proof: DetachedProof,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadResponse {
    #[serde(rename = "mediaType")]
    pub media_type: &'static str,
    pub content: String,
    #[serde(rename = "contentSourceDigest")]
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    #[serde(rename = "bodyDigest")]
    pub body_digest: tinycloud_core::share_email::Sha256Digest,
}

#[derive(Debug, Serialize)]
pub struct CapabilityDescriptor {
    pub id: &'static str,
    pub version: u8,
    pub origin: String,
    #[serde(rename = "returnOrigin")]
    pub return_origin: String,
    pub routes: [&'static str; 5],
    #[serde(rename = "contentKinds")]
    pub content_kinds: [&'static str; 2],
    #[serde(rename = "mailProvider")]
    pub mail_provider: &'static str,
    pub status: &'static str,
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
    let mut bytes = Vec::new();
    let mut reader =
        data.open((tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES + 1).bytes());
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| error(Status::BadRequest, "invalid_content_source"))?;
    if bytes.len() > tinycloud_core::share_email::state::MAX_REQUEST_BODY_BYTES {
        return Err(error(Status::PayloadTooLarge, "invalid_content_source"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error(Status::BadRequest, "invalid_content_source"))
}

#[derive(Clone)]
pub struct TinyCloudKvStore {
    pub tinycloud: Arc<TinyCloud>,
    pub space_name: String,
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
        if bytes.len() > tinycloud_core::share_email::MAX_MARKDOWN_BYTES {
            return Err(PortError::Denied);
        }
        Ok(Some(bytes))
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
}

impl ShareEmailRuntime {
    pub fn capability(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: "tinycloud.node-policy-email-v1",
            version: 1,
            origin: self.config.target_origin.clone(),
            return_origin: self.config.return_origin.clone(),
            routes: [
                "/share/v1/invitations/authorize",
                "/share/v1/invitations/consume",
                "/share/v1/policy/challenges",
                "/share/v1/policy/session",
                "/share/v1/read",
            ],
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
    if !config.enabled {
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
        EMAIL_VCT,
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
    let signing_secret = tinycloud_core::libp2p::identity::ed25519::SecretKey::try_from_bytes(
        key_setup.derive_key(b"tinycloud/share-email/invitation-signing"),
    )
    .map_err(|_| anyhow::anyhow!("invalid share email signing key"))?;
    let signing_ed25519 = tinycloud_core::libp2p::identity::ed25519::Keypair::from(signing_secret);
    let signing_keypair: tinycloud_core::libp2p::identity::Keypair = signing_ed25519.clone().into();
    let signing_public = signing_keypair
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow::anyhow!("invalid share email signing public key"))?;
    if signing_public.to_bytes() != invite_public_key {
        return Err(anyhow::anyhow!(
            "configured invitation public key does not match the derived node signing key"
        ));
    }
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
    let status_provider = Arc::new(material.status_provider());
    let attestation_provider = Arc::new(material.attestation_provider());
    let bridge = Arc::new(
        DatabaseAuthorityBridge117::new(conn.clone(), DatabaseAuthorityStore::new(conn.clone()))
            .with_authority_providers(material, status_provider, attestation_provider),
    );
    // Sequence C supplies authenticated authority material, fresh status, and
    // attestation/enrollment providers. Until all three are injected and
    // healthy, the capability is absent and every protocol route stays
    // fail-closed.
    if !bridge.ready() {
        return Ok(None);
    }
    let kv = TinyCloudKvStore {
        tinycloud,
        space_name: config.space_name.clone(),
    };
    let sql = SqlNamedStore {
        service: sql_service,
        space_name: config.space_name.clone(),
    };
    let data_plane = HolderBoundDataPlane::new(
        bridge.clone(),
        Arc::new(MarkdownKvAdapter::new(Arc::new(kv))),
        Arc::new(MarkdownSqlAdapter::new(Arc::new(sql.clone()))),
    );
    Ok(Some(ShareEmailRuntime {
        state: ProtocolStateRepository::new(conn),
        config,
        bridge,
        verifier,
        invitation_verifier,
        signer,
        data_plane,
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
    let resource = match &request.content_source {
        ContentSource::Kv { path, .. } => ExactResource::Kv { path: path.clone() },
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
        ContentSource::Kv { path, .. } => {
            matches!(&resource, ExactResource::Kv { path: resource_path } if resource_path == path)
                && request.resource == *path
        }
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
            ) && request.resource == *path
        }
    };
    if expected != request.content_source_digest
        || !resource_matches
        || request.target_origin.as_str() != config.target_origin
        || request.node_audience.as_str() != config.node_audience
        || !matches!(
            (&request.action, &request.content_source),
            (ShareAction::KvGet, ContentSource::Kv { .. })
                | (ShareAction::SqlRead, ContentSource::Sql { .. })
        )
    {
        return Err(());
    }
    Ok(ShareScope {
        share_cid: request.share_cid.clone(),
        share_id: request.share_id.clone(),
        delegation_cid: Some(request.delegation_cid.clone()),
        policy_cid: request.policy_cid.clone(),
        node_audience: request.node_audience.clone(),
        target_origin: request.target_origin.clone(),
        action: request.action,
        resource,
        content_source: request.content_source.clone(),
        content_source_digest: request.content_source_digest.clone(),
    })
}

fn scope_from_presentation(
    p: &PolicyPresentation,
    config: &ShareEmailConfig,
) -> Result<ShareScope, ()> {
    scope_from_request(
        &PolicyChallengeRequest {
            share_cid: p.share_cid.clone(),
            share_id: p.share_id.clone(),
            delegation_cid: p.delegation_cid.clone(),
            policy_cid: p.policy_cid.clone(),
            content_source: p.content_source.clone(),
            content_source_digest: p.content_source_digest.clone(),
            holder_did: p.holder_did.clone(),
            target_origin: p.target_origin.clone(),
            node_audience: p.node_audience.clone(),
            action: p.action,
            resource: p.resource.clone(),
            request_body_digest: p.request_body_digest.clone(),
        },
        config,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NodeInvitationAuthorizationRequest {
    pub jti: ProtocolJti,
    pub report_abuse_token: ProtocolJti,
    pub sender_did: DidKey,
    pub share_cid: ShareCid,
    pub share_id: ShareId,
    pub delegation_cid: ShareDelegationCid,
    pub policy_cid: PolicyCid,
    pub recipient_email: CanonicalEmail,
    pub target_origin: TargetOrigin,
    pub node_audience: Did,
    pub document_name: DocumentName,
    pub sender_trust: SenderTrust,
    pub content_source: ContentSource,
    pub content_source_digest: tinycloud_core::share_email::Sha256Digest,
    pub share_expires_at: String,
    pub request_body_digest: tinycloud_core::share_email::Sha256Digest,
    pub share_url: String,
    pub proof: DetachedProof,
}

#[post("/share/v1/invitations/authorize", format = "json", data = "<data>")]
pub async fn authorize_invitation(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
) -> ApiResult<Value> {
    let value = read_bounded_json(data).await?;
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let request: NodeInvitationAuthorizationRequest = serde_json::from_value(value.clone())
        .map_err(|_| error(Status::BadRequest, "invitation_authorization_invalid"))?;
    let mut signed_value = value;
    signed_value
        .as_object_mut()
        .ok_or(error(
            Status::BadRequest,
            "invitation_authorization_invalid",
        ))?
        .remove("proof");
    verify_did_key_signature(
        &request.sender_did,
        &request.proof,
        b"xyz.tinycloud.share/invite-authorization/v1\0",
        &signed_value,
    )
    .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let scope_request = PolicyChallengeRequest {
        share_cid: request.share_cid.clone(),
        share_id: request.share_id.clone(),
        delegation_cid: request.delegation_cid.clone(),
        policy_cid: request.policy_cid.clone(),
        content_source: request.content_source.clone(),
        content_source_digest: request.content_source_digest.clone(),
        holder_did: request.sender_did.clone(),
        target_origin: request.target_origin.clone(),
        node_audience: request.node_audience.clone(),
        action: if matches!(request.content_source, ContentSource::Kv { .. }) {
            ShareAction::KvGet
        } else {
            ShareAction::SqlRead
        },
        resource: match &request.content_source {
            ContentSource::Kv { path, .. } | ContentSource::Sql { path, .. } => path.clone(),
        },
        request_body_digest: request.request_body_digest.clone(),
    };
    let scope = scope_from_request(&scope_request, &runtime.config)
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let share_prefix = format!(
        "{}/s/{}#k=",
        runtime.config.return_origin,
        request.share_cid.as_str()
    );
    let token = request
        .share_url
        .strip_prefix(&share_prefix)
        .ok_or(error(Status::Forbidden, "invitation_authorization_invalid"))?;
    decode_share_url_token(token)
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
            request.sender_did.as_str(),
        )
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let (policy_email, policy_expiry) = runtime
        .bridge
        .policy_recipient_and_expiry(
            request.policy_cid.as_str(),
            request.delegation_cid.as_str(),
            now,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    if policy_email != request.recipient_email.as_str()
        || request.target_origin.as_str() != runtime.config.target_origin
        || request.node_audience.as_str() != runtime.config.node_audience
        || OffsetDateTime::parse(&request.share_expires_at, &Rfc3339).ok() != Some(policy_expiry)
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
            recipient_email: request.recipient_email,
            target_origin: request.target_origin,
            node_audience: request.node_audience,
            document_name: request.document_name,
            sender_trust: request.sender_trust,
            content_source: request.content_source,
            content_source_digest: request.content_source_digest,
            share_expires_at: request.share_expires_at,
            request_body_digest: request.request_body_digest,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InvitationAuthorizationConsumption {
    pub receipt: InvitationAuthorizationReceipt,
}

/// Consume the sender-authorized receipt after the delivery service has
/// linked it to the invitation.  The receipt is verified against deployment
/// configuration and the durable reservation is atomically one-use; no
/// caller-provided binding is accepted here.
#[post("/share/v1/invitations/consume", format = "json", data = "<data>")]
pub async fn consume_invitation(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
) -> ApiResult<Value> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let value = read_bounded_json(data).await?;
    let request: InvitationAuthorizationConsumption = serde_json::from_value(value)
        .map_err(|_| error(Status::BadRequest, "invitation_authorization_invalid"))?;
    let now = OffsetDateTime::now_utc();
    let target_origin = TargetOrigin::parse(runtime.config.target_origin.clone())
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let node_audience = Did::parse(runtime.config.node_audience.clone())
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let return_origin = TargetOrigin::parse(runtime.config.return_origin.clone())
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let authorization_digest_value = verify_invitation_authorization_for(
        &request.receipt,
        &runtime.invitation_verifier,
        now,
        &target_origin,
        &node_audience,
        &return_origin,
    )
    .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    let binding = json!({
        "authorizationDigest": authorization_digest_value.as_str(),
        "shareDigest": digest(&json!(request.receipt.authorization.share_cid.as_str())).as_str(),
    });
    runtime
        .state
        .consume_invitation_authorization(
            &request.receipt,
            binding,
            &authorization_digest_value,
            now,
        )
        .await
        .map_err(|_| error(Status::Forbidden, "invitation_authorization_invalid"))?;
    Ok(Json(
        json!({"authorizationDigest": authorization_digest_value.as_str()}),
    ))
}

#[post("/share/v1/policy/challenges", format = "json", data = "<data>")]
pub async fn policy_challenge(
    data: Data<'_>,
    runtime: &State<Option<ShareEmailRuntime>>,
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
    let scope = scope_from_request(&request, &runtime.config)
        .map_err(|_| generic("invalid_content_source"))?;
    let now = OffsetDateTime::now_utc();
    runtime
        .bridge
        .validate_scope(&scope, now)
        .await
        .map_err(|_| generic("policy_denied"))?;
    let challenge_id = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let nonce = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let expires = now + Duration::seconds(runtime.config.challenge_ttl_seconds as i64);
    let full_binding =
        serde_json::to_value(&request).map_err(|_| generic("invalid_content_source"))?;
    let request_digest = digest(&full_binding);
    let binding = json!({"requestDigest": request_digest.as_str()});
    let challenge = PolicyChallenge {
        artifact_type: "TinyCloudSharePolicyChallenge".to_owned(),
        version: 1,
        challenge_id: challenge_id.clone(),
        nonce: nonce.clone(),
        share_cid: request.share_cid,
        share_id: request.share_id,
        delegation_cid: request.delegation_cid,
        policy_cid: request.policy_cid,
        content_source: request.content_source,
        content_source_digest: request.content_source_digest,
        holder_did: request.holder_did,
        target_origin: request.target_origin,
        node_audience: request.node_audience,
        action: request.action,
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
    let nonce_hash = digest(&json!(nonce.as_str()));
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
        .map_err(|_| error(Status::TooManyRequests, "capability_unavailable"))?;
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
    let value = serde_json::to_value(p).map_err(|_| generic("invalid_holder_proof"))?;
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
    let (policy_email, policy_expiry) = runtime
        .bridge
        .policy_recipient_and_expiry(p.policy_cid.as_str(), p.delegation_cid.as_str(), now)
        .await
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    let evidence = runtime
        .verifier
        .at_time(now.unix_timestamp())
        .verify_exact_email_for(
            request.credential.as_bytes(),
            scope.share_scope(),
            &p.holder_did,
            &policy_email,
            policy_expiry.unix_timestamp(),
        )
        .map_err(|_| error(Status::Forbidden, "invalid_credential_profile"))?;
    if evidence.credential_digest != p.credential_digest {
        return Err(error(Status::Forbidden, "policy_denied"));
    }
    let challenge_binding = PolicyChallengeRequest {
        share_cid: p.share_cid.clone(),
        share_id: p.share_id.clone(),
        delegation_cid: p.delegation_cid.clone(),
        policy_cid: p.policy_cid.clone(),
        content_source: p.content_source.clone(),
        content_source_digest: p.content_source_digest.clone(),
        holder_did: p.holder_did.clone(),
        target_origin: p.target_origin.clone(),
        node_audience: p.node_audience.clone(),
        action: p.action,
        resource: p.resource.clone(),
        request_body_digest: p.request_body_digest.clone(),
    };
    let challenge_full_binding = serde_json::to_value(&challenge_binding)
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    let challenge_digest = digest(&challenge_full_binding);
    let challenge_binding = json!({"requestDigest": challenge_digest.as_str()});
    let session_request = AuthorityPolicySessionRequest {
        scope: scope.clone(),
        holder: p.holder_did.clone(),
        credential_digest: p.credential_digest.clone(),
        nonce: p.nonce.clone(),
        presentation_jti: p.jti.clone(),
        challenge_id: p.challenge_id.as_str().to_owned(),
        challenge_request_digest: challenge_digest,
        challenge_binding,
        policy_recipient_digest: digest(&json!(policy_email)),
        credential_expires_at: evidence.expires_at,
    };
    let session = runtime
        .bridge
        .establish_session(session_request, now)
        .await
        .map_err(|_| error(Status::Forbidden, "policy_denied"))?;
    let session_wire = PolicySession {
        artifact_type: "TinyCloudSharePolicySession".to_owned(),
        version: 1,
        session_id: session.handle,
        share_cid: p.share_cid.clone(),
        share_id: p.share_id.clone(),
        delegation_cid: p.delegation_cid.clone(),
        policy_cid: p.policy_cid.clone(),
        content_source: p.content_source.clone(),
        content_source_digest: p.content_source_digest.clone(),
        holder_did: p.holder_did.clone(),
        target_origin: p.target_origin.clone(),
        node_audience: p.node_audience.clone(),
        action: p.action,
        resource: p.resource.clone(),
        credential_digest: p.credential_digest.clone(),
        issued_at: timestamp(now),
        expires_at: timestamp(
            (now + Duration::seconds(300)).min(policy_expiry).min(
                OffsetDateTime::from_unix_timestamp(evidence.expires_at)
                    .map_err(|_| error(Status::Forbidden, "policy_denied"))?,
            ),
        ),
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
) -> ApiResult<ReadResponse> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let request: ReadRequest = serde_json::from_value(read_bounded_json(data).await?)
        .map_err(|_| error(Status::BadRequest, "read_denied"))?;
    if !body_is_bounded(&request) {
        return Err(error(Status::PayloadTooLarge, "read_denied"));
    }
    let i = request.invocation;
    if i.artifact_type != "TinyCloudShareReadInvocation" || i.version != 1 {
        return Err(error(Status::Forbidden, "read_denied"));
    }
    let mut scope = scope_from_request(
        &PolicyChallengeRequest {
            share_cid: i.share_cid.clone(),
            share_id: i.share_id.clone(),
            delegation_cid: ShareDelegationCid::parse(i.policy_cid.as_str())
                .map_err(|_| generic("read_denied"))?,
            policy_cid: i.policy_cid.clone(),
            content_source: i.content_source.clone(),
            content_source_digest: i.content_source_digest.clone(),
            holder_did: i.holder_did.clone(),
            target_origin: i.target_origin.clone(),
            node_audience: i.node_audience.clone(),
            action: i.action,
            resource: i.resource.clone(),
            request_body_digest: i.request_body_digest.clone(),
        },
        &runtime.config,
    )
    .map_err(|_| generic("read_denied"))?;
    scope.delegation_cid = None;
    if request.session_id != i.session_id
        || request.content_source != i.content_source
        || request.content_source_digest != i.content_source_digest
        || request.action != i.action
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
    let expected_source_digest = i.content_source_digest.clone();
    let read_request = HolderReadRequest {
        session: i.session_id,
        jti: i.jti,
        scope,
        holder: i.holder_did,
        request_body_digest: i.request_body_digest,
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
    Ok(Json(ReadResponse {
        media_type: response.media_type,
        content,
        content_source_digest: expected_source_digest,
        body_digest: response.body_digest,
    }))
}

trait ScopeEmail {
    fn share_scope(&self) -> &ShareScope;
}

impl ScopeEmail for ShareScope {
    fn share_scope(&self) -> &ShareScope {
        self
    }
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
}
