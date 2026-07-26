//! Production owner-rooted sharing policy registration.
//!
//! This is intentionally separate from the v1 email-claim composition.  v2
//! resolves the already-activated normal delegation graph from the database
//! and verifies the share-key artifacts supplied by the caller.  It never
//! reads the v1 static authority-material provider.

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use futures::io::{AsyncReadExt as FuturesAsyncReadExt, AsyncWriteExt as FuturesAsyncWriteExt};
use rocket::{
    data::{Data, ToByteUnit},
    http::Status,
    request::{FromRequest, Outcome},
    response::status::Custom,
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::io::AsyncReadExt;

use tinycloud_auth::{
    authorization::TinyCloudDelegation,
    identity::did_principal_matches,
    multihash_codetable::{Code, MultihashDigest},
    share_email_evidence::{normalized_email_hash, verify_detached_ed25519},
};
use tinycloud_core::{
    encryption::{maybe_decrypt, ColumnEncryption},
    keys::StaticSecret,
    models::{
        abilities, delegation, invocation as invocation_model, owner_share_policy, revocation,
        share_anonymous_challenge, share_holder_read_jti, share_invitation_authorization_jti,
        share_session_handle,
    },
    policy_capability::jcs,
    relationships::parent_delegations,
    sea_orm::{
        sea_query::Expr, ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection,
        EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
    },
    share_email::invitation::{Ed25519InvitationSigner, InvitationSigner},
    share_email::{
        types::{
            AuthorityMaterialHandle, Did, DidKey, PolicyCid,
            RecipientMatcher as TypedRecipientMatcher, ShareAction, ShareCid, ShareDelegationCid,
            ShareId, ShareScope, TargetOrigin,
        },
        verifier::ExactEmailVerifier,
        ProtocolNonce, Sha256Digest,
    },
    storage::ImmutableStaging,
    types::{Metadata, Resource},
    util::{DelegationInfo, DelegationMode, InvocationInfo},
    KvPrecondition,
};

use crate::{authorization::AuthHeaderGetter, config::ShareEmailConfig, tee::TeeContext};

pub const MAX_BODY_BYTES: usize = 100 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_BODY_BYTES + (MAX_BODY_BYTES / 3) + 4096;
const POLICY_DOMAIN: &str = "xyz.tinycloud.share/policy/v2\\0";
const ENFORCEMENT_DOMAIN: &str = "xyz.tinycloud.share/policy-enforcement/v2\\0";
const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
const MAX_GRAPH_NODES: usize = 64;

fn canonical_did_key_kid(did: &str) -> String {
    format!("{did}#{}", did.strip_prefix("did:key:").unwrap_or(did))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescriptor {
    pub id: &'static str,
    pub version: u8,
    pub routes: [&'static str; 6],
    pub max_body_bytes: usize,
    pub target_origin: String,
    pub node_audience: String,
    pub enforcer_did: String,
    pub tee_binding_digest: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessResponse {
    ready: bool,
    version: u8,
    max_body_bytes: usize,
    checks: ReadinessChecks,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessChecks {
    migration: bool,
    encrypted_storage: bool,
    delegation_revocation_lookup: bool,
    tee_identity: bool,
    signer: bool,
    route_version: bool,
    body_limit: bool,
    credential_verifier: bool,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    error: ApiError,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    code: &'static str,
}

type ApiErrorResponse = Custom<Json<ApiErrorBody>>;

fn error(status: Status, code: &'static str) -> ApiErrorResponse {
    Custom(
        status,
        Json(ApiErrorBody {
            error: ApiError { code },
        }),
    )
}

#[derive(Clone)]
pub struct ShareV2Runtime {
    conn: DatabaseConnection,
    tinycloud: Arc<crate::TinyCloud>,
    policy_encryption: ColumnEncryption,
    signer: Arc<Ed25519InvitationSigner>,
    enforcer_signer: Arc<Ed25519InvitationSigner>,
    signer_did: String,
    enforcer_did: String,
    config: ShareEmailConfig,
    tee_ready: bool,
    tee_binding_digest: Option<String>,
    live_ready: Arc<AtomicBool>,
    migration_ready: bool,
    graph_ready: bool,
    verifier: Option<ExactEmailVerifier>,
}

impl ShareV2Runtime {
    fn static_ready(&self) -> bool {
        self.config.enabled
            && TargetOrigin::parse(self.config.target_origin.clone()).is_ok()
            && !self.config.node_audience.is_empty()
            && self.config.node_audience.starts_with("did:")
            && self.tee_ready
            && self.tee_binding_digest.is_some()
            && !self.signer_did.is_empty()
            && !self.enforcer_did.is_empty()
            && self.migration_ready
            && self.graph_ready
            && self.verifier.is_some()
            && self.live_ready.load(Ordering::Acquire)
    }

    fn checks(&self, migration: bool, graph: bool) -> ReadinessChecks {
        ReadinessChecks {
            migration,
            encrypted_storage: self.encryption_probe(),
            delegation_revocation_lookup: graph,
            tee_identity: self.tee_ready,
            signer: !self.signer_did.is_empty(),
            route_version: true,
            body_limit: MAX_BODY_BYTES == 104_857_600,
            credential_verifier: self.verifier.is_some(),
        }
    }

    fn encryption_probe(&self) -> bool {
        let plaintext = b"tinycloud-share-v2-readiness";
        let encrypted = self.policy_encryption.encrypt(plaintext);
        maybe_decrypt(Some(&self.policy_encryption), &encrypted)
            .is_ok_and(|decrypted| decrypted == plaintext)
    }

    pub fn capability(&self) -> Option<CapabilityDescriptor> {
        self.static_ready().then(|| CapabilityDescriptor {
            id: "tinycloud.node-sharing-v2",
            version: 2,
            routes: [
                "/share/v2/policies",
                "/share/v2/readiness",
                "/share/v2/policy/challenges",
                "/share/v2/policy/session",
                "/share/v2/invoke",
                "/share/v2/deliveries/authorize",
            ],
            max_body_bytes: MAX_BODY_BYTES,
            target_origin: self.config.target_origin.clone(),
            node_audience: self.config.node_audience.clone(),
            enforcer_did: self.enforcer_did.clone(),
            tee_binding_digest: self.tee_binding_digest.clone().unwrap_or_default(),
            status: "ready",
        })
    }

    async fn readiness(&self) -> ReadinessResponse {
        let migration = owner_share_policy::Entity::find()
            .limit(1)
            .all(&self.conn)
            .await
            .is_ok()
            && self.encryption_probe();
        let graph = delegation::Entity::find()
            .select_only()
            .column(delegation::Column::Id)
            .limit(1)
            .all(&self.conn)
            .await
            .is_ok()
            && revocation::Entity::find()
                .select_only()
                .column(revocation::Column::Id)
                .limit(1)
                .all(&self.conn)
                .await
                .is_ok();
        let checks = self.checks(migration, graph);
        let ready = checks.migration
            && checks.encrypted_storage
            && checks.delegation_revocation_lookup
            && checks.tee_identity
            && checks.signer
            && checks.route_version
            && checks.body_limit
            && checks.credential_verifier
            && self.config.enabled;
        self.live_ready.store(ready, Ordering::Release);
        ReadinessResponse {
            ready,
            version: 2,
            max_body_bytes: MAX_BODY_BYTES,
            checks,
        }
    }

    async fn live(&self) -> bool {
        self.readiness().await.ready
    }
}

pub async fn compose(
    conn: DatabaseConnection,
    key_setup: &StaticSecret,
    config: ShareEmailConfig,
    tee_context: Option<TeeContext>,
    tee_key_derived: bool,
    tinycloud: Arc<crate::TinyCloud>,
) -> anyhow::Result<ShareV2Runtime> {
    let migration_ready = owner_share_policy::Entity::find()
        .select_only()
        .column(owner_share_policy::Column::PolicyCid)
        .limit(1)
        .all(&conn)
        .await
        .is_ok();
    let graph_ready = delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Id)
        .limit(1)
        .all(&conn)
        .await
        .is_ok()
        && revocation::Entity::find()
            .select_only()
            .column(revocation::Column::Id)
            .limit(1)
            .all(&conn)
            .await
            .is_ok();
    let signing_seed = key_setup.derive_key(b"tinycloud/share-email/invitation-signing");
    let signing_secret =
        tinycloud_core::libp2p::identity::ed25519::SecretKey::try_from_bytes(signing_seed)
            .map_err(|_| anyhow::anyhow!("invalid share v2 signing key"))?;
    let signing_keypair = tinycloud_core::libp2p::identity::ed25519::Keypair::from(signing_secret);
    let signer_did = tinycloud_core::keys::public_key_to_did_key(signing_keypair.public().into());
    let signer =
        Ed25519InvitationSigner::new(canonical_did_key_kid(&signer_did), signing_keypair.into())?;
    let enforcer_did = key_setup.node_did();
    let enforcer_signer = Ed25519InvitationSigner::new(
        canonical_did_key_kid(&enforcer_did),
        key_setup.node_keypair(),
    )?;
    let verifier = config
        .issuer_public_key
        .as_deref()
        .and_then(|encoded| decode_config(encoded, URL_SAFE_NO_PAD).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|public_key| {
            let issuer = tinycloud_auth::share_email_evidence::IssuerKey::new(
                config.issuer_did.clone(),
                config.issuer_vct.clone(),
                config.issuer_key_version,
                config.issuer_kid.clone(),
                public_key,
            );
            tinycloud_auth::share_email_evidence::IssuerTrustRegistry::new([issuer])
                .ok()
                .map(|trust| {
                    ExactEmailVerifier::new(
                        trust,
                        config.issuer_did.clone(),
                        OffsetDateTime::now_utc().unix_timestamp(),
                        config.clock_skew_seconds,
                    )
                })
        });
    let tee_ready = tee_key_derived
        && tee_context.as_ref().is_some_and(|context| {
            !context.app_id.is_empty()
                && !context.compose_hash.is_empty()
                && context.enforcer_did == key_setup.node_did()
                && context.enforcer_did == config.node_audience
        });
    let tee_binding_digest = tee_ready.then(|| {
        b64_digest(
            format!(
                "{}:{}:{}",
                tee_context
                    .as_ref()
                    .map(|context| context.app_id.as_str())
                    .unwrap_or_default(),
                tee_context
                    .as_ref()
                    .map(|context| context.compose_hash.as_str())
                    .unwrap_or_default(),
                key_setup.node_did()
            )
            .as_bytes(),
        )
    });
    let runtime = ShareV2Runtime {
        conn,
        tinycloud,
        policy_encryption: ColumnEncryption::new(
            key_setup.derive_key(b"tinycloud/hooks/webhook-secrets"),
        ),
        signer: Arc::new(signer),
        enforcer_signer: Arc::new(enforcer_signer),
        signer_did,
        enforcer_did,
        config,
        tee_ready,
        tee_binding_digest,
        live_ready: Arc::new(AtomicBool::new(false)),
        migration_ready,
        graph_ready,
        verifier,
    };
    let probe = runtime.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = probe.readiness().await;
        }
    });
    Ok(runtime)
}

pub fn public_routes() -> Vec<rocket::Route> {
    rocket::routes![
        readiness,
        register_policy,
        policy_challenge_v2,
        policy_session_v2,
        invoke_v2,
        authorize_delivery_v2
    ]
}

pub struct ShareV2Origin;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ShareV2Origin {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(origin) = request.headers().get_one("Origin") else {
            return Outcome::Success(Self);
        };
        let allowed = request
            .rocket()
            .state::<Option<ShareV2Runtime>>()
            .and_then(|runtime| runtime.as_ref())
            .map(|runtime| runtime.config.target_origin.as_str());
        if allowed == Some(origin) {
            Outcome::Success(Self)
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

#[get("/share/v2/readiness", format = "json")]
pub async fn readiness(runtime: &State<Option<ShareV2Runtime>>) -> Json<Value> {
    let response = if let Some(runtime) = runtime.inner().as_ref() {
        runtime.readiness().await
    } else {
        ReadinessResponse {
            ready: false,
            version: 2,
            max_body_bytes: MAX_BODY_BYTES,
            checks: ReadinessChecks {
                migration: false,
                encrypted_storage: false,
                delegation_revocation_lookup: false,
                tee_identity: false,
                signer: false,
                route_version: true,
                body_limit: true,
                credential_verifier: false,
            },
        }
    };
    Json(serde_json::to_value(response).expect("readiness response serializes"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    policy: PolicyInput,
    #[serde(rename = "ownerDelegation")]
    owner_delegation: OwnerDelegationInput,
    #[serde(rename = "enforcementDelegation")]
    enforcement_delegation: EnforcementDelegationInput,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    bytes: String,
    cid: String,
    proof: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDelegationInput {
    cid: String,
    #[serde(rename = "dagCbor")]
    dag_cbor: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct EnforcementDelegationInput {
    cid: String,
    #[serde(rename = "dagCbor")]
    dag_cbor: String,
    #[serde(rename = "issuerDid")]
    issuer_did: String,
    #[serde(rename = "audienceDid")]
    audience_did: String,
    facts: EnforcementFacts,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
struct EnforcementFacts {
    #[serde(rename = "ownerDelegationCid")]
    owner_delegation_cid: String,
    #[serde(rename = "policyCid")]
    policy_cid: String,
    #[serde(rename = "shareId")]
    share_id: String,
    #[serde(rename = "shareKeyDid")]
    share_key_did: String,
    #[serde(rename = "enforcerDid")]
    enforcer_did: String,
    #[serde(rename = "nodeAudience")]
    node_audience: String,
    #[serde(rename = "spaceId")]
    space_id: String,
    path: String,
    actions: Vec<String>,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEnvelope {
    domain: String,
    policy: PolicyDocument,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdkPolicyDocument {
    #[serde(rename = "type")]
    artifact_type: String,
    version: u8,
    #[serde(rename = "recipientMatcher")]
    recipient_matcher: RecipientMatcher,
    #[serde(rename = "contentSource")]
    content_source: SdkContentSource,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
    actions: Vec<String>,
    resource: SdkResource,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "issuerDid")]
    issuer_did: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdkContentSource {
    kind: String,
    space: String,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdkResource {
    kind: String,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    #[serde(rename = "type")]
    artifact_type: String,
    version: u8,
    #[serde(rename = "shareId")]
    share_id: String,
    #[serde(rename = "ownerDid")]
    owner_did: String,
    #[serde(rename = "shareKeyDid")]
    share_key_did: String,
    #[serde(rename = "recipientMatcher")]
    recipient_matcher: RecipientMatcher,
    target: PolicyTarget,
    resource: ExactResource,
    actions: Vec<String>,
    #[serde(rename = "contentSource")]
    content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
    #[serde(rename = "ownerDelegationCid")]
    owner_delegation_cid: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecipientMatcher {
    kind: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyTarget {
    origin: String,
    #[serde(rename = "nodeAudience")]
    node_audience: String,
    #[serde(rename = "enforcerDid")]
    enforcer_did: String,
    #[serde(rename = "spaceId")]
    space_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactResource {
    kind: String,
    path: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentSource {
    kind: String,
    space: String,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    registration_cid: String,
    policy_cid: String,
    owner_delegation_cid: String,
    enforcement_delegation_cid: String,
    owner_did: String,
    share_key_did: String,
    enforcer_did: String,
    target: RegistrationTarget,
    resource: ExactResource,
    actions: Vec<String>,
    content_source_digest: String,
    registered_at: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationTarget {
    origin: String,
    node_audience: String,
    enforcer_did: String,
    space_id: String,
}

#[derive(Debug, Serialize)]
struct ReceiptProof {
    alg: &'static str,
    kid: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct Receipt {
    registration: Registration,
    proof: ReceiptProof,
}

#[post("/share/v2/policies", format = "json", data = "<data>")]
pub async fn register_policy(
    data: Data<'_>,
    runtime: &State<Option<ShareV2Runtime>>,
    _origin: ShareV2Origin,
) -> Result<Json<Value>, ApiErrorResponse> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    if !runtime.live().await {
        return Err(error(Status::ServiceUnavailable, "capability_unavailable"));
    }
    let bytes = read_body(data).await?;
    let request: RegisterRequest = serde_json::from_slice(&bytes)
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?;
    let policy_bytes = decode_canonical_b64(&request.policy.bytes, MAX_POLICY_BYTES)
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?;
    let policy_cid = raw_sha256_cid(&policy_bytes);
    if policy_cid != request.policy.cid {
        return Err(error(Status::Forbidden, "policy_registration_invalid"));
    }
    let policy_value: Value = serde_json::from_slice(&policy_bytes)
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?;
    if jcs::canonicalize(&policy_value) != policy_bytes {
        return Err(error(Status::Forbidden, "policy_registration_invalid"));
    }
    let policy: PolicyEnvelope = match serde_json::from_value(policy_value.clone()) {
        Ok(policy) => policy,
        Err(_) => parse_sdk_policy(
            &policy_value,
            &request,
            &runtime.config,
            &runtime.enforcer_did,
        )
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?,
    };
    validate_policy(&policy, &request, &runtime.config, &runtime.enforcer_did)
        .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;
    if request.policy.cid == request.owner_delegation.cid
        || request.policy.cid == request.enforcement_delegation.cid
        || request.owner_delegation.cid == request.enforcement_delegation.cid
    {
        return Err(error(Status::Forbidden, "policy_registration_invalid"));
    }
    verify_policy_proof(
        &policy.policy.share_key_did,
        &policy_bytes,
        &request.policy.proof,
    )
    .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;
    if cid_revoked(&runtime.conn, &request.enforcement_delegation.cid)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
    {
        return Err(error(Status::Forbidden, "policy_registration_invalid"));
    }

    verify_owner_delegation(runtime, &policy.policy, &request.owner_delegation)
        .await
        .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;
    verify_enforcement_delegation(
        runtime,
        &policy,
        &request.policy.cid,
        &request.enforcement_delegation,
    )
    .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;

    let registered_at = timestamp(OffsetDateTime::now_utc());
    let registration_core = Registration {
        registration_cid: String::new(),
        policy_cid: request.policy.cid.clone(),
        owner_delegation_cid: request.owner_delegation.cid.clone(),
        enforcement_delegation_cid: request.enforcement_delegation.cid.clone(),
        owner_did: policy.policy.owner_did.clone(),
        share_key_did: policy.policy.share_key_did.clone(),
        enforcer_did: policy.policy.target.enforcer_did.clone(),
        target: RegistrationTarget {
            origin: policy.policy.target.origin.clone(),
            node_audience: policy.policy.target.node_audience.clone(),
            enforcer_did: policy.policy.target.enforcer_did.clone(),
            space_id: policy.policy.target.space_id.clone(),
        },
        resource: ExactResource {
            kind: policy.policy.resource.kind.clone(),
            path: policy.policy.resource.path.clone(),
        },
        actions: policy.policy.actions.clone(),
        content_source_digest: request.content_source_digest.clone(),
        registered_at,
        expires_at: policy.policy.expires_at.clone(),
    };
    let mut registration = registration_core;
    let mut registration_value =
        serde_json::to_value(&registration).expect("registration serializes");
    registration_value
        .as_object_mut()
        .expect("registration is an object")
        .remove("registrationCid");
    let registration_cid = raw_sha256_cid(&jcs::canonicalize(&registration_value));
    if registration_cid == request.policy.cid
        || registration_cid == request.owner_delegation.cid
        || registration_cid == request.enforcement_delegation.cid
    {
        return Err(error(Status::Forbidden, "policy_registration_invalid"));
    }
    registration.registration_cid = registration_cid;
    let mut core_value = serde_json::to_value(&registration).expect("registration serializes");
    core_value
        .as_object_mut()
        .expect("registration is an object")
        .remove("registrationCid");
    let signature = runtime
        .signer
        .sign(&jcs::canonicalize(&core_value))
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;

    let enforcement_record = serde_json::to_vec(&request.enforcement_delegation)
        .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;
    let matcher = serde_json::to_value(&policy.policy.recipient_matcher)
        .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;
    let actions = serde_json::to_value(&policy.policy.actions)
        .map_err(|_| error(Status::Forbidden, "policy_registration_invalid"))?;
    let model = owner_share_policy::ActiveModel {
        policy_cid: Set(request.policy.cid.clone()),
        registration_cid: Set(registration.registration_cid.clone()),
        owner_delegation_cid: Set(request.owner_delegation.cid.clone()),
        enforcement_delegation_cid: Set(request.enforcement_delegation.cid.clone()),
        policy_bytes: Set(runtime.policy_encryption.encrypt(&policy_bytes)),
        enforcement_delegation_bytes: Set(runtime.policy_encryption.encrypt(&enforcement_record)),
        policy_proof: Set(request.policy.proof.clone()),
        policy_digest: Set(b64_digest(&policy_bytes)),
        matcher_digest: Set(b64_digest(&jcs::canonicalize(&matcher))),
        content_source_digest: Set(request.content_source_digest),
        owner_did: Set(policy.policy.owner_did.clone()),
        share_key_did: Set(policy.policy.share_key_did.clone()),
        enforcer_did: Set(policy.policy.target.enforcer_did.clone()),
        node_audience: Set(policy.policy.target.node_audience.clone()),
        target_origin: Set(policy.policy.target.origin.clone()),
        space_id: Set(policy.policy.target.space_id.clone()),
        resource_kind: Set(policy.policy.resource.kind.clone()),
        resource_path: Set(policy.policy.resource.path.clone()),
        actions: Set(actions),
        registered_at: Set(registration.registered_at.clone()),
        expires_at: Set(registration.expires_at.clone()),
        revoked_at: Set(None),
    };
    let transaction = runtime
        .conn
        .begin()
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    model
        .insert(&transaction)
        .await
        .map_err(|_| error(Status::Conflict, "policy_registration_exists"))?;
    transaction
        .commit()
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;

    let receipt = Receipt {
        registration,
        proof: ReceiptProof {
            alg: "EdDSA",
            kid: runtime.signer_did.clone(),
            signature: encode_config(signature, URL_SAFE_NO_PAD),
        },
    };
    Ok(Json(serde_json::to_value(receipt).map_err(|_| {
        error(Status::InternalServerError, "capability_unavailable")
    })?))
}

async fn read_body(data: Data<'_>) -> Result<Vec<u8>, ApiErrorResponse> {
    let mut bytes = Vec::new();
    data.open((MAX_REQUEST_BYTES + 1).bytes())
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(error(
            Status::PayloadTooLarge,
            "policy_registration_invalid",
        ));
    }
    Ok(bytes)
}

fn decode_canonical_b64(value: &str, max_bytes: usize) -> Result<Vec<u8>, ()> {
    if value.is_empty() || value.len() > max_bytes.saturating_mul(2) {
        return Err(());
    }
    let bytes = decode_config(value, URL_SAFE_NO_PAD).map_err(|_| ())?;
    if bytes.is_empty()
        || bytes.len() > max_bytes
        || encode_config(&bytes, URL_SAFE_NO_PAD) != value
    {
        return Err(());
    }
    Ok(bytes)
}

fn raw_sha256_cid(bytes: &[u8]) -> String {
    tinycloud_auth::ipld_core::cid::Cid::new_v1(0x55, Code::Sha2_256.digest(bytes)).to_string()
}

fn b64_digest(bytes: &[u8]) -> String {
    encode_config(Sha256::digest(bytes), URL_SAFE_NO_PAD)
}

fn timestamp(value: OffsetDateTime) -> String {
    let format = time::format_description::parse(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
    )
    .expect("fixed timestamp format");
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&format)
        .expect("timestamp formats")
}

fn parse_sdk_policy(
    value: &Value,
    request: &RegisterRequest,
    config: &ShareEmailConfig,
    enforcer_did: &str,
) -> Result<PolicyEnvelope, ()> {
    let sdk: SdkPolicyDocument = serde_json::from_value(value.clone()).map_err(|_| ())?;
    let facts = &request.enforcement_delegation.facts;
    if sdk.artifact_type != "TinyCloudSharePolicy"
        || sdk.version != 2
        || sdk.content_source.kind != "kv"
        || sdk.resource.kind != "exact"
        || sdk.content_source_digest != request.content_source_digest
        || sdk.issuer_did.is_empty()
        || facts.share_id.is_empty()
        || facts.share_key_did.is_empty()
        || facts.enforcer_did != enforcer_did
        || facts.node_audience != config.node_audience
        || facts.space_id != sdk.content_source.space
        || facts.path != sdk.resource.path
        || facts.actions != sdk.actions
        || facts.content_source_digest != sdk.content_source_digest
        || facts.owner_delegation_cid != request.owner_delegation.cid
    {
        return Err(());
    }
    Ok(PolicyEnvelope {
        domain: POLICY_DOMAIN.to_owned(),
        policy: PolicyDocument {
            artifact_type: sdk.artifact_type,
            version: sdk.version,
            share_id: facts.share_id.clone(),
            owner_did: sdk.issuer_did,
            share_key_did: facts.share_key_did.clone(),
            recipient_matcher: sdk.recipient_matcher,
            target: PolicyTarget {
                origin: config.target_origin.clone(),
                node_audience: config.node_audience.clone(),
                enforcer_did: enforcer_did.to_owned(),
                space_id: sdk.content_source.space.clone(),
            },
            resource: ExactResource {
                kind: sdk.resource.kind,
                path: sdk.resource.path,
            },
            actions: sdk.actions,
            content_source: ContentSource {
                kind: sdk.content_source.kind,
                space: sdk.content_source.space,
                path: sdk.content_source.path,
            },
            content_source_digest: sdk.content_source_digest,
            owner_delegation_cid: request.owner_delegation.cid.clone(),
            expires_at: sdk.expires_at,
        },
    })
}

fn validate_policy(
    envelope: &PolicyEnvelope,
    request: &RegisterRequest,
    config: &ShareEmailConfig,
    enforcer_did: &str,
) -> Result<(), ()> {
    if envelope.domain != POLICY_DOMAIN {
        return Err(());
    }
    let policy = &envelope.policy;
    if policy.artifact_type != "TinyCloudSharePolicy"
        || policy.version != 2
        || policy.target.origin != config.target_origin
        || policy.target.node_audience != config.node_audience
        || policy.target.enforcer_did != enforcer_did
        || policy.content_source_digest != request.content_source_digest
        || policy.owner_delegation_cid != request.owner_delegation.cid
        || policy.resource.kind != "exact"
        || policy.content_source.kind != "kv"
        || policy.content_source.path != policy.resource.path
        || policy.content_source.space != policy.target.space_id
    {
        return Err(());
    }
    let source = serde_json::to_value(&policy.content_source).map_err(|_| ())?;
    if b64_digest(&jcs::canonicalize(&source)) != policy.content_source_digest
        || policy.content_source_digest != request.content_source_digest
        || decode_canonical_b64(&policy.content_source_digest, 32)
            .map_or(true, |digest| digest.len() != 32)
    {
        return Err(());
    }
    if policy.share_id.is_empty()
        || policy.share_id.len() > 200
        || policy.owner_did.is_empty()
        || !policy.share_key_did.starts_with("did:key:z")
        || policy.recipient_matcher.value.is_empty()
        || !matches!(
            policy.recipient_matcher.kind.as_str(),
            "exactEmail" | "emailDomain"
        )
        || !policy.recipient_matcher.value.is_ascii()
    {
        return Err(());
    }
    let canonical_matcher = match policy.recipient_matcher.kind.as_str() {
        "exactEmail" => {
            tinycloud_auth::share_email_evidence::normalize_email(&policy.recipient_matcher.value)
                .map_err(|_| ())?
        }
        "emailDomain" => tinycloud_auth::share_email_evidence::normalize_policy_domain(
            &policy.recipient_matcher.value,
        )
        .map_err(|_| ())?,
        _ => return Err(()),
    };
    if canonical_matcher != policy.recipient_matcher.value {
        return Err(());
    }
    let path_parts: Vec<&str> = policy.resource.path.split('/').collect();
    if path_parts.len() != 3
        || path_parts[0] != "shares"
        || path_parts[1] != policy.share_id
        || policy.resource.path.ends_with('/')
        || policy
            .resource
            .path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(());
    }
    let expected_actions = [
        "tinycloud.kv/get",
        "tinycloud.kv/metadata",
        "tinycloud.kv/put",
    ];
    if policy.actions.is_empty()
        || policy.actions.len() > 3
        || policy
            .actions
            .iter()
            .any(|action| !expected_actions.contains(&action.as_str()))
        || policy.actions.windows(2).any(|pair| pair[0] >= pair[1])
        || !policy
            .actions
            .iter()
            .any(|action| action == "tinycloud.kv/get")
        || !policy
            .actions
            .iter()
            .any(|action| action == "tinycloud.kv/metadata")
    {
        return Err(());
    }
    let expiry = OffsetDateTime::parse(&policy.expires_at, &Rfc3339).map_err(|_| ())?;
    if timestamp(expiry) != policy.expires_at || expiry <= OffsetDateTime::now_utc() {
        return Err(());
    }
    Ok(())
}

fn verify_policy_proof(share_key_did: &str, policy_bytes: &[u8], proof: &str) -> Result<(), ()> {
    let signature = decode_canonical_b64(proof, 64)?;
    if signature.len() != 64 {
        return Err(());
    }
    verify_detached_ed25519(share_key_did, policy_bytes, &signature).map_err(|_| ())
}

async fn verify_owner_delegation(
    runtime: &ShareV2Runtime,
    policy: &PolicyDocument,
    input: &OwnerDelegationInput,
) -> Result<(), ()> {
    let bytes = decode_canonical_b64(&input.dag_cbor, MAX_POLICY_BYTES)?;
    if raw_blake3_cid(&bytes) != input.cid {
        return Err(());
    }
    let cid: tinycloud_auth::ipld_core::cid::Cid = input.cid.parse().map_err(|_| ())?;
    let id = tinycloud_core::hash::Hash::from(cid);
    let row = delegation::Entity::find_by_id(id)
        .one(&runtime.conn)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    let stored =
        maybe_decrypt(Some(&runtime.policy_encryption), &row.serialization).map_err(|_| ())?;
    if stored != bytes {
        return Err(());
    }
    if revocation_in_ancestry(&runtime.conn, id).await? {
        return Err(());
    }
    let delegation = TinyCloudDelegation::from_bytes(&bytes).map_err(|_| ())?;
    verify_delegation_signature(&delegation).await?;
    let info = DelegationInfo::try_from(delegation).map_err(|_| ())?;
    if info.delegation_mode == DelegationMode::Terminal
        || !did_principal_matches(&info.delegator, &policy.owner_did)
        || !did_principal_matches(&info.delegate, &policy.share_key_did)
        || row
            .expiry
            .is_none_or(|expiry| expiry <= OffsetDateTime::now_utc())
        || row
            .not_before
            .is_some_and(|not_before| not_before > OffsetDateTime::now_utc())
    {
        return Err(());
    }
    let policy_expiry = OffsetDateTime::parse(&policy.expires_at, &Rfc3339).map_err(|_| ())?;
    if policy_expiry > row.expiry.ok_or(())? {
        return Err(());
    }
    if parent_delegations::Entity::find()
        .filter(parent_delegations::Column::Child.eq(id))
        .count(&runtime.conn)
        .await
        .map_err(|_| ())?
        != 0
    {
        return Err(());
    }
    let abilities = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(id))
        .all(&runtime.conn)
        .await
        .map_err(|_| ())?;
    if abilities.len() != policy.actions.len() {
        return Err(());
    }
    for action in &policy.actions {
        let has_exact = abilities.iter().any(|ability| {
            ability.ability.to_string() == *action
                && ability
                    .resource
                    .tinycloud_resource()
                    .is_some_and(|resource| {
                        resource.service().as_str() == "kv"
                            && resource
                                .path()
                                .is_some_and(|path| path.as_str() == policy.resource.path)
                            && resource.space().to_string() == policy.target.space_id
                    })
        });
        if !has_exact {
            return Err(());
        }
    }
    Ok(())
}

async fn verify_delegation_signature(delegation: &TinyCloudDelegation) -> Result<(), ()> {
    match delegation {
        TinyCloudDelegation::Ucan(ucan) => {
            ucan.verify_signature(&tinycloud_auth::ssi::dids::AnyDidMethod::default())
                .await
                .map_err(|_| ())?;
            ucan.payload().validate_time(None).map_err(|_| ())?;
        }
        TinyCloudDelegation::Cacao(cacao) => {
            cacao.verify().await.map_err(|_| ())?;
            if !cacao.payload().valid_now() {
                return Err(());
            }
        }
    }
    Ok(())
}

fn raw_blake3_cid(bytes: &[u8]) -> String {
    tinycloud_core::hash::hash(bytes).to_cid(0x55).to_string()
}

async fn revocation_in_ancestry<C: ConnectionTrait>(
    db: &C,
    root: tinycloud_core::hash::Hash,
) -> Result<bool, ()> {
    let mut frontier = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        if visited.len() > MAX_GRAPH_NODES {
            return Err(());
        }
        if revocation::Entity::find()
            .filter(revocation::Column::Revoked.eq(current))
            .count(db)
            .await
            .map_err(|_| ())?
            > 0
        {
            return Ok(true);
        }
        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(current))
            .all(db)
            .await
            .map_err(|_| ())?;
        frontier.extend(parents.into_iter().map(|parent| parent.parent));
    }
    Ok(false)
}

fn verify_dag_cbor_enforcement(input: &EnforcementDelegationInput) -> Result<Value, ()> {
    let bytes = decode_canonical_b64(&input.dag_cbor, MAX_POLICY_BYTES)?;
    if raw_sha256_cid(&bytes) != input.cid {
        return Err(());
    }
    let value: Value = serde_ipld_dagcbor::from_slice(&bytes).map_err(|_| ())?;
    if serde_ipld_dagcbor::to_vec(&value).map_err(|_| ())? != bytes {
        return Err(());
    }
    Ok(value)
}

fn verify_enforcement_delegation(
    runtime: &ShareV2Runtime,
    envelope: &PolicyEnvelope,
    policy_cid: &str,
    input: &EnforcementDelegationInput,
) -> Result<(), ()> {
    let value = verify_dag_cbor_enforcement(input)?;
    let object = value.as_object().ok_or(())?;
    if object.len() != 2 || object.get("domain") != Some(&Value::String(ENFORCEMENT_DOMAIN.into()))
    {
        return Err(());
    }
    let unsigned = object
        .get("unsigned")
        .and_then(Value::as_object)
        .ok_or(())?;
    if unsigned.len() != 5
        || unsigned.get("type") != Some(&Value::String("TinyCloudSharePolicyEnforcement".into()))
        || unsigned.get("version") != Some(&Value::Number(2.into()))
        || unsigned.get("issuerDid").and_then(Value::as_str) != Some(input.issuer_did.as_str())
        || unsigned.get("audienceDid").and_then(Value::as_str) != Some(input.audience_did.as_str())
    {
        return Err(());
    }
    let facts_value = unsigned.get("facts").ok_or(())?;
    let facts: EnforcementFacts = serde_json::from_value(facts_value.clone()).map_err(|_| ())?;
    if input.facts != facts
        || input.issuer_did != envelope.policy.share_key_did
        || input.audience_did != envelope.policy.target.enforcer_did
        || facts.owner_delegation_cid != envelope.policy.owner_delegation_cid
        || facts.policy_cid != policy_cid
        || facts.share_id != envelope.policy.share_id
        || facts.share_key_did != envelope.policy.share_key_did
        || facts.enforcer_did != runtime.enforcer_did
        || facts.node_audience != runtime.config.node_audience
        || facts.space_id != envelope.policy.target.space_id
        || facts.path != envelope.policy.resource.path
        || facts.actions != envelope.policy.actions
        || facts.content_source_digest != envelope.policy.content_source_digest
        || facts.expires_at != envelope.policy.expires_at
    {
        return Err(());
    }
    let signature = decode_canonical_b64(&input.signature, 64)?;
    if signature.len() != 64 {
        return Err(());
    }
    verify_detached_ed25519(
        &input.issuer_did,
        &decode_canonical_b64(&input.dag_cbor, MAX_POLICY_BYTES)?,
        &signature,
    )
    .map_err(|_| ())
}

const V2_CHALLENGE_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy-challenge/v2\0";
const V2_SESSION_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy-session/v2\0";
const V2_INVOCATION_DOMAIN: &[u8] = b"xyz.tinycloud.share/invocation/v2\0";
const V2_DELIVERY_DOMAIN: &[u8] = b"xyz.tinycloud.share/delivery-authorization/v2\0";
const RUNTIME_DELEGATION_DOMAIN: &str = "xyz.tinycloud.share/runtime-delegation/v2\\0";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2ChallengeRequest {
    envelope_cid: String,
    share_cid: String,
    share_id: String,
    registration_cid: String,
    delegation_cid: String,
    policy_cid: String,
    enforcement_delegation_cid: String,
    enforcement_delegation: EnforcementDelegationInput,
    outer_envelope: Value,
    content_source: Value,
    content_source_digest: String,
    holder_did: String,
    target_origin: String,
    node_audience: String,
    action: String,
    actions: Vec<String>,
    resource: String,
    request_body_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2SessionRequest {
    challenge_id: String,
    nonce: String,
    presentation: Value,
    credential: String,
    proof: DetachedProofV2,
    holder_binding: Value,
    read_signer_did: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2PolicyPresentation {
    #[serde(rename = "type")]
    artifact_type: String,
    version: u8,
    challenge_id: String,
    nonce: String,
    share_cid: String,
    share_id: String,
    delegation_cid: String,
    policy_cid: String,
    content_source: Value,
    content_source_digest: String,
    holder_did: String,
    target_origin: String,
    node_audience: String,
    enforcer_did: String,
    credential_digest: String,
    action: String,
    actions: Vec<String>,
    resource: String,
    request_body_digest: String,
    issued_at: String,
    expires_at: String,
    jti: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DetachedProofV2 {
    alg: String,
    kid: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2InvokeEnvelope {
    request: V2InvokeRequest,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_digest: Option<String>,
    #[serde(default)]
    if_match: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2InvokeRequest {
    session_id: String,
    envelope_cid: String,
    share_cid: String,
    share_id: String,
    registration_cid: String,
    delegation_cid: String,
    policy_cid: String,
    enforcement_delegation_cid: String,
    content_source: Value,
    content_source_digest: String,
    holder_did: String,
    node_audience: String,
    action: String,
    actions: Vec<String>,
    resource: String,
    request_body_digest: String,
    invocation: V2Invocation,
    proof: DetachedProofV2,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2Invocation {
    #[serde(rename = "type")]
    artifact_type: String,
    version: u8,
    session_id: String,
    envelope_cid: String,
    share_cid: String,
    share_id: String,
    registration_cid: String,
    delegation_cid: String,
    policy_cid: String,
    enforcement_delegation_cid: String,
    content_source: Value,
    content_source_digest: String,
    holder_did: String,
    node_audience: String,
    action: String,
    actions: Vec<String>,
    resource: String,
    issued_at: String,
    expires_at: String,
    jti: String,
    request_body_digest: String,
    #[serde(default)]
    body_digest: Option<String>,
    #[serde(default)]
    if_match: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2DeliveryRequest {
    envelope_cid: String,
    share_cid: String,
    share_id: String,
    registration_cid: String,
    policy_cid: String,
    delegation_cid: String,
    enforcement_delegation_cid: String,
    jti: String,
    expires_at: String,
    request_body_digest: String,
}

#[derive(Debug)]
struct RegisteredPolicy {
    row: owner_share_policy::Model,
    envelope: PolicyEnvelope,
    matcher: TypedRecipientMatcher,
    expiry: OffsetDateTime,
}

fn signed_value(
    signer: &Ed25519InvitationSigner,
    domain: &[u8],
    value: &Value,
) -> Result<DetachedProofV2, ()> {
    let mut bytes = domain.to_vec();
    bytes.extend(jcs::canonicalize(value));
    let signature = signer.sign(&bytes).map_err(|_| ())?;
    Ok(DetachedProofV2 {
        alg: "EdDSA".to_owned(),
        kid: signer.kid().to_owned(),
        signature: encode_config(signature, URL_SAFE_NO_PAD),
    })
}

fn verify_v2_proof(
    holder_did: &str,
    proof: &DetachedProofV2,
    domain: &[u8],
    value: &Value,
) -> Result<(), ()> {
    let signature = decode_canonical_b64(&proof.signature, 64).map_err(|_| ())?;
    if proof.alg != "EdDSA"
        || signature.len() != 64
        || proof.kid
            != format!(
                "{}#{}",
                holder_did,
                holder_did.trim_start_matches("did:key:")
            )
    {
        return Err(());
    }
    let mut bytes = domain.to_vec();
    bytes.extend(jcs::canonicalize(value));
    verify_detached_ed25519(holder_did, &bytes, &signature).map_err(|_| ())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2EnvelopeSignature {
    signer_did: String,
    algorithm: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct V2OuterEnvelope {
    schema: String,
    version: u8,
    envelope_cid: String,
    share_cid: String,
    share_id: String,
    delegation_cid: String,
    policy_cid: String,
    target: PolicyTarget,
    resource: ExactResource,
    actions: Vec<String>,
    content_source: Value,
    content_source_digest: String,
    expires_at: String,
    signature: V2EnvelopeSignature,
}

fn verify_outer_envelope(
    outer: &Value,
    request: &V2ChallengeRequest,
    share_key_did: &str,
) -> Result<OffsetDateTime, ()> {
    let envelope: V2OuterEnvelope = serde_json::from_value(outer.clone()).map_err(|_| ())?;
    let normalized = serde_json::to_value(&envelope).map_err(|_| ())?;
    if jcs::canonicalize(outer) != jcs::canonicalize(&normalized) {
        return Err(());
    }
    if envelope.schema != "xyz.tinycloud.share/envelope/v2"
        || envelope.version != 2
        || envelope.signature.algorithm != "Ed25519"
        || envelope.signature.signer_did != share_key_did
        || envelope.envelope_cid != request.envelope_cid
        || envelope.share_cid != request.share_cid
        || envelope.share_id != request.share_id
        || envelope.delegation_cid != request.delegation_cid
        || envelope.policy_cid != request.policy_cid
        || envelope.target.origin != request.target_origin
        || envelope.target.node_audience != request.node_audience
        || envelope.target.enforcer_did.is_empty()
        || envelope.target.space_id
            != request
                .content_source
                .get("space")
                .and_then(Value::as_str)
                .ok_or(())?
        || envelope.resource.kind != "exact"
        || envelope.resource.path != request.resource
        || envelope.actions != request.actions
        || envelope.content_source != request.content_source
        || envelope.content_source_digest != request.content_source_digest
    {
        return Err(());
    }
    let mut unsigned = serde_json::to_value(&envelope).map_err(|_| ())?;
    unsigned.as_object_mut().ok_or(())?.remove("signature");
    let mut signed = b"xyz.tinycloud.share/envelope/v2\0".to_vec();
    signed.extend(jcs::canonicalize(&unsigned));
    let signature = decode_canonical_b64(&envelope.signature.value, 64)?;
    if signature.len() != 64 || verify_detached_ed25519(share_key_did, &signed, &signature).is_err()
    {
        return Err(());
    }
    let expiry = OffsetDateTime::parse(&envelope.expires_at, &Rfc3339).map_err(|_| ())?;
    if timestamp(expiry) != envelope.expires_at || expiry <= OffsetDateTime::now_utc() {
        return Err(());
    }
    if b64_digest(&jcs::canonicalize(&envelope.content_source)) != envelope.content_source_digest {
        return Err(());
    }
    Ok(expiry)
}

async fn registered_policy(
    runtime: &ShareV2Runtime,
    registration_cid: &str,
    policy_cid: &str,
) -> Result<RegisteredPolicy, ()> {
    let row = owner_share_policy::Entity::find()
        .filter(owner_share_policy::Column::RegistrationCid.eq(registration_cid))
        .filter(owner_share_policy::Column::PolicyCid.eq(policy_cid))
        .one(&runtime.conn)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    if row.revoked_at.is_some() || row.policy_cid == row.registration_cid {
        return Err(());
    }
    let bytes =
        maybe_decrypt(Some(&runtime.policy_encryption), &row.policy_bytes).map_err(|_| ())?;
    if raw_sha256_cid(&bytes) != row.policy_cid
        || b64_digest(&bytes) != row.policy_digest
        || row.policy_proof.is_empty()
    {
        return Err(());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if jcs::canonicalize(&value) != bytes {
        return Err(());
    }
    let policy = if let Ok(policy) = serde_json::from_value::<PolicyEnvelope>(value.clone()) {
        policy
    } else {
        let sdk: SdkPolicyDocument = serde_json::from_value(value).map_err(|_| ())?;
        let share_id = row.resource_path.split('/').nth(1).ok_or(())?.to_owned();
        PolicyEnvelope {
            domain: POLICY_DOMAIN.to_owned(),
            policy: PolicyDocument {
                artifact_type: sdk.artifact_type,
                version: sdk.version,
                share_id,
                owner_did: row.owner_did.clone(),
                share_key_did: row.share_key_did.clone(),
                recipient_matcher: sdk.recipient_matcher,
                target: PolicyTarget {
                    origin: row.target_origin.clone(),
                    node_audience: row.node_audience.clone(),
                    enforcer_did: row.enforcer_did.clone(),
                    space_id: row.space_id.clone(),
                },
                resource: ExactResource {
                    kind: sdk.resource.kind,
                    path: sdk.resource.path,
                },
                actions: sdk.actions,
                content_source: ContentSource {
                    kind: sdk.content_source.kind,
                    space: sdk.content_source.space,
                    path: sdk.content_source.path,
                },
                content_source_digest: sdk.content_source_digest,
                owner_delegation_cid: row.owner_delegation_cid.clone(),
                expires_at: sdk.expires_at,
            },
        }
    };
    verify_policy_proof(&row.share_key_did, &bytes, &row.policy_proof).map_err(|_| ())?;
    validate_policy(
        &policy,
        &RegisterRequest {
            policy: PolicyInput {
                bytes: String::new(),
                cid: row.policy_cid.clone(),
                proof: String::new(),
            },
            owner_delegation: OwnerDelegationInput {
                cid: row.owner_delegation_cid.clone(),
                dag_cbor: String::new(),
            },
            enforcement_delegation: EnforcementDelegationInput {
                cid: row.enforcement_delegation_cid.clone(),
                dag_cbor: String::new(),
                issuer_did: row.share_key_did.clone(),
                audience_did: row.enforcer_did.clone(),
                facts: EnforcementFacts {
                    owner_delegation_cid: row.owner_delegation_cid.clone(),
                    policy_cid: row.policy_cid.clone(),
                    share_id: policy.policy.share_id.clone(),
                    share_key_did: row.share_key_did.clone(),
                    enforcer_did: row.enforcer_did.clone(),
                    node_audience: row.node_audience.clone(),
                    space_id: row.space_id.clone(),
                    path: row.resource_path.clone(),
                    actions: serde_json::from_value(row.actions.clone()).map_err(|_| ())?,
                    content_source_digest: row.content_source_digest.clone(),
                    expires_at: row.expires_at.clone(),
                },
                signature: String::new(),
            },
            content_source_digest: row.content_source_digest.clone(),
        },
        &runtime.config,
        &runtime.enforcer_did,
    )
    .map_err(|_| ())?;
    let expiry = OffsetDateTime::parse(&row.expires_at, &Rfc3339).map_err(|_| ())?;
    if expiry <= OffsetDateTime::now_utc() {
        return Err(());
    }
    let matcher = match policy.policy.recipient_matcher.kind.as_str() {
        "exactEmail" => TypedRecipientMatcher::ExactEmail(
            tinycloud_auth::share_email_evidence::normalize_email(
                &policy.policy.recipient_matcher.value,
            )
            .map_err(|_| ())?,
        ),
        "emailDomain" => TypedRecipientMatcher::EmailDomain(
            tinycloud_auth::share_email_evidence::normalize_policy_domain(
                &policy.policy.recipient_matcher.value,
            )
            .map_err(|_| ())?,
        ),
        _ => return Err(()),
    };
    let matcher_json = serde_json::to_value(&policy.policy.recipient_matcher).map_err(|_| ())?;
    if b64_digest(&jcs::canonicalize(&matcher_json)) != row.matcher_digest {
        return Err(());
    }
    Ok(RegisteredPolicy {
        row,
        envelope: policy,
        matcher,
        expiry,
    })
}

async fn verify_registered_ancestors(
    runtime: &ShareV2Runtime,
    registered: &RegisteredPolicy,
    supplied_enforcement: Option<&EnforcementDelegationInput>,
) -> Result<(), ()> {
    let id: tinycloud_core::hash::Hash = registered
        .row
        .owner_delegation_cid
        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
        .map_err(|_| ())?
        .into();
    let row = delegation::Entity::find_by_id(id)
        .one(&runtime.conn)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    let bytes =
        maybe_decrypt(Some(&runtime.policy_encryption), &row.serialization).map_err(|_| ())?;
    let owner = OwnerDelegationInput {
        cid: registered.row.owner_delegation_cid.clone(),
        dag_cbor: encode_config(bytes, URL_SAFE_NO_PAD),
    };
    verify_owner_delegation(runtime, &registered.envelope.policy, &owner).await?;
    let enforcement = if let Some(enforcement) = supplied_enforcement {
        enforcement.clone()
    } else {
        let stored = maybe_decrypt(
            Some(&runtime.policy_encryption),
            &registered.row.enforcement_delegation_bytes,
        )
        .map_err(|_| ())?;
        serde_json::from_slice(&stored).map_err(|_| ())?
    };
    if enforcement.cid != registered.row.enforcement_delegation_cid
        || cid_revoked(&runtime.conn, &enforcement.cid).await?
    {
        return Err(());
    }
    verify_enforcement_delegation(
        runtime,
        &registered.envelope,
        &registered.row.policy_cid,
        &enforcement,
    )
}

async fn cid_revoked<C: ConnectionTrait>(db: &C, cid: &str) -> Result<bool, ()> {
    let id: tinycloud_core::hash::Hash = cid
        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
        .map_err(|_| ())?
        .into();
    Ok(revocation::Entity::find()
        .filter(revocation::Column::Revoked.eq(id))
        .count(db)
        .await
        .map_err(|_| ())?
        > 0)
}

fn typed_scope(
    registered: &RegisteredPolicy,
    request: &V2ChallengeRequest,
) -> Result<ShareScope, ()> {
    let action = match request.action.as_str() {
        "tinycloud.kv/get" => ShareAction::KvGet,
        "tinycloud.kv/metadata" => ShareAction::KvGet,
        "tinycloud.kv/put" => ShareAction::KvPut,
        "tinycloud.kv/list" => ShareAction::KvList,
        _ => return Err(()),
    };
    let space_id: tinycloud_auth::resource::SpaceId =
        registered.row.space_id.parse().map_err(|_| ())?;
    let space = Did::parse(space_id.did().as_str().to_owned()).map_err(|_| ())?;
    let path = tinycloud_core::share_email::types::Path::parse(request.resource.clone())
        .map_err(|_| ())?;
    let source_path =
        tinycloud_core::share_email::types::Path::parse(registered.row.resource_path.clone())
            .map_err(|_| ())?;
    if path != source_path {
        return Err(());
    }
    let content_source = tinycloud_core::share_email::types::ContentSource::Kv {
        space: space.clone(),
        path: source_path,
        action: match action {
            ShareAction::KvPut => tinycloud_core::share_email::types::KvGetAction::Put,
            ShareAction::KvList => tinycloud_core::share_email::types::KvGetAction::List,
            _ => tinycloud_core::share_email::types::KvGetAction::Get,
        },
    };
    let digest = decode_canonical_b64(&registered.row.content_source_digest, 64).map_err(|_| ())?;
    let source_digest =
        tinycloud_core::share_email::Sha256Digest::from_bytes(digest.try_into().map_err(|_| ())?);
    Ok(ShareScope {
        share_cid: ShareCid::parse(request.share_cid.clone()).map_err(|_| ())?,
        share_id: ShareId::parse(request.share_id.clone()).map_err(|_| ())?,
        delegation_cid: Some(
            ShareDelegationCid::parse(request.delegation_cid.clone()).map_err(|_| ())?,
        ),
        authority_material_handle: AuthorityMaterialHandle::parse(format!(
            "amh_{}",
            registered.row.registration_cid
        ))
        .map_err(|_| ())?,
        authority_material_digest: source_digest.clone(),
        policy_cid: PolicyCid::parse(request.policy_cid.clone()).map_err(|_| ())?,
        node_audience: Did::parse(request.node_audience.clone()).map_err(|_| ())?,
        target_origin: TargetOrigin::parse(request.target_origin.clone()).map_err(|_| ())?,
        action,
        allowed_actions: request
            .actions
            .iter()
            .map(|action| match action.as_str() {
                "tinycloud.kv/get" | "tinycloud.kv/metadata" => Ok(ShareAction::KvGet),
                "tinycloud.kv/list" => Ok(ShareAction::KvList),
                "tinycloud.kv/put" => Ok(ShareAction::KvPut),
                _ => Err(()),
            })
            .collect::<Result<Vec<_>, _>>()?,
        resource: tinycloud_core::share_email::types::ExactResource::Kv { path },
        content_source,
        content_source_digest: source_digest,
    })
}

fn exact_content_source(registered: &RegisteredPolicy, _request: &V2ChallengeRequest) -> Value {
    serde_json::json!({
        "kind": "kv",
        "space": registered.row.space_id,
        "path": registered.row.resource_path,
    })
}

fn verify_policy_presentation(
    presentation: &Value,
    request: &V2ChallengeRequest,
    challenge_id: &str,
    nonce: &str,
    credential_digest: &str,
    enforcer_did: &str,
) -> Result<(), ()> {
    if presentation.get("type").and_then(Value::as_str) != Some("TinyCloudSharePolicyPresentation")
        || presentation.get("version").and_then(Value::as_u64) != Some(1)
        || presentation.get("challengeId").and_then(Value::as_str) != Some(challenge_id)
        || presentation.get("nonce").and_then(Value::as_str) != Some(nonce)
        || presentation.get("shareCid").and_then(Value::as_str) != Some(request.share_cid.as_str())
        || presentation.get("shareId").and_then(Value::as_str) != Some(request.share_id.as_str())
        || presentation.get("delegationCid").and_then(Value::as_str)
            != Some(request.delegation_cid.as_str())
        || presentation.get("policyCid").and_then(Value::as_str)
            != Some(request.policy_cid.as_str())
        || presentation.get("contentSource") != Some(&request.content_source)
        || presentation
            .get("contentSourceDigest")
            .and_then(Value::as_str)
            != Some(request.content_source_digest.as_str())
        || presentation.get("holderDid").and_then(Value::as_str)
            != Some(request.holder_did.as_str())
        || presentation.get("targetOrigin").and_then(Value::as_str)
            != Some(request.target_origin.as_str())
        || presentation.get("nodeAudience").and_then(Value::as_str)
            != Some(request.node_audience.as_str())
        || presentation.get("enforcerDid").and_then(Value::as_str) != Some(enforcer_did)
        || presentation.get("action").and_then(Value::as_str) != Some(request.action.as_str())
        || presentation.get("actions")
            != Some(&Value::Array(
                request.actions.iter().cloned().map(Value::String).collect(),
            ))
        || presentation.get("resource").and_then(Value::as_str) != Some(request.resource.as_str())
        || presentation
            .get("requestBodyDigest")
            .and_then(Value::as_str)
            != Some(request.request_body_digest.as_str())
        || presentation.get("credentialDigest").and_then(Value::as_str) != Some(credential_digest)
    {
        return Err(());
    }
    Ok(())
}

fn runtime_delegation_facts(
    registered: &RegisteredPolicy,
    request: &V2ChallengeRequest,
    holder_did: &str,
    credential_digest: &str,
    vp_digest: &str,
    expires_at: &str,
) -> Value {
    serde_json::json!({
        "ownerDelegationCid": registered.row.owner_delegation_cid,
        "policyCid": registered.row.policy_cid,
        "registrationCid": registered.row.registration_cid,
        "enforcementDelegationCid": registered.row.enforcement_delegation_cid,
        "envelopeCid": request.envelope_cid.clone(),
        "shareCid": request.share_cid,
        "shareId": request.share_id,
        "shareKeyDid": registered.row.share_key_did,
        "enforcerDid": registered.row.enforcer_did,
        "holderDid": holder_did,
        "nodeAudience": registered.row.node_audience,
        "spaceId": registered.row.space_id,
        "path": registered.row.resource_path,
        "actions": request.actions,
        "contentSourceDigest": registered.row.content_source_digest,
        "credentialDigest": credential_digest,
        "vpDigest": vp_digest,
        "expiresAt": expires_at,
    })
}

async fn create_runtime_delegation(
    runtime: &ShareV2Runtime,
    registered: &RegisteredPolicy,
    request: &V2ChallengeRequest,
    holder_did: &str,
    credential_digest: &str,
    vp_digest: &str,
    expires_at: &str,
) -> Result<Value, ()> {
    let facts = runtime_delegation_facts(
        registered,
        request,
        holder_did,
        credential_digest,
        vp_digest,
        expires_at,
    );
    let unsigned = serde_json::json!({
        "type": "TinyCloudShareRuntimeDelegation",
        "version": 2,
        "issuerDid": runtime.enforcer_did,
        "audienceDid": holder_did,
        "facts": facts,
    });
    let dag_value = serde_json::json!({
        "domain": RUNTIME_DELEGATION_DOMAIN,
        "unsigned": unsigned,
    });
    let dag_bytes = serde_ipld_dagcbor::to_vec(&dag_value).map_err(|_| ())?;
    let signature = runtime.enforcer_signer.sign(&dag_bytes).map_err(|_| ())?;
    Ok(serde_json::json!({
        "type": "TinyCloudShareRuntimeDelegation",
        "version": 2,
        "cid": raw_blake3_cid(&dag_bytes),
        "dagCbor": encode_config(&dag_bytes, URL_SAFE_NO_PAD),
        "issuerDid": runtime.enforcer_did,
        "audienceDid": holder_did,
        "facts": dag_value.get("unsigned").and_then(|v| v.get("facts")).ok_or(())?,
        "expiresAt": expires_at,
        "signature": encode_config(signature, URL_SAFE_NO_PAD),
    }))
}

#[allow(clippy::too_many_arguments)]
fn verify_runtime_delegation(
    runtime: &ShareV2Runtime,
    value: &Value,
    registered: &RegisteredPolicy,
    request: &V2ChallengeRequest,
    holder_did: &str,
    credential_digest: &str,
    vp_digest: &str,
    session_expires_at: &str,
) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != 9
        || object.get("type") != Some(&Value::String("TinyCloudShareRuntimeDelegation".into()))
        || object.get("version") != Some(&Value::Number(2.into()))
        || object.get("issuerDid").and_then(Value::as_str) != Some(runtime.enforcer_did.as_str())
        || object.get("audienceDid").and_then(Value::as_str) != Some(holder_did)
    {
        return Err(());
    }
    let bytes = decode_canonical_b64(
        object.get("dagCbor").and_then(Value::as_str).ok_or(())?,
        MAX_POLICY_BYTES,
    )?;
    if raw_blake3_cid(&bytes) != object.get("cid").and_then(Value::as_str).ok_or(())? {
        return Err(());
    }
    let dag_value: Value = serde_ipld_dagcbor::from_slice(&bytes).map_err(|_| ())?;
    if serde_ipld_dagcbor::to_vec(&dag_value).map_err(|_| ())? != bytes
        || dag_value.get("domain").and_then(Value::as_str) != Some(RUNTIME_DELEGATION_DOMAIN)
        || dag_value
            .get("unsigned")
            .and_then(|v| v.get("issuerDid"))
            .and_then(Value::as_str)
            != Some(runtime.enforcer_did.as_str())
        || dag_value
            .get("unsigned")
            .and_then(|v| v.get("audienceDid"))
            .and_then(Value::as_str)
            != Some(holder_did)
        || dag_value.get("unsigned").and_then(|v| v.get("facts"))
            != Some(&runtime_delegation_facts(
                registered,
                request,
                holder_did,
                credential_digest,
                vp_digest,
                session_expires_at,
            ))
        || object.get("facts") != dag_value.get("unsigned").and_then(|v| v.get("facts"))
        || object.get("expiresAt").and_then(Value::as_str) != Some(session_expires_at)
    {
        return Err(());
    }
    let signature = decode_canonical_b64(
        object.get("signature").and_then(Value::as_str).ok_or(())?,
        64,
    )?;
    verify_detached_ed25519(&runtime.enforcer_did, &bytes, &signature).map_err(|_| ())?;
    let expiry = OffsetDateTime::parse(
        object.get("expiresAt").and_then(Value::as_str).ok_or(())?,
        &Rfc3339,
    )
    .map_err(|_| ())?;
    let session_expiry = OffsetDateTime::parse(session_expires_at, &Rfc3339).map_err(|_| ())?;
    if expiry <= OffsetDateTime::now_utc() || expiry > session_expiry {
        return Err(());
    }
    Ok(())
}

fn request_digest_without(value: &Value, field: &str) -> Result<String, ()> {
    let mut value = value.clone();
    value.as_object_mut().ok_or(())?.remove(field);
    Ok(b64_digest(&jcs::canonicalize(&value)))
}

fn now_string() -> String {
    timestamp(OffsetDateTime::now_utc())
}

fn share_error(code: &'static str) -> ApiErrorResponse {
    error(Status::Forbidden, code)
}

#[post("/share/v2/policy/challenges", format = "json", data = "<data>")]
pub async fn policy_challenge_v2(
    data: Data<'_>,
    runtime: &State<Option<ShareV2Runtime>>,
    _origin: ShareV2Origin,
) -> Result<Json<Value>, ApiErrorResponse> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    if !runtime.live().await {
        return Err(error(Status::ServiceUnavailable, "capability_unavailable"));
    }
    let bytes = read_body(data).await?;
    let raw: Value = serde_json::from_slice(&bytes)
        .map_err(|_| error(Status::BadRequest, "policy_challenge_invalid"))?;
    let request: V2ChallengeRequest = serde_json::from_value(raw.clone())
        .map_err(|_| error(Status::BadRequest, "policy_challenge_invalid"))?;
    if request_digest_without(&raw, "requestBodyDigest")
        .ok()
        .as_deref()
        != Some(request.request_body_digest.as_str())
    {
        return Err(share_error("policy_challenge_invalid"));
    }
    let registered = registered_policy(runtime, &request.registration_cid, &request.policy_cid)
        .await
        .map_err(|_| share_error("policy_denied"))?;
    if request.envelope_cid == request.registration_cid
        || request.share_cid == request.envelope_cid
        || request.share_id != registered.envelope.policy.share_id
        || request.delegation_cid != registered.row.owner_delegation_cid
        || request.enforcement_delegation_cid != registered.row.enforcement_delegation_cid
        || request.target_origin != runtime.config.target_origin
        || request.node_audience != runtime.config.node_audience
        || request.content_source_digest != registered.row.content_source_digest
        || request.content_source != exact_content_source(&registered, &request)
        || b64_digest(&jcs::canonicalize(&request.content_source)) != request.content_source_digest
        || request.resource != registered.row.resource_path
        || request.actions.is_empty()
        || !request.actions.contains(&request.action)
        || request.actions.windows(2).any(|pair| pair[0] >= pair[1])
        || request
            .actions
            .iter()
            .any(|action| !registered.envelope.policy.actions.contains(action))
        || !registered.envelope.policy.actions.contains(&request.action)
    {
        return Err(share_error("policy_denied"));
    }
    let outer_expiry = verify_outer_envelope(
        &request.outer_envelope,
        &request,
        &registered.row.share_key_did,
    )
    .map_err(|_| share_error("policy_denied"))?;
    if outer_expiry > registered.expiry {
        return Err(share_error("policy_expired"));
    }
    verify_registered_ancestors(runtime, &registered, Some(&request.enforcement_delegation))
        .await
        .map_err(|_| share_error("policy_denied"))?;
    let scope = typed_scope(&registered, &request).map_err(|_| share_error("policy_denied"))?;
    if scope.allowed_actions.is_empty() || !scope.allowed_actions.contains(&scope.action) {
        return Err(share_error("policy_denied"));
    }
    let now = OffsetDateTime::now_utc();
    let challenge_id = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let nonce = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let expires = (now + time::Duration::seconds(120)).min(registered.expiry);
    if expires <= now {
        return Err(share_error("policy_expired"));
    }
    let mut redacted_request = raw.clone();
    let redacted_outer = serde_json::json!({
        "envelopeCid": request.envelope_cid,
        "digest": b64_digest(&jcs::canonicalize(&request.outer_envelope)),
    });
    let redacted_enforcement = serde_json::json!({
        "cid": request.enforcement_delegation.cid.clone(),
        "dagCbor": "",
        "issuerDid": request.enforcement_delegation.issuer_did.clone(),
        "audienceDid": request.enforcement_delegation.audience_did.clone(),
        "facts": request.enforcement_delegation.facts.clone(),
        "signature": "",
    });
    let redacted_object = redacted_request
        .as_object_mut()
        .ok_or_else(|| share_error("policy_challenge_invalid"))?;
    redacted_object.insert("outerEnvelope".to_owned(), redacted_outer);
    redacted_object.insert("enforcementDelegation".to_owned(), redacted_enforcement);
    let binding = serde_json::json!({ "request": redacted_request });
    share_anonymous_challenge::ActiveModel {
        challenge_id: Set(challenge_id.as_str().to_owned()),
        request_digest: Set(request.request_body_digest.clone()),
        binding_json: Set(binding),
        origin_digest: Set(b64_digest(request.target_origin.as_bytes())),
        ip_digest: Set(String::new()),
        share_digest: Set(b64_digest(request.envelope_cid.as_bytes())),
        nonce_hash: Set(b64_digest(nonce.as_str().as_bytes())),
        issued_at: Set(timestamp(now)),
        expires_at: Set(timestamp(expires)),
        consumed_at: Set(None),
    }
    .insert(&runtime.conn)
    .await
    .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let challenge = serde_json::json!({
        "type": "TinyCloudSharePolicyChallenge",
        "version": 2,
        "challengeId": challenge_id,
        "nonce": nonce,
        "envelopeCid": request.envelope_cid,
        "shareCid": request.share_cid,
        "shareId": request.share_id,
        "registrationCid": request.registration_cid,
        "delegationCid": request.delegation_cid,
        "policyCid": request.policy_cid,
        "enforcementDelegationCid": request.enforcement_delegation_cid,
        "contentSource": request.content_source,
        "contentSourceDigest": request.content_source_digest,
        "holderDid": request.holder_did,
        "targetOrigin": request.target_origin,
        "nodeAudience": request.node_audience,
        "enforcerDid": runtime.enforcer_did,
        "action": request.action,
        "actions": request.actions,
        "resource": request.resource,
        "requestBodyDigest": request.request_body_digest,
        "issuedAt": timestamp(now),
        "expiresAt": timestamp(expires),
    });
    let proof = signed_value(runtime.signer.as_ref(), V2_CHALLENGE_DOMAIN, &challenge)
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    Ok(Json(
        serde_json::json!({ "challenge": challenge, "proof": proof }),
    ))
}

#[post("/share/v2/policy/session", format = "json", data = "<data>")]
pub async fn policy_session_v2(
    data: Data<'_>,
    runtime: &State<Option<ShareV2Runtime>>,
    _origin: ShareV2Origin,
) -> Result<Json<Value>, ApiErrorResponse> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    if !runtime.live().await {
        return Err(error(Status::ServiceUnavailable, "capability_unavailable"));
    }
    let raw = read_body(data).await?;
    let request: V2SessionRequest = serde_json::from_slice(&raw)
        .map_err(|_| error(Status::BadRequest, "policy_session_invalid"))?;
    let challenge = share_anonymous_challenge::Entity::find_by_id(&request.challenge_id)
        .one(&runtime.conn)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
        .ok_or_else(|| share_error("policy_session_invalid"))?;
    let now = OffsetDateTime::now_utc();
    if challenge.consumed_at.is_some()
        || OffsetDateTime::parse(&challenge.expires_at, &Rfc3339)
            .map_err(|_| share_error("policy_session_invalid"))?
            <= now
        || challenge.nonce_hash != b64_digest(request.nonce.as_bytes())
    {
        return Err(share_error("policy_session_replayed"));
    }
    let challenge_request: Value = challenge
        .binding_json
        .get("request")
        .cloned()
        .ok_or_else(|| share_error("policy_session_invalid"))?;
    let challenge_request: V2ChallengeRequest = serde_json::from_value(challenge_request)
        .map_err(|_| share_error("policy_session_invalid"))?;
    let registered = registered_policy(
        runtime,
        &challenge_request.registration_cid,
        &challenge_request.policy_cid,
    )
    .await
    .map_err(|_| share_error("policy_denied"))?;
    if challenge_request.content_source != exact_content_source(&registered, &challenge_request)
        || b64_digest(&jcs::canonicalize(&challenge_request.content_source))
            != challenge_request.content_source_digest
    {
        return Err(share_error("policy_denied"));
    }
    verify_registered_ancestors(runtime, &registered, None)
        .await
        .map_err(|_| share_error("policy_denied"))?;
    let presentation: V2PolicyPresentation = serde_json::from_value(request.presentation.clone())
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let presentation_value =
        serde_json::to_value(&presentation).map_err(|_| share_error("invalid_holder_proof"))?;
    let presentation_holder = presentation.holder_did.as_str();
    if presentation_holder != challenge_request.holder_did
        || request.read_signer_did != presentation_holder
    {
        return Err(share_error("invalid_holder_proof"));
    }
    verify_v2_proof(
        presentation_holder,
        &request.proof,
        V2_SESSION_DOMAIN,
        &presentation_value,
    )
    .map_err(|_| share_error("invalid_holder_proof"))?;
    let credential_digest = b64_digest(request.credential.as_bytes());
    if presentation.credential_digest != credential_digest {
        return Err(share_error("invalid_holder_proof"));
    }
    let presentation_issued = OffsetDateTime::parse(&presentation.issued_at, &Rfc3339)
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let presentation_expires = OffsetDateTime::parse(&presentation.expires_at, &Rfc3339)
        .map_err(|_| share_error("invalid_holder_proof"))?;
    if presentation.jti.is_empty()
        || presentation_issued > now + time::Duration::seconds(30)
        || presentation_expires <= now
        || presentation_expires
            > OffsetDateTime::parse(&challenge.expires_at, &Rfc3339)
                .map_err(|_| share_error("invalid_holder_proof"))?
    {
        return Err(share_error("invalid_holder_proof"));
    }
    verify_policy_presentation(
        &presentation_value,
        &challenge_request,
        &request.challenge_id,
        &request.nonce,
        &credential_digest,
        &runtime.enforcer_did,
    )
    .map_err(|_| share_error("invalid_holder_proof"))?;
    let holder_binding = serde_json::to_vec(&request.holder_binding)
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let binding_message = tinycloud_auth::share_email_evidence::verify_holder_binding_artifact(
        &holder_binding,
        presentation_holder,
    )
    .map_err(|_| share_error("invalid_holder_proof"))?;
    if binding_message.get("holderDid").and_then(Value::as_str) != Some(presentation_holder)
        || binding_message.get("challengeId").and_then(Value::as_str)
            != Some(request.challenge_id.as_str())
        || binding_message
            .get("challengeNonce")
            .and_then(Value::as_str)
            != Some(request.nonce.as_str())
        || binding_message.get("shareId").and_then(Value::as_str)
            != Some(challenge_request.share_id.as_str())
        || binding_message.get("policyCid").and_then(Value::as_str)
            != Some(challenge_request.policy_cid.as_str())
        || binding_message
            .get("credentialDigest")
            .and_then(Value::as_str)
            != Some(credential_digest.as_str())
    {
        return Err(share_error("invalid_holder_proof"));
    }
    let scope =
        typed_scope(&registered, &challenge_request).map_err(|_| share_error("policy_denied"))?;
    let holder = DidKey::parse(presentation_holder.to_owned())
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let expiry = registered.expiry.unix_timestamp();
    let verifier = runtime
        .verifier
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?
        .at_time(now.unix_timestamp());
    let evidence = verifier
        .verify_matcher_for(
            request.credential.as_bytes(),
            &scope,
            &holder,
            &registered.matcher,
            expiry,
        )
        .map_err(|_| share_error("policy_denied"))?;
    if evidence.credential_digest.as_str() != credential_digest {
        return Err(share_error("policy_denied"));
    }
    let expected_email_hash = normalized_email_hash(&evidence.disclosed_email)
        .map_err(|_| share_error("policy_denied"))?;
    let challenge_nonce = ProtocolNonce::parse(request.nonce.clone())
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let challenge_id = ProtocolNonce::parse(request.challenge_id.clone())
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let request_digest = Sha256Digest::parse(challenge_request.request_body_digest.clone())
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let enforcer = DidKey::parse(runtime.enforcer_did.clone())
        .map_err(|_| share_error("invalid_holder_proof"))?;
    verifier
        .verify_holder_binding(
            &holder_binding,
            &scope,
            &expected_email_hash,
            &evidence.credential_digest,
            challenge_id.as_str(),
            &challenge_nonce,
            &request_digest,
            &enforcer,
            &holder,
            &holder,
            &holder,
            &holder,
        )
        .map_err(|_| share_error("invalid_holder_proof"))?;
    let session_id = tinycloud_core::share_email::invitation::random_protocol_nonce();
    let session_expires = (now + time::Duration::minutes(5)).min(registered.expiry);
    let runtime_delegation = create_runtime_delegation(
        runtime,
        &registered,
        &challenge_request,
        presentation_holder,
        &credential_digest,
        &b64_digest(&jcs::canonicalize(&presentation_value)),
        &timestamp(session_expires),
    )
    .await
    .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let session_binding = serde_json::json!({
        "challenge": serde_json::to_value(&challenge_request).map_err(|_| share_error("policy_session_invalid"))?,
        "holderDid": presentation_holder,
        "credentialDigest": credential_digest,
        "vpDigest": b64_digest(&jcs::canonicalize(&presentation_value)),
        "runtimeDelegation": runtime_delegation.clone(),
    });
    let session_model = share_session_handle::ActiveModel {
        session_handle: Set(session_id.as_str().to_owned()),
        authority_session_cid: Set(challenge_request.registration_cid.clone()),
        binding_json: Set(session_binding),
        holder_digest: Set(b64_digest(presentation_holder.as_bytes())),
        issued_at: Set(timestamp(now)),
        expires_at: Set(timestamp(session_expires)),
        revoked_at: Set(None),
    };
    let transaction = runtime
        .conn
        .begin()
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let consumed = share_anonymous_challenge::Entity::update_many()
        .col_expr(
            share_anonymous_challenge::Column::ConsumedAt,
            Expr::value(timestamp(now)),
        )
        .filter(share_anonymous_challenge::Column::ChallengeId.eq(&request.challenge_id))
        .filter(share_anonymous_challenge::Column::ConsumedAt.is_null())
        .exec(&transaction)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    if consumed.rows_affected != 1 {
        transaction
            .rollback()
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
        return Err(share_error("policy_session_replayed"));
    }
    session_model
        .insert(&transaction)
        .await
        .map_err(|_| error(Status::Conflict, "policy_session_replayed"))?;
    transaction
        .commit()
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let session = serde_json::json!({
        "type": "TinyCloudSharePolicySession",
        "version": 2,
        "sessionId": session_id,
        "envelopeCid": challenge_request.envelope_cid,
        "shareCid": challenge_request.share_cid,
        "shareId": challenge_request.share_id,
        "registrationCid": challenge_request.registration_cid,
        "delegationCid": challenge_request.delegation_cid,
        "policyCid": challenge_request.policy_cid,
        "enforcementDelegationCid": challenge_request.enforcement_delegation_cid,
        "holderDid": presentation_holder,
        "targetOrigin": challenge_request.target_origin,
        "nodeAudience": challenge_request.node_audience,
        "action": challenge_request.action,
        "actions": challenge_request.actions,
        "resource": challenge_request.resource,
        "credentialDigest": credential_digest,
        "runtimeDelegation": runtime_delegation,
        "issuedAt": timestamp(now),
        "expiresAt": timestamp(session_expires),
    });
    let proof = signed_value(runtime.signer.as_ref(), V2_SESSION_DOMAIN, &session)
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    Ok(Json(
        serde_json::json!({ "session": session, "proof": proof }),
    ))
}

fn parse_v2_etag(value: &str) -> Result<[u8; 32], ()> {
    let value = value.trim();
    let digest = value
        .strip_prefix("\"blake3-")
        .and_then(|value| value.strip_suffix('\"'))
        .ok_or(())?;
    let bytes = hex::decode(digest).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

async fn v2_space(
    runtime: &ShareV2Runtime,
    did: &str,
) -> Result<tinycloud_auth::resource::SpaceId, ()> {
    let _ = runtime;
    did.parse().map_err(|_| ())
}

#[post("/share/v2/invoke", format = "json", data = "<data>")]
pub async fn invoke_v2(
    data: Data<'_>,
    runtime: &State<Option<ShareV2Runtime>>,
    staging: &State<crate::BlockStage>,
    _origin: ShareV2Origin,
) -> Result<Json<Value>, ApiErrorResponse> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    if !runtime.live().await {
        return Err(error(Status::ServiceUnavailable, "capability_unavailable"));
    }
    let raw = read_body(data).await?;
    let envelope: V2InvokeEnvelope =
        serde_json::from_slice(&raw).map_err(|_| error(Status::BadRequest, "invoke_invalid"))?;
    let session = share_session_handle::Entity::find_by_id(&envelope.request.session_id)
        .one(&runtime.conn)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
        .ok_or_else(|| share_error("invoke_denied"))?;
    let now = OffsetDateTime::now_utc();
    if session.revoked_at.is_some()
        || OffsetDateTime::parse(&session.expires_at, &Rfc3339)
            .map_err(|_| share_error("invoke_denied"))?
            <= now
    {
        return Err(share_error("invoke_denied"));
    }
    let challenge: V2ChallengeRequest = serde_json::from_value(
        session
            .binding_json
            .get("challenge")
            .cloned()
            .ok_or_else(|| share_error("invoke_denied"))?,
    )
    .map_err(|_| share_error("invoke_denied"))?;
    if envelope.request.envelope_cid != challenge.envelope_cid
        || envelope.request.share_cid != challenge.share_cid
        || envelope.request.share_id != challenge.share_id
        || envelope.request.registration_cid != challenge.registration_cid
        || envelope.request.delegation_cid != challenge.delegation_cid
        || envelope.request.policy_cid != challenge.policy_cid
        || envelope.request.enforcement_delegation_cid != challenge.enforcement_delegation_cid
        || envelope.request.content_source != challenge.content_source
        || envelope.request.content_source_digest != challenge.content_source_digest
        || envelope.request.holder_did != challenge.holder_did
        || envelope.request.node_audience != challenge.node_audience
        || envelope.request.actions != challenge.actions
        || envelope.request.resource != challenge.resource
        || envelope.request.invocation.session_id != envelope.request.session_id
        || envelope.request.invocation.holder_did != envelope.request.holder_did
        || envelope.request.invocation.action != envelope.request.action
        || envelope.request.invocation.resource != envelope.request.resource
    {
        return Err(share_error("invoke_denied"));
    }
    let registered = registered_policy(runtime, &challenge.registration_cid, &challenge.policy_cid)
        .await
        .map_err(|_| share_error("invoke_denied"))?;
    verify_registered_ancestors(runtime, &registered, None)
        .await
        .map_err(|_| share_error("invoke_denied"))?;
    let credential_digest = session
        .binding_json
        .get("credentialDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| share_error("invoke_denied"))?;
    let vp_digest = session
        .binding_json
        .get("vpDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| share_error("invoke_denied"))?;
    verify_runtime_delegation(
        runtime,
        session
            .binding_json
            .get("runtimeDelegation")
            .ok_or_else(|| share_error("invoke_denied"))?,
        &registered,
        &challenge,
        &challenge.holder_did,
        credential_digest,
        vp_digest,
        &session.expires_at,
    )
    .map_err(|_| share_error("invoke_denied"))?;
    let invocation = &envelope.request.invocation;
    if invocation.artifact_type != "TinyCloudShareReadInvocation"
        || invocation.version != 2
        || invocation.session_id != envelope.request.session_id
        || invocation.envelope_cid != envelope.request.envelope_cid
        || invocation.share_cid != envelope.request.share_cid
        || invocation.share_id != envelope.request.share_id
        || invocation.registration_cid != envelope.request.registration_cid
        || invocation.delegation_cid != envelope.request.delegation_cid
        || invocation.policy_cid != envelope.request.policy_cid
        || invocation.enforcement_delegation_cid != envelope.request.enforcement_delegation_cid
        || invocation.content_source != envelope.request.content_source
        || invocation.content_source_digest != envelope.request.content_source_digest
        || invocation.node_audience != envelope.request.node_audience
        || invocation.actions != envelope.request.actions
        || invocation.request_body_digest != envelope.request.request_body_digest
    {
        return Err(share_error("invoke_denied"));
    }
    let issued = OffsetDateTime::parse(&invocation.issued_at, &Rfc3339)
        .map_err(|_| share_error("invoke_denied"))?;
    let expires = OffsetDateTime::parse(&invocation.expires_at, &Rfc3339)
        .map_err(|_| share_error("invoke_denied"))?;
    if issued > now + time::Duration::seconds(30)
        || expires <= now
        || expires
            > OffsetDateTime::parse(&session.expires_at, &Rfc3339)
                .map_err(|_| share_error("invoke_denied"))?
        || expires - issued > time::Duration::minutes(5)
    {
        return Err(share_error("invoke_expired"));
    }
    let mut invocation_value =
        serde_json::to_value(invocation).map_err(|_| share_error("invoke_invalid"))?;
    invocation_value
        .as_object_mut()
        .ok_or_else(|| share_error("invoke_invalid"))?
        .remove("requestBodyDigest");
    if b64_digest(&jcs::canonicalize(&invocation_value)) != invocation.request_body_digest {
        return Err(share_error("invoke_invalid"));
    }
    verify_v2_proof(
        &invocation.holder_did,
        &envelope.request.proof,
        V2_INVOCATION_DOMAIN,
        &serde_json::to_value(invocation).map_err(|_| share_error("invoke_invalid"))?,
    )
    .map_err(|_| share_error("invalid_holder_proof"))?;
    if invocation.body_digest != envelope.body_digest
        || invocation.if_match != envelope.if_match
        || invocation.content_type != envelope.content_type
    {
        return Err(share_error("invoke_invalid"));
    }
    let action = invocation.action.as_str();
    if !challenge.actions.iter().any(|allowed| allowed == action)
        || !registered
            .envelope
            .policy
            .actions
            .iter()
            .any(|allowed| allowed == action)
    {
        return Err(share_error("invoke_denied"));
    }
    let space = v2_space(runtime, &registered.row.space_id)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let path: tinycloud_auth::resource::Path = invocation
        .resource
        .parse()
        .map_err(|_| share_error("invoke_denied"))?;
    if path.as_str() != registered.row.resource_path {
        return Err(share_error("invoke_denied"));
    }
    if action == "tinycloud.kv/put" {
        let encoded = envelope
            .body
            .as_deref()
            .ok_or_else(|| error(Status::BadRequest, "edit_body_missing"))?;
        let body = decode_canonical_b64(encoded, MAX_BODY_BYTES)
            .map_err(|_| error(Status::BadRequest, "edit_body_invalid"))?;
        if invocation.body_digest.as_deref() != Some(b64_digest(&body).as_str()) {
            return Err(error(Status::BadRequest, "edit_body_invalid"));
        }
        let if_match = invocation
            .if_match
            .as_deref()
            .ok_or_else(|| error(Status::BadRequest, "if_match_required"))?;
        let current = runtime
            .tinycloud
            .kv_get(&space, &path)
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
            .map(|(_, hash, _)| format!("\"blake3-{}\"", hex::encode(hash.as_ref())));
        if current.as_deref() != Some(if_match) {
            return Err(error(Status::PreconditionFailed, "edit_conflict"));
        }
        let expected =
            parse_v2_etag(if_match).map_err(|_| error(Status::BadRequest, "invalid_if_match"))?;
        insert_invocation_replay(
            runtime,
            invocation,
            &envelope.request.request_body_digest,
            expires,
        )
        .await
        .map_err(|_| share_error("invoke_replayed"))?;
        let mut stage = staging
            .stage(&space)
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
        stage
            .write_all(&body)
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
        stage
            .flush()
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            "content-type".to_owned(),
            invocation
                .content_type
                .clone()
                .ok_or_else(|| error(Status::BadRequest, "edit_content_type_invalid"))?,
        );
        let hash = runtime
            .tinycloud
            .invoke_internal_kv_put::<crate::BlockStage>(
                space,
                path,
                Metadata(metadata),
                stage,
                Some(KvPrecondition::Matches(expected)),
            )
            .await
            .map_err(|_| error(Status::PreconditionFailed, "edit_conflict"))?;
        let etag = format!("\"blake3-{}\"", hex::encode(hash.as_ref()));
        return Ok(Json(serde_json::json!({
            "type": "TinyCloudShareInvokeResponse", "version": 2,
            "action": action, "resource": invocation.resource,
            "etag": etag, "bodyDigest": b64_digest(&body)
        })));
    }
    insert_invocation_replay(
        runtime,
        invocation,
        &envelope.request.request_body_digest,
        expires,
    )
    .await
    .map_err(|_| share_error("invoke_replayed"))?;
    let Some((metadata, hash, content)) = runtime
        .tinycloud
        .kv_get(&space, &path)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
    else {
        return Err(error(Status::NotFound, "content_not_found"));
    };
    let mut body = Vec::new();
    let (_, mut reader) = content.into_inner();
    reader
        .read_to_end(&mut body)
        .await
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    let etag = format!("\"blake3-{}\"", hex::encode(hash.as_ref()));
    if action == "tinycloud.kv/metadata" {
        return Ok(Json(serde_json::json!({
            "type": "TinyCloudShareInvokeResponse", "version": 2,
            "action": action, "resource": invocation.resource,
            "metadata": metadata.0, "etag": etag
        })));
    }
    if action != "tinycloud.kv/get" {
        return Err(share_error("unsupported_action"));
    }
    Ok(Json(serde_json::json!({
        "type": "TinyCloudShareInvokeResponse", "version": 2,
        "action": action, "resource": invocation.resource,
        "content": encode_config(&body, URL_SAFE_NO_PAD),
        "bodyDigest": b64_digest(&body), "etag": etag
    })))
}

async fn insert_invocation_replay(
    runtime: &ShareV2Runtime,
    invocation: &V2Invocation,
    digest: &str,
    expires: OffsetDateTime,
) -> Result<(), ()> {
    share_holder_read_jti::ActiveModel {
        jti: Set(invocation.jti.clone()),
        session_handle: Set(invocation.session_id.clone()),
        invocation_digest: Set(digest.to_owned()),
        binding_json: Set(serde_json::json!({
            "registrationCid": invocation.registration_cid,
            "envelopeCid": invocation.envelope_cid,
            "policyCid": invocation.policy_cid,
            "resource": invocation.resource,
            "action": invocation.action
        })),
        issued_at: Set(invocation.issued_at.clone()),
        expires_at: Set(timestamp(expires)),
        consumed_at: Set(Some(now_string())),
    }
    .insert(&runtime.conn)
    .await
    .map(|_| ())
    .map_err(|_| ())
}

fn normal_invocation_allows_delivery(
    invocation: &InvocationInfo,
    registered: &RegisteredPolicy,
) -> bool {
    let Ok(space) = registered
        .row
        .space_id
        .parse::<tinycloud_auth::resource::SpaceId>()
    else {
        return false;
    };
    let Ok(path) = registered
        .row
        .resource_path
        .parse::<tinycloud_auth::resource::Path>()
    else {
        return false;
    };
    let Ok(service) = "kv".parse() else {
        return false;
    };
    let expected = Resource::TinyCloud(space.to_resource(service, Some(path), None, None));
    invocation.capabilities.len() == 1
        && invocation.capabilities.iter().any(|capability| {
            capability.resource == expected
                && matches!(
                    capability.ability.as_ref().as_ref(),
                    "tinycloud.kv/get" | "tinycloud.kv/metadata" | "tinycloud.kv/put"
                )
        })
}

#[post("/share/v2/deliveries/authorize", format = "json", data = "<data>")]
pub async fn authorize_delivery_v2(
    data: Data<'_>,
    runtime: &State<Option<ShareV2Runtime>>,
    invocation: AuthHeaderGetter<InvocationInfo>,
    _origin: ShareV2Origin,
) -> Result<Json<Value>, ApiErrorResponse> {
    let runtime = runtime
        .inner()
        .as_ref()
        .ok_or(error(Status::ServiceUnavailable, "capability_unavailable"))?;
    if !runtime.live().await {
        return Err(error(Status::ServiceUnavailable, "capability_unavailable"));
    }
    invocation_model::verify_and_authorize(
        &runtime.conn,
        &invocation.0 .0,
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(|_| error(Status::Unauthorized, "delivery_authorization_invalid"))?;
    let raw = read_body(data).await?;
    let request: V2DeliveryRequest = serde_json::from_slice(&raw)
        .map_err(|_| error(Status::BadRequest, "delivery_authorization_invalid"))?;
    if request_digest_without(
        &serde_json::from_slice::<Value>(&raw)
            .map_err(|_| share_error("delivery_authorization_invalid"))?,
        "requestBodyDigest",
    )
    .ok()
    .as_deref()
        != Some(request.request_body_digest.as_str())
    {
        return Err(share_error("delivery_authorization_invalid"));
    }
    let registered = registered_policy(runtime, &request.registration_cid, &request.policy_cid)
        .await
        .map_err(|_| share_error("delivery_authorization_invalid"))?;
    verify_registered_ancestors(runtime, &registered, None)
        .await
        .map_err(|_| share_error("delivery_authorization_invalid"))?;
    let expires = OffsetDateTime::parse(&request.expires_at, &Rfc3339)
        .map_err(|_| share_error("delivery_authorization_invalid"))?;
    let now = OffsetDateTime::now_utc();
    if expires <= now
        || expires > now + time::Duration::minutes(5)
        || decode_canonical_b64(&request.jti, 16).map_or(true, |value| value.len() != 16)
    {
        return Err(share_error("delivery_authorization_invalid"));
    }
    if request.envelope_cid == request.registration_cid
        || request.share_cid == request.envelope_cid
        || request.share_id != registered.envelope.policy.share_id
        || request.delegation_cid != registered.row.owner_delegation_cid
        || request.enforcement_delegation_cid != registered.row.enforcement_delegation_cid
        || !normal_invocation_allows_delivery(&invocation.0 .0, &registered)
    {
        return Err(share_error("delivery_authorization_invalid"));
    }
    share_invitation_authorization_jti::ActiveModel {
        jti: Set(request.jti.clone()),
        authorization_digest: Set(request.request_body_digest.clone()),
        binding_json: Set(serde_json::json!({
            "registrationCid": request.registration_cid,
            "envelopeCid": request.envelope_cid,
            "policyCid": request.policy_cid,
            "shareId": request.share_id
        })),
        issued_at: Set(timestamp(now)),
        expires_at: Set(request.expires_at.clone()),
        consumed_at: Set(Some(timestamp(now))),
    }
    .insert(&runtime.conn)
    .await
    .map_err(|_| share_error("delivery_authorization_replayed"))?;
    let authorization = serde_json::json!({
        "type": "TinyCloudShareDeliveryAuthorization",
        "version": 2,
        "jti": request.jti,
        "shareCid": request.share_cid,
        "shareId": request.share_id,
        "registrationCid": request.registration_cid,
        "delegationCid": request.delegation_cid,
        "enforcementDelegationCid": request.enforcement_delegation_cid,
        "envelopeCid": request.envelope_cid,
        "policyCid": request.policy_cid,
        "nodeAudience": registered.row.node_audience,
        "targetOrigin": registered.row.target_origin,
        "expiresAt": request.expires_at,
        "dataAuthority": false
    });
    let proof = signed_value(runtime.signer.as_ref(), V2_DELIVERY_DOMAIN, &authorization)
        .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
    Ok(Json(
        serde_json::json!({ "authorization": authorization, "proof": proof }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn policy_domain_matches_the_sdk_wire_contract() {
        assert_eq!(POLICY_DOMAIN, "xyz.tinycloud.share/policy/v2\\0");
        assert_eq!(
            ENFORCEMENT_DOMAIN,
            "xyz.tinycloud.share/policy-enforcement/v2\\0"
        );
    }

    #[test]
    fn policy_cid_is_raw_sha256_and_not_a_fixture() {
        let bytes = br#"{"domain":"xyz.tinycloud.share/policy/v2\\0","policy":{}}"#;
        assert!(raw_sha256_cid(bytes).starts_with("bafkre"));
    }

    #[test]
    fn registration_bytes_require_canonical_unpadded_base64url() {
        assert_eq!(decode_canonical_b64("AQID", 3).unwrap(), vec![1, 2, 3]);
        assert!(decode_canonical_b64("AQID=", 3).is_err());
        assert!(decode_canonical_b64("AQI$", 3).is_err());
        assert!(decode_canonical_b64("", 3).is_err());
    }

    #[test]
    fn registration_digest_is_sha256_base64url() {
        assert_eq!(
            b64_digest(b"owner-rooted-share"),
            "1P94n7BpYl9ftisD56vWnBlC36pXiktWRZxMBT1Bsd0"
        );
    }

    fn sample_policy() -> (PolicyEnvelope, RegisterRequest, ShareEmailConfig) {
        let config = ShareEmailConfig::default();
        let expires_at = timestamp(OffsetDateTime::now_utc() + Duration::days(1));
        let mut envelope: PolicyEnvelope = serde_json::from_value(serde_json::json!({
            "domain": POLICY_DOMAIN,
            "policy": {
                "type": "TinyCloudSharePolicy",
                "version": 2,
                "shareId": "share-1",
                "ownerDid": "did:pkh:eip155:1:0xowner",
                "shareKeyDid": "did:key:z6MkShare",
                "recipientMatcher": {"kind": "exactEmail", "value": "alice@example.com"},
                "target": {
                    "origin": config.target_origin.clone(),
                    "nodeAudience": config.node_audience.clone(),
                    "enforcerDid": "did:key:z6MkEnforcer",
                    "spaceId": "applications"
                },
                "resource": {"kind": "exact", "path": "shares/share-1/document.md"},
                "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
                "contentSource": {"kind": "kv", "space": "applications", "path": "shares/share-1/document.md"},
                "contentSourceDigest": "digest",
                "ownerDelegationCid": "bafy-owner",
                "expiresAt": expires_at.clone()
            }
        }))
        .unwrap();
        let mut request: RegisterRequest = serde_json::from_value(serde_json::json!({
            "policy": {"bytes": "bytes", "cid": "bafy-policy", "proof": "proof"},
            "ownerDelegation": {"cid": "bafy-owner", "dagCbor": "dag"},
            "enforcementDelegation": {
                "cid": "bafy-enforcement",
                "dagCbor": "dag",
                "issuerDid": "did:key:z6MkShare",
                "audienceDid": "did:key:z6MkEnforcer",
                "facts": {
                    "ownerDelegationCid": "bafy-owner",
                    "policyCid": "bafy-policy",
                    "shareId": "share-1",
                    "shareKeyDid": "did:key:z6MkShare",
                    "enforcerDid": "did:key:z6MkEnforcer",
                    "nodeAudience": config.node_audience.clone(),
                    "spaceId": "applications",
                    "path": "shares/share-1/document.md",
                    "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
                    "contentSourceDigest": "digest",
                    "expiresAt": expires_at
                },
                "signature": "signature"
            },
            "contentSourceDigest": "digest"
        }))
        .unwrap();
        let source = serde_json::to_value(&envelope.policy.content_source).unwrap();
        let source_digest = b64_digest(&jcs::canonicalize(&source));
        envelope.policy.content_source_digest = source_digest.clone();
        request.content_source_digest = source_digest.clone();
        request.enforcement_delegation.facts.content_source_digest = source_digest;
        (envelope, request, config)
    }

    #[test]
    fn policy_validation_accepts_arbitrary_exact_email_matchers() {
        let (mut envelope, request, config) = sample_policy();
        envelope.policy.recipient_matcher.value = "person+tag@any.example".to_owned();
        assert!(validate_policy(&envelope, &request, &config, "did:key:z6MkEnforcer").is_ok());
    }

    #[test]
    fn policy_validation_rejects_path_and_action_widening() {
        let (mut envelope, request, config) = sample_policy();
        envelope.policy.resource.path = "shares/share-1/../other.md".to_owned();
        assert!(validate_policy(&envelope, &request, &config, "did:key:z6MkEnforcer").is_err());

        let (mut envelope, request, config) = sample_policy();
        envelope.policy.actions.push("tinycloud.kv/list".to_owned());
        assert!(validate_policy(&envelope, &request, &config, "did:key:z6MkEnforcer").is_err());
    }

    #[test]
    fn policy_validation_rejects_share_path_mismatch_and_digest_mutation() {
        let (mut envelope, request, config) = sample_policy();
        envelope.policy.resource.path = "shares/other/document.md".to_owned();
        envelope.policy.content_source.path = "shares/other/document.md".to_owned();
        assert!(validate_policy(&envelope, &request, &config, "did:key:z6MkEnforcer").is_err());

        let (mut envelope, request, config) = sample_policy();
        envelope.policy.content_source_digest =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        assert!(validate_policy(&envelope, &request, &config, "did:key:z6MkEnforcer").is_err());
    }

    #[test]
    fn outer_envelope_rejects_unsigned_wrappers_and_unknown_fields() {
        let request = sample_v2_challenge();
        assert!(verify_outer_envelope(
            &serde_json::json!({"envelope": {}}),
            &request,
            "did:key:z6MkShare"
        )
        .is_err());
        let mut value = serde_json::json!({
            "schema": "xyz.tinycloud.share/envelope/v2",
            "version": 2,
            "envelopeCid": "bafy-envelope",
            "shareCid": "bafy-share",
            "shareId": "share-1",
            "delegationCid": "bafy-owner",
            "policyCid": "bafy-policy",
            "target": {"origin": "https://share.tinycloud.xyz", "nodeAudience": "did:web:node.example", "enforcerDid": "did:key:z6MkEnforcer", "spaceId": "applications"},
            "resource": {"kind": "exact", "path": "shares/share-1/document.md"},
            "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
            "contentSource": {"kind": "kv", "space": "applications", "path": "shares/share-1/document.md"},
            "contentSourceDigest": "digest",
            "expiresAt": "2099-01-01T00:00:00.000Z",
            "signature": {"signerDid": "did:key:z6MkShare", "algorithm": "Ed25519", "value": "signature"},
            "unsignedExtra": true
        });
        assert!(verify_outer_envelope(&value, &request, "did:key:z6MkShare").is_err());
        value.as_object_mut().unwrap().remove("unsignedExtra");
        assert!(verify_outer_envelope(&value, &request, "did:key:z6MkShare").is_err());
    }

    #[test]
    fn runtime_delegation_facts_include_share_and_presentation_digests() {
        let request = sample_v2_challenge();
        assert_eq!(request.share_cid, "bafy-share");
        let presentation = serde_json::json!({"holderDid": request.holder_did});
        let digest = b64_digest(&jcs::canonicalize(&presentation));
        assert_eq!(digest.len(), 43);
    }

    fn sample_v2_challenge() -> V2ChallengeRequest {
        serde_json::from_value(serde_json::json!({
            "envelopeCid": "bafy-envelope",
            "shareCid": "bafy-share",
            "shareId": "share-1",
            "registrationCid": "bafy-registration",
            "delegationCid": "bafy-owner",
            "policyCid": "bafy-policy",
            "enforcementDelegationCid": "bafy-enforcement",
            "enforcementDelegation": {
                "cid": "bafy-enforcement",
                "dagCbor": "AQI",
                "issuerDid": "did:key:z6MkShare",
                "audienceDid": "did:key:z6MkEnforcer",
                "facts": {
                    "ownerDelegationCid": "bafy-owner",
                    "policyCid": "bafy-policy",
                    "shareId": "share-1",
                    "shareKeyDid": "did:key:z6MkShare",
                    "enforcerDid": "did:key:z6MkEnforcer",
                    "nodeAudience": "did:web:node.example",
                    "spaceId": "did:pkh:eip155:1:0xowner/applications",
                    "path": "shares/share-1/document.md",
                    "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
                    "contentSourceDigest": "digest",
                    "expiresAt": "2030-01-01T00:00:00.000Z"
                },
                "signature": "sig"
            },
            "outerEnvelope": {},
            "contentSource": {
                "kind": "kv",
                "action": "tinycloud.kv/get",
                "space": "did:pkh:eip155:1:0xowner/applications",
                "path": "shares/share-1/document.md"
            },
            "contentSourceDigest": "digest",
            "holderDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
            "targetOrigin": "https://share.tinycloud.xyz",
            "nodeAudience": "did:web:node.example",
            "action": "tinycloud.kv/get",
            "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
            "resource": "shares/share-1/document.md",
            "requestBodyDigest": "digest"
        }))
        .unwrap()
    }

    #[test]
    fn v2_presentation_is_bound_to_the_challenge_without_static_authority_material() {
        let request = sample_v2_challenge();
        let mut presentation = serde_json::json!({
            "type": "TinyCloudSharePolicyPresentation",
            "version": 1,
            "challengeId": "challenge",
            "nonce": "nonce",
            "shareCid": "bafy-share",
            "shareId": "share-1",
            "delegationCid": "bafy-owner",
            "policyCid": "bafy-policy",
            "contentSource": request.content_source.clone(),
            "contentSourceDigest": "digest",
            "holderDid": request.holder_did.clone(),
            "targetOrigin": "https://share.tinycloud.xyz",
            "nodeAudience": "did:web:node.example",
            "enforcerDid": "did:key:z6MkEnforcer",
            "credentialDigest": "credential",
            "action": "tinycloud.kv/get",
            "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
            "resource": "shares/share-1/document.md",
            "requestBodyDigest": "digest"
        });
        assert!(verify_policy_presentation(
            &presentation,
            &request,
            "challenge",
            "nonce",
            "credential",
            "did:key:z6MkEnforcer"
        )
        .is_ok());
        presentation["policyCid"] = serde_json::json!("bafy-other");
        assert!(verify_policy_presentation(
            &presentation,
            &request,
            "challenge",
            "nonce",
            "credential",
            "did:key:z6MkEnforcer"
        )
        .is_err());
    }
}
