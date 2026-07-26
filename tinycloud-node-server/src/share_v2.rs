//! Production owner-rooted sharing policy registration.
//!
//! This is intentionally separate from the v1 email-claim composition.  v2
//! resolves the already-activated normal delegation graph from the database
//! and verifies the share-key artifacts supplied by the caller.  It never
//! reads the v1 static authority-material provider.

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
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
use std::{collections::BTreeSet, sync::Arc};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::io::AsyncReadExt;

use tinycloud_auth::{
    authorization::TinyCloudDelegation,
    identity::did_principal_matches,
    multihash_codetable::{Code, MultihashDigest},
    share_email_evidence::verify_detached_ed25519,
};
use tinycloud_core::{
    encryption::{maybe_decrypt, ColumnEncryption},
    keys::StaticSecret,
    models::{abilities, delegation, owner_share_policy, revocation},
    policy_capability::jcs,
    relationships::parent_delegations,
    sea_orm::{
        ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
        PaginatorTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
    },
    share_email::invitation::{Ed25519InvitationSigner, InvitationSigner},
    share_email::TargetOrigin,
    util::{DelegationInfo, DelegationMode},
};

use crate::{config::ShareEmailConfig, tee::TeeContext};

pub const MAX_BODY_BYTES: usize = 100 * 1024 * 1024;
const POLICY_DOMAIN: &str = "xyz.tinycloud.share/policy/v2\\0";
const ENFORCEMENT_DOMAIN: &str = "xyz.tinycloud.share/policy-enforcement/v2\\0";
const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
const MAX_GRAPH_NODES: usize = 64;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescriptor {
    pub id: &'static str,
    pub version: u8,
    pub routes: [&'static str; 2],
    pub max_body_bytes: usize,
    pub target_origin: String,
    pub node_audience: String,
    pub enforcer_did: String,
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
    policy_encryption: ColumnEncryption,
    signer: Arc<Ed25519InvitationSigner>,
    signer_did: String,
    enforcer_did: String,
    config: ShareEmailConfig,
    tee_ready: bool,
    migration_ready: bool,
    graph_ready: bool,
}

impl ShareV2Runtime {
    fn static_ready(&self) -> bool {
        self.config.enabled
            && TargetOrigin::parse(self.config.target_origin.clone()).is_ok()
            && !self.config.node_audience.is_empty()
            && self.config.node_audience.starts_with("did:")
            && self.tee_ready
            && !self.signer_did.is_empty()
            && !self.enforcer_did.is_empty()
            && self.migration_ready
            && self.graph_ready
    }

    fn checks(&self, migration: bool, graph: bool) -> ReadinessChecks {
        ReadinessChecks {
            migration,
            encrypted_storage: true,
            delegation_revocation_lookup: graph,
            tee_identity: self.tee_ready,
            signer: !self.signer_did.is_empty(),
            route_version: true,
            body_limit: MAX_BODY_BYTES == 104_857_600,
        }
    }

    pub fn capability(&self) -> Option<CapabilityDescriptor> {
        self.static_ready().then(|| CapabilityDescriptor {
            id: "tinycloud.node-sharing-v2",
            version: 2,
            routes: ["/share/v2/policies", "/share/v2/readiness"],
            max_body_bytes: MAX_BODY_BYTES,
            target_origin: self.config.target_origin.clone(),
            node_audience: self.config.node_audience.clone(),
            enforcer_did: self.enforcer_did.clone(),
            status: "ready",
        })
    }

    async fn readiness(&self) -> ReadinessResponse {
        let migration = owner_share_policy::Entity::find()
            .select_only()
            .column(owner_share_policy::Column::PolicyCid)
            .limit(1)
            .all(&self.conn)
            .await
            .is_ok();
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
            && self.config.enabled;
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
    let signer = Ed25519InvitationSigner::new(signer_did.clone(), signing_keypair.into())?;
    Ok(ShareV2Runtime {
        conn,
        policy_encryption: ColumnEncryption::new(
            key_setup.derive_key(b"tinycloud/hooks/webhook-secrets"),
        ),
        signer: Arc::new(signer),
        signer_did,
        enforcer_did: key_setup.node_did(),
        config,
        tee_ready: tee_context.is_some(),
        migration_ready,
        graph_ready,
    })
}

pub fn public_routes() -> Vec<rocket::Route> {
    rocket::routes![readiness, register_policy]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize, PartialEq)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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
    let policy: PolicyEnvelope = serde_json::from_value(policy_value)
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?;
    validate_policy(&policy, &request, runtime)
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
    data.open((MAX_BODY_BYTES + 1).bytes())
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| error(Status::BadRequest, "policy_registration_invalid"))?;
    if bytes.len() > MAX_BODY_BYTES {
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

fn validate_policy(
    envelope: &PolicyEnvelope,
    request: &RegisterRequest,
    runtime: &ShareV2Runtime,
) -> Result<(), ()> {
    if envelope.domain != POLICY_DOMAIN {
        return Err(());
    }
    let policy = &envelope.policy;
    if policy.artifact_type != "TinyCloudSharePolicy"
        || policy.version != 2
        || policy.target.origin != runtime.config.target_origin
        || policy.target.node_audience != runtime.config.node_audience
        || policy.target.enforcer_did != runtime.enforcer_did
        || policy.content_source_digest != request.content_source_digest
        || policy.owner_delegation_cid != request.owner_delegation.cid
        || policy.resource.kind != "exact"
        || policy.content_source.kind != "kv"
        || policy.content_source.path != policy.resource.path
        || policy.content_source.space != policy.target.space_id
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
    if !policy.resource.path.starts_with("shares/")
        || policy.resource.path.split('/').count() < 3
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
