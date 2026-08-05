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
    encryption_network::NetworkId,
    hash::Hash,
    keys::StaticSecret,
    models::{
        abilities, delegation, invocation as invocation_model, owner_share_policy, revocation,
        share_anonymous_challenge, share_holder_read_jti, share_invitation_authorization_jti,
        share_session_handle,
    },
    policy_capability::jcs,
    relationships::parent_delegations,
    sea_orm::{
        sea_query::Expr, ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr,
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
const MAX_REQUEST_BYTES: usize =
    tinycloud_core::share_email::types::MAX_NATIVE_ENCODED_REQUEST_BYTES;
const POLICY_DOMAIN: &str = "xyz.tinycloud.share/policy/v2\0";
const ENFORCEMENT_DOMAIN: &str = "xyz.tinycloud.share/policy-enforcement/v2\0";
const REGISTRATION_DOMAIN: &str = "xyz.tinycloud.share/policy-registration/v2\0";
const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
const MAX_GRAPH_NODES: usize = 64;

fn legacy_v2_creation_open() -> bool {
    OffsetDateTime::now_utc()
        < OffsetDateTime::parse(crate::policy_v3::LAST_V2_CREATE_AT, &Rfc3339)
            .expect("valid v2 creation cutoff")
}

fn legacy_v2_reads_open() -> bool {
    OffsetDateTime::now_utc()
        <= OffsetDateTime::parse(crate::policy_v3::LAST_V2_READ_AT, &Rfc3339)
            .expect("valid v2 read cutoff")
}

fn legacy_expiry_allowed(expiry: OffsetDateTime) -> bool {
    expiry
        <= OffsetDateTime::parse(crate::policy_v3::MAX_LEGACY_ENVELOPE_EXPIRES_AT, &Rfc3339)
            .expect("valid legacy envelope cutoff")
}

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

/// Probes that the `owner_share_policy` table is queryable.
///
/// The projection and the deserialization target must agree: `select_only()`
/// narrows the SQL projection to a single column, so the rows have to be read
/// back as that column's type. Reading them back as the full entity `Model`
/// makes the query succeed on an empty table and fail with
/// `ColumnNotFound` the moment a single row exists (TC-349).
async fn probe_owner_share_policy_lookup(conn: &DatabaseConnection) -> Result<(), DbErr> {
    owner_share_policy::Entity::find()
        .select_only()
        .column(owner_share_policy::Column::PolicyCid)
        .limit(1)
        .into_tuple::<String>()
        .all(conn)
        .await
        .map(|_| ())
}

/// Probes that the `delegation` and `revocation` tables are queryable.
///
/// See [`probe_owner_share_policy_lookup`] for why the rows are read back as
/// the projected column's type rather than as the entity `Model`.
async fn probe_delegation_revocation_lookup(conn: &DatabaseConnection) -> Result<(), DbErr> {
    delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Id)
        .limit(1)
        .into_tuple::<Hash>()
        .all(conn)
        .await?;
    revocation::Entity::find()
        .select_only()
        .column(revocation::Column::Id)
        .limit(1)
        .into_tuple::<Hash>()
        .all(conn)
        .await?;
    Ok(())
}

/// Runs a readiness probe and reports the underlying [`DbErr`] before it is
/// collapsed into a boolean, so a failing check is diagnosable from the logs
/// rather than only inferable from `ready: false`.
fn report_probe(check: &str, result: Result<(), DbErr>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(
                check,
                error = %error,
                error_debug = ?error,
                "share v2 readiness probe failed"
            );
            false
        }
    }
}

impl ShareV2Runtime {
    fn static_ready(&self) -> bool {
        self.config.enabled
            && TargetOrigin::parse(self.config.target_origin.clone()).is_ok()
            && !self.config.node_audience.is_empty()
            && self.config.node_audience.starts_with("did:")
            && self
                .config
                .credentials_origin
                .as_deref()
                .is_some_and(|origin| TargetOrigin::parse(origin.to_owned()).is_ok())
            && self.config.credentials_origin.as_deref() != Some(self.config.target_origin.as_str())
            && self.config.credentials_origin.as_deref() != Some(self.config.return_origin.as_str())
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
        let migration = report_probe(
            "migration",
            probe_owner_share_policy_lookup(&self.conn).await,
        ) && self.encryption_probe();
        let graph = report_probe(
            "delegation_revocation_lookup",
            probe_delegation_revocation_lookup(&self.conn).await,
        );
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

/// TC-359: refuse to compose when the configured invitation key is not the key
/// this node derives and signs with.
///
/// `shareEmail.invitationPublicKey` is what every relying party — the share
/// site, the witness, the recipient's browser — verifies invitation signatures
/// against. The signing half is derived here from the node's own key material
/// (the dstack KMS in production). Nothing downstream compared the two, so a
/// mismatch produced no error anywhere: composition succeeded, readiness went
/// `ready: true`, invitations were minted and signed — and every verifier
/// silently rejected them. The only visible symptom was non-delivery.
///
/// A node that refuses to start with a wrong key is strictly better than one
/// that advertises a capability it can never fulfil, so this is fail-closed.
/// It only runs when `shareEmail.enabled` is set, so it cannot take down a
/// node that is not serving shares.
fn verify_configured_invitation_key(
    config: &ShareEmailConfig,
    key_setup: &StaticSecret,
) -> anyhow::Result<()> {
    let derived = key_setup.share_invitation_public_key();
    let Some(encoded) = config.invitation_public_key.as_deref() else {
        ::tracing::error!(
            derived_invitation_public_key = %encode_config(derived, URL_SAFE_NO_PAD),
            "share v2 is enabled but shareEmail.invitationPublicKey is unset"
        );
        anyhow::bail!(
            "share v2 is enabled but shareEmail.invitationPublicKey is unset; this node derives \
             {} — read it from GET /.well-known/tinycloud/node-keys",
            encode_config(derived, URL_SAFE_NO_PAD)
        );
    };
    let configured = decode_config(encoded, URL_SAFE_NO_PAD)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "shareEmail.invitationPublicKey must be 32 bytes of unpadded base64url, got {encoded:?}"
            )
        })?;
    if configured != derived {
        ::tracing::error!(
            configured_invitation_public_key = %encode_config(configured, URL_SAFE_NO_PAD),
            derived_invitation_public_key = %encode_config(derived, URL_SAFE_NO_PAD),
            "configured share invitation key does not match the node's derived signing key"
        );
        anyhow::bail!(
            "shareEmail.invitationPublicKey is {configured}, but this node signs share \
             invitations with {derived}. Every relying party would reject this node's \
             invitations and shares would silently never be delivered. Read the correct value \
             from GET /.well-known/tinycloud/node-keys and repin the trust bundle.",
            configured = encode_config(configured, URL_SAFE_NO_PAD),
            derived = encode_config(derived, URL_SAFE_NO_PAD),
        );
    }
    Ok(())
}

pub async fn compose(
    conn: DatabaseConnection,
    key_setup: &StaticSecret,
    config: ShareEmailConfig,
    tee_context: Option<TeeContext>,
    tee_key_derived: bool,
    tinycloud: Arc<crate::TinyCloud>,
) -> anyhow::Result<ShareV2Runtime> {
    verify_configured_invitation_key(&config, key_setup)?;
    let migration_ready = report_probe("migration", probe_owner_share_policy_lookup(&conn).await);
    let graph_ready = report_probe(
        "delegation_revocation_lookup",
        probe_delegation_revocation_lookup(&conn).await,
    );
    let signing_seed = key_setup.derive_key(b"tinycloud/share-email/invitation-signing");
    let signing_secret =
        tinycloud_core::libp2p::identity::ed25519::SecretKey::try_from_bytes(signing_seed)
            .map_err(|_| anyhow::anyhow!("invalid share v2 signing key"))?;
    let signing_keypair = tinycloud_core::libp2p::identity::ed25519::Keypair::from(signing_secret);
    let receipt_signer_did =
        tinycloud_core::keys::public_key_to_did_key(signing_keypair.public().into());
    let signer =
        Ed25519InvitationSigner::new(config.invitation_kid.clone(), signing_keypair.into())?;
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
        signer_did: receipt_signer_did,
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
            .is_some_and(|runtime| {
                runtime.config.target_origin == origin || runtime.config.return_origin == origin
            });
        if allowed {
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
    #[serde(
        default,
        rename = "decryptionNetworkId",
        skip_serializing_if = "Option::is_none"
    )]
    decryption_network_id: Option<String>,
    #[serde(
        default,
        rename = "decryptionAction",
        skip_serializing_if = "Option::is_none"
    )]
    decryption_action: Option<String>,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(rename = "shareId")]
    share_id: String,
    #[serde(rename = "ownerDid")]
    owner_did: String,
    #[serde(rename = "shareKeyDid")]
    share_key_did: String,
    #[serde(rename = "recipientMatcher")]
    recipient_matcher: RecipientMatcher,
    target: PolicyTarget,
    #[serde(rename = "contentSource")]
    content_source: SdkContentSource,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
    actions: Vec<String>,
    resource: SdkResource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decryption: Option<DecryptionGrant>,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "ownerDelegationCid")]
    owner_delegation_cid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdkContentSource {
    kind: String,
    space: String,
    path: String,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdkResource {
    kind: String,
    path: String,
}

#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decryption: Option<DecryptionGrant>,
    #[serde(rename = "contentSource")]
    content_source: ContentSource,
    #[serde(rename = "contentSourceDigest")]
    content_source_digest: String,
    #[serde(rename = "ownerDelegationCid")]
    owner_delegation_cid: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct RecipientMatcher {
    kind: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct ExactResource {
    kind: String,
    path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DecryptionGrant {
    network_id: String,
    action: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct ContentSource {
    kind: String,
    space: String,
    path: String,
    action: String,
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
    share_id: String,
    recipient_matcher: RecipientMatcher,
    target: RegistrationTarget,
    resource: ExactResource,
    actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decryption: Option<DecryptionGrant>,
    content_source: ContentSource,
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
    if !legacy_v2_creation_open() {
        return Err(error(Status::Gone, "legacy_v2_creation_closed"));
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
        share_id: policy.policy.share_id.clone(),
        recipient_matcher: policy.policy.recipient_matcher.clone(),
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
        decryption: policy.policy.decryption.clone(),
        content_source: policy.policy.content_source.clone(),
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
    let mut signed_registration = REGISTRATION_DOMAIN.as_bytes().to_vec();
    signed_registration.extend(jcs::canonicalize(&core_value));
    let signature = runtime
        .signer
        .sign(&signed_registration)
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
            // Registration receipts use the same enrolled public key as the
            // node invitation contract. The trust-bundle kid is the authority
            // boundary; a self-describing did:key fallback is not accepted by
            // production clients.
            kid: runtime.config.invitation_kid.clone(),
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
    let sdk_value = sdk_policy_document_value(value)?;
    let sdk: SdkPolicyDocument = serde_json::from_value(sdk_value.clone()).map_err(|_| ())?;
    let facts = &request.enforcement_delegation.facts;
    if sdk.artifact_type != "TinyCloudSharePolicy"
        || sdk.version != 2
        || sdk.content_source.kind != "kv"
        || sdk.content_source.action != "tinycloud.kv/get"
        || !matches!(sdk.resource.kind.as_str(), "exact" | "prefix")
        || sdk.content_source_digest != request.content_source_digest
        || sdk.owner_did.is_empty()
        || sdk.share_key_did.is_empty()
        || sdk.share_id.is_empty()
        || sdk.owner_delegation_cid != request.owner_delegation.cid
        || sdk.target.origin != config.target_origin
        || sdk.target.node_audience != config.node_audience
        || sdk.target.enforcer_did != enforcer_did
        || sdk.target.space_id != sdk.content_source.space
        || facts.share_id != sdk.share_id
        || facts.share_key_did != sdk.share_key_did
        || facts.enforcer_did != enforcer_did
        || facts.node_audience != config.node_audience
        || facts.space_id != sdk.content_source.space
        || facts.path != sdk.resource.path
        || facts.actions != sdk.actions
        || !decryption_facts_match(sdk.decryption.as_ref(), facts)
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
            share_id: sdk.share_id,
            owner_did: sdk.owner_did,
            share_key_did: sdk.share_key_did,
            recipient_matcher: sdk.recipient_matcher,
            target: PolicyTarget {
                origin: sdk.target.origin,
                node_audience: sdk.target.node_audience,
                enforcer_did: sdk.target.enforcer_did,
                space_id: sdk.target.space_id,
            },
            resource: ExactResource {
                kind: sdk.resource.kind,
                path: sdk.resource.path,
            },
            actions: sdk.actions,
            decryption: sdk.decryption,
            content_source: ContentSource {
                kind: sdk.content_source.kind,
                space: sdk.content_source.space,
                path: sdk.content_source.path,
                action: sdk.content_source.action,
            },
            content_source_digest: sdk.content_source_digest,
            owner_delegation_cid: sdk.owner_delegation_cid,
            expires_at: sdk.expires_at,
        },
    })
}

fn decryption_facts_match(decryption: Option<&DecryptionGrant>, facts: &EnforcementFacts) -> bool {
    facts.decryption_network_id.as_deref() == decryption.map(|grant| grant.network_id.as_str())
        && facts.decryption_action.as_deref() == decryption.map(|grant| grant.action.as_str())
}

fn sdk_policy_document_value(value: &Value) -> Result<&Value, ()> {
    let object = value.as_object().ok_or(())?;
    if object.get("domain") == Some(&Value::String(POLICY_DOMAIN.to_owned())) {
        object.get("policy").ok_or(())
    } else {
        Err(())
    }
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
        || !matches!(policy.resource.kind.as_str(), "exact" | "prefix")
        || policy.content_source.kind != "kv"
        || policy.content_source.action != "tinycloud.kv/get"
        || policy.content_source.path != policy.resource.path
        || policy.content_source.space != policy.target.space_id
        || validate_decryption_grant(policy.decryption.as_ref(), &policy.owner_did).is_err()
    {
        return Err(());
    }
    let policy_expiry = OffsetDateTime::parse(&policy.expires_at, &Rfc3339).map_err(|_| ())?;
    if timestamp(policy_expiry) != policy.expires_at
        || policy_expiry <= OffsetDateTime::now_utc()
        || !legacy_expiry_allowed(policy_expiry)
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
    let valid_shape = match policy.resource.kind.as_str() {
        "exact" => path_parts.len() >= 3 && !policy.resource.path.ends_with('/'),
        "prefix" => path_parts.len() >= 2 && !policy.resource.path.ends_with('/'),
        _ => false,
    };
    if !valid_shape
        || path_parts[0] != "shares"
        || path_parts[1] != policy.share_id
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
        "tinycloud.kv/list",
        "tinycloud.kv/metadata",
        "tinycloud.kv/put",
    ];
    if policy.actions.is_empty()
        || policy.actions.len() > 4
        || policy
            .actions
            .iter()
            .any(|action| !expected_actions.contains(&action.as_str()))
        || policy.actions.windows(2).any(|pair| pair[0] >= pair[1])
        || !policy
            .actions
            .iter()
            .any(|action| action == "tinycloud.kv/get")
    {
        return Err(());
    }
    let expiry = OffsetDateTime::parse(&policy.expires_at, &Rfc3339).map_err(|_| ())?;
    if timestamp(expiry) != policy.expires_at
        || expiry <= OffsetDateTime::now_utc()
        || !legacy_expiry_allowed(expiry)
    {
        return Err(());
    }
    Ok(())
}

fn validate_decryption_grant(
    decryption: Option<&DecryptionGrant>,
    owner_did: &str,
) -> Result<(), ()> {
    let Some(decryption) = decryption else {
        return Ok(());
    };
    let network: NetworkId = decryption.network_id.parse().map_err(|_| ())?;
    if decryption.action != "tinycloud.encryption/decrypt"
        || network.name() != "default"
        || !did_principal_matches(network.owner_did(), owner_did)
    {
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
    if !owner_delegation_abilities_match(policy, &abilities) {
        return Err(());
    }
    Ok(())
}

fn owner_delegation_abilities_match(
    policy: &PolicyDocument,
    abilities: &[abilities::Model],
) -> bool {
    if abilities.len() != policy.actions.len() + usize::from(policy.decryption.is_some()) {
        return false;
    }
    for action in &policy.actions {
        let has_exact = abilities.iter().any(|ability| {
            ability.ability.to_string() == *action
                && ability
                    .resource
                    .tinycloud_resource()
                    .is_some_and(|resource| {
                        resource.service().as_str() == "kv"
                            && resource.path().is_some_and(|path| {
                                path.as_str() == policy.resource.path
                                    || policy.resource.kind == "prefix"
                                        && path.as_str() == format!("{}/", policy.resource.path)
                            })
                            && resource.space().to_string() == policy.target.space_id
                    })
        });
        if !has_exact {
            return false;
        }
    }
    if let Some(decryption) = policy.decryption.as_ref() {
        if validate_decryption_grant(Some(decryption), &policy.owner_did).is_err() {
            return false;
        }
        let Ok(expected_network) = decryption.network_id.parse::<NetworkId>() else {
            return false;
        };
        let decrypt_abilities = abilities
            .iter()
            .filter(|ability| {
                ability.ability.to_string() == decryption.action
                    && match &ability.resource {
                        Resource::Other(resource) => resource
                            .as_str()
                            .parse::<NetworkId>()
                            .is_ok_and(|network| network == expected_network),
                        Resource::TinyCloud(_) => false,
                    }
            })
            .count();
        if decrypt_abilities != 1 {
            return false;
        }
    }
    true
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
const RUNTIME_DELEGATION_DOMAIN: &str = "xyz.tinycloud.share/runtime-delegation/v2\0";

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
    recipient_email: String,
    share_url: String,
    document_name: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decryption: Option<DecryptionGrant>,
    content_source: Value,
    content_source_digest: String,
    expires_at: String,
    signature: V2EnvelopeSignature,
}

fn verify_outer_envelope(
    outer: &Value,
    request: &V2ChallengeRequest,
    share_key_did: &str,
    decryption: Option<&DecryptionGrant>,
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
        || !matches!(envelope.resource.kind.as_str(), "exact" | "prefix")
        || envelope.resource.path != request.resource
        || envelope.actions != request.actions
        || !decryption_binding_matches(envelope.decryption.as_ref(), decryption)
        || envelope.content_source != request.content_source
        || envelope.content_source_digest != request.content_source_digest
    {
        return Err(());
    }
    let mut envelope_identity = serde_json::json!({
        "schema": envelope.schema.clone(),
        "version": envelope.version,
        "shareId": envelope.share_id.clone(),
        "delegationCid": envelope.delegation_cid.clone(),
        "policyCid": envelope.policy_cid.clone(),
        "target": envelope.target.clone(),
        "resource": envelope.resource.clone(),
        "actions": envelope.actions.clone(),
        "contentSource": envelope.content_source.clone(),
        "contentSourceDigest": envelope.content_source_digest.clone(),
        "expiresAt": envelope.expires_at.clone(),
    });
    if let Some(decryption) = envelope.decryption.as_ref() {
        envelope_identity.as_object_mut().ok_or(())?.insert(
            "decryption".to_owned(),
            serde_json::to_value(decryption).map_err(|_| ())?,
        );
    }
    if raw_sha256_cid(&jcs::canonicalize(&envelope_identity)) != envelope.envelope_cid {
        return Err(());
    }
    let share_identity = serde_json::json!({
        "version": envelope.version,
        "shareId": envelope.share_id.clone(),
        "policyCid": envelope.policy_cid.clone(),
        "envelopeCid": envelope.envelope_cid.clone(),
    });
    if raw_sha256_cid(&jcs::canonicalize(&share_identity)) != envelope.share_cid {
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
    if timestamp(expiry) != envelope.expires_at
        || expiry <= OffsetDateTime::now_utc()
        || !legacy_expiry_allowed(expiry)
    {
        return Err(());
    }
    if b64_digest(&jcs::canonicalize(&envelope.content_source)) != envelope.content_source_digest {
        return Err(());
    }
    Ok(expiry)
}

fn decryption_binding_matches(
    actual: Option<&DecryptionGrant>,
    expected: Option<&DecryptionGrant>,
) -> bool {
    actual == expected
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
        let sdk_value = sdk_policy_document_value(&value)?;
        let sdk: SdkPolicyDocument = serde_json::from_value(sdk_value.clone()).map_err(|_| ())?;
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
                decryption: sdk.decryption,
                content_source: ContentSource {
                    kind: sdk.content_source.kind,
                    space: sdk.content_source.space,
                    path: sdk.content_source.path,
                    action: sdk.content_source.action,
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
                    decryption_network_id: policy
                        .policy
                        .decryption
                        .as_ref()
                        .map(|grant| grant.network_id.clone()),
                    decryption_action: policy
                        .policy
                        .decryption
                        .as_ref()
                        .map(|grant| grant.action.clone()),
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
        "tinycloud.kv/metadata" => ShareAction::KvMetadata,
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
    if !resource_scope_allows(
        &registered.envelope.policy.resource.kind,
        source_path.as_str(),
        path.as_str(),
        request.action.as_str(),
    ) {
        return Err(());
    }
    let content_source = tinycloud_core::share_email::types::ContentSource::Kv {
        space: space.clone(),
        path: source_path.clone(),
        action: match action {
            ShareAction::KvPut => tinycloud_core::share_email::types::KvGetAction::Put,
            ShareAction::KvList => tinycloud_core::share_email::types::KvGetAction::List,
            ShareAction::KvMetadata | ShareAction::KvGet => {
                tinycloud_core::share_email::types::KvGetAction::Get
            }
            ShareAction::SqlRead => return Err(()),
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
                "tinycloud.kv/get" => Ok(ShareAction::KvGet),
                "tinycloud.kv/metadata" => Ok(ShareAction::KvMetadata),
                "tinycloud.kv/list" => Ok(ShareAction::KvList),
                "tinycloud.kv/put" => Ok(ShareAction::KvPut),
                _ => Err(()),
            })
            .collect::<Result<Vec<_>, _>>()?,
        resource: match registered.envelope.policy.resource.kind.as_str() {
            "prefix" => {
                tinycloud_core::share_email::types::ExactResource::KvPrefix { path: source_path }
            }
            _ => tinycloud_core::share_email::types::ExactResource::Kv { path },
        },
        content_source,
        content_source_digest: source_digest,
    })
}

fn exact_content_source(registered: &RegisteredPolicy, _request: &V2ChallengeRequest) -> Value {
    serde_json::json!({
        "kind": "kv",
        "space": registered.row.space_id,
        "path": registered.row.resource_path,
        "action": "tinycloud.kv/get",
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
        || presentation.get("version").and_then(Value::as_u64) != Some(2)
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
    let mut facts = serde_json::json!({
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
    });
    if let Some(decryption) = registered.envelope.policy.decryption.as_ref() {
        let object = facts
            .as_object_mut()
            .expect("runtime delegation facts are an object");
        object.insert(
            "decryptionNetworkId".to_owned(),
            Value::String(decryption.network_id.clone()),
        );
        object.insert(
            "decryptionAction".to_owned(),
            Value::String(decryption.action.clone()),
        );
    }
    facts
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

/// A prefix policy is intentionally a one-level capability, not a recursive
/// filesystem grant.  Listing stays anchored at the prefix; file operations
/// must name exactly one direct child.
fn resource_scope_allows(kind: &str, scope: &str, requested: &str, action: &str) -> bool {
    if kind == "exact" {
        return action != "tinycloud.kv/list" && scope == requested;
    }
    if kind != "prefix" || scope.is_empty() || scope.ends_with('/') {
        return false;
    }
    if action == "tinycloud.kv/list" {
        return requested == scope;
    }
    let Some(rest) = requested.strip_prefix(&format!("{scope}/")) else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains('/')
        && matches!(
            action,
            "tinycloud.kv/get" | "tinycloud.kv/metadata" | "tinycloud.kv/put"
        )
}

/// A `policy_denied` that says, in the log, which check produced it.
///
/// The caller still gets a flat `403 policy_denied`: which check failed is not a
/// recipient's business, and naming it in the response would turn this route
/// into an oracle for probing a registered policy. The operator is a different
/// matter — `policy_challenge_v2` had twenty-one distinct ways to reach
/// `policy_denied`, all indistinguishable from outside and none logged, so a
/// refused claim on production could not be diagnosed without reproducing the
/// whole stack locally. `reason` names a check and never carries a request value
/// (TC-446).
fn denied(reason: &'static str) -> ApiErrorResponse {
    tracing::warn!(check = reason, "share/v2 policy challenge denied");
    share_error("policy_denied")
}

/// Every consistency check a challenge request must pass, each with a name.
///
/// Behaviourally identical to the `||` chain it replaces — same predicates, same
/// order, first failure wins — but it can say *which* one rejected the request.
/// The names are stable identifiers for operators reading logs; they are never
/// returned to the caller.
fn challenge_request_violation(
    registered: &RegisteredPolicy,
    request: &V2ChallengeRequest,
    runtime: &ShareV2Runtime,
) -> Option<&'static str> {
    let checks: [(&'static str, bool); 16] = [
        (
            "envelope_cid_equals_registration_cid",
            request.envelope_cid == request.registration_cid,
        ),
        (
            "share_cid_equals_envelope_cid",
            request.share_cid == request.envelope_cid,
        ),
        (
            "share_id_mismatch",
            request.share_id != registered.envelope.policy.share_id,
        ),
        (
            "owner_delegation_cid_mismatch",
            request.delegation_cid != registered.row.owner_delegation_cid,
        ),
        (
            "enforcement_delegation_cid_mismatch",
            request.enforcement_delegation_cid != registered.row.enforcement_delegation_cid,
        ),
        (
            "target_origin_mismatch",
            request.target_origin != runtime.config.target_origin,
        ),
        (
            "node_audience_mismatch",
            request.node_audience != runtime.config.node_audience,
        ),
        (
            "content_source_digest_mismatch",
            request.content_source_digest != registered.row.content_source_digest,
        ),
        (
            "content_source_not_exact",
            request.content_source != exact_content_source(registered, request),
        ),
        (
            "content_source_digest_does_not_match_content_source",
            b64_digest(&jcs::canonicalize(&request.content_source))
                != request.content_source_digest,
        ),
        (
            "resource_scope_disallows_action",
            !resource_scope_allows(
                &registered.envelope.policy.resource.kind,
                &registered.row.resource_path,
                &request.resource,
                &request.action,
            ),
        ),
        ("actions_empty", request.actions.is_empty()),
        (
            "actions_missing_requested_action",
            !request.actions.contains(&request.action),
        ),
        (
            "actions_not_strictly_sorted",
            request.actions.windows(2).any(|pair| pair[0] >= pair[1]),
        ),
        (
            "action_outside_registered_policy",
            request
                .actions
                .iter()
                .any(|action| !registered.envelope.policy.actions.contains(action)),
        ),
        (
            "requested_action_outside_registered_policy",
            !registered.envelope.policy.actions.contains(&request.action),
        ),
    ];
    checks
        .into_iter()
        .find_map(|(name, failed)| failed.then_some(name))
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
    if !legacy_v2_creation_open() {
        return Err(error(Status::Gone, "legacy_v2_creation_closed"));
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
        .map_err(|_| denied("registered_policy_lookup"))?;
    if let Some(violation) = challenge_request_violation(&registered, &request, runtime) {
        return Err(denied(violation));
    }
    let outer_expiry = verify_outer_envelope(
        &request.outer_envelope,
        &request,
        &registered.row.share_key_did,
        registered.envelope.policy.decryption.as_ref(),
    )
    .map_err(|_| denied("outer_envelope_verification"))?;
    if outer_expiry > registered.expiry {
        return Err(share_error("policy_expired"));
    }
    verify_registered_ancestors(runtime, &registered, Some(&request.enforcement_delegation))
        .await
        .map_err(|_| denied("registered_ancestor_verification"))?;
    let scope = typed_scope(&registered, &request).map_err(|_| denied("typed_scope"))?;
    if scope.allowed_actions.is_empty() || !scope.allowed_actions.contains(&scope.action) {
        return Err(denied("scope_disallows_requested_action"));
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
    if !legacy_v2_creation_open() {
        return Err(error(Status::Gone, "legacy_v2_creation_closed"));
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
    if !legacy_v2_reads_open() {
        return Err(error(Status::Gone, "legacy_v2_reads_closed"));
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
        || !legacy_expiry_allowed(
            OffsetDateTime::parse(&session.expires_at, &Rfc3339)
                .map_err(|_| share_error("invoke_denied"))?,
        )
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
    if !resource_scope_allows(
        &registered.envelope.policy.resource.kind,
        &registered.row.resource_path,
        path.as_str(),
        action,
    ) {
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
            "etag": etag, "bodyDigest": b64_digest(&body), "contentType": invocation.content_type
        })));
    }
    if action == "tinycloud.kv/list" {
        insert_invocation_replay(
            runtime,
            invocation,
            &envelope.request.request_body_digest,
            expires,
        )
        .await
        .map_err(|_| share_error("invoke_replayed"))?;
        let prefix: tinycloud_auth::resource::Path = invocation
            .resource
            .parse()
            .map_err(|_| share_error("invoke_denied"))?;
        let (paths, _truncated, next) = runtime
            .tinycloud
            .list_direct_children_bounded(&space, &prefix, 100, None)
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?;
        let mut entries = Vec::with_capacity(paths.len());
        for path in paths {
            let kind = if runtime
                .tinycloud
                .kv_get(&space, &path)
                .await
                .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
                .is_some()
            {
                "file"
            } else {
                "folder"
            };
            entries.push(serde_json::json!({ "path": path.as_str(), "kind": kind }));
        }
        return Ok(Json(serde_json::json!({
            "type": "TinyCloudShareInvokeResponse", "version": 2,
            "action": action, "resource": invocation.resource,
            "entries": entries,
            "nextCursor": next.map(|path| path.as_str().to_owned())
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
    if action == "tinycloud.kv/metadata" {
        let Some((metadata, hash)) = runtime
            .tinycloud
            .kv_metadata_with_hash(&space, &path)
            .await
            .map_err(|_| error(Status::ServiceUnavailable, "capability_unavailable"))?
        else {
            return Err(error(Status::NotFound, "content_not_found"));
        };
        let etag = format!("\"blake3-{}\"", hex::encode(hash.as_ref()));
        return Ok(Json(serde_json::json!({
            "type": "TinyCloudShareInvokeResponse", "version": 2,
            "action": action, "resource": invocation.resource,
            "metadata": metadata.0, "etag": etag
        })));
    }
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
    if action != "tinycloud.kv/get" {
        return Err(share_error("unsupported_action"));
    }
    Ok(Json(serde_json::json!({
        "type": "TinyCloudShareInvokeResponse", "version": 2,
        "action": action, "resource": invocation.resource,
        "mediaType": metadata.0.get("content-type").map(String::as_str).unwrap_or("application/octet-stream"),
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
        || !registered
            .matcher
            .matches_verified_email(&request.recipient_email)
        || request.share_url.is_empty()
        || request.document_name.is_empty()
        || !normal_invocation_allows_delivery(&invocation.0 .0, &registered)
    {
        return Err(share_error("delivery_authorization_invalid"));
    }
    // Sourced from the node's own trust-bundle-resolved credentials origin,
    // never from the request. `static_ready()` already requires this to be a
    // valid https origin distinct from `node_audience`/`return_origin`, so
    // the runtime cannot reach this handler with a missing or degenerate
    // value; the explicit check keeps this call site fail-closed on its own.
    let open_credentials_audience = runtime
        .config
        .credentials_origin
        .clone()
        .ok_or_else(|| share_error("delivery_authorization_invalid"))?;
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
        "openCredentialsAudience": open_credentials_audience,
        "holder": invocation.0 .0.invoker,
        "recipientMatcher": serde_json::to_value(&registered.envelope.policy.recipient_matcher).map_err(|_| share_error("delivery_authorization_invalid"))?,
        "deliveryEmail": request.recipient_email,
        "shareUrl": request.share_url,
        "returnOrigin": runtime.config.return_origin,
        "documentName": request.document_name,
        "senderDid": invocation.0 .0.invoker,
        "senderTrust": "verified",
        "contentSource": serde_json::to_value(&registered.envelope.policy.content_source).map_err(|_| share_error("delivery_authorization_invalid"))?,
        "contentSourceDigest": registered.row.content_source_digest,
        "shareExpiresAt": registered.row.expires_at,
        "issuedAt": timestamp(now),
        "reportAbuseToken": request.jti,
        "actions": registered.envelope.policy.actions.clone(),
        "resource": registered.envelope.policy.resource.path.clone(),
        "authorityMaterialHandle": request.registration_cid,
        "authorityMaterialDigest": b64_digest(request.registration_cid.as_bytes()),
        "requestBodyDigest": request.request_body_digest,
        "idempotencyKey": request.jti,
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
    use hmac::{Hmac, Mac};
    use rocket::local::asynchronous::Client;
    use time::Duration;

    #[test]
    fn tenant_authorization_golden_vector_is_byte_exact() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/tenant_authorization_v1.json"))
                .expect("valid fixture");
        let body = fixture["body"].as_str().expect("body").as_bytes();
        assert_eq!(hex::encode(Sha256::digest(body)), fixture["contentSha256"]);
        let key = decode_config(
            fixture["webhookKey"].as_str().expect("key"),
            URL_SAFE_NO_PAD,
        )
        .unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        for (index, part) in [
            fixture["authorizationDomain"].as_str().unwrap().as_bytes(),
            fixture["method"].as_str().unwrap().as_bytes(),
            fixture["route"].as_str().unwrap().as_bytes(),
            fixture["deliveryId"].as_str().unwrap().as_bytes(),
            fixture["timestamp"].as_str().unwrap().as_bytes(),
            body,
        ]
        .iter()
        .enumerate()
        {
            mac.update(part);
            if index < 5 {
                mac.update(b"\0");
            }
        }
        assert_eq!(
            encode_config(mac.finalize().into_bytes(), URL_SAFE_NO_PAD),
            fixture["expectedMac"]
        );
    }

    #[test]
    fn policy_domain_matches_the_sdk_wire_contract() {
        assert_eq!(POLICY_DOMAIN, "xyz.tinycloud.share/policy/v2\0");
        assert_eq!(
            ENFORCEMENT_DOMAIN,
            "xyz.tinycloud.share/policy-enforcement/v2\0"
        );
    }

    #[test]
    fn policy_cid_is_raw_sha256_and_not_a_fixture() {
        let bytes = br#"{"domain":"xyz.tinycloud.share/policy/v2\u0000","policy":{}}"#;
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
                "contentSource": {"kind": "kv", "space": "applications", "path": "shares/share-1/document.md", "action": "tinycloud.kv/get"},
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
    fn decryption_grant_is_limited_to_the_owner_default_network() {
        let owner_did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        let valid = DecryptionGrant {
            network_id: format!("urn:tinycloud:encryption:{owner_did}:default"),
            action: "tinycloud.encryption/decrypt".to_owned(),
        };
        assert!(validate_decryption_grant(Some(&valid), owner_did).is_ok());
        assert!(validate_decryption_grant(None, owner_did).is_ok());

        let wrong_owner = DecryptionGrant {
            network_id: "urn:tinycloud:encryption:did:pkh:eip155:1:0x2222222222222222222222222222222222222222:default".to_owned(),
            action: valid.action.clone(),
        };
        assert!(validate_decryption_grant(Some(&wrong_owner), owner_did).is_err());

        let wrong_network = DecryptionGrant {
            network_id: format!("urn:tinycloud:encryption:{owner_did}:backup"),
            action: valid.action.clone(),
        };
        assert!(validate_decryption_grant(Some(&wrong_network), owner_did).is_err());

        let overbroad_action = DecryptionGrant {
            network_id: valid.network_id.clone(),
            action: "tinycloud.encryption/*".to_owned(),
        };
        assert!(validate_decryption_grant(Some(&overbroad_action), owner_did).is_err());
    }

    fn stored_ability(resource: Resource, action: &str) -> abilities::Model {
        abilities::Model {
            resource,
            ability: tinycloud_core::types::Ability::try_from(action.to_owned()).unwrap(),
            delegation: tinycloud_core::hash::hash(b"owner-delegation"),
            caveats: Default::default(),
        }
    }

    fn policy_ability(policy: &PolicyDocument, action: &str) -> abilities::Model {
        let space: tinycloud_auth::resource::SpaceId = policy.target.space_id.parse().unwrap();
        let service: tinycloud_auth::resource::Service = "kv".parse().unwrap();
        let path: tinycloud_auth::resource::Path = policy.resource.path.parse().unwrap();
        stored_ability(
            Resource::TinyCloud(space.to_resource(service, Some(path), None, None)),
            action,
        )
    }

    #[test]
    fn owner_delegation_ability_matrix_requires_exact_kv_and_decrypt_scope() {
        let (mut envelope, _, _) = sample_policy();
        let owner_did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        envelope.policy.owner_did = owner_did.to_owned();
        envelope.policy.target.space_id =
            "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:applications"
                .to_owned();
        let decryption = DecryptionGrant {
            network_id: format!("urn:tinycloud:encryption:{owner_did}:default"),
            action: "tinycloud.encryption/decrypt".to_owned(),
        };
        envelope.policy.decryption = Some(decryption.clone());
        let kv_abilities = envelope
            .policy
            .actions
            .iter()
            .map(|action| policy_ability(&envelope.policy, action))
            .collect::<Vec<_>>();
        let decrypt_ability =
            stored_ability(decryption.network_id.parse().unwrap(), &decryption.action);

        let mut valid = kv_abilities.clone();
        valid.push(decrypt_ability.clone());
        assert!(owner_delegation_abilities_match(&envelope.policy, &valid));

        assert!(!owner_delegation_abilities_match(
            &envelope.policy,
            &kv_abilities
        ));

        let mut wrong_network = kv_abilities.clone();
        wrong_network.push(stored_ability(
            format!("urn:tinycloud:encryption:{owner_did}:backup")
                .parse()
                .unwrap(),
            &decryption.action,
        ));
        assert!(!owner_delegation_abilities_match(
            &envelope.policy,
            &wrong_network
        ));

        let mut extra_action = valid.clone();
        extra_action.push(stored_ability(
            decryption.network_id.parse().unwrap(),
            "tinycloud.encryption/manage",
        ));
        assert!(!owner_delegation_abilities_match(
            &envelope.policy,
            &extra_action
        ));

        let mut duplicate_decrypt = valid.clone();
        duplicate_decrypt.push(decrypt_ability);
        assert!(!owner_delegation_abilities_match(
            &envelope.policy,
            &duplicate_decrypt
        ));

        envelope.policy.decryption = None;
        assert!(owner_delegation_abilities_match(
            &envelope.policy,
            &kv_abilities
        ));
        assert!(!owner_delegation_abilities_match(&envelope.policy, &valid));
    }

    #[test]
    fn decryption_binding_mutations_are_rejected_or_change_artifact_identity() {
        let (mut envelope, mut request, config) = sample_policy();
        let owner_did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        let decryption = DecryptionGrant {
            network_id: format!("urn:tinycloud:encryption:{owner_did}:default"),
            action: "tinycloud.encryption/decrypt".to_owned(),
        };
        envelope.policy.owner_did = owner_did.to_owned();
        envelope.policy.decryption = Some(decryption.clone());
        request.enforcement_delegation.facts.decryption_network_id =
            Some(decryption.network_id.clone());
        request.enforcement_delegation.facts.decryption_action = Some(decryption.action.clone());

        let policy_value = serde_json::to_value(&envelope).unwrap();
        assert!(parse_sdk_policy(&policy_value, &request, &config, "did:key:z6MkEnforcer").is_ok());

        let mut omitted_policy = policy_value.clone();
        omitted_policy["policy"]
            .as_object_mut()
            .unwrap()
            .remove("decryption");
        assert!(
            parse_sdk_policy(&omitted_policy, &request, &config, "did:key:z6MkEnforcer").is_err()
        );

        let mut tampered_policy = policy_value.clone();
        tampered_policy["policy"]["decryption"]["networkId"] =
            Value::String(format!("urn:tinycloud:encryption:{owner_did}:backup"));
        assert!(
            parse_sdk_policy(&tampered_policy, &request, &config, "did:key:z6MkEnforcer").is_err()
        );

        let mut unknown_policy_field = policy_value.clone();
        unknown_policy_field["policy"]["decryption"]["scope"] = Value::String("*".to_owned());
        assert!(parse_sdk_policy(
            &unknown_policy_field,
            &request,
            &config,
            "did:key:z6MkEnforcer"
        )
        .is_err());

        let registration_core = serde_json::json!({
            "policyCid": "bafy-policy",
            "ownerDelegationCid": "bafy-owner",
            "enforcementDelegationCid": "bafy-enforcement",
            "ownerDid": owner_did,
            "shareKeyDid": "did:key:z6MkShare",
            "enforcerDid": "did:key:z6MkEnforcer",
            "shareId": "share-1",
            "recipientMatcher": {"kind": "exactEmail", "value": "alice@example.com"},
            "target": {
                "origin": config.target_origin,
                "nodeAudience": config.node_audience,
                "enforcerDid": "did:key:z6MkEnforcer",
                "spaceId": "applications"
            },
            "resource": {"kind": "exact", "path": "shares/share-1/document.md"},
            "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"],
            "decryption": decryption,
            "contentSource": envelope.policy.content_source,
            "contentSourceDigest": envelope.policy.content_source_digest,
            "registeredAt": "2098-01-01T00:00:00.000Z",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        });
        let registration_cid = raw_sha256_cid(&jcs::canonicalize(&registration_core));
        let mut omitted_registration = registration_core.clone();
        omitted_registration
            .as_object_mut()
            .unwrap()
            .remove("decryption");
        assert_ne!(
            raw_sha256_cid(&jcs::canonicalize(&omitted_registration)),
            registration_cid
        );
        let mut tampered_registration = registration_core.clone();
        tampered_registration["decryption"]["action"] =
            Value::String("tinycloud.encryption/*".to_owned());
        assert_ne!(
            raw_sha256_cid(&jcs::canonicalize(&tampered_registration)),
            registration_cid
        );

        let wrong_decryption = DecryptionGrant {
            network_id: format!("urn:tinycloud:encryption:{owner_did}:backup"),
            action: "tinycloud.encryption/decrypt".to_owned(),
        };
        assert!(decryption_binding_matches(
            Some(&decryption),
            Some(&decryption)
        ));
        assert!(!decryption_binding_matches(None, Some(&decryption)));
        assert!(!decryption_binding_matches(
            Some(&wrong_decryption),
            Some(&decryption)
        ));
    }

    #[test]
    fn outer_envelope_rejects_unsigned_wrappers_and_unknown_fields() {
        let request = sample_v2_challenge();
        assert!(verify_outer_envelope(
            &serde_json::json!({"envelope": {}}),
            &request,
            "did:key:z6MkShare",
            None,
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
        assert!(verify_outer_envelope(&value, &request, "did:key:z6MkShare", None).is_err());
        value.as_object_mut().unwrap().remove("unsignedExtra");
        assert!(verify_outer_envelope(&value, &request, "did:key:z6MkShare", None).is_err());
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
            "version": 2,
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

    // --- HTTP/DB boundary and adversarial matrix -------------------------
    //
    // These exercise the real byte boundaries, real crypto verification,
    // and real persistence layer used by the v2 owner-rooted routes rather
    // than only the pure request-shape helpers above.

    use tinycloud_core::hash::hash;
    use tinycloud_core::keys::public_key_to_did_key;
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::models::actor;
    use tinycloud_core::sea_orm::{ConnectOptions, Database};
    use tinycloud_core::sea_orm_migration::MigratorTrait;
    use tinycloud_core::storage::StorageConfig;

    #[test]
    fn decoded_content_boundary_is_exactly_100_mib_not_101() {
        let at_limit = vec![7u8; MAX_BODY_BYTES];
        let encoded_at_limit = encode_config(&at_limit, URL_SAFE_NO_PAD);
        assert_eq!(
            decode_canonical_b64(&encoded_at_limit, MAX_BODY_BYTES)
                .expect("exactly 104857600 decoded bytes must be accepted")
                .len(),
            MAX_BODY_BYTES
        );

        let over_limit = vec![7u8; MAX_BODY_BYTES + 1];
        let encoded_over_limit = encode_config(&over_limit, URL_SAFE_NO_PAD);
        assert!(
            decode_canonical_b64(&encoded_over_limit, MAX_BODY_BYTES).is_err(),
            "104857601 decoded bytes must be rejected"
        );
    }

    #[rocket::post("/test/read-body", data = "<data>")]
    async fn read_body_probe(data: Data<'_>) -> Status {
        match read_body(data).await {
            Ok(_) => Status::Ok,
            Err(response) => response.0,
        }
    }

    #[rocket::async_test]
    async fn request_wire_boundary_is_independent_of_the_decoded_body_boundary() {
        let rocket = rocket::build().mount("/", rocket::routes![read_body_probe]);
        let client = Client::tracked(rocket).await.expect("rocket local client");

        let at_limit = vec![b'x'; MAX_REQUEST_BYTES];
        let response = client
            .post("/test/read-body")
            .body(at_limit)
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::PayloadTooLarge,
            "the exact wire boundary (MAX_REQUEST_BYTES) must not be rejected for size"
        );

        let over_limit = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let response = client
            .post("/test/read-body")
            .body(over_limit)
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::PayloadTooLarge,
            "one byte past the wire boundary must be rejected"
        );
        assert_ne!(
            MAX_REQUEST_BYTES, MAX_BODY_BYTES,
            "the wire (base64) boundary and the decoded-body boundary must be independently defined"
        );
    }

    fn tamper_keypair_and_did() -> (Ed25519InvitationSigner, String) {
        let keypair = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let did = public_key_to_did_key(
            tinycloud_core::libp2p::identity::Keypair::from(keypair.clone()).public(),
        );
        let kid = canonical_did_key_kid(&did);
        (
            Ed25519InvitationSigner::new(kid, keypair.into()).expect("valid kid"),
            did,
        )
    }

    #[test]
    fn v2_holder_proof_signature_tamper_is_rejected() {
        let (signer, holder_did) = tamper_keypair_and_did();
        let value = serde_json::json!({"resource": "shares/share-1/document.md"});
        let mut proof = signed_value(&signer, b"xyz.tinycloud.share/test-tamper/v1\0", &value)
            .expect("valid signature produced");
        assert!(verify_v2_proof(
            &holder_did,
            &proof,
            b"xyz.tinycloud.share/test-tamper/v1\0",
            &value
        )
        .is_ok());

        let mut signature_bytes = decode_config(&proof.signature, URL_SAFE_NO_PAD).unwrap();
        signature_bytes[0] ^= 0x01;
        proof.signature = encode_config(&signature_bytes, URL_SAFE_NO_PAD);
        assert!(
            verify_v2_proof(
                &holder_did,
                &proof,
                b"xyz.tinycloud.share/test-tamper/v1\0",
                &value
            )
            .is_err(),
            "a single flipped signature byte must be rejected"
        );
    }

    async fn migrated_memory_db() -> tinycloud_core::sea_orm::DatabaseConnection {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .expect("in-memory sqlite connects");
        Migrator::up(&db, None).await.expect("migrations apply");
        db
    }

    #[tokio::test]
    async fn revocation_in_ancestry_detects_transitive_revocation_on_the_real_chain_only() {
        let db = migrated_memory_db().await;
        actor::ActiveModel {
            id: Set("did:key:actor".to_owned()),
        }
        .insert(&db)
        .await
        .expect("actor row");

        let leaf = hash(b"v2-boundary-leaf");
        let parent = hash(b"v2-boundary-parent");
        let grandparent = hash(b"v2-boundary-grandparent");
        let sibling = hash(b"v2-boundary-sibling");

        for id in [leaf, parent, grandparent, sibling] {
            delegation::ActiveModel {
                id: Set(id),
                delegator: Set("did:key:actor".to_owned()),
                delegatee: Set("did:key:actor".to_owned()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(&db)
            .await
            .expect("delegation row");
        }
        parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(leaf),
        }
        .insert(&db)
        .await
        .expect("leaf->parent link");
        parent_delegations::ActiveModel {
            parent: Set(grandparent),
            child: Set(parent),
        }
        .insert(&db)
        .await
        .expect("parent->grandparent link");

        assert!(
            !revocation_in_ancestry(&db, leaf).await.unwrap(),
            "no revocation exists yet"
        );

        revocation::ActiveModel {
            id: Set(hash(b"v2-boundary-revocation")),
            revoker: Set("did:key:actor".to_owned()),
            revoked: Set(grandparent),
            serialization: Set(b"v2-boundary-revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db)
        .await
        .expect("revocation row");

        assert!(
            revocation_in_ancestry(&db, leaf).await.unwrap(),
            "revoking the grandparent must be visible transitively to the leaf"
        );
        assert!(
            !revocation_in_ancestry(&db, sibling).await.unwrap(),
            "an unrelated chain must not be affected by the revocation"
        );
    }

    #[tokio::test]
    async fn holder_read_jti_rejects_replay_and_the_rejection_survives_a_restart() {
        let directory = tempfile::tempdir().expect("tempdir");
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("share-v2-jti.sqlite").display()
        );
        async fn connect(url: &str) -> tinycloud_core::sea_orm::DatabaseConnection {
            let mut options = ConnectOptions::new(url.to_owned());
            options.max_connections(1);
            Database::connect(options)
                .await
                .expect("file-backed sqlite connects")
        }
        async fn insert(
            db: &tinycloud_core::sea_orm::DatabaseConnection,
            jti: &str,
        ) -> Result<(), tinycloud_core::sea_orm::DbErr> {
            share_holder_read_jti::ActiveModel {
                jti: Set(jti.to_owned()),
                session_handle: Set("session".to_owned()),
                invocation_digest: Set("digest".to_owned()),
                binding_json: Set(serde_json::json!({})),
                issued_at: Set(now_string()),
                expires_at: Set(now_string()),
                consumed_at: Set(Some(now_string())),
            }
            .insert(db)
            .await
            .map(|_| ())
        }

        let db = connect(&url).await;
        Migrator::up(&db, None).await.expect("migrations apply");
        insert(&db, "jti-restart-case")
            .await
            .expect("first use succeeds");
        assert!(
            insert(&db, "jti-restart-case").await.is_err(),
            "replaying the same JTI in the same process must be rejected"
        );
        db.close().await.expect("clean close");

        let restarted = connect(&url).await;
        assert!(
            insert(&restarted, "jti-restart-case").await.is_err(),
            "the replay rejection must survive a process restart, not just an in-memory cache"
        );
        assert!(
            insert(&restarted, "jti-fresh-after-restart").await.is_ok(),
            "a genuinely new JTI must still be accepted after restart"
        );
    }

    #[tokio::test]
    async fn invitation_authorization_jti_rejects_replay_and_the_rejection_survives_a_restart() {
        let directory = tempfile::tempdir().expect("tempdir");
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory
                .path()
                .join("share-v2-invitation-jti.sqlite")
                .display()
        );
        async fn connect(url: &str) -> tinycloud_core::sea_orm::DatabaseConnection {
            let mut options = ConnectOptions::new(url.to_owned());
            options.max_connections(1);
            Database::connect(options)
                .await
                .expect("file-backed sqlite connects")
        }
        async fn insert(
            db: &tinycloud_core::sea_orm::DatabaseConnection,
            jti: &str,
        ) -> Result<(), tinycloud_core::sea_orm::DbErr> {
            share_invitation_authorization_jti::ActiveModel {
                jti: Set(jti.to_owned()),
                authorization_digest: Set("digest".to_owned()),
                binding_json: Set(serde_json::json!({})),
                issued_at: Set(now_string()),
                expires_at: Set(now_string()),
                consumed_at: Set(Some(now_string())),
            }
            .insert(db)
            .await
            .map(|_| ())
        }

        let db = connect(&url).await;
        Migrator::up(&db, None).await.expect("migrations apply");
        insert(&db, "invitation-jti-restart-case")
            .await
            .expect("first use succeeds");
        assert!(
            insert(&db, "invitation-jti-restart-case").await.is_err(),
            "replaying the same invitation JTI in the same process must be rejected"
        );
        db.close().await.expect("clean close");

        let restarted = connect(&url).await;
        assert!(
            insert(&restarted, "invitation-jti-restart-case")
                .await
                .is_err(),
            "the replay rejection must survive a process restart, not just an in-memory cache"
        );
    }

    #[tokio::test]
    async fn concurrent_jti_race_admits_exactly_one_winner() {
        let db = std::sync::Arc::new(migrated_memory_db().await);
        let attempts = futures::future::join_all((0..8).map(|_| {
            let db = db.clone();
            async move {
                share_holder_read_jti::ActiveModel {
                    jti: Set("race-jti".to_owned()),
                    session_handle: Set("session".to_owned()),
                    invocation_digest: Set("digest".to_owned()),
                    binding_json: Set(serde_json::json!({})),
                    issued_at: Set(now_string()),
                    expires_at: Set(now_string()),
                    consumed_at: Set(Some(now_string())),
                }
                .insert(db.as_ref())
                .await
            }
        }))
        .await;
        let winners = attempts.iter().filter(|result| result.is_ok()).count();
        assert_eq!(
            winners, 1,
            "exactly one concurrent claim of the same JTI must win"
        );
    }

    // --- JOINED-TEE-READINESS ---------------------------------------------
    //
    // A deterministic local/test v2 bootstrap: a real migrated database, a
    // real (temp-dir backed) block store, and a TeeContext derived from the
    // node's own key material via `TeeContext::derive_local` rather than any
    // mounted fixture, descriptor-derived sender authority or static
    // capability. Proves the canonical local launch reaches ready:true and
    // that ordinary production startup (no TEE context) stays fail-closed.

    /// TC-359: the invitation key is pinned to the key the node under test
    /// actually derives, exactly as a correctly provisioned deployment pins
    /// it. A hardcoded fixture key here would be the very misconfiguration
    /// `verify_configured_invitation_key` exists to reject.
    fn local_tee_share_v2_config(key_setup: &StaticSecret) -> ShareEmailConfig {
        ShareEmailConfig {
            enabled: true,
            target_origin: "https://node.internal.tinycloud".into(),
            node_audience: "did:web:node.internal.tinycloud".into(),
            return_origin: "https://share.tinycloud.xyz".into(),
            allowed_origins: vec!["https://share.tinycloud.xyz".into()],
            node_signing_kid: "did:web:node.internal.tinycloud#invitation-key-1".into(),
            invitation_kid: "did:web:node.internal.tinycloud#invitation-key-1".into(),
            invitation_public_key: Some(encode_config(
                key_setup.share_invitation_public_key(),
                URL_SAFE_NO_PAD,
            )),
            issuer_did: "did:web:issuer.credentials.org".into(),
            issuer_kid: "did:web:issuer.credentials.org#email-signing-key-1".into(),
            issuer_key_version: 1,
            issuer_public_key: Some("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA".into()),
            credentials_origin: Some("https://witness.credentials.org".into()),
            ..ShareEmailConfig::default()
        }
    }

    /// Boots a real `ShareV2Runtime` against a fresh migrated database and a
    /// fresh temp-dir block store, mirroring the composition order `lib.rs`
    /// uses in production (TinyCloud boots and migrates first, then
    /// `share_v2::compose` reuses the same connection).
    async fn compose_test_runtime(
        key_setup: &StaticSecret,
        tee_context: Option<TeeContext>,
        tee_key_derived: bool,
    ) -> ShareV2Runtime {
        let conn = migrated_memory_db().await;
        let directory = tempfile::tempdir().expect("tempdir for local block store");
        let blocks = crate::BlockConfig::B(crate::storage::file_system::FileSystemConfig::new(
            directory.path(),
        ))
        .open()
        .await
        .expect("local block storage opens");
        let tinycloud = crate::TinyCloud::new(conn.clone(), blocks, key_setup.clone())
            .await
            .expect("in-process TinyCloud composes");
        compose(
            conn,
            key_setup,
            local_tee_share_v2_config(key_setup),
            tee_context,
            tee_key_derived,
            Arc::new(tinycloud),
        )
        .await
        .expect("share v2 runtime composes")
    }

    /// TC-359. Production published `tv7Sn8LztrteJyVgwP9aQL6b1kuiDq9CePhTx19HyrI`
    /// — a hardcoded development fixture — as `nodeInvitationPublicKey` while
    /// the CVM signed with a dstack-derived key nobody could read. Composition
    /// accepted it, readiness reported healthy, and shares silently never
    /// arrived. Composition must now refuse.
    #[tokio::test]
    async fn a_mismatched_invitation_key_fails_composition_loudly() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let mut config = local_tee_share_v2_config(&key_setup);
        // The exact fixture string production shipped.
        config.invitation_public_key = Some("tv7Sn8LztrteJyVgwP9aQL6b1kuiDq9CePhTx19HyrI".into());

        let error = verify_configured_invitation_key(&config, &key_setup)
            .expect_err("a wrong invitation key must fail composition");
        let message = error.to_string();

        assert!(
            message.contains("tv7Sn8LztrteJyVgwP9aQL6b1kuiDq9CePhTx19HyrI"),
            "the error must name the configured key: {message}"
        );
        assert!(
            message.contains(&encode_config(
                key_setup.share_invitation_public_key(),
                URL_SAFE_NO_PAD
            )),
            "the error must name the key the node actually signs with: {message}"
        );
        assert!(
            message.contains("/.well-known/tinycloud/node-keys"),
            "the error must say where to read the correct key: {message}"
        );
    }

    /// A missing key is the same failure mode as a wrong one: nothing to
    /// verify against, so nothing would ever be delivered.
    #[tokio::test]
    async fn a_missing_invitation_key_fails_composition() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let mut config = local_tee_share_v2_config(&key_setup);
        config.invitation_public_key = None;

        assert!(verify_configured_invitation_key(&config, &key_setup).is_err());

        let mut config = local_tee_share_v2_config(&key_setup);
        config.invitation_public_key = Some("not-base64url!".into());
        assert!(verify_configured_invitation_key(&config, &key_setup).is_err());
    }

    /// The correctly provisioned shape — the config pins exactly what the node
    /// derives — still composes.
    #[tokio::test]
    async fn the_derived_invitation_key_is_accepted() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let config = local_tee_share_v2_config(&key_setup);
        assert_eq!(
            config.invitation_public_key.as_deref(),
            Some(encode_config(key_setup.share_invitation_public_key(), URL_SAFE_NO_PAD).as_str())
        );

        assert!(verify_configured_invitation_key(&config, &key_setup).is_ok());

        // ...and a runtime composed from it reaches ready.
        let tee_context = TeeContext::derive_local(&key_setup);
        let runtime = compose_test_runtime(&key_setup, Some(tee_context), true).await;
        assert!(runtime.readiness().await.ready);
    }

    /// The mismatch has to be fatal at the `compose` boundary, not just in the
    /// helper: that is the boundary `lib.rs` calls.
    #[tokio::test]
    async fn compose_refuses_to_build_a_runtime_with_a_mismatched_key() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let mut config = local_tee_share_v2_config(&key_setup);
        config.invitation_public_key = Some("tv7Sn8LztrteJyVgwP9aQL6b1kuiDq9CePhTx19HyrI".into());

        let conn = migrated_memory_db().await;
        let directory = tempfile::tempdir().expect("tempdir for local block store");
        let blocks = crate::BlockConfig::B(crate::storage::file_system::FileSystemConfig::new(
            directory.path(),
        ))
        .open()
        .await
        .expect("local block storage opens");
        let tinycloud = crate::TinyCloud::new(conn.clone(), blocks, key_setup.clone())
            .await
            .expect("in-process TinyCloud composes");

        let composed = compose(
            conn,
            &key_setup,
            config,
            Some(TeeContext::derive_local(&key_setup)),
            true,
            Arc::new(tinycloud),
        )
        .await;

        let Err(error) = composed else {
            panic!("compose must fail closed on an invitation-key mismatch");
        };
        assert!(error
            .to_string()
            .contains("shareEmail.invitationPublicKey is"));
    }

    #[tokio::test]
    async fn local_tee_bootstrap_reaches_ready_true_without_weakening_the_tee_check() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let tee_context = TeeContext::derive_local(&key_setup);
        assert_eq!(
            tee_context.enforcer_did,
            key_setup.node_did(),
            "the local TEE context's enforcer DID must be the node's own derived DID, not a fixture"
        );

        let runtime = compose_test_runtime(&key_setup, Some(tee_context), true).await;
        let response = runtime.readiness().await;

        assert!(
            response.ready,
            "the canonical local bootstrap must reach ready:true"
        );
        assert!(response.checks.migration, "migration check must be true");
        assert!(
            response.checks.encrypted_storage,
            "encrypted_storage check must be true"
        );
        assert!(
            response.checks.delegation_revocation_lookup,
            "the revocation lookup must be a real query against the delegation/revocation tables"
        );
        assert!(
            response.checks.tee_identity,
            "tee_identity check must be true"
        );
        assert!(response.checks.signer, "signer check must be true");
        assert!(
            response.checks.route_version,
            "route_version check must be true"
        );
        assert!(response.checks.body_limit, "body_limit check must be true");
        assert!(
            response.checks.credential_verifier,
            "credential_verifier check must be true"
        );
    }

    /// TC-349: the delegation/revocation readiness probe must survive the
    /// tables being non-empty.
    ///
    /// The probe used to `select_only()` a single column and then read the
    /// rows back as the full entity `Model`. That projection mismatch is
    /// invisible on an empty table (no row is ever deserialized) and fails
    /// with `Query(SqlxError(ColumnNotFound("delegator")))` as soon as one
    /// delegation exists — which is what happens in the addressed-share flow
    /// between startup and `POST /share/v2/policies`. The runtime then went
    /// unready mid-run and 503'd with `capability_unavailable`.
    #[tokio::test]
    async fn readiness_survives_populated_delegation_and_revocation_tables() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let tee_context = TeeContext::derive_local(&key_setup);
        let runtime = compose_test_runtime(&key_setup, Some(tee_context), true).await;
        let conn = runtime.conn.clone();

        assert!(
            runtime.readiness().await.ready,
            "the runtime must start ready against empty tables"
        );

        actor::ActiveModel {
            id: Set("did:key:tc349-actor".to_owned()),
        }
        .insert(&conn)
        .await
        .expect("actor row");
        let delegation_id = hash(b"tc349-delegation");
        delegation::ActiveModel {
            id: Set(delegation_id),
            delegator: Set("did:key:tc349-actor".to_owned()),
            delegatee: Set("did:key:tc349-actor".to_owned()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(delegation_id.as_ref().to_vec()),
        }
        .insert(&conn)
        .await
        .expect("delegation row");

        let after_delegation = runtime.readiness().await;
        assert!(
            after_delegation.checks.delegation_revocation_lookup,
            "the lookup must stay green once a delegation row exists"
        );
        assert!(
            after_delegation.ready,
            "the runtime must stay ready once a delegation row exists"
        );

        revocation::ActiveModel {
            id: Set(hash(b"tc349-revocation")),
            revoker: Set("did:key:tc349-actor".to_owned()),
            revoked: Set(delegation_id),
            serialization: Set(b"tc349-revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&conn)
        .await
        .expect("revocation row");

        let after_revocation = runtime.readiness().await;
        assert!(
            after_revocation.checks.delegation_revocation_lookup,
            "the lookup must stay green once a revocation row exists"
        );
        assert!(
            after_revocation.ready,
            "the runtime must stay ready once a revocation row exists"
        );
        assert!(
            runtime.live().await,
            "live() must stay true, so POST /share/v2/policies does not 503 capability_unavailable"
        );
    }

    /// TC-349 companion: a node that boots against a database which already
    /// holds registered policies must compose ready, not fail-closed. The
    /// compose-time `migration` probe had the same projection mismatch, so a
    /// restart after the first successful registration would have condemned
    /// the runtime.
    #[tokio::test]
    async fn compose_is_ready_against_a_database_that_already_holds_rows() {
        let key_setup = StaticSecret::new(vec![0x42u8; 32]).expect("32-byte test secret");
        let tee_context = TeeContext::derive_local(&key_setup);
        let runtime = compose_test_runtime(&key_setup, Some(tee_context.clone()), true).await;
        let conn = runtime.conn.clone();

        actor::ActiveModel {
            id: Set("did:key:tc349-restart".to_owned()),
        }
        .insert(&conn)
        .await
        .expect("actor row");
        let delegation_id = hash(b"tc349-restart-delegation");
        delegation::ActiveModel {
            id: Set(delegation_id),
            delegator: Set("did:key:tc349-restart".to_owned()),
            delegatee: Set("did:key:tc349-restart".to_owned()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(delegation_id.as_ref().to_vec()),
        }
        .insert(&conn)
        .await
        .expect("delegation row");

        // Re-compose over the same, now-populated connection: the restart shape.
        let directory = tempfile::tempdir().expect("tempdir for local block store");
        let blocks = crate::BlockConfig::B(crate::storage::file_system::FileSystemConfig::new(
            directory.path(),
        ))
        .open()
        .await
        .expect("local block storage opens");
        let tinycloud = crate::TinyCloud::new(conn.clone(), blocks, key_setup.clone())
            .await
            .expect("in-process TinyCloud composes");
        let restarted = compose(
            conn,
            &key_setup,
            local_tee_share_v2_config(&key_setup),
            Some(tee_context),
            true,
            Arc::new(tinycloud),
        )
        .await
        .expect("share v2 runtime composes against a populated database");

        assert!(
            restarted.readiness().await.ready,
            "a restart against a populated database must reach ready:true"
        );
        assert!(
            restarted.capability().is_some(),
            "the capability descriptor must be advertised after a restart"
        );
    }

    #[tokio::test]
    async fn production_bootstrap_without_a_real_tee_context_stays_fail_closed() {
        let key_setup = StaticSecret::new(vec![0x99u8; 32]).expect("32-byte test secret");
        // Ordinary production startup shape: no TeeContext and no key-derived
        // TEE identity, exactly as a non-dstack build without `local-tee`
        // composes it.
        let runtime = compose_test_runtime(&key_setup, None, false).await;
        let response = runtime.readiness().await;

        assert!(
            !response.ready,
            "readiness must stay fail-closed without a real TEE context"
        );
        assert!(
            !response.checks.tee_identity,
            "tee_identity must be false without a real or derived TEE context"
        );
    }

    #[tokio::test]
    async fn local_tee_context_with_mismatched_enforcer_did_is_rejected() {
        let key_setup = StaticSecret::new(vec![0x11u8; 32]).expect("32-byte test secret");
        let mut tee_context = TeeContext::derive_local(&key_setup);
        tee_context.enforcer_did =
            "did:key:z6MkSomeoneElsesEnforcerDidNotOwnedByThisNode".to_owned();

        let runtime = compose_test_runtime(&key_setup, Some(tee_context), true).await;
        let response = runtime.readiness().await;

        assert!(
            !response.ready,
            "a TeeContext whose enforcer DID does not match the node's own key must not be accepted"
        );
        assert!(
            !response.checks.tee_identity,
            "tee_identity must be false when the enforcer DID does not match the node key"
        );
    }

    /// Mirrors `app_with_control`'s real composition order (`lib.rs`): v1's
    /// `share_email::compose` always runs first against the same config, and
    /// v2's `share_v2::compose` reuses the same connection/TinyCloud handle.
    /// Proves an enabled v2-only deployment reaches `ready:true` with no
    /// `authority_material_path` at all, that the legacy v1 runtime stays
    /// unavailable (`None`, not an error) rather than being silently loaded,
    /// and that ordinary non-TEE production composition stays fail-closed.
    #[tokio::test]
    async fn v2_only_composition_is_ready_without_the_legacy_v1_authority_material_while_v1_stays_unavailable(
    ) {
        use tinycloud_core::{
            database_artifacts::SeaOrmDatabaseArtifactRepository, sql::SqlService,
        };

        let key_setup = StaticSecret::new(vec![0x7cu8; 32]).expect("32-byte test secret");
        let mut config = local_tee_share_v2_config(&key_setup);
        assert!(
            config.authority_material_path.is_none(),
            "this composition must exercise the v2-only shape with no legacy authority material file"
        );
        config.enabled = true;

        let conn = migrated_memory_db().await;
        let directory = tempfile::tempdir().expect("tempdir for local block store");
        let blocks = crate::BlockConfig::B(crate::storage::file_system::FileSystemConfig::new(
            directory.path(),
        ))
        .open()
        .await
        .expect("local block storage opens");
        let tinycloud = crate::TinyCloud::new(conn.clone(), blocks, key_setup.clone())
            .await
            .expect("in-process TinyCloud composes");
        let sql_root = tempfile::tempdir().expect("tempdir for sql store");
        let artifact_repository: Arc<
            dyn tinycloud_core::database_artifacts::DatabaseArtifactRepository,
        > = Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone()));
        let sql_service = Arc::new(SqlService::new(
            sql_root.path().display().to_string(),
            0,
            artifact_repository,
        ));

        let v1_runtime = crate::share_email::compose(
            config.clone(),
            conn.clone(),
            &key_setup,
            Arc::new(tinycloud.clone()),
            sql_service,
        )
        .expect("v1 composition must not error when authority material is simply absent");
        assert!(
            v1_runtime.is_none(),
            "the legacy v1 runtime must stay unavailable without authority_material_path, not be silently loaded"
        );

        let tee_context = TeeContext::derive_local(&key_setup);
        let runtime = compose(
            conn.clone(),
            &key_setup,
            config.clone(),
            Some(tee_context),
            true,
            Arc::new(tinycloud.clone()),
        )
        .await
        .expect("share v2 runtime composes without the legacy v1 authority material");
        let response = runtime.readiness().await;
        assert!(
            response.ready,
            "an enabled v2-only composition must reach ready:true without authority_material_path: {:?}",
            response.checks
        );

        // Ordinary non-TEE production startup shape (no dstack, no
        // local-tee-derived context) must stay fail-closed even with the
        // exact same v2-only config.
        let production_runtime =
            compose(conn, &key_setup, config, None, false, Arc::new(tinycloud))
                .await
                .expect("share v2 runtime composes even without a TEE context");
        let production_response = production_runtime.readiness().await;
        assert!(
            !production_response.ready,
            "ordinary non-TEE production composition must not report ready:true"
        );
    }

    // ---- Share v2 production corpus (frozen, byte-exact js-sdk output) ----
    //
    // `tests/fixtures/share-v2-production/corpus.json` is an unedited copy of
    // js-sdk's `share-v2-corpus.json`, pinned by digest in the sibling
    // `PROVENANCE.json`. Its SDK-authored vectors (policy bytes/proof,
    // enforcement delegation dag-cbor/signature) are produced by driving the
    // real production SDK encoders and signers, not hand-assembled. These
    // tests gate Node's own hashing, canonicalization and signature
    // verification against those exact unmodified bytes, and against
    // one-byte/field mutations of them.

    fn production_corpus() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/share-v2-production/corpus.json");
        let bytes =
            std::fs::read(&path).expect("frozen share-v2 production corpus must be present");
        serde_json::from_slice(&bytes).expect("frozen share-v2 production corpus must be JSON")
    }

    fn production_provenance() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/share-v2-production/PROVENANCE.json");
        let bytes = std::fs::read(&path)
            .expect("frozen share-v2 production corpus provenance must be present");
        serde_json::from_slice(&bytes)
            .expect("frozen share-v2 production corpus provenance must be JSON")
    }

    fn b64u_decode(value: &str) -> Vec<u8> {
        decode_config(value, URL_SAFE_NO_PAD).expect("corpus vector must be canonical base64url")
    }

    #[test]
    fn production_corpus_is_pinned_to_its_exact_frozen_bytes() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/share-v2-production/corpus.json");
        let raw = std::fs::read(&path).expect("frozen corpus present");
        let provenance = production_provenance();
        assert_eq!(
            b64_digest(&raw),
            provenance["corpusDigest"].as_str().unwrap(),
            "the checked-in js-sdk production corpus must not drift from its pinned digest \
             without a conscious re-pin of PROVENANCE.json"
        );
        let corpus = production_corpus();
        assert_eq!(
            corpus["provenance"]["sdkCommit"], provenance["sdkCommit"],
            "the pinned sdkCommit in PROVENANCE.json must match the corpus's own provenance block"
        );
        assert_eq!(corpus["provenance"]["algorithm"], "sha256");
        assert_eq!(corpus["provenance"]["encoding"], "base64url-unpadded");
    }

    #[test]
    fn production_corpus_registration_policy_cid_and_digest_match_the_real_node_hash() {
        let corpus = production_corpus();
        let vector = &corpus["vectors"]["registrationPolicy"]["value"];
        let bytes = b64u_decode(vector["canonicalBytesBase64Url"].as_str().unwrap());
        assert_eq!(
            raw_sha256_cid(&bytes),
            vector["cid"].as_str().unwrap(),
            "Node's raw sha256 CID over the unmodified SDK-signed policy bytes must match the pinned corpus cid"
        );
        assert_eq!(
            b64_digest(&bytes),
            vector["digest"].as_str().unwrap(),
            "Node's sha256 digest over the unmodified SDK-signed policy bytes must match the pinned corpus digest"
        );

        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            raw_sha256_cid(&tampered),
            vector["cid"].as_str().unwrap(),
            "a single flipped byte in the policy bytes must change the recomputed cid"
        );
    }

    #[test]
    fn production_corpus_registration_policy_proof_verifies_and_rejects_mutation() {
        let corpus = production_corpus();
        let vector = &corpus["vectors"]["registrationPolicy"]["value"];
        let bytes = b64u_decode(vector["canonicalBytesBase64Url"].as_str().unwrap());
        let share_key_did = vector["policy"]["shareKeyDid"].as_str().unwrap();
        let proof = vector["proof"].as_str().unwrap();

        verify_policy_proof(share_key_did, &bytes, proof).expect(
            "the real production SDK signature over the real production canonical policy bytes must verify",
        );

        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(
            verify_policy_proof(share_key_did, &tampered, proof).is_err(),
            "a single flipped byte in the signed policy bytes must be rejected"
        );

        let mut policy_value: Value = serde_json::from_slice(&bytes).unwrap();
        policy_value["policy"]["shareId"] = Value::String("tampered-share-id".into());
        let mutated_bytes = jcs::canonicalize(&policy_value);
        assert!(
            verify_policy_proof(share_key_did, &mutated_bytes, proof).is_err(),
            "a mutated shareId field must invalidate the real production signature"
        );
    }

    #[test]
    fn production_corpus_enforcement_delegation_dag_cbor_and_signature_verify_and_reject_mutation()
    {
        let corpus = production_corpus();
        let vector = &corpus["vectors"]["registrationEnforcementDelegation"]["value"];
        let input: EnforcementDelegationInput = serde_json::from_value(serde_json::json!({
            "cid": vector["cid"],
            "dagCbor": vector["dagCbor"],
            "issuerDid": vector["issuerDid"],
            "audienceDid": vector["audienceDid"],
            "facts": vector["facts"],
            "signature": vector["signature"],
        }))
        .expect("corpus enforcement delegation matches the wire shape");

        verify_dag_cbor_enforcement(&input).expect(
            "the unmodified SDK-produced enforcement delegation dag-cbor must decode canonically and match its pinned cid",
        );

        let dag_cbor_bytes = b64u_decode(&input.dag_cbor);
        let signature = decode_config(&input.signature, URL_SAFE_NO_PAD).unwrap();
        verify_detached_ed25519(&input.issuer_did, &dag_cbor_bytes, &signature).expect(
            "the real production Ed25519 signature over the real production dag-cbor bytes must verify",
        );

        let mut tampered_cbor = dag_cbor_bytes.clone();
        *tampered_cbor.last_mut().unwrap() ^= 0x01;
        assert!(
            verify_detached_ed25519(&input.issuer_did, &tampered_cbor, &signature).is_err(),
            "a single flipped byte in the enforcement delegation dag-cbor must invalidate the real production signature"
        );

        // Field mutation: change one signed fact (`facts.path`) in the decoded
        // dag-cbor value, re-encode it canonically, and confirm the real
        // signature no longer verifies over the mutated bytes.
        let mut decoded_value = verify_dag_cbor_enforcement(&input).unwrap();
        decoded_value["unsigned"]["facts"]["path"] = Value::String("tampered/path.md".into());
        let mutated_dag_cbor_bytes =
            serde_ipld_dagcbor::to_vec(&decoded_value).expect("mutated value re-encodes");
        assert!(
            verify_detached_ed25519(&input.issuer_did, &mutated_dag_cbor_bytes, &signature)
                .is_err(),
            "the real signature must not verify over dag-cbor bytes with a mutated fact"
        );

        let mut cid_mutated = input.clone();
        cid_mutated.cid =
            "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        assert!(
            verify_dag_cbor_enforcement(&cid_mutated).is_err(),
            "a mutated cid must not match the real unmodified dag-cbor bytes"
        );
    }

    #[test]
    fn production_corpus_registration_core_cid_matches_and_rejects_mutation() {
        let corpus = production_corpus();
        let receipt =
            &corpus["vectors"]["registrationReceiptResponse"]["value"]["decoded"]["registration"];
        let pinned_cid = receipt["registrationCid"].as_str().unwrap().to_owned();
        let mut core = receipt.clone();
        core.as_object_mut().unwrap().remove("registrationCid");
        let bytes = jcs::canonicalize(&core);
        assert_eq!(
            raw_sha256_cid(&bytes),
            pinned_cid,
            "recomputing the registration-core cid over the real production registration fields \
             (Node's own jcs canonicalization + raw sha256 cid) must match the pinned receipt"
        );

        let mut tampered_bytes = bytes.clone();
        *tampered_bytes.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            raw_sha256_cid(&tampered_bytes),
            pinned_cid,
            "a single flipped byte in the canonical registration core must change its cid"
        );

        let mut tampered_core = core.clone();
        tampered_core["shareId"] = Value::String("tampered".into());
        let tampered_core_bytes = jcs::canonicalize(&tampered_core);
        assert_ne!(
            raw_sha256_cid(&tampered_core_bytes),
            pinned_cid,
            "a mutated shareId field in the registration core must change its cid"
        );
    }

    #[test]
    fn v2_proof_domain_kid_and_key_mutations_are_all_rejected() {
        let (signer, holder_did) = tamper_keypair_and_did();
        let value = serde_json::json!({"resource": "shares/share-1/document.md"});
        let domain = b"xyz.tinycloud.share/test-tamper/v1\0";
        let proof = signed_value(&signer, domain, &value).expect("valid signature produced");
        assert!(verify_v2_proof(&holder_did, &proof, domain, &value).is_ok());

        let mut mutated_domain = domain.to_vec();
        mutated_domain[0] ^= 0x01;
        assert!(
            verify_v2_proof(&holder_did, &proof, &mutated_domain, &value).is_err(),
            "a one-byte mutated domain must invalidate an otherwise-valid proof"
        );

        let (_other_signer, other_did) = tamper_keypair_and_did();
        let kid_mutated = DetachedProofV2 {
            alg: proof.alg.clone(),
            kid: format!("{}#{}", other_did, other_did.trim_start_matches("did:key:")),
            signature: proof.signature.clone(),
        };
        assert!(
            verify_v2_proof(&holder_did, &kid_mutated, domain, &value).is_err(),
            "a proof kid pointing at a different holder's key must be rejected"
        );

        assert!(
            verify_v2_proof(&other_did, &proof, domain, &value).is_err(),
            "a proof signed by one key must not verify against a different holder's public key"
        );

        let mut signature_bytes = decode_config(&proof.signature, URL_SAFE_NO_PAD).unwrap();
        signature_bytes[0] ^= 0x01;
        let sig_mutated = DetachedProofV2 {
            alg: proof.alg.clone(),
            kid: proof.kid.clone(),
            signature: encode_config(&signature_bytes, URL_SAFE_NO_PAD),
        };
        assert!(
            verify_v2_proof(&holder_did, &sig_mutated, domain, &value).is_err(),
            "a single flipped signature byte must be rejected"
        );
    }

    #[tokio::test]
    async fn production_corpus_registration_request_dispatches_through_a_real_rocket_route() {
        let corpus = production_corpus();
        let policy_vector = &corpus["vectors"]["registrationPolicy"]["value"];
        let enforcement_vector = &corpus["vectors"]["registrationEnforcementDelegation"]["value"];

        let key_setup = StaticSecret::new(vec![0x37u8; 32]).expect("32-byte test secret");
        let tee_context = TeeContext::derive_local(&key_setup);
        let runtime = compose_test_runtime(&key_setup, Some(tee_context), true).await;
        assert!(
            runtime.live().await,
            "the composed runtime must be live before dispatching a real HTTP request at it"
        );

        // The policy/enforcement-delegation fields below are the corpus's
        // exact, unmodified production SDK bytes. Only `ownerDelegation` is
        // not a production artifact: the js-sdk corpus generator does not
        // author a real owner delegation (see generate-share-v2-corpus.ts's
        // module docstring), so `cid` is the corpus's own placeholder,
        // unchanged, and `dagCbor` is an arbitrary well-formed filler that is
        // never reached because this composed node's own origin/audience/
        // enforcer identity does not match the frozen corpus's.
        let body = serde_json::json!({
            "policy": {
                "bytes": policy_vector["canonicalBytesBase64Url"],
                "cid": policy_vector["cid"],
                "proof": policy_vector["proof"],
            },
            "ownerDelegation": {
                "cid": policy_vector["policy"]["ownerDelegationCid"],
                "dagCbor": "AA",
            },
            "enforcementDelegation": enforcement_vector,
            "contentSourceDigest": policy_vector["policy"]["contentSourceDigest"],
        });

        let rocket = rocket::build()
            .manage(Some(runtime))
            .mount("/", rocket::routes![register_policy]);
        let client = Client::tracked(rocket).await.expect("rocket local client");
        let response = client
            .post("/share/v2/policies")
            .header(rocket::http::ContentType::JSON)
            .body(serde_json::to_vec(&body).expect("request body serializes"))
            .dispatch()
            .await;

        let status = response.status();
        let raw_bytes = response
            .into_bytes()
            .await
            .expect("a real HTTP response body must be readable as raw bytes");

        assert_ne!(
            status,
            Status::Ok,
            "the frozen corpus vector's target/audience/enforcer identity does not describe this \
             test node's own composed identity, so registration must not succeed"
        );
        let error_body: Value = serde_json::from_slice(&raw_bytes)
            .expect("the real raw response bytes must be the documented JSON error shape");
        assert_eq!(error_body["error"]["code"], "policy_registration_invalid");
    }

    #[tokio::test]
    async fn production_corpus_one_byte_and_field_mutations_of_the_registration_wire_are_denied() {
        let corpus = production_corpus();
        let policy_vector = &corpus["vectors"]["registrationPolicy"]["value"];
        let enforcement_vector = &corpus["vectors"]["registrationEnforcementDelegation"]["value"];

        let key_setup = StaticSecret::new(vec![0x38u8; 32]).expect("32-byte test secret");
        let tee_context = TeeContext::derive_local(&key_setup);
        let runtime = compose_test_runtime(&key_setup, Some(tee_context), true).await;
        assert!(runtime.live().await);

        let base_body = serde_json::json!({
            "policy": {
                "bytes": policy_vector["canonicalBytesBase64Url"],
                "cid": policy_vector["cid"],
                "proof": policy_vector["proof"],
            },
            "ownerDelegation": {
                "cid": policy_vector["policy"]["ownerDelegationCid"],
                "dagCbor": "AA",
            },
            "enforcementDelegation": enforcement_vector,
            "contentSourceDigest": policy_vector["policy"]["contentSourceDigest"],
        });

        async fn dispatch(runtime: ShareV2Runtime, body: &Value) -> Status {
            let rocket = rocket::build()
                .manage(Some(runtime))
                .mount("/", rocket::routes![register_policy]);
            let client = Client::tracked(rocket).await.expect("rocket local client");
            let response = client
                .post("/share/v2/policies")
                .header(rocket::http::ContentType::JSON)
                .body(serde_json::to_vec(body).expect("request body serializes"))
                .dispatch()
                .await;
            response.status()
        }

        let baseline = dispatch(runtime.clone(), &base_body).await;

        // policy: one flipped byte in the base64url policy bytes wire field.
        let mut policy_byte_flip = base_body.clone();
        let mut policy_bytes_str = policy_vector["canonicalBytesBase64Url"]
            .as_str()
            .unwrap()
            .to_owned();
        let last = policy_bytes_str.pop().unwrap();
        policy_bytes_str.push(if last == 'A' { 'B' } else { 'A' });
        policy_byte_flip["policy"]["bytes"] = Value::String(policy_bytes_str);
        assert_eq!(
            dispatch(runtime.clone(), &policy_byte_flip).await,
            Status::Forbidden,
            "a one-byte-mutated policy wire field must be denied"
        );

        // policy: field mutation (shareId) inside the policy JSON, cid unchanged.
        let mut policy_field_mutation = base_body.clone();
        let mut tampered_policy: Value = serde_json::from_slice(&b64u_decode(
            policy_vector["canonicalBytesBase64Url"].as_str().unwrap(),
        ))
        .unwrap();
        tampered_policy["policy"]["shareId"] = Value::String("mutated".into());
        policy_field_mutation["policy"]["bytes"] = Value::String(encode_config(
            jcs::canonicalize(&tampered_policy),
            URL_SAFE_NO_PAD,
        ));
        assert_eq!(
            dispatch(runtime.clone(), &policy_field_mutation).await,
            Status::Forbidden,
            "a mutated policy field must be denied even when it re-canonicalizes cleanly"
        );

        // delegations: one flipped byte in the enforcement delegation dag-cbor.
        let mut delegation_byte_flip = base_body.clone();
        let mut dag_cbor_str = enforcement_vector["dagCbor"].as_str().unwrap().to_owned();
        let last = dag_cbor_str.pop().unwrap();
        dag_cbor_str.push(if last == 'A' { 'B' } else { 'A' });
        delegation_byte_flip["enforcementDelegation"]["dagCbor"] = Value::String(dag_cbor_str);
        assert_eq!(
            dispatch(runtime.clone(), &delegation_byte_flip).await,
            Status::Forbidden,
            "a one-byte-mutated enforcement delegation dag-cbor must be denied"
        );

        // delegations: field mutation (facts.path) without touching dagCbor.
        let mut delegation_field_mutation = base_body.clone();
        delegation_field_mutation["enforcementDelegation"]["facts"]["path"] =
            Value::String("mutated/path.md".into());
        assert_eq!(
            dispatch(runtime.clone(), &delegation_field_mutation).await,
            Status::Forbidden,
            "a mutated enforcement delegation fact must be denied"
        );

        // registration core: mutated contentSourceDigest (part of the wire, not the signed policy bytes).
        let mut core_field_mutation = base_body.clone();
        core_field_mutation["contentSourceDigest"] =
            Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned());
        assert_eq!(
            dispatch(runtime.clone(), &core_field_mutation).await,
            Status::Forbidden,
            "a contentSourceDigest that no longer matches the signed policy must be denied"
        );

        // domain: policy JSON with a mutated domain field, re-signed bytes rejected because the
        // signature no longer covers the mutated canonical form.
        let mut domain_mutation = base_body.clone();
        let mut domain_tampered_policy: Value = serde_json::from_slice(&b64u_decode(
            policy_vector["canonicalBytesBase64Url"].as_str().unwrap(),
        ))
        .unwrap();
        domain_tampered_policy["domain"] =
            Value::String("xyz.tinycloud.share/policy/v1\0".to_owned());
        domain_mutation["policy"]["bytes"] = Value::String(encode_config(
            jcs::canonicalize(&domain_tampered_policy),
            URL_SAFE_NO_PAD,
        ));
        assert_eq!(
            dispatch(runtime.clone(), &domain_mutation).await,
            Status::Forbidden,
            "a mutated policy domain must be denied"
        );

        // kid: enforcement delegation issuerDid mutated to a different (validly shaped) did:key.
        let mut kid_mutation = base_body.clone();
        kid_mutation["enforcementDelegation"]["issuerDid"] =
            Value::String("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned());
        assert_eq!(
            dispatch(runtime.clone(), &kid_mutation).await,
            Status::Forbidden,
            "an enforcement delegation issuer that no longer matches the policy's share key must be denied"
        );

        // key: policy shareKeyDid mutated to a different did:key (breaks the signed bytes' cid binding).
        let mut key_mutation = base_body.clone();
        let mut key_tampered_policy: Value = serde_json::from_slice(&b64u_decode(
            policy_vector["canonicalBytesBase64Url"].as_str().unwrap(),
        ))
        .unwrap();
        key_tampered_policy["policy"]["shareKeyDid"] =
            Value::String("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned());
        key_mutation["policy"]["bytes"] = Value::String(encode_config(
            jcs::canonicalize(&key_tampered_policy),
            URL_SAFE_NO_PAD,
        ));
        assert_eq!(
            dispatch(runtime.clone(), &key_mutation).await,
            Status::Forbidden,
            "a mutated policy shareKeyDid must be denied"
        );

        // signature: one flipped byte in the policy proof signature.
        let mut signature_mutation = base_body.clone();
        let mut proof_str = policy_vector["proof"].as_str().unwrap().to_owned();
        let last = proof_str.pop().unwrap();
        proof_str.push(if last == 'A' { 'B' } else { 'A' });
        signature_mutation["policy"]["proof"] = Value::String(proof_str);
        assert_eq!(
            dispatch(runtime.clone(), &signature_mutation).await,
            Status::Forbidden,
            "a one-byte-mutated policy proof signature must be denied"
        );

        assert_eq!(
            baseline,
            Status::Forbidden,
            "the unmutated corpus baseline must itself be a deterministic denial (its identity fields do not \
             describe this test node's own composed identity), establishing the control for every mutation above"
        );
    }
}
