use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use policy_core::{
    requested_capabilities_hash_hex,
    signed_object::{compute_signed_object_id, digest_signed_object, SignedObjectType},
    verify_signed_object_value, Audit, AuditIssuance, DelegationMode, DenialDisclosure, Disclosure,
    EvidenceAuthority, EvidenceExpression, EvidenceRequirement, GrantChallenge, GrantOutput,
    GrantPresentation, GrantTemplate, HolderBindingProof, HolderEnrollment,
    HolderEnrollmentDisposition, HolderEnrollmentStatus, Policy, PolicyCapability,
    PolicyDisposition, PolicyResource, PolicyStatus, PresentedEvidence, RevocationMode, Signature,
    SignatureSuite, VerifiedSignedObject,
};
use policy_engine_http::{
    CapturedParentDelegateReceipt, ParentCapabilityBound, ParentDelegationConfig, SharedGrantIssuer,
};
use policy_evidence_vc::VcEvidenceVerifier;
use policy_runtime::{
    EvidenceSatisfaction, EvidenceVerifier, GrantIssueRequest, GrantIssuer, PolicyRuntime,
    PolicySpaceState, PortableDelegation, ProvenancedEvidenceSatisfaction, RuntimeConfig,
    RuntimeError, RuntimeEvidenceContext,
};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tinycloud_auth::{
    authorization::Cid as AuthCid,
    resolver::DID_METHODS,
    resource::{Path as AuthPath, ResourceId, Service, SpaceId},
    siwe_recap::Ability as UcanAbility,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, Params, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::{hash, Hash},
    models::{abilities, delegation, space},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database,
        DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    },
    sql::{SqlRequest, SqlService, SqlValue},
    types::SpaceIdWrap,
};

const RESOURCE_ID: &str = "xyz.tinycloud.listen/transcript/conversation-a";
const SUBJECT: &str = "did:pkh:eip155:1:0x7564105e977516c53be337314c7e53838967bdac";
const ISSUER: &str = "did:web:issuer.credentials.org";
const AUDIENCE: &str = "policy-engine:m1-realdata";
const SPACE_NAME: &str = "applications";
const SQL_PATH: &str = "xyz.tinycloud.listen/conversations";
const SQL_DB: &str = "conversations";
const KV_PATH: &str = "audio/conversation-a/recording";
const CONVERSATION_ID: &str = "conversation-a";
const EVIDENCE_ID: &str = "email-domain";
const KV_SEED: &[u8] = b"listen-audio-seed-from-m1-g-05a";
const HOSTILE_AMBIENT_TIMESTAMP: i64 = 4_102_444_800;
const RUNTIME_ISSUANCE_TIMESTAMP: i64 = 1_812_754_920;

const VALID_FIXTURE: &str = include_str!("../vendor/launch-credential-denials/baseline-valid.json");
const EXPIRED_FIXTURE: &str = include_str!("../vendor/launch-credential-denials/expired.json");
const UNTRUSTED_FIXTURE: &str =
    include_str!("../vendor/launch-credential-denials/untrusted-issuer-did.json");
const DENIAL_MATRIX: &str =
    include_str!("../vendor/policy-engine-conformance/denial-matrix-v0.json");
const GRANT_OUTPUT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/grant-output");
static NODE_APP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
struct NodeGrantIssuer {
    owner_jwk: JWK,
    owner_vm: String,
    owner_did: String,
    space: SpaceId,
}

type ClockObservation = Arc<Mutex<Option<(DateTime<Utc>, DateTime<Utc>)>>>;

struct FixtureTimeVerifier {
    inner: VcEvidenceVerifier,
    fixture_now: DateTime<Utc>,
    observation: Option<ClockObservation>,
}

struct InvocationSigner<'a> {
    jwk: &'a JWK,
    verification_method: &'a str,
    did: &'a str,
    parent: Hash,
}

struct InvocationContext<'a> {
    client: &'a Client,
    signer: InvocationSigner<'a>,
    space: &'a SpaceId,
}

struct EngineDenialContext<'a> {
    policy: &'a Policy,
    active_status: &'a PolicyStatus,
    owner_jwk: &'a JWK,
    owner_verification_method: &'a str,
    owner_did: &'a str,
    space: &'a SpaceId,
    holder_did: &'a str,
    holder_key: &'a SigningKey,
}

impl GrantIssuer for NodeGrantIssuer {
    fn issuer_did(&self) -> &str {
        &self.owner_did
    }

    fn issue(&mut self, request: GrantIssueRequest) -> Result<PortableDelegation, RuntimeError> {
        let encoded = signed_node_ucan(
            &self.owner_jwk,
            &self.owner_vm,
            &request.holder_did,
            &self.space,
            &request.capabilities,
            request.expires_at.timestamp() as f64,
            Some(json!({
                tinycloud_core::util::DelegationMode::FACT_KEY: if request.terminal {
                    "terminal"
                } else {
                    "attenuable"
                }
            })),
        )
        .map_err(|error| RuntimeError::GrantIssuanceFailed(error.to_string()))?;
        let delegation_id = hash(encoded.as_bytes()).to_cid(0x55).to_string();
        Ok(PortableDelegation {
            delegation_id,
            issuer_did: self.owner_did.clone(),
            holder_did: request.holder_did,
            policy_id: request.policy.policy_id,
            capabilities: request.capabilities,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            terminal: request.terminal,
            encoded,
        })
    }

    fn revoke(&mut self, _delegation_id: &str) -> Result<(), RuntimeError> {
        Ok(())
    }
}

impl EvidenceVerifier for FixtureTimeVerifier {
    fn verify(
        &self,
        requirement: &EvidenceRequirement,
        presentation: &Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<EvidenceSatisfaction, RuntimeError> {
        let fixture_context = self.fixture_context(context);
        EvidenceVerifier::verify(&self.inner, requirement, presentation, &fixture_context)
    }

    fn verify_with_provenance(
        &self,
        requirement: &EvidenceRequirement,
        presentation: &Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<ProvenancedEvidenceSatisfaction, RuntimeError> {
        let fixture_context = self.fixture_context(context);
        EvidenceVerifier::verify_with_provenance(
            &self.inner,
            requirement,
            presentation,
            &fixture_context,
        )
    }
}

impl FixtureTimeVerifier {
    fn fixture_context(&self, ambient: &RuntimeEvidenceContext) -> RuntimeEvidenceContext {
        if let Some(observation) = &self.observation {
            *observation.lock().expect("clock observation lock") =
                Some((ambient.now, self.fixture_now));
        }
        RuntimeEvidenceContext {
            policy: ambient.policy.clone(),
            eligible_subject_did: ambient.eligible_subject_did.clone(),
            holder_did: ambient.holder_did.clone(),
            requested_capabilities: ambient.requested_capabilities.clone(),
            now: self.fixture_now,
        }
    }
}

#[tokio::test]
async fn deterministic_cross_layer_contract_is_observed_from_real_operations() -> Result<()> {
    let _node_app_guard = NODE_APP_TEST_LOCK.lock().await;
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = URL_SAFE_NO_PAD.encode([29u8; 32]);
    let overlay = format!(
        r#"
[storage]
datadir = "{}"

[keys]
type = "Static"
secret = "{}"
"#,
        datadir.display(),
        secret
    );
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&overlay));
    let rocket = tinycloud::app(&figment).await?;
    let client = Client::tracked(rocket).await?;
    let sql_service = client
        .rocket()
        .state::<SqlService>()
        .context("node app must manage SqlService")?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;

    let mut owner_jwk = JWK::generate_ed25519()?;
    owner_jwk.algorithm = Some(Algorithm::EdDSA);
    let (owner_did, owner_vm) = node_identity(&owner_jwk)?;
    let space_id = SpaceId::new(owner_did.parse::<DIDBuf>()?, SPACE_NAME.parse()?);
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(&conn)
    .await?;
    assert_eq!(
        space::Entity::find().count(&conn).await?,
        1,
        "setup must provision exactly one non-authority space row"
    );
    assert_eq!(
        delegation::Entity::find().count(&conn).await?,
        0,
        "space setup must not provision delegation authority"
    );
    assert_eq!(
        abilities::Entity::find().count(&conn).await?,
        0,
        "space setup must not provision ability authority"
    );
    tokio::fs::create_dir_all(
        datadir
            .join("blocks")
            .join(space_id.suffix())
            .join(space_id.name().as_str()),
    )
    .await?;
    seed_listen_sql(sql_service, &space_id).await?;

    let mut holder_jwk = JWK::generate_ed25519()?;
    holder_jwk.algorithm = Some(Algorithm::EdDSA);
    let (holder_did, holder_vm) = node_identity(&holder_jwk)?;
    let holder_signing_key = signing_key(&holder_jwk)?;
    let owner_signing_key = signing_key(&owner_jwk)?;

    let policy_signing_did = node_identity(&owner_jwk)?.0;
    let policy = verified_policy(policy(&space_id, &policy_signing_did), &owner_signing_key)?;
    let active_status = verified_status(
        policy_status(&policy, &policy_signing_did, 1, PolicyDisposition::Active),
        &owner_signing_key,
    )?;

    let before_delegations = delegation::Entity::find().count(&conn).await?;
    let before_abilities = abilities::Entity::find().count(&conn).await?;
    let runtime_issuance_now = DateTime::from_timestamp(RUNTIME_ISSUANCE_TIMESTAMP, 0)
        .context("deterministic runtime issuance timestamp")?;
    let fixture_now = fixture_verification_time(VALID_FIXTURE)?;
    assert_eq!(
        fixture_now.timestamp(),
        1_781_222_580,
        "runtime evidence time must be the fixture verificationOptions.now instant"
    );
    let clock_observation = Arc::new(Mutex::new(None));
    let mut runtime = runtime(
        policy.clone(),
        active_status.clone(),
        fixture_time_verifier(
            trusted_verifier(),
            fixture_now,
            Some(Arc::clone(&clock_observation)),
        ),
        NodeGrantIssuer {
            owner_jwk: owner_jwk.clone(),
            owner_vm: owner_vm.clone(),
            owner_did: owner_did.clone(),
            space: space_id.clone(),
        },
    )?;
    let challenge = runtime.issue_challenge(&policy.policy_id, runtime_issuance_now)?;
    let valid_evidence = fixture_evidence(VALID_FIXTURE)?;
    let presentation = signed_presentation(
        &policy,
        &challenge,
        &holder_did,
        &holder_signing_key,
        valid_evidence,
        AUDIENCE,
        1,
        runtime_issuance_now,
    )?;
    let replay_presentation = presentation.clone();
    let issued = runtime.resolve(presentation, runtime_issuance_now)?;

    assert_eq!(
        *clock_observation.lock().expect("clock observation lock"),
        Some((runtime_issuance_now, fixture_now)),
        "the verifier must replace the runtime time with the parsed fixture instant"
    );
    assert_eq!(
        issued.issued_at, runtime_issuance_now,
        "issuance retains the injected runtime instant outside evidence verification"
    );
    assert_eq!(issued.policy_id, policy.policy_id);
    assert_eq!(issued.holder_did, holder_did);
    assert_eq!(issued.capabilities, policy.resource.permissions_ceiling);
    assert!(issued.terminal);
    assert!(!issued.encoded.is_empty());

    let record = runtime
        .state()
        .issuance(&issued.delegation_id)
        .context("resolve must create its issuance record")?;
    assert_eq!(record.policy_id, policy.policy_id);
    assert_eq!(record.eligible_subject_did, SUBJECT);
    assert_eq!(record.holder_did, holder_did);
    assert_eq!(record.resource_id, policy.resource.resource_id);
    assert_eq!(record.delegation_id, issued.delegation_id);
    assert_eq!(record.issued_at, issued.issued_at);
    assert_eq!(record.expires_at, issued.expires_at);
    assert_eq!(record.revocation, RevocationMode::RefreshOnly);
    assert_eq!(record.evidence_ids, vec![EVIDENCE_ID.to_string()]);
    let observed_ttl = (record.expires_at - record.issued_at).num_seconds();
    assert!(observed_ttl > 0 && observed_ttl <= 300);

    let imported = client
        .post("/delegate")
        .header(Header::new("Authorization", issued.encoded.clone()))
        .dispatch()
        .await;
    let import_status = imported.status();
    let import_body = imported.into_string().await.unwrap_or_default();
    assert_eq!(
        import_status,
        Status::Ok,
        "delegation import: {import_body}"
    );
    let import_json: Value = serde_json::from_str(&import_body)?;
    let imported_cid = import_json["cid"]
        .as_str()
        .context("delegate response cid")?;
    assert_eq!(imported_cid, issued.delegation_id);

    let after_delegations = delegation::Entity::find().count(&conn).await?;
    let after_abilities = abilities::Entity::find().count(&conn).await?;
    assert_eq!(after_delegations, before_delegations + 1);
    assert_eq!(after_abilities, before_abilities + 2);
    let imported_hash = Hash::from(imported_cid.parse::<AuthCid>()?);
    let imported_row = delegation::Entity::find_by_id(imported_hash)
        .one(&conn)
        .await?
        .context("/delegate must create the authority row")?;
    assert_eq!(imported_row.delegator, owner_did);
    assert_eq!(imported_row.delegatee, holder_did);
    assert!(!imported_row.serialization.is_empty());
    let imported_abilities = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(imported_hash))
        .all(&conn)
        .await?;
    assert_eq!(imported_abilities.len(), 2);

    seed_listen_kv(&client, &owner_jwk, &owner_vm, &owner_did, &space_id).await?;

    let invocation = InvocationContext {
        client: &client,
        signer: InvocationSigner {
            jwk: &holder_jwk,
            verification_method: &holder_vm,
            did: &holder_did,
            parent: imported_hash,
        },
        space: &space_id,
    };
    let conversation = invoke_sql(
        &invocation,
        "sql-success-conversation",
        SqlRequest::ExecuteStatement {
            name: "listen.getConversation".to_string(),
            params: vec![],
        },
    )
    .await?;
    assert_eq!(conversation.0, Status::Ok, "{}", conversation.1);
    let conversation_json: Value = serde_json::from_str(&conversation.1)?;
    assert_eq!(conversation_json["rowCount"], 1);
    assert_eq!(conversation_json["rows"][0][0], CONVERSATION_ID);
    assert_eq!(conversation_json["rows"][0][1], "Planning");

    let participants = invoke_sql(
        &invocation,
        "sql-success-participants",
        SqlRequest::ExecuteStatement {
            name: "listen.listParticipants".to_string(),
            params: vec![],
        },
    )
    .await?;
    assert_eq!(participants.0, Status::Ok, "{}", participants.1);
    let participant_json: Value = serde_json::from_str(&participants.1)?;
    assert_eq!(participant_json["rowCount"], 1);
    assert_eq!(participant_json["rows"][0][1], "Ada");

    let kv = invoke_kv(&invocation, "tinycloud.kv/get", "kv-success").await?;
    assert_eq!(kv.0, Status::Ok, "{}", String::from_utf8_lossy(&kv.1));
    assert_eq!(kv.1, KV_SEED);

    let sql_denials = vec![
        (
            "statement-not-allowed",
            SqlRequest::ExecuteStatement {
                name: "listen.notInCatalog".to_string(),
                params: vec![],
            },
            "sql-statement-not-allowed",
        ),
        (
            "fixed-param-override",
            SqlRequest::ExecuteStatement {
                name: "listen.getConversation".to_string(),
                params: vec![SqlValue::Text("conversation-b".to_string())],
            },
            "sql-fixed-param-override",
        ),
        (
            "raw-query",
            SqlRequest::Query {
                sql: "SELECT * FROM conversation".to_string(),
                params: vec![],
            },
            "sql-raw-query-blocked",
        ),
        (
            "raw-write",
            SqlRequest::Execute {
                sql: "DELETE FROM conversation".to_string(),
                params: vec![],
                schema: None,
            },
            "sql-raw-execute-blocked",
        ),
        (
            "batch",
            SqlRequest::Batch { statements: vec![] },
            "sql-batch-blocked",
        ),
        ("export", SqlRequest::Export, "sql-export-blocked"),
    ];
    for (case, request, expected) in sql_denials {
        let observed = invoke_sql(&invocation, &format!("sql-denial-{case}"), request).await?;
        assert_eq!(observed.0, Status::Forbidden, "{case}: {}", observed.1);
        assert_eq!(observed.1, expected, "operation {case} native outcome");
    }

    let unauthorized_kv = invoke_kv(&invocation, "tinycloud.kv/del", "kv-unauthorized").await?;
    assert_eq!(unauthorized_kv.0, Status::Unauthorized);
    assert!(String::from_utf8_lossy(&unauthorized_kv.1).contains("Unauthorized Action"));
    assert!(!unauthorized_kv
        .1
        .windows(KV_SEED.len())
        .any(|w| w == KV_SEED));

    let expired_ucan = signed_node_ucan(
        &owner_jwk,
        &owner_vm,
        &holder_did,
        &space_id,
        &policy.resource.permissions_ceiling,
        (Utc::now() - Duration::seconds(5)).timestamp() as f64,
        None,
    )?;
    let expired_import = client
        .post("/delegate")
        .header(Header::new("Authorization", expired_ucan))
        .dispatch()
        .await;
    let expired_import_status = expired_import.status();
    let expired_import_body = expired_import.into_string().await.unwrap_or_default();
    assert_eq!(expired_import_status, Status::Unauthorized);
    assert!(expired_import_body.contains("expired or not yet valid"));
    assert_eq!(
        delegation::Entity::find().count(&conn).await?,
        after_delegations
    );

    let replay_error = runtime
        .resolve(replay_presentation, runtime_issuance_now)
        .unwrap_err();
    assert_runtime_code(&replay_error, "challenge-nonce-consumed")?;

    exercise_engine_denials(&EngineDenialContext {
        policy: &policy,
        active_status: &active_status,
        owner_jwk: &owner_jwk,
        owner_verification_method: &owner_vm,
        owner_did: &owner_did,
        space: &space_id,
        holder_did: &holder_did,
        holder_key: &holder_signing_key,
    })?;

    observe_grant_output_on_real_node(&client, &conn, &datadir, sql_service).await?;

    Ok(())
}

fn exercise_engine_denials(context: &EngineDenialContext<'_>) -> Result<()> {
    let EngineDenialContext {
        policy,
        active_status,
        owner_jwk,
        owner_verification_method,
        owner_did,
        space,
        holder_did,
        holder_key,
    } = context;
    let issuer = || NodeGrantIssuer {
        owner_jwk: (*owner_jwk).clone(),
        owner_vm: (*owner_verification_method).to_string(),
        owner_did: (*owner_did).to_string(),
        space: (*space).clone(),
    };
    let runtime_issuance_now = DateTime::from_timestamp(RUNTIME_ISSUANCE_TIMESTAMP, 0)
        .context("deterministic runtime issuance timestamp")?;
    let valid_now = fixture_verification_time(VALID_FIXTURE)?;

    let mut audience_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        fixture_time_verifier(trusted_verifier(), valid_now, None),
        issuer(),
    )?;
    let challenge = audience_runtime.issue_challenge(&policy.policy_id, runtime_issuance_now)?;
    let mismatched = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(VALID_FIXTURE)?,
        "policy-engine:wrong-audience",
        1,
        runtime_issuance_now,
    )?;
    let audience_error = audience_runtime
        .resolve(mismatched, runtime_issuance_now)
        .unwrap_err();
    assert_runtime_code(&audience_error, "presentation-audience-mismatch")?;

    let expired_now = fixture_verification_time(EXPIRED_FIXTURE)?;
    let mut expired_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        fixture_time_verifier(trusted_verifier(), expired_now, None),
        issuer(),
    )?;
    let challenge = expired_runtime.issue_challenge(&policy.policy_id, runtime_issuance_now)?;
    let expired = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(EXPIRED_FIXTURE)?,
        AUDIENCE,
        1,
        runtime_issuance_now,
    )?;
    let expired_error = expired_runtime
        .resolve(expired, runtime_issuance_now)
        .unwrap_err();
    assert_runtime_code(&expired_error, "evidence-credential-invalid")?;

    let fixture_issuer = fixture_sd_jwt_issuer(UNTRUSTED_FIXTURE)?;
    assert_ne!(
        fixture_issuer, ISSUER,
        "the credential operation must exercise a distinct issuer"
    );
    let policy_key = signing_key(owner_jwk)?;
    let untrusted_policy = verified_policy(
        policy_with_accepted_issuer(space, owner_did, &fixture_issuer),
        &policy_key,
    )?;
    let untrusted_status = verified_status(
        policy_status(
            &untrusted_policy,
            &node_identity(owner_jwk)?.0,
            1,
            PolicyDisposition::Active,
        ),
        &policy_key,
    )?;
    let untrusted_now = fixture_verification_time(UNTRUSTED_FIXTURE)?;
    let mut untrusted_runtime = runtime(
        untrusted_policy.clone(),
        untrusted_status,
        fixture_time_verifier(untrusted_verifier(), untrusted_now, None),
        issuer(),
    )?;
    let challenge =
        untrusted_runtime.issue_challenge(&untrusted_policy.policy_id, runtime_issuance_now)?;
    let untrusted = signed_presentation(
        &untrusted_policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(UNTRUSTED_FIXTURE)?,
        AUDIENCE,
        1,
        runtime_issuance_now,
    )?;
    let untrusted_error = untrusted_runtime
        .resolve(untrusted, runtime_issuance_now)
        .unwrap_err();
    assert_runtime_code(&untrusted_error, "evidence-issuer-untrusted")?;

    let mut inactive_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        fixture_time_verifier(trusted_verifier(), valid_now, None),
        issuer(),
    )?;
    let challenge = inactive_runtime.issue_challenge(&policy.policy_id, runtime_issuance_now)?;
    let pending = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(VALID_FIXTURE)?,
        AUDIENCE,
        1,
        runtime_issuance_now,
    )?;
    let revoked = verified_status(
        policy_status(
            policy,
            &node_identity(owner_jwk)?.0,
            2,
            PolicyDisposition::Revoked,
        ),
        &policy_key,
    )?;
    inactive_runtime.state_mut().insert_policy_status(revoked)?;
    let inactive_error = inactive_runtime
        .resolve(pending, runtime_issuance_now)
        .unwrap_err();
    assert_runtime_code(&inactive_error, "policy-inactive")?;

    let mut compromised_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        fixture_time_verifier(trusted_verifier(), valid_now, None),
        issuer(),
    )?;
    let revoked_enrollment = enrollment_status(2, HolderEnrollmentDisposition::Revoked);
    compromised_runtime
        .state_mut()
        .enrollment_tracker_mut()
        .apply_status(&revoked_enrollment)?;
    let recovery = enrollment_status(3, HolderEnrollmentDisposition::Active);
    let recovery_error = compromised_runtime
        .state_mut()
        .enrollment_tracker_mut()
        .apply_status(&recovery)
        .unwrap_err();
    assert_eq!(
        recovery_error.as_str(),
        mounted_code("enrollment-revoked-irreversible")?
    );
    let challenge = compromised_runtime.issue_challenge(&policy.policy_id, runtime_issuance_now)?;
    let compromised = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(VALID_FIXTURE)?,
        AUDIENCE,
        3,
        runtime_issuance_now,
    )?;
    let compromised_error = compromised_runtime
        .resolve(compromised, runtime_issuance_now)
        .unwrap_err();
    assert_runtime_code(&compromised_error, "enrollment-revoked-irreversible")?;

    Ok(())
}

fn runtime(
    policy: Policy,
    status: PolicyStatus,
    verifier: FixtureTimeVerifier,
    issuer: NodeGrantIssuer,
) -> Result<PolicyRuntime<NodeGrantIssuer, FixtureTimeVerifier>> {
    let mut state = PolicySpaceState::default();
    state.insert_policy(policy);
    state.insert_policy_status(status)?;
    Ok(PolicyRuntime::new(
        RuntimeConfig {
            audience: AUDIENCE.to_string(),
            challenge_ttl_seconds: 120,
            accepted_suites: vec![SignatureSuite::EddsaEd25519Sha256JcsV1],
            challenge_signature: placeholder_signature(issuer.issuer_did()),
        },
        state,
        verifier,
        issuer,
    ))
}

fn trusted_verifier() -> VcEvidenceVerifier {
    let fixture: Value = serde_json::from_str(VALID_FIXTURE).expect("valid fixture JSON");
    let key = &fixture["profile"]["keys"]["trusted"];
    let jwk = serde_json::from_value(json!({
        "params": { "OKP": {
            "curve": key["crv"],
            "public_key": URL_SAFE_NO_PAD.decode(key["xB64u"].as_str().unwrap()).unwrap()
        }}
    }))
    .expect("fixture verifier JWK");
    VcEvidenceVerifier::new(BTreeMap::from([(ISSUER.to_string(), jwk)]))
}

fn untrusted_verifier() -> VcEvidenceVerifier {
    VcEvidenceVerifier::new(BTreeMap::new())
}

fn fixture_time_verifier(
    inner: VcEvidenceVerifier,
    fixture_now: DateTime<Utc>,
    observation: Option<ClockObservation>,
) -> FixtureTimeVerifier {
    FixtureTimeVerifier {
        inner,
        fixture_now,
        observation,
    }
}

fn policy(space: &SpaceId, signer_did: &str) -> Policy {
    policy_with_accepted_issuer(space, signer_did, ISSUER)
}

fn policy_with_accepted_issuer(space: &SpaceId, signer_did: &str, accepted_issuer: &str) -> Policy {
    Policy {
        schema: policy_core::POLICY_SCHEMA.to_string(),
        policy_id: String::new(),
        owner_did: space.did().to_string(),
        signing_key_did: signer_did.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        resource: PolicyResource {
            resource_type: "listen-transcript".to_string(),
            resource_id: RESOURCE_ID.to_string(),
            permissions_ceiling: policy_capabilities(space),
        },
        when: policy_core::Expression::Evidence(EvidenceExpression {
            evidence: EvidenceRequirement {
                requirement_id: EVIDENCE_ID.to_string(),
                verifier: "w3c.vc/credential/v1".to_string(),
                requirements: json!({
                    "type": "opencredentials.email/v1",
                    "emailDomains": ["credentials.org"]
                }),
                authority: Some(EvidenceAuthority {
                    profile: None,
                    accepted_issuers: Some(vec![accepted_issuer.to_string()]),
                    allow_owner_authorized_issuer: None,
                }),
                freshness: None,
            },
        }),
        grant: GrantTemplate {
            output: GrantOutput::PortableDelegation,
            max_ttl_seconds: 300,
            delegation_mode: DelegationMode::Terminal,
            revocation: RevocationMode::RefreshOnly,
        },
        disclosure: Some(Disclosure {
            denial: DenialDisclosure::Code,
        }),
        audit: Some(Audit {
            issuance: AuditIssuance::Security,
        }),
        signature: placeholder_signature(signer_did),
    }
}

fn policy_capabilities(space: &SpaceId) -> Vec<PolicyCapability> {
    vec![
        policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.sql",
            "space": space.did().to_string(),
            "path": SQL_PATH,
            "actions": ["tinycloud.sql/read"],
            "caveats": sql_caveat()
        }))
        .expect("canonical Listen SQL capability"),
        policy_core::parse_policy_capability(&json!({
            "service": "tinycloud.kv",
            "space": space.did().to_string(),
            "path": KV_PATH,
            "actions": ["tinycloud.kv/get"]
        }))
        .expect("Listen KV capability"),
    ]
}

fn sql_caveat() -> Value {
    json!({
        "mode": "constrained-statements",
        "readOnly": true,
        "statements": [
            {
                "name": "listen.getConversation",
                "sql": "SELECT id, title, source, source_id, source_url, started_at, ended_at, duration_secs, summary, metadata, transcript_json, transcript_text, created_at, updated_at FROM conversation WHERE id = ?",
                "fixedParams": [{ "index": 0, "value": CONVERSATION_ID }]
            },
            {
                "name": "listen.listParticipants",
                "sql": "SELECT id, name, email, speaker_label FROM participant WHERE conversation_id = ? ORDER BY COALESCE(speaker_label, name), id",
                "fixedParams": [{ "index": 0, "value": CONVERSATION_ID }]
            }
        ]
    })
}

fn policy_status(
    policy: &Policy,
    signer_did: &str,
    sequence: u64,
    disposition: PolicyDisposition,
) -> PolicyStatus {
    PolicyStatus {
        schema: policy_core::POLICY_STATUS_SCHEMA.to_string(),
        status_id: String::new(),
        policy_id: policy.policy_id.clone(),
        owner_did: policy.owner_did.clone(),
        sequence,
        disposition,
        effective_at: "2026-01-01T00:00:00Z".to_string(),
        reason_code: None,
        signing_key_did: signer_did.to_string(),
        signature: placeholder_signature(signer_did),
    }
}

fn verified_policy(mut value: Policy, key: &SigningKey) -> Result<Policy> {
    let digest = digest_signed_object(&value)?;
    value.policy_id = compute_signed_object_id(SignedObjectType::Policy, &digest);
    value.signature.value = URL_SAFE_NO_PAD.encode(key.sign(&digest).to_bytes());
    match verify_signed_object_value(&serde_json::to_value(value)?)? {
        VerifiedSignedObject::Policy(policy) => Ok(policy),
        _ => anyhow::bail!("verified object was not a policy"),
    }
}

fn verified_status(mut value: PolicyStatus, key: &SigningKey) -> Result<PolicyStatus> {
    let digest = digest_signed_object(&value)?;
    value.status_id = compute_signed_object_id(SignedObjectType::PolicyStatus, &digest);
    value.signature.value = URL_SAFE_NO_PAD.encode(key.sign(&digest).to_bytes());
    match verify_signed_object_value(&serde_json::to_value(value)?)? {
        VerifiedSignedObject::PolicyStatus(status) => Ok(status),
        _ => anyhow::bail!("verified object was not a policy status"),
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_presentation(
    policy: &Policy,
    challenge: &GrantChallenge,
    holder_did: &str,
    holder_key: &SigningKey,
    evidence: Value,
    audience: &str,
    enrollment_sequence: u64,
    verification_time: DateTime<Utc>,
) -> Result<GrantPresentation> {
    let capabilities = policy.resource.permissions_ceiling.clone();
    let mut presentation = GrantPresentation {
        schema: policy_core::GRANT_PRESENTATION_SCHEMA.to_string(),
        policy_id: policy.policy_id.clone(),
        eligible_subject_did: SUBJECT.to_string(),
        holder_did: holder_did.to_string(),
        holder_binding: HolderBindingProof::EnrolledAgent {
            enrollment: HolderEnrollment {
                schema: policy_core::HOLDER_ENROLLMENT_SCHEMA.to_string(),
                enrollment_id: "henr_m1_launch_holder".to_string(),
                eligible_subject_did: SUBJECT.to_string(),
                holder_did: holder_did.to_string(),
                scope: None,
                not_before: "2026-01-01T00:00:00Z".to_string(),
                expires_at: None,
                signing_key_did: holder_did.to_string(),
                signature: placeholder_signature(holder_did),
            },
            status: Some(enrollment_status(
                enrollment_sequence,
                HolderEnrollmentDisposition::Active,
            )),
        },
        requested_capabilities_hash: requested_capabilities_hash_hex(&capabilities),
        requested_capabilities: capabilities,
        audience: audience.to_string(),
        nonce: challenge.nonce.clone(),
        expires_at: (verification_time + Duration::minutes(5)).to_rfc3339(),
        evidence: Some(vec![PresentedEvidence {
            requirement_id: EVIDENCE_ID.to_string(),
            presentation: evidence,
        }]),
        holder_signature: placeholder_signature(holder_did),
    };
    let digest = policy_core::signed_object::digest_grant_presentation(&presentation)?;
    presentation.holder_signature.value =
        URL_SAFE_NO_PAD.encode(holder_key.sign(&digest).to_bytes());
    Ok(presentation)
}

fn enrollment_status(
    sequence: u64,
    disposition: HolderEnrollmentDisposition,
) -> HolderEnrollmentStatus {
    HolderEnrollmentStatus {
        schema: policy_core::HOLDER_ENROLLMENT_STATUS_SCHEMA.to_string(),
        status_id: format!("henrst_m1_{sequence}"),
        enrollment_id: "henr_m1_launch_holder".to_string(),
        sequence,
        disposition,
        effective_at: "2026-01-01T00:00:00Z".to_string(),
        signing_key_did: SUBJECT.to_string(),
        signature: placeholder_signature(SUBJECT),
    }
}

fn signed_node_ucan(
    owner_jwk: &JWK,
    owner_vm: &str,
    holder_did: &str,
    space: &SpaceId,
    capabilities: &[PolicyCapability],
    expiration: f64,
    fact: Option<Value>,
) -> Result<String> {
    let mut caps = Capabilities::new();
    for capability in capabilities {
        let service = match capability.service.as_str() {
            "tinycloud.sql" => "sql",
            "tinycloud.kv" => "kv",
            other => anyhow::bail!("unsupported policy capability service {other}"),
        }
        .parse::<Service>()?;
        let resource = space.clone().to_resource(
            service,
            Some(capability.path.parse::<AuthPath>()?),
            None,
            None,
        );
        let mut nb = BTreeMap::new();
        if let Some(caveat) = &capability.caveats {
            for (key, value) in caveat.as_object().context("caveat object")? {
                nb.insert(key.clone(), value.clone());
            }
        }
        for action in &capability.actions {
            caps.with_action(
                resource.as_uri(),
                action.parse::<UcanAbility>()?,
                [nb.clone()],
            );
        }
    }
    let ucan = Payload {
        issuer: owner_vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(expiration)?,
        nonce: Some(format!("m1-delegation-{}", expiration as i64)),
        facts: fact.map(|value| vec![value]),
        proof: vec![],
        attenuation: caps,
    }
    .sign(owner_jwk.get_algorithm().unwrap_or_default(), owner_jwk)?;
    Ok(ucan.encode()?)
}

fn holder_invocation(
    signer: &InvocationSigner<'_>,
    resource: &ResourceId,
    ability: &str,
    caveat: Option<Value>,
    nonce: &str,
) -> Result<String> {
    let mut caps = Capabilities::new();
    let mut nb = BTreeMap::new();
    if let Some(caveat) = caveat {
        for (key, value) in caveat.as_object().context("invocation caveat object")? {
            nb.insert(key.clone(), value.clone());
        }
    }
    caps.with_action(resource.as_uri(), ability.parse::<UcanAbility>()?, [nb]);
    let payload = Payload {
        issuer: signer.verification_method.parse::<DIDURLBuf>()?,
        audience: signer.did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            (Utc::now() + Duration::minutes(2)).timestamp() as f64
        )?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<Value>::new()),
        proof: vec![signer.parent.to_cid(0x55)],
        attenuation: caps,
    }
    .sign(signer.jwk.get_algorithm().unwrap_or_default(), signer.jwk)?;
    Ok(payload.encode()?)
}

async fn invoke_sql(
    context: &InvocationContext<'_>,
    nonce: &str,
    request: SqlRequest,
) -> Result<(Status, String)> {
    let resource = context.space.clone().to_resource(
        "sql".parse::<Service>()?,
        Some(SQL_PATH.parse::<AuthPath>()?),
        None,
        None,
    );
    let header = holder_invocation(
        &context.signer,
        &resource,
        "tinycloud.sql/read",
        Some(sql_caveat()),
        nonce,
    )?;
    let response = context
        .client
        .post("/invoke")
        .header(Header::new("Authorization", header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&request)?)
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    Ok((status, body))
}

async fn invoke_kv(
    context: &InvocationContext<'_>,
    ability: &str,
    nonce: &str,
) -> Result<(Status, Vec<u8>)> {
    let resource = context.space.clone().to_resource(
        "kv".parse::<Service>()?,
        Some(KV_PATH.parse::<AuthPath>()?),
        None,
        None,
    );
    let header = holder_invocation(&context.signer, &resource, ability, None, nonce)?;
    let response = context
        .client
        .post("/invoke")
        .header(Header::new("Authorization", header))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_bytes().await.unwrap_or_default();
    Ok((status, body))
}

async fn seed_listen_kv(
    client: &Client,
    owner_jwk: &JWK,
    owner_vm: &str,
    owner_did: &str,
    space: &SpaceId,
) -> Result<()> {
    let resource = space.clone().to_resource(
        "kv".parse::<Service>()?,
        Some(KV_PATH.parse::<AuthPath>()?),
        None,
        None,
    );
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        "tinycloud.kv/put".parse::<UcanAbility>()?,
        [BTreeMap::<String, Value>::new()],
    );
    let invocation = Payload {
        issuer: owner_vm.parse::<DIDURLBuf>()?,
        audience: owner_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            (Utc::now() + Duration::minutes(2)).timestamp() as f64
        )?,
        nonce: Some("kv-owner-seed".to_string()),
        facts: Some(Vec::<Value>::new()),
        proof: vec![],
        attenuation: caps,
    }
    .sign(owner_jwk.get_algorithm().unwrap_or_default(), owner_jwk)?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation.encode()?))
        .body(KV_SEED)
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "KV seed operation: {body}");
    Ok(())
}

async fn seed_listen_sql(sql: &SqlService, space: &SpaceId) -> Result<()> {
    sql.execute(
        space,
        SQL_DB,
        SqlRequest::Execute {
            schema: Some(vec![
                "CREATE TABLE conversation (id TEXT PRIMARY KEY, title TEXT, source TEXT, source_id TEXT, source_url TEXT, started_at TEXT, ended_at TEXT, duration_secs INTEGER, summary TEXT, metadata TEXT, transcript_json TEXT, transcript_text TEXT, created_at TEXT, updated_at TEXT)".to_string(),
                "CREATE TABLE participant (id TEXT PRIMARY KEY, conversation_id TEXT, name TEXT, email TEXT, speaker_label TEXT)".to_string(),
            ]),
            sql: "INSERT INTO conversation (id, title, source, source_id, source_url, started_at, ended_at, duration_secs, summary, metadata, transcript_json, transcript_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string(),
            params: vec![
                SqlValue::Text(CONVERSATION_ID.to_string()),
                SqlValue::Text("Planning".to_string()),
                SqlValue::Text("manual".to_string()),
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::Text("2026-05-14T14:00:00Z".to_string()),
                SqlValue::Text("2026-05-14T14:20:00Z".to_string()),
                SqlValue::Integer(1200),
                SqlValue::Text("M1 owner demo fixture".to_string()),
                SqlValue::Text("{}".to_string()),
                SqlValue::Text("[{\"speaker\":\"Ada\",\"text\":\"Hello\"}]".to_string()),
                SqlValue::Text("Ada: Hello".to_string()),
                SqlValue::Text("2026-05-14T14:00:00Z".to_string()),
                SqlValue::Text("2026-05-14T14:00:00Z".to_string()),
            ],
        },
        None,
        "tinycloud.sql/write".to_string(),
    )
    .await?;
    sql.execute(
        space,
        SQL_DB,
        SqlRequest::Execute {
            schema: None,
            sql: "INSERT INTO participant (id, conversation_id, name, email, speaker_label) VALUES (?, ?, ?, ?, ?)".to_string(),
            params: vec![
                SqlValue::Text("p1".to_string()),
                SqlValue::Text(CONVERSATION_ID.to_string()),
                SqlValue::Text("Ada".to_string()),
                SqlValue::Text("ada@example.com".to_string()),
                SqlValue::Text("Speaker 1".to_string()),
            ],
        },
        None,
        "tinycloud.sql/write".to_string(),
    )
    .await?;
    Ok(())
}

fn fixture_evidence(source: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(source)?;
    Ok(json!({ "sdJwt": value["evidencePresentation"]["sdJwt"] }))
}

fn fixture_verification_time(source: &str) -> Result<DateTime<Utc>> {
    let fixture: Value = serde_json::from_str(source)?;
    let timestamp = fixture["verificationOptions"]["now"]
        .as_i64()
        .context("fixture verificationOptions.now integer timestamp")?;
    DateTime::from_timestamp(timestamp, 0).context("fixture verificationOptions.now timestamp")
}

async fn observe_grant_output_on_real_node(
    client: &Client,
    conn: &DatabaseConnection,
    datadir: &Path,
    sql_service: &SqlService,
) -> Result<()> {
    let authority_before = delegation::Entity::find().count(conn).await?;
    let generated = TempDir::new()?;
    let instant = Utc::now().timestamp();
    let status = Command::new("python3")
        .arg(Path::new(GRANT_OUTPUT_DIR).join("generate.py"))
        .arg("--at-instant")
        .arg(instant.to_string())
        .arg("--output-dir")
        .arg(generated.path())
        .status()?;
    anyhow::ensure!(status.success(), "pinned grant generator failed");
    let accept: Value =
        serde_json::from_str(&fs::read_to_string(generated.path().join("accept.json"))?)?;

    let owner_did = accept["parentFormatVector"]["issuer"]
        .as_str()
        .context("parent issuer")?;
    let space_id = SpaceId::new(owner_did.parse::<DIDBuf>()?, "default".parse()?);
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(conn)
    .await?;
    tokio::fs::create_dir_all(
        datadir
            .join("blocks")
            .join(space_id.suffix())
            .join(space_id.name().as_str()),
    )
    .await?;
    seed_grant_vector_sql(sql_service, &space_id).await?;

    let mut parent = accept["parentFormatVector"]["dagCborBase64Url"]
        .as_str()
        .context("parent bytes")?
        .to_string();
    while parent.len() % 4 != 0 {
        parent.push('=');
    }
    let parent_response = client
        .post("/delegate")
        .header(Header::new("Authorization", parent))
        .dispatch()
        .await;
    let parent_status = parent_response.status();
    let parent_body = parent_response.into_string().await.unwrap_or_default();
    assert_eq!(parent_status, Status::Ok, "parent import: {parent_body}");
    let parent_json: Value = serde_json::from_str(&parent_body)?;
    assert_eq!(
        parent_json["cid"], accept["parentFormatVector"]["expectedCid"],
        "the real node must derive the frozen parent-format CID"
    );

    let grant = accept["cases"][0]["ucan"]["encoded"]
        .as_str()
        .context("generated accept UCAN")?
        .to_string();
    let grant_response = client
        .post("/delegate")
        .header(Header::new("Authorization", grant))
        .dispatch()
        .await;
    let grant_status = grant_response.status();
    let grant_body = grant_response.into_string().await.unwrap_or_default();
    assert_eq!(grant_status, Status::Ok, "grant import: {grant_body}");
    let grant_json: Value = serde_json::from_str(&grant_body)?;
    assert_eq!(
        grant_json["cid"],
        accept["cases"][0]["ucan"]["delegationId"]
    );
    assert_eq!(
        delegation::Entity::find().count(conn).await?,
        authority_before + 2
    );

    let holder_jwk = ed25519_jwk_from_seed([0x33; 32])?;
    let (holder_did, holder_vm) = node_identity(&holder_jwk)?;
    assert_eq!(holder_did, accept["cases"][0]["ucan"]["payload"]["aud"]);
    let imported_hash = Hash::from(
        grant_json["cid"]
            .as_str()
            .context("grant response CID")?
            .parse::<AuthCid>()?,
    );
    let sql_resource = space_id.clone().to_resource(
        "sql".parse::<Service>()?,
        Some(SQL_PATH.parse::<AuthPath>()?),
        None,
        None,
    );
    let vector_caveat = accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone();
    let invocation = holder_invocation(
        &InvocationSigner {
            jwk: &holder_jwk,
            verification_method: &holder_vm,
            did: &holder_did,
            parent: imported_hash,
        },
        &sql_resource,
        "tinycloud.sql/read",
        Some(vector_caveat),
        "grant-vector-named-sql",
    )?;
    let sql_response = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&SqlRequest::ExecuteStatement {
            name: "listen.getConversation".to_string(),
            params: vec![],
        })?)
        .dispatch()
        .await;
    let sql_status = sql_response.status();
    let sql_body = sql_response.into_string().await.unwrap_or_default();
    assert_eq!(sql_status, Status::Ok, "vector named SQL: {sql_body}");
    let sql_json: Value = serde_json::from_str(&sql_body)?;
    assert_eq!(sql_json["rowCount"], 1);
    assert_eq!(sql_json["rows"][0][0], "conv_456");

    let grant_jwk = ed25519_jwk_from_seed([0x22; 32])?;
    let grant_signer = signing_key(&grant_jwk)?;
    let (grant_issuer_did, grant_issuer_vm) = node_identity(&grant_jwk)?;
    assert_eq!(grant_issuer_did, accept["parentFormatVector"]["audience"]);
    let sql_capability = policy_core::parse_policy_capability(&json!({
        "service": "tinycloud.sql",
        "space": "default",
        "path": SQL_PATH,
        "actions": ["tinycloud.sql/read"],
        "caveats": accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()
    }))?;
    let parent_config = parent_config_from_vector(&accept, vec![sql_capability.clone()])?;
    let mut production_issuer =
        SharedGrantIssuer::new(grant_issuer_did.clone(), grant_signer, [parent_config]);
    let mut minimum_ttl_hash = None;
    let mut terminal_parent_hash = None;
    let interop_cases = [
        ("named-statement", vec![sql_capability.clone()], 120_i64),
        ("minimum-ttl", vec![sql_capability.clone()], 1_i64),
        ("maximum-ttl", vec![sql_capability], 300_i64),
    ];
    for (case_name, capabilities, ttl_seconds) in interop_cases {
        let issued_capabilities = capabilities.clone();
        let issued_at = Utc::now();
        let mut engine_policy = policy(&space_id, &grant_issuer_did);
        engine_policy.policy_id = format!("pol_m1_g08_{case_name}");
        engine_policy.resource.permissions_ceiling = capabilities.clone();
        engine_policy.grant.max_ttl_seconds = ttl_seconds as u64;
        engine_policy.grant.revocation = RevocationMode::RefreshOnly;
        let emitted = production_issuer.issue(GrantIssueRequest {
            holder_did: holder_did.clone(),
            capabilities,
            issued_at,
            expires_at: issued_at + Duration::seconds(ttl_seconds),
            presentation_expires_at: issued_at + Duration::seconds(300),
            terminal: true,
            evidence_ids: Vec::new(),
            evidence_provenance: Vec::new(),
            policy: engine_policy,
        })?;
        let emitted_response = client
            .post("/delegate")
            .header(Header::new("Authorization", emitted.encoded.clone()))
            .dispatch()
            .await;
        let emitted_status = emitted_response.status();
        let emitted_body = emitted_response.into_string().await.unwrap_or_default();
        assert_eq!(
            emitted_status,
            Status::Ok,
            "actual g-07 engine {case_name}: {emitted_body}"
        );
        let emitted_json: Value = serde_json::from_str(&emitted_body)?;
        assert_eq!(emitted_json["cid"], emitted.delegation_id);
        assert_eq!(
            production_issuer
                .issued(&emitted.delegation_id)
                .context("production issuer durable record")?
                .encoded,
            emitted.encoded
        );
        let emitted_hash = Hash::from(
            emitted
                .delegation_id
                .parse::<AuthCid>()
                .with_context(|| format!("{case_name} emitted CID"))?,
        );
        if case_name == "minimum-ttl" {
            minimum_ttl_hash = Some(emitted_hash);
        }
        if case_name == "named-statement" {
            terminal_parent_hash = Some(emitted_hash);
        }
        let emitted_invocation = holder_invocation(
            &InvocationSigner {
                jwk: &holder_jwk,
                verification_method: &holder_vm,
                did: &holder_did,
                parent: emitted_hash,
            },
            &sql_resource,
            "tinycloud.sql/read",
            issued_capabilities[0].caveats.clone(),
            &format!("engine-{case_name}"),
        )?;
        let enforced = client
            .post("/invoke")
            .header(Header::new("Authorization", emitted_invocation))
            .header(ContentType::JSON)
            .body(serde_json::to_string(&SqlRequest::ExecuteStatement {
                name: "listen.getConversation".to_string(),
                params: vec![],
            })?)
            .dispatch()
            .await;
        let enforced_status = enforced.status();
        let enforced_body = enforced.into_string().await.unwrap_or_default();
        assert_eq!(
            enforced_status,
            Status::Ok,
            "actual g-07 engine {case_name} enforcement: {enforced_body}"
        );
        let enforced_json: Value = serde_json::from_str(&enforced_body)?;
        assert_eq!(enforced_json["rows"][0][0], "conv_456");
    }

    exercise_engine_sql_kv_mix(EngineSqlKvContext {
        client,
        conn,
        datadir,
        sql_service,
        grant_jwk: &grant_jwk,
        grant_issuer_did: &grant_issuer_did,
        holder_jwk: &holder_jwk,
        holder_vm: &holder_vm,
        holder_did: &holder_did,
        caveat: accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone(),
    })
    .await?;

    let wrong_jwk = ed25519_jwk_from_seed([0x11; 32])?;
    let (wrong_did, wrong_vm) = node_identity(&wrong_jwk)?;
    let terminal_child = signed_delegation_with_proof(
        &holder_jwk,
        &holder_vm,
        &wrong_did,
        &sql_resource,
        "tinycloud.sql/read",
        Some(accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()),
        vec![terminal_parent_hash
            .context("terminal engine grant")?
            .to_cid(0x55)],
        "terminal",
        60,
        "terminal-parent-child",
    )?;
    assert_delegate_reject(
        client,
        terminal_child,
        "terminal-parent",
        "terminal-parent-cannot-redelegate",
    )
    .await?;

    let cacao_parent_cid = accept["parentFormatVector"]["expectedCid"]
        .as_str()
        .context("CACAO parent CID")?
        .parse::<AuthCid>()?;
    let narrow_parent = signed_delegation_with_proof(
        &grant_jwk,
        &grant_issuer_vm,
        &holder_did,
        &sql_resource,
        "tinycloud.sql/read",
        Some(accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()),
        vec![cacao_parent_cid],
        "attenuable",
        120,
        "caveat-parent",
    )?;
    let narrow_response = client
        .post("/delegate")
        .header(Header::new("Authorization", narrow_parent))
        .dispatch()
        .await;
    let narrow_status = narrow_response.status();
    let narrow_body = narrow_response.into_string().await.unwrap_or_default();
    assert_eq!(narrow_status, Status::Ok, "caveat parent: {narrow_body}");
    let narrow_json: Value = serde_json::from_str(&narrow_body)?;
    let narrow_hash = Hash::from(
        narrow_json["cid"]
            .as_str()
            .context("caveat parent CID")?
            .parse::<AuthCid>()?,
    );
    let wider_child = signed_delegation_with_proof(
        &holder_jwk,
        &holder_vm,
        &wrong_did,
        &sql_resource,
        "tinycloud.sql/read",
        None,
        vec![narrow_hash.to_cid(0x55)],
        "terminal",
        60,
        "caveat-child",
    )?;
    assert_delegate_reject(
        client,
        wider_child,
        "caveat-containment-failure",
        "child-caveats-not-subset-of-parent: containment-caveat-required",
    )
    .await?;

    let valid_grandchild = signed_delegation_with_proof(
        &holder_jwk,
        &holder_vm,
        &wrong_did,
        &sql_resource,
        "tinycloud.sql/read",
        Some(accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()),
        vec![narrow_hash.to_cid(0x55)],
        "terminal",
        60,
        "revoked-parent-child",
    )?;
    let grandchild_response = client
        .post("/delegate")
        .header(Header::new("Authorization", valid_grandchild))
        .dispatch()
        .await;
    let grandchild_status = grandchild_response.status();
    let grandchild_body = grandchild_response.into_string().await.unwrap_or_default();
    assert_eq!(
        grandchild_status,
        Status::Ok,
        "revoked-parent child import: {grandchild_body}"
    );
    let grandchild_json: Value = serde_json::from_str(&grandchild_body)?;
    let grandchild_hash = Hash::from(
        grandchild_json["cid"]
            .as_str()
            .context("revoked-parent child CID")?
            .parse::<AuthCid>()?,
    );
    let revocation = signed_ucan_revocation(
        &grant_jwk,
        &grant_issuer_vm,
        &grant_issuer_did,
        narrow_hash.to_cid(0x55),
    )?;
    let revoke_response = client
        .post("/revoke")
        .header(Header::new("Authorization", revocation))
        .dispatch()
        .await;
    let revoke_status = revoke_response.status();
    let revoke_body = revoke_response.into_string().await.unwrap_or_default();
    assert_eq!(revoke_status, Status::Ok, "revoke parent: {revoke_body}");
    let revoked_parent_invocation = holder_invocation(
        &InvocationSigner {
            jwk: &wrong_jwk,
            verification_method: &wrong_vm,
            did: &wrong_did,
            parent: grandchild_hash,
        },
        &sql_resource,
        "tinycloud.sql/read",
        Some(accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()),
        "node-invocation-revoked-parent",
    )?;
    assert_invoke_reject(
        client,
        revoked_parent_invocation,
        "revoked-parent",
        "delegation-ancestor-revoked:",
    )
    .await?;

    let wrong_invoker = holder_invocation(
        &InvocationSigner {
            jwk: &wrong_jwk,
            verification_method: &wrong_vm,
            did: &wrong_did,
            parent: imported_hash,
        },
        &sql_resource,
        "tinycloud.sql/read",
        Some(accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()),
        "node-invocation-wrong-invoker",
    )?;
    assert_invoke_reject(
        client,
        wrong_invoker,
        "holder-audience-mismatch",
        "Unauthorized Invoker",
    )
    .await?;

    let unauthorized_action = holder_invocation(
        &InvocationSigner {
            jwk: &holder_jwk,
            verification_method: &holder_vm,
            did: &holder_did,
            parent: imported_hash,
        },
        &sql_resource,
        "tinycloud.sql/write",
        None,
        "node-invocation-unauthorized-action",
    )?;
    assert_invoke_reject(
        client,
        unauthorized_action,
        "unauthorized-requested-action",
        "Unauthorized Action",
    )
    .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let expired_chain = holder_invocation(
        &InvocationSigner {
            jwk: &holder_jwk,
            verification_method: &holder_vm,
            did: &holder_did,
            parent: minimum_ttl_hash.context("minimum TTL grant hash")?,
        },
        &sql_resource,
        "tinycloud.sql/read",
        Some(accept["cases"][0]["expectedExtractedCapability"]["notaBene"]["0"].clone()),
        "node-invocation-expired-proof-chain",
    )?;
    assert_invoke_reject(
        client,
        expired_chain,
        "expired-proof-chain",
        "Unauthorized Action",
    )
    .await?;

    let rejects: Value = serde_json::from_str(&fs::read_to_string(
        generated.path().join("node-import-reject.json"),
    )?)?;
    for (case_name, expected_text) in [
        ("invalid-signature", "Failed to verify signature"),
        ("missing-persisted-parent", "Cannot find parent delegation"),
        (
            "parent-time-nesting-violation",
            "Child delegation expiry exceeds parent expiry",
        ),
        (
            "resource-or-ability-containment-failure",
            "Unauthorized Capability",
        ),
    ] {
        let case = rejects["cases"]
            .as_array()
            .context("node import cases")?
            .iter()
            .find(|case| case["case"] == case_name)
            .with_context(|| format!("missing generated case {case_name}"))?;
        let encoded = case["ucan"]["encoded"]
            .as_str()
            .context("reject UCAN")?
            .to_string();
        let response = client
            .post("/delegate")
            .header(Header::new("Authorization", encoded))
            .dispatch()
            .await;
        let observed_status = response.status();
        let observed_body = response.into_string().await.unwrap_or_default();
        assert_eq!(
            observed_status,
            Status::Unauthorized,
            "{case_name}: {observed_body}"
        );
        assert!(
            observed_body.contains(expected_text),
            "{case_name} intended {expected_text}, observed {observed_body}"
        );
        if case_name != "invalid-signature" {
            assert!(
                !observed_body.contains("expired or not yet valid"),
                "{case_name} was accidentally masked by ambient time: {observed_body}"
            );
        }
    }

    let frozen_accept: Value = serde_json::from_str(&fs::read_to_string(
        Path::new(GRANT_OUTPUT_DIR).join("accept.json"),
    )?)?;
    let frozen_encoded = frozen_accept["cases"][0]["ucan"]["encoded"]
        .as_str()
        .context("frozen ACCEPT UCAN")?
        .to_string();
    let frozen_rejects: Value = serde_json::from_str(&fs::read_to_string(
        Path::new(GRANT_OUTPUT_DIR).join("node-import-reject.json"),
    )?)?;
    let intended_invalid_time = frozen_rejects["cases"]
        .as_array()
        .context("frozen node import cases")?
        .iter()
        .find(|case| case["case"] == "invalid-time")
        .context("frozen invalid-time case")?["ucan"]["encoded"]
        .as_str()
        .context("frozen invalid-time UCAN")?
        .to_string();
    let invalid_time = client
        .post("/delegate")
        .header(Header::new("Authorization", intended_invalid_time))
        .dispatch()
        .await;
    let invalid_time_status = invalid_time.status();
    let invalid_time_body = invalid_time.into_string().await.unwrap_or_default();
    assert_eq!(invalid_time_status, Status::Unauthorized);
    assert!(invalid_time_body.contains("expired or not yet valid"));
    let expired = client
        .post("/delegate")
        .header(Header::new("Authorization", frozen_encoded))
        .dispatch()
        .await;
    let expired_status = expired.status();
    let expired_body = expired.into_string().await.unwrap_or_default();
    assert_eq!(expired_status, Status::Unauthorized);
    assert!(
        expired_body.contains("expired or not yet valid"),
        "LONGEVITY OBSERVATION: frozen ACCEPT should now be natively time-invalid: {expired_body}"
    );
    Ok(())
}

fn ed25519_jwk_from_seed(seed: [u8; 32]) -> Result<JWK> {
    let key = SigningKey::from_bytes(&seed);
    let mut jwk: JWK = serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        "d": URL_SAFE_NO_PAD.encode(seed),
        "alg": "EdDSA"
    }))?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    Ok(jwk)
}

fn parent_config_from_vector(
    accept: &Value,
    policy_capabilities: Vec<PolicyCapability>,
) -> Result<ParentDelegationConfig> {
    let vector = &accept["parentFormatVector"];
    let not_before = Some(
        DateTime::parse_from_rfc3339(vector["issuedAt"].as_str().context("parent issuedAt")?)?
            .with_timezone(&Utc),
    );
    let expires_at =
        DateTime::parse_from_rfc3339(vector["expiresAt"].as_str().context("parent expiresAt")?)?
            .with_timezone(&Utc);
    let native_resource = accept["cases"][0]["expectedExtractedCapability"]["resource"]
        .as_str()
        .context("native resource")?
        .to_string();
    let bounds = policy_capabilities
        .into_iter()
        .map(|policy_capability| ParentCapabilityBound {
            policy_capability,
            native_resource: native_resource.clone(),
        })
        .collect::<Vec<_>>();
    let expected_cid = vector["expectedCid"]
        .as_str()
        .context("parent CID")?
        .to_string();
    let audience = vector["audience"]
        .as_str()
        .context("parent audience")?
        .to_string();
    Ok(ParentDelegationConfig {
        owner_did: vector["issuer"]
            .as_str()
            .context("parent owner")?
            .to_string(),
        artifact_base64_url: vector["dagCborBase64Url"]
            .as_str()
            .context("parent artifact")?
            .to_string(),
        expected_cid: expected_cid.clone(),
        audience: audience.clone(),
        not_before,
        expires_at,
        terminal: false,
        capability_bounds: bounds.clone(),
        delegate_receipt: CapturedParentDelegateReceipt {
            delegation_id: expected_cid,
            delegatee_did: audience,
            not_before,
            expires_at,
            terminal: false,
            capability_bounds: bounds,
        },
    })
}

async fn seed_grant_vector_sql(sql: &SqlService, space: &SpaceId) -> Result<()> {
    sql.execute(
        space,
        SQL_DB,
        SqlRequest::Execute {
            schema: Some(vec!["CREATE TABLE conversation (id TEXT PRIMARY KEY, title TEXT, source TEXT, source_id TEXT, source_url TEXT, started_at TEXT, ended_at TEXT, duration_secs INTEGER, summary TEXT, metadata TEXT, transcript_json TEXT, transcript_text TEXT, created_at TEXT, updated_at TEXT)".to_string()]),
            sql: "INSERT INTO conversation (id, title, source, source_id, source_url, started_at, ended_at, duration_secs, summary, metadata, transcript_json, transcript_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string(),
            params: vec![
                SqlValue::Text("conv_456".to_string()),
                SqlValue::Text("Grant compatibility".to_string()),
                SqlValue::Text("m1-g-08".to_string()),
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::Text("2026-07-11T00:00:00Z".to_string()),
                SqlValue::Text("2026-07-11T00:01:00Z".to_string()),
                SqlValue::Integer(60),
                SqlValue::Text("real node vector seed".to_string()),
                SqlValue::Text("{}".to_string()),
                SqlValue::Text("[]".to_string()),
                SqlValue::Text("seeded bytes".to_string()),
                SqlValue::Text("2026-07-11T00:00:00Z".to_string()),
                SqlValue::Text("2026-07-11T00:00:00Z".to_string()),
            ],
        },
        None,
        "tinycloud.sql/write".to_string(),
    )
    .await?;
    Ok(())
}

struct EngineSqlKvContext<'a> {
    client: &'a Client,
    conn: &'a DatabaseConnection,
    datadir: &'a Path,
    sql_service: &'a SqlService,
    grant_jwk: &'a JWK,
    grant_issuer_did: &'a str,
    holder_jwk: &'a JWK,
    holder_vm: &'a str,
    holder_did: &'a str,
    caveat: Value,
}

async fn exercise_engine_sql_kv_mix(context: EngineSqlKvContext<'_>) -> Result<()> {
    let owner_jwk = ed25519_jwk_from_seed([0x44; 32])?;
    let (owner_did, owner_vm) = node_identity(&owner_jwk)?;
    let space_id = SpaceId::new(owner_did.parse::<DIDBuf>()?, "default".parse()?);
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(context.conn)
    .await?;
    tokio::fs::create_dir_all(
        context
            .datadir
            .join("blocks")
            .join(space_id.suffix())
            .join(space_id.name().as_str()),
    )
    .await?;
    seed_grant_vector_sql(context.sql_service, &space_id).await?;
    seed_listen_kv(context.client, &owner_jwk, &owner_vm, &owner_did, &space_id).await?;

    let sql_resource = space_id.clone().to_resource(
        "sql".parse::<Service>()?,
        Some(SQL_PATH.parse::<AuthPath>()?),
        None,
        None,
    );
    let kv_resource = space_id.clone().to_resource(
        "kv".parse::<Service>()?,
        Some(KV_PATH.parse::<AuthPath>()?),
        None,
        None,
    );
    let encoded_parent = signed_multi_delegation(
        &owner_jwk,
        &owner_vm,
        context.grant_issuer_did,
        vec![
            (sql_resource.clone(), "tinycloud.sql/read".to_string(), None),
            (kv_resource.clone(), "tinycloud.kv/get".to_string(), None),
        ],
        Vec::new(),
        "attenuable",
        600,
        "engine-sql-kv-parent",
    )?;
    let parent_response = context
        .client
        .post("/delegate")
        .header(Header::new("Authorization", encoded_parent.clone()))
        .dispatch()
        .await;
    let parent_status = parent_response.status();
    let parent_body = parent_response.into_string().await.unwrap_or_default();
    assert_eq!(parent_status, Status::Ok, "SQL+KV parent: {parent_body}");
    let parent_json: Value = serde_json::from_str(&parent_body)?;
    let parent_cid = parent_json["cid"]
        .as_str()
        .context("SQL+KV parent CID")?
        .to_string();

    let sql_capability = policy_core::parse_policy_capability(&json!({
        "service": "tinycloud.sql",
        "space": "default",
        "path": SQL_PATH,
        "actions": ["tinycloud.sql/read"],
        "caveats": context.caveat.clone()
    }))?;
    let kv_capability = policy_core::parse_policy_capability(&json!({
        "service": "tinycloud.kv",
        "space": "default",
        "path": KV_PATH,
        "actions": ["tinycloud.kv/get"]
    }))?;
    let bounds = vec![
        ParentCapabilityBound {
            policy_capability: PolicyCapability {
                caveats: None,
                ..sql_capability.clone()
            },
            native_resource: sql_resource.as_uri().to_string(),
        },
        ParentCapabilityBound {
            policy_capability: kv_capability.clone(),
            native_resource: kv_resource.as_uri().to_string(),
        },
    ];
    let expires_at = Utc::now() + Duration::minutes(10);
    let parent_config = ParentDelegationConfig {
        owner_did: owner_did.clone(),
        artifact_base64_url: encoded_parent,
        expected_cid: parent_cid.clone(),
        audience: context.grant_issuer_did.to_string(),
        not_before: None,
        expires_at,
        terminal: false,
        capability_bounds: bounds.clone(),
        delegate_receipt: CapturedParentDelegateReceipt {
            delegation_id: parent_cid,
            delegatee_did: context.grant_issuer_did.to_string(),
            not_before: None,
            expires_at,
            terminal: false,
            capability_bounds: bounds,
        },
    };
    let mut issuer = SharedGrantIssuer::new(
        context.grant_issuer_did,
        signing_key(context.grant_jwk)?,
        [parent_config],
    );
    let capabilities = vec![sql_capability, kv_capability];
    let issued_at = Utc::now();
    let mut grant_policy = policy(&space_id, context.grant_issuer_did);
    grant_policy.policy_id = "pol_m1_g08_sql_kv_mix".to_string();
    grant_policy.resource.permissions_ceiling = capabilities.clone();
    grant_policy.grant.max_ttl_seconds = 120;
    let emitted = issuer.issue(GrantIssueRequest {
        holder_did: context.holder_did.to_string(),
        capabilities,
        issued_at,
        expires_at: issued_at + Duration::seconds(120),
        presentation_expires_at: issued_at + Duration::seconds(120),
        terminal: true,
        evidence_ids: Vec::new(),
        evidence_provenance: Vec::new(),
        policy: grant_policy,
    })?;
    let response = context
        .client
        .post("/delegate")
        .header(Header::new("Authorization", emitted.encoded.clone()))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "SQL+KV engine grant: {body}");
    let imported: Value = serde_json::from_str(&body)?;
    assert_eq!(imported["cid"], emitted.delegation_id);
    let invocation = InvocationContext {
        client: context.client,
        signer: InvocationSigner {
            jwk: context.holder_jwk,
            verification_method: context.holder_vm,
            did: context.holder_did,
            parent: Hash::from(emitted.delegation_id.parse::<AuthCid>()?),
        },
        space: &space_id,
    };
    let sql_header = holder_invocation(
        &invocation.signer,
        &sql_resource,
        "tinycloud.sql/read",
        Some(context.caveat),
        "engine-mixed-sql",
    )?;
    let sql_response = context
        .client
        .post("/invoke")
        .header(Header::new("Authorization", sql_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&SqlRequest::ExecuteStatement {
            name: "listen.getConversation".to_string(),
            params: vec![],
        })?)
        .dispatch()
        .await;
    let sql_status = sql_response.status();
    let sql_body = sql_response.into_string().await.unwrap_or_default();
    assert_eq!(sql_status, Status::Ok, "SQL+KV SQL: {sql_body}");
    let kv = invoke_kv(&invocation, "tinycloud.kv/get", "engine-mixed-kv").await?;
    assert_eq!(
        kv.0,
        Status::Ok,
        "SQL+KV KV: {}",
        String::from_utf8_lossy(&kv.1)
    );
    assert_eq!(kv.1, KV_SEED);
    Ok(())
}

async fn assert_invoke_reject(
    client: &Client,
    authorization: String,
    case_name: &str,
    expected_text: &str,
) -> Result<()> {
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", authorization))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Unauthorized, "{case_name}: {body}");
    assert!(
        body.contains(expected_text),
        "{case_name} intended {expected_text}, observed {body}"
    );
    Ok(())
}

async fn assert_delegate_reject(
    client: &Client,
    authorization: String,
    case_name: &str,
    expected_text: &str,
) -> Result<()> {
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", authorization))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Unauthorized, "{case_name}: {body}");
    assert!(
        body.contains(expected_text),
        "{case_name} intended {expected_text}, observed {body}"
    );
    assert!(
        !body.contains("expired or not yet valid"),
        "{case_name} was accidentally masked by ambient time: {body}"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn signed_delegation_with_proof(
    issuer_jwk: &JWK,
    issuer_vm: &str,
    audience: &str,
    resource: &ResourceId,
    ability: &str,
    caveat: Option<Value>,
    proof: Vec<AuthCid>,
    mode: &str,
    ttl_seconds: i64,
    nonce: &str,
) -> Result<String> {
    signed_multi_delegation(
        issuer_jwk,
        issuer_vm,
        audience,
        vec![(resource.clone(), ability.to_string(), caveat)],
        proof,
        mode,
        ttl_seconds,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_multi_delegation(
    issuer_jwk: &JWK,
    issuer_vm: &str,
    audience: &str,
    grants: Vec<(ResourceId, String, Option<Value>)>,
    proof: Vec<AuthCid>,
    mode: &str,
    ttl_seconds: i64,
    nonce: &str,
) -> Result<String> {
    let mut capabilities = Capabilities::new();
    for (resource, ability, caveat) in grants {
        let mut nota_bene = BTreeMap::new();
        if let Some(caveat) = caveat {
            for (key, value) in caveat.as_object().context("delegation caveat object")? {
                nota_bene.insert(key.clone(), value.clone());
            }
        }
        capabilities.with_action(
            resource.as_uri(),
            ability.parse::<UcanAbility>()?,
            [nota_bene],
        );
    }
    let payload = Payload {
        issuer: issuer_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            (Utc::now() + Duration::seconds(ttl_seconds)).timestamp() as f64,
        )?,
        nonce: Some(nonce.to_string()),
        facts: Some(vec![json!({
            tinycloud_core::util::DelegationMode::FACT_KEY: mode
        })]),
        proof,
        attenuation: capabilities,
    }
    .sign(issuer_jwk.get_algorithm().unwrap_or_default(), issuer_jwk)?;
    Ok(payload.encode()?)
}

fn signed_ucan_revocation(
    issuer_jwk: &JWK,
    issuer_vm: &str,
    audience: &str,
    target: AuthCid,
) -> Result<String> {
    let mut capabilities = Capabilities::new();
    let resource = format!("urn:cid:{target}");
    capabilities.with_action(
        resource.parse()?,
        "tinycloud/revoke".parse::<UcanAbility>()?,
        [BTreeMap::<String, Value>::new()],
    );
    let payload = Payload {
        issuer: issuer_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            (Utc::now() + Duration::minutes(2)).timestamp() as f64
        )?,
        nonce: Some("m1-g-08-revoked-parent".to_string()),
        facts: Some(Vec::<Value>::new()),
        proof: Vec::new(),
        attenuation: capabilities,
    }
    .sign(issuer_jwk.get_algorithm().unwrap_or_default(), issuer_jwk)?;
    Ok(payload.encode()?)
}

#[test]
fn evidence_verification_uses_fixture_time_under_hostile_ambient() -> Result<()> {
    let mut owner_jwk = JWK::generate_ed25519()?;
    owner_jwk.algorithm = Some(Algorithm::EdDSA);
    let owner_did = node_identity(&owner_jwk)?.0;
    let space = SpaceId::new(owner_did.parse::<DIDBuf>()?, SPACE_NAME.parse()?);
    let policy = policy(&space, &owner_did);
    let requirement = match &policy.when {
        policy_core::Expression::Evidence(expression) => expression.evidence.clone(),
        _ => anyhow::bail!("launch policy must contain its credential evidence requirement"),
    };
    let hostile_ambient_now = DateTime::from_timestamp(HOSTILE_AMBIENT_TIMESTAMP, 0)
        .context("hostile ambient timestamp")?;
    let fixture_now = fixture_verification_time(VALID_FIXTURE)?;
    let observation = Arc::new(Mutex::new(None));
    let verifier = fixture_time_verifier(
        trusted_verifier(),
        fixture_now,
        Some(Arc::clone(&observation)),
    );
    let ambient_context = RuntimeEvidenceContext {
        policy: policy.clone(),
        eligible_subject_did: SUBJECT.to_string(),
        holder_did: SUBJECT.to_string(),
        requested_capabilities: policy.resource.permissions_ceiling.clone(),
        now: hostile_ambient_now,
    };

    let satisfaction = EvidenceVerifier::verify_with_provenance(
        &verifier,
        &requirement,
        &fixture_evidence(VALID_FIXTURE)?,
        &ambient_context,
    )?;

    assert_eq!(
        *observation.lock().expect("clock observation lock"),
        Some((hostile_ambient_now, fixture_now)),
        "the real verifier adapter must observe hostile ambient runtime time and pass fixture time onward"
    );
    assert_ne!(hostile_ambient_now, fixture_now);
    assert!(
        !satisfaction.evidence_ids.is_empty(),
        "credential verification must produce evidence satisfaction under hostile ambient time"
    );
    Ok(())
}

#[test]
fn evidence_verification_path_rejects_direct_wall_clock_reads() {
    let source = include_str!("cross_layer_contract.rs");
    let setup_and_resolve = source
        .split_once("    let before_delegations =")
        .expect("main resolve source marker")
        .1
        .split_once("    let imported = client")
        .expect("main native-node source marker")
        .0;
    let denial_resolves = source
        .split_once("fn exercise_engine_denials")
        .expect("denial source marker")
        .1
        .split_once("fn runtime(")
        .expect("runtime source marker")
        .0;
    let presentation_constructor = source
        .split_once("fn signed_presentation")
        .expect("presentation source marker")
        .1
        .split_once("fn enrollment_status")
        .expect("enrollment source marker")
        .0;
    let verifier_adapter = source
        .split_once("impl EvidenceVerifier for FixtureTimeVerifier")
        .expect("fixture verifier source marker")
        .1
        .split_once("#[tokio::test]")
        .expect("integration test source marker")
        .0;
    let fixture_time_constructor = source
        .split_once("fn fixture_verification_time")
        .expect("fixture time source marker")
        .1
        .split_once("async fn observe_grant_output_on_real_node")
        .expect("source guard marker")
        .0;
    let ambient_independence_guard = source
        .split_once("fn evidence_verification_uses_fixture_time_under_hostile_ambient")
        .expect("ambient independence source marker")
        .1
        .split_once("fn evidence_verification_path_rejects_direct_wall_clock_reads")
        .expect("source guard function marker")
        .0;

    for evidence_path in [
        setup_and_resolve,
        denial_resolves,
        presentation_constructor,
        verifier_adapter,
        fixture_time_constructor,
        ambient_independence_guard,
    ] {
        for prohibited in ["Utc::now", "SystemTime::now", "Local::now"] {
            assert!(
                !evidence_path.contains(prohibited),
                "evidence-verification path contains direct wall-clock read {prohibited}"
            );
        }
    }
}

fn fixture_sd_jwt_issuer(source: &str) -> Result<String> {
    let fixture: Value = serde_json::from_str(source)?;
    let sd_jwt = fixture["evidencePresentation"]["sdJwt"]
        .as_str()
        .context("fixture SD-JWT")?;
    let compact_jwt = sd_jwt.split('~').next().context("fixture compact JWT")?;
    let payload = compact_jwt
        .split('.')
        .nth(1)
        .context("fixture compact JWT payload")?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    claims["iss"]
        .as_str()
        .map(ToOwned::to_owned)
        .context("fixture credential issuer")
}

fn mounted_code(code: &str) -> Result<String> {
    let matrix: Value = serde_json::from_str(DENIAL_MATRIX)?;
    matrix
        .as_array()
        .context("denial matrix array")?
        .iter()
        .find(|row| row["code"] == code && row["reachability"] == "mounted-runtime")
        .and_then(|row| row["code"].as_str())
        .map(ToOwned::to_owned)
        .with_context(|| format!("mounted-runtime conformance row for {code}"))
}

fn assert_runtime_code(error: &RuntimeError, code: &str) -> Result<()> {
    let expected = mounted_code(code)?;
    let observed = match error {
        RuntimeError::Presentation(code)
        | RuntimeError::HolderBinding(code)
        | RuntimeError::Evidence(code) => code.as_str(),
        _ => error.as_str(),
    };
    assert_eq!(
        observed, expected,
        "operation returned a different mounted-runtime code"
    );
    Ok(())
}

fn placeholder_signature(signer: &str) -> Signature {
    Signature {
        suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
        signer_did: signer.to_string(),
        value: String::new(),
    }
}

fn node_identity(jwk: &JWK) -> Result<(String, String)> {
    let did = DID_METHODS.generate(jwk, "key")?.to_string();
    let fragment = did.rsplit_once(':').context("missing did:key fragment")?.1;
    Ok((did.clone(), format!("{did}#{fragment}")))
}

fn signing_key(jwk: &JWK) -> Result<SigningKey> {
    let Params::OKP(params) = &jwk.params else {
        anyhow::bail!("expected Ed25519 OKP key");
    };
    let private = params.private_key.as_ref().context("missing private key")?;
    let bytes: [u8; 32] = private
        .0
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("unexpected private key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
