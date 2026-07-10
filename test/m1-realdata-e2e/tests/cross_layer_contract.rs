use std::{collections::BTreeMap, convert::TryInto};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
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
use policy_evidence_vc::VcEvidenceVerifier;
use policy_runtime::{
    GrantIssueRequest, GrantIssuer, PolicyRuntime, PolicySpaceState, PortableDelegation,
    RuntimeConfig, RuntimeError,
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
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database, EntityTrait,
        PaginatorTrait, QueryFilter,
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

const VALID_FIXTURE: &str = include_str!("../vendor/launch-credential-denials/baseline-valid.json");
const EXPIRED_FIXTURE: &str = include_str!("../vendor/launch-credential-denials/expired.json");
const UNTRUSTED_FIXTURE: &str =
    include_str!("../vendor/launch-credential-denials/untrusted-issuer-did.json");
const DENIAL_MATRIX: &str =
    include_str!("../vendor/policy-engine-conformance/denial-matrix-v0.json");

#[derive(Clone)]
struct NodeGrantIssuer {
    owner_jwk: JWK,
    owner_vm: String,
    owner_did: String,
    space: SpaceId,
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

#[tokio::test]
async fn deterministic_cross_layer_contract_is_observed_from_real_operations() -> Result<()> {
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
    let sql_service = rocket
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
    let now = Utc::now();
    let mut runtime = runtime(
        policy.clone(),
        active_status.clone(),
        trusted_verifier(),
        NodeGrantIssuer {
            owner_jwk: owner_jwk.clone(),
            owner_vm: owner_vm.clone(),
            owner_did: owner_did.clone(),
            space: space_id.clone(),
        },
    )?;
    let challenge = runtime.issue_challenge(&policy.policy_id, now)?;
    let valid_evidence = fixture_evidence(VALID_FIXTURE)?;
    let presentation = signed_presentation(
        &policy,
        &challenge,
        &holder_did,
        &holder_signing_key,
        valid_evidence,
        AUDIENCE,
        1,
    )?;
    let replay_presentation = presentation.clone();
    let issued = runtime.resolve(presentation, now)?;

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

    let client = Client::tracked(rocket).await?;
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

    let replay_error = runtime.resolve(replay_presentation, now).unwrap_err();
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
    let now = Utc::now();

    let mut audience_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        trusted_verifier(),
        issuer(),
    )?;
    let challenge = audience_runtime.issue_challenge(&policy.policy_id, now)?;
    let mismatched = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(VALID_FIXTURE)?,
        "policy-engine:wrong-audience",
        1,
    )?;
    let audience_error = audience_runtime.resolve(mismatched, now).unwrap_err();
    assert_runtime_code(&audience_error, "presentation-audience-mismatch")?;

    let mut expired_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        trusted_verifier(),
        issuer(),
    )?;
    let challenge = expired_runtime.issue_challenge(&policy.policy_id, now)?;
    let expired = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(EXPIRED_FIXTURE)?,
        AUDIENCE,
        1,
    )?;
    let expired_error = expired_runtime.resolve(expired, now).unwrap_err();
    assert_runtime_code(&expired_error, "evidence-credential-invalid")?;

    let mut untrusted_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        untrusted_verifier(),
        issuer(),
    )?;
    let challenge = untrusted_runtime.issue_challenge(&policy.policy_id, now)?;
    let untrusted = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(UNTRUSTED_FIXTURE)?,
        AUDIENCE,
        1,
    )?;
    let untrusted_error = untrusted_runtime.resolve(untrusted, now).unwrap_err();
    assert_runtime_code(&untrusted_error, "evidence-issuer-untrusted")?;

    let mut inactive_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        trusted_verifier(),
        issuer(),
    )?;
    let challenge = inactive_runtime.issue_challenge(&policy.policy_id, now)?;
    let pending = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(VALID_FIXTURE)?,
        AUDIENCE,
        1,
    )?;
    let policy_key = signing_key(owner_jwk)?;
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
    let inactive_error = inactive_runtime.resolve(pending, now).unwrap_err();
    assert_runtime_code(&inactive_error, "policy-inactive")?;

    let mut compromised_runtime = runtime(
        (*policy).clone(),
        (*active_status).clone(),
        trusted_verifier(),
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
    let challenge = compromised_runtime.issue_challenge(&policy.policy_id, now)?;
    let compromised = signed_presentation(
        policy,
        &challenge,
        holder_did,
        holder_key,
        fixture_evidence(VALID_FIXTURE)?,
        AUDIENCE,
        3,
    )?;
    let compromised_error = compromised_runtime.resolve(compromised, now).unwrap_err();
    assert_runtime_code(&compromised_error, "enrollment-revoked-irreversible")?;

    Ok(())
}

fn runtime(
    policy: Policy,
    status: PolicyStatus,
    verifier: VcEvidenceVerifier,
    issuer: NodeGrantIssuer,
) -> Result<PolicyRuntime<NodeGrantIssuer, VcEvidenceVerifier>> {
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

fn policy(space: &SpaceId, signer_did: &str) -> Policy {
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
                    accepted_issuers: Some(vec![ISSUER.to_string()]),
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
        effective_at: Utc::now().to_rfc3339(),
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

fn signed_presentation(
    policy: &Policy,
    challenge: &GrantChallenge,
    holder_did: &str,
    holder_key: &SigningKey,
    evidence: Value,
    audience: &str,
    enrollment_sequence: u64,
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
        expires_at: (Utc::now() + Duration::minutes(5)).to_rfc3339(),
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
        effective_at: Utc::now().to_rfc3339(),
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
    let observed = error.to_string();
    assert!(
        observed.contains(&expected),
        "operation returned {observed:?}, expected mounted-runtime code {expected:?}"
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
