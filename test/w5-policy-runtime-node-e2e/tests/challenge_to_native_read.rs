use std::convert::TryInto;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use policy_core::{
    requested_capabilities_hash_hex, Audit, AuditIssuance, DelegationMode, DenialDisclosure,
    Disclosure, EvidenceAuthority, EvidenceExpression, EvidenceFreshness, EvidenceRequirement,
    GrantChallenge, GrantOutput, GrantPresentation, GrantTemplate, HolderBindingProof,
    HolderEnrollment, HolderEnrollmentDisposition, HolderEnrollmentStatus, Policy,
    PolicyCapability, PolicyDisposition, PolicyResource, PolicyStatus, PresentedEvidence,
    RevocationMode, Signature, SignatureSuite,
};
use policy_runtime::{
    EvidenceSatisfaction, EvidenceVerifier, GrantIssueRequest, GrantIssuer, PolicyRuntime,
    PolicySpaceState, PortableDelegation, RuntimeConfig, RuntimeError, RuntimeEvidenceContext,
};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::json;
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
    hash::Hash,
    models::{abilities, actor, delegation as deleg_model, revocation as revo_model, space},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database},
    sql::{SqlRequest, SqlService, SqlValue},
    types::{Ability, Caveats, Facts, Resource, SpaceIdWrap},
    util::DelegationMode as NodeDelegationMode,
};

const SUBJECT: &str = "did:key:z6Mkw5subject";
const ISSUED_AT: i64 = 1_800_000_000;
const POLICY_ID: &str = "pol_w5_email_domain";
const SPACE_NAME: &str = "w5-runtime-node";

struct RuntimeNodeGrantIssuer {
    issuer_did: String,
    delegation_hash: Hash,
    issued: Option<GrantIssueRequest>,
    revoked: Vec<String>,
}

impl RuntimeNodeGrantIssuer {
    fn new(issuer_did: String, delegation_hash: Hash) -> Self {
        Self {
            issuer_did,
            delegation_hash,
            issued: None,
            revoked: Vec::new(),
        }
    }

    fn delegation_id(&self) -> String {
        self.delegation_hash.to_cid(0x55).to_string()
    }
}

impl GrantIssuer for RuntimeNodeGrantIssuer {
    fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    fn issue(&mut self, request: GrantIssueRequest) -> Result<PortableDelegation, RuntimeError> {
        let delegation_id = self.delegation_id();
        let delegation = PortableDelegation {
            delegation_id: delegation_id.clone(),
            issuer_did: self.issuer_did.clone(),
            holder_did: request.holder_did.clone(),
            policy_id: request.policy.policy_id.clone(),
            capabilities: request.capabilities.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            terminal: request.terminal,
            encoded: format!("tinycloud-node-row:{delegation_id}"),
        };
        self.issued = Some(request);
        Ok(delegation)
    }

    fn revoke(&mut self, delegation_id: &str) -> Result<(), RuntimeError> {
        self.revoked.push(delegation_id.to_string());
        Ok(())
    }
}

struct AcceptEvidence;

impl EvidenceVerifier for AcceptEvidence {
    fn verify(
        &self,
        requirement: &policy_core::EvidenceRequirement,
        _presentation: &serde_json::Value,
        context: &RuntimeEvidenceContext,
    ) -> Result<EvidenceSatisfaction, RuntimeError> {
        Ok(EvidenceSatisfaction {
            evidence_ids: vec![requirement.requirement_id.clone()],
            valid_until: context.now + chrono::Duration::hours(1),
        })
    }
}

#[tokio::test]
async fn challenge_resolve_issued_delegation_native_read_then_cutoff_denies() -> Result<()> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let config_overlay = format!(
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
        .merge(Toml::string(&config_overlay));
    let rocket = tinycloud::app(&figment).await?;

    let sql_service = rocket
        .state::<SqlService>()
        .context("node app must manage SqlService")?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;

    let space_id = test_space_id(SPACE_NAME);
    let owner_did = space_id.did().to_string();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(&conn)
    .await?;

    sql_service
        .execute(
            &space_id,
            "main",
            SqlRequest::Execute {
                schema: Some(vec![
                    "CREATE TABLE labels (label TEXT PRIMARY KEY, val INTEGER NOT NULL)"
                        .to_string(),
                ]),
                sql: "INSERT INTO labels (label, val) VALUES (?, ?)".to_string(),
                params: vec![SqlValue::Text("alpha".to_string()), SqlValue::Integer(111)],
            },
            None,
            "tinycloud.sql/write".to_string(),
        )
        .await?;
    sql_service
        .execute(
            &space_id,
            "main",
            SqlRequest::Execute {
                schema: None,
                sql: "INSERT INTO labels (label, val) VALUES (?, ?)".to_string(),
                params: vec![SqlValue::Text("beta".to_string()), SqlValue::Integer(222)],
            },
            None,
            "tinycloud.sql/write".to_string(),
        )
        .await?;

    let mut holder_jwk = JWK::generate_ed25519()?;
    holder_jwk.algorithm = Some(Algorithm::EdDSA);
    let (holder_did, holder_verification_method) = node_verification_method(&holder_jwk)?;
    let holder_key = signing_key_from_node_jwk(&holder_jwk)?;

    for did in [&owner_did, &holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&conn)
        .await?;
    }

    let mut state = PolicySpaceState::default();
    state.insert_policy(policy(&space_id));
    state.insert_policy_status(active_status(&space_id))?;
    let delegation_hash = tinycloud_core::hash::hash(b"w5-runtime-node-delegation");
    let mut runtime = PolicyRuntime::new(
        RuntimeConfig {
            audience: "policy-engine:test".to_string(),
            challenge_ttl_seconds: 120,
            accepted_suites: vec![SignatureSuite::EddsaEd25519Sha256JcsV1],
            challenge_signature: placeholder_signature("did:key:z6Mkengine"),
        },
        state,
        AcceptEvidence,
        RuntimeNodeGrantIssuer::new("did:key:z6Mkpolicyengine".to_string(), delegation_hash),
    );

    let challenge = runtime.issue_challenge(POLICY_ID, now())?;
    let presentation = signed_presentation(&space_id, &challenge, &holder_did, &holder_key);
    let delegation = runtime.resolve(presentation, now())?;
    assert!(delegation.terminal);
    assert_eq!(delegation.holder_did, holder_did);

    let issued_request = runtime
        .grant_issuer()
        .issued
        .as_ref()
        .context("runtime must issue one grant")?
        .clone();
    persist_runtime_grant(
        &conn,
        delegation_hash,
        &issued_request,
        delegation.encoded.as_bytes().to_vec(),
    )
    .await?;

    let sql_resource = sql_resource(&space_id)?;
    let constrained_caveat = policy_capability(&space_id)
        .caveats
        .context("policy capability must carry SQL caveat")?;
    let mut invocation_caps = Capabilities::new();
    let mut invocation_nb = std::collections::BTreeMap::new();
    for (key, value) in constrained_caveat
        .as_object()
        .context("test caveat must be an object")?
    {
        invocation_nb.insert(key.clone(), value.clone());
    }
    invocation_caps.with_action(
        sql_resource.as_uri(),
        "tinycloud.sql/read".parse::<UcanAbility>()?,
        [invocation_nb],
    );
    let parent_cid: AuthCid = delegation_hash.to_cid(0x55);
    let invocation = Payload {
        issuer: holder_verification_method.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some("urn:uuid:00000000-0000-4000-8000-0000000000w5".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent_cid],
        attenuation: invocation_caps.clone(),
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), &holder_jwk)?;
    let auth_header = invocation.encode()?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&SqlRequest::ExecuteStatement {
            name: "get_val".to_string(),
            params: vec![],
        })?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "unexpected /invoke response: {body}");
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["rowCount"], 1);
    assert_eq!(json["rows"][0][0], 111);

    let revoked = runtime.active_cutoff_policy(POLICY_ID)?;
    assert_eq!(revoked, vec![delegation.delegation_id.clone()]);
    assert_eq!(
        runtime.grant_issuer().revoked,
        vec![delegation.delegation_id.clone()]
    );

    let revocation_hash = tinycloud_core::hash::hash(b"w5-runtime-node-revocation");
    revo_model::ActiveModel {
        id: Set(revocation_hash),
        revoker: Set(owner_did),
        revoked: Set(delegation_hash),
        serialization: Set(b"w5-runtime-node-revocation".to_vec()),
    }
    .insert(&conn)
    .await?;

    // The node's invocation replay guard rejects reused nonces, so the
    // post-revocation dispatch must carry a fresh nonce; only the nonce
    // differs from the first invocation.
    let post_revocation_invocation = Payload {
        issuer: holder_verification_method.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some("urn:uuid:00000000-0000-4000-8000-0000000001w5".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent_cid],
        attenuation: invocation_caps,
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), &holder_jwk)?;
    let post_revocation_auth_header = post_revocation_invocation.encode()?;

    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", post_revocation_auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&SqlRequest::ExecuteStatement {
            name: "get_val".to_string(),
            params: vec![],
        })?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Unauthorized,
        "active cutoff must block subsequent native read: {body}"
    );
    assert!(
        body.contains("delegation-revoked"),
        "expected delegation-revoked error body, got {body}"
    );

    Ok(())
}

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(ISSUED_AT + 60, 0).single().unwrap()
}

fn test_space_id(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

fn placeholder_signature(signer: &str) -> Signature {
    Signature {
        suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
        signer_did: signer.to_string(),
        value: "unused".to_string(),
    }
}

fn node_verification_method(jwk: &JWK) -> Result<(String, String)> {
    let did = DID_METHODS.generate(jwk, "key")?.to_string();
    let fragment = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    Ok((did.clone(), format!("{did}#{fragment}")))
}

fn signing_key_from_node_jwk(jwk: &JWK) -> Result<SigningKey> {
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

fn sql_resource(space: &SpaceId) -> Result<ResourceId> {
    Ok(space.clone().to_resource(
        "sql".parse::<Service>()?,
        Some("main".parse::<AuthPath>()?),
        None,
        None,
    ))
}

fn policy_capability(space: &SpaceId) -> PolicyCapability {
    policy_core::parse_policy_capability(&json!({
        "service": "tinycloud.sql",
        "space": space.did().to_string(),
        "path": "main",
        "actions": ["tinycloud.sql/read"],
        "caveats": {
            "mode": "constrained-statements",
            "readOnly": true,
            "statements": [{
                "name": "get_val",
                "sql": "SELECT val FROM labels WHERE label=?",
                "fixedParams": [{ "index": 0, "value": "alpha" }]
            }]
        }
    }))
    .unwrap()
}

fn policy(space: &SpaceId) -> Policy {
    Policy {
        schema: policy_core::POLICY_SCHEMA.to_string(),
        policy_id: POLICY_ID.to_string(),
        owner_did: space.did().to_string(),
        signing_key_did: "did:key:z6Mkpolicy".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        resource: PolicyResource {
            resource_type: "sql-label".to_string(),
            resource_id: "alpha".to_string(),
            permissions_ceiling: vec![policy_capability(space)],
        },
        when: policy_core::Expression::Evidence(EvidenceExpression {
            evidence: EvidenceRequirement {
                requirement_id: "email-domain".to_string(),
                verifier: "test.email-domain".to_string(),
                requirements: json!({
                    "emailDomains": ["tinycloud.xyz"]
                }),
                authority: Some(EvidenceAuthority {
                    profile: None,
                    accepted_issuers: None,
                    allow_owner_authorized_issuer: None,
                }),
                freshness: Some(EvidenceFreshness {
                    max_status_age_seconds: 365 * 24 * 60 * 60,
                }),
            },
        }),
        grant: GrantTemplate {
            output: GrantOutput::PortableDelegation,
            max_ttl_seconds: 3600,
            delegation_mode: DelegationMode::Terminal,
            revocation: RevocationMode::ActiveCutoff,
        },
        disclosure: Some(Disclosure {
            denial: DenialDisclosure::Code,
        }),
        audit: Some(Audit {
            issuance: AuditIssuance::Security,
        }),
        signature: placeholder_signature("did:key:z6Mkpolicy"),
    }
}

fn active_status(space: &SpaceId) -> PolicyStatus {
    PolicyStatus {
        schema: policy_core::POLICY_STATUS_SCHEMA.to_string(),
        status_id: "pstat_w5".to_string(),
        policy_id: POLICY_ID.to_string(),
        owner_did: space.did().to_string(),
        sequence: 1,
        disposition: PolicyDisposition::Active,
        effective_at: "2026-01-01T00:00:00Z".to_string(),
        reason_code: None,
        signing_key_did: "did:key:z6Mkpolicy".to_string(),
        signature: placeholder_signature("did:key:z6Mkpolicy"),
    }
}

fn enrollment(holder_did: &str) -> HolderEnrollment {
    HolderEnrollment {
        schema: policy_core::HOLDER_ENROLLMENT_SCHEMA.to_string(),
        enrollment_id: "henr_w5".to_string(),
        eligible_subject_did: SUBJECT.to_string(),
        holder_did: holder_did.to_string(),
        scope: None,
        not_before: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signing_key_did: SUBJECT.to_string(),
        signature: placeholder_signature(SUBJECT),
    }
}

fn enrollment_status() -> HolderEnrollmentStatus {
    HolderEnrollmentStatus {
        schema: policy_core::HOLDER_ENROLLMENT_STATUS_SCHEMA.to_string(),
        status_id: "henrst_w5".to_string(),
        enrollment_id: "henr_w5".to_string(),
        sequence: 1,
        disposition: HolderEnrollmentDisposition::Active,
        effective_at: "2026-01-01T00:00:00Z".to_string(),
        signing_key_did: SUBJECT.to_string(),
        signature: placeholder_signature(SUBJECT),
    }
}

fn signed_presentation(
    space: &SpaceId,
    challenge: &GrantChallenge,
    holder_did: &str,
    holder_key: &SigningKey,
) -> GrantPresentation {
    let caps = vec![policy_capability(space)];
    let mut presentation = GrantPresentation {
        schema: policy_core::GRANT_PRESENTATION_SCHEMA.to_string(),
        policy_id: POLICY_ID.to_string(),
        eligible_subject_did: SUBJECT.to_string(),
        holder_did: holder_did.to_string(),
        holder_binding: HolderBindingProof::EnrolledAgent {
            enrollment: enrollment(holder_did),
            status: Some(enrollment_status()),
        },
        requested_capabilities_hash: requested_capabilities_hash_hex(&caps),
        requested_capabilities: caps,
        audience: "policy-engine:test".to_string(),
        nonce: challenge.nonce.clone(),
        expires_at: (now() + chrono::Duration::minutes(30)).to_rfc3339(),
        evidence: Some(vec![PresentedEvidence {
            requirement_id: "email-domain".to_string(),
            presentation: json!({ "emailDomain": "tinycloud.xyz" }),
        }]),
        holder_signature: placeholder_signature(holder_did),
    };
    let digest =
        policy_core::signed_object::digest_grant_presentation(&presentation).expect("digest");
    presentation.holder_signature = Signature {
        suite: SignatureSuite::EddsaEd25519Sha256JcsV1,
        signer_did: holder_did.to_string(),
        value: URL_SAFE_NO_PAD.encode(holder_key.sign(&digest).to_bytes()),
    };
    presentation
}

async fn persist_runtime_grant(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    delegation_hash: Hash,
    request: &GrantIssueRequest,
    serialization: Vec<u8>,
) -> Result<()> {
    let mut facts = std::collections::BTreeMap::new();
    facts.insert(
        NodeDelegationMode::FACT_KEY.to_string(),
        serde_json::Value::String(NodeDelegationMode::Terminal.as_str().to_string()),
    );
    deleg_model::ActiveModel {
        id: Set(delegation_hash),
        delegator: Set(request.policy.owner_did.clone()),
        delegatee: Set(request.holder_did.clone()),
        expiry: Set(Some(time::OffsetDateTime::from_unix_timestamp(
            request.expires_at.timestamp(),
        )?)),
        issued_at: Set(Some(time::OffsetDateTime::from_unix_timestamp(
            request.issued_at.timestamp(),
        )?)),
        not_before: Set(None),
        facts: Set(Some(Facts(facts))),
        serialization: Set(serialization),
    }
    .insert(conn)
    .await?;

    for capability in &request.capabilities {
        let service = match capability.service.as_str() {
            "tinycloud.sql" => "sql",
            other => anyhow::bail!("unsupported service in test: {other}"),
        }
        .parse::<Service>()?;
        let path = capability.path.parse::<AuthPath>()?;
        let space = SpaceId::new(
            request.policy.owner_did.parse::<DIDBuf>()?,
            SPACE_NAME.parse()?,
        );
        let resource_id: ResourceId = space.to_resource(service, Some(path), None, None);
        let mut caveats = std::collections::BTreeMap::new();
        if let Some(caveat) = &capability.caveats {
            caveats.insert("0".to_string(), caveat.clone());
        }
        for action in &capability.actions {
            abilities::ActiveModel {
                delegation: Set(delegation_hash),
                resource: Set(Resource::TinyCloud(resource_id.clone())),
                ability: Set(Ability::try_from(action.clone()).unwrap()),
                caveats: Set(Caveats(caveats.clone())),
            }
            .insert(conn)
            .await?;
        }
    }

    Ok(())
}
