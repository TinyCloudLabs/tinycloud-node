use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::io::AsyncWriteExt;
use k256::ecdsa::SigningKey;
use rocket::{
    fairing::AdHoc,
    figment::{
        providers::{Format, Serialized, Toml},
        Figment,
    },
    Build, Rocket,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    str::FromStr,
};
use tempfile::TempDir;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{
    authorization::{make_invocation, InvocationOptions, TinyCloudDelegation},
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    resource::{Path as ResourcePath, Service, SpaceId},
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
        ucan::Payload,
    },
};
use tinycloud_core::{
    events::{Delegation, Invocation},
    policy_capability::{
        jcs::canonicalize, parse as parse_capability, requested_capabilities_hash_hex,
    },
    storage::{HashBuffer, ImmutableStaging},
    types::Metadata,
};
use tinycloud_node::{app, config::Config, BlockStage, TinyCloud};

const TARGET_ORIGIN: &str = "https://node.example";
const NODE_AUDIENCE: &str = "did:web:node.example";
const RETURN_ORIGIN: &str = "https://share.tinycloud.xyz";
const INVITATION_KID: &str = "did:web:node.example#invitation-key-1";
const ISSUER_DID: &str = "did:web:issuer.credentials.org";
const ISSUER_KID: &str = "did:web:issuer.credentials.org#email-signing-key-1";
const DEFAULT_ISSUER_KEY: &str = "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY";
const SPACE: &str = "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7";
const ROOT_DOMAIN: &[u8] = b"xyz.tinycloud.policy/enforcement-delegation/v1\0";

#[derive(Clone)]
struct Case {
    kind: &'static str,
    source: Value,
    policy: Value,
    policy_cid: String,
    delegation_cid: String,
    authority: Value,
    authority_digest: String,
    expires_at: String,
    content: &'static str,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn sha256_b64(bytes: &[u8]) -> String {
    b64(&Sha256::digest(bytes))
}
fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn cid(codec: u64, hash: Code, bytes: &[u8]) -> String {
    Cid::new_v1(codec, hash.digest(bytes)).to_string()
}
fn value_bytes(value: &Value) -> Vec<u8> {
    canonicalize(value)
}
fn canonical_time(value: OffsetDateTime) -> String {
    value
        .replace_nanosecond(0)
        .expect("valid timestamp")
        .format(&Rfc3339)
        .expect("UTC formatting")
}
fn millis_time(value: OffsetDateTime) -> String {
    value
        .replace_nanosecond(0)
        .expect("valid timestamp")
        .format(&Rfc3339)
        .expect("UTC formatting")
        .replace('Z', ".000Z")
}

fn ed_key(seed: [u8; 32]) -> tinycloud_core::libp2p::identity::Keypair {
    let secret = tinycloud_core::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed)
        .expect("ed25519 seed");
    tinycloud_core::libp2p::identity::ed25519::Keypair::from(secret).into()
}

fn did_key(key: &tinycloud_core::libp2p::identity::Keypair) -> String {
    tinycloud_core::keys::public_key_to_did_key(key.public())
}

fn canonical_kid(did: &str) -> String {
    format!("{did}#{}", did.strip_prefix("did:key:").unwrap_or(did))
}

fn signed_wrapper(
    name: &str,
    domain: &[u8],
    message: Value,
    key: &tinycloud_core::libp2p::identity::Keypair,
    signer: &str,
) -> Value {
    let jcs = value_bytes(&message);
    let mut signed = domain.to_vec();
    signed.extend_from_slice(&jcs);
    let signature = key.sign(&signed).expect("ed25519 signature");
    json!({
        "name": name,
        "domain": String::from_utf8(domain.to_vec()).expect("domain"),
        "signerDid": signer,
        "message": message,
        "jcs": String::from_utf8(jcs.clone()).expect("jcs"),
        "messageDigest": sha256_b64(&jcs),
        "signedBytesDigest": sha256_b64(&signed),
        "signatureDigest": sha256_b64(&signature),
        "signature": {"alg": "EdDSA", "kid": canonical_kid(signer), "value": b64(&signature)}
    })
}

fn owner_did(seed: &[u8; 32]) -> String {
    let signing = SigningKey::from_bytes(seed.into()).expect("owner key");
    let point = signing.verifying_key().to_encoded_point(false);
    let address = Keccak256::digest(&point.as_bytes()[1..]);
    format!("did:pkh:eip155:1:0x{}", hex(&address[12..]))
}

#[allow(clippy::too_many_arguments)]
fn signed_parent(
    role: &str,
    audience: &str,
    capabilities: &[Value],
    facts: &BTreeMap<String, String>,
    owner: &[u8; 32],
    issuer: &str,
    not_before: &str,
    expires_at: &str,
) -> Result<Value> {
    let mut unsigned = Map::new();
    unsigned.insert(
        "schema".into(),
        json!("xyz.tinycloud.policy/enforcement-delegation/v1"),
    );
    unsigned.insert("role".into(), json!(role));
    unsigned.insert("issuerDid".into(), json!(issuer));
    unsigned.insert("audienceDid".into(), json!(audience));
    unsigned.insert("capabilities".into(), Value::Array(capabilities.to_vec()));
    unsigned.insert("proofCids".into(), json!([]));
    unsigned.insert("notBefore".into(), json!(not_before));
    unsigned.insert("expiresAt".into(), json!(expires_at));
    unsigned.insert(
        "delegationMode".into(),
        json!(if role == "policy-authority" {
            "policy-source"
        } else {
            "conditional-mint"
        }),
    );
    unsigned.insert("facts".into(), serde_json::to_value(facts)?);
    let unsigned_value = Value::Object(unsigned);
    let unsigned_bytes = value_bytes(&unsigned_value);
    let digest = Sha256::digest([ROOT_DOMAIN, unsigned_bytes.as_slice()].concat());
    let preimage = [
        b"\\x19Ethereum Signed Message:\\n32".as_slice(),
        digest.as_ref(),
    ]
    .concat();
    let hash = Keccak256::digest(preimage);
    let signing = SigningKey::from_bytes(owner.into()).expect("owner key");
    let (signature, recovery) = signing
        .sign_prehash_recoverable(&hash)
        .map_err(|error| anyhow::anyhow!("parent signing: {error}"))?;
    let mut signature_bytes = signature.to_bytes().to_vec();
    signature_bytes.push(recovery.to_byte());
    let signature_value = b64(&signature_bytes);
    let mut artifact = match unsigned_value {
        Value::Object(object) => object,
        _ => unreachable!(),
    };
    artifact.insert(
        "signature".into(),
        json!({"suite":"eip191-secp256k1-sha256-jcs-v1","value":signature_value}),
    );
    let artifact_value = Value::Object(artifact);
    let artifact_bytes = value_bytes(&artifact_value);
    let delegation_cid = cid(0x55, Code::Blake3_256, &artifact_bytes);
    let mut final_object = artifact_value.as_object().cloned().expect("parent object");
    final_object.insert("delegationCid".into(), json!(delegation_cid));
    Ok(Value::Object(final_object))
}

fn status(
    parent_cid: &str,
    now: &str,
    fresh_until: &str,
    signer: &tinycloud_core::libp2p::identity::Keypair,
    signer_did: &str,
) -> Value {
    let message = json!({"type":"TinyCloudShareAuthorityStatusObservation","version":1,"parentCid":parent_cid,"state":"active","sequence":1,"checkedAt":now,"freshUntil":fresh_until,"revokedAt":null,"signerKid":canonical_kid(signer_did),"signerVersion":1});
    let mut bytes = value_bytes(&message);
    let mut signed = b"xyz.tinycloud.share/authority-status/v1\0".to_vec();
    signed.append(&mut bytes);
    let signature = signer.sign(&signed).expect("status signature");
    let mut object = message.as_object().cloned().expect("status");
    object.insert(
        "signature".into(),
        json!({"alg":"EdDSA","kid":canonical_kid(signer_did),"value":b64(&signature)}),
    );
    Value::Object(object)
}

fn attestation(
    enrollment: &Value,
    enforcer_did: &str,
    expires_at: &str,
    signer: &tinycloud_core::libp2p::identity::Keypair,
) -> Value {
    let message = json!({
        "type":"PolicyEnforcerAttestation","version":1,"targetOrigin":TARGET_ORIGIN,"nodeAudience":NODE_AUDIENCE,
        "enforcerDid":enforcer_did,"enforcerKid":"did:web:node.example#enforcement-key-1","publicKey":enrollment["invitationPublicKey"],"keyVersion":1,
        "localSignerDid":enforcer_did,"localSignerKid":canonical_kid(enforcer_did),"measurement":"tinycloud-node-n4-mounted-fixture-v1",
        "measurementDigest":sha256_b64(&value_bytes(&json!({"measurement":"tinycloud-node-n4-mounted-fixture-v1"}))),"expiresAt":expires_at,
        "enrollmentDigest":sha256_b64(&value_bytes(enrollment))
    });
    let mut signed = b"xyz.tinycloud.share/enrollment-attestation/v1\0".to_vec();
    signed.extend_from_slice(&value_bytes(&message));
    let signature = signer.sign(&signed).expect("attestation signature");
    let mut object = message.as_object().cloned().expect("attestation");
    object.insert(
        "signature".into(),
        json!({"alg":"EdDSA","kid":canonical_kid(enforcer_did),"value":b64(&signature)}),
    );
    Value::Object(object)
}

fn build_case(
    kind: &'static str,
    sender: &tinycloud_core::libp2p::identity::Keypair,
    node: &tinycloud_core::libp2p::identity::Keypair,
    now: OffsetDateTime,
) -> Result<Case> {
    let sender_did = did_key(sender);
    let node_did = did_key(node);
    let owner_seed = [0x55u8; 32];
    let owner = owner_did(&owner_seed);
    let expires_at = millis_time(now + time::Duration::hours(1));
    let source = if kind == "kv" {
        json!({"kind":"kv","space":SPACE,"path":"documents/plan.md","action":"tinycloud.kv/get"})
    } else {
        let arguments = json!({"document_id":123});
        json!({"kind":"sql","space":SPACE,"database":"documents","path":"shared/plan","statement":"shared_document_by_id","arguments":arguments,"argumentsDigest":sha256_b64(&value_bytes(&arguments)),"action":"tinycloud.sql/read"})
    };
    let source_digest = sha256_b64(&value_bytes(&source));
    let policy = json!({"type":"TinyCloudSharePolicy","version":1,"recipientEmail":"Alice+Notes@example.com","contentSource":source,"contentSourceDigest":source_digest,"action":source["action"],"resource":source["path"],"expiresAt":expires_at,"issuerDid":sender_did});
    let policy_bytes = value_bytes(&policy);
    let policy_cid = cid(0x55, Code::Sha2_256, &policy_bytes);
    let delegation_cid = cid(
        0x55,
        Code::Sha2_256,
        format!("n4-mounted-delegation-{kind}").as_bytes(),
    );
    let capability = if kind == "kv" {
        json!({"service":"tinycloud.kv","space":SPACE,"path":"documents/plan.md","actions":["tinycloud.kv/get"]})
    } else {
        json!({"service":"tinycloud.sql","space":SPACE,"path":"shared/plan","actions":["tinycloud.sql/read"],"caveats":{"mode":"constrained-statements","readOnly":true,"statements":[{"name":"shared_document_by_id","sql":"SELECT markdown FROM shared_documents WHERE document_id = ?","fixedParams":[{"index":1,"value":123}]}]}})
    };
    let parsed =
        parse_capability(&capability).map_err(|error| anyhow::anyhow!("capability: {error:?}"))?;
    let capability_hash = requested_capabilities_hash_hex(&[parsed]);
    let policy_digest = sha256_hex(&policy_bytes);
    let policy_id = format!("pol_n4-mounted-{kind}");
    let mut common = BTreeMap::new();
    common.insert("xyz.tinycloud.policy/ownerDid".into(), owner.clone());
    common.insert("xyz.tinycloud.policy/policyId".into(), policy_id.clone());
    common.insert(
        "xyz.tinycloud.policy/policyDigestHex".into(),
        policy_digest.clone(),
    );
    common.insert(
        "xyz.tinycloud.policy/capabilityCeilingHashHex".into(),
        capability_hash.clone(),
    );
    let mut enforcement = common.clone();
    enforcement.insert("xyz.tinycloud.policy/enforcerDid".into(), node_did.clone());
    enforcement.insert(
        "xyz.tinycloud.policy/nodeAudience".into(),
        NODE_AUDIENCE.into(),
    );
    enforcement.insert("xyz.tinycloud.policy/attestationBindingDigestHex".into(), sha256_b64(&value_bytes(&json!({"targetOrigin":TARGET_ORIGIN,"nodeAudience":NODE_AUDIENCE,"enforcerDid":node_did,"enforcerKid":"did:web:node.example#enforcement-key-1","keyVersion":1}))));
    enforcement.insert(
        "xyz.tinycloud.policy/maxSessionTtlSeconds".into(),
        "300".into(),
    );
    enforcement.insert(
        "xyz.tinycloud.policy/sessionMode".into(),
        "attenuable".into(),
    );
    enforcement.insert(
        "xyz.tinycloud.policy/maxRedelegationDepth".into(),
        "2".into(),
    );
    enforcement.insert(
        "xyz.tinycloud.policy/auditProfile".into(),
        "vp-digest-v1".into(),
    );
    let not_before = canonical_time(now - time::Duration::seconds(30));
    let parent_expires = canonical_time(now + time::Duration::hours(1));
    let authority_parent = signed_parent(
        "policy-authority",
        NODE_AUDIENCE,
        std::slice::from_ref(&capability),
        &common,
        &owner_seed,
        &owner,
        &not_before,
        &parent_expires,
    )?;
    let enforcement_parent = signed_parent(
        "policy-enforcement",
        &node_did,
        &[capability],
        &enforcement,
        &owner_seed,
        &owner,
        &not_before,
        &parent_expires,
    )?;
    let authority_parent_bytes = value_bytes(&authority_parent);
    let enforcement_parent_bytes = value_bytes(&enforcement_parent);
    tinycloud_core::policy_authority::AuthorityArtifactVerifier
        .verify(&authority_parent_bytes)
        .map_err(|error| anyhow::anyhow!("authority parent validation: {error:?}"))?;
    tinycloud_core::policy_authority::AuthorityArtifactVerifier
        .verify(&enforcement_parent_bytes)
        .map_err(|error| anyhow::anyhow!("enforcement parent validation: {error:?}"))?;
    let invitation_public = node
        .public()
        .try_into_ed25519()
        .expect("node key")
        .to_bytes();
    let enrollment = json!({"targetOrigin":TARGET_ORIGIN,"nodeAudience":NODE_AUDIENCE,"invitationKid":INVITATION_KID,"invitationPublicKey":b64(&invitation_public),"keyVersion":1,"enabled":true});
    let status_now = canonical_time(now);
    let status_fresh = canonical_time(now + time::Duration::seconds(240));
    let policy_parent_cid = authority_parent["delegationCid"].as_str().expect("cid");
    let enforcement_parent_cid = enforcement_parent["delegationCid"].as_str().expect("cid");
    let authority_status = status(
        policy_parent_cid,
        &status_now,
        &status_fresh,
        node,
        &node_did,
    );
    let enforcement_status = status(
        enforcement_parent_cid,
        &status_now,
        &status_fresh,
        node,
        &node_did,
    );
    let attestation = attestation(&enrollment, &node_did, &status_fresh, node);
    let authority = json!({"type":"TinyCloudShareAuthorityMaterial","version":1,"handle":format!("amh_{kind}_001"),"policyOwnerDid":owner,"senderDid":sender_did,"relationship":{"policyOwnerDid":owner,"senderDid":sender_did,"authenticated":true},"mapping":{"sharePolicyCid":policy_cid,"shareDelegationCid":delegation_cid,"policyAuthorityCid":policy_parent_cid,"policyEnforcementCid":enforcement_parent_cid},"policyAuthorityBytes":b64(&authority_parent_bytes),"policyAuthorityCid":policy_parent_cid,"policyEnforcementBytes":b64(&enforcement_parent_bytes),"policyEnforcementCid":enforcement_parent_cid,"statusObservations":[authority_status,enforcement_status],"enrollment":enrollment,"attestation":attestation});
    let authority_digest = sha256_b64(&value_bytes(&authority));
    Ok(Case {
        kind,
        source,
        policy,
        policy_cid,
        delegation_cid,
        authority,
        authority_digest,
        expires_at,
        content: if kind == "kv" {
            "# KV mounted plan\n"
        } else {
            "# SQL mounted plan\n"
        },
    })
}

fn descriptor(
    cases: &[Case],
    node: &tinycloud_core::libp2p::identity::Keypair,
    issuer_public: &str,
    url: &str,
) -> Value {
    let node_public = node
        .public()
        .try_into_ed25519()
        .expect("node key")
        .to_bytes();
    let sender_seed = [0x44u8; 32];
    let sender = ed_key(sender_seed);
    let case_values = cases.iter().map(|case| json!({
        "kind":case.kind,"source":case.source,"expectedContentSourceDigest":sha256_b64(&value_bytes(&case.source)),"expectedRecipientEmail":"Alice+Notes@example.com","expiresAt":case.expires_at,
        "policyCid":case.policy_cid,"delegationCid":case.delegation_cid,"authorityMaterialHandle":format!("amh_{}_001",case.kind),"authorityMaterialDigest":case.authority_digest,
        "policyOwnerDid":case.authority["policyOwnerDid"],"senderDid":case.authority["senderDid"],"senderPrivateKey":b64(&sender_seed),"delegation":format!("uCAESA.n4-mounted.{}",case.kind),"spaceId":SPACE,"documentName":"Project plan.md","senderTrust":"verified","authorityMaterial":case.authority,"targetOrigin":TARGET_ORIGIN,"nodeAudience":NODE_AUDIENCE,
        "trustedNode":{"targetOrigin":TARGET_ORIGIN,"nodeAudience":NODE_AUDIENCE,"invitationKid":INVITATION_KID,"invitationPublicKey":b64(&node_public),"keyVersion":1,"enabled":true},"expectedContent":case.content
    })).collect::<Vec<_>>();
    json!({"testOnly":true,"service":"tinycloud-node-n4-mounted-fixture","url":url,"healthUrl":format!("{url}/healthz"),"issuerDid":ISSUER_DID,"issuerKid":ISSUER_KID,"issuerPublicKey":issuer_public,"trustedNode":{"targetOrigin":TARGET_ORIGIN,"nodeAudience":NODE_AUDIENCE,"invitationKid":INVITATION_KID,"invitationPublicKey":b64(&node_public),"keyVersion":1,"enabled":true},"senderDid":did_key(&sender),"cases":case_values})
}

fn figment(
    datadir: &Path,
    secret: &[u8],
    material: &Path,
    issuer_public: &str,
    invitation_public: &str,
    invitation_private: &str,
    port: u16,
) -> Figment {
    let secret = b64(secret);
    let toml = format!(
        r#"
        address = "127.0.0.1"
        port = {port}
        [keys]
        type = "Static"
        secret = "{secret}"
        [storage]
        datadir = "{}"
        [share_email]
        enabled = true
        target_origin = "{TARGET_ORIGIN}"
        node_audience = "{NODE_AUDIENCE}"
        return_origin = "{RETURN_ORIGIN}"
        node_signing_kid = "{INVITATION_KID}"
        invitation_kid = "{INVITATION_KID}"
        invitation_public_key = "{invitation_public}"
        invitation_private_key = "{invitation_private}"
        issuer_did = "{ISSUER_DID}"
        issuer_kid = "{ISSUER_KID}"
        issuer_key_version = 1
        issuer_public_key = "{issuer_public}"
        authority_material_path = "{}"
        challenge_ttl_seconds = 120
        space_name = "documents"
    "#,
        datadir.display(),
        material.display()
    );
    rocket::Config::figment()
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::string(&toml))
}

async fn seed_sql(rocket: &Rocket<Build>) -> Result<()> {
    let space = SpaceId::from_str(
        "tinycloud:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7:documents",
    )?;
    let service = rocket
        .state::<tinycloud_core::sql::SqlService>()
        .context("SQL service missing")?;
    use tinycloud_core::sql::{SqlRequest, SqlValue};
    service.execute(&space, "documents", SqlRequest::Execute { sql: "CREATE TABLE IF NOT EXISTS shared_documents (document_id INTEGER PRIMARY KEY, markdown TEXT NOT NULL)".into(), params: vec![], schema: None }, None, "tinycloud.sql/write".into()).await.map_err(|error| anyhow::anyhow!("SQL schema seed: {error}"))?;
    service
        .execute(
            &space,
            "documents",
            SqlRequest::Execute {
                sql:
                    "INSERT OR REPLACE INTO shared_documents (document_id, markdown) VALUES (?, ?)"
                        .into(),
                params: vec![
                    SqlValue::Integer(123),
                    SqlValue::Text("# SQL mounted plan\n".into()),
                ],
                schema: None,
            },
            None,
            "tinycloud.sql/write".into(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("SQL row seed: {error}"))?;
    Ok(())
}

async fn seed_kv(rocket: &Rocket<Build>, seed: [u8; 32]) -> Result<()> {
    let space = SpaceId::from_str(
        "tinycloud:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7:documents",
    )?;
    let resource = space.clone().to_resource(
        "kv".parse::<Service>()?,
        Some("documents/plan.md".parse::<ResourcePath>()?),
        None,
        None,
    );
    let key = ed_key(seed);
    let jwk = JWK {
        public_key_use: None,
        key_operations: None,
        algorithm: Some(Algorithm::EdDSA),
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        params: Params::OKP(OctetParams {
            curve: "Ed25519".into(),
            public_key: Base64urlUInt(
                key.public()
                    .try_into_ed25519()
                    .expect("key")
                    .to_bytes()
                    .to_vec(),
            ),
            private_key: Some(Base64urlUInt(seed.to_vec())),
        }),
    };
    let mut verification_method = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = verification_method
        .rsplit_once(':')
        .context("generated DID fragment")?
        .1
        .to_owned();
    verification_method.push('#');
    verification_method.push_str(&fragment);
    let mut delegation_caps = tinycloud_auth::ucan_capabilities_object::Capabilities::<()>::new();
    let host_resource = space
        .clone()
        .to_resource("space".parse::<Service>()?, None, None, None);
    delegation_caps.with_actions(
        host_resource.as_uri(),
        std::iter::once(("tinycloud.space/host".parse()?, [])),
    );
    delegation_caps.with_actions(
        resource.clone().as_uri(),
        std::iter::once(("tinycloud.kv/put".parse()?, [])),
    );
    let delegation = Payload {
        issuer: verification_method.parse::<DIDURLBuf>()?,
        audience: verification_method
            .split('#')
            .next()
            .context("delegation audience")?
            .parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as f64,
        )?,
        nonce: Some("n4-mounted-kv-delegation".into()),
        facts: Some(Vec::<Value>::new()),
        proof: vec![],
        attenuation: delegation_caps,
    }
    .sign(Algorithm::EdDSA, &jwk)?;
    let delegation_event =
        Delegation::from_header_ser::<TinyCloudDelegation>(&delegation.encode()?)?;
    let delegation_cid = delegation_event.content_hash().to_cid(0x55);
    let tinycloud = rocket
        .state::<TinyCloud>()
        .context("TinyCloud state missing")?;
    tinycloud
        .delegate(delegation_event)
        .await
        .map_err(|error| anyhow::anyhow!("KV host delegation: {error}"))?;
    let invocation = make_invocation(
        vec![(resource, vec!["tinycloud.kv/put".parse()?])],
        &delegation_cid,
        &jwk,
        &verification_method,
        (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as f64,
        InvocationOptions::default(),
    )?;
    let invocation =
        Invocation::from_header_ser::<tinycloud_auth::authorization::TinyCloudInvocation>(
            &tinycloud_auth::authorization::HeaderEncode::encode(&invocation)?,
        )?;
    let staging = rocket.state::<BlockStage>().context("staging missing")?;
    let mut buffer: HashBuffer<_> = staging.stage(&space).await?;
    buffer.write_all(b"# KV mounted plan\n").await?;
    buffer.flush().await?;
    let mut inputs: std::collections::HashMap<
        (_, _),
        (
            Metadata,
            HashBuffer<<BlockStage as ImmutableStaging>::Writable>,
        ),
    > = std::collections::HashMap::new();
    inputs.insert(
        (space.clone(), "documents/plan.md".parse::<ResourcePath>()?),
        (Metadata(BTreeMap::new()), buffer),
    );
    tinycloud
        .invoke::<BlockStage>(invocation, inputs)
        .await
        .map_err(|error| anyhow::anyhow!("KV seed invocation: {error}"))?;
    Ok(())
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let descriptor_path = args
        .windows(2)
        .find(|pair| pair[0] == "--descriptor")
        .map(|pair| PathBuf::from(&pair[1]));
    let issuer_public = args
        .windows(2)
        .find(|pair| pair[0] == "--issuer-public-key")
        .map(|pair| pair[1].clone())
        .or_else(|| std::env::var("OPENCREDENTIALS_ISSUER_PUBLIC_KEY").ok())
        .unwrap_or_else(|| DEFAULT_ISSUER_KEY.into());
    let secret = args
        .windows(2)
        .find(|pair| pair[0] == "--keys-secret")
        .map(|pair| pair[1].clone())
        .or_else(|| std::env::var("TINYCLOUD_KEYS_SECRET").ok())
        .unwrap_or_else(|| b64(&[9u8; 32]));
    let secret = URL_SAFE_NO_PAD
        .decode(secret)
        .context("--keys-secret must be unpadded base64url")?;
    if secret.len() < 32 {
        bail!("--keys-secret must decode to at least 32 bytes");
    }
    let _node_secret = tinycloud_core::keys::StaticSecret::new(secret.clone())
        .map_err(|_| anyhow::anyhow!("invalid key secret"))?;
    let signing = [0x42u8; 32];
    let node = ed_key(signing);
    if let Some(expected) = args
        .windows(2)
        .find(|pair| pair[0] == "--invitation-public-key")
        .map(|pair| pair[1].as_str())
    {
        let actual = b64(&node
            .public()
            .try_into_ed25519()
            .expect("node key")
            .to_bytes());
        if actual != expected {
            bail!("derived invitation public key {actual} does not match --invitation-public-key {expected}; use the exact OpenCredentials enrollment key secret");
        }
    }
    let sender = ed_key([0x44; 32]);
    let now = OffsetDateTime::now_utc()
        .replace_second(0)
        .and_then(|value| value.replace_nanosecond(0))?;
    let cases = vec![
        build_case("kv", &sender, &node, now)?,
        build_case("sql", &sender, &node, now)?,
    ];
    let temp = TempDir::new().context("temporary fixture directory")?;
    let material_path = temp.path().join("authority-material.json");
    let records = cases.iter().map(|case| {
        let sender_did = case.authority["senderDid"].as_str().expect("sender");
        let sender_key = ed_key([0x44; 32]);
        json!({"authorityMaterial":signed_wrapper("authorityMaterial", b"xyz.tinycloud.share/authority-material-bundle/v1\0", case.authority.clone(), &sender_key, sender_did),"policy":signed_wrapper("policy", b"xyz.tinycloud.share/policy/v1\0", case.policy.clone(), &sender_key, sender_did)})
    }).collect::<Vec<_>>();
    let material_json = json!({"records":records});
    fs::write(&material_path, serde_json::to_vec(&material_json)?)
        .context("authority material write")?;
    tinycloud_core::share_email::AuthenticatedAuthorityMaterialProvider::from_path(&material_path)
        .map_err(|error| anyhow::anyhow!("generated authority material validation: {error:?}"))?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("reserve ephemeral local port")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let invitation_public = b64(&node
        .public()
        .try_into_ed25519()
        .expect("node key")
        .to_bytes());
    let figment = figment(
        temp.path(),
        &secret,
        &material_path,
        &issuer_public,
        &invitation_public,
        &b64(&signing),
        port,
    );
    let rocket = app(&figment)
        .await
        .context("production Rocket app composition")?;
    seed_sql(&rocket).await?;
    seed_kv(&rocket, [0x44; 32]).await?;
    let descriptor = descriptor(
        &cases,
        &node,
        &issuer_public,
        &format!("http://127.0.0.1:{port}"),
    );
    let descriptor_path_for_fairing = descriptor_path.clone();
    let descriptor_bytes = serde_json::to_vec_pretty(&descriptor)?;
    let rocket = rocket.attach(AdHoc::on_liftoff("n4-mounted-descriptor", move |_| {
        let descriptor_bytes = descriptor_bytes.clone();
        let descriptor_path = descriptor_path_for_fairing.clone();
        Box::pin(async move {
            if let Some(path) = descriptor_path {
                if let Err(error) = fs::write(&path, &descriptor_bytes) {
                    eprintln!("n4-mounted fixture descriptor write failed: {error}");
                }
            }
            println!("{}", String::from_utf8_lossy(&descriptor_bytes));
            eprintln!("tinycloud-node-n4-mounted-fixture listening on http://127.0.0.1:{port}");
        })
    }));
    rocket.launch().await.context("production Rocket launch")?;
    drop(temp);
    std::process::exit(0)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("tinycloud-node-n4-mounted-fixture: {error:#}");
        std::process::exit(1);
    }
}
