use super::*;
use tinycloud_auth::{
    authorization::{make_invocation, InvocationOptions},
    resolver::DID_METHODS,
    siwe_recap::Ability as UcanAbility,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    models::{actor, key_revocation, space},
    types::{Ability, Caveats, SpaceIdWrap},
};

// Registration and challenge/session creation closed September 30. The
// signed synthetic policy and delegation are inserted as a reconstruction of
// a historically registered policy, not sent to today's closed creation
// route. Reads remain open until January 5; new challenge/mint requests
// continue returning 410. A real pre-cutoff five-minute session cannot still
// be live today, so its short-lived signed binding is reconstructed separately.
struct HistoricalShare {
    challenge: Value,
    session_id: String,
    sender: JWK,
    sender_did: String,
    sender_vm: String,
    sender_delegation_cid: tinycloud_auth::ipld_core::cid::Cid,
    holder: Ed25519InvitationSigner,
    registered: RegisteredPolicy,
}

fn owner_identity() -> (JWK, String, String) {
    let owner = JWK::generate_ed25519().expect("owner Ed25519 key");
    let did = DID_METHODS
        .generate(&owner, "key")
        .expect("owner DID")
        .to_string();
    let vm = canonical_did_key_kid(&did);
    (owner, did, vm)
}

async fn historical_share(
    runtime: &ShareV2Runtime,
    owner: &JWK,
    owner_did: &str,
    owner_vm: &str,
    share_id: &str,
) -> HistoricalShare {
    let (share_key, share_did) = tamper_keypair_and_did();
    let (holder, holder_did) = tamper_keypair_and_did();
    let (mut sender, sender_did, sender_vm) = owner_identity();
    sender.algorithm = Some(Algorithm::EdDSA);
    let path = format!("shares/{share_id}");
    let space_id = tinycloud_auth::resource::SpaceId::new(
        owner_did.parse::<DIDBuf>().expect("owner DID"),
        "applications".parse().expect("space name"),
    );
    let space_id_string = space_id.to_string();
    let expires_at = "2026-12-28T00:00:00.000Z".to_owned();
    let actions = vec![
        "tinycloud.kv/get".to_owned(),
        "tinycloud.kv/list".to_owned(),
    ];
    let service = "kv".parse().expect("kv service");
    let resource_path = path.parse().expect("resource path");
    let resource = space_id.to_resource(service, Some(resource_path), None, None);
    let mut capabilities = Capabilities::new();
    for action in &actions {
        capabilities.with_action(
            resource.as_uri(),
            action.parse::<UcanAbility>().expect("UCAN action"),
            [std::collections::BTreeMap::<String, Value>::new()],
        );
    }
    let owner_ucan = Payload {
        issuer: owner_vm
            .parse::<DIDURLBuf>()
            .expect("owner verification method"),
        audience: share_did.parse::<DIDBuf>().expect("share DID"),
        not_before: None,
        expiration: NumericDate::try_from_seconds(1_798_416_000.0).expect("December 2026"),
        nonce: Some(format!("historical-{share_id}")),
        facts: Some(Vec::<Value>::new()),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(Algorithm::EdDSA, owner)
    .expect("signed owner delegation")
    .encode()
    .expect("encoded owner delegation")
    .into_bytes();
    let owner_cid = raw_blake3_cid(&owner_ucan);
    let owner_id: tinycloud_core::hash::Hash = owner_cid
        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
        .expect("owner CID")
        .into();
    actor::ActiveModel {
        id: Set(share_did.clone()),
    }
    .insert(&runtime.conn)
    .await
    .expect("share-key actor");
    delegation::ActiveModel {
        id: Set(owner_id),
        delegator: Set(owner_did.to_owned()),
        delegatee: Set(share_did.clone()),
        expiry: Set(Some(OffsetDateTime::parse(&expires_at, &Rfc3339).unwrap())),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(runtime.policy_encryption.encrypt(&owner_ucan)),
    }
    .insert(&runtime.conn)
    .await
    .expect("historical signed owner delegation row");
    for action in &actions {
        abilities::ActiveModel {
            resource: Set(Resource::TinyCloud(resource.clone())),
            ability: Set(Ability::try_from(action.clone()).expect("stored ability")),
            delegation: Set(owner_id),
            caveats: Set(Caveats(Default::default())),
        }
        .insert(&runtime.conn)
        .await
        .expect("owner ability row");
    }
    // A separate owner-signed grant gives the sender exactly one ordinary
    // capability for the delivery route's authenticated invocation.
    let mut sender_capabilities = Capabilities::new();
    sender_capabilities.with_action(
        resource.as_uri(),
        "tinycloud.kv/get".parse::<UcanAbility>().unwrap(),
        [std::collections::BTreeMap::<String, Value>::new()],
    );
    let sender_ucan = Payload {
        issuer: owner_vm.parse::<DIDURLBuf>().unwrap(),
        audience: sender_did.parse::<DIDBuf>().unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds(1_798_416_000.0).unwrap(),
        nonce: Some(format!("historical-sender-{share_id}")),
        facts: Some(Vec::<Value>::new()),
        proof: vec![],
        attenuation: sender_capabilities,
    }
    .sign(Algorithm::EdDSA, owner)
    .expect("signed sender grant")
    .encode()
    .expect("encoded sender grant")
    .into_bytes();
    let sender_delegation_cid: tinycloud_auth::ipld_core::cid::Cid =
        raw_blake3_cid(&sender_ucan).parse().expect("sender CID");
    actor::ActiveModel {
        id: Set(sender_did.clone()),
    }
    .insert(&runtime.conn)
    .await
    .expect("sender actor");
    delegation::ActiveModel {
        id: Set(sender_delegation_cid.into()),
        delegator: Set(owner_did.to_owned()),
        delegatee: Set(sender_did.clone()),
        expiry: Set(Some(OffsetDateTime::parse(&expires_at, &Rfc3339).unwrap())),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(runtime.policy_encryption.encrypt(&sender_ucan)),
    }
    .insert(&runtime.conn)
    .await
    .expect("historical signed sender grant row");
    abilities::ActiveModel {
        resource: Set(Resource::TinyCloud(resource.clone())),
        ability: Set(Ability::try_from("tinycloud.kv/get".to_owned()).unwrap()),
        delegation: Set(sender_delegation_cid.into()),
        caveats: Set(Caveats(Default::default())),
    }
    .insert(&runtime.conn)
    .await
    .expect("sender ability row");
    let source = serde_json::json!({
        "kind": "kv", "space": space_id_string, "path": path, "action": "tinycloud.kv/get"
    });
    let source_digest = b64_digest(&jcs::canonicalize(&source));
    let policy = serde_json::json!({
        "domain": POLICY_DOMAIN,
        "policy": {
            "type": "TinyCloudSharePolicy", "version": 2,
            "shareId": share_id, "ownerDid": owner_did, "shareKeyDid": share_did,
            "recipientMatcher": {"kind": "exactEmail", "value": "alice@example.com"},
            "target": {"origin": runtime.config.target_origin, "nodeAudience": runtime.config.node_audience,
                "enforcerDid": runtime.enforcer_did, "spaceId": space_id_string},
            "resource": {"kind": "prefix", "path": path},
            "actions": actions, "contentSource": source,
            "contentSourceDigest": source_digest, "ownerDelegationCid": owner_cid,
            "expiresAt": expires_at
        }
    });
    let policy_bytes = jcs::canonicalize(&policy);
    let policy_cid = raw_sha256_cid(&policy_bytes);
    let policy_proof = encode_config(
        share_key.sign(&policy_bytes).expect("policy signed"),
        URL_SAFE_NO_PAD,
    );
    let facts: EnforcementFacts = serde_json::from_value(serde_json::json!({
        "ownerDelegationCid": owner_cid, "policyCid": policy_cid, "shareId": share_id,
        "shareKeyDid": share_did, "enforcerDid": runtime.enforcer_did,
        "nodeAudience": runtime.config.node_audience, "spaceId": space_id_string,
        "path": path, "actions": actions, "contentSourceDigest": source_digest,
        "expiresAt": expires_at
    }))
    .expect("enforcement facts");
    let enforcement_wire = serde_json::json!({
        "domain": ENFORCEMENT_DOMAIN,
        "unsigned": {"type": "TinyCloudSharePolicyEnforcement", "version": 2,
            "issuerDid": share_did, "audienceDid": runtime.enforcer_did, "facts": facts}
    });
    let enforcement_bytes =
        serde_ipld_dagcbor::to_vec(&enforcement_wire).expect("canonical DAG-CBOR");
    let enforcement = EnforcementDelegationInput {
        cid: raw_sha256_cid(&enforcement_bytes),
        dag_cbor: encode_config(&enforcement_bytes, URL_SAFE_NO_PAD),
        issuer_did: share_did.clone(),
        audience_did: runtime.enforcer_did.clone(),
        facts,
        signature: encode_config(
            share_key
                .sign(&enforcement_bytes)
                .expect("enforcement signed"),
            URL_SAFE_NO_PAD,
        ),
    };
    let matcher = &policy["policy"]["recipientMatcher"];
    let registration = Registration {
        registration_cid: String::new(),
        policy_cid: policy_cid.clone(),
        owner_delegation_cid: owner_cid.clone(),
        enforcement_delegation_cid: enforcement.cid.clone(),
        owner_did: owner_did.to_owned(),
        share_key_did: share_did.clone(),
        enforcer_did: runtime.enforcer_did.clone(),
        share_id: share_id.to_owned(),
        recipient_matcher: serde_json::from_value(matcher.clone()).unwrap(),
        target: RegistrationTarget {
            origin: runtime.config.target_origin.clone(),
            node_audience: runtime.config.node_audience.clone(),
            enforcer_did: runtime.enforcer_did.clone(),
            space_id: space_id_string.clone(),
        },
        resource: ExactResource {
            kind: "prefix".into(),
            path: path.clone(),
        },
        actions: actions.clone(),
        decryption: None,
        content_source: serde_json::from_value(source.clone()).unwrap(),
        content_source_digest: source_digest.clone(),
        registered_at: "2026-09-29T00:00:00.000Z".into(),
        expires_at: expires_at.clone(),
    };
    let mut core = serde_json::to_value(&registration).unwrap();
    core.as_object_mut().unwrap().remove("registrationCid");
    let registration_cid = raw_sha256_cid(&jcs::canonicalize(&core));
    let row = owner_share_policy::ActiveModel {
        policy_cid: Set(policy_cid.clone()),
        registration_cid: Set(registration_cid.clone()),
        owner_delegation_cid: Set(owner_cid.clone()),
        enforcement_delegation_cid: Set(enforcement.cid.clone()),
        policy_bytes: Set(runtime.policy_encryption.encrypt(&policy_bytes)),
        enforcement_delegation_bytes: Set(runtime
            .policy_encryption
            .encrypt(&serde_json::to_vec(&enforcement).unwrap())),
        policy_proof: Set(policy_proof),
        policy_digest: Set(b64_digest(&policy_bytes)),
        matcher_digest: Set(b64_digest(&jcs::canonicalize(matcher))),
        content_source_digest: Set(source_digest.clone()),
        owner_did: Set(owner_did.to_owned()),
        share_key_did: Set(share_did.clone()),
        enforcer_did: Set(runtime.enforcer_did.clone()),
        node_audience: Set(runtime.config.node_audience.clone()),
        target_origin: Set(runtime.config.target_origin.clone()),
        space_id: Set(space_id_string.clone()),
        resource_kind: Set("prefix".to_owned()),
        resource_path: Set(path.clone()),
        actions: Set(serde_json::to_value(&actions).unwrap()),
        registered_at: Set(registration.registered_at),
        expires_at: Set(expires_at.clone()),
        revoked_at: Set(None),
    };
    row.insert(&runtime.conn)
        .await
        .expect("historical policy registration row");
    let registered = registered_policy(runtime, &registration_cid, &policy_cid)
        .await
        .expect("signed historical registration passes real DB and signature checks");
    verify_registered_ancestors(runtime, &registered, Some(&enforcement))
        .await
        .expect("signed owner and enforcement ancestors pass real verification");

    let target = policy["policy"]["target"].clone();
    let envelope_identity = serde_json::json!({
        "schema": "xyz.tinycloud.share/envelope/v2", "version": 2,
        "shareId": share_id, "delegationCid": owner_cid, "policyCid": policy_cid,
        "target": target, "resource": {"kind": "prefix", "path": path},
        "actions": actions, "contentSource": source, "contentSourceDigest": source_digest,
        "expiresAt": expires_at
    });
    let envelope_cid = raw_sha256_cid(&jcs::canonicalize(&envelope_identity));
    let share_cid = raw_sha256_cid(&jcs::canonicalize(&serde_json::json!({
        "version": 2, "shareId": share_id, "policyCid": policy_cid, "envelopeCid": envelope_cid
    })));
    let mut outer = envelope_identity;
    let obj = outer.as_object_mut().unwrap();
    obj.insert("envelopeCid".into(), Value::String(envelope_cid.clone()));
    obj.insert("shareCid".into(), Value::String(share_cid.clone()));
    let mut signed_outer = b"xyz.tinycloud.share/envelope/v2\0".to_vec();
    signed_outer.extend(jcs::canonicalize(&outer));
    outer.as_object_mut().unwrap().insert("signature".into(), serde_json::json!({
        "signerDid": share_did, "algorithm": "Ed25519",
        "value": encode_config(share_key.sign(&signed_outer).expect("signed outer envelope"), URL_SAFE_NO_PAD)
    }));
    let mut challenge = serde_json::json!({
        "envelopeCid": envelope_cid, "shareCid": share_cid, "shareId": share_id,
        "registrationCid": registration_cid, "delegationCid": owner_cid,
        "policyCid": policy_cid, "enforcementDelegationCid": enforcement.cid,
        "enforcementDelegation": enforcement, "outerEnvelope": outer,
        "contentSource": source, "contentSourceDigest": source_digest,
        "holderDid": holder_did, "targetOrigin": runtime.config.target_origin,
        "nodeAudience": runtime.config.node_audience, "action": "tinycloud.kv/list",
        "actions": actions, "resource": path
    });
    let digest = b64_digest(&jcs::canonicalize(&challenge));
    challenge
        .as_object_mut()
        .unwrap()
        .insert("requestBodyDigest".into(), Value::String(digest));
    let challenge_request: V2ChallengeRequest = serde_json::from_value(challenge.clone()).unwrap();
    verify_outer_envelope(
        &challenge_request.outer_envelope,
        &challenge_request,
        &share_did,
        None,
    )
    .expect("historically signed outer envelope verifies");
    // No post-cutoff mint route exists. Reconstruct only its durable binding
    // from the real node signer and a genuine holder-signed presentation.
    let session_id = format!("historical-session-{share_id}");
    let session_issued = timestamp(OffsetDateTime::now_utc());
    let session_expires = timestamp(OffsetDateTime::now_utc() + Duration::minutes(4));
    let credential_digest = b64_digest(b"synthetic credential bound to test-only session");
    let presentation = serde_json::json!({
        "type": "TinyCloudSharePolicyPresentation", "version": 2,
        "challengeId": format!("synthetic-{share_id}"), "nonce": format!("nonce-{share_id}"),
        "shareCid": share_cid, "shareId": share_id, "delegationCid": owner_cid,
        "policyCid": policy_cid, "contentSource": source, "contentSourceDigest": source_digest,
        "holderDid": holder_did, "targetOrigin": runtime.config.target_origin,
        "nodeAudience": runtime.config.node_audience, "enforcerDid": runtime.enforcer_did,
        "credentialDigest": credential_digest, "action": "tinycloud.kv/list",
        "actions": actions, "resource": path,
        "requestBodyDigest": challenge_request.request_body_digest,
        "issuedAt": session_issued, "expiresAt": session_expires, "jti": format!("vp-{share_id}")
    });
    let presentation_proof = signed_value(&holder, V2_SESSION_DOMAIN, &presentation)
        .expect("holder-signed session presentation");
    verify_v2_proof(
        &holder_did,
        &presentation_proof,
        V2_SESSION_DOMAIN,
        &presentation,
    )
    .expect("holder session proof verifies");
    let vp_digest = b64_digest(&jcs::canonicalize(&presentation));
    let runtime_delegation = create_runtime_delegation(
        runtime,
        &registered,
        &challenge_request,
        &holder_did,
        &credential_digest,
        &vp_digest,
        &session_expires,
    )
    .await
    .expect("node-signed reconstructed session delegation");
    share_session_handle::ActiveModel {
        session_handle: Set(session_id.clone()),
        authority_session_cid: Set(registration_cid),
        binding_json: Set(serde_json::json!({
            "challenge": challenge, "holderDid": holder_did,
            "credentialDigest": credential_digest, "vpDigest": vp_digest,
            "runtimeDelegation": runtime_delegation
        })),
        holder_digest: Set(b64_digest(holder_did.as_bytes())),
        issued_at: Set(session_issued),
        expires_at: Set(session_expires),
        revoked_at: Set(None),
    }
    .insert(&runtime.conn)
    .await
    .expect("reconstructed short-lived holder session row");
    HistoricalShare {
        challenge: serde_json::to_value(challenge_request).unwrap(),
        session_id,
        holder,
        registered,
        sender,
        sender_did,
        sender_vm,
        sender_delegation_cid,
    }
}

async fn invoke(client: &Client, share: &HistoricalShare, jti: &str) -> (Status, Value) {
    let challenge = &share.challenge;
    let now = OffsetDateTime::now_utc();
    let mut invocation = serde_json::json!({
        "type": "TinyCloudShareReadInvocation", "version": 2,
        "sessionId": share.session_id, "envelopeCid": challenge["envelopeCid"],
        "shareCid": challenge["shareCid"], "shareId": challenge["shareId"],
        "registrationCid": challenge["registrationCid"], "delegationCid": challenge["delegationCid"],
        "policyCid": challenge["policyCid"],
        "enforcementDelegationCid": challenge["enforcementDelegationCid"],
        "contentSource": challenge["contentSource"], "contentSourceDigest": challenge["contentSourceDigest"],
        "holderDid": challenge["holderDid"], "nodeAudience": challenge["nodeAudience"],
        "action": "tinycloud.kv/list", "actions": challenge["actions"],
        "resource": challenge["resource"], "issuedAt": timestamp(now),
        "expiresAt": timestamp(now + Duration::minutes(1)), "jti": jti,
        "bodyDigest": null, "ifMatch": null, "contentType": null
    });
    let digest = b64_digest(&jcs::canonicalize(&invocation));
    invocation
        .as_object_mut()
        .unwrap()
        .insert("requestBodyDigest".into(), Value::String(digest.clone()));
    let mut request = serde_json::json!({
        "sessionId": share.session_id, "envelopeCid": challenge["envelopeCid"],
        "shareCid": challenge["shareCid"], "shareId": challenge["shareId"],
        "registrationCid": challenge["registrationCid"], "delegationCid": challenge["delegationCid"],
        "policyCid": challenge["policyCid"],
        "enforcementDelegationCid": challenge["enforcementDelegationCid"],
        "contentSource": challenge["contentSource"], "contentSourceDigest": challenge["contentSourceDigest"],
        "holderDid": challenge["holderDid"], "nodeAudience": challenge["nodeAudience"],
        "action": "tinycloud.kv/list", "actions": challenge["actions"],
        "resource": challenge["resource"], "requestBodyDigest": digest,
        "invocation": invocation
    });
    let proof = signed_value(&share.holder, V2_INVOCATION_DOMAIN, &invocation)
        .expect("holder signs real invocation");
    request
        .as_object_mut()
        .unwrap()
        .insert("proof".into(), serde_json::to_value(proof).unwrap());
    let response = client
        .post("/share/v2/invoke")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_vec(&serde_json::json!({"request": request})).unwrap())
        .dispatch()
        .await;
    let status = response.status();
    let body: Value = serde_json::from_slice(&response.into_bytes().await.unwrap()).unwrap();
    (status, body)
}

async fn authorize_delivery(client: &Client, share: &HistoricalShare, jti: u8) -> (Status, Value) {
    let challenge = &share.challenge;
    let mut request = serde_json::json!({
        "envelopeCid": challenge["envelopeCid"], "shareCid": challenge["shareCid"],
        "shareId": challenge["shareId"], "registrationCid": challenge["registrationCid"],
        "policyCid": challenge["policyCid"], "delegationCid": challenge["delegationCid"],
        "enforcementDelegationCid": challenge["enforcementDelegationCid"],
        "recipientEmail": "alice@example.com",
        "shareUrl": format!("https://share.tinycloud.xyz/s/{}", challenge["shareCid"].as_str().unwrap()),
        "documentName": "historical document",
        "jti": encode_config([jti; 16], URL_SAFE_NO_PAD),
        "expiresAt": timestamp(OffsetDateTime::now_utc() + Duration::minutes(4))
    });
    let digest = request_digest_without(&request, "requestBodyDigest").expect("delivery digest");
    request
        .as_object_mut()
        .unwrap()
        .insert("requestBodyDigest".into(), Value::String(digest));
    let space_id = share
        .registered
        .row
        .space_id
        .parse::<tinycloud_auth::resource::SpaceId>()
        .expect("registered space");
    let path = share
        .registered
        .row
        .resource_path
        .parse()
        .expect("registered path");
    let resource = space_id.to_resource("kv".parse().unwrap(), Some(path), None, None);
    let invocation = make_invocation(
        [(
            resource,
            ["tinycloud.kv/get".parse::<UcanAbility>().unwrap()],
        )],
        &share.sender_delegation_cid,
        &share.sender,
        &share.sender_vm,
        (OffsetDateTime::now_utc() + Duration::seconds(45)).unix_timestamp() as f64,
        InvocationOptions::default(),
    )
    .expect("real sender-signed ordinary invocation");
    let response = client
        .post("/share/v2/deliveries/authorize")
        .header(rocket::http::ContentType::JSON)
        .header(rocket::http::Header::new(
            "Authorization",
            invocation.encode().unwrap(),
        ))
        .body(serde_json::to_vec(&request).unwrap())
        .dispatch()
        .await;
    let status = response.status();
    let body: Value = serde_json::from_slice(&response.into_bytes().await.unwrap()).unwrap();
    (status, body)
}

async fn creation_closed(client: &Client, route: &str, body: &Value) {
    let response = client
        .post(route)
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_vec(body).unwrap())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Gone,
        "{route} must remain closed after September 30"
    );
    let body: Value = serde_json::from_slice(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "legacy_v2_creation_closed");
}

#[tokio::test]
async fn historical_signed_share_invoke_and_delivery_stop_after_share_key_tombstone_without_affecting_other_shares(
) {
    let key_setup = StaticSecret::new(vec![0x59u8; 32]).expect("node test key");
    let runtime =
        compose_test_runtime(&key_setup, Some(TeeContext::derive_local(&key_setup)), true).await;
    assert!(
        runtime.live().await,
        "composed node must accept read requests"
    );
    let (owner, owner_did, owner_vm) = owner_identity();
    actor::ActiveModel {
        id: Set(owner_did.clone()),
    }
    .insert(&runtime.conn)
    .await
    .unwrap();
    let space_id = tinycloud_auth::resource::SpaceId::new(
        owner_did.parse().unwrap(),
        "applications".parse().unwrap(),
    );
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id)),
    }
    .insert(&runtime.conn)
    .await
    .unwrap();
    let revoked = historical_share(&runtime, &owner, &owner_did, &owner_vm, "legacy-revoked").await;
    let unaffected =
        historical_share(&runtime, &owner, &owner_did, &owner_vm, "legacy-control").await;
    let share_did = revoked.registered.row.share_key_did.clone();
    let client = Client::tracked(
        rocket::build()
            .manage(Some(runtime.clone()))
            .manage(crate::BlockStage::from(
                crate::config::StagingStorage::Memory,
            ))
            .mount(
                "/",
                rocket::routes![
                    policy_challenge_v2,
                    policy_session_v2,
                    invoke_v2,
                    authorize_delivery_v2
                ],
            ),
    )
    .await
    .expect("real Rocket client");

    // September 30 closed *creation*, not historically registered read access.
    creation_closed(&client, "/share/v2/policy/challenges", &revoked.challenge).await;
    creation_closed(&client, "/share/v2/policy/session", &serde_json::json!({})).await;
    let (status, body) = invoke(&client, &revoked, "pre-revoke").await;
    assert_eq!(
        status,
        Status::Ok,
        "signed historical read must work: {body}"
    );
    assert_eq!(body["action"], "tinycloud.kv/list");
    assert_eq!(
        invoke(&client, &unaffected, "control-before").await.0,
        Status::Ok
    );
    let (status, body) = authorize_delivery(&client, &revoked, 1).await;
    assert_eq!(
        status,
        Status::Ok,
        "signed sender delivery must work: {body}"
    );
    assert_eq!(body["authorization"]["senderDid"], revoked.sender_did);
    assert_eq!(body["authorization"]["senderTrust"], "verified");
    assert_eq!(
        authorize_delivery(&client, &unaffected, 2).await.0,
        Status::Ok
    );

    // Persist the same canonical global DID tombstone written by explicit key
    // revoke. No CID revocation or policy/session flag is used as a substitute.
    key_revocation::ActiveModel {
        target_did: Set(share_did),
        scope_key: Set("global".to_owned()),
        revoked_at: Set(OffsetDateTime::now_utc().unix_timestamp()),
    }
    .insert(&runtime.conn)
    .await
    .expect("durable key tombstone");
    creation_closed(&client, "/share/v2/policy/challenges", &revoked.challenge).await;
    creation_closed(&client, "/share/v2/policy/session", &serde_json::json!({})).await;
    let (status, body) = invoke(&client, &revoked, "post-revoke-new-jti").await;
    assert_eq!(
        status,
        Status::Forbidden,
        "revoked share key must deny invoke: {body}"
    );
    assert_eq!(body["error"]["code"], "invoke_denied");
    let (status, body) = authorize_delivery(&client, &revoked, 3).await;
    assert_eq!(
        status,
        Status::Forbidden,
        "revoked share key must deny delivery: {body}"
    );
    assert_eq!(body["error"]["code"], "delivery_authorization_invalid");
    let (status, body) = invoke(&client, &unaffected, "control-after").await;
    assert_eq!(
        status,
        Status::Ok,
        "unrelated share must still work: {body}"
    );
    let (status, body) = authorize_delivery(&client, &unaffected, 4).await;
    assert_eq!(
        status,
        Status::Ok,
        "unrelated share delivery must still work: {body}"
    );
}

#[tokio::test]
async fn historical_signed_delivery_denies_revoked_owner_enforcer_or_sender() {
    for (index, target) in ["owner", "enforcer", "sender"].iter().enumerate() {
        let key_setup = StaticSecret::new(vec![0x59u8; 32]).expect("node test key");
        let runtime =
            compose_test_runtime(&key_setup, Some(TeeContext::derive_local(&key_setup)), true)
                .await;
        assert!(
            runtime.live().await,
            "composed node must accept read requests"
        );
        let (owner, owner_did, owner_vm) = owner_identity();
        actor::ActiveModel {
            id: Set(owner_did.clone()),
        }
        .insert(&runtime.conn)
        .await
        .unwrap();
        let space_id = tinycloud_auth::resource::SpaceId::new(
            owner_did.parse().unwrap(),
            "applications".parse().unwrap(),
        );
        space::ActiveModel {
            id: Set(SpaceIdWrap(space_id)),
        }
        .insert(&runtime.conn)
        .await
        .unwrap();
        let share = historical_share(
            &runtime,
            &owner,
            &owner_did,
            &owner_vm,
            &format!("legacy-delivery-{target}"),
        )
        .await;
        let revoked_did = match *target {
            "owner" => owner_did,
            "enforcer" => runtime.enforcer_did.clone(),
            "sender" => share.sender_did.clone(),
            _ => unreachable!(),
        };
        let client = Client::tracked(rocket::build().manage(Some(runtime.clone())).mount(
            "/",
            rocket::routes![
                policy_challenge_v2,
                policy_session_v2,
                authorize_delivery_v2
            ],
        ))
        .await
        .expect("real Rocket client");
        creation_closed(&client, "/share/v2/policy/challenges", &share.challenge).await;
        creation_closed(&client, "/share/v2/policy/session", &serde_json::json!({})).await;
        let (status, body) = authorize_delivery(&client, &share, (index * 2 + 10) as u8).await;
        assert_eq!(status, Status::Ok, "{target} pre-revoke delivery: {body}");
        assert_eq!(body["authorization"]["senderDid"], share.sender_did);
        assert_eq!(body["authorization"]["senderTrust"], "verified");

        key_revocation::ActiveModel {
            target_did: Set(revoked_did),
            scope_key: Set("global".to_owned()),
            revoked_at: Set(OffsetDateTime::now_utc().unix_timestamp()),
        }
        .insert(&runtime.conn)
        .await
        .expect("durable key tombstone");
        creation_closed(&client, "/share/v2/policy/challenges", &share.challenge).await;
        creation_closed(&client, "/share/v2/policy/session", &serde_json::json!({})).await;
        let (status, body) = authorize_delivery(&client, &share, (index * 2 + 11) as u8).await;
        assert!(
            status == Status::Unauthorized || status == Status::Forbidden,
            "{target} tombstone must deny delivery, got {status}: {body}"
        );
        assert_eq!(body["error"]["code"], "delivery_authorization_invalid");
    }
}
