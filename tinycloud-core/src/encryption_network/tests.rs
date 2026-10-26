//! Integration tests covering decrypt authorization, hash bindings, replay
//! protection, ceremony state, and network lookup. These exercise the public
//! API of [`EncryptionService`] against a sqlite in-memory database.

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection, EntityTrait,
};
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use time::OffsetDateTime;
use x25519_dalek::{PublicKey, StaticSecret as X25519StaticSecret};

use tinycloud_auth::{
    authorization::Cid,
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
};

use crate::encryption::ColumnEncryption;
use crate::encryption_network::backend::{wrap_to_public_key, LocalOneOfOneBackend};
use crate::encryption_network::canonical::{canonical_hash, canonical_json_bytes};
use crate::encryption_network::key_id::{parse as parse_resource, EncryptionResource, KeyLocation};
use crate::encryption_network::keys::KeyState;
use crate::encryption_network::network_id::NetworkId;
use crate::encryption_network::protocol::{
    DecryptFacts, DecryptInvocation, DecryptRequestBody, InvocationCapability, NetworkAdminFacts,
    DECRYPT_ACTION, DECRYPT_REQUEST_TYPE, NETWORK_ADMIN_TYPE, NETWORK_CREATE_ACTION,
};
use crate::encryption_network::service::{
    CreateNetworkRequest, EncryptionService, EncryptionServiceError, WellKnownRecord,
};
use crate::encryption_network::types::{
    KeyBackendKind, NetworkMemberDescriptor, NetworkState, Threshold, ALG_X25519_AES256GCM,
};
use crate::keys::{public_key_to_did_key, Keypair, StaticSecret as NodeStaticSecret};
use crate::migrations::Migrator;
use crate::models::{encryption_ceremony, encryption_network_key};
use crate::test_support::PostgresTestSchema;

const NODE_DID: &str = "did:key:z6MkNodeTest";
const NETWORK_NAME: &str = "default";

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .expect("connect sqlite");
    Migrator::up(&db, None).await.expect("migrate");
    db
}

fn make_service(db: DatabaseConnection) -> EncryptionService {
    let seal = ColumnEncryption::new([0xABu8; 32]);
    let backend = Arc::new(LocalOneOfOneBackend::new(seal));
    EncryptionService::new(db, NODE_DID.to_string(), backend)
}

fn owner_keypair() -> Keypair {
    NodeStaticSecret::new(vec![0x11; 32])
        .expect("static owner secret")
        .node_keypair()
}

fn attacker_keypair() -> Keypair {
    NodeStaticSecret::new(vec![0x22; 32])
        .expect("static attacker secret")
        .node_keypair()
}

fn did_for(keypair: &Keypair) -> String {
    public_key_to_did_key(keypair.public())
}

fn owner_did() -> String {
    did_for(&owner_keypair())
}

fn network_id() -> NetworkId {
    NetworkId::new(owner_did(), NETWORK_NAME.to_string()).unwrap()
}

struct ClientCtx {
    receiver_secret: X25519StaticSecret,
    receiver_pub: Vec<u8>,
    wrapped_key: Vec<u8>,
    symmetric: Vec<u8>,
}

fn make_client_request(network_pub: &[u8]) -> ClientCtx {
    let symmetric = vec![0xCDu8; 32];
    let wrapped_key = wrap_to_public_key(network_pub, &symmetric).unwrap();
    let receiver_secret = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
    let receiver_pub_arr = PublicKey::from(&receiver_secret);
    ClientCtx {
        receiver_secret,
        receiver_pub: receiver_pub_arr.as_bytes().to_vec(),
        wrapped_key,
        symmetric,
    }
}

fn build_body(ctx: &ClientCtx, net: &NetworkId) -> (DecryptRequestBody, Value) {
    let encrypted_symmetric_key = STANDARD.encode(&ctx.wrapped_key);
    let receiver_public_key = STANDARD.encode(&ctx.receiver_pub);
    let body = DecryptRequestBody {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
        encrypted_symmetric_key: encrypted_symmetric_key.clone(),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(encrypted_symmetric_key)),
        receiver_public_key: receiver_public_key.clone(),
        receiver_public_key_hash: canonical_hash(&Value::String(receiver_public_key)),
        key_path: None,
    };
    let value = serde_json::to_value(&body).unwrap();
    (body, value)
}

fn build_invocation(
    net: &NetworkId,
    body_value: &Value,
    ctx: &ClientCtx,
    overrides: impl FnOnce(&mut DecryptInvocation),
) -> DecryptInvocation {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut inv = DecryptInvocation {
        issuer: owner_did(),
        audience: NODE_DID.to_string(),
        att: vec![InvocationCapability {
            with: net.to_string(),
            can: DECRYPT_ACTION.to_string(),
            nb: BTreeMap::new(),
        }],
        facts: DecryptFacts {
            ty: DECRYPT_REQUEST_TYPE.to_string(),
            target_node: NODE_DID.to_string(),
            network_id: net.clone(),
            body_hash: canonical_hash(body_value),
            encrypted_symmetric_key_hash: canonical_hash(&Value::String(
                STANDARD.encode(&ctx.wrapped_key),
            )),
            receiver_public_key_hash: canonical_hash(&Value::String(
                STANDARD.encode(&ctx.receiver_pub),
            )),
            key_path: None,
            alg: ALG_X25519_AES256GCM.to_string(),
            key_version: 1,
        },
        nonce: format!("nonce-{now}"),
        not_before: None,
        exp: now + 60,
        proof_cid: Vec::new(),
        sig: String::new(),
    };
    overrides(&mut inv);
    sign_invocation(&mut inv, &owner_keypair());
    inv
}

fn build_session_invocation_info(
    resource: &NetworkId,
    action: &str,
    facts: Vec<Value>,
    audience: &str,
) -> crate::util::InvocationInfo {
    build_session_invocation_for(&resource.to_string(), action, facts, audience)
}

fn build_session_invocation_for(
    resource: &str,
    action: &str,
    facts: Vec<Value>,
    audience: &str,
) -> crate::util::InvocationInfo {
    let mut jwk = JWK::generate_ed25519().expect("session jwk");
    jwk.algorithm = Some(Algorithm::EdDSA);

    let mut verification_method = DID_METHODS
        .generate(&jwk, "key")
        .expect("session did")
        .to_string();
    let fragment = verification_method
        .rsplit_once(':')
        .expect("fragment")
        .1
        .to_string();
    verification_method.push('#');
    verification_method.push_str(&fragment);

    let resource_uri: iri_string::types::UriString =
        resource.to_string().parse().expect("network uri");
    let capability: tinycloud_auth::ucan_capabilities_object::Ability =
        action.to_string().try_into().expect("capability");
    let delegation_cid = Cid::new_v1(0x55, Code::Blake3_256.digest(b"network-session-delegation"));

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut attenuation = tinycloud_auth::ucan_capabilities_object::Capabilities::new();
    attenuation.with_actions(resource_uri, std::iter::once((capability, [])));
    let payload = Payload {
        issuer: verification_method
            .parse::<DIDURLBuf>()
            .expect("session issuer"),
        audience: audience.parse::<DIDBuf>().expect("session audience"),
        not_before: None,
        expiration: NumericDate::try_from_seconds((now + 60) as f64).expect("expiration"),
        nonce: Some(format!("session-nonce-{now}")),
        facts: Some(facts),
        proof: vec![delegation_cid],
        attenuation,
    };
    let invocation = payload
        .sign(Algorithm::EdDSA, &jwk)
        .expect("session invocation");

    crate::util::InvocationInfo::try_from(invocation).expect("invocation info")
}

fn sign_invocation(inv: &mut DecryptInvocation, keypair: &Keypair) {
    let message = canonical_json_bytes(&inv.unsigned_payload());
    inv.sig = STANDARD.encode(keypair.sign(&message).expect("sign decrypt invocation"));
}

fn unwrap_with_secret(secret: &X25519StaticSecret, wrapped: &[u8]) -> Vec<u8> {
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&wrapped[..32]);
    let pub_peer = PublicKey::from(peer);
    let shared = secret.diffie_hellman(&pub_peer);
    ColumnEncryption::new(*shared.as_bytes())
        .decrypt(&wrapped[32..])
        .expect("decrypt rewrapped key")
}

#[tokio::test]
async fn create_one_of_one_network_initializes_active_state() {
    let db = fresh_db().await;
    let svc = make_service(db.clone());
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();

    assert_eq!(descriptor.state, NetworkState::Active);
    assert_eq!(descriptor.alg, ALG_X25519_AES256GCM);
    assert_eq!(descriptor.threshold.n, 1);
    assert_eq!(descriptor.threshold.t, 1);
    assert_eq!(descriptor.key_backend, KeyBackendKind::LocalOneOfOne);
    assert_eq!(descriptor.public_encryption_key.len(), 32);
    assert_eq!(
        descriptor.members,
        vec![NetworkMemberDescriptor {
            node_id: NODE_DID.to_string(),
            role: "primary".to_string()
        }]
    );

    let ceremonies = encryption_ceremony::Entity::find()
        .all(&db)
        .await
        .expect("ceremonies");
    assert_eq!(ceremonies.len(), 1);
    assert_eq!(ceremonies[0].network_id, descriptor.network_id.to_string());
    assert_eq!(ceremonies[0].state, "completed");
    assert!(ceremonies[0].transcript_hash.is_some());
}

#[tokio::test]
async fn create_network_rejects_duplicate() {
    let svc = make_service(fresh_db().await);
    svc.create_one_of_one_network(CreateNetworkRequest {
        name: NETWORK_NAME.to_string(),
        owner_did: owner_did(),
        threshold: Threshold::one_of_one(),
    })
    .await
    .unwrap();
    let err = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkAlreadyExists));
}

#[tokio::test]
async fn get_network_returns_descriptor() {
    let db = fresh_db().await;
    let svc = make_service(db.clone());
    let net = network_id();
    svc.create_one_of_one_network(CreateNetworkRequest {
        name: NETWORK_NAME.to_string(),
        owner_did: owner_did(),
        threshold: Threshold::one_of_one(),
    })
    .await
    .unwrap();

    let fetched = svc.get_network(&net).await.unwrap();
    assert_eq!(fetched.network_id, net);
    assert_eq!(fetched.owner_did, owner_did());
    assert_eq!(fetched.state, NetworkState::Active);
}

#[tokio::test]
async fn get_network_by_name_returns_discovery_view() {
    let db = fresh_db().await;
    let svc = make_service(db);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();

    let by_owner = svc
        .get_network_by_name(NETWORK_NAME, Some(&owner_did()))
        .await
        .unwrap();
    let by_name = svc.get_network_by_name(NETWORK_NAME, None).await.unwrap();

    assert_eq!(by_owner.network_id, net);
    assert_eq!(by_name.network_id, net);

    let well_known = WellKnownRecord::from(&descriptor);
    let serialized = serde_json::to_value(&well_known).unwrap();
    assert_eq!(serialized["networkId"], net.to_string());
    assert_eq!(serialized["keyVersion"], 1);
    assert_eq!(serialized["keyBackend"], "local-one-of-one");
    assert_eq!(
        serialized["publicEncryptionKey"],
        STANDARD.encode(&descriptor.public_encryption_key)
    );
}

#[tokio::test]
async fn network_admin_authorized_accepts_session_invoker() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let body_value = serde_json::json!({
        "name": NETWORK_NAME,
        "ownerDid": owner_did(),
        "threshold": { "n": 1, "t": 1 }
    });
    let facts = serde_json::to_value(NetworkAdminFacts {
        ty: NETWORK_ADMIN_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(&body_value),
        action: NETWORK_CREATE_ACTION.to_string(),
    })
    .unwrap();
    let invocation =
        build_session_invocation_info(&net, NETWORK_CREATE_ACTION, vec![facts], NODE_DID);

    svc.verify_network_admin_authorized(&net, NETWORK_CREATE_ACTION, &invocation, &body_value)
        .await
        .unwrap();
    assert_ne!(invocation.invoker, owner_did());
}

#[tokio::test]
async fn decrypt_round_trip_returns_rewrapped_key() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});

    let verified = svc.decrypt(&net, &inv, &body_value).await.unwrap();
    assert_eq!(verified.response.target_node, NODE_DID);
    assert_eq!(verified.response.network_id, net);

    // Client unwraps the rewrapped key with the receiver private key.
    let rewrapped = STANDARD
        .decode(&verified.response.wrapped_key)
        .expect("base64 wrapped key");
    let recovered = unwrap_with_secret(&ctx.receiver_secret, &rewrapped);
    assert_eq!(recovered, ctx.symmetric);
}

#[tokio::test]
async fn decrypt_authorized_accepts_session_invoker() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let facts = serde_json::to_value(DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(&body_value),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.wrapped_key),
        )),
        receiver_public_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.receiver_pub),
        )),
        key_path: None,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    })
    .unwrap();
    let invocation = build_session_invocation_info(&net, DECRYPT_ACTION, vec![facts], NODE_DID);

    let verified = svc
        .decrypt_authorized(
            &crate::encryption_network::DecryptTarget::Root(net.clone()),
            &invocation,
            &body_value,
        )
        .await
        .unwrap();
    let rewrapped = STANDARD
        .decode(&verified.response.wrapped_key)
        .expect("base64 wrapped key");
    let recovered = unwrap_with_secret(&ctx.receiver_secret, &rewrapped);
    assert_eq!(recovered, ctx.symmetric);
    assert_ne!(invocation.invoker, owner_did());
}

#[tokio::test]
async fn decrypt_authorized_reads_the_network_row_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut db = fresh_db().await;
    let network_reads = Arc::new(AtomicUsize::new(0));
    let counter = network_reads.clone();
    db.set_metric_callback(move |info| {
        if info.statement.sql.contains(r#"FROM "encryption_network" "#) {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let svc = make_service(db);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let facts = serde_json::to_value(DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(&body_value),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.wrapped_key),
        )),
        receiver_public_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.receiver_pub),
        )),
        key_path: None,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    })
    .unwrap();
    let invocation = build_session_invocation_info(&net, DECRYPT_ACTION, vec![facts], NODE_DID);

    network_reads.store(0, Ordering::SeqCst);
    svc.decrypt_authorized(
        &crate::encryption_network::DecryptTarget::Root(net.clone()),
        &invocation,
        &body_value,
    )
    .await
    .unwrap();

    assert_eq!(network_reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn decrypt_authorized_rejects_audience_mismatch() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let facts = serde_json::to_value(DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(&body_value),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.wrapped_key),
        )),
        receiver_public_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.receiver_pub),
        )),
        key_path: None,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    })
    .unwrap();
    let invocation = build_session_invocation_info(
        &net,
        DECRYPT_ACTION,
        vec![facts],
        "did:key:z6MkSomeOtherNode",
    );

    let err = svc
        .decrypt_authorized(
            &crate::encryption_network::DecryptTarget::Root(net.clone()),
            &invocation,
            &body_value,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::AudienceMismatch));
}

#[tokio::test]
async fn decrypt_rejects_audience_mismatch() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |inv| {
        inv.audience = "did:key:z6MkSomeOtherNode".to_string();
    });
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::AudienceMismatch));
}

#[tokio::test]
async fn decrypt_rejects_target_node_mismatch_in_body() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (mut body, _) = build_body(&ctx, &net);
    body.target_node = "did:key:z6MkOther".to_string();
    let body_value = serde_json::to_value(&body).unwrap();
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::TargetNodeMismatch));
}

#[tokio::test]
async fn decrypt_rejects_target_node_mismatch_in_invocation() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let mut inv = build_invocation(&net, &body_value, &ctx, |_| {});
    inv.facts.target_node = "did:key:z6MkOther".to_string();
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::TargetNodeMismatch));
}

#[tokio::test]
async fn decrypt_rejects_body_hash_mismatch() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |inv| {
        inv.facts.body_hash = "ff".repeat(32);
    });
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(
        err,
        EncryptionServiceError::HashMismatch("bodyHash")
    ));
}

#[tokio::test]
async fn decrypt_rejects_receiver_public_key_substitution() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (mut body, _) = build_body(&ctx, &net);
    // Substitute a different receiver pubkey but leave the declared hash intact
    let attacker = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
    let attacker_pub = PublicKey::from(&attacker);
    body.receiver_public_key = STANDARD.encode(attacker_pub.as_bytes());
    let body_value = serde_json::to_value(&body).unwrap();
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(
        err,
        EncryptionServiceError::HashMismatch("receiverPublicKeyHash")
    ));
}

#[tokio::test]
async fn decrypt_rejects_encrypted_key_substitution() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (mut body, _) = build_body(&ctx, &net);
    // Replace the wrapped key bytes; leave the declared hash intact.
    let other_wrapped = wrap_to_public_key(&descriptor.public_encryption_key, &[0u8; 32]).unwrap();
    body.encrypted_symmetric_key = STANDARD.encode(&other_wrapped);
    let body_value = serde_json::to_value(&body).unwrap();
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(
        err,
        EncryptionServiceError::HashMismatch("encryptedSymmetricKeyHash")
    ));
}

#[tokio::test]
async fn decrypt_rejects_wrong_network() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let other_net = NetworkId::new(owner_did(), "wrong".to_string()).unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});
    let err = svc
        .decrypt(&other_net, &inv, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkMismatch));
}

#[tokio::test]
async fn decrypt_rejects_invocation_network_mismatch() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let other_net = NetworkId::new(owner_did(), "wrong".to_string()).unwrap();
    let mut inv = build_invocation(&net, &body_value, &ctx, |_| {});
    inv.facts.network_id = other_net;
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkMismatch));
}

#[tokio::test]
async fn decrypt_rejects_wrong_owner() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let attacker = attacker_keypair();
    let mut inv = build_invocation(&net, &body_value, &ctx, |inv| {
        inv.issuer = did_for(&attacker);
        // no delegation proof attached
    });
    sign_invocation(&mut inv, &attacker);
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::OwnerMismatch));
}

#[tokio::test]
async fn decrypt_rejects_signature_mismatch() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let mut inv = build_invocation(&net, &body_value, &ctx, |_| {});
    inv.issuer = did_for(&attacker_keypair());
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::SignatureInvalid(_)));
}

#[tokio::test]
async fn decrypt_rejects_replay() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});
    svc.decrypt(&net, &inv, &body_value).await.unwrap();
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NonceReplay));
}

#[tokio::test]
async fn decrypt_rejects_expired_invocation() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |inv| {
        inv.exp = OffsetDateTime::now_utc().unix_timestamp() - 1;
    });
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Expired));
}

#[tokio::test]
async fn decrypt_rejects_wrong_capability_action() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |inv| {
        inv.att[0].can = "tinycloud.kv/get".to_string();
    });
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Unauthorized));
}

#[tokio::test]
async fn revoked_network_refuses_decrypt() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    svc.revoke_network(&net).await.unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let inv = build_invocation(&net, &body_value, &ctx, |_| {});
    let err = svc.decrypt(&net, &inv, &body_value).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkRevoked));
}

#[tokio::test]
async fn unknown_network_returns_not_found() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let err = svc.get_network(&net).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkNotFound));
}

#[tokio::test]
async fn unique_request_hashes_per_decrypt() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx1 = make_client_request(&descriptor.public_encryption_key);
    let (_, body1) = build_body(&ctx1, &net);
    let inv1 = build_invocation(&net, &body1, &ctx1, |inv| {
        inv.nonce = "n1".to_string();
    });
    let r1 = svc.decrypt(&net, &inv1, &body1).await.unwrap();

    let ctx2 = make_client_request(&descriptor.public_encryption_key);
    let (_, body2) = build_body(&ctx2, &net);
    let inv2 = build_invocation(&net, &body2, &ctx2, |inv| {
        inv.nonce = "n2".to_string();
    });
    let r2 = svc.decrypt(&net, &inv2, &body2).await.unwrap();

    assert_ne!(r1.request_hash, r2.request_hash);
}

fn key_loc(path: &str) -> KeyLocation {
    let urn = format!(
        "urn:tinycloud:encryption:{}:{}/{}",
        owner_did(),
        NETWORK_NAME,
        path
    );
    match parse_resource(&urn).expect("parse key urn") {
        EncryptionResource::Key(loc) => loc,
        other => panic!("expected key resource, got {other:?}"),
    }
}

async fn create_network(svc: &EncryptionService) {
    svc.create_one_of_one_network(CreateNetworkRequest {
        name: NETWORK_NAME.to_string(),
        owner_did: owner_did(),
        threshold: Threshold::one_of_one(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn create_key_returns_active_deterministic_descriptor() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let key = svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    assert_eq!(key.state, KeyState::Active);
    assert_eq!(key.kind, "deterministic");
    assert_eq!(key.key_version, 1);
    assert_eq!(key.alg, ALG_X25519_AES256GCM);
    assert_eq!(key.key_path, "docs/alpha");
    assert_eq!(key.public_encryption_key.len(), 32);
}

#[tokio::test]
async fn create_key_is_idempotent_for_active_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let first = svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    let second = svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    assert_eq!(first, second);
}

#[tokio::test]
async fn create_key_rejects_existing_blocked_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    svc.block_key(&key_loc("docs/alpha")).await.unwrap();
    let err = svc
        .create_key(&key_loc("docs/alpha"), false)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyExists));
}

#[tokio::test]
async fn create_key_requires_existing_network() {
    let svc = make_service(fresh_db().await);
    let err = svc
        .create_key(&key_loc("docs/alpha"), false)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkNotFound));
}

#[tokio::test]
async fn create_key_refuses_revoked_network() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    svc.revoke_network(&network_id()).await.unwrap();
    let err = svc
        .create_key(&key_loc("docs/alpha"), false)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EncryptionServiceError::NetworkNotActive(s) if s == "revoked"),
        "revoked network must map to network_not_active(revoked), got {err:?}"
    );
}

#[tokio::test]
async fn create_key_cap_counts_blocked_rows() {
    let svc = make_service(fresh_db().await).with_key_cap_per_network(2);
    create_network(&svc).await;
    svc.create_key(&key_loc("a"), false).await.unwrap();
    svc.create_key(&key_loc("b"), false).await.unwrap();
    svc.block_key(&key_loc("a")).await.unwrap();
    let err = svc.create_key(&key_loc("c"), false).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyLimitExceeded));
}

#[tokio::test]
async fn block_and_unblock_are_idempotent_round_trip() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    let blocked = svc.block_key(&key_loc("docs/alpha")).await.unwrap();
    assert_eq!(blocked.state, KeyState::Blocked);
    assert_eq!(
        svc.block_key(&key_loc("docs/alpha")).await.unwrap(),
        blocked
    );
    let active = svc.unblock_key(&key_loc("docs/alpha")).await.unwrap();
    assert_eq!(active.state, KeyState::Active);
}

#[tokio::test]
async fn block_missing_key_is_not_found() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let err = svc.block_key(&key_loc("docs/missing")).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyNotFound));
}

#[tokio::test]
async fn public_get_derives_without_writing_and_matches_created_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("docs/beta");
    let derived = svc.public_key(&loc).await.unwrap();
    let err = svc.describe_key(&loc).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyNotFound));
    let created = svc.create_key(&loc, false).await.unwrap();
    assert_eq!(derived.public_encryption_key, created.public_encryption_key);
}

#[tokio::test]
async fn public_get_is_identical_for_missing_active_and_blocked_keys() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("docs/gamma");
    let missing = svc.public_key(&loc).await.unwrap();
    svc.create_key(&loc, false).await.unwrap();
    let active = svc.public_key(&loc).await.unwrap();
    svc.block_key(&loc).await.unwrap();
    let blocked = svc.public_key(&loc).await.unwrap();
    assert_eq!(missing, active);
    assert_eq!(active, blocked);
}

#[tokio::test]
async fn unwrap_named_key_round_trip_for_active_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    let symmetric = vec![0x5Au8; 32];
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &symmetric).unwrap();
    let (_, unwrapped) = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap();
    assert_eq!(unwrapped, symmetric);
}

#[tokio::test]
async fn unwrap_named_key_refuses_blocked_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &[0x5Au8; 32]).unwrap();
    svc.block_key(&loc).await.unwrap();
    let err = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyBlocked));
}

#[tokio::test]
async fn unwrap_named_key_refuses_missing_row() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let err = svc
        .unwrap_named_key(&key_loc("docs/alpha"), &[0u8; 96], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyNotFound));
}

#[tokio::test]
async fn unwrap_named_key_rejects_wrapping_to_other_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let alpha = svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    svc.create_key(&key_loc("docs/beta"), false).await.unwrap();
    let wrapped = wrap_to_public_key(&alpha.public_encryption_key, &[0x5Au8; 32]).unwrap();
    let err = svc
        .unwrap_named_key(&key_loc("docs/beta"), &wrapped, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyUnwrapFailed(_)));
}

#[tokio::test]
async fn unwrap_named_key_refuses_revoked_network() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &[0x5Au8; 32]).unwrap();
    svc.revoke_network(&network_id()).await.unwrap();
    let err = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap_err();
    assert!(
        matches!(&err, EncryptionServiceError::NetworkNotActive(s) if s == "revoked"),
        "unwrap after network revoke must be refused, got {err:?}"
    );
}

#[tokio::test]
async fn public_key_refuses_revoked_network() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("docs/alpha");
    svc.create_key(&loc, false).await.unwrap();
    svc.revoke_network(&network_id()).await.unwrap();
    let err = svc.public_key(&loc).await.unwrap_err();
    assert!(
        matches!(&err, EncryptionServiceError::NetworkNotActive(s) if s == "revoked"),
        "public GET after network revoke must be refused, got {err:?}"
    );
}

#[tokio::test]
async fn stored_unknown_state_is_refused_as_corrupt() {
    let db = fresh_db().await;
    let svc = make_service(db.clone());
    create_network(&svc).await;
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &[0x5Au8; 32]).unwrap();
    // A raw row in a state this build does not know, as a future build might write.
    let mut row: encryption_network_key::ActiveModel = encryption_network_key::Entity::find_by_id(
        (network_id().to_string(), "docs/alpha".to_string()),
    )
    .one(&db)
    .await
    .unwrap()
    .unwrap()
    .into();
    row.state = Set("retired".to_string());
    row.update(&db).await.unwrap();

    let err = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "unwrap: {err:?}"
    );
    let err = svc.describe_key(&loc).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "describe: {err:?}"
    );
    let err = svc.block_key(&loc).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "block: {err:?}"
    );
    let err = svc.unblock_key(&loc).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "unblock: {err:?}"
    );
    let err = svc.create_key(&loc, false).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "create: {err:?}"
    );
}

// PostgreSQL-backed. Locally these return early unless
// TINYCLOUD_TEST_POSTGRES_URL is set; CI runs them with a PostgreSQL service.
#[tokio::test]
async fn postgres_concurrent_identical_creates_return_one_row() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_concurrent_identical_creates_return_one_row",
        None,
    )
    .await
    else {
        return;
    };
    let db = fixture.connect(8).await;
    let svc = Arc::new(make_service(db.clone()));
    create_network(&svc).await;

    let results = futures::future::join_all((0..8).map(|_| {
        let svc = svc.clone();
        async move { svc.create_key(&key_loc("docs/alpha"), false).await }
    }))
    .await;
    let descriptors: Vec<_> = results
        .into_iter()
        .map(|r| r.expect("identical concurrent create must be Ok"))
        .collect();
    assert!(descriptors.windows(2).all(|w| w[0] == w[1]));
    let rows = encryption_network_key::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one row per (network, key_path)");
}

// PostgreSQL-backed; CI-only, see the note on the identical-create test.
#[tokio::test]
async fn postgres_concurrent_creates_respect_the_key_cap() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_concurrent_creates_respect_the_key_cap",
        None,
    )
    .await
    else {
        return;
    };
    const CAP: u64 = 3;
    let db = fixture.connect(8).await;
    let svc = Arc::new(make_service(db.clone()).with_key_cap_per_network(CAP));
    create_network(&svc).await;
    for seed in 0..(CAP - 1) {
        svc.create_key(&key_loc(&format!("seed-{seed}")), false)
            .await
            .unwrap();
    }

    let results = futures::future::join_all((0..8).map(|i| {
        let svc = svc.clone();
        async move { svc.create_key(&key_loc(&format!("race-{i}")), false).await }
    }))
    .await;
    let won = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(won, 1, "exactly one create fits under the cap");
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| matches!(e, EncryptionServiceError::KeyLimitExceeded)));
    let rows = encryption_network_key::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(rows.len() as u64, CAP, "cap is never exceeded");
}

// PostgreSQL-backed; CI-only. `create_key` must end its transaction before it
// returns. A dropped transaction is rolled back by a task sqlx spawns, which
// cannot run while `execute_blocking` holds this runtime's only thread, so a
// create that returns without ending its transaction still holds the network
// row lock here.
#[tokio::test]
async fn postgres_create_key_ends_its_transaction_before_returning() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_create_key_ends_its_transaction_before_returning",
        None,
    )
    .await
    else {
        return;
    };
    const LOCK: &str = "SELECT 1 FROM encryption_network FOR UPDATE NOWAIT";
    let db = fixture.connect(2).await;
    let svc = make_service(db.clone()).with_key_cap_per_network(1);
    create_network(&svc).await;

    svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    fixture
        .execute_blocking(LOCK)
        .expect("a create that inserts releases the network row lock");

    svc.create_key(&key_loc("docs/alpha"), false).await.unwrap();
    fixture
        .execute_blocking(LOCK)
        .expect("an identical create answered from the existing row releases the network row lock");

    let err = svc
        .create_key(&key_loc("docs/beta"), false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyLimitExceeded),
        "{err:?}"
    );
    fixture
        .execute_blocking(LOCK)
        .expect("a create refused by the cap releases the network row lock");
}

use crate::encryption_network::{keys::canonical_key_urn, DecryptTarget};

fn key_body(
    ctx: &ClientCtx,
    net: &NetworkId,
    path: &str,
    key_version: i64,
) -> (DecryptRequestBody, Value) {
    let (mut body, _) = build_body(ctx, net);
    body.key_path = Some(path.to_string());
    body.key_version = key_version;
    let value = serde_json::to_value(&body).unwrap();
    (body, value)
}

fn key_facts(
    ctx: &ClientCtx,
    net: &NetworkId,
    body_value: &Value,
    path: &str,
    key_version: i64,
) -> Value {
    serde_json::to_value(DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(body_value),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.wrapped_key),
        )),
        receiver_public_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.receiver_pub),
        )),
        key_path: Some(path.to_string()),
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version,
    })
    .unwrap()
}

fn key_invocation(loc: &KeyLocation, facts: Value) -> crate::util::InvocationInfo {
    build_session_invocation_for(
        &canonical_key_urn(loc),
        DECRYPT_ACTION,
        vec![facts],
        NODE_DID,
    )
}

#[tokio::test]
async fn key_decrypt_round_trip_returns_rewrapped_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    let ctx = make_client_request(&key.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/alpha", 1);
    let invocation = key_invocation(&loc, key_facts(&ctx, &net, &body_value, "docs/alpha", 1));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&loc)).unwrap();

    let verified = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap();
    let rewrapped = STANDARD
        .decode(&verified.response.wrapped_key)
        .expect("base64 wrapped key");
    assert_eq!(
        unwrap_with_secret(&ctx.receiver_secret, &rewrapped),
        ctx.symmetric
    );
}

#[tokio::test]
async fn key_decrypt_refuses_body_key_path_mismatch() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let alpha = key_loc("docs/alpha");
    let key = svc.create_key(&alpha, false).await.unwrap();
    let ctx = make_client_request(&key.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/beta", 1);
    let invocation = key_invocation(&alpha, key_facts(&ctx, &net, &body_value, "docs/beta", 1));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&alpha)).unwrap();

    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyPathInvalid(_)));
}

#[tokio::test]
async fn key_decrypt_refuses_capability_for_sibling_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let alpha = key_loc("docs/alpha");
    let beta = key_loc("docs/beta");
    let key = svc.create_key(&alpha, false).await.unwrap();
    svc.create_key(&beta, false).await.unwrap();
    let ctx = make_client_request(&key.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/alpha", 1);
    let invocation = key_invocation(&beta, key_facts(&ctx, &net, &body_value, "docs/alpha", 1));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&alpha)).unwrap();

    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Unauthorized));
}

#[tokio::test]
async fn root_decrypt_refuses_body_key_path() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/alpha", 1);
    let invocation = build_session_invocation_info(
        &net,
        DECRYPT_ACTION,
        vec![key_facts(&ctx, &net, &body_value, "docs/alpha", 1)],
        NODE_DID,
    );

    let err = svc
        .decrypt_authorized(&DecryptTarget::Root(net.clone()), &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyPathInvalid(_)));
}

#[tokio::test]
async fn key_decrypt_refuses_blocked_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    svc.block_key(&loc).await.unwrap();
    let ctx = make_client_request(&key.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/alpha", 1);
    let invocation = key_invocation(&loc, key_facts(&ctx, &net, &body_value, "docs/alpha", 1));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&loc)).unwrap();

    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyBlocked));
}

#[tokio::test]
async fn key_decrypt_refuses_missing_key() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let loc = key_loc("docs/missing");
    let derived = svc.public_key(&loc).await.unwrap();
    let ctx = make_client_request(&derived.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/missing", 1);
    let invocation = key_invocation(&loc, key_facts(&ctx, &net, &body_value, "docs/missing", 1));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&loc)).unwrap();

    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyNotFound));
}

#[tokio::test]
async fn key_decrypt_wrong_key_material_is_key_unwrap_failed() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let alpha = key_loc("docs/alpha");
    let beta = key_loc("docs/beta");
    svc.create_key(&alpha, false).await.unwrap();
    let other = svc.create_key(&beta, false).await.unwrap();
    let ctx = make_client_request(&other.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/alpha", 1);
    let invocation = key_invocation(&alpha, key_facts(&ctx, &net, &body_value, "docs/alpha", 1));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&alpha)).unwrap();

    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyUnwrapFailed(_)));
}

#[tokio::test]
async fn key_decrypt_refuses_key_version_mismatch() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let loc = key_loc("docs/alpha");
    let key = svc.create_key(&loc, false).await.unwrap();
    let ctx = make_client_request(&key.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "docs/alpha", 2);
    let invocation = key_invocation(&loc, key_facts(&ctx, &net, &body_value, "docs/alpha", 2));
    let target = DecryptTarget::from_resource(&canonical_key_urn(&loc)).unwrap();

    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::AlgKeyVersionMismatch));
}

#[test]
fn decrypt_target_classifies_resources() {
    let net = network_id();
    assert!(matches!(
        &DecryptTarget::from_resource(&net.to_string()),
        Ok(DecryptTarget::Root(n)) if n == &net
    ));
    let loc = key_loc("docs/alpha");
    assert!(matches!(
        DecryptTarget::from_resource(&canonical_key_urn(&loc)),
        Ok(DecryptTarget::Key { .. })
    ));
    let prefix = format!(
        "urn:tinycloud:encryption:{}:{}/docs/",
        owner_did(),
        NETWORK_NAME
    );
    assert!(matches!(
        DecryptTarget::from_resource(&prefix),
        Err(EncryptionServiceError::Unauthorized)
    ));
    assert!(matches!(
        DecryptTarget::from_resource("not-a-resource"),
        Err(EncryptionServiceError::Unauthorized)
    ));
}

#[tokio::test]
async fn root_decrypt_refuses_a_key_capability() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    let mut facts = key_facts(&ctx, &net, &body_value, "docs/alpha", 1);
    facts.as_object_mut().unwrap().remove("keyPath");
    let loc = key_loc("docs/alpha");
    let invocation = key_invocation(&loc, facts);

    let err = svc
        .decrypt_authorized(&DecryptTarget::Root(net.clone()), &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NetworkMismatch));
}

#[tokio::test]
async fn denied_audit_row_for_root_target_never_takes_the_request_key_path() {
    let db = fresh_db().await;
    let svc = make_service(db.clone());
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let (_, body_value) = build_body(&ctx, &net);
    // Denied before `check_decrypt_scope`: the request names a key path the root target never had.
    let facts = serde_json::to_value(DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: "did:key:z6MkOther".to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(&body_value),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.wrapped_key),
        )),
        receiver_public_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.receiver_pub),
        )),
        key_path: Some("docs/alpha".to_string()),
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    })
    .unwrap();
    let invocation = build_session_invocation_info(&net, DECRYPT_ACTION, vec![facts], NODE_DID);

    let err = svc
        .decrypt_authorized(
            &crate::encryption_network::DecryptTarget::Root(net.clone()),
            &invocation,
            &body_value,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::TargetNodeMismatch));

    let rows = crate::models::encryption_audit::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "denied:target-node");
    assert_eq!(rows[0].key_path, None);
}

#[tokio::test]
async fn decrypt_authorized_refuses_a_low_order_receiver_key() {
    let svc = make_service(fresh_db().await);
    let net = network_id();
    let descriptor = svc
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    let ctx = make_client_request(&descriptor.public_encryption_key);
    let low_order = [0u8; 32];
    let (_, mut body_value) = build_body(&ctx, &net);
    body_value["receiverPublicKey"] = serde_json::json!(STANDARD.encode(low_order));
    let facts = serde_json::to_value(DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        body_hash: canonical_hash(&body_value),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(
            STANDARD.encode(&ctx.wrapped_key),
        )),
        receiver_public_key_hash: canonical_hash(&Value::String(STANDARD.encode(low_order))),
        key_path: None,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    })
    .unwrap();
    let invocation = build_session_invocation_info(&net, DECRYPT_ACTION, vec![facts], NODE_DID);

    let err = svc
        .decrypt_authorized(
            &crate::encryption_network::DecryptTarget::Root(net.clone()),
            &invocation,
            &body_value,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        EncryptionServiceError::InvalidReceiverPublicKey
    ));
    assert!(
        err.to_string().starts_with("receiver_key_invalid: "),
        "{err}"
    );
}

// Deletable keys (paths under `apps/`), state guards, reinstall and caps.

use crate::encryption_network::backend::KeyBackend;
use crate::encryption_network::keys::{ensure_no_deterministic_app_keys, KeyDescriptor};

fn key_vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/encryption/app-key-vectors.json"
    ))
    .expect("vector file parses")
}

async fn key_row(db: &DatabaseConnection, path: &str) -> encryption_network_key::Model {
    encryption_network_key::Entity::find_by_id((network_id().to_string(), path.to_string()))
        .one(db)
        .await
        .unwrap()
        .expect("key row exists")
}

/// Writes `state` and `sealed_seed` straight into a key row.
async fn force_row(db: &DatabaseConnection, path: &str, state: &str, sealed_seed: Option<Vec<u8>>) {
    let mut row: encryption_network_key::ActiveModel = key_row(db, path).await.into();
    row.state = Set(state.to_string());
    row.sealed_seed = Set(sealed_seed);
    row.update(db).await.unwrap();
}

async fn insert_raw_row(db: &DatabaseConnection, path: &str, kind: &str, seed: Option<Vec<u8>>) {
    encryption_network_key::ActiveModel {
        network_id: Set(network_id().to_string()),
        key_path: Set(path.to_string()),
        kind: Set(kind.to_string()),
        state: Set("active".to_string()),
        public_key: Set(vec![7u8; 32]),
        sealed_seed: Set(seed),
        key_version: Set(1),
        created_at: Set("2026-01-01T00:00:00Z".to_string()),
        updated_at: Set("2026-01-01T00:00:00Z".to_string()),
    }
    .insert(db)
    .await
    .unwrap();
}

async fn service_with_network() -> (DatabaseConnection, EncryptionService) {
    let db = fresh_db().await;
    let svc = make_service(db.clone());
    create_network(&svc).await;
    (db, svc)
}

async fn deleted_app_key(
    db: &DatabaseConnection,
    svc: &EncryptionService,
    path: &str,
) -> KeyDescriptor {
    let created = svc.create_key(&key_loc(path), true).await.unwrap();
    force_row(db, path, "deleted", None).await;
    created
}

#[tokio::test]
async fn app_key_is_deletable_seeded_and_differs_from_the_deterministic_derivation() {
    let (db, svc) = service_with_network().await;
    let loc = key_loc("apps/foo/x");
    let created = svc.create_key(&loc, true).await.unwrap();
    assert_eq!(created.kind, "deletable");
    assert_eq!(created.state, KeyState::Active);
    assert_eq!(created.key_version, 1);

    let row = key_row(&db, "apps/foo/x").await;
    let sealed = row.sealed_seed.expect("a deletable key stores a seed");
    assert_eq!(sealed[0], 0x01, "sealed with the column key");
    let backend = LocalOneOfOneBackend::new(ColumnEncryption::new([0xABu8; 32]));
    assert!(backend.open_seed(&sealed).is_ok());

    // The same URN derived without the seed is a different key.
    let network_row =
        crate::models::encryption_network::Entity::find_by_id(network_id().to_string())
            .one(&db)
            .await
            .unwrap()
            .unwrap();
    let network_secret = backend
        .open_network_secret(network_row.sealed_private_key.as_deref().unwrap())
        .unwrap();
    let unseeded = backend
        .derive_named_public_key(&network_secret, &canonical_key_urn(&loc), None)
        .unwrap();
    assert_ne!(created.public_encryption_key, unseeded);

    // Two deletable keys never share a seed.
    svc.create_key(&key_loc("apps/foo/y"), true).await.unwrap();
    assert_ne!(
        key_row(&db, "apps/foo/y").await.sealed_seed,
        key_row(&db, "apps/foo/x").await.sealed_seed
    );
}

#[tokio::test]
async fn deterministic_key_stores_no_seed_and_deletable_flag_must_match_the_path() {
    let (db, svc) = service_with_network().await;
    let created = svc.create_key(&key_loc("docs/a"), false).await.unwrap();
    assert_eq!(created.kind, "deterministic");
    assert!(key_row(&db, "docs/a").await.sealed_seed.is_none());

    let vectors = key_vectors();
    let cases = vectors["createFlagMatchesPath"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let path = case["keyPath"].as_str().unwrap();
        let deletable = case["deletable"].as_bool().unwrap();
        let accepted = case["accepted"].as_bool().unwrap();
        let result = svc.create_key(&key_loc(path), deletable).await;
        if accepted {
            result.unwrap_or_else(|e| panic!("{path} {deletable}: {e}"));
        } else {
            assert!(
                matches!(result, Err(EncryptionServiceError::KeyPathInvalid(_))),
                "{path} {deletable}: {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn app_key_unwraps_only_at_its_own_version_and_path() {
    let (_, svc) = service_with_network().await;
    let loc = key_loc("apps/foo/x");
    let key = svc.create_key(&loc, true).await.unwrap();
    let symmetric = vec![0x5Au8; 32];
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &symmetric).unwrap();
    let (version, opened) = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap();
    assert_eq!((version, opened), (1, symmetric));

    // A request for another version is refused before any unwrap.
    for requested in [0, 2] {
        let err = svc
            .unwrap_named_key(&loc, &wrapped, requested)
            .await
            .unwrap_err();
        assert!(matches!(err, EncryptionServiceError::KeyDeleted), "{err:?}");
    }
    // A sibling app key cannot open it.
    svc.create_key(&key_loc("apps/foo/y"), true).await.unwrap();
    let err = svc
        .unwrap_named_key(&key_loc("apps/foo/y"), &wrapped, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyUnwrapFailed(_)));
}

#[tokio::test]
async fn deleted_row_refuses_block_unblock_unwrap_and_keeps_its_state() {
    let (db, svc) = service_with_network().await;
    let loc = key_loc("apps/foo/x");
    let created = deleted_app_key(&db, &svc, "apps/foo/x").await;
    let wrapped = wrap_to_public_key(&created.public_encryption_key, &[1u8; 32]).unwrap();

    for (name, err) in [
        ("block", svc.block_key(&loc).await.unwrap_err()),
        ("unblock", svc.unblock_key(&loc).await.unwrap_err()),
        (
            "unwrap",
            svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap_err(),
        ),
    ] {
        assert!(
            matches!(err, EncryptionServiceError::KeyDeleted),
            "{name}: {err:?}"
        );
    }
    let row = key_row(&db, "apps/foo/x").await;
    assert_eq!(row.state, "deleted");
    assert!(row.sealed_seed.is_none());
    assert_eq!(row.key_version, 1);
    let described = svc.describe_key(&loc).await.unwrap();
    assert_eq!(described.state, KeyState::Deleted);
}

#[tokio::test]
async fn deleted_deterministic_row_stays_burned() {
    let (db, svc) = service_with_network().await;
    let loc = key_loc("docs/a");
    svc.create_key(&loc, false).await.unwrap();
    force_row(&db, "docs/a", "deleted", None).await;
    let err = svc.create_key(&loc, false).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyDeleted), "{err:?}");
    let err = svc.unblock_key(&loc).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyDeleted), "{err:?}");
    let row = key_row(&db, "docs/a").await;
    assert_eq!((row.state.as_str(), row.key_version), ("deleted", 1));
}

#[tokio::test]
async fn create_on_a_deleted_app_key_reinstalls_it_with_a_fresh_seed_and_next_version() {
    let (db, svc) = service_with_network().await;
    let loc = key_loc("apps/foo/x");
    let old = deleted_app_key(&db, &svc, "apps/foo/x").await;
    let old_wrapped = wrap_to_public_key(&old.public_encryption_key, &[9u8; 32]).unwrap();

    let fresh = svc.create_key(&loc, true).await.unwrap();
    assert_eq!(fresh.state, KeyState::Active);
    assert_eq!(fresh.key_version, 2);
    assert_eq!(fresh.created_at, old.created_at);
    assert_ne!(fresh.public_encryption_key, old.public_encryption_key);
    let row = key_row(&db, "apps/foo/x").await;
    assert!(row.sealed_seed.is_some());

    // Data wrapped to the old key and the old version are not released.
    let err = svc
        .unwrap_named_key(&loc, &old_wrapped, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyDeleted), "{err:?}");
    let err = svc
        .unwrap_named_key(&loc, &old_wrapped, 2)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyUnwrapFailed(_)),
        "{err:?}"
    );
    // The new key works at its version.
    let wrapped = wrap_to_public_key(&fresh.public_encryption_key, &[3u8; 32]).unwrap();
    let (version, opened) = svc.unwrap_named_key(&loc, &wrapped, 2).await.unwrap();
    assert_eq!((version, opened), (2, vec![3u8; 32]));

    // Another create on the now-active key does not replace the seed.
    let seed_before = key_row(&db, "apps/foo/x").await.sealed_seed;
    let err = svc.create_key(&loc, true).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyExists), "{err:?}");
    assert_eq!(key_row(&db, "apps/foo/x").await.sealed_seed, seed_before);
}

#[tokio::test]
async fn blocked_app_key_is_not_reinstalled_by_create() {
    let (db, svc) = service_with_network().await;
    let loc = key_loc("apps/foo/x");
    svc.create_key(&loc, true).await.unwrap();
    svc.block_key(&loc).await.unwrap();
    let seed = key_row(&db, "apps/foo/x").await.sealed_seed;
    let err = svc.create_key(&loc, true).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyExists), "{err:?}");
    let row = key_row(&db, "apps/foo/x").await;
    assert_eq!((row.state.as_str(), row.key_version), ("blocked", 1));
    assert_eq!(row.sealed_seed, seed);
}

#[tokio::test]
async fn rows_that_cannot_be_read_as_keys_are_corrupt() {
    let (db, svc) = service_with_network().await;
    // A deletable row that is not deleted and has no seed.
    svc.create_key(&key_loc("apps/foo/x"), true).await.unwrap();
    force_row(&db, "apps/foo/x", "active", None).await;
    // A deletable row whose seed is 32 zero bytes, which is not a sealed
    // value: a seed opens only through the versioned, authenticated unseal.
    svc.create_key(&key_loc("apps/foo/y"), true).await.unwrap();
    force_row(&db, "apps/foo/y", "active", Some(vec![0u8; 32])).await;
    // A deterministic row under apps/, and a deletable row outside it.
    insert_raw_row(&db, "apps/foo/z", "deterministic", None).await;
    insert_raw_row(&db, "docs/seeded", "deletable", Some(vec![1u8; 61])).await;

    for path in ["apps/foo/x", "apps/foo/z", "docs/seeded"] {
        let loc = key_loc(path);
        let deletable = loc.kind() == crate::encryption_network::key_id::KeyKind::Deletable;
        for result in [
            svc.unwrap_named_key(&loc, &[0u8; 96], 1).await.map(|_| ()),
            svc.describe_key(&loc).await.map(|_| ()),
            svc.block_key(&loc).await.map(|_| ()),
            svc.unblock_key(&loc).await.map(|_| ()),
            svc.create_key(&loc, deletable).await.map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(EncryptionServiceError::CorruptKeyRow)),
                "{path}: {result:?}"
            );
        }
    }
    // A zeroed seed does not open when the key is read.
    let err = svc
        .unwrap_named_key(&key_loc("apps/foo/y"), &[0u8; 96], 1)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "{err:?}"
    );
}

#[tokio::test]
async fn public_get_under_apps_never_answers_with_a_key() {
    let (db, svc) = service_with_network().await;
    svc.create_key(&key_loc("apps/foo/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/foo/blocked"), true)
        .await
        .unwrap();
    svc.block_key(&key_loc("apps/foo/blocked")).await.unwrap();
    deleted_app_key(&db, &svc, "apps/foo/gone").await;
    for path in [
        "apps/foo/x",
        "apps/foo/blocked",
        "apps/foo/gone",
        "apps/foo/missing",
        "apps/other/missing",
    ] {
        let err = svc.public_key(&key_loc(path)).await.unwrap_err();
        assert!(
            matches!(err, EncryptionServiceError::KeyNotFound),
            "{path}: {err:?}"
        );
    }
    // The answer does not read the network: it is the same for a revoked one.
    svc.revoke_network(&network_id()).await.unwrap();
    let err = svc.public_key(&key_loc("apps/foo/x")).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyNotFound),
        "{err:?}"
    );
    // Outside apps/ the network state is checked: a revoked network is refused.
    let err = svc.public_key(&key_loc("docs/a")).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::NetworkNotActive(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn per_app_prefix_cap_counts_deleted_rows_until_they_are_reused() {
    let db = fresh_db().await;
    let svc = make_service(db.clone()).with_key_cap_per_app_prefix(2);
    create_network(&svc).await;
    svc.create_key(&key_loc("apps/a/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/a/y/deep"), true)
        .await
        .unwrap();
    let err = svc
        .create_key(&key_loc("apps/a/z"), true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyLimitExceeded),
        "{err:?}"
    );
    // Other prefixes, including one that only shares leading bytes, are separate.
    svc.create_key(&key_loc("apps/ab/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/b/x"), true).await.unwrap();
    svc.create_key(&key_loc("docs/a"), false).await.unwrap();

    // A deleted row still counts; reusing it adds no row.
    force_row(&db, "apps/a/x", "deleted", None).await;
    let err = svc
        .create_key(&key_loc("apps/a/z"), true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyLimitExceeded),
        "{err:?}"
    );
    let reused = svc.create_key(&key_loc("apps/a/x"), true).await.unwrap();
    assert_eq!(reused.key_version, 2);
}

#[tokio::test]
async fn per_network_cap_counts_deleted_rows() {
    let db = fresh_db().await;
    let svc = make_service(db.clone()).with_key_cap_per_network(1);
    create_network(&svc).await;
    svc.create_key(&key_loc("apps/a/x"), true).await.unwrap();
    force_row(&db, "apps/a/x", "deleted", None).await;
    let err = svc.create_key(&key_loc("docs/a"), false).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyLimitExceeded),
        "{err:?}"
    );
    svc.create_key(&key_loc("apps/a/x"), true).await.unwrap();
}

#[tokio::test]
async fn startup_check_finds_rows_under_apps_that_are_not_deletable() {
    let (db, svc) = service_with_network().await;
    svc.create_key(&key_loc("docs/a"), false).await.unwrap();
    svc.create_key(&key_loc("appsx/y"), false).await.unwrap();
    svc.create_key(&key_loc("apps/foo/x"), true).await.unwrap();
    ensure_no_deterministic_app_keys(&db).await.unwrap();

    insert_raw_row(&db, "apps/foo/old", "deterministic", None).await;
    insert_raw_row(&db, "apps", "deterministic", None).await;
    let err = ensure_no_deterministic_app_keys(&db).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::StrayAppKeyRows(2)),
        "{err:?}"
    );
    assert!(err.to_string().contains("SELECT network_id, key_path"));
}

// PostgreSQL-backed; CI-only. Concurrent creates on one deleted app key
// reinstall it exactly once.
#[tokio::test]
async fn postgres_concurrent_reinstall_creates_bump_the_version_once() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_concurrent_reinstall_creates_bump_the_version_once",
        None,
    )
    .await
    else {
        return;
    };
    let db = fixture.connect(8).await;
    let svc = Arc::new(make_service(db.clone()));
    create_network(&svc).await;
    deleted_app_key(&db, &svc, "apps/foo/x").await;

    let results = futures::future::join_all((0..8).map(|_| {
        let svc = svc.clone();
        async move { svc.create_key(&key_loc("apps/foo/x"), true).await }
    }))
    .await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| matches!(e, EncryptionServiceError::KeyExists)));
    assert_eq!(key_row(&db, "apps/foo/x").await.key_version, 2);
}

// PostgreSQL-backed; CI-only. Block, unblock and create hold the network row
// lock, so a lock held elsewhere stalls them and they release it when done.
#[tokio::test]
async fn postgres_block_and_unblock_take_and_release_the_network_row_lock() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_block_and_unblock_take_and_release_the_network_row_lock",
        None,
    )
    .await
    else {
        return;
    };
    const LOCK: &str = "SELECT 1 FROM encryption_network FOR UPDATE NOWAIT";
    let db = fixture.connect(4).await;
    let svc = Arc::new(make_service(db.clone()));
    create_network(&svc).await;
    svc.create_key(&key_loc("apps/foo/x"), true).await.unwrap();

    svc.block_key(&key_loc("apps/foo/x")).await.unwrap();
    fixture
        .execute_blocking(LOCK)
        .expect("block releases the network row lock");
    svc.unblock_key(&key_loc("apps/foo/x")).await.unwrap();
    fixture
        .execute_blocking(LOCK)
        .expect("unblock releases the network row lock");
    let err = svc
        .block_key(&key_loc("apps/foo/missing"))
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyNotFound));
    fixture
        .execute_blocking(LOCK)
        .expect("a refused block releases the network row lock");

    let results = futures::future::join_all((0..8).map(|i| {
        let svc = svc.clone();
        async move {
            if i % 2 == 0 {
                svc.block_key(&key_loc("apps/foo/x")).await
            } else {
                svc.unblock_key(&key_loc("apps/foo/x")).await
            }
        }
    }))
    .await;
    assert!(results.iter().all(|r| r.is_ok()));
}

#[tokio::test]
async fn per_app_prefix_cap_ignores_keys_of_an_app_id_that_extends_it() {
    let svc = make_service(fresh_db().await).with_key_cap_per_app_prefix(2);
    create_network(&svc).await;
    svc.create_key(&key_loc("apps/ab/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/ab/y"), true).await.unwrap();
    svc.create_key(&key_loc("apps/ab.c/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/a/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/a/y"), true).await.unwrap();
    let err = svc
        .create_key(&key_loc("apps/a/z"), true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyLimitExceeded),
        "{err:?}"
    );
}

// `apps/` keys through the release guard and the key lifecycle.

/// A decrypt request for `body_path` at `version` carrying `key_public` as the
/// wrapping key, authorized by a capability on `capability_loc`.
async fn app_decrypt(
    svc: &EncryptionService,
    key_public: &[u8],
    capability_loc: &KeyLocation,
    body_path: &str,
    version: i64,
) -> Result<(), EncryptionServiceError> {
    let net = network_id();
    let ctx = make_client_request(key_public);
    let (_, body_value) = key_body(&ctx, &net, body_path, version);
    let invocation = key_invocation(
        capability_loc,
        key_facts(&ctx, &net, &body_value, body_path, version),
    );
    let target = DecryptTarget::from_resource(&canonical_key_urn(capability_loc)).unwrap();
    svc.decrypt_authorized(&target, &invocation, &body_value)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn app_key_decrypt_round_trip_returns_rewrapped_key_at_its_version() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let net = network_id();
    let loc = key_loc("apps/foo/alpha");
    let key = svc.create_key(&loc, true).await.unwrap();
    let ctx = make_client_request(&key.public_encryption_key);
    let (_, body_value) = key_body(&ctx, &net, "apps/foo/alpha", 1);
    let invocation = key_invocation(
        &loc,
        key_facts(&ctx, &net, &body_value, "apps/foo/alpha", 1),
    );
    let target = DecryptTarget::from_resource(&canonical_key_urn(&loc)).unwrap();
    let verified = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap();
    assert_eq!(verified.response.key_version, 1);
    let rewrapped = STANDARD
        .decode(&verified.response.wrapped_key)
        .expect("base64 wrapped key");
    assert_eq!(
        unwrap_with_secret(&ctx.receiver_secret, &rewrapped),
        ctx.symmetric
    );
}

#[tokio::test]
async fn app_key_decrypt_refuses_body_key_path_mismatch_and_sibling_capability() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let alpha = key_loc("apps/foo/alpha");
    let beta = key_loc("apps/foo/beta");
    let key = svc.create_key(&alpha, true).await.unwrap();
    svc.create_key(&beta, true).await.unwrap();
    let public = key.public_encryption_key;
    let err = app_decrypt(&svc, &public, &alpha, "apps/foo/beta", 1)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyPathInvalid(_)),
        "{err:?}"
    );
    // The request names alpha while the invocation's capability is on beta.
    let net = network_id();
    let ctx = make_client_request(&public);
    let (_, body_value) = key_body(&ctx, &net, "apps/foo/alpha", 1);
    let invocation = key_invocation(
        &beta,
        key_facts(&ctx, &net, &body_value, "apps/foo/alpha", 1),
    );
    let target = DecryptTarget::from_resource(&canonical_key_urn(&alpha)).unwrap();
    let err = svc
        .decrypt_authorized(&target, &invocation, &body_value)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::Unauthorized),
        "{err:?}"
    );
}

#[tokio::test]
async fn app_key_decrypt_refuses_blocked_missing_and_other_version() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("apps/foo/alpha");
    let key = svc.create_key(&loc, true).await.unwrap();
    let public = key.public_encryption_key;
    let err = app_decrypt(&svc, &public, &loc, "apps/foo/alpha", 2)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyDeleted), "{err:?}");

    svc.block_key(&loc).await.unwrap();
    let err = app_decrypt(&svc, &public, &loc, "apps/foo/alpha", 1)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyBlocked), "{err:?}");
    svc.unblock_key(&loc).await.unwrap();
    app_decrypt(&svc, &public, &loc, "apps/foo/alpha", 1)
        .await
        .expect("an unblocked key decrypts");

    let missing = key_loc("apps/foo/missing");
    let err = app_decrypt(&svc, &public, &missing, "apps/foo/missing", 1)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyNotFound),
        "{err:?}"
    );
}

#[tokio::test]
async fn unwrap_named_key_refuses_blocked_and_missing_app_keys() {
    let svc = make_service(fresh_db().await);
    create_network(&svc).await;
    let loc = key_loc("apps/foo/alpha");
    let key = svc.create_key(&loc, true).await.unwrap();
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &[0x5Au8; 32]).unwrap();
    svc.block_key(&loc).await.unwrap();
    let err = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyBlocked), "{err:?}");
    let err = svc
        .unwrap_named_key(&key_loc("apps/foo/missing"), &wrapped, 1)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyNotFound),
        "{err:?}"
    );
}

#[tokio::test]
async fn app_keys_need_an_existing_active_network() {
    let svc = make_service(fresh_db().await);
    let loc = key_loc("apps/foo/alpha");
    let err = svc.create_key(&loc, true).await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::NetworkNotFound),
        "{err:?}"
    );

    create_network(&svc).await;
    let key = svc.create_key(&loc, true).await.unwrap();
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &[0x5Au8; 32]).unwrap();
    svc.revoke_network(&network_id()).await.unwrap();
    let err = svc
        .create_key(&key_loc("apps/foo/beta"), true)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EncryptionServiceError::NetworkNotActive(s) if s == "revoked"),
        "{err:?}"
    );
    let err = svc.unwrap_named_key(&loc, &wrapped, 1).await.unwrap_err();
    assert!(
        matches!(&err, EncryptionServiceError::NetworkNotActive(s) if s == "revoked"),
        "{err:?}"
    );
}

#[tokio::test]
async fn unknown_stored_state_on_an_app_key_is_a_corrupt_row() {
    let (db, svc) = service_with_network().await;
    let loc = key_loc("apps/foo/alpha");
    let key = svc.create_key(&loc, true).await.unwrap();
    let wrapped = wrap_to_public_key(&key.public_encryption_key, &[0x5Au8; 32]).unwrap();
    let seed = key_row(&db, "apps/foo/alpha").await.sealed_seed;
    force_row(&db, "apps/foo/alpha", "retired", seed).await;
    for result in [
        svc.unwrap_named_key(&loc, &wrapped, 1).await.map(|_| ()),
        svc.describe_key(&loc).await.map(|_| ()),
        svc.block_key(&loc).await.map(|_| ()),
        svc.unblock_key(&loc).await.map(|_| ()),
        svc.create_key(&loc, true).await.map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(EncryptionServiceError::CorruptKeyRow)),
            "{result:?}"
        );
    }
}

// PostgreSQL-backed; CI-only. Block, unblock and create wait for the network
// row lock: with a transaction on a second pool holding it, each operation is
// still pending after 800 ms and completes once the lock is released.
#[tokio::test]
async fn postgres_key_writes_wait_for_the_network_row_lock() {
    use sea_orm::{ConnectionTrait, TransactionTrait};
    use std::time::Duration;

    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_key_writes_wait_for_the_network_row_lock",
        None,
    )
    .await
    else {
        return;
    };
    let db = fixture.connect(4).await;
    let holder_pool = fixture.connect(1).await;
    let svc = Arc::new(make_service(db.clone()));
    create_network(&svc).await;
    svc.create_key(&key_loc("apps/foo/x"), true).await.unwrap();
    svc.create_key(&key_loc("apps/foo/gone"), true)
        .await
        .unwrap();
    force_row(&db, "apps/foo/gone", "deleted", None).await;

    for operation in ["block", "unblock", "create", "reinstall"] {
        let lock = holder_pool.begin().await.unwrap();
        lock.execute_unprepared("SELECT 1 FROM encryption_network FOR UPDATE")
            .await
            .unwrap();
        let pending = {
            let svc = svc.clone();
            tokio::spawn(async move {
                match operation {
                    "block" => svc.block_key(&key_loc("apps/foo/x")).await,
                    "unblock" => svc.unblock_key(&key_loc("apps/foo/x")).await,
                    "create" => svc.create_key(&key_loc("apps/foo/new"), true).await,
                    _ => svc.create_key(&key_loc("apps/foo/gone"), true).await,
                }
            })
        };
        let mut pending = pending;
        assert!(
            tokio::time::timeout(Duration::from_millis(800), &mut pending)
                .await
                .is_err(),
            "{operation} finished while the network row lock was held"
        );
        lock.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(20), pending)
            .await
            .unwrap_or_else(|_| panic!("{operation} did not finish after the lock was released"))
            .unwrap();
        result.unwrap_or_else(|e| panic!("{operation}: {e}"));
    }
}
