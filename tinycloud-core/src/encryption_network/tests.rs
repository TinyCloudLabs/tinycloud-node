//! Integration tests covering decrypt authorization, hash bindings, replay
//! protection, ceremony state, and network lookup. These exercise the public
//! API of [`EncryptionService`] against a sqlite in-memory database.

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait};
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
use crate::models::encryption_ceremony;

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
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    })
    .unwrap();
    let invocation = build_session_invocation_info(&net, DECRYPT_ACTION, vec![facts], NODE_DID);

    let verified = svc
        .decrypt_authorized(&net, &invocation, &body_value)
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
        .decrypt_authorized(&net, &invocation, &body_value)
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
