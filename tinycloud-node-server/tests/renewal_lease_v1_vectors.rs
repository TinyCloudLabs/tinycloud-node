//! Test-only known-answer vector for an owner-signed UCAN renewal lease.
//!
//! This pins a real signed lease token and canonical raw-CID binding. Fixed keys
//! are public test data only; no runtime renewal code is exercised here.

use base64::{encode_config, URL_SAFE};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    resolver::DID_METHODS,
    siwe_recap::Ability,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::hash,
    keys::{public_key_to_did_key, Keypair, StaticSecret},
};

const OWNER_SEED: [u8; 32] = [0x11; 32];
const HOLDER_SEED: [u8; 32] = [0x22; 32];
const NODE_STATIC_SECRET: [u8; 32] = [0x42; 32];
const RENEWER_CONTEXT: &[u8] = b"tinycloud/node/renewer/v1";
const ISSUED_AT: f64 = 1_700_000_000.0;
const ORIGINAL_EXPIRY: f64 = 1_702_592_000.0;
const LEASE_EXPIRY: f64 = 1_731_536_000.0;

fn fixed_ed25519_jwk(seed: [u8; 32]) -> JWK {
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let x = encode_config(signer.verifying_key().to_bytes(), URL_SAFE)
        .trim_end_matches('=')
        .to_owned();
    let d = encode_config(seed, URL_SAFE)
        .trim_end_matches('=')
        .to_owned();
    serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": x,
        "d": d,
    }))
    .expect("fixed Ed25519 JWK")
}

fn did_and_verification_method(jwk: &JWK) -> (String, String) {
    let did = DID_METHODS
        .generate(jwk, "key")
        .expect("did:key resolves from JWK")
        .to_string();
    let method = format!("{did}#{}", did.trim_start_matches("did:key:"));
    (did, method)
}

fn signed_ucan(
    issuer_jwk: &JWK,
    issuer_method: &str,
    audience: &str,
    resource: &str,
    ability: &str,
    nonce: &str,
    expiration: f64,
) -> String {
    let mut capabilities = Capabilities::<Value>::new();
    capabilities.with_action(
        resource.parse().expect("test resource parses"),
        ability.parse::<Ability>().expect("test ability parses"),
        [BTreeMap::<String, Value>::new()],
    );
    Payload::<Value> {
        issuer: issuer_method
            .parse()
            .expect("issuer verification method parses"),
        audience: audience.parse().expect("audience DID parses"),
        not_before: Some(NumericDate::try_from_seconds(ISSUED_AT).unwrap()),
        expiration: NumericDate::try_from_seconds(expiration).unwrap(),
        nonce: Some(nonce.to_owned()),
        facts: None,
        proof: Vec::new(),
        attenuation: capabilities,
    }
    .sign(Algorithm::EdDSA, issuer_jwk)
    .expect("UCAN signs with the owner key")
    .encode()
    .expect("UCAN encodes as its signed token")
}

fn canonical_ucan_cid(token: &str) -> String {
    let (delegation, bytes) = TinyCloudDelegation::decode(token).expect("signed UCAN decodes");
    assert!(matches!(delegation, TinyCloudDelegation::Ucan(_)));
    assert_eq!(bytes, token.as_bytes());
    hash(&bytes).to_cid(0x55).to_string()
}

#[test]
fn renewal_lease_v1_pins_real_owner_signed_ucan_and_exact_original_cid() {
    let owner_jwk = fixed_ed25519_jwk(OWNER_SEED);
    let holder_jwk = fixed_ed25519_jwk(HOLDER_SEED);
    let (owner_did, owner_method) = did_and_verification_method(&owner_jwk);
    let (holder_did, _) = did_and_verification_method(&holder_jwk);

    let node_secret = StaticSecret::new(NODE_STATIC_SECRET.to_vec()).unwrap();
    let renewer_seed = node_secret.derive_key(RENEWER_CONTEXT);
    let renewer_key = Keypair::ed25519_from_bytes(renewer_seed).unwrap();
    let renewer_did = public_key_to_did_key(renewer_key.public());
    let renewer_jwk = fixed_ed25519_jwk(renewer_seed);
    let (derived_renewer_did, _) = did_and_verification_method(&renewer_jwk);
    assert_eq!(renewer_did, derived_renewer_did);

    let resource_cid = hash(b"renewal-lease-vector-content-v1").to_cid(0x55);
    let original_resource = format!("urn:cid:{resource_cid}");
    let original_token = signed_ucan(
        &owner_jwk,
        &owner_method,
        &holder_did,
        &original_resource,
        "tinycloud.kv/get",
        "renewal-lease-vector-original-v1",
        ORIGINAL_EXPIRY,
    );
    let original_cid = canonical_ucan_cid(&original_token);
    let lease_resource = format!("urn:cid:{original_cid}");
    let lease_token = signed_ucan(
        &owner_jwk,
        &owner_method,
        &renewer_did,
        &lease_resource,
        "tinycloud.delegation/renew",
        "renewal-lease-vector-lease-v1",
        LEASE_EXPIRY,
    );
    let lease_cid = canonical_ucan_cid(&lease_token);

    let vector = json!({
        "schema": "tinycloud/node/renewal-lease-vector/v1",
        "testOnlyOwnerSeedHex": hex::encode(OWNER_SEED),
        "testOnlyHolderSeedHex": hex::encode(HOLDER_SEED),
        "testOnlyNodeStaticSecretHex": hex::encode(NODE_STATIC_SECRET),
        "renewerKeyContext": String::from_utf8_lossy(RENEWER_CONTEXT),
        "issuedAt": ISSUED_AT as u64,
        "originalExpiration": ORIGINAL_EXPIRY as u64,
        "leaseExpiration": LEASE_EXPIRY as u64,
        "ownerDid": owner_did,
        "holderDid": holder_did,
        "renewerDid": renewer_did,
        "originalResource": original_resource,
        "originalAbility": "tinycloud.kv/get",
        "originalToken": original_token,
        "originalCid": original_cid,
        "renewAbility": "tinycloud.delegation/renew",
        "renewResource": lease_resource,
        "leaseToken": lease_token,
        "leaseCid": lease_cid,
    });

    let fixture: Value = serde_json::from_str(include_str!("fixtures/renewal-lease-v1.json"))
        .expect("renewal lease fixture parses");
    assert_eq!(vector, fixture, "pin the complete signed UCAN vector");
}
