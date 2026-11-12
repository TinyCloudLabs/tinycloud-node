//! Test-only known-answer vector for an owner-signed UCAN renewal lease.
//!
//! This pins a real signed lease token and canonical raw-CID binding. Fixed keys
//! are public test data only; no runtime renewal code is exercised here.

use base64::{encode_config, URL_SAFE};
use ed25519_dalek::{Signer, SigningKey, Verifier};
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
    renewal::{period_seconds as runtime_period_seconds, OriginalFormat},
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

    let TinyCloudDelegation::Ucan(original_ucan) =
        TinyCloudDelegation::decode(&original_token).unwrap().0
    else {
        panic!("original vector is a UCAN");
    };
    let original_payload = original_ucan.payload();
    let original_not_before = original_payload
        .not_before
        .expect("owner-signed original nbf")
        .as_seconds();
    let original_expiration = original_payload.expiration.as_seconds();
    let period_seconds = original_expiration - original_not_before;
    assert_eq!(
        runtime_period_seconds(
            original_expiration as i64,
            Some(original_not_before as i64),
            None,
            OriginalFormat::Ucan,
        )
        .unwrap(),
        period_seconds as i64,
        "the runtime period is derived from the owner's signed original claims",
    );
    assert_eq!(period_seconds, 2_592_000.0);

    let TinyCloudDelegation::Ucan(lease_ucan) =
        TinyCloudDelegation::decode(&lease_token).unwrap().0
    else {
        panic!("lease vector is a UCAN");
    };
    let lease_payload = lease_ucan.payload();
    let lease_not_before = lease_payload
        .not_before
        .expect("owner-signed lease nbf")
        .as_seconds();
    let lease_expiration = lease_payload.expiration.as_seconds();
    let lease_lifetime_seconds = lease_expiration - lease_not_before;
    assert_eq!(lease_lifetime_seconds, 31_536_000.0);

    let first_stamp_now = original_expiration - 86_400.0;
    let first_stamp_end = (first_stamp_now + period_seconds).min(lease_expiration);
    assert_eq!(
        first_stamp_end,
        original_expiration + period_seconds - 86_400.0
    );
    let near_lease_end = lease_expiration - 86_400.0;
    assert_eq!(
        (near_lease_end + period_seconds).min(lease_expiration),
        lease_expiration,
        "the 365-day lease expiry remains an independent upper bound"
    );
    let first_stamp_new_end = time::OffsetDateTime::from_unix_timestamp(first_stamp_end as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let node_did = node_secret.node_did();
    assert_ne!(node_did, renewer_did);
    let first_stamp = json!({
        "domain": "tinycloud/node/renewal-stamp/v1",
        "unsigned": {
            "type": "TinyCloudRenewalStamp",
            "version": 1,
            "originalCid": original_cid,
            "leaseCid": lease_cid,
            "leaseGeneration": 1,
            "previousStampCid": lease_cid,
            "nodeDid": node_did,
            "renewerEpoch": 1,
            "newEnd": first_stamp_new_end,
        },
    });
    let first_stamp_bytes = serde_ipld_dagcbor::to_vec(&first_stamp).unwrap();
    let stamp_signer = SigningKey::from_bytes(&renewer_seed);
    let first_stamp_signature = stamp_signer.sign(&first_stamp_bytes);
    stamp_signer
        .verifying_key()
        .verify(&first_stamp_bytes, &first_stamp_signature)
        .unwrap();
    let first_stamp_cid = hash(&first_stamp_bytes).to_cid(0x55).to_string();
    let first_stamp_vector = json!({
        "stamp": first_stamp,
        "canonicalDagCborHex": hex::encode(&first_stamp_bytes),
        "stampCid": first_stamp_cid,
        "signerDid": renewer_did,
        "signerPublicKeyHex": hex::encode(stamp_signer.verifying_key().to_bytes()),
        "signatureHex": hex::encode(first_stamp_signature.to_bytes()),
    });
    assert_eq!(
        first_stamp_vector["stamp"]["unsigned"]["leaseCid"],
        lease_cid
    );
    assert_eq!(
        first_stamp_vector["stamp"]["unsigned"]["previousStampCid"],
        lease_cid
    );
    let vector = json!({
        "schema": "tinycloud/node/renewal-lease-vector/v1",
        "testOnlyOwnerSeedHex": hex::encode(OWNER_SEED),
        "testOnlyHolderSeedHex": hex::encode(HOLDER_SEED),
        "testOnlyNodeStaticSecretHex": hex::encode(NODE_STATIC_SECRET),
        "renewerKeyContext": String::from_utf8_lossy(RENEWER_CONTEXT),
        "issuedAt": ISSUED_AT as u64,
        "originalExpiration": ORIGINAL_EXPIRY as u64,
        "leaseExpiration": LEASE_EXPIRY as u64,
        "renewalPeriodSource": "owner-signed original exp - nbf",
        "renewalPeriodSeconds": period_seconds as u64,
        "leaseLifetimeSeconds": lease_lifetime_seconds as u64,
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
        "firstStamp": first_stamp_vector,
        "nodeIdentityDid": node_did,
    });

    let fixture: Value = serde_json::from_str(include_str!("fixtures/renewal-lease-v1.json"))
        .expect("renewal lease fixture parses");
    assert_eq!(
        fixture["firstStamp"]["stamp"]["unsigned"]["leaseCid"], fixture["leaseCid"],
        "the first stamp is rooted at the real signed lease CID"
    );
    assert_eq!(
        fixture["firstStamp"]["stamp"]["unsigned"]["previousStampCid"], fixture["leaseCid"],
        "the first previous stamp is the real signed lease CID"
    );
    assert_eq!(
        fixture["renewalPeriodSeconds"], period_seconds as u64,
        "renewal period comes from the owner's signed original exp - nbf"
    );
    assert_eq!(
        vector, fixture,
        "pin the complete signed UCAN and stamp vectors"
    );
}
#[test]
fn runtime_signer_reproduces_the_frozen_linked_first_stamp() {
    assert_eq!(RENEWER_CONTEXT, b"tinycloud/node/renewer/v1");
    let fixture: Value = serde_json::from_str(include_str!("fixtures/renewal-lease-v1.json"))
        .expect("renewal lease fixture parses");
    let secret = StaticSecret::new(NODE_STATIC_SECRET.to_vec()).expect("fixed test secret");
    let signer = tinycloud_core::renewal::RenewalSigner::from_seed(
        secret.derive_key(RENEWER_CONTEXT),
        secret.node_did(),
        1,
    );
    let stamp = &fixture["firstStamp"];
    let unsigned = &stamp["stamp"]["unsigned"];
    let (bytes, signature, cid) = signer
        .sign_stamp(
            fixture["originalCid"].as_str().unwrap(),
            fixture["leaseCid"].as_str().unwrap(),
            unsigned["leaseGeneration"].as_u64().unwrap(),
            unsigned["previousStampCid"].as_str().unwrap(),
            unsigned["newEnd"].as_str().unwrap(),
        )
        .expect("runtime stamp encoding succeeds");

    assert_eq!(hex::encode(&bytes), stamp["canonicalDagCborHex"]);
    assert_eq!(cid, stamp["stampCid"]);
    assert_eq!(hex::encode(&signature), stamp["signatureHex"]);
}
