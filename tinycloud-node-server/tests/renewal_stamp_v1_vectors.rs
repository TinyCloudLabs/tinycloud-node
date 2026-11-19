//! Contract-only known-answer vector for the v1 renewal stamp.
//!
//! The fixture pins canonical DAG-CBOR bytes, the raw-Blake3 CID, and the
//! detached Ed25519 signature before runtime implementation. Its fixed master
//! seed is synthetic and public; it is not a production key.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use tinycloud_core::{hash::hash, keys::StaticSecret};

fn raw_blake3_cid(bytes: &[u8]) -> String {
    hash(bytes).to_cid(0x55).to_string()
}

fn dag_cbor(value: &Value) -> Vec<u8> {
    serde_ipld_dagcbor::to_vec(value).expect("test vector DAG-CBOR serializes")
}

fn decode_hex(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid fixture hex")
}

#[test]
fn renewal_stamp_v1_matches_pinned_bytes_cid_and_signature() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/renewal-stamp-v1.json"))
        .expect("renewal vector JSON parses");
    let key_context = fixture["renewerKeyContext"].as_str().unwrap().as_bytes();
    let domain = fixture["stampDomain"].as_str().unwrap();
    let master_secret = decode_hex(&fixture["testOnlyMasterSecretHex"]);
    let node_secret = StaticSecret::new(master_secret).expect("32-byte test seed");
    let signing_seed = node_secret.derive_key(key_context);
    let signer = SigningKey::from_bytes(&signing_seed);

    let original_cid = raw_blake3_cid(&dag_cbor(&fixture["originalArtifact"]));
    let lease_cid = raw_blake3_cid(&dag_cbor(&fixture["leaseArtifact"]));
    let resource = format!(
        "{}{}",
        fixture["renewResourcePrefix"].as_str().unwrap(),
        original_cid
    );

    assert_eq!(fixture["renewAbility"], "tinycloud.delegation/renew");
    assert_eq!(
        fixture["renewResourcePrefix"], "urn:cid:",
        "the control capability targets the canonical original CID"
    );
    assert_eq!(resource, format!("urn:cid:{original_cid}"));

    let stamp = &fixture["stamp"];
    assert_eq!(stamp["domain"], domain);
    assert_eq!(stamp["unsigned"]["type"], "TinyCloudRenewalStamp");
    assert_eq!(stamp["unsigned"]["version"], 1);
    assert_eq!(stamp["unsigned"]["originalCid"], original_cid);
    assert_eq!(stamp["unsigned"]["leaseCid"], lease_cid);
    assert_eq!(stamp["unsigned"]["previousStampCid"], lease_cid);
    assert_eq!(stamp["unsigned"]["nodeDid"], node_secret.node_did());
    assert_eq!(stamp["unsigned"]["leaseGeneration"], 3);
    assert_eq!(stamp["unsigned"]["renewerEpoch"], 7);
    assert_eq!(stamp["unsigned"]["newEnd"], "2030-01-02T03:04:05Z");

    let bytes = dag_cbor(stamp);
    assert_eq!(hex::encode(&bytes), fixture["canonicalDagCborHex"]);
    assert_eq!(raw_blake3_cid(&bytes), fixture["stampCid"]);
    assert_eq!(
        hex::encode(signer.verifying_key().to_bytes()),
        fixture["signerPublicKeyHex"]
    );

    let signature_bytes = signer.sign(&bytes).to_bytes();
    assert_eq!(hex::encode(signature_bytes), fixture["signatureHex"]);
    let signature = ed25519_dalek::Signature::from_slice(&decode_hex(&fixture["signatureHex"]))
        .expect("64-byte Ed25519 signature");
    let verifying_key = VerifyingKey::from_bytes(&signer.verifying_key().to_bytes())
        .expect("derived public key is valid");
    verifying_key
        .verify(&bytes, &signature)
        .expect("pinned detached signature verifies over exact DAG-CBOR bytes");

    let decoded: Value =
        serde_ipld_dagcbor::from_slice(&bytes).expect("canonical DAG-CBOR decodes");
    assert_eq!(
        dag_cbor(&decoded),
        bytes,
        "DAG-CBOR re-encoding is byte-identical"
    );
}
#[test]
fn runtime_signer_reproduces_the_frozen_stamp_vector() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/renewal-stamp-v1.json"))
        .expect("renewal vector JSON parses");
    assert_eq!(
        tinycloud_core::renewal::STAMP_DOMAIN,
        "tinycloud/node/renewal-stamp/v1"
    );
    assert_eq!(
        tinycloud_core::renewal::RENEWER_KEY_CONTEXT,
        b"tinycloud/node/renewer/v1"
    );

    let master_secret = decode_hex(&fixture["testOnlyMasterSecretHex"]);
    let node_secret = StaticSecret::new(master_secret).expect("32-byte test seed");
    let signer = tinycloud_core::renewal::RenewalSigner::from_seed(
        node_secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT),
        node_secret.node_did(),
        fixture["stamp"]["unsigned"]["renewerEpoch"]
            .as_u64()
            .unwrap(),
    );
    let original_cid = raw_blake3_cid(&dag_cbor(&fixture["originalArtifact"]));
    let lease_cid = raw_blake3_cid(&dag_cbor(&fixture["leaseArtifact"]));
    let (bytes, signature, cid) = signer
        .sign_stamp(
            &original_cid,
            &lease_cid,
            fixture["stamp"]["unsigned"]["leaseGeneration"]
                .as_u64()
                .unwrap(),
            fixture["stamp"]["unsigned"]["previousStampCid"]
                .as_str()
                .unwrap(),
            fixture["stamp"]["unsigned"]["newEnd"].as_str().unwrap(),
        )
        .expect("runtime stamp encoding succeeds");

    assert_eq!(hex::encode(bytes), fixture["canonicalDagCborHex"]);
    assert_eq!(cid, fixture["stampCid"]);
    assert_eq!(hex::encode(signature), fixture["signatureHex"]);
}
