//! The `deliveryAdmission` vectors of the links API contract, against the
//! node's admission v1. Every key in the vectors is a published TEST ONLY key.

use super::*;
use tinycloud_core::libp2p::identity::{ed25519, Keypair};

const VECTORS: &str = include_str!("../../tests/fixtures/short-links-api-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap()
}

/// The vectors' `node` identity: a TEST ONLY seed.
fn node_signer(vectors: &Value) -> (Keypair, String) {
    let identity = vectors["identities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|identity| identity["name"] == "node")
        .unwrap();
    let seed: [u8; 32] = hex::decode(text(identity, "seedHex"))
        .unwrap()
        .try_into()
        .unwrap();
    let keypair = Keypair::from(ed25519::Keypair::from(
        ed25519::SecretKey::try_from_bytes(seed).unwrap(),
    ));
    let did = tinycloud_core::keys::public_key_to_did_key(keypair.public());
    assert_eq!(did, text(identity, "did"));
    (keypair, did)
}

fn signature_bytes(vector: &Value) -> Vec<u8> {
    decode_config(text(&vector["signature"], "value"), URL_SAFE_NO_PAD).unwrap()
}

fn verifies(vector: &Value, domain: &[u8]) -> bool {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(&canonical_json_value(&vector["admission"]));
    verify_detached_ed25519(
        text(&vector["signature"], "signerDid"),
        &Sha256::digest(preimage),
        &signature_bytes(vector),
    )
    .is_ok()
}

#[test]
fn the_node_reproduces_the_v1_admission_vector_byte_for_byte() {
    let vectors = vectors();
    let vector = &vectors["deliveryAdmission"]["vectors"][0];
    let admission = &vector["admission"];
    let (signer, signer_did) = node_signer(&vectors);

    let registration = policy_v3_registration::Model {
        policy_cid: text(admission, "policyId").into(),
        policy_bytes: Vec::new(),
        policy_digest_hex: "11".repeat(32),
        owner_did: text(admission, "ownerDid").into(),
        policy_root_cid: String::new(),
        enforcement_root_cid: String::new(),
        content_source_digest_hex: "22".repeat(32),
        native_projection_hash_hex: "33".repeat(32),
        attested_enforcer_binding_bytes: Vec::new(),
        registered_at: "2026-10-24T00:00:00Z".into(),
        expires_at: text(admission, "shareExpiresAt").into(),
    };
    let request = DeliveryAuthorizationRequest {
        share_url: text(admission, "returnLink").into(),
        recipient_email: text(admission, "recipient").into(),
        document_name: text(admission, "label").into(),
        jti: text(admission, "nonce").into(),
        expires_at: text(admission, "expiresAt").into(),
        request_body_digest: "unused".into(),
    };
    let source = DeliveryReceiptSource {
        request: &request,
        registration: &registration,
        envelope_ref: text(admission, "envelopeRef"),
        resource: text(admission, "resource"),
        credential_type: text(admission, "credentialType"),
        sender_key_did: text(admission, "senderKeyDid"),
        audience: text(admission, "audience"),
    };
    let receipt = build_delivery_authorization_receipt(
        &source,
        text(admission, "issuedAt"),
        &signer,
        &signer_did,
    )
    .unwrap();

    // The admission without its signature is the vector's, field for field.
    let mut produced = receipt.value["admission"].clone();
    let signature = produced
        .as_object_mut()
        .unwrap()
        .remove("signature")
        .unwrap();
    assert_eq!(&produced, admission);
    assert_eq!(
        String::from_utf8(canonical_json_value(&produced)).unwrap(),
        text(vector, "jcs")
    );

    // Preimage, digest and signature.
    let mut preimage = DELIVERY_ADMISSION_DOMAIN.to_vec();
    preimage.extend_from_slice(&canonical_json_value(&produced));
    assert_eq!(hex::encode(&preimage), text(vector, "preimageHex"));
    assert_eq!(
        hex::encode(Sha256::digest(&preimage)),
        text(vector, "digestHex")
    );
    assert_eq!(signature, vector["signature"]);
    assert!(verifies(vector, DELIVERY_ADMISSION_DOMAIN));

    // The invitation request the sender forwards carries the same link and
    // the link's `c`, and the admission digest binds the unsigned admission.
    let invitation = &receipt.value["request"];
    assert_eq!(invitation["returnLink"], admission["returnLink"]);
    assert_eq!(invitation["envelopeRef"], admission["envelopeRef"]);
    assert_eq!(
        receipt.authorization_digest,
        encode_config(
            Sha256::digest(canonical_json_value(admission)),
            URL_SAFE_NO_PAD
        )
    );
}

#[test]
fn the_domain_separates_v0_from_v1() {
    let vectors = vectors();
    let valid = &vectors["deliveryAdmission"]["vectors"][0];
    let v0_signed = &vectors["deliveryAdmission"]["vectors"][1];
    assert_eq!(valid["expect"]["valid"], true);
    assert_eq!(v0_signed["expect"]["valid"], false);
    let v0 = b"xyz.tinycloud.policy/delivery-admission/v0\0".as_slice();

    assert!(verifies(valid, DELIVERY_ADMISSION_DOMAIN));
    assert!(!verifies(valid, v0));
    // The second vector is the same admission signed under the v0 domain: it
    // is a real signature, and it does not verify as v1.
    assert!(!verifies(v0_signed, DELIVERY_ADMISSION_DOMAIN));
    assert!(verifies(v0_signed, v0));
}

#[test]
fn the_constants_are_the_contracts() {
    let vectors = vectors();
    assert_eq!(
        DELIVERY_ADMISSION_DOMAIN,
        text(&vectors["constants"]["domains"], "deliveryAdmissionV1").as_bytes()
    );
    assert_eq!(DELIVERY_ADMISSION_DOMAIN.last(), Some(&0));
    assert_eq!(
        DELIVERY_ADMISSION_DOMAIN
            .iter()
            .filter(|byte| **byte == 0)
            .count(),
        1
    );
    assert_eq!(
        DELIVERY_ADMISSION_SCHEMA,
        vectors["deliveryAdmission"]["vectors"][0]["admission"]["schema"]
    );
    assert_eq!(
        text(&vectors["constants"], "sealAad").as_bytes(),
        SEALED_ENVELOPE_AAD
    );
}

#[test]
fn request_expires_at_is_exactly_the_contract_millisecond_form() {
    use crate::delivery_link::utc_millis;
    // `YYYY-MM-DDTHH:mm:ss.SSSZ`, UTC, three fractional digits: what
    // `toISOString()` writes, trailing zeros included.
    for text in [
        "2026-10-24T12:00:00.123Z",
        "2026-10-24T12:00:00.000Z",
        "2026-10-24T12:00:00.120Z",
        "2026-10-24T12:00:00.100Z",
    ] {
        let parsed = utc_millis(text).unwrap_or_else(|| panic!("{text} is refused"));
        assert_eq!(parsed, parse_time(text).unwrap(), "{text}");
    }
    // Every other spelling is refused, whatever instant it names.
    for text in [
        "2026-10-24T12:00:00Z",
        "2026-10-24T12:00:00.12Z",
        "2026-10-24T12:00:00.1Z",
        "2026-10-24T12:00:00.1230Z",
        "2026-10-24T12:00:00.123456789Z",
        "2026-10-24T12:00:00.123+00:00",
        "2026-10-24T12:00:00.123+01:00",
        "2026-10-24T13:00:00.123+01:00",
        "2026-10-24T12:00:00.123z",
        "2026-10-24t12:00:00.123Z",
        "2026-10-24 12:00:00.123Z",
        "2026-10-24T12:00:00.123",
        "2026-10-24T12:00:00,123Z",
        "2026-02-30T12:00:00.123Z",
        " 2026-10-24T12:00:00.123Z",
        "2026-10-24T12:00:00.123Z ",
        "",
    ] {
        assert!(utc_millis(text).is_none(), "{text:?} is accepted");
    }
}

#[test]
fn both_admission_vectors_pass_the_request_expiry_format_as_requests() {
    use crate::delivery_link::utc_millis;
    let vectors = vectors();
    for vector in vectors["deliveryAdmission"]["vectors"].as_array().unwrap() {
        // The admission's `expiresAt` is the request's, echoed byte for byte.
        let expires_at = text(&vector["admission"], "expiresAt");
        assert!(utc_millis(expires_at).is_some(), "{expires_at}");
        let request = DeliveryAuthorizationRequest {
            share_url: text(&vector["admission"], "returnLink").into(),
            recipient_email: text(&vector["admission"], "recipient").into(),
            document_name: text(&vector["admission"], "label").into(),
            jti: text(&vector["admission"], "nonce").into(),
            expires_at: expires_at.into(),
            request_body_digest: "unused".into(),
        };
        assert_eq!(
            delivery_admission_value(
                &DeliveryReceiptSource {
                    request: &request,
                    registration: &policy_v3_registration::Model {
                        policy_cid: text(&vector["admission"], "policyId").into(),
                        policy_bytes: Vec::new(),
                        policy_digest_hex: String::new(),
                        owner_did: text(&vector["admission"], "ownerDid").into(),
                        policy_root_cid: String::new(),
                        enforcement_root_cid: String::new(),
                        content_source_digest_hex: String::new(),
                        native_projection_hash_hex: String::new(),
                        attested_enforcer_binding_bytes: Vec::new(),
                        registered_at: String::new(),
                        expires_at: text(&vector["admission"], "shareExpiresAt").into(),
                    },
                    envelope_ref: text(&vector["admission"], "envelopeRef"),
                    resource: text(&vector["admission"], "resource"),
                    credential_type: text(&vector["admission"], "credentialType"),
                    sender_key_did: text(&vector["admission"], "senderKeyDid"),
                    audience: text(&vector["admission"], "audience"),
                },
                text(&vector["admission"], "issuedAt"),
            )["expiresAt"],
            expires_at
        );
    }
}

#[test]
fn the_request_expiry_is_after_now_and_at_most_five_minutes_ahead() {
    use crate::delivery_link::test_support::millis;
    // The clock is injected: `now` is a parameter of the check.
    let now = parse_time("2026-10-24T12:00:00Z").unwrap();
    let accepts = |offset: Duration| delivery_request_expiry(&millis(now + offset), now).is_some();

    assert!(accepts(Duration::minutes(5) - Duration::seconds(1)));
    // The bound is inclusive, and one millisecond past it is refused.
    assert!(accepts(Duration::minutes(5)));
    assert!(!accepts(Duration::minutes(5) + Duration::milliseconds(1)));
    assert!(!accepts(Duration::minutes(5) + Duration::seconds(1)));
    assert!(!accepts(Duration::hours(1)));
    // The lower end: `now` itself and the past are refused.
    assert!(accepts(Duration::milliseconds(1)));
    assert!(!accepts(Duration::ZERO));
    assert!(!accepts(-Duration::seconds(1)));
    // The window is read from the parsed instant of an exact-form string.
    assert_eq!(
        delivery_request_expiry("2026-10-24T12:04:59.999Z", now),
        Some(now + Duration::minutes(5) - Duration::milliseconds(1))
    );
    assert_eq!(delivery_request_expiry("2026-10-24T12:03:00Z", now), None);
}
