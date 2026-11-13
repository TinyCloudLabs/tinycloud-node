use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tinycloud_core::resource_review::{ReviewExpectation, ReviewVerifier, TargetRow};

fn signed(payload: Value, key: &SigningKey, domain: &[u8]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_jcs::to_vec(&payload).unwrap());
    serde_json::to_vec(
        &json!({"payload":payload,"signature":URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes())}),
    )
    .unwrap()
}
fn verifier(writer: &SigningKey, operator: &SigningKey) -> ReviewVerifier {
    ReviewVerifier::new(
        BTreeMap::from([(
            ("openkey".into(), "key-1".into()),
            writer.verifying_key().to_bytes(),
        )]),
        BTreeMap::from([(
            ("operator".into(), "key-1".into()),
            operator.verifying_key().to_bytes(),
        )]),
        BTreeSet::new(),
    )
    .unwrap()
}
fn payload(owner: &str, target: &TargetRow) -> Value {
    let rows = json!([[
        "host-test",
        owner,
        1,
        [target.0],
        [[target.0, target.1, target.2, target.3]]
    ]]);
    let hash = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&json!([1, rows])).unwrap(),
    ));
    json!([
        1,
        "openkey",
        "key-1",
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
        "host-test",
        owner,
        target.0,
        "proceed",
        "security operator",
        100,
        "quote \" slash \\ é e\u{301} 😀 \u{2028}",
        hash,
        rows,
        200
    ])
}
#[test]
fn verifies_canonical_unicode_and_rejects_changed_target_snapshot_or_expiry() {
    let writer = SigningKey::from_bytes(&[7; 32]);
    let operator = SigningKey::from_bytes(&[8; 32]);
    let verifier = verifier(&writer, &operator);
    let owner = "a".repeat(64);
    let target = TargetRow("b".repeat(64), 1, "c".repeat(64), "fp-1".into());
    let hosts = BTreeSet::from(["host-test".into()]);
    let expected = ReviewExpectation {
        host_id: "host-test",
        owner_hmac: &owner,
        target: &target,
        authoritative_hosts: &hosts,
    };
    let original = payload(&owner, &target);
    let proof = signed(
        original.clone(),
        &writer,
        b"tinycloud-resource-review-decision-v1\0",
    );
    assert!(verifier
        .verify_decision(&proof, &[], &expected, 150)
        .is_ok());
    // Reformatting the carrier never changes the authenticated canonical bytes.
    let parsed: Value = serde_json::from_slice(&proof).unwrap();
    assert!(verifier
        .verify_decision(
            &serde_json::to_vec_pretty(&parsed).unwrap(),
            &[],
            &expected,
            150
        )
        .is_ok());
    for (index, value) in [
        (5, json!("another-host")),
        (7, json!("d".repeat(64))),
        (14, json!(149)),
        (8, json!("wait_for_re-encryption")),
    ] {
        let mut altered = original.clone();
        altered[index] = value;
        assert!(verifier
            .verify_decision(
                &signed(altered, &writer, b"tinycloud-resource-review-decision-v1\0"),
                &[],
                &expected,
                150
            )
            .is_err());
    }
    let changed = TargetRow(target.0.clone(), 2, "d".repeat(64), target.3.clone());
    let changed_expectation = ReviewExpectation {
        target: &changed,
        ..expected
    };
    assert!(verifier
        .verify_decision(&proof, &[], &changed_expectation, 150)
        .is_err());
    assert!(verifier
        .verify_decision(&proof, &[], &expected, 200)
        .is_err());
}
#[test]
fn revocation_requires_separate_operator_and_fails_closed() {
    let writer = SigningKey::from_bytes(&[7; 32]);
    let operator = SigningKey::from_bytes(&[8; 32]);
    let verifier = verifier(&writer, &operator);
    let owner = "a".repeat(64);
    let target = TargetRow("b".repeat(64), 1, "c".repeat(64), "fp-1".into());
    let hosts = BTreeSet::from(["host-test".into()]);
    let expected = ReviewExpectation {
        host_id: "host-test",
        owner_hmac: &owner,
        target: &target,
        authoritative_hosts: &hosts,
    };
    let proof = signed(
        payload(&owner, &target),
        &writer,
        b"tinycloud-resource-review-decision-v1\0",
    );
    for (scope, writer_id, key_id) in [
        ("writer_key", json!("openkey"), json!("key-1")),
        ("all", Value::Null, Value::Null),
    ] {
        let revocation = json!([
            1,
            "operator",
            "key-1",
            "00000000-0000-4000-8000-000000000003",
            scope,
            writer_id,
            key_id,
            120
        ]);
        for key in [&operator, &writer] {
            let record = signed(
                revocation.clone(),
                key,
                b"tinycloud-resource-review-revocation-v1\0",
            );
            assert!(verifier
                .verify_decision(&proof, &[record], &expected, 150)
                .is_err());
        }
    }
    assert!(verifier
        .verify_decision(&proof, &[b"malformed".to_vec()], &expected, 150)
        .is_err());
}

#[test]
fn verifies_typescript_jcs_and_ed25519_public_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/resource-review-typescript-jcs.json")).unwrap();
    assert_eq!(fixture["synthetic"], true);
    let pem = fixture["publicKeySpkiPem"].as_str().unwrap();
    let base64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .unwrap();
    assert_eq!(
        &der[..12],
        &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
    );
    let key = ed25519_dalek::VerifyingKey::from_bytes(der[12..].try_into().unwrap()).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let payload = &vector["proof"]["payload"];
        let bytes = serde_jcs::to_vec(payload).unwrap();
        assert_eq!(bytes, vector["payloadJcs"].as_str().unwrap().as_bytes());
        let snapshot = serde_jcs::to_vec(&json!([1, payload[13]])).unwrap();
        assert_eq!(snapshot, vector["snapshotJcs"].as_str().unwrap().as_bytes());
        let mut message = b"tinycloud-resource-review-decision-v1\0".to_vec();
        message.extend(bytes);
        let signature = URL_SAFE_NO_PAD
            .decode(vector["proof"]["signature"].as_str().unwrap())
            .unwrap();
        key.verify_strict(
            &message,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
        let target: TargetRow = serde_json::from_value(payload[13][0][4][0].clone()).unwrap();
        let hosts = BTreeSet::from([payload[5].as_str().unwrap().into()]);
        let expected = ReviewExpectation {
            host_id: payload[5].as_str().unwrap(),
            owner_hmac: payload[6].as_str().unwrap(),
            target: &target,
            authoritative_hosts: &hosts,
        };
        let operator = SigningKey::from_bytes(&[9; 32]);
        let verifier = ReviewVerifier::new(
            BTreeMap::from([(
                (
                    payload[1].as_str().unwrap().into(),
                    payload[2].as_str().unwrap().into(),
                ),
                key.to_bytes(),
            )]),
            BTreeMap::from([(
                ("operator".into(), "key-1".into()),
                operator.verifying_key().to_bytes(),
            )]),
            BTreeSet::new(),
        )
        .unwrap();
        assert!(verifier
            .verify_decision(
                &serde_json::to_vec(&vector["proof"]).unwrap(),
                &[],
                &expected,
                fixture["verifyAtUnix"].as_i64().unwrap()
            )
            .is_ok());
    }
}

#[test]
#[ignore = "manual public interoperability fixture export"]
fn export_rust_signed_interop_fixture() {
    let output =
        std::env::var("TC2871_INTEROP_OUTPUT").expect("explicit public fixture destination");
    let mut fixture: Value =
        serde_json::from_str(include_str!("fixtures/resource-review-typescript-jcs.json")).unwrap();
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&key.verifying_key().to_bytes());
    fixture["publicKeySpkiPem"] = json!(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    ));
    for vector in fixture["vectors"].as_array_mut().unwrap() {
        let payload = vector["proof"]["payload"].clone();
        vector["proof"] = serde_json::from_slice(&signed(
            payload.clone(),
            &key,
            b"tinycloud-resource-review-decision-v1\0",
        ))
        .unwrap();
        vector["payloadJcs"] =
            json!(String::from_utf8(serde_jcs::to_vec(&payload).unwrap()).unwrap());
        vector["snapshotJcs"] =
            json!(String::from_utf8(serde_jcs::to_vec(&json!([1, payload[13]])).unwrap()).unwrap());
    }
    std::fs::write(output, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
}
