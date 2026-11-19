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
        job_id: "00000000-0000-4000-8000-000000000002",
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
        job_id: "00000000-0000-4000-8000-000000000002",
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
            job_id: payload[4].as_str().unwrap(),
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
fn export_rust_signed_interop_fixture() {
    let temporary = tempfile::tempdir().unwrap();
    let output = std::env::var_os("TC2871_INTEROP_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("public-rust-fixture.json"));
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
    std::fs::write(&output, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    let reopened: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    for vector in reopened["vectors"].as_array().unwrap() {
        let bytes = serde_jcs::to_vec(&vector["proof"]["payload"]).unwrap();
        assert_eq!(bytes, vector["payloadJcs"].as_str().unwrap().as_bytes());
        let mut message = b"tinycloud-resource-review-decision-v1\0".to_vec();
        message.extend(bytes);
        let signature = URL_SAFE_NO_PAD
            .decode(vector["proof"]["signature"].as_str().unwrap())
            .unwrap();
        key.verifying_key()
            .verify_strict(
                &message,
                &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
    }
}

async fn consumption(db: &tinycloud_core::sea_orm::DatabaseConnection) {
    use tinycloud_core::{
        migrations::Migrator,
        models::resource_review_consumption as used,
        resource_review::{consume, ReviewUse},
        sea_orm::{EntityTrait, PaginatorTrait, TransactionTrait},
        sea_orm_migration::MigratorTrait,
    };
    Migrator::up(db, None).await.unwrap();
    let writer = SigningKey::from_bytes(&[7; 32]);
    let operator = SigningKey::from_bytes(&[8; 32]);
    let verifier = verifier(&writer, &operator);
    let owner = "a".repeat(64);
    let target = TargetRow("b".repeat(64), 1, "c".repeat(64), "fp-1".into());
    let hosts = BTreeSet::from(["host-test".into()]);
    let expected = ReviewExpectation {
        job_id: "00000000-0000-4000-8000-000000000002",
        host_id: "host-test",
        owner_hmac: &owner,
        target: &target,
        authoritative_hosts: &hosts,
    };
    let raw = signed(
        payload(&owner, &target),
        &writer,
        b"tinycloud-resource-review-decision-v1\0",
    );
    let proof = verifier.verify_decision(&raw, &[], &expected, 150).unwrap();
    let id = "00000000-0000-4000-8000-000000000099";
    let now = time::OffsetDateTime::from_unix_timestamp(150).unwrap();
    let tx = db.begin().await.unwrap();
    assert_eq!(
        consume(&tx, &proof, id, now).await.unwrap(),
        ReviewUse::Fresh
    );
    tx.rollback().await.unwrap();
    assert_eq!(used::Entity::find().count(db).await.unwrap(), 0);
    let tx = db.begin().await.unwrap();
    assert_eq!(
        consume(&tx, &proof, id, now).await.unwrap(),
        ReviewUse::Fresh
    );
    tx.commit().await.unwrap();
    let tx = db.begin().await.unwrap();
    assert_eq!(
        consume(&tx, &proof, id, now).await.unwrap(),
        ReviewUse::OriginalPurge
    );
    assert!(
        consume(&tx, &proof, "00000000-0000-4000-8000-000000000098", now)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(used::Entity::find().count(db).await.unwrap(), 1);
    let tx = db.begin().await.unwrap();
    assert!(consume(
        &tx,
        &proof,
        id,
        time::OffsetDateTime::from_unix_timestamp(200).unwrap()
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn sqlite_review_consumption_is_atomic_and_bound_to_original_purge() {
    consumption(
        &tinycloud_core::sea_orm::Database::connect("sqlite::memory:")
            .await
            .unwrap(),
    )
    .await;
}
#[tokio::test]
async fn postgres_review_consumption_is_atomic_and_bound_to_original_purge() {
    use tinycloud_core::sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DbBackend, Statement,
    };
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").expect("isolated PostgreSQL URL");
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "review_consume_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    consumption(&db).await;
    concurrent_acceptors(&db).await;
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}

#[test]
fn rotation_retains_audit_keys_without_granting_old_keys_new_authority() {
    let old = SigningKey::from_bytes(&[7; 32]);
    let current = SigningKey::from_bytes(&[10; 32]);
    let operator = SigningKey::from_bytes(&[8; 32]);
    let verifier = ReviewVerifier::with_history(
        BTreeMap::from([
            (
                ("openkey".into(), "key-1".into()),
                old.verifying_key().to_bytes(),
            ),
            (
                ("openkey".into(), "key-2".into()),
                current.verifying_key().to_bytes(),
            ),
        ]),
        BTreeMap::from([("openkey".into(), "key-2".into())]),
        BTreeMap::from([(
            ("operator".into(), "key-1".into()),
            operator.verifying_key().to_bytes(),
        )]),
        BTreeSet::new(),
    )
    .unwrap();
    let owner = "a".repeat(64);
    let target = TargetRow("b".repeat(64), 1, "c".repeat(64), "fp-1".into());
    let hosts = BTreeSet::from(["host-test".into()]);
    let expected = ReviewExpectation {
        job_id: "00000000-0000-4000-8000-000000000002",
        host_id: "host-test",
        owner_hmac: &owner,
        target: &target,
        authoritative_hosts: &hosts,
    };
    let old_proof = signed(
        payload(&owner, &target),
        &old,
        b"tinycloud-resource-review-decision-v1\0",
    );
    assert!(verifier.verify_retained_signature(&old_proof).is_ok());
    assert!(verifier
        .verify_decision(&old_proof, &[], &expected, 150)
        .is_err());
    let mut newer = payload(&owner, &target);
    newer[2] = json!("key-2");
    assert!(verifier
        .verify_decision(
            &signed(newer, &current, b"tinycloud-resource-review-decision-v1\0"),
            &[],
            &expected,
            150
        )
        .is_ok());
    let removed = ReviewVerifier::new(
        BTreeMap::from([(
            ("openkey".into(), "key-2".into()),
            current.verifying_key().to_bytes(),
        )]),
        BTreeMap::from([(
            ("operator".into(), "key-1".into()),
            operator.verifying_key().to_bytes(),
        )]),
        BTreeSet::new(),
    )
    .unwrap();
    assert!(removed.verify_retained_signature(&old_proof).is_err());
}

#[test]
fn job_binding_and_strict_carrier_and_signature_are_required() {
    let writer = SigningKey::from_bytes(&[7; 32]);
    let operator = SigningKey::from_bytes(&[8; 32]);
    let verifier = verifier(&writer, &operator);
    let owner = "a".repeat(64);
    let target = TargetRow("b".repeat(64), 1, "c".repeat(64), "fp-1".into());
    let hosts = BTreeSet::from(["host-test".into()]);
    let expected = ReviewExpectation {
        job_id: "00000000-0000-4000-8000-000000000002",
        host_id: "host-test",
        owner_hmac: &owner,
        target: &target,
        authoritative_hosts: &hosts,
    };
    let raw = signed(
        payload(&owner, &target),
        &writer,
        b"tinycloud-resource-review-decision-v1\0",
    );
    let other_job = ReviewExpectation {
        job_id: "00000000-0000-4000-8000-000000000003",
        ..expected
    };
    assert!(verifier
        .verify_decision(&raw, &[], &other_job, 150)
        .is_err());
    assert!(verifier.verify_decision(&raw, &[], &expected, 150).is_ok());
    let carrier: Value = serde_json::from_slice(&raw).unwrap();
    let duplicate = format!(
        "{{\"payload\":{},\"signature\":{},\"signature\":{}}}",
        carrier["payload"], carrier["signature"], carrier["signature"]
    );
    assert!(verifier
        .verify_decision(duplicate.as_bytes(), &[], &expected, 150)
        .is_err());
    let mut unknown = carrier.clone();
    unknown["extra"] = json!(true);
    assert!(verifier
        .verify_decision(&serde_json::to_vec(&unknown).unwrap(), &[], &expected, 150)
        .is_err());
    let mut noncanonical = carrier.clone();
    noncanonical["signature"] = json!(format!("{}=", carrier["signature"].as_str().unwrap()));
    assert!(verifier
        .verify_decision(
            &serde_json::to_vec(&noncanonical).unwrap(),
            &[],
            &expected,
            150
        )
        .is_err());
    let mut signature = URL_SAFE_NO_PAD
        .decode(carrier["signature"].as_str().unwrap())
        .unwrap();
    signature[63] |= 0x80;
    let mut malleable = carrier;
    malleable["signature"] = json!(URL_SAFE_NO_PAD.encode(signature));
    assert!(verifier
        .verify_decision(
            &serde_json::to_vec(&malleable).unwrap(),
            &[],
            &expected,
            150
        )
        .is_err());
}

async fn concurrent_acceptors(db: &tinycloud_core::sea_orm::DatabaseConnection) {
    use tinycloud_core::{
        migrations::Migrator,
        resource_review::{consume, ReviewUse},
        sea_orm::{EntityTrait, TransactionTrait},
        sea_orm_migration::MigratorTrait,
    };
    Migrator::up(db, None).await.unwrap();
    let writer = SigningKey::from_bytes(&[7; 32]);
    let operator = SigningKey::from_bytes(&[8; 32]);
    let verifier = verifier(&writer, &operator);
    let owner = "a".repeat(64);
    let target = TargetRow("b".repeat(64), 1, "c".repeat(64), "fp-1".into());
    let hosts = BTreeSet::from(["host-test".into()]);
    let expected = ReviewExpectation {
        job_id: "00000000-0000-4000-8000-000000000002",
        host_id: "host-test",
        owner_hmac: &owner,
        target: &target,
        authoritative_hosts: &hosts,
    };
    let mut p = payload(&owner, &target);
    p[3] = json!(uuid::Uuid::new_v4().to_string());
    let raw = signed(p, &writer, b"tinycloud-resource-review-decision-v1\0");
    let a = verifier.verify_decision(&raw, &[], &expected, 150).unwrap();
    let b = verifier.verify_decision(&raw, &[], &expected, 150).unwrap();
    let barrier = tokio::sync::Barrier::new(2);
    let barrier = &barrier;
    let attempt = |proof, purge: &'static str| async move {
        let tx = db.begin().await.unwrap();
        barrier.wait().await;
        let result = consume(
            &tx,
            proof,
            purge,
            time::OffsetDateTime::from_unix_timestamp(150).unwrap(),
        )
        .await;
        if result.is_ok() {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        result
    };
    let (a, b) = tokio::join!(
        attempt(&a, "00000000-0000-4000-8000-000000000071"),
        attempt(&b, "00000000-0000-4000-8000-000000000072")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.or(b).unwrap(), ReviewUse::Fresh);
    let proof = verifier.verify_decision(&raw, &[], &expected, 150).unwrap();
    let stored = tinycloud_core::models::resource_review_consumption::Entity::find_by_id(
        proof.decision_id(),
    )
    .one(db)
    .await
    .unwrap()
    .unwrap();
    assert!([
        "00000000-0000-4000-8000-000000000071",
        "00000000-0000-4000-8000-000000000072"
    ]
    .contains(&stored.purge_id.as_str()));
}
#[tokio::test]
async fn sqlite_two_concurrent_acceptors_cannot_spend_one_decision_for_different_purges() {
    use tinycloud_core::sea_orm::{ConnectOptions, Database};
    let directory = tempfile::tempdir().unwrap();
    let mut options = ConnectOptions::new(format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("review.db").display()
    ));
    options.max_connections(2);
    let db = Database::connect(options).await.unwrap();
    concurrent_acceptors(&db).await;
}
