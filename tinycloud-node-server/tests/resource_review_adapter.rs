use base64::{decode_config, encode_config, STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use tinycloud::storage::{
    file_system::FileSystemConfig,
    purge_ledger::PurgeLedgerStore,
    resource_review::{record_and_consume, verify_current},
};
use tinycloud_core::{
    migrations::Migrator,
    models::resource_review_consumption as used,
    resource_review::{ReviewExpectation, ReviewUse, ReviewVerifier, TargetRow},
    sea_orm::{Database, DatabaseConnection, EntityTrait, PaginatorTrait, TransactionTrait},
    sea_orm_migration::MigratorTrait,
    storage::StorageConfig,
};

async fn adapter(db: &DatabaseConnection) {
    Migrator::up(db, None).await.unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tinycloud-core/tests/fixtures/resource-review-typescript-jcs.json"
    ))
    .unwrap();
    assert_eq!(fixture["synthetic"], true);
    let pem = fixture["publicKeySpkiPem"].as_str().unwrap();
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = decode_config(encoded, STANDARD).unwrap();
    assert_eq!(der.len(), 44);
    let proof = &fixture["vectors"][0]["proof"];
    let payload = &proof["payload"];
    let writer = payload[1].as_str().unwrap();
    let key_id = payload[2].as_str().unwrap();
    let operator = SigningKey::from_bytes(&[9; 32]);
    let verifier = ReviewVerifier::new(
        BTreeMap::from([(
            (writer.into(), key_id.into()),
            der[12..].try_into().unwrap(),
        )]),
        BTreeMap::from([(
            ("operator".into(), "key-1".into()),
            operator.verifying_key().to_bytes(),
        )]),
        BTreeSet::new(),
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
    let now =
        OffsetDateTime::from_unix_timestamp(fixture["verifyAtUnix"].as_i64().unwrap()).unwrap();
    let clock = move || now;
    let directory = tempfile::tempdir().unwrap();
    let ledger = FileSystemConfig::new(directory.path())
        .open()
        .await
        .unwrap();
    let body = serde_json::to_vec(proof).unwrap();
    let id = "00000000-0000-4000-8000-000000000099";
    let tx = db.begin().await.unwrap();
    assert_eq!(
        record_and_consume(&tx, &ledger, &verifier, &body, &expected, id, &clock)
            .await
            .unwrap(),
        ReviewUse::Fresh
    );
    tx.rollback().await.unwrap();
    assert_eq!(used::Entity::find().count(db).await.unwrap(), 0);
    assert_eq!(ledger.list_purge_records().await.unwrap().len(), 1);
    let tx = db.begin().await.unwrap();
    assert_eq!(
        record_and_consume(&tx, &ledger, &verifier, &body, &expected, id, &clock)
            .await
            .unwrap(),
        ReviewUse::Fresh
    );
    tx.commit().await.unwrap();
    let tx = db.begin().await.unwrap();
    assert_eq!(
        record_and_consume(&tx, &ledger, &verifier, &body, &expected, id, &clock)
            .await
            .unwrap(),
        ReviewUse::OriginalPurge
    );
    assert!(record_and_consume(
        &tx,
        &ledger,
        &verifier,
        &body,
        &expected,
        "00000000-0000-4000-8000-000000000098",
        &clock
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert_eq!(used::Entity::find().count(db).await.unwrap(), 1);
    // A fresh protected-ledger revocation defeats a previously verifying proof.
    let revocation_id = uuid::Uuid::new_v4().to_string();
    let revoke = json!([
        1,
        "operator",
        "key-1",
        revocation_id,
        "writer_key",
        writer,
        key_id,
        now.unix_timestamp() - 1
    ]);
    let mut bytes = b"tinycloud-resource-review-revocation-v1\0".to_vec();
    bytes.extend(serde_jcs::to_vec(&revoke).unwrap());
    let record = serde_json::to_vec(&json!({"payload":revoke,"signature":encode_config(operator.sign(&bytes).to_bytes(),URL_SAFE_NO_PAD)})).unwrap();
    ledger
        .append_purge_record(
            &format!("_purge-ledger/review-revocations/{revocation_id}"),
            &record,
        )
        .await
        .unwrap();
    assert!(
        verify_current(&ledger, &verifier, &body, &expected, now.unix_timestamp())
            .await
            .is_err()
    );
    let tx = db.begin().await.unwrap();
    assert!(
        record_and_consume(&tx, &ledger, &verifier, &body, &expected, id, &clock)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(used::Entity::find().count(db).await.unwrap(), 1);
}
#[tokio::test]
async fn sqlite_review_adapter_repairs_publication_and_consumes_only_original_purge() {
    adapter(&Database::connect("sqlite::memory:").await.unwrap()).await;
}
#[tokio::test]
async fn postgres_review_adapter_repairs_publication_and_consumes_only_original_purge() {
    use tinycloud_core::sea_orm::{ConnectOptions, ConnectionTrait, DbBackend, Statement};
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").expect("isolated PostgreSQL URL");
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "review_adapter_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
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
    adapter(&db).await;
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}
