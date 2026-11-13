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
        job_id: payload[4].as_str().unwrap(),
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

#[derive(Clone, Copy)]
enum LedgerFault {
    List,
    Read,
    ExpireAfterFinalRead,
}
struct FaultLedger<'a> {
    inner: &'a dyn PurgeLedgerStore,
    fault: LedgerFault,
    listings: std::sync::atomic::AtomicUsize,
    clock: std::sync::Arc<std::sync::atomic::AtomicI64>,
    expires: i64,
}
#[rocket::async_trait]
impl PurgeLedgerStore for FaultLedger<'_> {
    async fn append_purge_record(&self, key: &str, body: &[u8]) -> std::io::Result<()> {
        self.inner.append_purge_record(key, body).await
    }
    async fn read_purge_record(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        if matches!(self.fault, LedgerFault::Read) {
            return Err(std::io::Error::other("injected ledger read failure"));
        }
        self.inner.read_purge_record(key).await
    }
    async fn list_purge_records(&self) -> std::io::Result<Vec<String>> {
        use std::sync::atomic::Ordering;
        match self.fault {
            LedgerFault::List => Err(std::io::Error::other("injected ledger list failure")),
            LedgerFault::Read => Ok(vec![
                "_purge-ledger/review-revocations/00000000-0000-4000-8000-000000000001".into(),
            ]),
            LedgerFault::ExpireAfterFinalRead => {
                let paths = self.inner.list_purge_records().await?;
                if self.listings.fetch_add(1, Ordering::SeqCst) == 1 {
                    // Publication has completed. The final fresh ledger read
                    // crosses expiry while its caller's earlier sample is valid.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    self.clock.store(self.expires, Ordering::SeqCst);
                }
                Ok(paths)
            }
        }
    }
}

#[tokio::test]
async fn review_job_mismatch_and_io_or_expiry_during_final_read_never_consume() {
    use std::sync::{
        atomic::{AtomicI64, AtomicUsize, Ordering},
        Arc,
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tinycloud-core/tests/fixtures/resource-review-typescript-jcs.json"
    ))
    .unwrap();
    let proof = &fixture["vectors"][0]["proof"];
    let payload = &proof["payload"];
    let pem: String = fixture["publicKeySpkiPem"]
        .as_str()
        .unwrap()
        .lines()
        .filter(|s| !s.starts_with("-----"))
        .collect();
    let der = decode_config(pem, STANDARD).unwrap();
    let operator = SigningKey::from_bytes(&[9; 32]);
    let verifier = ReviewVerifier::new(
        BTreeMap::from([(
            (
                payload[1].as_str().unwrap().into(),
                payload[2].as_str().unwrap().into(),
            ),
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
        job_id: payload[4].as_str().unwrap(),
        host_id: payload[5].as_str().unwrap(),
        owner_hmac: payload[6].as_str().unwrap(),
        target: &target,
        authoritative_hosts: &hosts,
    };
    let body = serde_json::to_vec(proof).unwrap();
    let now = fixture["verifyAtUnix"].as_i64().unwrap();
    let expires = payload[14].as_i64().unwrap();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let ledger = FileSystemConfig::new(directory.path())
        .open()
        .await
        .unwrap();
    let wrong_job = ReviewExpectation {
        job_id: "00000000-0000-4000-8000-000000000099",
        ..expected
    };
    let tx = db.begin().await.unwrap();
    let clock = || OffsetDateTime::from_unix_timestamp(now).unwrap();
    assert!(record_and_consume(
        &tx,
        &ledger,
        &verifier,
        &body,
        &wrong_job,
        "00000000-0000-4000-8000-000000000071",
        &clock
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert!(ledger.list_purge_records().await.unwrap().is_empty());
    for fault in [
        LedgerFault::List,
        LedgerFault::Read,
        LedgerFault::ExpireAfterFinalRead,
    ] {
        let time = Arc::new(AtomicI64::new(now));
        let clock = || OffsetDateTime::from_unix_timestamp(time.load(Ordering::SeqCst)).unwrap();
        let faulty = FaultLedger {
            inner: &ledger,
            fault,
            listings: AtomicUsize::new(0),
            clock: time.clone(),
            expires,
        };
        let tx = db.begin().await.unwrap();
        assert!(record_and_consume(
            &tx,
            &faulty,
            &verifier,
            &body,
            &expected,
            "00000000-0000-4000-8000-000000000071",
            &clock
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        assert_eq!(used::Entity::find().count(&db).await.unwrap(), 0);
        if matches!(fault, LedgerFault::ExpireAfterFinalRead) {
            assert_eq!(time.load(Ordering::SeqCst), expires);
            assert_eq!(ledger.list_purge_records().await.unwrap().len(), 1);
        }
    }
}
