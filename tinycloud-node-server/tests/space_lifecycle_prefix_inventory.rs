use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{purge_space, LifecycleRuntime, PurgeStorageLayout},
    storage::{
        file_system::FileSystemConfig, purge_ledger::PurgeLedgerStore,
        purge_reconcile::PrefixStoreKind,
    },
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::{space_purge_job, space_purge_ledger_copy},
    sea_orm::{Database, EntityTrait, PaginatorTrait},
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    storage::StorageConfig,
};
fn new_owner() -> (JWK, String) {
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    (key, owner)
}
fn signed(key: &JWK, owner: &str, space: &str, id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
    make_invocation_from_uris(
        [(
            format!("{space}/space").parse().unwrap(),
            ["tinycloud.space/delete".parse().unwrap()],
        )],
        &Cid::default(),
        key,
        &format!("{owner}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![
                serde_json::json!({"idempotency_key":id,"hostId":"host-test"}),
            ]),
            proof: Some(vec![]),
        },
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[tokio::test]
async fn every_configured_namespace_is_signed_and_missing_layout_never_accepts() {
    use PrefixStoreKind::*;
    for layout in [
        None,
        Some((KvFileSystem, SqlFileSystem)),
        Some((KvS3, SqlS3)),
    ] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileSystemConfig::new(directory.path())
                .open()
                .await
                .unwrap(),
        );
        let keys = Arc::new(
            LedgerKeys::new(
                "test".into(),
                BTreeMap::from([("test".into(), vec![4; 32])]),
            )
            .unwrap(),
        );
        let mut runtime = LifecycleRuntime::new(
            db.clone().into(),
            keys.clone(),
            store.clone(),
            "host-test".into(),
        )
        .unwrap();
        if let Some((kv, sql)) = layout {
            runtime = runtime.with_storage_layout(PurgeStorageLayout::new(kv, sql, true).unwrap());
        }
        runtime.verify_ledger().await.unwrap();
        let client = Client::tracked(
            rocket::build()
                .manage(runtime)
                .mount("/", rocket::routes![purge_space]),
        )
        .await
        .unwrap();
        let (key, owner) = new_owner();
        let space = format!("tinycloud:{}:app", &owner[4..]);
        let id = uuid::Uuid::new_v4().to_string();
        let response = client
            .post("/space/purge")
            .header(ContentType::JSON)
            .header(Header::new(
                "Authorization",
                signed(&key, &owner, &space, &id),
            ))
            .header(Header::new("Idempotency-Key", id))
            .json(&serde_json::json!({"version":1,"space_id":space}))
            .dispatch()
            .await;
        if let Some((kv, sql)) = layout {
            assert_eq!(response.status(), Status::Accepted);
            let paths = store.list_purge_records().await.unwrap();
            assert_eq!(paths.len(), 1);
            let bytes = store.read_purge_record(&paths[0]).await.unwrap().unwrap();
            let record = keys.verify(&paths[0], &bytes).unwrap();
            assert_eq!(record.version, 2);
            let mut kinds: Vec<_> = record
                .prefixes
                .iter()
                .map(|p| p.store_kind.as_str())
                .collect();
            kinds.sort();
            let mut expected = vec![
                kv.as_str(),
                sql.as_str(),
                SqliteCache.as_str(),
                DuckDbCache.as_str(),
            ];
            expected.sort();
            assert_eq!(kinds, expected);
            assert_eq!(
                space_purge_ledger_copy::Entity::find_by_id(&paths[0])
                    .one(&db)
                    .await
                    .unwrap()
                    .unwrap()
                    .body,
                bytes
            );
        } else {
            assert_eq!(response.status(), Status::ServiceUnavailable);
            assert!(store.list_purge_records().await.unwrap().is_empty());
            assert_eq!(space_purge_job::Entity::find().count(&db).await.unwrap(), 0);
            assert_eq!(
                space_purge_ledger_copy::Entity::find()
                    .count(&db)
                    .await
                    .unwrap(),
                0
            );
        }
    }
}
