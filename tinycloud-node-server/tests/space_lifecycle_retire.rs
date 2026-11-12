use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{retire_owner, LifecycleRuntime},
    storage::{file_system::FileSystemConfig, purge_ledger::PurgeLedgerStore},
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::space_retirement,
    sea_orm::{Database, EntityTrait, PaginatorTrait},
    sea_orm_migration::MigratorTrait,
    space_purge_fence::FenceError,
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
fn signed(key: &JWK, owner: &str, target: &str, id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
    make_invocation_from_uris(
        [(
            target.parse().unwrap(),
            ["tinycloud.space/retire-owner".parse().unwrap()],
        )],
        &Cid::default(),
        key,
        &format!("{owner}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![serde_json::json!({"idempotency_key":id})]),
            proof: Some(vec![]),
        },
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[tokio::test]
async fn retirement_is_owner_only_durable_idempotent_and_replay_safe() {
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
            BTreeMap::from([("test".into(), vec![5; 32])]),
        )
        .unwrap(),
    );
    let runtime = LifecycleRuntime::new(
        db.clone().into(),
        keys.clone(),
        store.clone(),
        "host-test".into(),
    )
    .unwrap();
    runtime.verify_ledger().await.unwrap();
    runtime.fence.set_serving_ready(true);
    let fence = runtime.fence.clone();
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![retire_owner]),
    )
    .await
    .unwrap();
    let (key, owner) = new_owner();
    let id = uuid::Uuid::new_v4().to_string();
    let body = serde_json::json!({"version":1,"owner_did":owner});
    // Both added contract rejection vectors must leave no record.
    for target in [
        format!("tinycloud:{}", &owner[4..]),
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111".into(),
    ] {
        let response = client
            .post("/space/retire-owner")
            .header(ContentType::JSON)
            .header(Header::new(
                "Authorization",
                signed(&key, &owner, &target, &id),
            ))
            .header(Header::new("Idempotency-Key", id.clone()))
            .json(&body)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
        assert_eq!(
            space_retirement::Entity::find().count(&db).await.unwrap(),
            0
        );
        assert!(store.list_purge_records().await.unwrap().is_empty());
    }
    let jwt = signed(&key, &owner, &owner, &id);
    let response = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt.clone()))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    assert_eq!(
        response.into_json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({"version":1,"hostId":"host-test","state":"retired"})
    );
    let space = format!("tinycloud:{}:future-space", &owner[4..])
        .parse()
        .unwrap();
    assert!(matches!(
        fence.check(&db, &space).await,
        Err(FenceError::Deleted)
    ));
    let replay = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(replay.status(), Status::Unauthorized);
    let retry = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &owner, &id),
        ))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(retry.status(), Status::Ok);
    assert_eq!(
        retry.into_json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({"version":1,"hostId":"host-test","state":"retired"})
    );
    let (other_key, other) = new_owner();
    let conflict = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&other_key, &other, &other, &id),
        ))
        .header(Header::new("Idempotency-Key", id))
        .json(&serde_json::json!({"version":1,"owner_did":other}))
        .dispatch()
        .await;
    assert_eq!(conflict.status(), Status::Conflict);
    assert_eq!(
        space_retirement::Entity::find().count(&db).await.unwrap(),
        1
    );
    let paths = store.list_purge_records().await.unwrap();
    assert_eq!(paths.len(), 1);
    let record = store.read_purge_record(&paths[0]).await.unwrap().unwrap();
    let verified = keys.verify(&paths[0], &record).unwrap();
    assert_eq!(verified.state, "retired");
    assert!(!String::from_utf8(record).unwrap().contains(&owner));
    // A published acceptance that outlived a failed DB transaction is reused,
    // including its authenticated operation ID and timestamp.
    let (pending_key, pending_owner) = new_owner();
    let old_id = uuid::Uuid::new_v4().to_string();
    let timestamp = OffsetDateTime::now_utc().unix_timestamp() - 1;
    let digest = keys.target_hmac("test", "owner", &pending_owner).unwrap();
    let published = keys
        .sign("test", "owner", &digest, &old_id, "retired", timestamp)
        .unwrap();
    store
        .append_purge_record(
            &published.object_key().unwrap(),
            &published.to_bytes().unwrap(),
        )
        .await
        .unwrap();
    let new_id = uuid::Uuid::new_v4().to_string();
    let response = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&pending_key, &pending_owner, &pending_owner, &new_id),
        ))
        .header(Header::new("Idempotency-Key", new_id))
        .json(&serde_json::json!({"version":1,"owner_did":pending_owner}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    let restored = space_retirement::Entity::find_by_id((digest, "test".into()))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.retirement_id, old_id);
    assert_eq!(restored.accepted_at.unix_timestamp(), timestamp);
}

#[tokio::test]
async fn external_acceptance_followed_by_db_failure_fences_serving_until_reconciliation() {
    use tinycloud_core::sea_orm::ConnectionTrait;
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
            BTreeMap::from([("test".into(), vec![6; 32])]),
        )
        .unwrap(),
    );
    let runtime = LifecycleRuntime::new(
        db.clone().into(),
        keys.clone(),
        store.clone(),
        "host-test".into(),
    )
    .unwrap();
    runtime.verify_ledger().await.unwrap();
    runtime.fence.set_serving_ready(true);
    let fence = runtime.fence.clone();
    db.execute_unprepared("CREATE TRIGGER fail_retire BEFORE INSERT ON space_retirement BEGIN SELECT RAISE(FAIL, 'injected failure'); END").await.unwrap();
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![retire_owner]),
    )
    .await
    .unwrap();
    let (key, owner) = new_owner();
    let id = uuid::Uuid::new_v4().to_string();
    let body = serde_json::json!({"version":1,"owner_did":owner});
    let response = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &owner, &id),
        ))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::ServiceUnavailable);
    assert_eq!(
        space_retirement::Entity::find().count(&db).await.unwrap(),
        0
    );
    let paths = store.list_purge_records().await.unwrap();
    assert_eq!(paths.len(), 1);
    let bytes = store.read_purge_record(&paths[0]).await.unwrap().unwrap();
    let accepted = keys.verify(&paths[0], &bytes).unwrap();
    assert_eq!(accepted.operation_id, id);
    let any_space = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:unrelated"
        .parse()
        .unwrap();
    assert!(matches!(
        fence.check(&db, &any_space).await,
        Err(FenceError::Unavailable)
    ));
    db.execute_unprepared("DROP TRIGGER fail_retire")
        .await
        .unwrap();
    let runtime = client.rocket().state::<LifecycleRuntime>().unwrap();
    assert_eq!(runtime.verify_ledger().await.unwrap().len(), 1);
    let response = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &owner, &id),
        ))
        .header(Header::new("Idempotency-Key", id))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    assert_eq!(
        space_retirement::Entity::find().count(&db).await.unwrap(),
        1
    );
    assert!(
        matches!(
            fence.check(&db, &any_space).await,
            Err(FenceError::Unavailable)
        ),
        "verification alone must not remove the global restore fence"
    );
}
