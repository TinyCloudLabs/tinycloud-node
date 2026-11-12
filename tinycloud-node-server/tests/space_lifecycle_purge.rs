use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{purge_space, purge_status, LifecycleRuntime, PurgeResponse},
    storage::{file_system::FileSystemConfig, purge_ledger::PurgeLedgerStore},
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::{space, space_purge_job, space_purge_tombstone},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, Database, EntityTrait, PaginatorTrait, TransactionTrait,
    },
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
            facts: Some(vec![serde_json::json!({"idempotency_key":id})]),
            proof: Some(vec![]),
        },
    )
    .unwrap()
    .encode()
    .unwrap()
}
#[tokio::test]
async fn purge_enqueue_is_idempotent_bound_to_target_and_status_uses_inline_owner_proof() {
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
    let (key, owner) = new_owner();
    let target = format!("tinycloud:{}:app", &owner[4..]);
    let other = format!("tinycloud:{}:other", &owner[4..]);
    for raw in [&target, &other] {
        space::ActiveModel {
            id: Set(raw.parse::<SpaceId>().unwrap().into()),
        }
        .insert(&db)
        .await
        .unwrap();
    }
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![purge_space, purge_status]),
    )
    .await
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let jwt = signed(&key, &owner, &target, &id);
    let body = serde_json::json!({"version":1,"space_id":target});
    let response = client
        .post("/space/purge")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt.clone()))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    let accepted = response.into_json::<PurgeResponse>().await.unwrap();
    assert_eq!(accepted.state, "purging");
    uuid::Uuid::parse_str(&accepted.purge_id).unwrap();
    assert!(matches!(
        fence.check(&db, &target.parse().unwrap()).await,
        Err(FenceError::Deleted)
    ));
    assert!(fence.check(&db, &other.parse().unwrap()).await.is_ok());
    let replay = client
        .post("/space/purge")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&body)
        .dispatch()
        .await;
    assert_eq!(replay.status(), Status::Unauthorized);
    for operation_key in [id.clone(), uuid::Uuid::new_v4().to_string()] {
        let response = client
            .post("/space/purge")
            .header(ContentType::JSON)
            .header(Header::new(
                "Authorization",
                signed(&key, &owner, &target, &operation_key),
            ))
            .header(Header::new("Idempotency-Key", operation_key))
            .json(&body)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response
                .into_json::<PurgeResponse>()
                .await
                .unwrap()
                .purge_id,
            accepted.purge_id
        );
    }
    let conflict = client
        .post("/space/purge")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &other, &id),
        ))
        .header(Header::new("Idempotency-Key", id))
        .json(&serde_json::json!({"version":1,"space_id":other}))
        .dispatch()
        .await;
    assert_eq!(conflict.status(), Status::Conflict);
    assert_eq!(space_purge_job::Entity::find().count(&db).await.unwrap(), 1);
    assert_eq!(store.list_purge_records().await.unwrap().len(), 1);
    let status_body =
        serde_json::json!({"version":1,"purge_id":accepted.purge_id,"space_id":target});
    let status_key = uuid::Uuid::new_v4().to_string();
    let response = client
        .post("/space/purge/status")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &target, &status_key),
        ))
        .header(Header::new("Idempotency-Key", status_key))
        .json(&status_body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json::<PurgeResponse>().await.unwrap().state,
        "purging"
    );
    let unknown_key = uuid::Uuid::new_v4().to_string();
    let unknown_jwt = signed(&key, &owner, &target, &unknown_key);
    let unknown_body = serde_json::json!({"version":1,"purge_id":uuid::Uuid::new_v4().to_string(),"space_id":target});
    let unknown = client
        .post("/space/purge/status")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", unknown_jwt.clone()))
        .header(Header::new("Idempotency-Key", unknown_key.clone()))
        .json(&unknown_body)
        .dispatch()
        .await;
    assert_eq!(unknown.status(), Status::NotFound);
    let replay = client
        .post("/space/purge/status")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", unknown_jwt))
        .header(Header::new("Idempotency-Key", unknown_key))
        .json(&unknown_body)
        .dispatch()
        .await;
    assert_eq!(replay.status(), Status::Unauthorized);
    let (foreign_key, foreign_owner) = new_owner();
    let mut refusals = Vec::new();
    for request in [&status_body, &unknown_body] {
        let k = uuid::Uuid::new_v4().to_string();
        let response = client
            .post("/space/purge/status")
            .header(ContentType::JSON)
            .header(Header::new(
                "Authorization",
                signed(&foreign_key, &foreign_owner, &target, &k),
            ))
            .header(Header::new("Idempotency-Key", k))
            .json(request)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
        refusals.push(response.into_json::<serde_json::Value>().await.unwrap());
    }
    assert_eq!(refusals[0], refusals[1]);
    let mismatch_key = uuid::Uuid::new_v4().to_string();
    let mismatch = client
        .post("/space/purge")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &target, &mismatch_key),
        ))
        .header(Header::new("Idempotency-Key", mismatch_key))
        .json(&serde_json::json!({"version":1,"space_id":other}))
        .dispatch()
        .await;
    assert_eq!(mismatch.status(), Status::Unauthorized);
    assert!(fence.check(&db, &other.parse().unwrap()).await.is_ok());
    // Model the worker's already separately tested terminal transaction. This
    // status test proves authorization after delegation/live-space rows vanish;
    // it makes no new physical-purge claim.
    let job = space_purge_job::Entity::find_by_id(accepted.purge_id.clone())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let completed_at = OffsetDateTime::now_utc();
    let record = keys
        .sign(
            "test",
            "space",
            &job.tombstone_hmac,
            &job.purge_id,
            "complete",
            completed_at.unix_timestamp(),
        )
        .unwrap();
    store
        .append_purge_record(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .await
        .unwrap();
    let tx = db.begin().await.unwrap();
    space_purge_tombstone::ActiveModel {
        tombstone_hmac: Set(job.tombstone_hmac.clone()),
        hmac_key_id: Set("test".into()),
        purge_id: Set(job.purge_id.clone()),
        completed_at: Set(completed_at),
    }
    .insert(&tx)
    .await
    .unwrap();
    let mut done: space_purge_job::ActiveModel = job.into();
    done.phase = Set("complete".into());
    done.space = Set(None);
    done.updated_at = Set(completed_at);
    done.update(&tx).await.unwrap();
    space::Entity::delete_by_id(target.parse::<SpaceId>().unwrap())
        .exec(&tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let k = uuid::Uuid::new_v4().to_string();
    let response = client
        .post("/space/purge/status")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &target, &k),
        ))
        .header(Header::new("Idempotency-Key", k))
        .json(&status_body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let payload = response.into_json::<serde_json::Value>().await.unwrap();
    assert_eq!(payload["state"], "complete");
    assert!(!payload.to_string().contains("tinycloud:"));
    assert!(!payload.to_string().contains(&owner));
}
