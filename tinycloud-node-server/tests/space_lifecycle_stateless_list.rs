use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{list_my_spaces, resources::list_my_resources, LifecycleRuntime},
    storage::file_system::FileSystemConfig,
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::{space, space_purge_nonce, space_purge_request},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait},
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    storage::StorageConfig,
};
fn signed(key: &JWK, owner: &str, action: &str, id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
    make_invocation_from_uris(
        [(owner.parse().unwrap(), [action.parse().unwrap()])],
        &Cid::default(),
        key,
        &format!("{owner}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![json!({"idempotency_key":id,"hostId":"host-test"})]),
            proof: Some(vec![]),
        },
    )
    .unwrap()
    .encode()
    .unwrap()
}
#[tokio::test]
async fn list_key_reuse_with_fresh_nonce_is_read_only_and_creates_no_request_records() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    let target: SpaceId = format!("tinycloud:{}:app", &owner[4..]).parse().unwrap();
    space::ActiveModel {
        id: Set(target.into()),
    }
    .insert(&db)
    .await
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(root.path()).open().await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![22; 32])]),
        )
        .unwrap(),
    );
    let runtime =
        LifecycleRuntime::new(db.clone().into(), keys, Arc::new(store), "host-test".into())
            .unwrap();
    runtime.verify_ledger().await.unwrap();
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![list_my_spaces, list_my_resources]),
    )
    .await
    .unwrap();
    for (path, action) in [
        ("/space/list", "tinycloud.space/list"),
        ("/resource/list", "tinycloud.resource/list"),
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        let mut first = None;
        let mut token = None;
        for _ in 0..2 {
            let jwt = signed(&key, &owner, action, &id);
            let response = client
                .post(path)
                .header(ContentType::JSON)
                .header(Header::new("Authorization", jwt.clone()))
                .header(Header::new("Idempotency-Key", id.clone()))
                .json(&json!({"version":1,"ownerDid":owner,"cursor":null}))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            let value = response.into_json::<Value>().await.unwrap();
            if let Some(previous) = &first {
                assert_eq!(previous, &value);
            } else {
                first = Some(value);
                token = Some(jwt);
            }
        }
        let replay = client
            .post(path)
            .header(ContentType::JSON)
            .header(Header::new("Authorization", token.unwrap()))
            .header(Header::new("Idempotency-Key", id))
            .json(&json!({"version":1,"ownerDid":owner,"cursor":null}))
            .dispatch()
            .await;
        assert_eq!(replay.status(), Status::Unauthorized);
    }
    assert!(space_purge_request::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        space_purge_nonce::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        4
    );
}
