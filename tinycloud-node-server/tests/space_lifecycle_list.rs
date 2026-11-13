use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{list_my_spaces, LifecycleRuntime, ListResponse},
    storage::file_system::FileSystemConfig,
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::{database_alias, space, space_purge_job, space_retirement},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, Database},
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
fn signed(key: &JWK, signer: &str, target: &str) -> (String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
    let invocation = make_invocation_from_uris(
        [(
            target.parse().unwrap(),
            ["tinycloud.space/list".parse().unwrap()],
        )],
        &Cid::default(),
        key,
        &format!("{signer}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![serde_json::json!({"idempotency_key":id})]),
            proof: Some(vec![]),
        },
    )
    .unwrap();
    (invocation.encode().unwrap(), id)
}

#[tokio::test]
async fn owner_list_pages_live_and_purging_spaces_and_preserves_privacy_after_retirement() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(directory.path())
        .open()
        .await
        .unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![9; 32])]),
        )
        .unwrap(),
    );
    let (key, owner) = new_owner();
    let prefix = format!("tinycloud:{}:", &owner[4..]);
    let owner_hash = keys.target_hmac("test", "owner", &owner).unwrap();
    for n in 0..501 {
        space::ActiveModel {
            id: Set(format!("{prefix}s{n:04}")
                .parse::<tinycloud_auth::resource::SpaceId>()
                .unwrap()
                .into()),
        }
        .insert(&db)
        .await
        .unwrap();
    }
    let now = OffsetDateTime::now_utc();
    space_retirement::ActiveModel {
        owner_hmac: Set(owner_hash.clone()),
        hmac_key_id: Set("test".into()),
        retirement_id: Set(uuid::Uuid::new_v4().to_string()),
        accepted_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();
    let purging = format!("{prefix}z-purging");
    space_purge_job::ActiveModel {
        purge_id: Set(uuid::Uuid::new_v4().to_string()),
        space: Set(Some(purging.clone())),
        tombstone_hmac: Set(keys.target_hmac("test", "space", &purging).unwrap()),
        hmac_key_id: Set("test".into()),
        owner_hmac: Set(owner_hash),
        accepted_at: Set(now),
        phase: Set("drain".into()),
        fence_generation: Set(1),
        updated_at: Set(now),
        next_attempt_at: Set(now),
        attempt_count: Set(0),
        last_error_code: Set(None),
        lease_token: Set(None),
        lease_until: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();
    let sql_only = format!("{prefix}z-sql-only");
    database_alias::ActiveModel {
        service: Set("sql".into()),
        space: Set(sql_only.clone()),
        logical_name: Set("db".into()),
        path: Set(None),
        physical_name: Set("db.sqlite".into()),
    }
    .insert(&db)
    .await
    .unwrap();
    let runtime =
        LifecycleRuntime::new(db.into(), keys, Arc::new(store), "host-test".into()).unwrap();
    runtime.verify_ledger().await.unwrap();
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![list_my_spaces]),
    )
    .await
    .unwrap();
    let (jwt, id) = signed(&key, &owner, &owner);
    let first_body = serde_json::json!({"version":1,"ownerDid":owner,"cursor":null});
    let response = client
        .post("/space/list")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt.clone()))
        .header(Header::new("Idempotency-Key", id.clone()))
        .json(&first_body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let first = response.into_json::<ListResponse>().await.unwrap();
    assert_eq!(first.host_id, "host-test");
    assert_eq!(first.owner_did, owner);
    assert_eq!(first.spaces.len(), 500);
    assert!(!first.last_page);
    assert!(first.next_cursor.is_some());
    let replay = client
        .post("/space/list")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id))
        .json(&first_body)
        .dispatch()
        .await;
    assert_eq!(replay.status(), Status::Unauthorized);
    let (jwt, id) = signed(&key, &owner, &owner);
    let response = client
        .post("/space/list")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id))
        .json(&serde_json::json!({"version":1,"ownerDid":owner,"cursor":first.next_cursor}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let second = response.into_json::<ListResponse>().await.unwrap();
    assert!(second.last_page);
    assert_eq!(second.next_cursor, None);
    assert_eq!(second.spaces.len(), 3);
    assert!(second.spaces.contains(&sql_only));
    assert!(second.spaces.contains(&purging));
    let mut all = first.spaces;
    all.extend(second.spaces);
    let mut sorted = all.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(all, sorted);
    assert_eq!(all.len(), 503);
    let (other_key, other) = new_owner();
    let mut refusals = Vec::new();
    for target in [
        &owner,
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
    ] {
        let (jwt, id) = signed(&other_key, &other, target);
        let response = client
            .post("/space/list")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", jwt))
            .header(Header::new("Idempotency-Key", id))
            .json(&serde_json::json!({"version":1,"ownerDid":target,"cursor":null}))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
        refusals.push(response.into_json::<serde_json::Value>().await.unwrap());
    }
    assert_eq!(refusals[0], refusals[1]);
    assert_eq!(
        refusals[0],
        serde_json::json!({"hostId":"host-test","error":{"code":"not_found"}})
    );
}
