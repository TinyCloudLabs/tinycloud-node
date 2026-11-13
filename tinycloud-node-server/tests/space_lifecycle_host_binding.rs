use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::{Client, LocalResponse},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{
        list_my_spaces, purge_space, purge_status, resources::list_my_resources, retire_owner,
        LifecycleRuntime,
    },
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
    models::{space, space_purge_job, space_purge_request, space_retirement},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Database, DatabaseConnection,
        EntityTrait,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    storage::StorageConfig,
};
async fn host(id: &str, byte: u8) -> (Client, tempfile::TempDir, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(root.path()).open().await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![byte; 32])]),
        )
        .unwrap(),
    );
    let runtime = LifecycleRuntime::new(db.clone().into(), keys, Arc::new(store), id.into())
        .unwrap()
        .with_storage_layout(
            tinycloud::space_lifecycle::PurgeStorageLayout::new(
                tinycloud::storage::purge_reconcile::PrefixStoreKind::KvFileSystem,
                tinycloud::storage::purge_reconcile::PrefixStoreKind::SqlFileSystem,
                false,
            )
            .unwrap(),
        );
    runtime.verify_ledger().await.unwrap();
    let client = Client::tracked(rocket::build().manage(runtime).mount(
        "/",
        rocket::routes![
            list_my_spaces,
            list_my_resources,
            retire_owner,
            purge_space,
            purge_status
        ],
    ))
    .await
    .unwrap();
    (client, root, db)
}
fn signed(
    key: &JWK,
    owner: &str,
    resource: &str,
    action: &str,
    host: Option<Value>,
    duplicate: bool,
) -> (String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
    let mut fact = json!({"idempotency_key":id});
    if let Some(host) = host {
        fact["hostId"] = host;
    }
    let mut facts = vec![fact];
    if duplicate {
        facts.push(json!({"hostId":"host-a"}));
    }
    let invocation = make_invocation_from_uris(
        [(resource.parse().unwrap(), [action.parse().unwrap()])],
        &Cid::default(),
        key,
        &format!("{owner}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(facts),
            proof: Some(vec![]),
        },
    )
    .unwrap();
    (invocation.encode().unwrap(), id)
}
async fn dispatch<'a>(
    client: &'a Client,
    path: &'static str,
    signed: &(String, String),
    body: &Value,
) -> LocalResponse<'a> {
    client
        .post(path)
        .header(ContentType::JSON)
        .header(Header::new("Authorization", signed.0.clone()))
        .header(Header::new("Idempotency-Key", signed.1.clone()))
        .json(body)
        .dispatch()
        .await
}
#[tokio::test]
async fn every_implemented_lifecycle_route_refuses_cross_host_replay_before_database_lookup() {
    let (a, _a_root, a_db) = host("host-a", 20).await;
    let (b, _b_root, b_db) = host("host-b", 21).await;
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    let target: SpaceId = format!("tinycloud:{}:app", &owner[4..]).parse().unwrap();
    space::ActiveModel {
        id: Set(target.clone().into()),
    }
    .insert(&a_db)
    .await
    .unwrap();
    // Any nonce lookup would now fail. A mismatched target must still return
    // its request-only refusal rather than entering management_transaction.
    b_db.execute_unprepared("DROP TABLE space_purge_nonce")
        .await
        .unwrap();
    let mut purge_id = None;
    for (path, action, resource, body, expected) in [
        (
            "/space/list",
            "tinycloud.space/list",
            owner.clone(),
            json!({"version":1,"ownerDid":owner,"cursor":null}),
            Status::Ok,
        ),
        (
            "/resource/list",
            "tinycloud.resource/list",
            owner.clone(),
            json!({"version":1,"ownerDid":owner,"cursor":null}),
            Status::Ok,
        ),
        (
            "/space/retire-owner",
            "tinycloud.space/retire-owner",
            owner.clone(),
            json!({"version":1,"owner_did":owner}),
            Status::Accepted,
        ),
        (
            "/space/purge",
            "tinycloud.space/delete",
            format!("{target}/space"),
            json!({"version":1,"space_id":target.to_string()}),
            Status::Accepted,
        ),
    ] {
        let token = signed(
            &key,
            &owner,
            &resource,
            action,
            Some(json!("host-a")),
            false,
        );
        let response = dispatch(&a, path, &token, &body).await;
        assert_eq!(response.status(), expected);
        let value = response.into_json::<Value>().await.unwrap();
        assert_eq!(value["hostId"], "host-a");
        if path == "/space/purge" {
            purge_id = Some(value["purge_id"].as_str().unwrap().to_owned());
        }
        let response = dispatch(&b, path, &token, &body).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_json::<Value>().await.unwrap(),
            json!({"hostId":"host-b","error":{"code":"host_mismatch"}})
        );
        for (host, duplicate) in [
            (None, false),
            (Some(json!(42)), false),
            (Some(json!("host-b")), true),
        ] {
            let invalid = signed(&key, &owner, &resource, action, host, duplicate);
            assert_eq!(
                dispatch(&b, path, &invalid, &body).await.status(),
                Status::BadRequest
            );
        }
        let correctly_bound = signed(
            &key,
            &owner,
            &resource,
            action,
            Some(json!("host-b")),
            false,
        );
        assert_eq!(
            dispatch(&b, path, &correctly_bound, &body).await.status(),
            Status::ServiceUnavailable
        );
    }
    let body = json!({"version":1,"space_id":target.to_string(),"purge_id":purge_id.unwrap()});
    let token = signed(
        &key,
        &owner,
        &format!("{target}/space"),
        "tinycloud.space/delete",
        Some(json!("host-a")),
        false,
    );
    let response = dispatch(&a, "/space/purge/status", &token, &body).await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json::<Value>().await.unwrap()["hostId"],
        "host-a"
    );
    let response = dispatch(&b, "/space/purge/status", &token, &body).await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(
        response.into_json::<Value>().await.unwrap()["error"]["code"],
        "host_mismatch"
    );
    assert!(space_purge_job::Entity::find()
        .all(&b_db)
        .await
        .unwrap()
        .is_empty());
    assert!(space_retirement::Entity::find()
        .all(&b_db)
        .await
        .unwrap()
        .is_empty());
    assert!(space_purge_request::Entity::find()
        .all(&b_db)
        .await
        .unwrap()
        .is_empty());
}
