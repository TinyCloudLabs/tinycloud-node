use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{
        resources::{list_my_resources, ResourceListResponse},
        LifecycleRuntime,
    },
    storage::file_system::FileSystemConfig,
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::{encryption_network, encryption_network_key},
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
            ["tinycloud.resource/list".parse().unwrap()],
        )],
        &Cid::default(),
        key,
        &format!("{signer}#blockchainAccountId"),
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
    .unwrap();
    (invocation.encode().unwrap(), id)
}

#[tokio::test]
async fn resource_inventory_pages_all_networks_and_keys_and_refuses_nonowners() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let (key, owner) = new_owner();
    let mut expected = Vec::new();
    let mut main = String::new();
    for name in ["default", "archive"] {
        let id = tinycloud_core::encryption_network::NetworkId::new(&owner, name)
            .unwrap()
            .to_string();
        if name == "default" {
            main = id.clone();
        }
        expected.push(id.clone());
        encryption_network::ActiveModel {
            network_id: Set(id),
            owner_did: Set(owner.clone()),
            name: Set(name.into()),
            alg: Set("X25519".into()),
            key_version: Set(1),
            public_key: Set(vec![1; 32]),
            state: Set("active".into()),
            threshold_n: Set(1),
            threshold_t: Set(1),
            key_backend: Set("local-one-of-one".into()),
            sealed_private_key: Set(None),
            created_at: Set("2026-11-12T00:00:00Z".into()),
            updated_at: Set("2026-11-12T00:00:00Z".into()),
        }
        .insert(&db)
        .await
        .unwrap();
    }
    for n in 0..501 {
        let path = format!("apps/app/key{n:04}");
        expected.push(format!("{main}/{path}"));
        encryption_network_key::ActiveModel {
            network_id: Set(main.clone()),
            key_path: Set(path),
            kind: Set("deletable".into()),
            state: Set("active".into()),
            public_key: Set(vec![1; 32]),
            sealed_seed: Set(None),
            key_version: Set(1),
            created_at: Set("2026-11-12T00:00:00Z".into()),
            updated_at: Set("2026-11-12T00:00:00Z".into()),
        }
        .insert(&db)
        .await
        .unwrap();
    }
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
    let runtime =
        LifecycleRuntime::new(db.into(), keys, Arc::new(store), "host-test".into()).unwrap();
    runtime.verify_ledger().await.unwrap();
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![list_my_resources]),
    )
    .await
    .unwrap();
    let mut cursor = None;
    let mut found = Vec::new();
    for page in 0..2 {
        let (jwt, id) = signed(&key, &owner, &owner);
        let response = client
            .post("/resource/list")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", jwt))
            .header(Header::new("Idempotency-Key", id))
            .json(&serde_json::json!({"version":1,"ownerDid":owner,"cursor":cursor}))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<ResourceListResponse>().await.unwrap();
        assert_eq!(response.host_id, "host-test");
        assert_eq!(response.owner_did, owner);
        assert_eq!(response.last_page, page == 1);
        assert_eq!(response.resources.len(), if page == 0 { 500 } else { 3 });
        found.extend(response.resources);
        cursor = response.next_cursor;
    }
    assert!(cursor.is_none());
    expected.sort();
    assert_eq!(found, expected);
    let (other_key, other) = new_owner();
    let mut refused = Vec::new();
    for target in [
        &owner,
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
    ] {
        let (jwt, id) = signed(&other_key, &other, target);
        let response = client
            .post("/resource/list")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", jwt))
            .header(Header::new("Idempotency-Key", id))
            .json(&serde_json::json!({"version":1,"ownerDid":target,"cursor":null}))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
        let body = response.into_json::<serde_json::Value>().await.unwrap();
        assert_eq!(body["hostId"], "host-test");
        refused.push(body);
    }
    assert_eq!(refused[0], refused[1]);
}
