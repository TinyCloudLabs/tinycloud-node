use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use tinycloud::{
    space_lifecycle::{
        lifecycle_error, list_my_spaces, resources::list_my_resources, LifecycleRuntime,
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
    sea_orm::{ConnectionTrait, Database},
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    storage::StorageConfig,
};
#[tokio::test]
async fn lifecycle_guard_and_json_refusals_use_the_configured_host_envelope_without_lookup() {
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
            BTreeMap::from([("test".into(), vec![7; 32])]),
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
            .mount("/", rocket::routes![list_my_spaces, list_my_resources])
            .register("/space", rocket::catchers![lifecycle_error])
            .register("/resource", rocket::catchers![lifecycle_error]),
    )
    .await
    .unwrap();
    db.execute_unprepared("DROP TABLE space_purge_nonce")
        .await
        .unwrap();
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    let id = uuid::Uuid::new_v4().to_string();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
    let jwt = make_invocation_from_uris(
        [(
            owner.parse().unwrap(),
            ["tinycloud.space/list".parse().unwrap()],
        )],
        &Cid::default(),
        &key,
        &format!("{owner}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![
                serde_json::json!({"hostId":"host-test","idempotency_key":id}),
            ]),
            proof: Some(vec![]),
        },
    )
    .unwrap()
    .encode()
    .unwrap();
    let valid_body = serde_json::json!({"version":1,"ownerDid":owner,"cursor":null}).to_string();
    for (path, authorization, header, body, expected_status) in [
        ("/space/list", None, None, "{}", Status::Unauthorized),
        ("/resource/list", None, None, "{}", Status::Unauthorized),
        (
            "/space/list",
            Some(jwt.as_str()),
            Some("not-a-uuid"),
            valid_body.as_str(),
            Status::Unauthorized,
        ),
        (
            "/space/list",
            Some(jwt.as_str()),
            Some(id.as_str()),
            "{",
            Status::BadRequest,
        ),
    ] {
        let mut request = client.post(path).header(ContentType::JSON).body(body);
        if let Some(jwt) = authorization {
            request = request.header(Header::new("Authorization", jwt.to_owned()));
        }
        if let Some(id) = header {
            request = request.header(Header::new("Idempotency-Key", id.to_owned()));
        }
        let response = request.dispatch().await;
        assert_eq!(response.status(), expected_status);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        let body = response.into_json::<serde_json::Value>().await.unwrap();
        assert_eq!(body["hostId"], "host-test");
        assert_eq!(
            body["error"]["code"],
            if expected_status == Status::Unauthorized {
                "authentication_failed"
            } else {
                "invalid_request"
            }
        );
    }
    // A well-formed request reaches the deliberately absent nonce table and
    // fails closed, demonstrating that guard/JSON errors above did not look up.
    let response = client
        .post("/space/list")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id))
        .body(valid_body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::ServiceUnavailable);
    assert_eq!(
        response.into_json::<serde_json::Value>().await.unwrap()["hostId"],
        "host-test"
    );
}
