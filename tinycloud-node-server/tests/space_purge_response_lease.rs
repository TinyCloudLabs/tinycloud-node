use rocket::{http::Status, local::asynchronous::Client, State};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tinycloud::space_lifecycle::leases::{PurgeLeaseFairing, PurgeLeases};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::sea_orm::{self, TransactionTrait};
use tinycloud_core::{
    migrations::Migrator, sea_orm::Database, sea_orm_migration::MigratorTrait,
    space_purge_fence::SpacePurgeFence, space_purge_ledger::LedgerKeys,
};

struct ReadContext {
    db: sea_orm::DatabaseConnection,
    fence: Arc<SpacePurgeFence>,
    space: SpaceId,
}
#[rocket::get("/stream")]
async fn stream(context: &State<ReadContext>, leases: PurgeLeases) -> &'static str {
    leases.hold_space(
        context
            .fence
            .admit(&context.db, &context.space)
            .await
            .unwrap(),
    );
    "immutable bytes"
}
async fn response_blocks_purge_until_closed(consume: bool) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![14; 32])]),
        )
        .unwrap(),
    );
    let fence = Arc::new(SpacePurgeFence::new(keys.clone()));
    fence.set_serving_ready(true);
    let space: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:stream"
        .parse()
        .unwrap();
    let client = Client::tracked(
        rocket::build()
            .manage(ReadContext {
                db: db.clone(),
                fence: fence.clone(),
                space: space.clone(),
            })
            .attach(PurgeLeaseFairing)
            .mount("/", rocket::routes![stream]),
    )
    .await
    .unwrap();
    let response = client.get("/stream").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.headers().get_one("Content-Length"), Some("15"));
    assert_eq!(
        response.headers().get_one("Content-Type"),
        Some("text/plain; charset=utf-8")
    );
    let tx = db.begin().await.unwrap();
    let digest = keys
        .target_hmac("test", "space", &space.to_string())
        .unwrap();
    fence
        .fence_hmac(&tx, "space", "test", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut draining = tokio::spawn(async move { fence.drain(&db, &space).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut draining)
            .await
            .is_err()
    );
    if consume {
        assert_eq!(
            response.into_string().await.as_deref(),
            Some("immutable bytes")
        );
    } else {
        drop(response);
    }
    let _guard = tokio::time::timeout(Duration::from_secs(2), draining)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn purge_waits_for_response_body_and_preserves_wire_headers() {
    response_blocks_purge_until_closed(true).await;
}
#[tokio::test]
async fn cancelled_response_releases_its_operation_lease() {
    response_blocks_purge_until_closed(false).await;
}
