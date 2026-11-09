use super::*;
use crate::{storage::file_system::FileSystemConfig as NodeFileSystemConfig, TinyCloud};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};
use std::{convert::Infallible, net::TcpListener};
use tempfile::TempDir;
use tinycloud_core::{
    db::{HOOK_DELIVERY_STATUS_DELIVERED, HOOK_DELIVERY_STATUS_PENDING},
    keys::StaticSecret,
    models::{hook_delivery, hook_subscription},
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait,
        Statement,
    },
    storage::either::Either,
    storage::StorageConfig as _,
};

const OWNER_DID: &str = "did:key:z6Mkpcii8rkJV79k3JV37Wm5utAU6WkRsziqXf6mpMs734vB";
const SPACE_ID: &str = "tinycloud:key:z6Mkpcii8rkJV79k3JV37Wm5utAU6WkRsziqXf6mpMs734vB:files";
const LEASE: Duration = Duration::from_secs(60);

async fn setup() -> Result<(TempDir, TinyCloud, DatabaseConnection, ColumnEncryption)> {
    let tempdir = TempDir::new()?;
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
    let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
    let encryption = ColumnEncryption::new([9u8; 32]);
    let tinycloud = TinyCloud::new_with_encryption(
        db.clone().into(),
        Either::B(storage),
        StaticSecret::new(vec![0u8; 32]).unwrap(),
        Some(encryption.clone()),
    )
    .await?;
    Ok((tempdir, tinycloud, db, encryption))
}

/// Callback server that records the `X-TinyCloud-Event-Id` of every request.
async fn callback_server() -> Result<(String, Arc<std::sync::Mutex<Vec<String>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let make_service = make_service_fn(move |_| {
        let log = log.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |request: Request<Body>| {
                let log = log.clone();
                async move {
                    let event = request
                        .headers()
                        .get("X-TinyCloud-Event-Id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    log.lock().unwrap().push(event);
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::from(""))
                            .unwrap(),
                    )
                }
            }))
        }
    });
    rocket::tokio::spawn(async move {
        let _ = Server::from_tcp(listener)
            .unwrap()
            .serve(make_service)
            .await;
    });
    Ok((format!("http://{address}/hooks"), seen))
}

async fn insert_deliveries(
    db: &DatabaseConnection,
    encryption: &ColumnEncryption,
    callback_url: &str,
    count: usize,
) -> Result<()> {
    hook_subscription::Entity::insert(hook_subscription::ActiveModel::from(
        hook_subscription::Model {
            id: "sub_01".to_string(),
            subscriber_did: OWNER_DID.to_string(),
            space_id: SPACE_ID.to_string(),
            target_service: "kv".to_string(),
            path_prefix: Some("documents".to_string()),
            abilities_json: Some(
                serde_json::to_string(&vec!["tinycloud.kv/put".to_string()]).unwrap(),
            ),
            callback_url: callback_url.to_string(),
            encrypted_secret: encryption.encrypt(b"hook-secret"),
            secret_key_id: PRIMARY_SECRET_KEY_ID.to_string(),
            active: true,
            created_at: "2026-04-09T00:00:00Z".to_string(),
        },
    ))
    .exec(db)
    .await?;
    for index in 0..count {
        hook_delivery::Entity::insert(hook_delivery::ActiveModel::from(hook_delivery::Model {
            id: format!("delivery_{index:02}"),
            subscription_id: "sub_01".to_string(),
            event_id: format!("event_{index:02}"),
            payload_json: "{}".to_string(),
            status: HOOK_DELIVERY_STATUS_PENDING.to_string(),
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            created_at: format!("2026-04-09T00:00:{index:02}Z"),
            delivered_at: None,
        }))
        .exec(db)
        .await?;
    }
    Ok(())
}

fn dispatcher(tinycloud: &TinyCloud, encryption: &ColumnEncryption) -> Result<WebhookDispatcher> {
    WebhookDispatcher::new(
        tinycloud.clone(),
        HooksConfig::default(),
        encryption.clone(),
        EgressPolicy::test_loopback(),
    )
}

#[tokio::test]
async fn two_concurrent_dispatchers_send_each_delivery_once() -> Result<()> {
    let (_tempdir, tinycloud, db, encryption) = setup().await?;
    let (callback_url, seen) = callback_server().await?;
    insert_deliveries(&db, &encryption, &callback_url, 8).await?;
    let first = dispatcher(&tinycloud, &encryption)?;
    let second = dispatcher(&tinycloud, &encryption)?;

    let (a, b) = tokio::join!(first.dispatch_due_once(), second.dispatch_due_once());
    a?;
    b?;

    let mut events = seen.lock().unwrap().clone();
    events.sort();
    let expected: Vec<String> = (0..8).map(|index| format!("event_{index:02}")).collect();
    assert_eq!(events, expected, "each delivery is sent exactly once");
    let rows = hook_delivery::Entity::find().all(&db).await?;
    assert!(rows
        .iter()
        .all(|row| row.status == HOOK_DELIVERY_STATUS_DELIVERED && row.attempts == 1));
    Ok(())
}

#[tokio::test]
async fn unexpired_lease_blocks_second_claim() -> Result<()> {
    let (_tempdir, tinycloud, db, encryption) = setup().await?;
    insert_deliveries(&db, &encryption, "http://127.0.0.1:9/hooks", 1).await?;

    let first = tinycloud.claim_due_webhook_deliveries(10, LEASE).await?;
    let second = tinycloud.claim_due_webhook_deliveries(10, LEASE).await?;

    assert_eq!(first.len(), 1);
    assert!(second.is_empty());
    Ok(())
}

#[tokio::test]
async fn stale_mark_after_reclaim_is_refused() -> Result<()> {
    let (_tempdir, tinycloud, db, encryption) = setup().await?;
    insert_deliveries(&db, &encryption, "http://127.0.0.1:9/hooks", 1).await?;

    let stale = tinycloud
        .claim_due_webhook_deliveries(1, Duration::ZERO)
        .await?
        .remove(0);
    let current = tinycloud
        .claim_due_webhook_deliveries(1, LEASE)
        .await?
        .remove(0);
    assert_eq!(stale.id, current.id);
    assert_ne!(stale.lease_token, current.lease_token);

    assert!(
        !tinycloud
            .mark_webhook_delivery_delivered(&stale.id, &stale.lease_token, 1)
            .await?
    );
    assert!(
        !tinycloud
            .mark_webhook_delivery_failed(&stale.id, &stale.lease_token, 1, None, "x".into(), true)
            .await?
    );
    let row = hook_delivery::Entity::find_by_id(stale.id.clone())
        .one(&db)
        .await?
        .unwrap();
    assert_eq!(row.status, HOOK_DELIVERY_STATUS_PENDING);
    assert_eq!(row.attempts, 0);

    assert!(
        tinycloud
            .mark_webhook_delivery_delivered(&current.id, &current.lease_token, 1)
            .await?
    );
    assert!(
        !tinycloud
            .mark_webhook_delivery_delivered(&current.id, &current.lease_token, 1)
            .await?,
        "a settled delivery cannot be marked again"
    );
    Ok(())
}

#[tokio::test]
async fn expired_lease_is_claimed_again() -> Result<()> {
    let (_tempdir, tinycloud, db, encryption) = setup().await?;
    insert_deliveries(&db, &encryption, "http://127.0.0.1:9/hooks", 1).await?;
    let first = tinycloud
        .claim_due_webhook_deliveries(1, LEASE)
        .await?
        .remove(0);

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "UPDATE hook_delivery SET lease_expires_at = '2000-01-01T00:00:00Z'".to_string(),
    ))
    .await?;

    let again = tinycloud.claim_due_webhook_deliveries(1, LEASE).await?;
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].id, first.id);
    assert_ne!(again[0].lease_token, first.lease_token);
    Ok(())
}

#[tokio::test]
async fn released_lease_is_claimable_at_once_and_stale_release_is_refused() -> Result<()> {
    let (_tempdir, tinycloud, db, encryption) = setup().await?;
    insert_deliveries(&db, &encryption, "http://127.0.0.1:9/hooks", 1).await?;

    let first = tinycloud
        .claim_due_webhook_deliveries(1, LEASE)
        .await?
        .remove(0);
    assert!(
        !tinycloud
            .release_webhook_delivery_lease(&first.id, "not-the-token")
            .await?
    );
    assert!(tinycloud
        .claim_due_webhook_deliveries(1, LEASE)
        .await?
        .is_empty());

    assert!(
        tinycloud
            .release_webhook_delivery_lease(&first.id, &first.lease_token)
            .await?
    );
    let second = tinycloud
        .claim_due_webhook_deliveries(1, LEASE)
        .await?
        .remove(0);
    assert_eq!(second.id, first.id);
    assert!(
        !tinycloud
            .mark_webhook_delivery_delivered(&first.id, &first.lease_token, 1)
            .await?,
        "the released holder can no longer mark"
    );
    Ok(())
}

/// Two dispatchers on separate PostgreSQL pools (real concurrent connections).
/// Gated like the other PostgreSQL-backed tests: skips locally, panics on
/// GitHub Actions if the database URL is missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_two_pools_claim_each_delivery_once_and_refuse_stale_marks() -> Result<()> {
    use std::collections::BTreeSet;

    let Some(url) = crate::test_support::postgres_test_url(
        "postgres_two_pools_claim_each_delivery_once_and_refuse_stale_marks",
    ) else {
        return Ok(());
    };
    let admin = Database::connect(ConnectOptions::new(url.clone())).await?;
    let schema = format!(
        "tc2614_lease_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;

    let encryption = ColumnEncryption::new([9u8; 32]);
    let tempdir = TempDir::new()?;
    let mut pools = Vec::new();
    for _ in 0..2 {
        let mut pool_url = reqwest::Url::parse(&url)?;
        pool_url
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let mut config = crate::config::Config::default();
        config.storage.database = Some(pool_url.to_string());
        config.database.max_connections = 8;
        let conn = crate::connect_database(&config).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        pools.push(
            TinyCloud::new_with_encryption(
                conn,
                Either::B(storage),
                StaticSecret::new(vec![0u8; 32]).unwrap(),
                Some(encryption.clone()),
            )
            .await?,
        );
    }
    let mut setup_options = ConnectOptions::new(url.clone());
    setup_options
        .max_connections(2)
        .sqlx_logging(false)
        .set_schema_search_path(schema.clone());
    let setup = Database::connect(setup_options).await?;
    insert_deliveries(&setup, &encryption, "http://127.0.0.1:9/hooks", 40).await?;

    let (first, second) = (pools[0].clone(), pools[1].clone());
    let claim_a = tokio::spawn(async move { first.claim_due_webhook_deliveries(40, LEASE).await });
    let claim_b = tokio::spawn(async move { second.claim_due_webhook_deliveries(40, LEASE).await });
    let (claimed_a, claimed_b) = (claim_a.await??, claim_b.await??);
    let ids_a: BTreeSet<_> = claimed_a.iter().map(|d| d.id.clone()).collect();
    let ids_b: BTreeSet<_> = claimed_b.iter().map(|d| d.id.clone()).collect();
    assert!(ids_a.is_disjoint(&ids_b), "a delivery was claimed twice");
    assert_eq!(ids_a.len() + ids_b.len(), 40, "every delivery is claimed");

    // A stale mark after a re-claim by the other pool is refused.
    setup
        .execute_unprepared("UPDATE hook_delivery SET lease_expires_at = '2000-01-01T00:00:00Z' WHERE id = 'delivery_00'")
        .await?;
    let holder = claimed_a
        .iter()
        .chain(claimed_b.iter())
        .find(|d| d.id == "delivery_00")
        .unwrap()
        .clone();
    let reclaimed = pools[1]
        .claim_due_webhook_deliveries(40, LEASE)
        .await?
        .remove(0);
    assert_eq!(reclaimed.id, holder.id);
    assert!(
        !pools[0]
            .mark_webhook_delivery_delivered(&holder.id, &holder.lease_token, 1)
            .await?
    );
    assert!(
        pools[1]
            .mark_webhook_delivery_delivered(&reclaimed.id, &reclaimed.lease_token, 1)
            .await?
    );

    drop(pools);
    setup.close().await?;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await?;
    Ok(())
}
