use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TransactionTrait};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    migrations::Migrator,
    sea_orm_migration::MigratorTrait,
    space_purge_fence::{FenceError, SpacePurgeFence},
    space_purge_ledger::LedgerKeys,
};

fn setup() -> (Arc<LedgerKeys>, Arc<SpacePurgeFence>, SpaceId) {
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![3; 32])]),
        )
        .unwrap(),
    );
    let fence = Arc::new(SpacePurgeFence::new(keys.clone()));
    let space = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
        .parse()
        .unwrap();
    (keys, fence, space)
}

#[tokio::test]
async fn drain_waits_for_operations_and_orphan_pass_but_not_other_space_requests() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let (keys, fence, space) = setup();
    assert!(matches!(
        fence.admit(&db, &space).await,
        Err(FenceError::Unavailable)
    ));
    fence.set_serving_ready(true);
    let operation = fence.admit(&db, &space).await.unwrap();
    let collector = fence.collector_operation().await;
    let tx = db.begin().await.unwrap();
    let digest = keys
        .target_hmac("test", "space", &space.to_string())
        .unwrap();
    assert_eq!(
        fence
            .fence_hmac(&tx, "space", "test", &digest)
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    let tx = db.begin().await.unwrap();
    assert!(matches!(
        fence.recheck(&tx, &operation).await,
        Err(FenceError::Deleted)
    ));
    tx.rollback().await.unwrap();
    let drain_fence = fence.clone();
    let drain_db = db.clone();
    let drain_space = space.clone();
    let mut draining =
        tokio::spawn(async move { drain_fence.drain(&drain_db, &drain_space).await.unwrap() });
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut draining)
            .await
            .is_err()
    );
    drop(collector);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut draining)
            .await
            .is_err()
    );
    drop(operation);
    let guard = tokio::time::timeout(Duration::from_secs(2), draining)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(guard.space(), &space);
    assert!(matches!(
        fence.admit(&db, &space).await,
        Err(FenceError::Deleted)
    ));
    let other = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:other"
        .parse()
        .unwrap();
    assert!(fence.admit(&db, &other).await.is_ok());
    drop(guard);
    let tx = db.begin().await.unwrap();
    assert_eq!(
        fence
            .fence_hmac(&tx, "space", "test", &digest)
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn postgres_commit_lock_orders_the_fence_and_refuses_a_stale_admission() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").unwrap();
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_fence_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let (keys, fence, space) = setup();
    fence.set_serving_ready(true);
    let operation = fence.admit(&db, &space).await.unwrap();
    let writer = db.begin().await.unwrap();
    fence.recheck(&writer, &operation).await.unwrap();
    let retiring_fence = fence.clone();
    let retiring_db = db.clone();
    let digest = keys
        .target_hmac("test", "space", &space.to_string())
        .unwrap();
    let mut retirement = tokio::spawn(async move {
        let tx = retiring_db.begin().await.unwrap();
        let generation = retiring_fence
            .fence_hmac(&tx, "space", "test", &digest)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        generation
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut retirement)
            .await
            .is_err()
    );
    writer.commit().await.unwrap();
    assert_eq!(retirement.await.unwrap(), 1);
    let late = db.begin().await.unwrap();
    assert!(matches!(
        fence.recheck(&late, &operation).await,
        Err(FenceError::Deleted)
    ));
    late.rollback().await.unwrap();
    drop(operation);
    fence.set_serving_ready(false);
    assert!(matches!(
        fence.admit(&db, &space).await,
        Err(FenceError::Unavailable)
    ));
    // Restore-time workers can drain fenced state while ordinary serving is disabled.
    let guard = fence.drain(&db, &space).await.unwrap();
    drop(guard);
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}
