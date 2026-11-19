use sea_orm::{Database, TransactionTrait};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    migrations::Migrator,
    resource_purge_fence::ResourceTarget,
    sea_orm_migration::MigratorTrait,
    space_purge_fence::{FenceError, SpacePurgeFence},
    space_purge_ledger::LedgerKeys,
};

#[tokio::test]
async fn restore_drains_all_admissions_and_derived_worker_guard_keeps_it_exclusive() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![15; 32])]),
        )
        .unwrap(),
    );
    let fence = Arc::new(SpacePurgeFence::new(keys.clone()));
    fence.set_serving_ready(true);
    let owner = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    let space: SpaceId = format!("tinycloud:{}:files", &owner[4..]).parse().unwrap();
    let resource =
        ResourceTarget::parse(&format!("urn:tinycloud:encryption:{owner}:default")).unwrap();
    let read = fence.admit(&db, &space).await.unwrap();
    let key_use = fence.admit_resource(&db, &resource).await.unwrap();
    let collector = fence.collector_operation().await;
    let management = fence.lifecycle_operation().await;
    let restore_fence = fence.clone();
    let mut restoring = tokio::spawn(async move { restore_fence.restore_drain().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut restoring)
            .await
            .is_err()
    );
    drop(read);
    drop(key_use);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut restoring)
            .await
            .is_err()
    );
    drop(collector);
    drop(management);
    let restore = tokio::time::timeout(Duration::from_secs(2), restoring)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        fence.check(&db, &space).await,
        Err(FenceError::Unavailable)
    ));
    let tx = db.begin().await.unwrap();
    let digest = keys
        .target_hmac("test", "space", &space.to_string())
        .unwrap();
    fence
        .fence_hmac(&tx, "space", "test", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let foreign_fence = SpacePurgeFence::new(keys);
    assert!(matches!(
        foreign_fence
            .drain_during_restore(&db, &space, &restore)
            .await,
        Err(FenceError::Unavailable)
    ));
    let restoring_worker = fence
        .drain_during_restore(&db, &space, &restore)
        .await
        .unwrap();
    drop(restore);
    let normal_fence = fence.clone();
    let normal_db = db.clone();
    let target = space.clone();
    let mut normal = tokio::spawn(async move { normal_fence.drain(&normal_db, &target).await });
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut normal)
        .await
        .is_err());
    drop(restoring_worker);
    let _normal = tokio::time::timeout(Duration::from_secs(2), normal)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        fence.check(&db, &space).await,
        Err(FenceError::Unavailable)
    ));
}

#[tokio::test]
async fn resource_restore_drain_retains_the_verified_barrier_until_key_cleanup_finishes() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![18; 32])]),
        )
        .unwrap(),
    );
    let fence = Arc::new(SpacePurgeFence::new(keys.clone()));
    let target = ResourceTarget::parse("urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default").unwrap();
    let tx = db.begin().await.unwrap();
    let digest = keys
        .target_hmac("test", "resource", target.as_str())
        .unwrap();
    fence
        .fence_hmac(&tx, "resource", "test", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let restore = fence.restore_drain().await;
    let foreign = SpacePurgeFence::new(keys);
    assert!(matches!(
        foreign
            .drain_resource_during_restore(&db, &target, &restore)
            .await,
        Err(FenceError::Unavailable)
    ));
    let drain = fence
        .drain_resource_during_restore(&db, &target, &restore)
        .await
        .unwrap();
    assert_eq!(drain.resource().as_str(), target.as_str());
    drop(restore);
    let waiting_fence = fence.clone();
    let mut admission = tokio::spawn(async move { waiting_fence.lifecycle_operation().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut admission)
            .await
            .is_err()
    );
    drop(drain);
    let _admission = tokio::time::timeout(Duration::from_secs(2), admission)
        .await
        .unwrap()
        .unwrap();
}
