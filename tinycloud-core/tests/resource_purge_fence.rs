use sea_orm::{Database, EntityTrait, TransactionTrait};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tinycloud_core::{
    migrations::Migrator,
    models::space_purge_fence as state,
    resource_purge_fence::ResourceTarget,
    sea_orm_migration::MigratorTrait,
    space_purge_fence::{FenceError, SpacePurgeFence},
    space_purge_ledger::LedgerKeys,
};

#[tokio::test]
async fn resource_fence_drains_owner_work_checks_generation_and_covers_network_keys() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let owner = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    let network =
        ResourceTarget::parse(&format!("urn:tinycloud:encryption:{owner}:default")).unwrap();
    let key = ResourceTarget::parse(&format!("{}/apps/app/key", network.as_str())).unwrap();
    assert!(ResourceTarget::parse(&format!("{}/apps/app/", network.as_str())).is_err());
    let other = ResourceTarget::parse(&format!("urn:tinycloud:encryption:{owner}:other")).unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![12; 32])]),
        )
        .unwrap(),
    );
    let fence = Arc::new(SpacePurgeFence::new(keys.clone()));
    fence.set_serving_ready(true);
    let operation = fence.admit_resource(&db, &key).await.unwrap();
    let tx = db.begin().await.unwrap();
    let hmac = keys
        .target_hmac("test", "resource", network.as_str())
        .unwrap();
    fence
        .fence_hmac(&tx, "resource", "test", &hmac)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        fence.check_resource(&db, &key).await,
        Err(FenceError::Deleted)
    ));
    fence.check_resource(&db, &other).await.unwrap();
    let tx = db.begin().await.unwrap();
    assert!(matches!(
        fence.recheck_resource(&tx, &operation).await,
        Err(FenceError::Deleted)
    ));
    tx.rollback().await.unwrap();
    let draining_fence = fence.clone();
    let draining_db = db.clone();
    let target = network.clone();
    let mut draining =
        tokio::spawn(async move { draining_fence.drain_resource(&draining_db, &target).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut draining)
            .await
            .is_err()
    );
    drop(operation);
    let drain = tokio::time::timeout(Duration::from_secs(2), draining)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(drain.resource().as_str(), network.as_str());
    assert_eq!(drain.resource().owner_did(), owner);
    assert!(
        state::Entity::find_by_id(("resource".into(), hmac, "test".into()))
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .fenced
    );
}
