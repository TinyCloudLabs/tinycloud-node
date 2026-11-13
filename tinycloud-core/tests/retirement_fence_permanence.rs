use sea_orm::{Database, TransactionTrait};
use std::{collections::BTreeMap, sync::Arc};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    migrations::Migrator,
    sea_orm_migration::MigratorTrait,
    space_purge_fence::{FenceError, SpacePurgeFence},
    space_purge_ledger::LedgerKeys,
};

#[tokio::test]
async fn retirement_refuses_reopening_existing_or_new_owner_targets_after_restart() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![7; 32])]),
        )
        .unwrap(),
    );
    let existing: SpaceId =
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:existing"
            .parse()
            .unwrap();
    let new: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:new"
        .parse()
        .unwrap();
    let fence = SpacePurgeFence::new(keys.clone());
    fence.set_serving_ready(true);
    let admitted = fence.admit(&db, &existing).await.unwrap();
    let owner = keys
        .target_hmac("test", "owner", existing.did().as_str())
        .unwrap();
    let tx = db.begin().await.unwrap();
    fence
        .fence_hmac(&tx, "owner", "test", &owner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = db.begin().await.unwrap();
    assert!(matches!(
        fence.recheck(&tx, &admitted).await,
        Err(FenceError::Deleted)
    ));
    tx.rollback().await.unwrap();
    drop(admitted);
    // A fresh runtime and admission-row creation cannot reopen the owner.
    let restarted = SpacePurgeFence::new(keys);
    restarted.set_serving_ready(true);
    assert!(matches!(
        restarted.admit(&db, &existing).await,
        Err(FenceError::Deleted)
    ));
    assert!(matches!(
        restarted.admit(&db, &new).await,
        Err(FenceError::Deleted)
    ));
    let tx = db.begin().await.unwrap();
    assert!(matches!(
        restarted.lock_live(&tx, &new).await,
        Err(FenceError::Deleted)
    ));
    tx.rollback().await.unwrap();
}
