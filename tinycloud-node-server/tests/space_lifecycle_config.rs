use std::sync::Arc;
use tinycloud::{
    space_lifecycle::LifecycleRuntime,
    storage::{file_system::FileSystemConfig, purge_ledger::PurgeLedgerStore},
};
use tinycloud_core::{
    migrations::Migrator, sea_orm::Database, sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys, storage::StorageConfig,
};

#[tokio::test]
async fn lifecycle_requires_stable_host_and_independent_key_and_cannot_disable_existing_ledger() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let conn = tinycloud_core::RecoveringConnection::from(db);
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FileSystemConfig::new(directory.path())
            .open()
            .await
            .unwrap(),
    );
    let raw = base64::encode_config([9_u8; 32], base64::URL_SAFE_NO_PAD);
    assert!(
        LifecycleRuntime::from_settings(conn.clone(), store.clone(), None, None)
            .await
            .unwrap()
            .is_none()
    );
    for (host, key) in [
        (Some("stable-host"), None),
        (None, Some(raw.as_str())),
        (Some(""), Some(raw.as_str())),
        (Some("Host"), Some(raw.as_str())),
        (Some("a/b"), Some(raw.as_str())),
        (Some("stable-host"), Some("invalid-key")),
    ] {
        assert!(LifecycleRuntime::from_settings(
            conn.clone(),
            store.clone(),
            host.map(str::to_owned),
            key.map(str::to_owned),
        )
        .await
        .is_err());
    }
    assert!(LifecycleRuntime::from_settings(
        conn.clone(),
        store.clone(),
        Some("stable-host".into()),
        Some(raw.clone()),
    )
    .await
    .unwrap()
    .is_some());
    let keys = LedgerKeys::from_config(raw).unwrap();
    let owner_hmac = keys
        .target_hmac(
            keys.active_key_id(),
            "owner",
            "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        )
        .unwrap();
    let record = keys
        .sign(
            keys.active_key_id(),
            "owner",
            &owner_hmac,
            &uuid::Uuid::new_v4().to_string(),
            "retired",
            1,
        )
        .unwrap();
    store
        .append_purge_record(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .await
        .unwrap();
    assert!(LifecycleRuntime::from_settings(conn, store, None, None)
        .await
        .is_err());
}
