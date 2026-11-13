use std::{collections::BTreeMap, sync::Arc};
use tinycloud::storage::{
    file_system::FileSystemConfig,
    purge_ledger::PurgeLedgerStore,
    purge_reconcile::{
        finish_absent_prefix, repair_acceptance_copies, repair_one, scan_store_inventory,
        PrefixStoreKind, RepairOneOutcome, VerifiedPurgePrefix,
    },
    purge_restore::RestorePurgeStore,
    sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore},
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    migrations::Migrator,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement},
    sea_orm_migration::MigratorTrait,
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::LedgerKeys,
    storage::StorageConfig,
};

#[tokio::test]
async fn postgres_restore_driver_deletes_only_matched_hash_prefix_and_proves_absence_after_restart()
{
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").expect("isolated PostgreSQL URL");
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("restore_driver_{}", uuid::Uuid::new_v4().simple());
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
    let root = tempfile::tempdir().unwrap();
    let blocks = root.path().join("blocks");
    let sql_root = root.path().join("sql-store");
    let ledger = FileSystemConfig::new(&blocks).open().await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![13; 32])]),
        )
        .unwrap(),
    );
    let suffix = format!("{}{}", ".".repeat(95), uuid::Uuid::new_v4().simple());
    let target: SpaceId =
        format!("tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:a{suffix}")
            .parse()
            .unwrap();
    let neighbor: SpaceId =
        format!("tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:b{suffix}")
            .parse()
            .unwrap();
    let target_prefix = SqlPhysicalPrefix::for_space(&target);
    let neighbor_prefix = SqlPhysicalPrefix::for_space(&neighbor);
    assert!(target_prefix.as_str().starts_with("sql/v1/~"));
    let kind = PrefixStoreKind::SqlFileSystem;
    let record = keys
        .with_prefixes(
            keys.sign(
                "test",
                "space",
                &keys
                    .target_hmac("test", "space", &target.to_string())
                    .unwrap(),
                &uuid::Uuid::new_v4().to_string(),
                "purging",
                1,
            )
            .unwrap(),
            vec![keys
                .prefix_hmac("test", kind.as_str(), target_prefix.as_str())
                .unwrap()],
        )
        .unwrap();
    let path = record.object_key().unwrap();
    let body = record.to_bytes().unwrap();
    ledger.append_purge_record(&path, &body).await.unwrap();
    let target_directory = sql_root.join(target_prefix.as_str());
    let neighbor_directory = sql_root.join(neighbor_prefix.as_str());
    std::fs::create_dir_all(&target_directory).unwrap();
    std::fs::create_dir_all(&neighbor_directory).unwrap();
    for i in 0..300 {
        std::fs::write(target_directory.join(format!("part-{i}")), b"target bytes").unwrap();
    }
    std::fs::write(neighbor_directory.join("keep"), b"neighbor bytes").unwrap();
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    repair_acceptance_copies(&db, &ledger, &keys, &drain, |_| Ok(()))
        .await
        .unwrap();
    let store = FsSqlObjectStore::open(sql_root.clone(), &blocks).unwrap();
    let inventory = scan_store_inventory(
        &RestorePurgeStore::SqlFileSystem(&store),
        &keys,
        &fence,
        &drain,
    )
    .await
    .unwrap();
    let digest = &record.prefixes[0].prefix_hmac;
    assert!(inventory.prove_absent(&path, &body, digest).is_err());
    let candidate = inventory.matching_prefix("test", digest).unwrap();
    let proof =
        VerifiedPurgePrefix::verify_candidate(&keys, &path, &body, kind, candidate).unwrap();
    let mut completed = false;
    for _ in 0..5 {
        // Reopen physical storage between batches; progress lives in PostgreSQL,
        // and the hashed namespace is never reversed into a synthetic SpaceId.
        let reopened = FsSqlObjectStore::open(sql_root.clone(), &blocks).unwrap();
        match repair_one(
            &db,
            RestorePurgeStore::SqlFileSystem(&reopened),
            &fence,
            &drain,
            &proof,
        )
        .await
        .unwrap()
        {
            RepairOneOutcome::MoreObjects => {}
            RepairOneOutcome::VerifiedEmpty => {
                completed = true;
                break;
            }
            _ => panic!("unexpected repair state"),
        }
    }
    assert!(completed);
    assert!(!target_directory.exists());
    assert_eq!(
        std::fs::read(neighbor_directory.join("keep")).unwrap(),
        b"neighbor bytes"
    );
    let current = scan_store_inventory(
        &RestorePurgeStore::SqlFileSystem(&store),
        &keys,
        &fence,
        &drain,
    )
    .await
    .unwrap();
    let absent = current.prove_absent(&path, &body, digest).unwrap();
    tinycloud_core::space_purge_prefix_repair::enqueue(&db, &keys, &record)
        .await
        .unwrap();
    assert_eq!(
        finish_absent_prefix(&db, &absent).await.unwrap(),
        RepairOneOutcome::VerifiedEmpty
    );
    assert!(fence.check(&db, &target).await.is_err());
    // Physical progress alone neither enables serving nor claims terminal purge.
    assert!(ledger.read_purge_record(&path).await.unwrap().is_some());
    drop(absent);
    drop(current);
    drop(inventory);
    drop(drain);
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}
