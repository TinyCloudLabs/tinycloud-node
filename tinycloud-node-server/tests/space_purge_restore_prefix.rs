//! Physical-side crash prerequisites for V17.1-LEDGER-FORWARD-COMPLETE-01.
//! Full dual-write transition tests belong to the durable repair orchestrator.
use std::{collections::BTreeMap, sync::Arc};
use tinycloud::storage::{
    file_system::FileSystemConfig,
    purge_ledger::PurgeLedgerStore,
    purge_reconcile::{PrefixStoreKind, VerifiedPurgePrefix},
    purge_restore::{purge_restore_prefix_batch, RestorePrefixOutcome, RestorePurgeStore},
    sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore},
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    storage::StorageConfig,
};

fn keys() -> Arc<LedgerKeys> {
    Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![31; 32])]),
        )
        .unwrap(),
    )
}

fn accepted(
    keys: &LedgerKeys,
    kind: PrefixStoreKind,
) -> (LedgerRecord, SqlPhysicalPrefix, SqlPhysicalPrefix) {
    // A valid dot-heavy lowercase name reaches SQL's hashed encoding. The
    // repair caller receives only opaque ledger evidence and physical prefixes.
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let original_name = format!("a{}{nonce}", ".".repeat(95));
    let neighbor_name = format!("b{}{nonce}", ".".repeat(95));
    let original: SpaceId = format!(
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:{original_name}"
    )
    .parse()
    .unwrap();
    let neighbor: SpaceId = format!(
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:{neighbor_name}"
    )
    .parse()
    .unwrap();
    let target = SqlPhysicalPrefix::for_space(&original);
    let neighbor = SqlPhysicalPrefix::for_space(&neighbor);
    assert!(target.as_str().starts_with("sql/v1/~"));
    let target_hmac = keys
        .target_hmac("test", "space", &original.to_string())
        .unwrap();
    let prefix_hmac = keys
        .prefix_hmac("test", kind.as_str(), target.as_str())
        .unwrap();
    let record = keys
        .with_prefixes(
            keys.sign(
                "test",
                "space",
                &target_hmac,
                &uuid::Uuid::new_v4().to_string(),
                "purging",
                1,
            )
            .unwrap(),
            vec![prefix_hmac],
        )
        .unwrap();
    (record, target, neighbor)
}

#[tokio::test]
async fn authenticated_hashed_restore_restarts_without_raw_space_and_preserves_ahead_ledger() {
    let root = tempfile::tempdir().unwrap();
    let blocks_root = root.path().join("blocks");
    let ledger = FileSystemConfig::new(&blocks_root).open().await.unwrap();
    let sql_root = root.path().join("sql-store");
    let store = FsSqlObjectStore::open(sql_root.clone(), &blocks_root).unwrap();
    let keys = keys();
    let (accepted, target, neighbor) = accepted(&keys, PrefixStoreKind::SqlFileSystem);
    let completion = keys
        .with_prefixes(
            keys.sign(
                "test",
                "space",
                &hex::decode(&accepted.target_hmac).unwrap(),
                &accepted.operation_id,
                "complete",
                2,
            )
            .unwrap(),
            accepted.prefixes.clone(),
        )
        .unwrap();
    let accepted_key = accepted.object_key().unwrap();
    let completion_key = completion.object_key().unwrap();
    let completion_body = completion.to_bytes().unwrap();
    ledger
        .append_purge_record(&accepted_key, &accepted.to_bytes().unwrap())
        .await
        .unwrap();
    ledger
        .append_purge_record(&completion_key, &completion_body)
        .await
        .unwrap();
    let directory = sql_root.join(target.as_str());
    let adjacent = sql_root.join(neighbor.as_str());
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::create_dir_all(&adjacent).unwrap();
    for index in 0..260 {
        std::fs::write(directory.join(index.to_string()), b"synthetic payload").unwrap();
    }
    std::fs::write(adjacent.join("keep"), b"synthetic neighbor").unwrap();
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &completion_key,
        &completion_body,
        PrefixStoreKind::SqlFileSystem,
        neighbor.as_str()
    )
    .is_err());
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &completion_key,
        &completion_body,
        PrefixStoreKind::SqlS3,
        target.as_str()
    )
    .is_err());
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &completion_key,
        &completion_body,
        PrefixStoreKind::SqlFileSystem,
        target.as_str(),
    )
    .unwrap();
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    assert!(
        purge_restore_prefix_batch(RestorePurgeStore::KvFileSystem(&ledger), &drain, &proof)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 260);
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqlFileSystem(&store), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::MoreObjects
    );
    assert!(std::fs::read_dir(&directory).unwrap().count() > 0);
    assert!(
        ledger
            .read_purge_record(&completion_key)
            .await
            .unwrap()
            .unwrap()
            == completion_body
    );
    drop(drain);
    drop(store);
    drop(ledger);
    // Crash/restart after one destructive batch: no cursor, owner lookup, raw
    // SpaceId, synthetic space job, or previous claim participates in resumption.
    let ledger = FileSystemConfig::new(&blocks_root).open().await.unwrap();
    let store = FsSqlObjectStore::open(sql_root.clone(), &blocks_root).unwrap();
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    let body = ledger
        .read_purge_record(&completion_key)
        .await
        .unwrap()
        .unwrap();
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &completion_key,
        &body,
        PrefixStoreKind::SqlFileSystem,
        target.as_str(),
    )
    .unwrap();
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqlFileSystem(&store), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::MoreObjects
    );
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqlFileSystem(&store), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::VerifiedEmpty
    );
    assert!(!directory.exists());
    assert!(std::fs::read(adjacent.join("keep")).unwrap() == b"synthetic neighbor");
    assert!(
        ledger
            .read_purge_record(&completion_key)
            .await
            .unwrap()
            .unwrap()
            == completion_body
    );
    assert!(ledger
        .read_purge_record(&accepted_key)
        .await
        .unwrap()
        .is_some());
}

#[test]
fn acceptance_prefix_proof_is_required_and_tampering_never_authorizes_repair() {
    let keys = keys();
    let (accepted, target, _) = accepted(&keys, PrefixStoreKind::SqlFileSystem);
    let path = accepted.object_key().unwrap();
    let body = accepted.to_bytes().unwrap();
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &body,
        PrefixStoreKind::SqlFileSystem,
        target.as_str()
    )
    .is_ok());
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        b"",
        PrefixStoreKind::SqlFileSystem,
        target.as_str()
    )
    .is_err());
    let mut changed_inventory = accepted.clone();
    changed_inventory.prefixes[0].prefix_hmac = "00".repeat(32);
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &changed_inventory.to_bytes().unwrap(),
        PrefixStoreKind::SqlFileSystem,
        target.as_str()
    )
    .is_err());
    let mut changed = accepted.clone();
    changed.state = "complete".into();
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &changed.to_bytes().unwrap(),
        PrefixStoreKind::SqlFileSystem,
        target.as_str()
    )
    .is_err());
    let old = keys
        .sign(
            "test",
            "space",
            &hex::decode(&accepted.target_hmac).unwrap(),
            &accepted.operation_id,
            "purging",
            1,
        )
        .unwrap();
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &old.to_bytes().unwrap(),
        PrefixStoreKind::SqlFileSystem,
        target.as_str()
    )
    .is_err());
}

#[tokio::test]
async fn minio_authenticated_hashed_restore_rechecks_empty_after_lost_batch_progress() {
    use tinycloud::storage::{
        s3::S3BlockConfig,
        sql_object::{S3SqlObjectStore, WriteMode},
    };
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let bucket = std::env::var("TC735_TEST_MINIO_BUCKET").unwrap();
    let ledger = S3BlockConfig {
        bucket: bucket.clone(),
        endpoint: Some(endpoint.parse().unwrap()),
    }
    .open()
    .await
    .unwrap();
    let keys = keys();
    let (accepted, target, neighbor) = accepted(&keys, PrefixStoreKind::SqlS3);
    let path = accepted.object_key().unwrap();
    let body = accepted.to_bytes().unwrap();
    ledger.append_purge_record(&path, &body).await.unwrap();
    let neighbor_key = format!("{}keep", neighbor.as_str());
    ledger
        .client
        .put_object()
        .bucket(&bucket)
        .key(&neighbor_key)
        .body(b"synthetic neighbor".to_vec().into())
        .send()
        .await
        .unwrap();
    for index in 0..260 {
        ledger
            .client
            .put_object()
            .bucket(&bucket)
            .key(format!("{}{index}", target.as_str()))
            .body(b"synthetic payload".to_vec().into())
            .send()
            .await
            .unwrap();
    }
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &body,
        PrefixStoreKind::SqlS3,
        target.as_str(),
    )
    .unwrap();
    let store = S3SqlObjectStore::new(
        ledger.client.clone(),
        bucket.clone(),
        WriteMode::Conditional,
    );
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqlS3(&store), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::MoreObjects
    );
    drop(store);
    drop(drain);
    // Simulate losing the last batch acknowledgement: retry from the beginning
    // with new runtime guards and the original immutable accepted inventory.
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    let store = S3SqlObjectStore::new(
        ledger.client.clone(),
        bucket.clone(),
        WriteMode::Conditional,
    );
    let stored = ledger.read_purge_record(&path).await.unwrap().unwrap();
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &stored,
        PrefixStoreKind::SqlS3,
        target.as_str(),
    )
    .unwrap();
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqlS3(&store), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::MoreObjects
    );
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqlS3(&store), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::VerifiedEmpty
    );
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &stored,
        PrefixStoreKind::SqlS3,
        neighbor.as_str()
    )
    .is_err());
    let neighbor_bytes = ledger
        .client
        .get_object()
        .bucket(&bucket)
        .key(&neighbor_key)
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes();
    assert!(neighbor_bytes.as_ref() == b"synthetic neighbor");
    assert!(ledger.read_purge_record(&path).await.unwrap().unwrap() == body);
    // Fixture cleanup is one exact object created by this test, outside repair.
    ledger
        .client
        .delete_object()
        .bucket(&bucket)
        .key(&neighbor_key)
        .send()
        .await
        .unwrap();
}

fn cache_record(keys: &LedgerKeys, space: &SpaceId, kind: PrefixStoreKind) -> LedgerRecord {
    let target = keys
        .target_hmac("test", "space", &space.to_string())
        .unwrap();
    let prefix = keys
        .prefix_hmac("test", kind.as_str(), &format!("{space}/"))
        .unwrap();
    keys.with_prefixes(
        keys.sign(
            "test",
            "space",
            &target,
            &uuid::Uuid::new_v4().to_string(),
            "purging",
            1,
        )
        .unwrap(),
        vec![prefix],
    )
    .unwrap()
}

#[tokio::test]
async fn sqlite_cache_prefix_closes_live_actors_and_preserves_neighbor_export() {
    use tinycloud_core::{
        database_artifacts::SeaOrmDatabaseArtifactRepository,
        migrations::Migrator,
        sea_orm::Database,
        sea_orm_migration::MigratorTrait,
        sql::{SqlRequest, SqlService},
    };
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("sqlite-cache");
    let ledger = FileSystemConfig::new(root.path().join("blocks"))
        .open()
        .await
        .unwrap();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let service = SqlService::new(
        cache.to_string_lossy().into_owned(),
        0,
        Arc::new(SeaOrmDatabaseArtifactRepository::new(db)),
    );
    let target: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:cache"
        .parse()
        .unwrap();
    let neighbor: SpaceId =
        "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:cache"
            .parse()
            .unwrap();
    for space in [&target, &neighbor] {
        service
            .execute(
                space,
                "main",
                SqlRequest::Execute {
                    sql: "CREATE TABLE entries(id INTEGER)".into(),
                    params: vec![],
                    schema: None,
                },
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
    }
    let directory = cache.join(target.to_string());
    std::fs::write(directory.join("abandoned.tmp"), b"synthetic remainder").unwrap();
    let keys = keys();
    let record = cache_record(&keys, &target, PrefixStoreKind::SqliteCache);
    let path = record.object_key().unwrap();
    let body = record.to_bytes().unwrap();
    ledger.append_purge_record(&path, &body).await.unwrap();
    let stored = ledger.read_purge_record(&path).await.unwrap().unwrap();
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &stored,
        PrefixStoreKind::SqliteCache,
        &format!("{target}/"),
    )
    .unwrap();
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqliteCache(&service), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::VerifiedEmpty
    );
    assert!(!directory.exists());
    assert!(!service.export(&neighbor, "main").await.unwrap().is_empty());
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &stored,
        PrefixStoreKind::SqliteCache,
        &format!("{neighbor}/")
    )
    .is_err());
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::SqliteCache(&service), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::VerifiedEmpty
    );
    assert!(ledger.read_purge_record(&path).await.unwrap().unwrap() == body);
    service.drain_and_evict_space(&neighbor).await.unwrap();
}

#[cfg(feature = "duckdb")]
#[tokio::test]
async fn duckdb_cache_prefix_closes_live_actors_and_preserves_neighbor_export() {
    use tinycloud_core::{
        database_artifacts::{
            ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
        },
        duckdb::{DuckDbRequest, DuckDbService},
        migrations::Migrator,
        sea_orm::Database,
        sea_orm_migration::MigratorTrait,
    };
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("duckdb-cache");
    let ledger = FileSystemConfig::new(root.path().join("blocks"))
        .open()
        .await
        .unwrap();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(db));
    let payload = tokio::task::spawn_blocking(|| {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("seed.duckdb");
        let conn = tinycloud_core::duckdb::storage::open_connection(Some(&path), "64MB").unwrap();
        conn.execute_batch("CREATE TABLE seed(id INTEGER); CHECKPOINT")
            .unwrap();
        drop(conn);
        std::fs::read(path).unwrap()
    })
    .await
    .unwrap();
    let service = DuckDbService::new(
        cache.to_string_lossy().into_owned(),
        0,
        300,
        "64MB".into(),
        repo.clone(),
    );
    let target: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:cache"
        .parse()
        .unwrap();
    let neighbor: SpaceId =
        "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:cache"
            .parse()
            .unwrap();
    for space in [&target, &neighbor] {
        repo.save(
            "duckdb",
            &space.to_string(),
            "main",
            payload.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        service
            .execute(
                space,
                "main",
                DuckDbRequest::Execute {
                    sql: "CREATE TABLE entries(id INTEGER)".into(),
                    params: vec![],
                    schema: None,
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
    }
    let directory = cache.join(target.to_string());
    std::fs::write(directory.join("abandoned.tmp"), b"synthetic remainder").unwrap();
    let keys = keys();
    let record = cache_record(&keys, &target, PrefixStoreKind::DuckDbCache);
    let path = record.object_key().unwrap();
    let body = record.to_bytes().unwrap();
    ledger.append_purge_record(&path, &body).await.unwrap();
    let stored = ledger.read_purge_record(&path).await.unwrap().unwrap();
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &stored,
        PrefixStoreKind::DuckDbCache,
        &format!("{target}/"),
    )
    .unwrap();
    let fence = SpacePurgeFence::new(keys.clone());
    let drain = fence.restore_drain().await;
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::DuckDbCache(&service), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::VerifiedEmpty
    );
    assert!(!directory.exists());
    assert!(!service.export(&neighbor, "main").await.unwrap().is_empty());
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &stored,
        PrefixStoreKind::SqliteCache,
        &format!("{target}/")
    )
    .is_err());
    assert_eq!(
        purge_restore_prefix_batch(RestorePurgeStore::DuckDbCache(&service), &drain, &proof)
            .await
            .unwrap(),
        RestorePrefixOutcome::VerifiedEmpty
    );
    assert!(ledger.read_purge_record(&path).await.unwrap().unwrap() == body);
    service.drain_and_evict_space(&neighbor).await.unwrap();
}
