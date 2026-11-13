use std::{collections::BTreeMap, sync::Arc};
use tinycloud::{
    space_purge_executor::{PhaseOutcome, SpacePurgeExecutor, SqlPurgeStore},
    storage::{
        file_system::FileSystemConfig,
        purge_ledger::PurgeLedgerStore,
        sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore},
    },
    BlockStores,
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    database_artifacts::SeaOrmDatabaseArtifactRepository,
    migrations::Migrator,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TransactionTrait},
    sea_orm_migration::MigratorTrait,
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::LedgerKeys,
    space_purge_worker::claim_specific,
    sql::{SqlRequest, SqlService},
    storage::{either::Either, StorageConfig},
};

#[tokio::test]
async fn postgres_filesystem_executor_drains_defers_claims_and_resumes_exact_prefixes() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("purge_executor_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let blocks_root = root.path().join("blocks");
    let cache_root = root.path().join("cache");
    let sql_root = root.path().join("sql-store");
    let blocks: BlockStores = Either::B(FileSystemConfig::new(&blocks_root).open().await.unwrap());
    let sql_store = FsSqlObjectStore::open(sql_root.clone(), &blocks_root).unwrap();
    let repository = Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone()));
    let sql = SqlService::new(
        cache_root.to_string_lossy().into_owned(),
        0,
        repository.clone(),
    );
    let a: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
        .parse()
        .unwrap();
    let b: SpaceId = "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:files"
        .parse()
        .unwrap();
    for space in [&a, &b] {
        sql.execute(
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
        let kv = blocks_root.join(space.suffix()).join(space.name().as_str());
        std::fs::create_dir_all(&kv).unwrap();
        let physical = sql_root
            .join(SqlPhysicalPrefix::for_space(space).as_str())
            .join("db/lineage/snap");
        std::fs::create_dir_all(&physical).unwrap();
        let count = if space == &a { 260 } else { 1 };
        for n in 0..count {
            std::fs::write(kv.join(format!("{n}")), b"kv bytes").unwrap();
            std::fs::write(physical.join(format!("{n}")), b"sql bytes").unwrap();
        }
    }
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![11; 32])]),
        )
        .unwrap(),
    );
    let fence = SpacePurgeFence::new(keys.clone());
    let digest = keys.target_hmac("test", "space", &a.to_string()).unwrap();
    let owner_digest = keys.target_hmac("test", "owner", a.did().as_str()).unwrap();
    let purge_id = uuid::Uuid::new_v4().to_string();
    let accepted = keys
        .sign(
            "test",
            "space",
            &digest,
            &purge_id,
            "purging",
            time::OffsetDateTime::now_utc().unix_timestamp() - 600,
        )
        .unwrap();
    if let Either::B(store) = &blocks {
        store
            .append_purge_record(
                &accepted.object_key().unwrap(),
                &accepted.to_bytes().unwrap(),
            )
            .await
            .unwrap();
    }
    let tx = db.begin().await.unwrap();
    let generation = fence
        .fence_hmac(&tx, "space", "test", &digest)
        .await
        .unwrap();
    tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO space_purge_job(purge_id,space,tombstone_hmac,hmac_key_id,owner_hmac,accepted_at,phase,fence_generation,updated_at,next_attempt_at,attempt_count) VALUES($1,$2,$3,'test',$5,clock_timestamp()-INTERVAL '10 minutes','drain',$4,clock_timestamp(),clock_timestamp(),0)",
        [purge_id.clone().into(),a.to_string().into(),digest.clone().into(),generation.into(),owner_digest.into()])).await.unwrap();
    tx.commit().await.unwrap();
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,"INSERT INTO kv_orphan_attempt(space,value,attempt_id,generation,created_at) VALUES($1,$2,'in-flight',1,clock_timestamp())",[a.to_string().into(),vec![1u8;32].into()])).await.unwrap();
    let drain = fence.drain(&db, &a).await.unwrap();
    let executor = SpacePurgeExecutor {
        db: &db,
        blocks: &blocks,
        sql: &sql,
        #[cfg(feature = "duckdb")]
        duckdb: None,
        sql_objects: Some(SqlPurgeStore::FileSystem(&sql_store)),
        keys: &keys,
        encryption: None,
    };
    let recent = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &purge_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        executor.execute_claimed(&recent, &drain).await.unwrap(),
        PhaseOutcome::Deferred
    );
    assert!(blocks_root
        .join(a.suffix())
        .join(a.name().as_str())
        .join("0")
        .exists());
    assert!(cache_root.join(a.to_string()).exists());
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,"UPDATE kv_orphan_attempt SET created_at=clock_timestamp()-INTERVAL '10 minutes' WHERE space=$1",[a.to_string().into()])).await.unwrap();
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE space_purge_job SET next_attempt_at=clock_timestamp() WHERE purge_id=$1",
        [purge_id.clone().into()],
    ))
    .await
    .unwrap();
    for phase in ["drain", "database", "access"] {
        let job = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &purge_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.phase, phase);
        assert_eq!(
            executor.execute_claimed(&job, &drain).await.unwrap(),
            PhaseOutcome::Advanced
        );
    }
    assert!(!cache_root.join(a.to_string()).exists());
    assert!(cache_root.join(b.to_string()).exists());
    let first = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &purge_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.phase, "objects");
    assert_eq!(
        executor.execute_claimed(&first, &drain).await.unwrap(),
        PhaseOutcome::MoreObjects
    );
    let still_claimed: i64 = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM kv_orphan_attempt WHERE space=$1",
            [a.to_string().into()],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap();
    assert_eq!(still_claimed, 1);
    drop(drain);
    drop(blocks);
    // Rebuild transport, service registries and guards from durable state after
    // a successful batch, with neither an object cursor nor the old lease.
    let blocks: BlockStores = Either::B(FileSystemConfig::new(&blocks_root).open().await.unwrap());
    let resumed_sql = SqlService::new(cache_root.to_string_lossy().into_owned(), 0, repository);
    let resumed_fence = SpacePurgeFence::new(keys.clone());
    let drain = resumed_fence.drain(&db, &a).await.unwrap();
    let executor = SpacePurgeExecutor {
        db: &db,
        blocks: &blocks,
        sql: &resumed_sql,
        #[cfg(feature = "duckdb")]
        duckdb: None,
        sql_objects: Some(SqlPurgeStore::FileSystem(&sql_store)),
        keys: &keys,
        encryption: None,
    };
    let mut complete = false;
    for _ in 0..12 {
        let job = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &purge_id)
            .await
            .unwrap()
            .unwrap();
        match executor.execute_claimed(&job, &drain).await.unwrap() {
            PhaseOutcome::Complete => {
                complete = true;
                break;
            }
            PhaseOutcome::MoreObjects => {}
            other => panic!("unexpected outcome {other:?}"),
        }
    }
    assert!(complete);
    assert_eq!(
        executor.execute_claimed(&first, &drain).await.unwrap(),
        PhaseOutcome::LeaseLost
    );
    assert_eq!(
        std::fs::read(
            blocks_root
                .join(b.suffix())
                .join(b.name().as_str())
                .join("0")
        )
        .unwrap(),
        b"kv bytes"
    );
    assert_eq!(
        std::fs::read(
            sql_root
                .join(SqlPhysicalPrefix::for_space(&b).as_str())
                .join("db/lineage/snap/0")
        )
        .unwrap(),
        b"sql bytes"
    );
    let job = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT phase,space FROM space_purge_job WHERE purge_id=$1",
            [purge_id.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.try_get::<String>("", "phase").unwrap(), "complete");
    assert!(job
        .try_get::<Option<String>>("", "space")
        .unwrap()
        .is_none());
    assert!(sql.export(&b, "main").await.is_ok());
    sql.drain_and_evict_space(&b).await.unwrap();
    drop(drain);
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
