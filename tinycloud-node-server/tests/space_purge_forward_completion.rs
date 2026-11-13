//! Worker-side V17.1-LEDGER-FORWARD-COMPLETE-01: an object-side completion
//! never bypasses physical cleanup or a lease-checked terminal transaction.
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_purge_executor::{PhaseOutcome, SpacePurgeExecutor, SqlPurgeStore},
    storage::{
        file_system::{FileSystemConfig, FileSystemStore},
        purge_completion::complete_purge,
        purge_ledger::PurgeLedgerStore,
        sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore},
    },
    BlockStores,
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    database_artifacts::SeaOrmDatabaseArtifactRepository,
    migrations::Migrator,
    models::{space_purge_job, space_purge_ledger_copy},
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait,
        Statement, TransactionTrait,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    space_purge_worker::{claim_specific, ClaimedPurge},
    sql::SqlService,
    storage::{either::Either, StorageConfig},
};

struct Fixture {
    admin: DatabaseConnection,
    db: DatabaseConnection,
    schema: String,
    root: tempfile::TempDir,
    store: FileSystemStore,
    sql_store: FsSqlObjectStore,
    sql: SqlService,
    keys: Arc<LedgerKeys>,
    fence: SpacePurgeFence,
    space: SpaceId,
    accepted: LedgerRecord,
    job: ClaimedPurge,
}
impl Fixture {
    async fn new(phase: &str, external_acceptance: bool) -> Option<Self> {
        let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
            return None;
        };
        let admin = Database::connect(&url).await.unwrap();
        let schema = format!("purge_forward_{}", uuid::Uuid::new_v4().simple());
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options.set_schema_search_path(schema.clone());
        let db = Database::connect(options).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let blocks = root.path().join("blocks");
        let store = FileSystemConfig::new(&blocks).open().await.unwrap();
        let sql_store = FsSqlObjectStore::open(root.path().join("sql-store"), &blocks).unwrap();
        let sql = SqlService::new(
            root.path().join("cache").to_string_lossy().into_owned(),
            0,
            Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone())),
        );
        let keys = Arc::new(
            LedgerKeys::new(
                "test".into(),
                BTreeMap::from([("test".into(), vec![23; 32])]),
            )
            .unwrap(),
        );
        let fence = SpacePurgeFence::new(keys.clone());
        let space: SpaceId =
            "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:forward"
                .parse()
                .unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let accepted_at = OffsetDateTime::from_unix_timestamp(now.unix_timestamp() - 600).unwrap();
        let digest = keys
            .target_hmac("test", "space", &space.to_string())
            .unwrap();
        let owner = keys
            .target_hmac("test", "owner", space.did().as_str())
            .unwrap();
        let accepted = keys
            .with_prefixes(
                keys.sign(
                    "test",
                    "space",
                    &digest,
                    &id,
                    "purging",
                    accepted_at.unix_timestamp(),
                )
                .unwrap(),
                vec![
                    keys.prefix_hmac(
                        "test",
                        "kv-filesystem",
                        &format!("{}/{}/", space.suffix(), space.name()),
                    )
                    .unwrap(),
                    keys.prefix_hmac(
                        "test",
                        "sql-filesystem",
                        SqlPhysicalPrefix::for_space(&space).as_str(),
                    )
                    .unwrap(),
                    keys.prefix_hmac("test", "sqlite-cache", &format!("{space}/"))
                        .unwrap(),
                ],
            )
            .unwrap();
        let tx = db.begin().await.unwrap();
        let generation = fence
            .fence_hmac(&tx, "space", "test", &digest)
            .await
            .unwrap();
        tx.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO space(id) VALUES($1)",
            [space.to_string().into()],
        ))
        .await
        .unwrap();
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO space_purge_job(purge_id,space,tombstone_hmac,hmac_key_id,owner_hmac,accepted_at,phase,fence_generation,updated_at,next_attempt_at,attempt_count) VALUES($1,$2,$3,'test',$4,$5,$6,$7,clock_timestamp(),clock_timestamp(),0)",
            [id.clone().into(),space.to_string().into(),digest.into(),owner.into(),accepted_at.into(),phase.into(),generation.into()])).await.unwrap();
        tinycloud_core::space_purge_ledger_copy::retain(
            &tx,
            &keys,
            &accepted.object_key().unwrap(),
            &accepted.to_bytes().unwrap(),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if external_acceptance {
            store
                .append_purge_record(
                    &accepted.object_key().unwrap(),
                    &accepted.to_bytes().unwrap(),
                )
                .await
                .unwrap();
        }
        let job = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &id)
            .await
            .unwrap()
            .unwrap();
        Some(Self {
            admin,
            db,
            schema,
            root,
            store,
            sql_store,
            sql,
            keys,
            fence,
            space,
            accepted,
            job,
        })
    }
    fn executor<'a>(&'a self, blocks: &'a BlockStores) -> SpacePurgeExecutor<'a> {
        SpacePurgeExecutor {
            db: &self.db,
            blocks,
            sql: &self.sql,
            #[cfg(feature = "duckdb")]
            duckdb: None,
            sql_objects: Some(SqlPurgeStore::FileSystem(&self.sql_store)),
            keys: &self.keys,
            encryption: None,
        }
    }
    fn completed(&self, timestamp: i64) -> LedgerRecord {
        self.keys
            .completion_from_acceptance(self.accepted.clone(), timestamp)
            .unwrap()
    }
    async fn pending(&self) {
        let current = space_purge_job::Entity::find_by_id(&self.job.purge_id)
            .one(&self.db)
            .await
            .unwrap()
            .unwrap();
        assert!(current.phase != "complete");
        assert!(current.space.is_some());
    }
    async fn dispose(self) {
        self.db.close().await.unwrap();
        self.admin
            .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn database_only_acceptance_cannot_delete_before_matching_object_copy_exists() {
    let Some(f) = Fixture::new("drain", false).await else {
        return;
    };
    let directory = f
        .root
        .path()
        .join("blocks")
        .join(f.space.suffix())
        .join(f.space.name().as_str());
    let cache = f.root.path().join("cache").join(f.space.to_string());
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("keep"), b"synthetic payload").unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("keep"), b"synthetic cache").unwrap();
    let restore = f.fence.restore_drain().await;
    let drain = f
        .fence
        .drain_during_restore(&f.db, &f.space, &restore)
        .await
        .unwrap();
    let blocks = Either::B(f.store.clone());
    let executor = f.executor(&blocks);
    assert!(executor.execute_claimed(&f.job, &drain).await.is_err());
    assert!(directory.join("keep").exists());
    assert!(cache.join("keep").exists());
    f.pending().await;
    let completed = f.completed(OffsetDateTime::now_utc().unix_timestamp());
    assert!(f
        .store
        .read_purge_record(&completed.object_key().unwrap())
        .await
        .unwrap()
        .is_none());
    // A matching durable copy repairs acceptance forward, without completing it.
    f.store
        .append_purge_record(
            &f.accepted.object_key().unwrap(),
            &f.accepted.to_bytes().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        executor.execute_claimed(&f.job, &drain).await.unwrap(),
        PhaseOutcome::Advanced
    );
    f.pending().await;
    assert!(directory.join("keep").exists());
    assert!(!cache.exists());
    assert!(f
        .store
        .read_purge_record(&completed.object_key().unwrap())
        .await
        .unwrap()
        .is_none());
    drop(drain);
    drop(restore);
    f.dispose().await;
}

#[tokio::test]
async fn tampered_acceptance_stays_pending_without_publishing_completion() {
    let Some(f) = Fixture::new("objects", true).await else {
        return;
    };
    let path = f.accepted.object_key().unwrap();
    let mut damaged = f.accepted.clone();
    damaged.prefixes[0].prefix_hmac = "00".repeat(32);
    // Simulated damaged restore media; the append-only application API is not used to overwrite it.
    std::fs::write(
        f.root.path().join("blocks").join(&path),
        damaged.to_bytes().unwrap(),
    )
    .unwrap();
    assert!(complete_purge(&f.db, &f.store, &f.keys, &f.job)
        .await
        .is_err());
    f.pending().await;
    let completed = f.completed(OffsetDateTime::now_utc().unix_timestamp());
    assert!(f
        .store
        .read_purge_record(&completed.object_key().unwrap())
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
}

#[tokio::test]
async fn conflicting_authenticated_completion_inventory_is_never_overwritten_or_committed() {
    let Some(f) = Fixture::new("objects", true).await else {
        return;
    };
    let expected = f.completed(OffsetDateTime::now_utc().unix_timestamp() - 300);
    let wrong = f
        .keys
        .with_prefixes(expected.clone(), vec![f.accepted.prefixes[0].clone()])
        .unwrap();
    let path = wrong.object_key().unwrap();
    let body = wrong.to_bytes().unwrap();
    f.store.append_purge_record(&path, &body).await.unwrap();
    assert!(complete_purge(&f.db, &f.store, &f.keys, &f.job)
        .await
        .is_err());
    f.pending().await;
    assert!(f.store.read_purge_record(&path).await.unwrap().unwrap() == body);
    assert!(space_purge_ledger_copy::Entity::find_by_id(path)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
}

#[tokio::test]
async fn ahead_object_completion_redeletes_restored_prefixes_and_commits_only_with_current_claim() {
    let Some(f) = Fixture::new("objects", true).await else {
        return;
    };
    let completed = f.completed(OffsetDateTime::now_utc().unix_timestamp() - 300);
    let path = completed.object_key().unwrap();
    let body = completed.to_bytes().unwrap();
    f.store.append_purge_record(&path, &body).await.unwrap();
    let kv = f
        .root
        .path()
        .join("blocks")
        .join(f.space.suffix())
        .join(f.space.name().as_str());
    let sql = f
        .root
        .path()
        .join("sql-store")
        .join(SqlPhysicalPrefix::for_space(&f.space).as_str());
    for directory in [&kv, &sql] {
        std::fs::create_dir_all(directory).unwrap();
        for index in 0..260 {
            std::fs::write(
                directory.join(index.to_string()),
                b"synthetic restored payload",
            )
            .unwrap();
        }
    }
    f.db.execute_unprepared("CREATE TABLE forward_blocker(space TEXT REFERENCES space(id))")
        .await
        .unwrap();
    f.db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO forward_blocker(space) VALUES($1)",
        [f.space.to_string().into()],
    ))
    .await
    .unwrap();
    let restore = f.fence.restore_drain().await;
    let drain = f
        .fence
        .drain_during_restore(&f.db, &f.space, &restore)
        .await
        .unwrap();
    let blocks = Either::B(f.store.clone());
    let executor = f.executor(&blocks);
    assert_eq!(
        executor.execute_claimed(&f.job, &drain).await.unwrap(),
        PhaseOutcome::MoreObjects
    );
    f.pending().await;
    assert!(kv.exists());
    assert!(sql.exists());
    assert!(f.store.read_purge_record(&path).await.unwrap().unwrap() == body);
    let mut failed_terminal = false;
    for _ in 0..4 {
        let job = claim_specific(&f.db, &uuid::Uuid::new_v4().to_string(), &f.job.purge_id)
            .await
            .unwrap()
            .unwrap();
        match executor.execute_claimed(&job, &drain).await {
            Ok(PhaseOutcome::MoreObjects) => {}
            Err(_) => {
                failed_terminal = true;
                break;
            }
            other => panic!("unexpected repair outcome {other:?}"),
        }
    }
    assert!(failed_terminal);
    assert!(!kv.exists());
    assert!(!sql.exists());
    f.pending().await;
    assert!(space_purge_ledger_copy::Entity::find_by_id(path.clone())
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.db.execute_unprepared("DROP TABLE forward_blocker")
        .await
        .unwrap();
    f.db.execute(Statement::from_sql_and_values(DbBackend::Postgres,"UPDATE space_purge_job SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE purge_id=$1",[f.job.purge_id.clone().into()])).await.unwrap();
    assert!(!complete_purge(&f.db, &f.store, &f.keys, &f.job)
        .await
        .unwrap());
    let resumed = claim_specific(&f.db, &uuid::Uuid::new_v4().to_string(), &f.job.purge_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        executor.execute_claimed(&resumed, &drain).await.unwrap(),
        PhaseOutcome::Complete
    );
    let current = space_purge_job::Entity::find_by_id(&f.job.purge_id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(current.space.is_none());
    assert_eq!(current.phase, "complete");
    let copied = space_purge_ledger_copy::Entity::find_by_id(path.clone())
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(copied.body == body);
    assert!(f.store.read_purge_record(&path).await.unwrap().unwrap() == body);
    drop(drain);
    drop(restore);
    f.dispose().await;
}
