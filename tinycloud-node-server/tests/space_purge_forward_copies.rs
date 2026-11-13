//! V17.1-LEDGER-FORWARD-ACCEPT-01: actual independent-copy recovery with
//! injected crashes. Completion copies deliberately wait for physical proof.
use std::{collections::BTreeMap, io, sync::Arc};
use tinycloud::storage::{
    file_system::{FileSystemConfig, FileSystemStore},
    purge_ledger::PurgeLedgerStore,
    purge_reconcile::{repair_acceptance_copies, CopyRepairPoint},
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    migrations::Migrator,
    models::{space_purge_ledger_copy, space_purge_prefix_repair},
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait,
        Statement,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_fence::{FenceError, SpacePurgeFence},
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    storage::StorageConfig,
};

struct Fixture {
    admin: DatabaseConnection,
    db: DatabaseConnection,
    schema: String,
    _root: tempfile::TempDir,
    ledger: FileSystemStore,
    keys: Arc<LedgerKeys>,
    space: SpaceId,
    acceptance: LedgerRecord,
}
impl Fixture {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
            return None;
        };
        let admin = Database::connect(&url).await.unwrap();
        let schema = format!("forward_copies_{}", uuid::Uuid::new_v4().simple());
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options.set_schema_search_path(schema.clone());
        let db = Database::connect(options).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let ledger = FileSystemConfig::new(root.path()).open().await.unwrap();
        let keys = Arc::new(
            LedgerKeys::new(
                "test".into(),
                BTreeMap::from([("test".into(), vec![19; 32])]),
            )
            .unwrap(),
        );
        let space: SpaceId =
            "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:copies"
                .parse()
                .unwrap();
        let digest = keys
            .target_hmac("test", "space", &space.to_string())
            .unwrap();
        let acceptance = keys
            .with_prefixes(
                keys.sign(
                    "test",
                    "space",
                    &digest,
                    &uuid::Uuid::new_v4().to_string(),
                    "purging",
                    1,
                )
                .unwrap(),
                vec![keys
                    .prefix_hmac(
                        "test",
                        "sql-filesystem",
                        &format!("sql/v1/~{}/", "a".repeat(64)),
                    )
                    .unwrap()],
            )
            .unwrap();
        Some(Self {
            admin,
            db,
            schema,
            _root: root,
            ledger,
            keys,
            space,
            acceptance,
        })
    }
    async fn database(&self, record: &LedgerRecord) {
        tinycloud_core::space_purge_ledger_copy::retain(
            &self.db,
            &self.keys,
            &record.object_key().unwrap(),
            &record.to_bytes().unwrap(),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    }
    async fn external(&self, record: &LedgerRecord) {
        self.ledger
            .append_purge_record(&record.object_key().unwrap(), &record.to_bytes().unwrap())
            .await
            .unwrap();
    }
    async fn matching(&self, record: &LedgerRecord) {
        let path = record.object_key().unwrap();
        let bytes = record.to_bytes().unwrap();
        let row = space_purge_ledger_copy::Entity::find_by_id(path.clone())
            .one(&self.db)
            .await
            .unwrap()
            .unwrap();
        assert!(row.body == bytes);
        assert!(self.ledger.read_purge_record(&path).await.unwrap().unwrap() == bytes);
    }
    async fn dispose(self) {
        self.db.close().await.unwrap();
        self.admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {} CASCADE", self.schema),
            ))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn acceptance_crashes_on_either_durable_side_repair_forward_and_retry_idempotently() {
    for (database_first, stop) in [
        (true, CopyRepairPoint::ExternalPublished),
        (false, CopyRepairPoint::DatabaseCommitted),
    ] {
        let Some(f) = Fixture::new().await else {
            return;
        };
        if database_first {
            f.database(&f.acceptance).await;
        } else {
            f.external(&f.acceptance).await;
        }
        let fence = SpacePurgeFence::new(f.keys.clone());
        let drain = fence.restore_drain().await;
        let mut reached = 0;
        let interrupted = repair_acceptance_copies(&f.db, &f.ledger, &f.keys, &drain, |point| {
            if point == stop {
                reached += 1;
                return Err(io::Error::other("injected durable-copy crash"));
            }
            Ok(())
        })
        .await;
        assert!(interrupted.is_err());
        assert_eq!(reached, 1);
        f.matching(&f.acceptance).await;
        assert!(matches!(
            fence.check(&f.db, &f.space).await,
            Err(FenceError::Unavailable)
        ));
        drop(drain);
        let restarted = SpacePurgeFence::new(f.keys.clone());
        let drain = restarted.restore_drain().await;
        let retried = repair_acceptance_copies(&f.db, &f.ledger, &f.keys, &drain, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(retried.repaired_copies, 0);
        assert_eq!(retried.completion_records_requiring_storage_check, 0);
        f.matching(&f.acceptance).await;
        let repairs = space_purge_prefix_repair::Entity::find()
            .all(&f.db)
            .await
            .unwrap();
        assert_eq!(repairs.len(), 1);
        assert!(repairs.iter().all(|row| row.phase == "pending"));
        let completed = f
            .keys
            .completion_from_acceptance(f.acceptance.clone(), 2)
            .unwrap();
        assert!(f
            .ledger
            .read_purge_record(&completed.object_key().unwrap())
            .await
            .unwrap()
            .is_none());
        assert!(
            space_purge_ledger_copy::Entity::find_by_id(completed.object_key().unwrap())
                .one(&f.db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            restarted.check(&f.db, &f.space).await,
            Err(FenceError::Unavailable)
        ));
        drop(drain);
        f.dispose().await;
    }
}

#[tokio::test]
async fn completion_ahead_on_either_side_never_gets_counterpart_before_storage_recheck() {
    for database_ahead in [true, false] {
        let Some(f) = Fixture::new().await else {
            return;
        };
        f.database(&f.acceptance).await;
        f.external(&f.acceptance).await;
        let completed = f
            .keys
            .completion_from_acceptance(f.acceptance.clone(), 2)
            .unwrap();
        if database_ahead {
            f.database(&completed).await;
        } else {
            f.external(&completed).await;
        }
        let fence = SpacePurgeFence::new(f.keys.clone());
        let drain = fence.restore_drain().await;
        let counts = repair_acceptance_copies(&f.db, &f.ledger, &f.keys, &drain, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(counts.repaired_copies, 0);
        assert_eq!(counts.completion_records_requiring_storage_check, 1);
        f.matching(&f.acceptance).await;
        let path = completed.object_key().unwrap();
        let bytes = completed.to_bytes().unwrap();
        let database = space_purge_ledger_copy::Entity::find_by_id(path.clone())
            .one(&f.db)
            .await
            .unwrap();
        let external = f.ledger.read_purge_record(&path).await.unwrap();
        if database_ahead {
            assert!(database.unwrap().body == bytes);
            assert!(external.is_none());
        } else {
            assert!(database.is_none());
            assert!(external.unwrap() == bytes);
        }
        let repairs = space_purge_prefix_repair::Entity::find()
            .all(&f.db)
            .await
            .unwrap();
        assert_eq!(repairs.len(), 2);
        assert!(repairs.iter().all(|row| row.phase == "pending"));
        assert!(matches!(
            fence.check(&f.db, &f.space).await,
            Err(FenceError::Unavailable)
        ));
        drop(drain);
        f.dispose().await;
    }
}

#[tokio::test]
async fn invalid_union_entry_prevents_every_repair_write() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.database(&f.acceptance).await;
    let other = f
        .keys
        .target_hmac("test", "space", "synthetic-other-target")
        .unwrap();
    let mut damaged = f
        .keys
        .with_prefixes(
            f.keys
                .sign(
                    "test",
                    "space",
                    &other,
                    &uuid::Uuid::new_v4().to_string(),
                    "purging",
                    1,
                )
                .unwrap(),
            f.acceptance.prefixes.clone(),
        )
        .unwrap();
    damaged.mac = "00".repeat(32);
    f.ledger
        .append_purge_record(&damaged.object_key().unwrap(), &damaged.to_bytes().unwrap())
        .await
        .unwrap();
    let fence = SpacePurgeFence::new(f.keys.clone());
    let drain = fence.restore_drain().await;
    assert!(
        repair_acceptance_copies(&f.db, &f.ledger, &f.keys, &drain, |_| Ok(()))
            .await
            .is_err()
    );
    assert!(f
        .ledger
        .read_purge_record(&f.acceptance.object_key().unwrap())
        .await
        .unwrap()
        .is_none());
    assert!(space_purge_prefix_repair::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    drop(drain);
    f.dispose().await;
}

#[tokio::test]
async fn conflicting_valid_terminal_inventory_fails_before_any_missing_copy_is_written() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.database(&f.acceptance).await;
    let complete = f
        .keys
        .completion_from_acceptance(f.acceptance.clone(), 2)
        .unwrap();
    let wrong = f.keys.with_prefixes(complete, vec![]).unwrap();
    f.external(&wrong).await;
    let fence = SpacePurgeFence::new(f.keys.clone());
    let drain = fence.restore_drain().await;
    assert!(
        repair_acceptance_copies(&f.db, &f.ledger, &f.keys, &drain, |_| Ok(()))
            .await
            .is_err()
    );
    assert!(f
        .ledger
        .read_purge_record(&f.acceptance.object_key().unwrap())
        .await
        .unwrap()
        .is_none());
    assert!(
        space_purge_ledger_copy::Entity::find_by_id(wrong.object_key().unwrap())
            .one(&f.db)
            .await
            .unwrap()
            .is_none()
    );
    assert!(space_purge_prefix_repair::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    drop(drain);
    f.dispose().await;
}
