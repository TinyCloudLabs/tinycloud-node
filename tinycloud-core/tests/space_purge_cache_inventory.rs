use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    database_artifacts::{
        ArtifactExpectation, ArtifactMeta, ArtifactSink, DatabaseArtifact, DatabaseArtifactError,
        DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    },
    migrations::Migrator,
    sea_orm::Database,
    sea_orm_migration::MigratorTrait,
    sql::{service::SqlWaitBounds, SqlRequest, SqlService},
};

async fn repository() -> Arc<SeaOrmDatabaseArtifactRepository> {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    Arc::new(SeaOrmDatabaseArtifactRepository::new(db))
}

struct BlockHydration {
    inner: Arc<SeaOrmDatabaseArtifactRepository>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl DatabaseArtifactRepository for BlockHydration {
    async fn load_meta(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.load_meta(service, space, name).await
    }
    async fn read_chunks(
        &self,
        service: &str,
        space: &str,
        name: &str,
        meta: &ArtifactMeta,
        sink: &mut dyn ArtifactSink,
    ) -> Result<(), DatabaseArtifactError> {
        self.inner
            .read_chunks(service, space, name, meta, sink)
            .await
    }
    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
        expected: ArtifactExpectation,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        self.inner
            .save(service, space, name, payload, expected)
            .await
    }
}

#[tokio::test]
async fn restore_inventory_waits_for_detached_hydration_and_retains_target() {
    let cache = tempfile::tempdir().unwrap();
    let repo = Arc::new(BlockHydration {
        inner: repository().await,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let service = SqlService::new(cache.path().to_string_lossy().into_owned(), 0, repo.clone())
        .with_wait_bounds(SqlWaitBounds {
            hydration_wait: Duration::from_millis(10),
            ..Default::default()
        });
    let target: SpaceId = "tinycloud:key:test:detached".parse().unwrap();
    let request = tokio::spawn({
        let service = service.clone();
        let target = target.clone();
        async move {
            service
                .execute(
                    &target,
                    "late",
                    SqlRequest::Query {
                        sql: "SELECT 1".into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                )
                .await
        }
    });
    repo.entered.notified().await;
    assert!(request.await.unwrap().is_err());
    let keys = tinycloud_core::space_purge_ledger::LedgerKeys::new(
        "test".into(),
        std::collections::BTreeMap::from([("test".into(), vec![15; 32])]),
    )
    .unwrap();
    let fence = tinycloud_core::space_purge_fence::SpacePurgeFence::new(Arc::new(keys));
    let drain = fence.restore_drain().await;
    let mut inventory = tokio::spawn({
        let service = service.clone();
        async move { service.enumerate_cache_spaces_for_restore(&drain).await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut inventory)
            .await
            .is_err()
    );
    repo.release.notify_one();
    let spaces = tokio::time::timeout(Duration::from_secs(2), inventory)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(spaces.contains(&target));
}

#[tokio::test]
async fn restore_inventory_keeps_live_actor_and_disk_only_neighbor() {
    let cache = tempfile::tempdir().unwrap();
    let service = SqlService::new(
        cache.path().to_string_lossy().into_owned(),
        u64::MAX,
        repository().await,
    );
    let target: SpaceId = "tinycloud:key:test:actor".parse().unwrap();
    let neighbor: SpaceId = "tinycloud:key:test:disk".parse().unwrap();
    service
        .execute(
            &target,
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
    tokio::fs::create_dir_all(cache.path().join(neighbor.to_string()))
        .await
        .unwrap();
    let keys = tinycloud_core::space_purge_ledger::LedgerKeys::new(
        "test".into(),
        std::collections::BTreeMap::from([("test".into(), vec![15; 32])]),
    )
    .unwrap();
    let fence = tinycloud_core::space_purge_fence::SpacePurgeFence::new(Arc::new(keys));
    let drain = fence.restore_drain().await;
    let spaces = service
        .enumerate_cache_spaces_for_restore(&drain)
        .await
        .unwrap();
    assert_eq!(spaces.len(), 2);
    assert!(spaces.contains(&target));
    assert!(spaces.contains(&neighbor));
    assert!(cache.path().join(neighbor.to_string()).exists());
    assert!(!service.export(&target, "main").await.unwrap().is_empty());
}

#[cfg(feature = "duckdb")]
#[tokio::test]
async fn duckdb_restore_inventory_preserves_disk_only_cache() {
    let cache = tempfile::tempdir().unwrap();
    let target: SpaceId = "tinycloud:key:test:duck-cache".parse().unwrap();
    tokio::fs::create_dir(cache.path().join(target.to_string()))
        .await
        .unwrap();
    let service = tinycloud_core::duckdb::DuckDbService::new(
        cache.path().to_string_lossy().into_owned(),
        0,
        300,
        "64MB".into(),
        repository().await,
    );
    let keys = tinycloud_core::space_purge_ledger::LedgerKeys::new(
        "test".into(),
        std::collections::BTreeMap::from([("test".into(), vec![15; 32])]),
    )
    .unwrap();
    let fence = tinycloud_core::space_purge_fence::SpacePurgeFence::new(Arc::new(keys));
    let drain = fence.restore_drain().await;
    let spaces = service
        .enumerate_cache_spaces_for_restore(&drain)
        .await
        .unwrap();
    assert_eq!(spaces, vec![target.clone()]);
    assert!(cache.path().join(target.to_string()).exists());
}
