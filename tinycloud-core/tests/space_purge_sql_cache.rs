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

async fn warm(service: &SqlService, space: &SpaceId, name: &str) {
    service
        .execute(
            space,
            name,
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

#[tokio::test]
async fn sqlite_eviction_closes_multiple_actors_removes_crash_files_and_preserves_neighbour() {
    let cache = tempfile::tempdir().unwrap();
    let repo = repository().await;
    let service = SqlService::new(cache.path().to_string_lossy().into_owned(), 0, repo.clone());
    let target: SpaceId = "tinycloud:key:test:purge".parse().unwrap();
    let neighbour: SpaceId = "tinycloud:key:test:purge-other".parse().unwrap();
    warm(&service, &target, "first").await;
    warm(&service, &target, "second").await;
    warm(&service, &neighbour, "first").await;
    let directory = cache.path().join(target.to_string());
    assert!(directory.join("first.db").exists());
    tokio::fs::write(
        directory.join("abandoned-checkpoint.tmp"),
        b"crash remainder",
    )
    .await
    .unwrap();
    service.drain_and_evict_space(&target).await.unwrap();
    assert!(!directory.exists());
    assert!(cache
        .path()
        .join(neighbour.to_string())
        .join("first.db")
        .exists());
    assert!(!service
        .export(&neighbour, "first")
        .await
        .unwrap()
        .is_empty());
    service.drain_and_evict_space(&target).await.unwrap();
    // A fresh process has no actor inventory; filesystem remnants still get removed.
    tokio::fs::create_dir_all(&directory).await.unwrap();
    tokio::fs::write(directory.join("orphan.db-wal"), b"orphan")
        .await
        .unwrap();
    let restarted = SqlService::new(cache.path().to_string_lossy().into_owned(), 0, repo);
    restarted.drain_and_evict_space(&target).await.unwrap();
    assert!(!directory.exists());
    service.drain_and_evict_space(&neighbour).await.unwrap();
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
async fn sqlite_eviction_waits_for_hydration_that_outlived_its_request() {
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
    let mut eviction = tokio::spawn({
        let service = service.clone();
        let target = target.clone();
        async move { service.drain_and_evict_space(&target).await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut eviction)
            .await
            .is_err()
    );
    repo.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), eviction)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!cache.path().join(target.to_string()).exists());
}

#[cfg(feature = "duckdb")]
#[tokio::test]
async fn duckdb_eviction_closes_actors_and_preserves_neighbour() {
    use tinycloud_core::duckdb::{DuckDbRequest, DuckDbService};
    let cache = tempfile::tempdir().unwrap();
    let repo = repository().await;
    let payload = tokio::task::spawn_blocking(|| {
        let staging = tempfile::tempdir().unwrap();
        let path = staging.path().join("seed.duckdb");
        let connection =
            tinycloud_core::duckdb::storage::open_connection(Some(&path), "64MB").unwrap();
        connection
            .execute_batch("CREATE TABLE seed(id INTEGER); CHECKPOINT")
            .unwrap();
        drop(connection);
        std::fs::read(path).unwrap()
    })
    .await
    .unwrap();
    let service = DuckDbService::new(
        cache.path().to_string_lossy().into_owned(),
        0,
        300,
        "64MB".into(),
        repo.clone(),
    );
    let target: SpaceId = "tinycloud:key:test:purge".parse().unwrap();
    let neighbour: SpaceId = "tinycloud:key:test:purge-other".parse().unwrap();
    for (space, name) in [
        (&target, "first"),
        (&target, "second"),
        (&neighbour, "first"),
    ] {
        repo.save(
            "duckdb",
            &space.to_string(),
            name,
            payload.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        service
            .execute(
                space,
                name,
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
    let directory = cache.path().join(target.to_string());
    assert!(directory.join("first.duckdb").exists());
    tokio::fs::write(directory.join("abandoned.tmp"), b"remainder")
        .await
        .unwrap();
    service.drain_and_evict_space(&target).await.unwrap();
    assert!(!directory.exists());
    assert!(!service
        .export(&neighbour, "first")
        .await
        .unwrap()
        .is_empty());
    service.drain_and_evict_space(&target).await.unwrap();
    service.drain_and_evict_space(&neighbour).await.unwrap();
}
