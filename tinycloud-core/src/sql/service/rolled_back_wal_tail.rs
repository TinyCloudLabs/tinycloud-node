//! TC-4290: the production PG-master save path must never publish a WAL tail
//! left behind by a rolled-back transaction.
//!
//! A write that outgrows SQLite's page cache (the node never sets
//! `cache_size`, so the default is about 2 MiB) puts frames into the WAL
//! before its COMMIT. If it rolls back, those frames stay in the file; the
//! next, smaller commit overwrites only the start of them, and what it does
//! not reach is a tail that fails the WAL checksum chain. The WAL-delta route
//! of `persist_write` sent the raw `-wal` file, so the stored artifact could
//! not be restored.
//!
//! These tests drive the real service and actor (`SqlService::execute`), take
//! the bytes the repository receives, and restore checkpoint + WAL with the
//! shadow restore's own `materialise`.

use super::*;
use crate::{
    database_artifacts::{
        ArtifactMeta, ArtifactSink, DatabaseArtifact, DeltaSave, SeaOrmDatabaseArtifactRepository,
    },
    migrations::Migrator,
    sea_orm::{ConnectOptions, Database},
    sea_orm_migration::MigratorTrait,
    sql::store::shadow::restore::{check_wal, db_page_size, materialise, wal_path},
};
use async_trait::async_trait;
use std::sync::Mutex;
use tempfile::TempDir;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{dids::DIDBuf, jwk::JWK},
};

/// More dirty pages than the default page cache holds, in one transaction.
const SPILL_BLOBS: usize = 4;
const SPILL_BLOB_BYTES: usize = 1_000_000;

fn space_id(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap()).unwrap()
}

/// What the repository was asked to store: the last whole checkpoint and the
/// last WAL.
#[derive(Default)]
struct Published {
    checkpoint: Option<Vec<u8>>,
    wal: Option<Vec<u8>>,
}

fn statement(sql: &str) -> SqlStatement {
    SqlStatement {
        sql: sql.into(),
        params: Vec::new(),
    }
}

async fn run(service: &SqlService, space: &SpaceId, request: SqlRequest) -> Result<(), SqlError> {
    service
        .execute(space, "main", request, None, "tinycloud.sql/admin".into())
        .await
        .map(|_| ())
}

async fn execute(service: &SqlService, space: &SpaceId, sql: &str) {
    run(
        service,
        space,
        SqlRequest::Execute {
            schema: None,
            sql: sql.into(),
            params: Vec::new(),
        },
    )
    .await
    .unwrap();
}

/// A transaction that spills past the page cache and then rolls back (its
/// last statement violates NOT NULL).
async fn rolled_back_spill(service: &SqlService, space: &SpaceId) {
    let mut statements: Vec<SqlStatement> = (0..SPILL_BLOBS)
        .map(|_| {
            statement(&format!(
                "INSERT INTO t (v) VALUES (zeroblob({SPILL_BLOB_BYTES}))"
            ))
        })
        .collect();
    statements.push(statement("INSERT INTO t (v) VALUES (NULL)"));
    let failed = run(service, space, SqlRequest::Batch { statements }).await;
    assert!(matches!(failed, Err(SqlError::Sqlite(_))), "{failed:?}");
}

/// Restore `checkpoint` + `wal` the way the shadow restore does and return
/// the rows of `t`.
fn restore(checkpoint: &[u8], wal: &[u8]) -> Result<Vec<String>, String> {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("db");
    std::fs::write(&db, checkpoint).unwrap();
    std::fs::write(wal_path(&db), wal).unwrap();
    // The same two checks `materialise` makes first, so a failure names them.
    let page_size = db_page_size(&db).map_err(|e| e.to_string())?;
    check_wal(&wal_path(&db), page_size).map_err(|e| e.to_string())?;
    materialise(&db, true, true).map_err(|e| e.to_string())?;
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut rows = conn.prepare("SELECT length(v) FROM t ORDER BY id").unwrap();
    let rows = rows
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .map(|len| len.unwrap().to_string())
        .collect();
    Ok(rows)
}

fn assert_restores_committed_rows(published: &Published) {
    let checkpoint = published.checkpoint.as_deref().expect("a checkpoint");
    let wal = published.wal.as_deref().expect("a WAL");
    // The spill is in the file the route copies: the raw WAL is well past the
    // committed data, and still inside the delta route's 8 MiB bound.
    assert!(
        wal.len() > 2 * 1024 * 1024 && wal.len() < MAX_WAL_DELTA_BYTES,
        "the rolled-back write must leave a WAL tail under the delta bound; wal bytes = {}",
        wal.len()
    );
    let rows = restore(checkpoint, wal).unwrap_or_else(|error| {
        panic!("the published checkpoint + WAL do not restore: {error}")
    });
    // Only the two committed rows; nothing of the rolled-back blobs.
    assert_eq!(rows, vec!["4".to_string(), "5".to_string()]);
}

async fn sqlite_repository() -> Arc<SeaOrmDatabaseArtifactRepository> {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    Arc::new(SeaOrmDatabaseArtifactRepository::new(db))
}

/// The row-store route (`save` + `save_delta`): records every payload.
struct Recording {
    inner: Arc<SeaOrmDatabaseArtifactRepository>,
    published: Arc<Mutex<Published>>,
}

#[async_trait]
impl DatabaseArtifactRepository for Recording {
    async fn load_meta(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
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
        payload: ::bytes::Bytes,
        expected: ArtifactExpectation,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        {
            let mut published = self.published.lock().unwrap();
            published.checkpoint = Some(payload.to_vec());
            published.wal = None;
        }
        self.inner
            .save(service, space, name, payload, expected)
            .await
    }

    async fn save_delta(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: ::bytes::Bytes,
        expected: ArtifactExpectation,
    ) -> Result<DeltaSave, DatabaseArtifactError> {
        self.published.lock().unwrap().wal = Some(payload.to_vec());
        self.inner
            .save_delta(service, space, name, payload, expected)
            .await
    }
}

/// The chunked route (`save_snapshot` + `save_wal_snapshot`, what a Postgres
/// repository with chunk limits takes), held in memory.
struct Chunked {
    published: Arc<Mutex<Published>>,
}

impl Chunked {
    fn meta(&self, revision: i64) -> ArtifactMeta {
        let published = self.published.lock().unwrap();
        let checkpoint = published.checkpoint.as_ref().map_or(0, Vec::len) as i64;
        let wal = published.wal.as_ref().map_or(0, Vec::len) as i64;
        ArtifactMeta {
            revision,
            size_bytes: checkpoint + wal,
            content_hash: format!("content-{revision}"),
            checkpoint_content_hash: "checkpoint-1".into(),
            checkpoint_size_bytes: checkpoint,
            delta_content_hash: (wal > 0).then(|| format!("delta-{revision}")),
            delta_size_bytes: wal,
            updated_at: "2026-11-24T00:00:00Z".into(),
            storage_mode: "chunked".into(),
            backend: "test".into(),
        }
    }
}

#[async_trait]
impl DatabaseArtifactRepository for Chunked {
    async fn load_meta(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
        Ok(self
            .published
            .lock()
            .unwrap()
            .checkpoint
            .is_some()
            .then(|| self.meta(1)))
    }

    async fn read_chunks(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &ArtifactMeta,
        _: &mut dyn ArtifactSink,
    ) -> Result<(), DatabaseArtifactError> {
        Err(DatabaseArtifactError::Sink("not used".into()))
    }

    fn chunked_checkpoints(&self, _: &str, _: &str, _: &str) -> bool {
        true
    }

    async fn save_snapshot(
        &self,
        _: &str,
        _: &str,
        _: &str,
        snapshot: tempfile::NamedTempFile,
        _: ArtifactExpectation,
    ) -> Result<ArtifactMeta, DatabaseArtifactError> {
        let bytes = std::fs::read(snapshot.path()).unwrap();
        let mut published = self.published.lock().unwrap();
        published.checkpoint = Some(bytes);
        published.wal = None;
        drop(published);
        Ok(self.meta(1))
    }

    async fn save_wal_snapshot(
        &self,
        _: &str,
        _: &str,
        _: &str,
        snapshot: tempfile::NamedTempFile,
        _: ArtifactExpectation,
    ) -> Result<ArtifactMeta, DatabaseArtifactError> {
        let bytes = std::fs::read(snapshot.path()).unwrap();
        self.published.lock().unwrap().wal = Some(bytes);
        Ok(self.meta(2))
    }

    async fn save(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: ::bytes::Bytes,
        _: ArtifactExpectation,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        Err(DatabaseArtifactError::IncrementalPersistenceUnsupported)
    }
}

/// Seed one committed row, roll back a write that spills past the cache, then
/// commit one small row: the save that follows is the one under test.
async fn spill_then_small_commit(service: &SqlService, space: &SpaceId) {
    execute(
        service,
        space,
        "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB NOT NULL)",
    )
    .await;
    execute(service, space, "INSERT INTO t (v) VALUES (zeroblob(4))").await;
    rolled_back_spill(service, space).await;
    execute(service, space, "INSERT INTO t (v) VALUES (zeroblob(5))").await;
}

#[tokio::test]
async fn tc4290_delta_route_does_not_publish_a_rolled_back_wal_tail() {
    let published = Arc::new(Mutex::new(Published::default()));
    let cache = TempDir::new().unwrap();
    let service = SqlService::new(
        cache.path().to_string_lossy().into_owned(),
        0,
        Arc::new(Recording {
            inner: sqlite_repository().await,
            published: published.clone(),
        }),
    );
    let space = space_id("tc4290-delta");
    spill_then_small_commit(&service, &space).await;
    assert_restores_committed_rows(&published.lock().unwrap());
}

#[tokio::test]
async fn tc4290_chunked_route_does_not_publish_a_rolled_back_wal_tail() {
    let published = Arc::new(Mutex::new(Published::default()));
    let cache = TempDir::new().unwrap();
    let service = SqlService::new(
        cache.path().to_string_lossy().into_owned(),
        0,
        Arc::new(Chunked {
            published: published.clone(),
        }),
    );
    let space = space_id("tc4290-chunked");
    spill_then_small_commit(&service, &space).await;
    assert_restores_committed_rows(&published.lock().unwrap());
}
