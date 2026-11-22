//! Where the shadow uploader pulls its bytes from (TC-1491 P1).
//!
//! The save hook only says that a revision landed; the upload job reads the
//! durable artifact itself, through a [`ShadowSource`], straight into a
//! scratch file. Nothing here assembles a whole payload in memory.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use super::machine::{ArtifactHead, Head};
use crate::database_artifacts::{
    ArtifactMeta, ArtifactPart, ArtifactSink, DatabaseArtifactError, DatabaseArtifactRepository,
};
use crate::sql::store::key::DbRef;

/// The artifact service the SQL service saves under.
const SERVICE: &str = "sql";

/// How often a checkpoint read restarts when only the revision moved on
/// (a WAL delta landed on the same checkpoint mid-read).
const CHECKPOINT_READ_RETRIES: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The artifact is no longer at the revision or checkpoint asked for.
    #[error("the artifact moved on")]
    MovedOn,
    /// The artifact or its space is gone.
    #[error("the artifact or its space is gone")]
    Gone,
    /// The artifact is larger than the source will read.
    #[error("the artifact is larger than the read limit")]
    TooLarge,
    /// The stored bytes failed their own checks, or the layout cannot be
    /// read as asked; retrying the same row cannot help.
    #[error("the artifact is unreadable: {0}")]
    Unreadable(String),
    /// Anything else (connection, timeout, local file); retried with backoff.
    #[error("artifact source error: {0}")]
    Transient(String),
}

/// What a copy wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Copied {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[async_trait]
pub trait ShadowSource: Send + Sync {
    /// The artifact's current head; `None` when there is no artifact.
    async fn head(&self, db: &DbRef<'_>) -> Result<Option<ArtifactHead>, SourceError>;

    /// Write the stored checkpoint whose cid is `expected_cid` into `file`
    /// (truncated first). The cid is verified while the bytes stream; a row
    /// whose checkpoint changed is `MovedOn`.
    async fn checkpoint_to(
        &self,
        db: &DbRef<'_>,
        expected_cid: &str,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError>;

    /// Write the cumulative WAL of exactly `head` (revision and checkpoint)
    /// into `file` (truncated first); `MovedOn` once the row is elsewhere.
    async fn wal_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError>;
}

/// [`ShadowSource`] over the Postgres artifact repository, including the
/// chunked checkpoint layout.
pub struct PgArtifactSource {
    repository: Arc<dyn DatabaseArtifactRepository>,
}

impl PgArtifactSource {
    pub fn new(repository: Arc<dyn DatabaseArtifactRepository>) -> Self {
        Self { repository }
    }

    async fn meta(&self, db: &DbRef<'_>) -> Result<ArtifactMeta, SourceError> {
        self.repository
            .load_meta(SERVICE, db.space, db.db_id)
            .await
            .map_err(source_error)?
            .ok_or(SourceError::Gone)
    }

    async fn copy(
        &self,
        db: &DbRef<'_>,
        meta: &ArtifactMeta,
        part: ArtifactPart,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        let mut sink = FileSink::new(file);
        sink.truncate().await.map_err(sink_error)?;
        self.repository
            .read_part_chunks(SERVICE, db.space, db.db_id, meta, part, &mut sink)
            .await
            .map_err(source_error)?;
        sink.done().await
    }
}

#[async_trait]
impl ShadowSource for PgArtifactSource {
    async fn head(&self, db: &DbRef<'_>) -> Result<Option<ArtifactHead>, SourceError> {
        match self.meta(db).await {
            Ok(meta) => Ok(Some(artifact_head(&meta))),
            Err(SourceError::Gone) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn checkpoint_to(
        &self,
        db: &DbRef<'_>,
        expected_cid: &str,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        let mut retries = 0;
        loop {
            let meta = self.meta(db).await?;
            if meta.checkpoint_content_hash != expected_cid {
                return Err(SourceError::MovedOn);
            }
            match self.copy(db, &meta, ArtifactPart::Checkpoint, file).await {
                // A delta save on the same checkpoint bumps the revision the
                // read is pinned to; the checkpoint bytes are unchanged.
                Err(SourceError::MovedOn) if retries < CHECKPOINT_READ_RETRIES => retries += 1,
                other => return other,
            }
        }
    }

    async fn wal_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        let meta = self.meta(db).await?;
        if meta.revision != head.revision
            || meta.checkpoint_content_hash != head.cid
            || !meta.has_delta()
        {
            return Err(SourceError::MovedOn);
        }
        self.copy(db, &meta, ArtifactPart::Wal, file).await
    }
}

pub fn artifact_head(meta: &ArtifactMeta) -> ArtifactHead {
    ArtifactHead {
        revision: meta.revision,
        cid: meta.checkpoint_content_hash.clone(),
        has_delta: meta.has_delta(),
        checkpoint_bytes: u64::try_from(meta.checkpoint_size_bytes).unwrap_or(0),
        delta_bytes: u64::try_from(meta.delta_size_bytes).unwrap_or(0),
    }
}

fn source_error(error: DatabaseArtifactError) -> SourceError {
    use DatabaseArtifactError as E;
    match error {
        E::ArtifactChanged | E::StaleLineage => SourceError::MovedOn,
        E::SpaceDeleted => SourceError::Gone,
        E::ReadLimitExceeded { .. } | E::PayloadTooLarge(_) => SourceError::TooLarge,
        E::HashMismatch { .. } | E::SizeMismatch { .. } | E::IncrementalPersistenceUnsupported => {
            SourceError::Unreadable(error.to_string())
        }
        other => SourceError::Transient(other.to_string()),
    }
}

fn sink_error(error: std::io::Error) -> SourceError {
    SourceError::Transient(format!("scratch file: {:?}", error.kind()))
}

/// Writes the one part it is handed into a scratch file, hashing it.
struct FileSink<'a> {
    file: &'a mut tokio::fs::File,
    hasher: Sha256,
    bytes: u64,
    parts: usize,
}

impl<'a> FileSink<'a> {
    fn new(file: &'a mut tokio::fs::File) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            bytes: 0,
            parts: 0,
        }
    }

    async fn truncate(&mut self) -> std::io::Result<()> {
        self.file.set_len(0).await?;
        self.file.rewind().await?;
        self.hasher = Sha256::new();
        self.bytes = 0;
        self.parts = 0;
        Ok(())
    }

    async fn done(mut self) -> Result<Copied, SourceError> {
        if self.parts != 1 {
            return Err(SourceError::Unreadable("the part was not delivered".into()));
        }
        self.file.flush().await.map_err(sink_error)?;
        Ok(Copied {
            bytes: self.bytes,
            sha256: std::mem::take(&mut self.hasher).finalize().into(),
        })
    }
}

fn io(error: std::io::Error) -> DatabaseArtifactError {
    DatabaseArtifactError::Sink(format!("scratch file: {:?}", error.kind()))
}

#[async_trait]
impl ArtifactSink for FileSink<'_> {
    async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
        self.truncate().await.map_err(io)
    }

    async fn begin_part(&mut self, _part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
        self.parts += 1;
        Ok(())
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
        self.file.write_all(bytes).await.map_err(io)?;
        self.hasher.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::database_artifacts::{ArtifactExpectation, SeaOrmDatabaseArtifactRepository};
    use crate::migrations::Migrator;
    use crate::sql::store::object::sha256;
    use sea_orm::{ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;

    pub(crate) const SPACE: &str = "tinycloud:pkh:eip155:1:0xAb://default";

    pub(crate) async fn repository() -> (
        sea_orm::DatabaseConnection,
        Arc<SeaOrmDatabaseArtifactRepository>,
    ) {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        (
            conn.clone(),
            Arc::new(SeaOrmDatabaseArtifactRepository::new(conn)),
        )
    }

    /// Save a checkpoint (revision 1) and, per `wals`, WAL deltas on it.
    pub(crate) async fn saved(
        repo: &SeaOrmDatabaseArtifactRepository,
        db: &str,
        checkpoint: &[u8],
        wals: &[&[u8]],
    ) -> ArtifactMeta {
        let saved = repo
            .save(
                SERVICE,
                SPACE,
                db,
                bytes::Bytes::copy_from_slice(checkpoint),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let mut revision = saved.revision;
        for wal in wals {
            revision = repo
                .save_delta(
                    SERVICE,
                    SPACE,
                    db,
                    bytes::Bytes::copy_from_slice(wal),
                    ArtifactExpectation::Derived {
                        revision,
                        checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
                    },
                )
                .await
                .unwrap()
                .revision;
        }
        repo.load_meta(SERVICE, SPACE, db).await.unwrap().unwrap()
    }

    async fn scratch() -> (tempfile::TempPath, tokio::fs::File) {
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
            .unwrap();
        (path, file)
    }

    const DB: DbRef<'static> = DbRef {
        space: SPACE,
        db_id: "main",
    };

    #[tokio::test]
    async fn checkpoint_and_wal_stream_into_files_with_their_sha256() {
        let (_, repo) = repository().await;
        let meta = saved(&repo, "main", b"checkpoint-bytes", &[b"wal-1", b"wal-1+2"]).await;
        let source = PgArtifactSource::new(repo);
        let head = source.head(&DB).await.unwrap().unwrap();
        assert_eq!(
            head,
            ArtifactHead {
                revision: 3,
                cid: meta.checkpoint_content_hash.clone(),
                has_delta: true,
                checkpoint_bytes: 16,
                delta_bytes: 7,
            }
        );
        let (path, mut file) = scratch().await;
        // A stale file is truncated, not appended to.
        file.write_all(b"stale-stale-stale-stale").await.unwrap();
        let copied = source
            .checkpoint_to(&DB, &head.cid, &mut file)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"checkpoint-bytes");
        assert_eq!(
            copied,
            Copied {
                bytes: 16,
                sha256: sha256(b"checkpoint-bytes")
            }
        );
        let copied = source.wal_to(&DB, &head.head(), &mut file).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"wal-1+2");
        assert_eq!(copied.sha256, sha256(b"wal-1+2"));
    }

    #[tokio::test]
    async fn a_source_that_moved_on_is_refused() {
        let (_, repo) = repository().await;
        let meta = saved(&repo, "main", b"ck", &[b"w1"]).await;
        let source = PgArtifactSource::new(repo.clone());
        let (_path, mut file) = scratch().await;
        assert!(matches!(
            source.checkpoint_to(&DB, "bafy-other", &mut file).await,
            Err(SourceError::MovedOn)
        ));
        let stale = Head {
            revision: meta.revision - 1,
            cid: meta.checkpoint_content_hash.clone(),
        };
        assert!(matches!(
            source.wal_to(&DB, &stale, &mut file).await,
            Err(SourceError::MovedOn)
        ));
        let missing = DbRef {
            space: SPACE,
            db_id: "nope",
        };
        assert_eq!(source.head(&missing).await.unwrap(), None);
        assert!(matches!(
            source.checkpoint_to(&missing, "x", &mut file).await,
            Err(SourceError::Gone)
        ));
    }

    #[tokio::test]
    async fn a_checkpoint_without_a_delta_has_no_wal() {
        let (_, repo) = repository().await;
        let meta = saved(&repo, "main", b"only-ck", &[]).await;
        let source = PgArtifactSource::new(repo);
        let head = source.head(&DB).await.unwrap().unwrap();
        assert!(!head.has_delta);
        assert_eq!(head.revision, meta.revision);
        let (_path, mut file) = scratch().await;
        assert!(matches!(
            source.wal_to(&DB, &head.head(), &mut file).await,
            Err(SourceError::MovedOn)
        ));
    }
}
