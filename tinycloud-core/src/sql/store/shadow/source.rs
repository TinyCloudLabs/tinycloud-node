//! Where the shadow uploader pulls its bytes from (TC-1491 P1).
//!
//! The save hook only says that a revision landed; the upload job reads the
//! durable artifact itself, through a [`ShadowSource`], straight into a
//! scratch file. Nothing here assembles a whole payload in memory.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use super::machine::{ArtifactHead, DeltaPlan, Head};
use crate::database_artifacts::{
    ArtifactMeta, ArtifactPart, ArtifactSink, DatabaseArtifactError, DatabaseArtifactRepository,
    WalMark,
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

    /// The WAL marks the artifact stored for `revisions`; a revision without
    /// a (valid) mark is left out.
    async fn wal_marks(
        &self,
        db: &DbRef<'_>,
        revisions: &[i64],
    ) -> Result<Vec<WalMark>, SourceError>;

    /// Write the WAL bytes `delta.start.wal_end_bytes .. delta.end.wal_end_bytes`
    /// of exactly `head` into `file` (truncated first). The whole stored WAL
    /// streams past and is hashed: if its first `start` bytes or its first
    /// `end` bytes do not hash to the marks' SHA-256, or it is not `end`
    /// bytes long, it is not the WAL the marks describe and the result is
    /// `None` (the caller publishes the cumulative WAL instead). `MovedOn`
    /// once the row is elsewhere.
    async fn wal_delta_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        delta: &DeltaPlan,
        file: &mut tokio::fs::File,
    ) -> Result<Option<Copied>, SourceError>;
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

    /// The row's metadata, if it is still at `head` and carries a WAL.
    async fn wal_meta(&self, db: &DbRef<'_>, head: &Head) -> Result<ArtifactMeta, SourceError> {
        let meta = self.meta(db).await?;
        if meta.revision != head.revision
            || meta.checkpoint_content_hash != head.cid
            || !meta.has_delta()
        {
            return Err(SourceError::MovedOn);
        }
        Ok(meta)
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
        let meta = self.wal_meta(db, head).await?;
        self.copy(db, &meta, ArtifactPart::Wal, file).await
    }

    async fn wal_marks(
        &self,
        db: &DbRef<'_>,
        revisions: &[i64],
    ) -> Result<Vec<WalMark>, SourceError> {
        self.repository
            .load_wal_marks(SERVICE, db.space, db.db_id, revisions)
            .await
            .map_err(source_error)
    }

    async fn wal_delta_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        delta: &DeltaPlan,
        file: &mut tokio::fs::File,
    ) -> Result<Option<Copied>, SourceError> {
        let meta = self.wal_meta(db, head).await?;
        let mut sink = RangeSink::new(file, delta);
        sink.truncate().await.map_err(sink_error)?;
        self.repository
            .read_part_chunks(
                SERVICE,
                db.space,
                db.db_id,
                &meta,
                ArtifactPart::Wal,
                &mut sink,
            )
            .await
            .map_err(source_error)?;
        sink.done().await
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

    /// Bytes go straight to the scratch file.
    fn buffers_in_memory(&self) -> bool {
        false
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

/// Writes the bytes of the one part it is handed that lie between two marks
/// into a scratch file, hashing the whole prefix up to each mark on the way.
struct RangeSink<'a> {
    file: &'a mut tokio::fs::File,
    start: u64,
    end: u64,
    start_sha256: [u8; 32],
    end_sha256: [u8; 32],
    /// SHA-256 of the part's bytes `[0, offset)`, up to `end`.
    prefix: Sha256,
    start_digest: Option<[u8; 32]>,
    end_digest: Option<[u8; 32]>,
    /// The slice written to the file.
    slice: Sha256,
    written: u64,
    /// Bytes of the part seen so far.
    offset: u64,
    parts: usize,
}

impl<'a> RangeSink<'a> {
    fn new(file: &'a mut tokio::fs::File, delta: &DeltaPlan) -> Self {
        Self {
            file,
            start: delta.start.wal_end_bytes,
            end: delta.end.wal_end_bytes,
            start_sha256: delta.start.wal_prefix_sha256,
            end_sha256: delta.end.wal_prefix_sha256,
            prefix: Sha256::new(),
            start_digest: None,
            end_digest: None,
            slice: Sha256::new(),
            written: 0,
            offset: 0,
            parts: 0,
        }
    }

    async fn truncate(&mut self) -> std::io::Result<()> {
        self.file.set_len(0).await?;
        self.file.rewind().await?;
        self.prefix = Sha256::new();
        self.slice = Sha256::new();
        self.written = 0;
        self.offset = 0;
        self.parts = 0;
        self.start_digest = None;
        self.end_digest = None;
        self.seal();
        Ok(())
    }

    /// Record the prefix hash when the stream reaches a mark.
    fn seal(&mut self) {
        if self.offset == self.start {
            self.start_digest = Some(self.prefix.clone().finalize().into());
        }
        if self.offset == self.end {
            self.end_digest = Some(self.prefix.clone().finalize().into());
        }
    }

    async fn done(mut self) -> Result<Option<Copied>, SourceError> {
        if self.parts != 1 {
            return Err(SourceError::Unreadable("the part was not delivered".into()));
        }
        if self.offset != self.end
            || self.start_digest != Some(self.start_sha256)
            || self.end_digest != Some(self.end_sha256)
        {
            return Ok(None);
        }
        self.file.flush().await.map_err(sink_error)?;
        Ok(Some(Copied {
            bytes: self.written,
            sha256: std::mem::take(&mut self.slice).finalize().into(),
        }))
    }
}

#[async_trait]
impl ArtifactSink for RangeSink<'_> {
    async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
        self.truncate().await.map_err(io)
    }

    async fn begin_part(&mut self, _part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
        self.parts += 1;
        Ok(())
    }

    /// Bytes go straight to the scratch file.
    fn buffers_in_memory(&self) -> bool {
        false
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
        let mut rest = bytes;
        while !rest.is_empty() && self.offset < self.end {
            // Up to the next mark: the start of the slice, then its end.
            let boundary = if self.offset < self.start {
                self.start
            } else {
                self.end
            };
            let take =
                usize::try_from(boundary - self.offset).map_or(rest.len(), |n| n.min(rest.len()));
            let (chunk, tail) = rest.split_at(take);
            self.prefix.update(chunk);
            if self.offset >= self.start {
                self.file.write_all(chunk).await.map_err(io)?;
                self.slice.update(chunk);
                self.written += chunk.len() as u64;
            }
            self.offset += chunk.len() as u64;
            self.seal();
            rest = tail;
        }
        // Bytes past the end are counted, so a longer WAL is told apart.
        self.offset += rest.len() as u64;
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

    // ---- TC-1491 P3: WAL deltas --------------------------------------------

    fn mark(cid: &str, revision: i64, wal: &[u8]) -> WalMark {
        WalMark {
            revision,
            checkpoint_content_hash: cid.into(),
            wal_end_bytes: wal.len() as u64,
            wal_prefix_sha256: sha256(wal),
        }
    }

    fn delta(start: WalMark, end: WalMark) -> DeltaPlan {
        DeltaPlan {
            from_seq: start.revision as u64 + 1,
            to_seq: end.revision as u64,
            start,
            end,
        }
    }

    #[tokio::test]
    async fn marks_carve_the_stored_wal_and_the_pieces_concatenate_to_the_prefix() {
        let (_, repo) = repository().await;
        let w1: &[u8] = b"wal-1";
        let w2: &[u8] = b"wal-1+2";
        let w3: &[u8] = b"wal-1+2+3";
        let meta = saved(&repo, "main", b"ck", &[w1, w2, w3]).await;
        let cid = meta.checkpoint_content_hash.clone();
        let source = PgArtifactSource::new(repo);
        let mut marks = source.wal_marks(&DB, &[2, 3, 4, 9]).await.unwrap();
        marks.sort_by_key(|m| m.revision);
        assert_eq!(
            marks,
            vec![mark(&cid, 2, w1), mark(&cid, 3, w2), mark(&cid, 4, w3)]
        );

        // Revision 2's WAL, then the bytes up to the head.
        let plan = delta(marks[0].clone(), marks[2].clone());
        let (path, mut file) = scratch().await;
        let copied = source
            .wal_delta_to(&DB, &meta_head(&meta), &plan, &mut file)
            .await
            .unwrap()
            .expect("the stored WAL extends the marked prefix");
        let piece = std::fs::read(&path).unwrap();
        assert_eq!(piece, b"+2+3");
        assert_eq!(
            copied,
            Copied {
                bytes: 4,
                sha256: sha256(b"+2+3")
            }
        );
        assert_eq!([w1, &piece[..]].concat(), w3, "prefix + delta = the WAL");
    }

    fn meta_head(meta: &ArtifactMeta) -> Head {
        artifact_head(meta).head()
    }

    #[tokio::test]
    async fn the_carve_does_not_depend_on_how_the_wal_is_chunked() {
        let wal = b"0123456789abcdefghij";
        let plan = delta(mark("ck", 2, &wal[..6]), mark("ck", 5, wal));
        for chunk in [1, 2, 5, 6, 7, 9, 15, 20, 64] {
            let (path, mut file) = scratch().await;
            let mut sink = RangeSink::new(&mut file, &plan);
            sink.truncate().await.unwrap();
            sink.begin_part(ArtifactPart::Wal).await.unwrap();
            for piece in wal.chunks(chunk) {
                sink.write(piece).await.unwrap();
            }
            sink.finish_part().await.unwrap();
            let copied = sink.done().await.unwrap().expect("matching prefixes");
            assert_eq!(std::fs::read(&path).unwrap(), &wal[6..], "chunk {chunk}");
            assert_eq!(copied.bytes, 14, "chunk {chunk}");
            assert_eq!(copied.sha256, sha256(&wal[6..]), "chunk {chunk}");
        }
    }

    #[tokio::test]
    async fn a_wal_that_does_not_extend_the_marked_prefix_is_not_carved() {
        let (_, repo) = repository().await;
        // Revision 3's WAL does not start with revision 2's: another WAL
        // generation reused the revision's place.
        let meta = saved(&repo, "main", b"ck", &[b"aaaaa", b"bbbbbbb"]).await;
        let cid = meta.checkpoint_content_hash.clone();
        let source = PgArtifactSource::new(repo);
        let plan = delta(mark(&cid, 2, b"aaaaa"), mark(&cid, 3, b"bbbbbbb"));
        let (_path, mut file) = scratch().await;
        assert_eq!(
            source
                .wal_delta_to(&DB, &meta_head(&meta), &plan, &mut file)
                .await
                .unwrap(),
            None,
            "the start mark's prefix hash differs"
        );
        // The end mark disagrees with the stored bytes.
        let plan = delta(mark(&cid, 2, b"bbbbb"), mark(&cid, 3, b"bbbbbbc"));
        assert_eq!(
            source
                .wal_delta_to(&DB, &meta_head(&meta), &plan, &mut file)
                .await
                .unwrap(),
            None,
            "the end mark's prefix hash differs"
        );
    }

    #[tokio::test]
    async fn a_stored_wal_longer_than_the_end_mark_is_not_carved() {
        let (_, repo) = repository().await;
        let meta = saved(&repo, "main", b"ck", &[b"wal-1", b"wal-1+2"]).await;
        let cid = meta.checkpoint_content_hash.clone();
        let source = PgArtifactSource::new(repo);
        // Both prefixes hash right, but the stored WAL goes on past `end`.
        let plan = delta(mark(&cid, 2, b"wal-1"), mark(&cid, 3, b"wal-1+"));
        let (_path, mut file) = scratch().await;
        assert_eq!(
            source
                .wal_delta_to(&DB, &meta_head(&meta), &plan, &mut file)
                .await
                .unwrap(),
            None
        );
        // And a WAL shorter than `end` never reaches it.
        let plan = delta(mark(&cid, 2, b"wal-1"), mark(&cid, 3, b"wal-1+2xx"));
        assert_eq!(
            source
                .wal_delta_to(&DB, &meta_head(&meta), &plan, &mut file)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_delta_read_of_a_head_that_moved_on_is_refused() {
        let (_, repo) = repository().await;
        let meta = saved(&repo, "main", b"ck", &[b"wal-1", b"wal-1+2"]).await;
        let cid = meta.checkpoint_content_hash.clone();
        let source = PgArtifactSource::new(repo);
        let plan = delta(mark(&cid, 2, b"wal-1"), mark(&cid, 3, b"wal-1+2"));
        let (_path, mut file) = scratch().await;
        let stale = Head {
            revision: meta.revision - 1,
            cid,
        };
        assert!(matches!(
            source.wal_delta_to(&DB, &stale, &plan, &mut file).await,
            Err(SourceError::MovedOn)
        ));
    }

    #[tokio::test]
    async fn a_new_checkpoint_leaves_no_marks_to_plan_from() {
        let (_, repo) = repository().await;
        saved(&repo, "main", b"ck", &[b"wal-1"]).await;
        repo.save(
            SERVICE,
            SPACE,
            "main",
            bytes::Bytes::from_static(b"ck2"),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let source = PgArtifactSource::new(repo);
        assert!(source.wal_marks(&DB, &[1, 2, 3]).await.unwrap().is_empty());
    }

    /// TC-2917: a database saved as `checkpoint-parts-v1` keeps its WAL as a
    /// second part. The source must read that WAL, not only the checkpoint
    /// part, and a row with no WAL has none to read.
    #[tokio::test]
    async fn postgres_a_parts_row_with_a_wal_is_read_checkpoint_and_wal() {
        use crate::database_artifacts::chunks::{ChunkLimits, CHUNK_BYTES};
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_a_parts_row_with_a_wal_is_read_checkpoint_and_wal",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:shadow";
        let repo = Arc::new(
            SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(Some(
                ChunkLimits {
                    artifact_bytes: 8 * CHUNK_BYTES as u64,
                    account_bytes: 8 * CHUNK_BYTES as u64,
                },
            )),
        );
        let part = |bytes: &[u8]| {
            use std::io::Write;
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(bytes).unwrap();
            file
        };
        // Each part spans two chunks.
        let checkpoint = vec![1u8; CHUNK_BYTES + 17];
        let wal = vec![2u8; CHUNK_BYTES + 23];
        let first = repo
            .save_snapshot(
                SERVICE,
                space,
                "main",
                part(&checkpoint),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let db = DbRef {
            space,
            db_id: "main",
        };
        let source = PgArtifactSource::new(repo.clone());
        let head = source.head(&db).await.unwrap().unwrap();
        assert!(!head.has_delta);
        let (_path, mut file) = scratch().await;
        assert!(matches!(
            source.wal_to(&db, &head.head(), &mut file).await,
            Err(SourceError::MovedOn)
        ));

        repo.save_wal_snapshot(
            SERVICE,
            space,
            "main",
            part(&wal),
            ArtifactExpectation::Derived {
                revision: first.revision,
                checkpoint_content_hash: first.checkpoint_content_hash.clone(),
            },
        )
        .await
        .unwrap();
        let head = source.head(&db).await.unwrap().unwrap();
        assert!(head.has_delta);
        assert_eq!(head.checkpoint_bytes, checkpoint.len() as u64);
        assert_eq!(head.delta_bytes, wal.len() as u64);

        let (path, mut file) = scratch().await;
        let copied = source
            .checkpoint_to(&db, &head.cid, &mut file)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), checkpoint);
        assert_eq!(copied.sha256, sha256(&checkpoint));
        let copied = source.wal_to(&db, &head.head(), &mut file).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), wal);
        assert_eq!(
            copied,
            Copied {
                bytes: wal.len() as u64,
                sha256: sha256(&wal)
            }
        );
    }
}
