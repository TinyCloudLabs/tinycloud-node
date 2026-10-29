use async_trait::async_trait;
use sea_orm::{
    sea_query::{Expr, Func},
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, DbErr, EntityTrait, QueryFilter, QuerySelect, SqlErr,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    db_pool::BulkScope,
    hash::{hash, Blake3Hasher},
    models::database_artifact,
};

#[derive(Debug, Clone)]
pub struct DatabaseArtifact {
    pub payload: Vec<u8>,
    pub content_hash: String,
    pub revision: i64,
    pub size_bytes: i64,
    pub updated_at: String,
    pub backend: String,
    pub storage_mode: String,
    pub checkpoint_content_hash: String,
    pub delta_payload: Option<Vec<u8>>,
    pub delta_content_hash: Option<String>,
    pub delta_size_bytes: i64,
}

/// What the caller's local database state derives from, asserted at save time.
///
/// The revision compare-and-swap below is a CONCURRENCY guard only: both saves
/// re-read the current revision, so a writer that is merely *stale* — an actor
/// holding a database it hydrated from an older checkpoint, running alone —
/// reads the current revision, matches it, and overwrites the newer durable
/// state. Carrying the base the caller actually derives from turns that into a
/// lineage check the stale writer cannot pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactExpectation {
    /// No lineage assertion: replace whatever is durable. For callers that
    /// deliberately overwrite unrelated content (DuckDB `import_db`).
    Any,
    /// The caller derives from NO durable artifact, so it may only create one.
    /// A row appearing in the meantime means the caller's empty database would
    /// clobber content it never read.
    Absent,
    /// The caller derives from exactly this checkpoint. `checkpoint_content_hash`
    /// (not `content_hash`) is the anchor: a WAL delta advances the revision and
    /// the logical hash while leaving the base checkpoint — and therefore the
    /// bytes the caller actually hydrated — unchanged.
    Derived {
        revision: i64,
        checkpoint_content_hash: String,
    },
}

impl ArtifactExpectation {
    /// The expectation a caller carries after committing `revision` on top of
    /// the same base checkpoint (a WAL delta save).
    pub fn advanced_to(&self, revision: i64) -> Self {
        match self {
            Self::Derived {
                checkpoint_content_hash,
                ..
            } => Self::Derived {
                revision,
                checkpoint_content_hash: checkpoint_content_hash.clone(),
            },
            other => other.clone(),
        }
    }

    /// Reject before touching durable state when the base is already known to
    /// differ. The atomic check is the update's `WHERE` clause or, for `Absent`,
    /// the create's primary key. Details: TC-2214
    fn check(&self, existing: Option<(i64, &str)>) -> Result<(), DatabaseArtifactError> {
        let conflict = match (self, existing) {
            (Self::Any, _) => false,
            (Self::Absent, existing) => existing.is_some(),
            (Self::Derived { .. }, None) => true,
            (
                Self::Derived {
                    revision,
                    checkpoint_content_hash,
                },
                Some((current_revision, current_hash)),
            ) => *revision != current_revision || checkpoint_content_hash != current_hash,
        };
        if conflict {
            return Err(DatabaseArtifactError::StaleLineage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaSave {
    pub revision: i64,
    pub size_bytes: i64,
    pub delta_size_bytes: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseArtifactError {
    #[error("database artifact storage error: {0}")]
    Db(#[from] DbErr),
    #[error("database artifact payload too large: {0} bytes")]
    PayloadTooLarge(u64),
    #[error("database artifact backend error: {0}")]
    Backend(String),
    #[error("database artifact checkpoint is missing")]
    MissingCheckpoint,
    #[error("database artifact backend does not support incremental persistence")]
    IncrementalPersistenceUnsupported,
    #[error("database artifact was written from a superseded checkpoint")]
    StaleLineage,
    #[error("database artifact changed while it was being read")]
    ArtifactChanged,
    #[error("database artifact {part} failed its content hash")]
    HashMismatch { part: &'static str },
    #[error("database artifact {part} is {actual} bytes, expected {expected}")]
    SizeMismatch {
        part: &'static str,
        expected: u64,
        actual: u64,
    },
    /// The sink handed to [`DatabaseArtifactRepository::read_chunks`] refused
    /// the bytes; the message is the sink's own.
    #[error("{0}")]
    Sink(String),
}

/// The stored metadata of one artifact row: everything but the payload bytes.
///
/// Reading it never touches the `payload` / `delta_payload` columns, so its
/// cost is independent of the artifact's size. It is what an existence check
/// or a size comparison needs, and what [`DatabaseArtifactRepository::read_chunks`]
/// pins a streamed read to.
///
/// Shape note for at-rest encoding (TC-887): sizes and hashes here describe the
/// STORED bytes, which today are the plain database file. An encoding column
/// (`payload_encoding`) would be added to this struct, and chunking would keep
/// applying to the stored (encoded) bytes, so decoding belongs in the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMeta {
    pub revision: i64,
    pub size_bytes: i64,
    pub content_hash: String,
    pub checkpoint_content_hash: String,
    pub checkpoint_size_bytes: i64,
    pub delta_content_hash: Option<String>,
    pub delta_size_bytes: i64,
    pub updated_at: String,
    pub storage_mode: String,
    pub backend: String,
}

impl ArtifactMeta {
    /// Whether the row carries a WAL delta next to its checkpoint.
    pub fn has_delta(&self) -> bool {
        self.delta_content_hash.is_some()
    }
}

/// Which stored column a streamed byte range belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPart {
    Checkpoint,
    Wal,
}

impl ArtifactPart {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::Wal => "wal",
        }
    }
}

/// Where [`DatabaseArtifactRepository::read_chunks`] delivers the artifact.
///
/// Calls for one attempt arrive as `begin_part(Checkpoint)`, `write`*,
/// `finish_part`, then, when the row has a delta, the same for `Wal`. A part
/// with no bytes still gets `begin_part` and `finish_part`. Nothing the sink
/// received is final until the caller's own commit step: a sink must be able to
/// `reset` and take the whole sequence again (a changed row restarts the read),
/// and must publish nothing before its caller says the read succeeded.
#[async_trait]
pub trait ArtifactSink: Send {
    /// Discard everything received so far; a new attempt is about to begin.
    async fn reset(&mut self) -> Result<(), DatabaseArtifactError>;
    async fn begin_part(&mut self, part: ArtifactPart) -> Result<(), DatabaseArtifactError>;
    /// The stored size of the part just begun, for sinks that buffer it.
    fn size_hint(&mut self, _part: ArtifactPart, _bytes: u64) {}
    async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError>;
    async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError>;
}

/// The most [`MemorySink`] allocates ahead of the bytes it is given.
const MAX_SIZE_HINT_BYTES: u64 = 64 * 1024 * 1024;

/// An [`ArtifactSink`] that keeps the bytes in memory, for callers that return
/// the whole artifact anyway (a DuckDB export) and for tests.
#[derive(Debug, Default)]
pub struct MemorySink {
    pub checkpoint: Vec<u8>,
    pub wal: Option<Vec<u8>>,
    current: Option<ArtifactPart>,
}

#[async_trait]
impl ArtifactSink for MemorySink {
    async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
        *self = Self::default();
        Ok(())
    }

    async fn begin_part(&mut self, part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
        self.current = Some(part);
        if part == ArtifactPart::Wal {
            self.wal = Some(Vec::new());
        }
        Ok(())
    }

    fn size_hint(&mut self, part: ArtifactPart, bytes: u64) {
        let target = match part {
            ArtifactPart::Checkpoint => Some(&mut self.checkpoint),
            ArtifactPart::Wal => self.wal.as_mut(),
        };
        if let Some(target) = target {
            // The hint comes from stored metadata. A corrupt value must not
            // abort the node (`reserve_exact` panics or aborts on overflow or
            // a failed allocation), so cap it and treat a refusal as no hint.
            let hint = usize::try_from(bytes.min(MAX_SIZE_HINT_BYTES)).unwrap_or(0);
            let _ = target.try_reserve_exact(hint);
        }
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
        match self.current {
            Some(ArtifactPart::Checkpoint) => self.checkpoint.extend_from_slice(bytes),
            Some(ArtifactPart::Wal) => self
                .wal
                .get_or_insert_with(Vec::new)
                .extend_from_slice(bytes),
            None => return Err(DatabaseArtifactError::Sink("write outside a part".into())),
        }
        Ok(())
    }

    async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
        self.current = None;
        Ok(())
    }
}

/// An [`ArtifactSink`] that stages the checkpoint and WAL as temp files next
/// to their final paths: nothing is visible at a final path until
/// [`CacheFileSink::commit`], which the caller runs only after
/// [`read_artifact`] succeeded. Dropping the sink (a failed, abandoned or
/// timed-out hydration) removes whatever was staged.
///
/// The leading bytes of each part are checked with the given validators before
/// the part is accepted, so a payload the database engine would misread (and
/// silently revert to empty) is refused.
pub struct CacheFileSink {
    service: &'static str,
    label: String,
    checkpoint_path: std::path::PathBuf,
    wal_path: std::path::PathBuf,
    valid_checkpoint: fn(&[u8]) -> bool,
    valid_wal: fn(&[u8]) -> bool,
    current: Option<StagedPart>,
    staged: Vec<(std::path::PathBuf, std::path::PathBuf)>,
}

struct StagedPart {
    part: ArtifactPart,
    temp: std::path::PathBuf,
    file: tokio::fs::File,
    validated: bool,
}

impl CacheFileSink {
    pub fn new(
        service: &'static str,
        label: String,
        checkpoint_path: std::path::PathBuf,
        wal_path: std::path::PathBuf,
        valid_checkpoint: fn(&[u8]) -> bool,
        valid_wal: fn(&[u8]) -> bool,
    ) -> Self {
        Self {
            service,
            label,
            checkpoint_path,
            wal_path,
            valid_checkpoint,
            valid_wal,
            current: None,
            staged: Vec::new(),
        }
    }

    fn io(error: std::io::Error) -> DatabaseArtifactError {
        DatabaseArtifactError::Sink(error.to_string())
    }

    fn validator(&self, part: ArtifactPart) -> fn(&[u8]) -> bool {
        match part {
            ArtifactPart::Checkpoint => self.valid_checkpoint,
            ArtifactPart::Wal => self.valid_wal,
        }
    }

    fn validate(&self, part: ArtifactPart, head: &[u8]) -> Result<(), DatabaseArtifactError> {
        if (self.validator(part))(head) {
            return Ok(());
        }
        tracing::error!(
            service = self.service,
            role = part.as_str(),
            "Durable database artifact does not carry the expected file header; refusing to hydrate"
        );
        Err(DatabaseArtifactError::Sink(format!(
            "database artifact {} for {} does not carry the expected file header",
            part.as_str(),
            self.label
        )))
    }

    fn discard(&mut self) {
        if let Some(current) = self.current.take() {
            let _ = std::fs::remove_file(&current.temp);
            release_staging(&current.temp);
        }
        for (temp, _) in self.staged.drain(..) {
            let _ = std::fs::remove_file(&temp);
            release_staging(&temp);
        }
    }

    /// Move the staged files to their final paths. The caller has already
    /// removed the stale cache files they replace.
    pub async fn commit(&mut self) -> std::io::Result<()> {
        // Renamed entries leave `staged`; on failure every one still in it
        // (the failing temp included) is removed by `discard`.
        let mut dirs = std::collections::BTreeSet::new();
        while let Some((temp, path)) = self.staged.first().cloned() {
            if let Err(error) = tokio::fs::rename(&temp, &path).await {
                self.discard();
                return Err(error);
            }
            release_staging(&temp);
            self.staged.remove(0);
            if let Some(parent) = path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        // The parts were synced before the rename; the rename itself is only
        // durable once its directory is (TC-1491).
        for dir in dirs {
            tokio::fs::File::open(&dir).await?.sync_all().await?;
        }
        Ok(())
    }
}

impl Drop for CacheFileSink {
    fn drop(&mut self) {
        self.discard();
    }
}

/// Staging files this process has created and not yet published or removed.
/// The sweep never touches these, so it cannot race a live write whose pid
/// matches a dead process's (pid reuse) or a write of another task.
fn live_staging() -> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    static LIVE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    > = std::sync::OnceLock::new();
    LIVE.get_or_init(Default::default)
}

/// A temp sibling of `path`, unique per call, registered as live until
/// [`release_staging`].
pub(crate) fn staging_path(path: &std::path::Path) -> std::path::PathBuf {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    // Appended to the whole path, never `with_extension`: `main.db` and
    // `main.db-wal` must not share a temp name.
    let temp = std::path::PathBuf::from(format!(
        "{}.tmp.{}.{}",
        path.display(),
        std::process::id(),
        NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    live_staging()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(temp.clone());
    temp
}

/// The staging file at `temp` was published or removed: the sweep may take it
/// from here on (a no-op if it is already gone).
pub(crate) fn release_staging(temp: &std::path::Path) {
    live_staging()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(temp);
}

#[cfg(feature = "duckdb")]
/// Releases a [`staging_path`] when dropped, whichever way its writer ends.
pub(crate) struct StagingRelease(pub(crate) std::path::PathBuf);

#[cfg(feature = "duckdb")]
impl Drop for StagingRelease {
    fn drop(&mut self) {
        release_staging(&self.0);
    }
}

/// Remove the `<final>.tmp.<pid>.<n>` files a crashed hydration left beside
/// each of `finals`: exactly this sink's temp-name pattern, and never a file
/// this process still has in flight. Run before a hydration begins, under the
/// database's hydration exclusion.
pub(crate) async fn sweep_stale_staging(finals: &[&std::path::Path]) {
    for path in finals {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            continue;
        };
        let prefix = format!("{}.tmp.", name.to_string_lossy());
        let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let Some(rest) = file_name
                .to_string_lossy()
                .strip_prefix(&prefix)
                .map(str::to_owned)
            else {
                continue;
            };
            let is_staging = matches!(
                rest.split_once('.'),
                Some((pid, id))
                    if !pid.is_empty()
                        && !id.is_empty()
                        && pid.bytes().all(|b| b.is_ascii_digit())
                        && id.bytes().all(|b| b.is_ascii_digit())
            );
            let temp = entry.path();
            let live = live_staging()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&temp);
            if is_staging && !live && tokio::fs::remove_file(&temp).await.is_ok() {
                tracing::info!("Removed a staging file left by an interrupted hydration");
            }
        }
    }
}

#[async_trait]
impl ArtifactSink for CacheFileSink {
    async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
        self.discard();
        Ok(())
    }

    async fn begin_part(&mut self, part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
        let path = match part {
            ArtifactPart::Checkpoint => self.checkpoint_path.clone(),
            ArtifactPart::Wal => self.wal_path.clone(),
        };
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(Self::io)?;
        }
        let temp = staging_path(&path);
        let file = match tokio::fs::File::create(&temp).await {
            Ok(file) => file,
            Err(error) => {
                release_staging(&temp);
                return Err(Self::io(error));
            }
        };
        self.current = Some(StagedPart {
            part,
            temp,
            file,
            validated: false,
        });
        Ok(())
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
        use tokio::io::AsyncWriteExt;
        let Some(current) = self.current.as_ref() else {
            return Err(DatabaseArtifactError::Sink("write outside a part".into()));
        };
        // The first slice holds every header the validators look at.
        if !current.validated {
            self.validate(current.part, bytes)?;
        }
        let current = self.current.as_mut().expect("checked above");
        current.validated = true;
        current.file.write_all(bytes).await.map_err(Self::io)
    }

    async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
        let Some(current) = self.current.as_ref() else {
            return Err(DatabaseArtifactError::Sink("no part to finish".into()));
        };
        // An empty part never saw a write; it is judged as the empty header.
        if !current.validated {
            self.validate(current.part, &[])?;
        }
        let StagedPart {
            part, temp, file, ..
        } = self.current.take().expect("checked above");
        if let Err(error) = file.sync_all().await {
            let _ = tokio::fs::remove_file(&temp).await;
            release_staging(&temp);
            return Err(Self::io(error));
        }
        drop(file);
        let path = match part {
            ArtifactPart::Checkpoint => self.checkpoint_path.clone(),
            ArtifactPart::Wal => self.wal_path.clone(),
        };
        self.staged.push((temp, path));
        Ok(())
    }
}

/// Read an artifact into `sink` in bounded slices, restarting when the row
/// changes underneath the read.
///
/// Returns the metadata the delivered bytes belong to, or `None` when there is
/// no such artifact (the sink is reset). A concurrent save between two
/// slices surfaces from [`DatabaseArtifactRepository::read_chunks`] as
/// [`DatabaseArtifactError::ArtifactChanged`]; the sink is `reset` and the read
/// restarts from fresh metadata, at most [`ARTIFACT_READ_RETRIES`] times, so a
/// sink never ends up holding a checkpoint of one revision and a WAL of
/// another.
pub async fn read_artifact<R: DatabaseArtifactRepository + ?Sized>(
    repository: &R,
    service: &str,
    space: &str,
    name: &str,
    sink: &mut dyn ArtifactSink,
) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
    let mut retries = 0;
    loop {
        let Some(meta) = repository.load_meta(service, space, name).await? else {
            sink.reset().await?;
            return Ok(None);
        };
        sink.reset().await?;
        match repository
            .read_chunks(service, space, name, &meta, sink)
            .await
        {
            Ok(()) => return Ok(Some(meta)),
            Err(DatabaseArtifactError::ArtifactChanged) if retries < ARTIFACT_READ_RETRIES => {
                retries += 1;
                tracing::info!(
                    service,
                    retries,
                    "Database artifact changed mid-read; restarting"
                );
            }
            Err(error) => return Err(error),
        }
    }
}

#[async_trait]
pub trait DatabaseArtifactRepository: Send + Sync {
    /// The artifact's stored metadata, with no payload bytes read.
    ///
    /// One cheap statement whatever the artifact's size: use it for existence
    /// checks and size comparisons, never `read_chunks`.
    async fn load_meta(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError>;

    /// Stream the stored checkpoint, then the WAL delta when `meta` has one,
    /// into `sink` in slices of at most [`ARTIFACT_CHUNK_BYTES`]; an artifact
    /// of at most [`BASE_TIMEOUT_PAYLOAD_BYTES`] stored bytes is one slice per
    /// part.
    ///
    /// Peak memory is one slice on PostgreSQL. On SQLite it is one stored blob
    /// transiently (the engine materialises the value before `substr` cuts it)
    /// and CPU is O(n^2 / chunk) in the artifact size, so the bound there is
    /// the part's size, not the slice. Every slice is
    /// its own statement (`substr(column, offset, length)`, which runs on
    /// both PostgreSQL `bytea` and SQLite `BLOB`) under the pool's base
    /// timeout, guarded by `WHERE revision = meta.revision AND
    /// checkpoint_content_hash = meta.checkpoint_content_hash`: a row that
    /// moved on yields [`DatabaseArtifactError::ArtifactChanged`] instead of
    /// bytes from two revisions. Round trips are `ceil(size / chunk)` per
    /// non-empty part, on top of the one `load_meta` that produced `meta`.
    ///
    /// The checkpoint is hashed while it streams and compared to
    /// `checkpoint_content_hash`, the WAL to `delta_content_hash`, and the row's
    /// logical `content_hash` to what those imply; any mismatch is an error and
    /// the caller must discard what the sink received. Prefer [`read_artifact`],
    /// which also handles the restart.
    ///
    /// TC-887: chunking applies to the STORED bytes; an encoded payload would
    /// be decoded by the sink (or a decoding wrapper around it), and the
    /// hashes verified here would be the stored-bytes hashes.
    async fn read_chunks(
        &self,
        service: &str,
        space: &str,
        name: &str,
        meta: &ArtifactMeta,
        sink: &mut dyn ArtifactSink,
    ) -> Result<(), DatabaseArtifactError>;

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
        expected: ArtifactExpectation,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError>;

    async fn save_delta(
        &self,
        _service: &str,
        _space: &str,
        _name: &str,
        _payload: Vec<u8>,
        _expected: ArtifactExpectation,
    ) -> Result<DeltaSave, DatabaseArtifactError> {
        Err(DatabaseArtifactError::IncrementalPersistenceUnsupported)
    }
}

/// The largest artifact payload written under the pool's base statement
/// timeout; a larger checkpoint is written in a
/// [`RecoveringConnection::begin_bulk`] scope (TC-1054). It matches the SQL
/// service's WAL delta bound (8 MiB): the server's work on an 8 MiB value
/// (compression, TOAST, WAL) takes well under a second, far inside the 30 s
/// default.
///
/// [`RecoveringConnection::begin_bulk`]: crate::db_pool::RecoveringConnection::begin_bulk
pub const BASE_TIMEOUT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// The slice size of a streamed artifact read. Two slices fit well inside
/// [`BASE_TIMEOUT_PAYLOAD_BYTES`]'s budget, so each runs under the base
/// statement timeout.
pub const ARTIFACT_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// How many times [`read_artifact`] restarts a read whose row changed.
pub const ARTIFACT_READ_RETRIES: usize = 2;

/// The stored metadata a full checkpoint save is checked against.
struct CurrentArtifact {
    revision: i64,
    size_bytes: i64,
    checkpoint_content_hash: String,
}

#[derive(Clone)]
pub struct SeaOrmDatabaseArtifactRepository {
    conn: crate::db_pool::RecoveringConnection,
    sqlite_writer_lock: Option<std::sync::Arc<tokio::sync::Mutex<()>>>,
    /// Test-only rendezvous seam (see [`wait_at_race_barrier`]) that lets two
    /// writers read the same base revision before either commits, so the
    /// full-checkpoint CAS conflict path can be exercised deterministically.
    #[cfg(test)]
    race_barrier: Option<std::sync::Arc<tokio::sync::Barrier>>,
}

impl SeaOrmDatabaseArtifactRepository {
    pub fn new(conn: impl Into<crate::db_pool::RecoveringConnection>) -> Self {
        Self {
            conn: conn.into(),
            sqlite_writer_lock: None,
            #[cfg(test)]
            race_barrier: None,
        }
    }

    /// Share the node's SQLite gate: artifact writes use the capability DB and
    /// must not advance its WAL beneath a delegation transaction's snapshot.
    pub fn with_sqlite_writer_lock(
        mut self,
        lock: Option<std::sync::Arc<tokio::sync::Mutex<()>>>,
    ) -> Self {
        self.sqlite_writer_lock = lock;
        self
    }

    #[cfg(test)]
    fn with_race_barrier_for_test(mut self, barrier: std::sync::Arc<tokio::sync::Barrier>) -> Self {
        self.race_barrier = Some(barrier);
        self
    }

    /// Park at the shared test barrier (SQLite only, matching the other
    /// CAS-conflict tests) after reading the current revision and before the
    /// conditional update, so a concurrent writer can bump the revision in
    /// between and drive this writer's compare-and-swap to zero rows.
    #[cfg(test)]
    async fn wait_at_race_barrier(&self) {
        use sea_orm::ConnectionTrait;
        if self.conn.get_database_backend() == sea_orm::DbBackend::Sqlite {
            if let Some(barrier) = &self.race_barrier {
                barrier.wait().await;
            }
        }
    }
}

struct ArtifactKey<'a> {
    service: &'a str,
    space: &'a str,
    name: &'a str,
}

impl SeaOrmDatabaseArtifactRepository {
    /// Stream one payload column into `sink`, hash it, and return its CID.
    async fn read_part(
        &self,
        key: &ArtifactKey<'_>,
        meta: &ArtifactMeta,
        part: ArtifactPart,
        size_bytes: i64,
        expected_hash: &str,
        sink: &mut dyn ArtifactSink,
    ) -> Result<String, DatabaseArtifactError> {
        let column = match part {
            ArtifactPart::Checkpoint => database_artifact::Column::Payload,
            ArtifactPart::Wal => database_artifact::Column::DeltaPayload,
        };
        let expected_len = u64::try_from(size_bytes).unwrap_or(0);
        // An artifact that fits the base-timeout budget is one slice per part:
        // no extra round trips for the common small database.
        // Gated on the part's own size as well, so inconsistent metadata
        // can never ask for a slice past the budget.
        let budget = BASE_TIMEOUT_PAYLOAD_BYTES as i64;
        let slice_bytes = if meta.size_bytes <= budget && size_bytes <= budget {
            expected_len.max(1)
        } else {
            ARTIFACT_CHUNK_BYTES as u64
        };
        let mut hasher = Blake3Hasher::new();
        sink.begin_part(part).await?;
        sink.size_hint(part, expected_len);
        let mut offset = 0_u64;
        while offset < expected_len {
            let len = (expected_len - offset).min(slice_bytes);
            // `substr` is 1-based and takes int4 on PostgreSQL.
            let start = i32::try_from(offset + 1)
                .map_err(|_| DatabaseArtifactError::PayloadTooLarge(expected_len))?;
            let slice = database_artifact::Entity::find()
                .select_only()
                .expr(
                    Func::cust("substr")
                        .arg(Expr::col(column))
                        .arg(start)
                        .arg(len as i32),
                )
                .filter(database_artifact::Column::Service.eq(key.service))
                .filter(database_artifact::Column::Space.eq(key.space))
                .filter(database_artifact::Column::Name.eq(key.name))
                .filter(database_artifact::Column::Revision.eq(meta.revision))
                .filter(
                    database_artifact::Column::CheckpointContentHash
                        .eq(meta.checkpoint_content_hash.as_str()),
                )
                .into_tuple::<Option<Vec<u8>>>()
                .one(&self.conn)
                .await?;
            // No row: the artifact was replaced or deleted since `meta`.
            let Some(slice) = slice else {
                return Err(DatabaseArtifactError::ArtifactChanged);
            };
            let slice = slice.unwrap_or_default();
            if slice.len() as u64 != len {
                return Err(DatabaseArtifactError::SizeMismatch {
                    part: part.as_str(),
                    expected: expected_len,
                    actual: offset + slice.len() as u64,
                });
            }
            hasher.update(&slice);
            sink.write(&slice).await?;
            offset += len;
        }
        let actual = hasher.finalize().to_cid(0x55).to_string();
        if actual != expected_hash {
            return Err(DatabaseArtifactError::HashMismatch {
                part: part.as_str(),
            });
        }
        sink.finish_part().await?;
        Ok(actual)
    }
}

#[async_trait]
impl DatabaseArtifactRepository for SeaOrmDatabaseArtifactRepository {
    async fn load_meta(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
        use database_artifact::Column;
        let row = database_artifact::Entity::find_by_id((
            service.to_string(),
            space.to_string(),
            name.to_string(),
        ))
        .select_only()
        .column(Column::Revision)
        .column(Column::SizeBytes)
        .column(Column::ContentHash)
        .column(Column::CheckpointContentHash)
        .column(Column::CheckpointSizeBytes)
        .column(Column::DeltaContentHash)
        .column(Column::DeltaSizeBytes)
        .column(Column::UpdatedAt)
        .column(Column::StorageMode)
        .column(Column::Backend)
        .into_tuple::<(
            i64,
            i64,
            String,
            String,
            i64,
            Option<String>,
            i64,
            String,
            String,
            String,
        )>()
        .one(&self.conn)
        .await?;
        Ok(row.map(
            |(
                revision,
                size_bytes,
                content_hash,
                checkpoint_content_hash,
                checkpoint_size_bytes,
                delta_content_hash,
                delta_size_bytes,
                updated_at,
                storage_mode,
                backend,
            )| ArtifactMeta {
                revision,
                size_bytes,
                content_hash,
                checkpoint_content_hash,
                checkpoint_size_bytes,
                delta_content_hash,
                delta_size_bytes,
                updated_at,
                storage_mode,
                backend,
            },
        ))
    }

    async fn read_chunks(
        &self,
        service: &str,
        space: &str,
        name: &str,
        meta: &ArtifactMeta,
        sink: &mut dyn ArtifactSink,
    ) -> Result<(), DatabaseArtifactError> {
        let key = ArtifactKey {
            service,
            space,
            name,
        };
        let checkpoint = self
            .read_part(
                &key,
                meta,
                ArtifactPart::Checkpoint,
                meta.checkpoint_size_bytes,
                &meta.checkpoint_content_hash,
                sink,
            )
            .await?;
        let logical = match &meta.delta_content_hash {
            Some(delta_hash) => {
                self.read_part(
                    &key,
                    meta,
                    ArtifactPart::Wal,
                    meta.delta_size_bytes,
                    delta_hash,
                    sink,
                )
                .await?;
                hash(format!("{checkpoint}:{delta_hash}").as_bytes())
                    .to_cid(0x55)
                    .to_string()
            }
            None => checkpoint,
        };
        if logical != meta.content_hash {
            return Err(DatabaseArtifactError::HashMismatch { part: "content" });
        }
        Ok(())
    }

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
        expected: ArtifactExpectation,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let size_bytes = i64::try_from(payload.len())
            .map_err(|_| DatabaseArtifactError::PayloadTooLarge(payload.len() as u64))?;
        let content_hash = hash(&payload).to_cid(0x55).to_string();
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        // A checkpoint larger than a WAL delta may take longer to upload than
        // the pool's base statement timeout allows, so its write runs under
        // the bulk one (TC-1054). Smaller ones, like every delta, fit the
        // base timeout and pay no extra round trip.
        let scope = if payload.len() > BASE_TIMEOUT_PAYLOAD_BYTES {
            self.conn.begin_bulk().await?
        } else {
            BulkScope::Pool(self.conn.clone())
        };
        // For Absent, the primary key on the create below asserts absence
        // atomically. Details: TC-2214
        let existing = if expected == ArtifactExpectation::Absent {
            None
        } else {
            // Only the metadata the CAS and the shrink warning need: reading the
            // stored checkpoint back would move it a second time.
            database_artifact::Entity::find_by_id((
                service.to_string(),
                space.to_string(),
                name.to_string(),
            ))
            .select_only()
            .column(database_artifact::Column::Revision)
            .column(database_artifact::Column::SizeBytes)
            .column(database_artifact::Column::CheckpointContentHash)
            .into_tuple::<(i64, i64, String)>()
            .one(&scope)
            .await?
            .map(
                |(revision, size_bytes, checkpoint_content_hash)| CurrentArtifact {
                    revision,
                    size_bytes,
                    checkpoint_content_hash,
                },
            )
        };

        expected.check(
            existing
                .as_ref()
                .map(|model| (model.revision, model.checkpoint_content_hash.as_str())),
        )?;

        // A full checkpoint that is a fraction of the content it replaces is
        // the shape of a database that reverted to an older (or empty) state
        // and re-anchored on it. Legitimate causes exist — VACUUM, a large
        // DELETE, WAL compaction — so this warns rather than rejects.
        if let Some(previous) = existing.as_ref() {
            if previous.size_bytes > 0 && size_bytes.saturating_mul(2) < previous.size_bytes {
                tracing::warn!(
                    service,
                    revision = previous.revision,
                    previous_logical_bytes = previous.size_bytes,
                    bytes = size_bytes,
                    "Database checkpoint shrank sharply against the artifact it replaces"
                );
            }
        }

        let revision = existing
            .as_ref()
            .map(|model| model.revision + 1)
            .unwrap_or(1);

        // Barrier seam (tests only): lets a second writer observe the same base
        // revision before either commits, exercising the CAS conflict path.
        #[cfg(test)]
        self.wait_at_race_barrier().await;

        match existing.as_ref() {
            Some(existing) => {
                // Compare-and-swap on the (revision, checkpoint) this save read.
                // That alone is a CONCURRENCY guard: it catches a writer whose
                // base was superseded between this read and this update, and
                // nothing else — a save re-reads the row every time, so a writer
                // running alone always matches whatever is current no matter how
                // stale its own database is. The lineage assertion checked above
                // is what rejects that writer; pairing the two here is what makes
                // the assertion atomic. Callers surface the conflict and force
                // actor rehydration rather than retry.
                let update = database_artifact::Entity::update_many()
                    .col_expr(database_artifact::Column::Revision, Expr::value(revision))
                    .col_expr(
                        database_artifact::Column::ContentHash,
                        Expr::value(content_hash.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::Payload,
                        Expr::value(payload.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::SizeBytes,
                        Expr::value(size_bytes),
                    )
                    .col_expr(
                        database_artifact::Column::Backend,
                        Expr::value("storage.database"),
                    )
                    .col_expr(
                        database_artifact::Column::StorageMode,
                        Expr::value("database-blob"),
                    )
                    .col_expr(
                        database_artifact::Column::UpdatedAt,
                        Expr::value(now.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::CheckpointSizeBytes,
                        Expr::value(size_bytes),
                    )
                    .col_expr(
                        database_artifact::Column::CheckpointContentHash,
                        Expr::value(content_hash.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::DeltaPayload,
                        Expr::value(Option::<Vec<u8>>::None),
                    )
                    .col_expr(
                        database_artifact::Column::DeltaContentHash,
                        Expr::value(Option::<String>::None),
                    )
                    .col_expr(
                        database_artifact::Column::DeltaSizeBytes,
                        Expr::value(0_i64),
                    )
                    .filter(database_artifact::Column::Service.eq(service))
                    .filter(database_artifact::Column::Space.eq(space))
                    .filter(database_artifact::Column::Name.eq(name))
                    .filter(database_artifact::Column::Revision.eq(existing.revision))
                    .filter(
                        database_artifact::Column::CheckpointContentHash
                            .eq(existing.checkpoint_content_hash.clone()),
                    )
                    .exec(&scope)
                    .await?;
                if update.rows_affected != 1 {
                    return Err(DatabaseArtifactError::Backend(
                        "concurrent database artifact update".to_string(),
                    ));
                }
            }
            None => {
                database_artifact::ActiveModel {
                    service: Set(service.to_string()),
                    space: Set(space.to_string()),
                    name: Set(name.to_string()),
                    revision: Set(revision),
                    content_hash: Set(content_hash.clone()),
                    payload: Set(payload.clone()),
                    size_bytes: Set(size_bytes),
                    backend: Set("storage.database".to_string()),
                    storage_mode: Set("database-blob".to_string()),
                    created_at: Set(now.clone()),
                    updated_at: Set(now.clone()),
                    checkpoint_size_bytes: Set(size_bytes),
                    checkpoint_content_hash: Set(content_hash.clone()),
                    delta_payload: Set(None),
                    delta_content_hash: Set(None),
                    delta_size_bytes: Set(0),
                }
                .insert(&scope)
                .await
                .map_err(|error| {
                    // For this table the composite primary key is the only unique
                    // constraint; translate a unique violation only for this Absent
                    // INSERT. Details: TC-2214
                    if expected == ArtifactExpectation::Absent
                        && matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
                    {
                        DatabaseArtifactError::StaleLineage
                    } else {
                        error.into()
                    }
                })?;
            }
        }

        scope.commit().await?;

        Ok(DatabaseArtifact {
            payload,
            content_hash: content_hash.clone(),
            revision,
            size_bytes,
            updated_at: now,
            backend: "storage.database".to_string(),
            storage_mode: "database-blob".to_string(),
            checkpoint_content_hash: content_hash,
            delta_payload: None,
            delta_content_hash: None,
            delta_size_bytes: 0,
        })
    }

    async fn save_delta(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
        expected: ArtifactExpectation,
    ) -> Result<DeltaSave, DatabaseArtifactError> {
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let existing = database_artifact::Entity::find_by_id((
            service.to_string(),
            space.to_string(),
            name.to_string(),
        ))
        .select_only()
        .column(database_artifact::Column::Revision)
        .column(database_artifact::Column::CheckpointSizeBytes)
        .column(database_artifact::Column::CheckpointContentHash)
        .into_tuple::<(i64, i64, String)>()
        .one(&self.conn)
        .await?
        .ok_or(DatabaseArtifactError::MissingCheckpoint)?;

        // A WAL is only replayable against the checkpoint it was built on, so
        // an actor that hydrated from a different one must not attach its delta
        // here — the resulting (checkpoint, WAL) pair would not describe any
        // database that ever existed.
        expected.check(Some((existing.0, existing.2.as_str())))?;

        let delta_size_bytes = i64::try_from(payload.len())
            .map_err(|_| DatabaseArtifactError::PayloadTooLarge(payload.len() as u64))?;
        let delta_content_hash = hash(&payload).to_cid(0x55).to_string();
        let logical_content_hash =
            hash(format!("{}:{}", existing.2, delta_content_hash).as_bytes())
                .to_cid(0x55)
                .to_string();
        let size_bytes = existing
            .1
            .checked_add(delta_size_bytes)
            .ok_or(DatabaseArtifactError::PayloadTooLarge(u64::MAX))?;
        let revision = existing.0 + 1;
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        let update = database_artifact::Entity::update_many()
            .col_expr(database_artifact::Column::Revision, Expr::value(revision))
            .col_expr(
                database_artifact::Column::ContentHash,
                Expr::value(logical_content_hash),
            )
            .col_expr(
                database_artifact::Column::DeltaPayload,
                Expr::value(Some(payload)),
            )
            .col_expr(
                database_artifact::Column::DeltaContentHash,
                Expr::value(Some(delta_content_hash)),
            )
            .col_expr(
                database_artifact::Column::DeltaSizeBytes,
                Expr::value(delta_size_bytes),
            )
            .col_expr(
                database_artifact::Column::SizeBytes,
                Expr::value(size_bytes),
            )
            .col_expr(
                database_artifact::Column::StorageMode,
                Expr::value("checkpoint+wal"),
            )
            .col_expr(database_artifact::Column::UpdatedAt, Expr::value(now))
            .filter(database_artifact::Column::Service.eq(service))
            .filter(database_artifact::Column::Space.eq(space))
            .filter(database_artifact::Column::Name.eq(name))
            .filter(database_artifact::Column::Revision.eq(existing.0))
            .filter(database_artifact::Column::CheckpointContentHash.eq(existing.2.clone()))
            .exec(&self.conn)
            .await?;
        if update.rows_affected != 1 {
            return Err(DatabaseArtifactError::Backend(
                "concurrent database artifact update".to_string(),
            ));
        }

        Ok(DeltaSave {
            revision,
            size_bytes,
            delta_size_bytes,
        })
    }
}

/// Test-only whole-artifact read built on the public streaming API, so tests
/// can assert on payload bytes. There is deliberately no such method on the
/// repository: the node never reads a whole row.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    #[async_trait]
    pub(crate) trait ReadAll {
        async fn read_all(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError>;
    }

    #[async_trait]
    impl<T: DatabaseArtifactRepository + ?Sized> ReadAll for T {
        async fn read_all(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
            let mut sink = MemorySink::default();
            let Some(meta) = read_artifact(self, service, space, name, &mut sink).await? else {
                return Ok(None);
            };
            Ok(Some(DatabaseArtifact {
                payload: sink.checkpoint,
                content_hash: meta.content_hash,
                revision: meta.revision,
                size_bytes: meta.size_bytes,
                updated_at: meta.updated_at,
                backend: meta.backend,
                storage_mode: meta.storage_mode,
                checkpoint_content_hash: meta.checkpoint_content_hash,
                delta_payload: sink.wal,
                delta_content_hash: meta.delta_content_hash,
                delta_size_bytes: meta.delta_size_bytes,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::ReadAll;
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn delta_save_replaces_wal_and_checkpoint_clears_it() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        repo.save(
            "sql",
            "space",
            "main",
            vec![1; 100],
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let delta = repo
            .save_delta(
                "sql",
                "space",
                "main",
                vec![2; 12],
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
        assert_eq!(delta.revision, 2);
        assert_eq!(delta.size_bytes, 112);
        assert_eq!(delta.delta_size_bytes, 12);

        let loaded = repo
            .read_all("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.payload, vec![1; 100]);
        assert_eq!(loaded.delta_payload, Some(vec![2; 12]));
        assert_eq!(loaded.storage_mode, "checkpoint+wal");

        repo.save(
            "sql",
            "space",
            "main",
            vec![3; 80],
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let checkpoint = repo
            .read_all("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.size_bytes, 80);
        assert_eq!(checkpoint.delta_size_bytes, 0);
        assert_eq!(checkpoint.delta_payload, None);
    }

    /// The failure the revision compare-and-swap cannot see: one writer, no
    /// concurrency, holding a database built on a superseded checkpoint.
    #[tokio::test]
    async fn stale_lineage_save_is_rejected_with_no_concurrent_writer() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        let base = repo
            .save(
                "sql",
                "space",
                "main",
                vec![1; 100],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let stale = ArtifactExpectation::Derived {
            revision: base.revision,
            checkpoint_content_hash: base.checkpoint_content_hash.clone(),
        };

        // A live actor advances the database. The stale actor's base is now gone.
        let current = repo
            .save("sql", "space", "main", vec![2; 200], stale.clone())
            .await
            .unwrap();
        assert_eq!(current.revision, 2);

        // The stale actor runs ALONE and re-reads the row, so the revision CAS
        // it performs matches whatever is current — only the lineage it carries
        // says its 100 bytes never derived from these 200.
        let err = repo
            .save("sql", "space", "main", vec![1; 100], stale.clone())
            .await
            .expect_err("a save from a superseded checkpoint must not commit");
        assert!(
            matches!(err, DatabaseArtifactError::StaleLineage),
            "expected a lineage rejection, got {err:?}"
        );
        let err = repo
            .save_delta("sql", "space", "main", vec![9; 12], stale)
            .await
            .expect_err("a WAL built on a superseded checkpoint must not attach");
        assert!(
            matches!(err, DatabaseArtifactError::StaleLineage),
            "expected a lineage rejection, got {err:?}"
        );

        let loaded = repo
            .read_all("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.revision, 2);
        assert_eq!(loaded.payload, vec![2; 200]);
        assert_eq!(loaded.delta_payload, None);

        // The guard rejects only supersession: the caller that is actually
        // caught up still commits.
        repo.save(
            "sql",
            "space",
            "main",
            vec![3; 300],
            ArtifactExpectation::Derived {
                revision: current.revision,
                checkpoint_content_hash: current.checkpoint_content_hash,
            },
        )
        .await
        .expect("a caller on the current checkpoint must still commit");
    }

    /// The other half of the same defect: a database that hydrated from nothing
    /// (an empty one) must not overwrite a row that appeared meanwhile.
    #[tokio::test]
    async fn save_expecting_no_artifact_is_rejected_once_one_exists() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        repo.save(
            "sql",
            "space",
            "main",
            vec![1; 4096],
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();

        let err = repo
            .save(
                "sql",
                "space",
                "main",
                vec![0; 8],
                ArtifactExpectation::Absent,
            )
            .await
            .expect_err("an empty database must not clobber durable content");
        assert!(
            matches!(err, DatabaseArtifactError::StaleLineage),
            "expected a lineage rejection, got {err:?}"
        );

        let loaded = repo
            .read_all("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.payload, vec![1; 4096]);
    }

    #[tokio::test]
    async fn postgres_absent_create_refuses_an_existing_or_racing_row() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
        use std::time::Duration;

        let Some(fixture) = crate::test_support::PostgresTestSchema::migrated_through(
            "postgres_absent_create_refuses_an_existing_or_racing_row",
            None,
        )
        .await
        else {
            return;
        };
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        let competitor = fixture.connect(1).await;
        let tx = competitor.begin().await.unwrap();
        let pid: i32 = tx
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT pg_backend_pid()",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        let payload = vec![7; 4096];
        let content_hash = hash(&payload).to_cid(0x55).to_string();
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let winner = database_artifact::ActiveModel {
            service: Set("sql".to_string()),
            space: Set("space".to_string()),
            name: Set("main".to_string()),
            revision: Set(1),
            content_hash: Set(content_hash.clone()),
            payload: Set(payload.clone()),
            size_bytes: Set(payload.len() as i64),
            backend: Set("storage.database".to_string()),
            storage_mode: Set("database-blob".to_string()),
            created_at: Set(now.clone()),
            updated_at: Set(now),
            checkpoint_size_bytes: Set(payload.len() as i64),
            checkpoint_content_hash: Set(content_hash),
            delta_payload: Set(None),
            delta_content_hash: Set(None),
            delta_size_bytes: Set(0),
        }
        .insert(&tx)
        .await
        .unwrap();
        let saver = repo.clone();
        let mut save = tokio::spawn(async move {
            saver
                .save(
                    "sql",
                    "space",
                    "main",
                    vec![0; 8],
                    ArtifactExpectation::Absent,
                )
                .await
        });
        let blocked = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if fixture
                    .conn
                    .query_one(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
                        [pid.into()],
                    ))
                    .await?
                    .is_some()
                {
                    return Ok::<_, DbErr>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let committed = tx.commit().await;
        let result = tokio::time::timeout(Duration::from_secs(10), &mut save).await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                save.abort();
                let _ = save.await;
                panic!("artifact save did not finish after competitor release: {error}");
            }
        };
        committed.unwrap();
        blocked
            .expect("save must wait for the uncommitted creator")
            .unwrap();
        let result = result.unwrap();
        assert!(
            matches!(result, Err(DatabaseArtifactError::StaleLineage)),
            "expected StaleLineage after the competing create committed, got {result:?}"
        );
        let stored = database_artifact::Entity::find_by_id((
            "sql".to_string(),
            "space".to_string(),
            "main".to_string(),
        ))
        .one(&fixture.conn)
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored, winner);
        let loaded = repo
            .read_all("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.payload, payload);
        assert_eq!(
            repo.load_meta("sql", "space", "main")
                .await
                .unwrap()
                .unwrap(),
            ArtifactMeta {
                revision: winner.revision,
                size_bytes: winner.size_bytes,
                content_hash: winner.content_hash,
                checkpoint_content_hash: winner.checkpoint_content_hash,
                checkpoint_size_bytes: winner.checkpoint_size_bytes,
                delta_content_hash: winner.delta_content_hash,
                delta_size_bytes: winner.delta_size_bytes,
                updated_at: winner.updated_at,
                storage_mode: winner.storage_mode,
                backend: winner.backend,
            }
        );

        repo.save("sql", "space", "empty", vec![], ArtifactExpectation::Any)
            .await
            .unwrap();
        let empty_before = repo.load_meta("sql", "space", "empty").await.unwrap();
        let result = repo
            .save(
                "sql",
                "space",
                "empty",
                vec![9; 8],
                ArtifactExpectation::Absent,
            )
            .await;
        assert!(
            matches!(result, Err(DatabaseArtifactError::StaleLineage)),
            "expected StaleLineage for an existing zero-byte row, got {result:?}"
        );
        assert_eq!(
            repo.load_meta("sql", "space", "empty").await.unwrap(),
            empty_before
        );
        let empty = repo
            .read_all("sql", "space", "empty")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(empty.revision, 1);
        assert_eq!(empty.payload, Vec::<u8>::new());
        competitor.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_full_checkpoint_save_conflicts_and_preserves_newer_revision() {
        // One shared in-memory database (single pooled connection) so two cloned
        // repositories race against the same rows. Per-statement pool acquisition
        // means neither holds the connection while parked at the barrier.
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        // Seed the checkpoint both writers will read as their base (revision 1).
        let seeded = repo
            .save(
                "sql",
                "space",
                "main",
                vec![1; 100],
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
        assert_eq!(seeded.revision, 1);

        // Both writers read revision 1, rendezvous at the barrier, then attempt
        // the full-checkpoint update. Exactly one wins the compare-and-swap; the
        // stale loser must fail without clobbering the winner's committed state.
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let first = repo
            .clone()
            .with_race_barrier_for_test(std::sync::Arc::clone(&barrier));
        let second = repo
            .clone()
            .with_race_barrier_for_test(std::sync::Arc::clone(&barrier));

        let (a, b) = tokio::join!(
            first.save(
                "sql",
                "space",
                "main",
                vec![2; 80],
                ArtifactExpectation::Any
            ),
            second.save(
                "sql",
                "space",
                "main",
                vec![3; 60],
                ArtifactExpectation::Any
            ),
        );

        let (winner, loser_err) = match (a, b) {
            (Ok(win), Err(err)) => (win, err),
            (Err(err), Ok(win)) => (win, err),
            other => panic!("expected exactly one success and one conflict, got {other:?}"),
        };
        assert!(
            matches!(&loser_err, DatabaseArtifactError::Backend(message)
                if message == "concurrent database artifact update"),
            "stale checkpoint must fail with the concurrent-update conflict, got {loser_err:?}"
        );
        assert_eq!(
            winner.revision, 2,
            "winner commits the single next revision"
        );

        // The stale writer must not have clobbered: durable state is the winner's
        // payload at revision 2, never the loser's bytes.
        let loaded = repo
            .read_all("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.revision, 2);
        assert_eq!(
            loaded.payload, winner.payload,
            "stale writer must not overwrite the winner's checkpoint"
        );
    }

    // ---- bounded streaming reads (TC-822) ----

    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use std::sync::{Arc, Mutex};

    const CHUNK: usize = ARTIFACT_CHUNK_BYTES;

    /// The replacement (checkpoint, optional WAL) a disturbance saves.
    type Disturb = fn(usize) -> (Vec<u8>, Option<Vec<u8>>);

    fn bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// A migrated in-memory SQLite repository plus a log of every statement
    /// it sends, the "counting connection" of the round-trip assertions.
    async fn spied_repo() -> (
        SeaOrmDatabaseArtifactRepository,
        DatabaseConnection,
        Arc<Mutex<Vec<String>>>,
    ) {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1);
        let mut conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let statements = Arc::new(Mutex::new(Vec::new()));
        let log = statements.clone();
        conn.set_metric_callback(move |info| {
            log.lock().unwrap().push(info.statement.sql.clone());
        });
        (
            SeaOrmDatabaseArtifactRepository::new(conn.clone()),
            conn,
            statements,
        )
    }

    fn ceil_div(len: usize) -> usize {
        len.div_ceil(CHUNK)
    }

    #[tokio::test]
    async fn chunk_boundaries_round_trip_within_the_round_trip_budget() {
        let (repo, _conn, statements) = spied_repo().await;
        let sizes = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1];
        let deltas = [None, Some(1), Some(CHUNK), Some(CHUNK + 1)];
        for (index, len) in sizes.into_iter().enumerate() {
            for (delta_index, delta) in deltas.into_iter().enumerate() {
                let name = format!("db-{index}-{delta_index}");
                let payload = bytes(len, 1);
                repo.save(
                    "sql",
                    "space",
                    &name,
                    payload.clone(),
                    ArtifactExpectation::Any,
                )
                .await
                .unwrap();
                let wal = delta.map(|len| bytes(len, 2));
                if let Some(wal) = &wal {
                    repo.save_delta("sql", "space", &name, wal.clone(), ArtifactExpectation::Any)
                        .await
                        .unwrap();
                }

                statements.lock().unwrap().clear();
                let mut sink = MemorySink::default();
                let meta = read_artifact(&repo, "sql", "space", &name, &mut sink)
                    .await
                    .unwrap()
                    .expect("the artifact exists");
                assert_eq!(sink.checkpoint, payload, "{name}: checkpoint");
                assert_eq!(sink.wal, wal, "{name}: wal");
                assert_eq!(meta.has_delta(), wal.is_some(), "{name}");

                // Every statement is a retryable read: a lost connection costs
                // one slice's retry, not the hydration.
                for sql in statements.lock().unwrap().iter() {
                    assert!(crate::db_pool::is_read_only_statement(sql), "{sql}");
                }
                // One metadata statement, then one per slice of each part; an
                // artifact within the base-timeout budget is one slice a part.
                let total = len + delta.unwrap_or(0);
                let parts = |part: usize| {
                    if total <= BASE_TIMEOUT_PAYLOAD_BYTES {
                        usize::from(part > 0)
                    } else {
                        ceil_div(part)
                    }
                };
                let expected = 1 + parts(len) + delta.map_or(0, parts);
                assert_eq!(
                    statements.lock().unwrap().len(),
                    expected,
                    "{name}: round trips for {len} + {delta:?} bytes"
                );
            }
        }
    }

    #[tokio::test]
    async fn metadata_and_absence_never_select_payload_columns() {
        let (repo, _conn, statements) = spied_repo().await;
        repo.save(
            "sql",
            "space",
            "main",
            bytes(CHUNK + 5, 3),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        repo.save_delta(
            "sql",
            "space",
            "main",
            bytes(9, 4),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();

        statements.lock().unwrap().clear();
        let meta = repo
            .load_meta("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.revision, 2);
        assert_eq!(meta.checkpoint_size_bytes, (CHUNK + 5) as i64);
        assert_eq!(meta.delta_size_bytes, 9);
        assert_eq!(meta.size_bytes, (CHUNK + 14) as i64);
        assert_eq!(meta.storage_mode, "checkpoint+wal");
        assert!(repo
            .load_meta("sql", "space", "absent")
            .await
            .unwrap()
            .is_none());

        let seen = statements.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(
            seen.iter().all(|sql| !sql.contains("payload")),
            "a metadata read must not touch payload columns: {seen:?}"
        );

        // Reading an absent artifact through the streaming helper stops at the
        // metadata too.
        statements.lock().unwrap().clear();
        let mut sink = MemorySink::default();
        assert!(read_artifact(&repo, "sql", "space", "absent", &mut sink)
            .await
            .unwrap()
            .is_none());
        assert_eq!(statements.lock().unwrap().len(), 1);
    }

    /// Disturbs the row once per attempt, right after the first slice landed,
    /// the way a concurrent save would between two slice statements.
    struct RaceSink<'a> {
        inner: MemorySink,
        repo: &'a SeaOrmDatabaseArtifactRepository,
        disturbances_left: usize,
        disturbed_this_attempt: bool,
        disturb: Disturb,
        attempts: usize,
    }

    #[async_trait]
    impl ArtifactSink for RaceSink<'_> {
        async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
            self.attempts += 1;
            self.disturbed_this_attempt = false;
            self.inner.reset().await
        }
        async fn begin_part(&mut self, part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
            self.inner.begin_part(part).await
        }
        async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
            self.inner.write(bytes).await?;
            if self.disturbances_left > 0 && !self.disturbed_this_attempt {
                self.disturbed_this_attempt = true;
                self.disturbances_left -= 1;
                let (checkpoint, wal) = (self.disturb)(self.disturbances_left);
                self.repo
                    .save("sql", "space", "main", checkpoint, ArtifactExpectation::Any)
                    .await
                    .unwrap();
                if let Some(wal) = wal {
                    self.repo
                        .save_delta("sql", "space", "main", wal, ArtifactExpectation::Any)
                        .await
                        .unwrap();
                }
            }
            Ok(())
        }
        async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
            self.inner.finish_part().await
        }
    }

    fn race_sink(
        repo: &SeaOrmDatabaseArtifactRepository,
        disturbances: usize,
        disturb: Disturb,
    ) -> RaceSink<'_> {
        RaceSink {
            inner: MemorySink::default(),
            repo,
            disturbances_left: disturbances,
            disturbed_this_attempt: false,
            disturb,
            attempts: 0,
        }
    }

    #[tokio::test]
    async fn a_row_replaced_mid_read_restarts_and_never_mixes_revisions() {
        let (repo, _conn, _) = spied_repo().await;
        repo.save(
            "sql",
            "space",
            "main",
            bytes(2 * CHUNK + 7, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let replacement = bytes(CHUNK + 3, 9);
        let wal = bytes(11, 8);

        let mut sink = race_sink(&repo, 1, |_| (bytes(CHUNK + 3, 9), Some(bytes(11, 8))));
        let meta = read_artifact(&repo, "sql", "space", "main", &mut sink)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sink.attempts, 2, "one restart");
        assert_eq!(meta.revision, 3, "save, save, then the WAL delta");
        assert_eq!(sink.inner.checkpoint, replacement, "only the new revision");
        assert_eq!(sink.inner.wal, Some(wal));
    }

    #[tokio::test]
    async fn a_wal_only_change_mid_read_also_restarts() {
        let (repo, _conn, _) = spied_repo().await;
        repo.save(
            "sql",
            "space",
            "main",
            bytes(2 * CHUNK + 1, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        repo.save_delta(
            "sql",
            "space",
            "main",
            bytes(5, 2),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();

        // The checkpoint hash is untouched by a delta, so the revision guard
        // is what catches this.
        struct DeltaRace<'a>(RaceSink<'a>, bool);
        #[async_trait]
        impl ArtifactSink for DeltaRace<'_> {
            async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
                self.0.reset().await
            }
            async fn begin_part(
                &mut self,
                part: ArtifactPart,
            ) -> Result<(), DatabaseArtifactError> {
                self.0.begin_part(part).await
            }
            async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
                self.0.inner.write(bytes).await?;
                if !self.1 {
                    self.1 = true;
                    self.0
                        .repo
                        .save_delta("sql", "space", "main", vec![7; 6], ArtifactExpectation::Any)
                        .await
                        .unwrap();
                }
                Ok(())
            }
            async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
                self.0.finish_part().await
            }
        }
        let mut sink = DeltaRace(race_sink(&repo, 0, |_| unreachable!()), false);
        let meta = read_artifact(&repo, "sql", "space", "main", &mut sink)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.revision, 3);
        assert_eq!(sink.0.attempts, 2);
        assert_eq!(sink.0.inner.wal, Some(vec![7; 6]));
        assert_eq!(sink.0.inner.checkpoint, bytes(2 * CHUNK + 1, 1));
    }

    #[tokio::test]
    async fn a_row_that_keeps_changing_gives_up_after_the_retries() {
        let (repo, _conn, _) = spied_repo().await;
        repo.save(
            "sql",
            "space",
            "main",
            bytes(2 * CHUNK + 1, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let mut sink = race_sink(&repo, 10, |left| (bytes(2 * CHUNK + 1, left as u8), None));
        let error = read_artifact(&repo, "sql", "space", "main", &mut sink)
            .await
            .expect_err("every attempt is overtaken");
        assert!(
            matches!(error, DatabaseArtifactError::ArtifactChanged),
            "{error:?}"
        );
        assert_eq!(sink.attempts, 1 + ARTIFACT_READ_RETRIES);
    }

    fn dir_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn cache_sink(dir: &std::path::Path) -> CacheFileSink {
        CacheFileSink::new(
            "sql",
            "space/main".to_string(),
            dir.join("main.db"),
            dir.join("main.db-wal"),
            |_| true,
            |_| true,
        )
    }

    #[tokio::test]
    async fn a_cache_file_is_never_seeded_from_a_mixed_read() {
        let (repo, _conn, _) = spied_repo().await;
        repo.save(
            "sql",
            "space",
            "main",
            bytes(2 * CHUNK + 7, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut files = cache_sink(dir.path());

        // Overtaken after the first slice of the old checkpoint reached the
        // temp file; the restart must rewrite it from the new revision.
        struct Overtaken<'a>(
            &'a mut CacheFileSink,
            &'a SeaOrmDatabaseArtifactRepository,
            bool,
        );
        #[async_trait]
        impl ArtifactSink for Overtaken<'_> {
            async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
                self.0.reset().await
            }
            async fn begin_part(
                &mut self,
                part: ArtifactPart,
            ) -> Result<(), DatabaseArtifactError> {
                self.0.begin_part(part).await
            }
            async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
                self.0.write(bytes).await?;
                if !self.2 {
                    self.2 = true;
                    self.1
                        .save(
                            "sql",
                            "space",
                            "main",
                            vec![5; CHUNK + 2],
                            ArtifactExpectation::Any,
                        )
                        .await
                        .unwrap();
                }
                Ok(())
            }
            async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
                self.0.finish_part().await
            }
        }
        read_artifact(
            &repo,
            "sql",
            "space",
            "main",
            &mut Overtaken(&mut files, &repo, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            dir_names(dir.path())
                .iter()
                .all(|name| name.contains(".tmp.")),
            "nothing is published before commit: {:?}",
            dir_names(dir.path())
        );
        files.commit().await.unwrap();
        assert_eq!(dir_names(dir.path()), ["main.db"]);
        assert_eq!(
            std::fs::read(dir.path().join("main.db")).unwrap(),
            vec![5; CHUNK + 2]
        );
    }

    #[tokio::test]
    async fn corrupt_artifact_bytes_are_rejected_and_nothing_is_seeded() {
        let (repo, conn, _) = spied_repo().await;
        let len = CHUNK + 10;
        repo.save(
            "sql",
            "space",
            "main",
            bytes(len, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        repo.save_delta(
            "sql",
            "space",
            "main",
            bytes(20, 2),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();

        for (what, sql, part) in [
            (
                "checkpoint flipped, same length",
                format!("UPDATE database_artifact SET payload = zeroblob({len})"),
                "checkpoint",
            ),
            (
                "wal flipped, same length",
                "UPDATE database_artifact SET delta_payload = zeroblob(20)".to_string(),
                "wal",
            ),
        ] {
            // Restore a good row before each corruption.
            repo.save(
                "sql",
                "space",
                "main",
                bytes(len, 1),
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
            repo.save_delta(
                "sql",
                "space",
                "main",
                bytes(20, 2),
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
            conn.execute_unprepared(&sql).await.unwrap();

            let dir = tempfile::tempdir().unwrap();
            let mut sink = cache_sink(dir.path());
            let error = read_artifact(&repo, "sql", "space", "main", &mut sink)
                .await
                .expect_err(what);
            assert!(
                matches!(&error, DatabaseArtifactError::HashMismatch { part: got } if *got == part),
                "{what}: {error:?}"
            );
            drop(sink);
            assert_eq!(
                dir_names(dir.path()),
                Vec::<String>::new(),
                "{what}: nothing left behind"
            );
        }

        // A stored size that disagrees with the bytes is refused too.
        repo.save(
            "sql",
            "space",
            "main",
            bytes(len, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        conn.execute_unprepared("UPDATE database_artifact SET payload = zeroblob(10)")
            .await
            .unwrap();
        let error = read_artifact(&repo, "sql", "space", "main", &mut MemorySink::default())
            .await
            .expect_err("short payload");
        assert!(
            matches!(error, DatabaseArtifactError::SizeMismatch { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn the_cache_sink_checks_the_leading_bytes_of_each_part() {
        let (repo, _conn, _) = spied_repo().await;
        repo.save(
            "sql",
            "space",
            "main",
            b"MAGIC-body".to_vec(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut sink = CacheFileSink::new(
            "sql",
            "space/main".to_string(),
            dir.path().join("main.db"),
            dir.path().join("main.db-wal"),
            |head| head.starts_with(b"OTHER"),
            |_| true,
        );
        let error = read_artifact(&repo, "sql", "space", "main", &mut sink)
            .await
            .expect_err("wrong header");
        assert!(
            error.to_string().contains("expected file header"),
            "{error}"
        );
        drop(sink);
        assert!(dir_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn postgres_slices_round_trip_at_chunk_boundaries_and_detect_changes() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::migrated_through(
            "postgres_slices_round_trip_at_chunk_boundaries_and_detect_changes",
            None,
        )
        .await
        else {
            return;
        };
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        for (index, len) in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1].into_iter().enumerate() {
            for (delta_index, delta) in [None, Some(1), Some(CHUNK + 1)].into_iter().enumerate() {
                let name = format!("db-{index}-{delta_index}");
                let payload = bytes(len, 1);
                repo.save(
                    "sql",
                    "space",
                    &name,
                    payload.clone(),
                    ArtifactExpectation::Any,
                )
                .await
                .unwrap();
                let wal = delta.map(|len| bytes(len, 2));
                if let Some(wal) = &wal {
                    repo.save_delta("sql", "space", &name, wal.clone(), ArtifactExpectation::Any)
                        .await
                        .unwrap();
                }
                let mut sink = MemorySink::default();
                read_artifact(&repo, "sql", "space", &name, &mut sink)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(sink.checkpoint, payload, "{name}: checkpoint");
                assert_eq!(sink.wal, wal, "{name}: wal");
            }
        }

        // Mid-read replacement restarts on Postgres too.
        repo.save(
            "sql",
            "space",
            "main",
            bytes(2 * CHUNK + 7, 1),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let mut sink = race_sink(&repo, 1, |_| (bytes(CHUNK + 3, 9), None));
        read_artifact(&repo, "sql", "space", "main", &mut sink)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sink.attempts, 2);
        assert_eq!(sink.inner.checkpoint, bytes(CHUNK + 3, 9));

        // And so does corruption.
        fixture
            .conn
            .execute_unprepared("UPDATE database_artifact SET payload = decode(repeat('00', 8), 'hex') || substr(payload, 9) WHERE name = 'main'")
            .await
            .unwrap();
        let error = read_artifact(&repo, "sql", "space", "main", &mut MemorySink::default())
            .await
            .expect_err("corrupt");
        assert!(
            matches!(error, DatabaseArtifactError::HashMismatch { .. }),
            "{error:?}"
        );
    }

    fn names(dir: &std::path::Path) -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        found
    }

    async fn stage_both(sink: &mut CacheFileSink) {
        for (part, body) in [
            (ArtifactPart::Checkpoint, b"cp"),
            (ArtifactPart::Wal, b"wl"),
        ] {
            sink.begin_part(part).await.unwrap();
            sink.write(body).await.unwrap();
            sink.finish_part().await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_failed_commit_leaves_no_staged_temp_files() {
        for blocked in ["main.db", "main.db-wal"] {
            let dir = tempfile::tempdir().unwrap();
            let mut sink = cache_sink(dir.path());
            stage_both(&mut sink).await;
            // A non-empty directory at the destination makes the rename fail.
            let target = dir.path().join(blocked);
            std::fs::create_dir(&target).unwrap();
            std::fs::write(target.join("occupied"), b"x").unwrap();

            sink.commit().await.unwrap_err();

            assert!(
                names(dir.path()).iter().all(|name| !name.contains(".tmp.")),
                "{blocked}: {:?}",
                names(dir.path())
            );
            drop(sink);
            assert!(names(dir.path()).iter().all(|name| !name.contains(".tmp.")));
        }
    }

    #[tokio::test]
    async fn the_sweep_removes_only_orphaned_staging_files() {
        let dir = tempfile::tempdir().unwrap();
        let orphans = ["main.db.tmp.4242.0", "main.db-wal.tmp.4242.7"];
        let kept = [
            "main.db",
            "main.db-wal",
            "other.db.tmp.4242.0",
            "main.db.tmp.abc.def",
            "main.db.tmp.1",
            "main.db.tmp.",
            "main.db.tmpx.1.2",
        ];
        for name in orphans.iter().chain(kept.iter()) {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        // A hydration in progress: one part still streaming, one finished.
        let mut live = cache_sink(dir.path());
        live.begin_part(ArtifactPart::Checkpoint).await.unwrap();
        live.write(b"cp").await.unwrap();
        live.finish_part().await.unwrap();
        live.begin_part(ArtifactPart::Wal).await.unwrap();
        let live_files: Vec<String> = names(dir.path())
            .into_iter()
            .filter(|name| name.contains(&format!(".tmp.{}.", std::process::id())))
            .collect();
        assert_eq!(live_files.len(), 2, "{live_files:?}");

        let main = dir.path().join("main.db");
        let wal = dir.path().join("main.db-wal");
        sweep_stale_staging(&[&main, &wal]).await;

        let left = names(dir.path());
        for name in orphans {
            assert!(!left.iter().any(|n| n == name), "{name} survived: {left:?}");
        }
        for name in kept.iter().map(|n| n.to_string()).chain(live_files) {
            assert!(left.contains(&name), "{name} was removed: {left:?}");
        }

        // Once the hydration ends, its files are no longer protected.
        drop(live);
        assert!(names(dir.path())
            .iter()
            .all(|n| !n.contains(&format!(".tmp.{}.", std::process::id()))));
    }

    /// A corrupt size in the artifact metadata is only a hint: it must not
    /// abort or panic the node, and the bytes still arrive intact.
    #[tokio::test]
    async fn tc1491_memory_sink_survives_an_absurd_size_hint() {
        for hint in [
            u64::MAX,
            usize::MAX as u64,
            (isize::MAX as u64) + 1,
            1 << 62,
            1 << 40,
        ] {
            let mut sink = MemorySink::default();
            sink.begin_part(ArtifactPart::Checkpoint).await.unwrap();
            sink.size_hint(ArtifactPart::Checkpoint, hint);
            sink.write(b"SQLite format 3\0").await.unwrap();
            sink.write(b"checkpoint").await.unwrap();
            sink.finish_part().await.unwrap();
            sink.begin_part(ArtifactPart::Wal).await.unwrap();
            sink.size_hint(ArtifactPart::Wal, hint);
            sink.write(b"wal").await.unwrap();
            sink.finish_part().await.unwrap();
            assert_eq!(sink.checkpoint, b"SQLite format 3\0checkpoint", "{hint}");
            assert_eq!(sink.wal.as_deref(), Some(&b"wal"[..]), "{hint}");
            assert!(
                sink.checkpoint.capacity() <= 64 * 1024 * 1024 + 64,
                "a hint of {hint} reserved {} bytes",
                sink.checkpoint.capacity()
            );
        }
    }
}
