use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{
    sea_query::{Expr, Func},
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, DbErr, EntityTrait, QueryFilter, QuerySelect, SqlErr,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    at_rest::{
        self, AtRestMode, AtRestSource, AtRestView, BlobIdentity, DataKey, DataKeyError,
        DataKeyProvider, EnvelopeError, Header, PayloadEncoding, SegmentOpener, SqlManifestPart,
        HEADER_LEN,
    },
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
    /// The at-rest keys a sealed write or read needs are not available now:
    /// locked, the encrypt gate closed, or the key store failed. Nothing was
    /// written and nothing was read as plaintext. Callers answer 503.
    #[error("database artifact at-rest keys are unavailable")]
    AtRestUnavailable,
    /// A sealed part did not open: tampered, truncated, moved from another
    /// artifact, revision or space, or naming a key its space never had.
    /// Never read as legacy plaintext. Callers answer 500.
    #[error("database artifact {part} failed its at-rest integrity check")]
    AtRestIntegrity { part: &'static str },
    /// A part stored in a later at-rest format than this build reads. The
    /// marker is unauthenticated, so this fails closed exactly like an
    /// integrity failure. Callers answer 500.
    #[error("database artifact {part} uses unsupported at-rest format version {version}; upgrade the node")]
    AtRestUnsupported { part: &'static str, version: u8 },
    /// A legacy plaintext part read in `strict` mode. Callers answer 500.
    #[error("database artifact {part} is legacy plaintext, which strict at-rest mode refuses")]
    LegacyPlaintextRefused { part: &'static str },
}

/// A key-store failure while reading a sealed part. A key the space never
/// had is an integrity failure of the part; anything else means the keys
/// are unavailable now.
fn read_key_error(part: ArtifactPart, error: DataKeyError) -> DatabaseArtifactError {
    key_error_at(part.as_str(), error)
}

/// [`read_key_error`] for a sealed item named `role`.
fn key_error_at(role: &'static str, error: DataKeyError) -> DatabaseArtifactError {
    match error {
        DataKeyError::UnknownKey { .. } => {
            tracing::error!(
                role,
                "Sealed database artifact names a data key its space does not have"
            );
            DatabaseArtifactError::AtRestIntegrity { part: role }
        }
        error => {
            tracing::warn!(role, %error, "At-rest keys unavailable for a sealed database artifact");
            DatabaseArtifactError::AtRestUnavailable
        }
    }
}

/// An envelope failure on a sealed part: `Unsupported` keeps its operator
/// message, everything else is an integrity failure. Both fail closed.
fn envelope_error(part: ArtifactPart, error: EnvelopeError) -> DatabaseArtifactError {
    envelope_error_at(part.as_str(), error)
}

/// [`envelope_error`] for a sealed item named `role`.
fn envelope_error_at(role: &'static str, error: EnvelopeError) -> DatabaseArtifactError {
    match error {
        EnvelopeError::Unsupported { version } => {
            tracing::error!(
                role,
                version,
                "Database artifact uses an unsupported at-rest format; upgrade the node"
            );
            DatabaseArtifactError::AtRestUnsupported {
                part: role,
                version,
            }
        }
        error => {
            tracing::error!(role, %error, "Database artifact failed its at-rest integrity check");
            DatabaseArtifactError::AtRestIntegrity { part: role }
        }
    }
}

/// The stored metadata of one artifact row: everything but the payload bytes.
///
/// Reading it never touches the `payload` / `delta_payload` columns, so its
/// cost is independent of the artifact's size. It is what an existence check
/// or a size comparison needs, and what [`DatabaseArtifactRepository::read_chunks`]
/// pins a streamed read to.
///
/// At rest (TC-887): sizes and hashes here describe the PLAINTEXT database
/// file whatever the encoding, so quota and growth checks read them as
/// before; they are also part of what a sealed part is bound to. A TCE1 part
/// stores `at_rest::ciphertext_len(size)` bytes, which the streamed read
/// slices and decodes before hashing.
#[derive(Debug, Clone, PartialEq, Eq, sea_orm::FromQueryResult)]
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
    /// How `payload` is stored (`at_rest::PayloadEncoding::from_column`).
    pub payload_encoding: Option<i16>,
    /// How `delta_payload` is stored.
    pub delta_encoding: Option<i16>,
    /// The row's manifest tag (80 bytes when present): checked before any
    /// part is read (`docs/at-rest/INTERFACES.md` §8).
    pub manifest: Option<Vec<u8>>,
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
    /// TC-887: chunking applies to the STORED bytes. A TCE1 part is decoded
    /// as it streams, one 64 KiB segment at a time, so the sink receives and
    /// the hashes cover the plaintext database file. Whether a part is
    /// sealed comes from its encoding column, never from its bytes.
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
    /// The node's at-rest state, read per operation; `None` is mode `off`
    /// with no keys.
    at_rest: Option<Arc<dyn AtRestSource>>,
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
            at_rest: None,
            #[cfg(test)]
            race_barrier: None,
        }
    }

    /// Seal and open parts by the node's at-rest state (TC-887). Mode `off`
    /// stores plaintext exactly as without it; any other mode seals every
    /// part it writes or fails the write, never falling back to plaintext.
    pub fn with_at_rest(mut self, source: Arc<dyn AtRestSource>) -> Self {
        self.at_rest = Some(source);
        self
    }

    fn at_rest_view(&self) -> AtRestView {
        self.at_rest
            .as_ref()
            .map_or_else(AtRestView::off, |source| source.view())
    }

    /// The key a write in `space` seals with, or `None` in mode `off`.
    ///
    /// Runs before the SQLite writer lock: `current_key` may create the
    /// space's data key, which writes the key store, and the key store
    /// takes that lock on SQLite.
    async fn write_key(&self, space: &str) -> Result<Option<DataKey>, DatabaseArtifactError> {
        let view = self.at_rest_view();
        if view.mode == AtRestMode::Off {
            return Ok(None);
        }
        let provider = match view.provider {
            Some(provider) if view.encrypting => provider,
            _ => {
                tracing::warn!("Database artifact write refused: at-rest encryption is not on");
                return Err(DatabaseArtifactError::AtRestUnavailable);
            }
        };
        match provider.current_key(space).await {
            Ok(key) => Ok(Some(key)),
            Err(error) => {
                tracing::warn!(%error, "Database artifact write refused: no at-rest data key");
                Err(DatabaseArtifactError::AtRestUnavailable)
            }
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

#[derive(Clone, Copy)]
struct ArtifactKey<'a> {
    service: &'a str,
    space: &'a str,
    name: &'a str,
}

/// What one stored part's TCE1 ciphertext is bound to
/// (`docs/at-rest/INTERFACES.md` §4): the row's key and the part's plaintext
/// hash and size, and for a WAL the revision that wrote it and the checkpoint
/// it applies to. A part moved to another row, revision or checkpoint does
/// not open. Owned, so sealing can run off the async runtime.
enum PartBinding {
    Checkpoint {
        service: String,
        space: String,
        name: String,
        content_hash: String,
        size_bytes: u64,
    },
    Wal {
        service: String,
        space: String,
        name: String,
        revision: i64,
        checkpoint_content_hash: String,
        delta_content_hash: String,
    },
}

impl PartBinding {
    fn checkpoint(key: &ArtifactKey<'_>, content_hash: &str, size_bytes: i64) -> Self {
        Self::Checkpoint {
            service: key.service.to_owned(),
            space: key.space.to_owned(),
            name: key.name.to_owned(),
            content_hash: content_hash.to_owned(),
            size_bytes: u64::try_from(size_bytes).unwrap_or(0),
        }
    }

    fn wal(
        key: &ArtifactKey<'_>,
        revision: i64,
        checkpoint_content_hash: &str,
        delta_content_hash: &str,
    ) -> Self {
        Self::Wal {
            service: key.service.to_owned(),
            space: key.space.to_owned(),
            name: key.name.to_owned(),
            revision,
            checkpoint_content_hash: checkpoint_content_hash.to_owned(),
            delta_content_hash: delta_content_hash.to_owned(),
        }
    }

    /// The binding of `part` of the row `meta` describes.
    fn of(key: &ArtifactKey<'_>, meta: &ArtifactMeta, part: ArtifactPart) -> Self {
        match part {
            ArtifactPart::Checkpoint => Self::checkpoint(
                key,
                &meta.checkpoint_content_hash,
                meta.checkpoint_size_bytes,
            ),
            ArtifactPart::Wal => Self::wal(
                key,
                meta.revision,
                &meta.checkpoint_content_hash,
                meta.delta_content_hash.as_deref().unwrap_or_default(),
            ),
        }
    }

    fn identity(&self) -> BlobIdentity<'_> {
        match self {
            Self::Checkpoint {
                service,
                space,
                name,
                content_hash,
                size_bytes,
            } => BlobIdentity::SqlCheckpoint {
                service,
                space,
                name,
                checkpoint_content_hash: content_hash,
                checkpoint_size_bytes: *size_bytes,
            },
            Self::Wal {
                service,
                space,
                name,
                revision,
                checkpoint_content_hash,
                delta_content_hash,
            } => BlobIdentity::SqlWal {
                service,
                space,
                name,
                revision: *revision,
                checkpoint_content_hash,
                delta_content_hash,
            },
        }
    }
}

/// A row's manifest (`docs/at-rest/INTERFACES.md` §8): its revision, logical
/// hash and size, and for each part it holds the plaintext hash, size and
/// encoding. A sealed write stores a tag for it in `manifest` (a TCE1 seal
/// of nothing under this identity, so a key-bound MAC); a read checks the
/// tag before any part. A dropped delta, a part or metadata from another
/// revision, or a changed encoding then fails as integrity instead of
/// reading as some other database.
struct RowManifest<'a> {
    key: ArtifactKey<'a>,
    revision: i64,
    content_hash: &'a str,
    size_bytes: i64,
    checkpoint: SqlManifestPart<'a>,
    delta: Option<SqlManifestPart<'a>>,
}

impl<'a> RowManifest<'a> {
    fn of_meta(key: ArtifactKey<'a>, meta: &'a ArtifactMeta) -> Self {
        Self {
            key,
            revision: meta.revision,
            content_hash: &meta.content_hash,
            size_bytes: meta.size_bytes,
            checkpoint: SqlManifestPart {
                content_hash: &meta.checkpoint_content_hash,
                size_bytes: meta.checkpoint_size_bytes,
                encoding: meta.payload_encoding,
            },
            delta: meta
                .delta_content_hash
                .as_deref()
                .map(|content_hash| SqlManifestPart {
                    content_hash,
                    size_bytes: meta.delta_size_bytes,
                    encoding: meta.delta_encoding,
                }),
        }
    }

    fn of_row(row: &'a database_artifact::Model) -> Self {
        Self {
            key: ArtifactKey {
                service: &row.service,
                space: &row.space,
                name: &row.name,
            },
            revision: row.revision,
            content_hash: &row.content_hash,
            size_bytes: row.size_bytes,
            checkpoint: SqlManifestPart {
                content_hash: &row.checkpoint_content_hash,
                size_bytes: row.checkpoint_size_bytes,
                encoding: row.payload_encoding,
            },
            delta: row
                .delta_content_hash
                .as_deref()
                .map(|content_hash| SqlManifestPart {
                    content_hash,
                    size_bytes: row.delta_size_bytes,
                    encoding: row.delta_encoding,
                }),
        }
    }

    fn identity(&self) -> BlobIdentity<'_> {
        BlobIdentity::SqlManifest {
            service: self.key.service,
            space: self.key.space,
            name: self.key.name,
            revision: self.revision,
            content_hash: self.content_hash,
            size_bytes: self.size_bytes,
            checkpoint: self.checkpoint,
            delta: self.delta,
        }
    }

    /// The tag a sealed write stores with the row.
    fn seal(&self, key: &DataKey) -> Result<Vec<u8>, DatabaseArtifactError> {
        // `seal` refuses only a plaintext past the TCE1 limit; this one is empty.
        at_rest::seal(key, &self.identity(), Vec::new())
            .map_err(|_| DatabaseArtifactError::PayloadTooLarge(0))
    }

    /// Checks the row's stored `tag` against this manifest, before any part
    /// is read. Only mode `off` writes a row without a tag: one with no
    /// sealed part, or a delta written in `off` over a sealed checkpoint (that
    /// legacy delta is as unauthenticated as any legacy part, and `strict`
    /// refuses it). Any other row without a tag fails as integrity.
    async fn verify(
        &self,
        tag: Option<&[u8]>,
        keys: Option<&dyn DataKeyProvider>,
    ) -> Result<(), DatabaseArtifactError> {
        const ROLE: &str = "manifest";
        // An unknown or invalid encoding keeps its own error.
        let checkpoint = PayloadEncoding::from_column(self.checkpoint.encoding)
            .map_err(|error| envelope_error(ArtifactPart::Checkpoint, error))?;
        let delta = self
            .delta
            .map(|delta| {
                PayloadEncoding::from_column(delta.encoding)
                    .map_err(|error| envelope_error(ArtifactPart::Wal, error))
            })
            .transpose()?;
        let Some(tag) = tag else {
            return match (checkpoint, delta) {
                (PayloadEncoding::LegacyPlaintext, None)
                | (_, Some(PayloadEncoding::LegacyPlaintext)) => Ok(()),
                _ => {
                    tracing::error!(
                        role = ROLE,
                        "Database artifact has sealed parts but no manifest tag"
                    );
                    Err(DatabaseArtifactError::AtRestIntegrity { part: ROLE })
                }
            };
        };
        let Some(keys) = keys else {
            tracing::warn!(
                role = ROLE,
                "Sealed database artifact read with no at-rest keys configured"
            );
            return Err(DatabaseArtifactError::AtRestUnavailable);
        };
        let header = Header::parse(tag).map_err(|error| envelope_error_at(ROLE, error))?;
        let data_key = keys
            .key(self.key.space, header.dek_id())
            .await
            .map_err(|error| key_error_at(ROLE, error))?;
        let opened = at_rest::open(&data_key, &self.identity(), tag.to_vec())
            .map_err(|error| envelope_error_at(ROLE, error))?;
        if !opened.is_empty() {
            return Err(envelope_error_at(ROLE, EnvelopeError::Integrity));
        }
        Ok(())
    }
}

/// Room for sealing a part of `len` plaintext bytes in place.
fn sealed_capacity(len: usize) -> Result<usize, DatabaseArtifactError> {
    at_rest::ciphertext_len(len as u64)
        .ok()
        .and_then(|stored| usize::try_from(stored).ok())
        .ok_or(DatabaseArtifactError::PayloadTooLarge(len as u64))
}

/// Seal one part off the async runtime (a checkpoint can be tens of MiB).
/// `plaintext` should already have [`sealed_capacity`], so sealing in place
/// neither reallocates nor copies.
async fn seal_part(
    key: DataKey,
    binding: PartBinding,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, DatabaseArtifactError> {
    let len = plaintext.len() as u64;
    tokio::task::spawn_blocking(move || at_rest::seal(&key, &binding.identity(), plaintext))
        .await
        .map_err(|error| DatabaseArtifactError::Backend(error.to_string()))?
        // `seal` refuses only a plaintext past the TCE1 size limit.
        .map_err(|_| DatabaseArtifactError::PayloadTooLarge(len))
}

/// Turns one part's stored bytes into its plaintext as they stream. Legacy
/// plaintext passes through; a TCE1 part is opened one authenticated 64 KiB
/// segment at a time, so at most one segment is buffered. What it hands on
/// is what the sink receives and the content hash covers.
enum PartDecoder {
    Plain,
    /// Collecting the 64-byte header, which names the data key.
    Header {
        header: Vec<u8>,
        provider: Arc<dyn DataKeyProvider>,
        binding: PartBinding,
        plaintext_len: u64,
    },
    Sealed(Box<SegmentOpener>),
}

impl PartDecoder {
    async fn feed(
        &mut self,
        part: ArtifactPart,
        space: &str,
        mut stored: &[u8],
        hasher: &mut Blake3Hasher,
        sink: &mut dyn ArtifactSink,
    ) -> Result<(), DatabaseArtifactError> {
        if let Self::Header {
            header,
            provider,
            binding,
            plaintext_len,
        } = self
        {
            let take = (HEADER_LEN - header.len()).min(stored.len());
            header.extend_from_slice(&stored[..take]);
            stored = &stored[take..];
            if header.len() < HEADER_LEN {
                return Ok(());
            }
            let parsed = Header::parse(header).map_err(|error| envelope_error(part, error))?;
            // The row's plaintext size is part of the stored length already
            // read; a header that disagrees is refused before any key lookup.
            // The segments authenticate the header either way.
            if parsed.plaintext_len() != *plaintext_len {
                return Err(envelope_error(part, EnvelopeError::Integrity));
            }
            let key = provider
                .key(space, parsed.dek_id())
                .await
                .map_err(|error| read_key_error(part, error))?;
            let opener = SegmentOpener::new(&key, &binding.identity(), &parsed)
                .map_err(|error| envelope_error(part, error))?;
            *self = Self::Sealed(Box::new(opener));
        }
        match self {
            Self::Plain => {
                hasher.update(stored);
                sink.write(stored).await
            }
            Self::Sealed(opener) => {
                while let Some(plain) = opener
                    .push(&mut stored)
                    .map_err(|error| envelope_error(part, error))?
                {
                    // An empty part is one empty segment; like a legacy
                    // empty part, the sink sees no write.
                    if !plain.is_empty() {
                        hasher.update(plain);
                        sink.write(plain).await?;
                    }
                }
                Ok(())
            }
            Self::Header { .. } => Ok(()),
        }
    }

    /// Every stored byte was fed: a sealed part must have opened completely.
    fn finish(&self, part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
        match self {
            Self::Plain => Ok(()),
            Self::Header { .. } => Err(envelope_error(part, EnvelopeError::Integrity)),
            Self::Sealed(opener) => opener.finish().map_err(|error| envelope_error(part, error)),
        }
    }
}

/// The plaintext of one whole stored part, for [`open_row`].
async fn open_whole(
    key: &ArtifactKey<'_>,
    part: ArtifactPart,
    encoding: Option<i16>,
    stored: Vec<u8>,
    binding: PartBinding,
    keys: Option<&dyn DataKeyProvider>,
) -> Result<Vec<u8>, DatabaseArtifactError> {
    match PayloadEncoding::from_column(encoding).map_err(|error| envelope_error(part, error))? {
        PayloadEncoding::LegacyPlaintext => Ok(stored),
        PayloadEncoding::Tce1 => {
            let Some(keys) = keys else {
                return Err(DatabaseArtifactError::AtRestUnavailable);
            };
            let header = Header::parse(&stored).map_err(|error| envelope_error(part, error))?;
            let data_key = keys
                .key(key.space, header.dek_id())
                .await
                .map_err(|error| read_key_error(part, error))?;
            at_rest::open(&data_key, &binding.identity(), stored)
                .map_err(|error| envelope_error(part, error))
        }
    }
}

/// The plaintext checkpoint and WAL of a whole stored row, for the offline
/// tool that inspects designated local snapshots (the node itself only
/// streams). Legacy parts come back as stored. The row's manifest tag is
/// checked first, as on a streamed read; sealed parts need `keys` and are
/// opened and authenticated, or the call fails: ciphertext is never
/// returned as a database file.
pub async fn open_row(
    row: database_artifact::Model,
    keys: Option<&dyn DataKeyProvider>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), DatabaseArtifactError> {
    RowManifest::of_row(&row)
        .verify(row.manifest.as_deref(), keys)
        .await?;
    let key = ArtifactKey {
        service: &row.service,
        space: &row.space,
        name: &row.name,
    };
    let checkpoint = open_whole(
        &key,
        ArtifactPart::Checkpoint,
        row.payload_encoding,
        row.payload,
        PartBinding::checkpoint(
            &key,
            &row.checkpoint_content_hash,
            row.checkpoint_size_bytes,
        ),
        keys,
    )
    .await?;
    let wal = match row.delta_payload {
        Some(delta) => Some(
            open_whole(
                &key,
                ArtifactPart::Wal,
                row.delta_encoding,
                delta,
                PartBinding::wal(
                    &key,
                    row.revision,
                    &row.checkpoint_content_hash,
                    row.delta_content_hash.as_deref().unwrap_or_default(),
                ),
                keys,
            )
            .await?,
        ),
        None => None,
    };
    Ok((checkpoint, wal))
}

impl SeaOrmDatabaseArtifactRepository {
    /// Stream one payload column into `sink`, decode and hash it, and return
    /// the plaintext's CID.
    async fn read_part(
        &self,
        key: &ArtifactKey<'_>,
        meta: &ArtifactMeta,
        part: ArtifactPart,
        view: &AtRestView,
        sink: &mut dyn ArtifactSink,
    ) -> Result<String, DatabaseArtifactError> {
        let (column, size_bytes, expected_hash, encoding) = match part {
            ArtifactPart::Checkpoint => (
                database_artifact::Column::Payload,
                meta.checkpoint_size_bytes,
                meta.checkpoint_content_hash.as_str(),
                meta.payload_encoding,
            ),
            ArtifactPart::Wal => (
                database_artifact::Column::DeltaPayload,
                meta.delta_size_bytes,
                meta.delta_content_hash.as_deref().unwrap_or_default(),
                meta.delta_encoding,
            ),
        };
        let plaintext_len = u64::try_from(size_bytes).unwrap_or(0);
        // Legacy or sealed is the column's answer, decided before any byte.
        let mut decoder = match PayloadEncoding::from_column(encoding)
            .map_err(|error| envelope_error(part, error))?
        {
            PayloadEncoding::LegacyPlaintext if !view.legacy_readable() => {
                tracing::error!(
                    role = part.as_str(),
                    "Legacy plaintext database artifact refused in strict at-rest mode"
                );
                return Err(DatabaseArtifactError::LegacyPlaintextRefused {
                    part: part.as_str(),
                });
            }
            PayloadEncoding::LegacyPlaintext => PartDecoder::Plain,
            PayloadEncoding::Tce1 => {
                let Some(provider) = view.provider.clone() else {
                    tracing::warn!(
                        role = part.as_str(),
                        "Sealed database artifact read with no at-rest keys configured"
                    );
                    return Err(DatabaseArtifactError::AtRestUnavailable);
                };
                PartDecoder::Header {
                    header: Vec::with_capacity(HEADER_LEN),
                    provider,
                    binding: PartBinding::of(key, meta, part),
                    plaintext_len,
                }
            }
        };
        // A sealed part stores exactly `ciphertext_len(size)` bytes. Its last
        // slice asks for one byte more: bytes appended past that length, or
        // a part cut short, fail as integrity.
        let sealed = !matches!(decoder, PartDecoder::Plain);
        let expected_len = if sealed {
            at_rest::ciphertext_len(plaintext_len).map_err(|error| envelope_error(part, error))?
        } else {
            plaintext_len
        };
        // An artifact that fits the base-timeout budget is one slice per part:
        // no extra round trips for the common small database.
        // Gated on the part's own stored size as well, so inconsistent
        // metadata can never ask for a slice past the budget.
        let budget = BASE_TIMEOUT_PAYLOAD_BYTES as u64;
        let slice_bytes = if meta.size_bytes <= budget as i64 && expected_len <= budget {
            expected_len.max(1)
        } else {
            ARTIFACT_CHUNK_BYTES as u64
        };
        let mut hasher = Blake3Hasher::new();
        sink.begin_part(part).await?;
        sink.size_hint(part, plaintext_len);
        let mut offset = 0_u64;
        while offset < expected_len {
            let len = (expected_len - offset).min(slice_bytes);
            let ask = if sealed && offset + len == expected_len {
                len + 1
            } else {
                len
            };
            // `substr` is 1-based and takes int4 on PostgreSQL.
            let start = i32::try_from(offset + 1)
                .map_err(|_| DatabaseArtifactError::PayloadTooLarge(expected_len))?;
            let slice = database_artifact::Entity::find()
                .select_only()
                .expr(
                    Func::cust("substr")
                        .arg(Expr::col(column))
                        .arg(start)
                        .arg(ask as i32),
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
                if sealed {
                    tracing::error!(
                        role = part.as_str(),
                        expected = expected_len,
                        "Sealed database artifact part is not its sealed length"
                    );
                    return Err(DatabaseArtifactError::AtRestIntegrity {
                        part: part.as_str(),
                    });
                }
                return Err(DatabaseArtifactError::SizeMismatch {
                    part: part.as_str(),
                    expected: expected_len,
                    actual: offset + slice.len() as u64,
                });
            }
            decoder
                .feed(part, key.space, &slice, &mut hasher, sink)
                .await?;
            offset += len;
        }
        decoder.finish(part)?;
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
        Ok(database_artifact::Entity::find_by_id((
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
        .column(Column::PayloadEncoding)
        .column(Column::DeltaEncoding)
        .column(Column::Manifest)
        .into_model::<ArtifactMeta>()
        .one(&self.conn)
        .await?)
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
        // One view for both parts: the mode and keys a read sees. The
        // manifest tag is checked before any byte reaches the sink.
        let view = self.at_rest_view();
        RowManifest::of_meta(key, meta)
            .verify(meta.manifest.as_deref(), view.provider.as_deref())
            .await?;
        let checkpoint = self
            .read_part(&key, meta, ArtifactPart::Checkpoint, &view, sink)
            .await?;
        let logical = match &meta.delta_content_hash {
            Some(delta_hash) => {
                self.read_part(&key, meta, ArtifactPart::Wal, &view, sink)
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
        // Before the writer lock: preparing the space's key may write the
        // key store, which takes that lock on SQLite.
        let data_key = self.write_key(space).await?;
        let size_bytes = i64::try_from(payload.len())
            .map_err(|_| DatabaseArtifactError::PayloadTooLarge(payload.len() as u64))?;
        // Hash and size stay those of the plaintext, sealed or not.
        let content_hash = hash(&payload).to_cid(0x55).to_string();
        let (stored, encoding) = match &data_key {
            None => (payload.clone(), PayloadEncoding::LegacyPlaintext),
            Some(data_key) => {
                let mut plaintext = Vec::with_capacity(sealed_capacity(payload.len())?);
                plaintext.extend_from_slice(&payload);
                let binding = PartBinding::checkpoint(
                    &ArtifactKey {
                        service,
                        space,
                        name,
                    },
                    &content_hash,
                    size_bytes,
                );
                (
                    seal_part(data_key.clone(), binding, plaintext).await?,
                    PayloadEncoding::Tce1,
                )
            }
        };
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        // A checkpoint larger than a WAL delta may take longer to upload than
        // the pool's base statement timeout allows, so its write runs under
        // the bulk one (TC-1054). Smaller ones, like every delta, fit the
        // base timeout and pay no extra round trip.
        let scope = if stored.len() > BASE_TIMEOUT_PAYLOAD_BYTES {
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
        // The new row's manifest tag when sealing; mode `off` clears it.
        let manifest = data_key
            .as_ref()
            .map(|data_key| {
                RowManifest {
                    key: ArtifactKey {
                        service,
                        space,
                        name,
                    },
                    revision,
                    content_hash: &content_hash,
                    size_bytes,
                    checkpoint: SqlManifestPart {
                        content_hash: &content_hash,
                        size_bytes,
                        encoding: encoding.to_column(),
                    },
                    delta: None,
                }
                .seal(data_key)
            })
            .transpose()?;

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
                    .col_expr(database_artifact::Column::Payload, Expr::value(stored))
                    .col_expr(
                        database_artifact::Column::PayloadEncoding,
                        Expr::value(encoding.to_column()),
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
                    .col_expr(
                        database_artifact::Column::DeltaEncoding,
                        Expr::value(Option::<i16>::None),
                    )
                    .col_expr(database_artifact::Column::Manifest, Expr::value(manifest))
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
                    payload: Set(stored),
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
                    payload_encoding: Set(encoding.to_column()),
                    delta_encoding: Set(None),
                    manifest: Set(manifest),
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
        // Before the writer lock: preparing the space's key may write the
        // key store, which takes that lock on SQLite.
        let data_key = self.write_key(space).await?;
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
        .column(database_artifact::Column::PayloadEncoding)
        .into_tuple::<(i64, i64, String, Option<i16>)>()
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
        // Hash and size above stay those of the plaintext; the sealed WAL is
        // bound to the revision it is written at and the checkpoint it
        // applies to.
        let (stored, encoding) = match &data_key {
            None => (payload, PayloadEncoding::LegacyPlaintext),
            Some(data_key) => {
                let mut plaintext = payload;
                plaintext.reserve_exact(sealed_capacity(plaintext.len())? - plaintext.len());
                let binding = PartBinding::wal(
                    &ArtifactKey {
                        service,
                        space,
                        name,
                    },
                    revision,
                    &existing.2,
                    &delta_content_hash,
                );
                (
                    seal_part(data_key.clone(), binding, plaintext).await?,
                    PayloadEncoding::Tce1,
                )
            }
        };
        // The row's new manifest tag when sealing; mode `off` clears it. Its
        // checkpoint fields are the columns read above (the update below is
        // pinned to that revision and checkpoint hash); a checkpoint whose
        // stored size or encoding disagrees still fails its own read checks.
        let manifest = data_key
            .as_ref()
            .map(|data_key| {
                RowManifest {
                    key: ArtifactKey {
                        service,
                        space,
                        name,
                    },
                    revision,
                    content_hash: &logical_content_hash,
                    size_bytes,
                    checkpoint: SqlManifestPart {
                        content_hash: &existing.2,
                        size_bytes: existing.1,
                        encoding: existing.3,
                    },
                    delta: Some(SqlManifestPart {
                        content_hash: &delta_content_hash,
                        size_bytes: delta_size_bytes,
                        encoding: encoding.to_column(),
                    }),
                }
                .seal(data_key)
            })
            .transpose()?;
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        let update = database_artifact::Entity::update_many()
            .col_expr(database_artifact::Column::Revision, Expr::value(revision))
            .col_expr(
                database_artifact::Column::ContentHash,
                Expr::value(logical_content_hash.clone()),
            )
            .col_expr(
                database_artifact::Column::DeltaPayload,
                Expr::value(Some(stored)),
            )
            .col_expr(
                database_artifact::Column::DeltaEncoding,
                Expr::value(encoding.to_column()),
            )
            .col_expr(
                database_artifact::Column::DeltaContentHash,
                Expr::value(Some(delta_content_hash.clone())),
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
            .col_expr(database_artifact::Column::Manifest, Expr::value(manifest))
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
            payload_encoding: Set(None),
            delta_encoding: Set(None),
            manifest: Set(None),
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
                payload_encoding: None,
                delta_encoding: None,
                manifest: None,
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
        // The encoding columns are metadata; the payload columns are not.
        assert!(
            seen.iter()
                .all(|sql| !sql.contains("\"payload\"") && !sql.contains("\"delta_payload\"")),
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

    // ---- sealed at rest (TC-887) ----

    use crate::at_rest::{
        ciphertext_len, AtRestMode, DataKeyProvider, FixedKeyProvider, TestAtRestSource,
    };

    const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";
    const WAL_HEADER: &[u8] = &[0x37, 0x7f, 0x06, 0x82, 0, 0x2d, 0xe2, 0x18];
    const MARKER: &[u8] = b"tc887-sql-artifact-marker";

    fn keys() -> Arc<dyn DataKeyProvider> {
        Arc::new(FixedKeyProvider::new([7; 32]))
    }

    /// A database-shaped part: the engine's file header, then filler with a
    /// marker in it.
    fn database_bytes(header: &[u8], len: usize, seed: u8) -> Vec<u8> {
        let mut out = bytes(len, seed);
        out[..header.len()].copy_from_slice(header);
        out[100..100 + MARKER.len()].copy_from_slice(MARKER);
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn cid(bytes: &[u8]) -> String {
        hash(bytes).to_cid(0x55).to_string()
    }

    async fn sqlite_conn() -> DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    fn at_rest_repo(
        conn: &DatabaseConnection,
        mode: AtRestMode,
    ) -> (SeaOrmDatabaseArtifactRepository, Arc<TestAtRestSource>) {
        let source = TestAtRestSource::new(mode, mode != AtRestMode::Off, Some(keys()));
        let repo = SeaOrmDatabaseArtifactRepository::new(conn.clone()).with_at_rest(source.clone());
        (repo, source)
    }

    /// The stored row, payload bytes included.
    async fn stored_row(
        conn: &DatabaseConnection,
        space: &str,
        name: &str,
    ) -> Option<database_artifact::Model> {
        database_artifact::Entity::find_by_id(("sql".to_owned(), space.to_owned(), name.to_owned()))
            .one(conn)
            .await
            .unwrap()
    }

    /// Overwrite the stored parts of `space/name` with `row`'s, the way
    /// someone with write access to the database could.
    async fn put_parts(
        conn: &DatabaseConnection,
        space: &str,
        name: &str,
        row: &database_artifact::Model,
    ) {
        use database_artifact::Column;
        database_artifact::Entity::update_many()
            .col_expr(Column::Payload, Expr::value(row.payload.clone()))
            .col_expr(Column::PayloadEncoding, Expr::value(row.payload_encoding))
            .col_expr(Column::DeltaPayload, Expr::value(row.delta_payload.clone()))
            .col_expr(Column::DeltaEncoding, Expr::value(row.delta_encoding))
            .filter(Column::Service.eq("sql"))
            .filter(Column::Space.eq(space))
            .filter(Column::Name.eq(name))
            .exec(conn)
            .await
            .unwrap();
    }

    /// Reads `space/name` into a cache sink that checks the real file headers,
    /// as hydration does, and publishes it.
    async fn hydrate(
        repo: &SeaOrmDatabaseArtifactRepository,
        space: &str,
        name: &str,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = CacheFileSink::new(
            "sql",
            format!("{space}/{name}"),
            dir.path().join("main.db"),
            dir.path().join("main.db-wal"),
            |head| head.starts_with(SQLITE_HEADER),
            |head| head.starts_with(WAL_HEADER),
        );
        read_artifact(repo, "sql", space, name, &mut sink)
            .await
            .unwrap()
            .expect("the artifact exists");
        sink.commit().await.unwrap();
        (
            std::fs::read(dir.path().join("main.db")).unwrap(),
            std::fs::read(dir.path().join("main.db-wal")).ok(),
        )
    }

    /// A read that must fail; whatever the sink staged is gone afterwards.
    async fn read_error(
        repo: &SeaOrmDatabaseArtifactRepository,
        space: &str,
        name: &str,
    ) -> DatabaseArtifactError {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = cache_sink(dir.path());
        let error = read_artifact(repo, "sql", space, name, &mut sink)
            .await
            .expect_err("must not read");
        drop(sink);
        assert!(
            dir_names(dir.path()).is_empty(),
            "{error:?}: staged bytes left"
        );
        error
    }

    /// Saves a multi-MiB checkpoint and a WAL delta sealed, and checks what
    /// reached the database and what a hydration gets back. The read is
    /// sliced at 4 MiB, which never falls on a 64 KiB segment boundary of
    /// the stored (ciphertext) bytes.
    async fn assert_sealed_round_trip(
        repo: &SeaOrmDatabaseArtifactRepository,
        conn: &DatabaseConnection,
    ) {
        let checkpoint = database_bytes(SQLITE_HEADER, 2 * CHUNK + 70_001, 1);
        let wal = database_bytes(WAL_HEADER, 200_003, 2);
        repo.save(
            "sql",
            "space",
            "main",
            checkpoint.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let saved = repo
            .save_delta(
                "sql",
                "space",
                "main",
                wal.clone(),
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
        assert_eq!(saved.delta_size_bytes, wal.len() as i64);

        let row = stored_row(conn, "space", "main").await.unwrap();
        assert_eq!(
            (row.payload_encoding, row.delta_encoding),
            (Some(1), Some(1))
        );
        let delta = row.delta_payload.as_deref().unwrap();
        for (stored, plain) in [(&row.payload[..], &checkpoint), (delta, &wal)] {
            assert!(stored.starts_with(b"TCE1"));
            assert!(!stored.starts_with(SQLITE_HEADER) && !stored.starts_with(WAL_HEADER));
            assert!(!contains(stored, MARKER), "plaintext reached the database");
            assert_eq!(
                stored.len() as u64,
                ciphertext_len(plain.len() as u64).unwrap()
            );
        }
        // Sizes and hashes stay those of the plaintext: quota, growth checks
        // and lineage read them unchanged.
        assert_eq!(row.checkpoint_size_bytes, checkpoint.len() as i64);
        assert_eq!(row.delta_size_bytes, wal.len() as i64);
        assert_eq!(row.size_bytes, (checkpoint.len() + wal.len()) as i64);
        assert_eq!(row.checkpoint_content_hash, cid(&checkpoint));
        assert_eq!(row.delta_content_hash, Some(cid(&wal)));
        let meta = repo
            .load_meta("sql", "space", "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.size_bytes, (checkpoint.len() + wal.len()) as i64);
        assert_eq!(
            (meta.payload_encoding, meta.delta_encoding),
            (Some(1), Some(1))
        );

        assert_eq!(
            hydrate(repo, "space", "main").await,
            (checkpoint, Some(wal))
        );
    }

    #[tokio::test]
    async fn sealed_parts_hold_no_plaintext_and_hydrate_exactly() {
        let conn = sqlite_conn().await;
        let (repo, source) = at_rest_repo(&conn, AtRestMode::Encrypt);
        assert_sealed_round_trip(&repo, &conn).await;

        // Sealed parts are read whenever the keys exist, in every mode.
        let expected = hydrate(&repo, "space", "main").await;
        for mode in [AtRestMode::Off, AtRestMode::Strict] {
            source.set(mode, false);
            assert_eq!(hydrate(&repo, "space", "main").await, expected, "{mode:?}");
        }

        // An empty database seals and reads back as empty.
        source.set(AtRestMode::Encrypt, true);
        repo.save("sql", "space", "empty", vec![], ArtifactExpectation::Any)
            .await
            .unwrap();
        let row = stored_row(&conn, "space", "empty").await.unwrap();
        assert_eq!(row.payload_encoding, Some(1));
        assert_eq!(row.payload.len() as u64, ciphertext_len(0).unwrap());
        let mut sink = MemorySink::default();
        read_artifact(&repo, "sql", "space", "empty", &mut sink)
            .await
            .unwrap()
            .unwrap();
        assert!(sink.checkpoint.is_empty() && sink.wal.is_none());
    }

    #[tokio::test]
    async fn postgres_sealed_parts_round_trip_and_refuse_a_moved_part() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::migrated_through(
            "postgres_sealed_parts_round_trip_and_refuse_a_moved_part",
            None,
        )
        .await
        else {
            return;
        };
        let (repo, _source) = at_rest_repo(&fixture.conn, AtRestMode::Encrypt);
        assert_sealed_round_trip(&repo, &fixture.conn).await;

        // The same database saved in another space: equal hash and size, but
        // its ciphertext does not open as this space's.
        let checkpoint = database_bytes(SQLITE_HEADER, 2 * CHUNK + 70_001, 1);
        repo.save("sql", "other", "main", checkpoint, ArtifactExpectation::Any)
            .await
            .unwrap();
        let mut moved = stored_row(&fixture.conn, "space", "main").await.unwrap();
        moved.payload = stored_row(&fixture.conn, "other", "main")
            .await
            .unwrap()
            .payload;
        put_parts(&fixture.conn, "space", "main", &moved).await;
        assert!(matches!(
            read_error(&repo, "space", "main").await,
            DatabaseArtifactError::AtRestIntegrity { part: "checkpoint" }
        ));
    }

    #[tokio::test]
    async fn off_writes_plaintext_and_legacy_parts_read_unless_strict() {
        let conn = sqlite_conn().await;
        let (repo, source) = at_rest_repo(&conn, AtRestMode::Off);
        let checkpoint = database_bytes(SQLITE_HEADER, 70_000, 3);
        let wal = database_bytes(WAL_HEADER, 5_000, 4);

        // Mode `off` stores the bytes as given, keys or not.
        repo.save(
            "sql",
            "space",
            "main",
            checkpoint.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let row = stored_row(&conn, "space", "main").await.unwrap();
        assert_eq!(row.payload, checkpoint);
        assert_eq!((row.payload_encoding, row.delta_encoding), (None, None));

        // In `encrypt` a legacy checkpoint still reads, and a new WAL delta
        // on top of it is sealed on its own.
        source.set(AtRestMode::Encrypt, true);
        assert_eq!(
            hydrate(&repo, "space", "main").await,
            (checkpoint.clone(), None)
        );
        repo.save_delta(
            "sql",
            "space",
            "main",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let row = stored_row(&conn, "space", "main").await.unwrap();
        assert_eq!(row.payload, checkpoint);
        assert_eq!((row.payload_encoding, row.delta_encoding), (None, Some(1)));
        assert_eq!(
            hydrate(&repo, "space", "main").await,
            (checkpoint.clone(), Some(wal.clone()))
        );

        // `strict` refuses the legacy checkpoint instead of serving it.
        source.set(AtRestMode::Strict, true);
        assert!(matches!(
            read_error(&repo, "space", "main").await,
            DatabaseArtifactError::LegacyPlaintextRefused { part: "checkpoint" }
        ));
        // A full save seals it, and the delta it replaces goes with it.
        repo.save(
            "sql",
            "space",
            "main",
            checkpoint.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let row = stored_row(&conn, "space", "main").await.unwrap();
        assert_eq!((row.payload_encoding, row.delta_encoding), (Some(1), None));
        assert_eq!(hydrate(&repo, "space", "main").await, (checkpoint, None));

        // Back in `off`, a full save over a sealed row is plaintext again.
        source.set(AtRestMode::Off, false);
        repo.save(
            "sql",
            "space",
            "main",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let row = stored_row(&conn, "space", "main").await.unwrap();
        assert_eq!((row.payload.clone(), row.payload_encoding), (wal, None));
    }

    #[tokio::test]
    async fn without_unlocked_keys_writes_fail_and_change_nothing() {
        let conn = sqlite_conn().await;
        let (repo, source) = at_rest_repo(&conn, AtRestMode::Off);
        let checkpoint = database_bytes(SQLITE_HEADER, 9_000, 5);
        repo.save(
            "sql",
            "space",
            "main",
            checkpoint.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let before = stored_row(&conn, "space", "main").await.unwrap();

        let locked: Arc<dyn DataKeyProvider> = Arc::new(FixedKeyProvider::new([7; 32]).locked());
        for (mode, encrypting, provider) in [
            // The gate is closed: the mode asks for sealing, nothing can seal.
            (AtRestMode::Encrypt, false, Some(keys())),
            (AtRestMode::Strict, false, Some(keys())),
            // No keyring at all.
            (AtRestMode::Encrypt, true, None),
            // The keys are locked.
            (AtRestMode::Encrypt, true, Some(locked.clone())),
        ] {
            source.set(mode, encrypting);
            source.set_provider(provider);
            let case = format!("{mode:?} encrypting={encrypting}");
            assert!(
                matches!(
                    repo.save(
                        "sql",
                        "space",
                        "new",
                        checkpoint.clone(),
                        ArtifactExpectation::Any
                    )
                    .await,
                    Err(DatabaseArtifactError::AtRestUnavailable)
                ),
                "{case}"
            );
            assert!(stored_row(&conn, "space", "new").await.is_none(), "{case}");
            assert!(
                matches!(
                    repo.save(
                        "sql",
                        "space",
                        "main",
                        checkpoint.clone(),
                        ArtifactExpectation::Any
                    )
                    .await,
                    Err(DatabaseArtifactError::AtRestUnavailable)
                ),
                "{case}"
            );
            assert!(
                matches!(
                    repo.save_delta(
                        "sql",
                        "space",
                        "main",
                        vec![1; 64],
                        ArtifactExpectation::Any
                    )
                    .await,
                    Err(DatabaseArtifactError::AtRestUnavailable)
                ),
                "{case}"
            );
            assert_eq!(
                stored_row(&conn, "space", "main").await.unwrap(),
                before,
                "{case}: the row is untouched"
            );
        }

        // A sealed row is not served while its keys are locked or absent.
        source.set(AtRestMode::Encrypt, true);
        source.set_provider(Some(keys()));
        repo.save(
            "sql",
            "space",
            "sealed",
            checkpoint,
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        for provider in [Some(locked), None] {
            source.set_provider(provider);
            assert!(matches!(
                read_error(&repo, "space", "sealed").await,
                DatabaseArtifactError::AtRestUnavailable
            ));
        }
    }

    #[tokio::test]
    async fn tampered_or_moved_sealed_parts_are_integrity_errors() {
        let conn = sqlite_conn().await;
        let (repo, _source) = at_rest_repo(&conn, AtRestMode::Encrypt);
        let checkpoint = database_bytes(SQLITE_HEADER, 3 * 65_536 + 17, 6);
        let wal = database_bytes(WAL_HEADER, 40_000, 7);
        for (space, name) in [("space", "main"), ("other", "main"), ("space", "copy")] {
            repo.save(
                "sql",
                space,
                name,
                checkpoint.clone(),
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
        }
        repo.save_delta(
            "sql",
            "space",
            "main",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let good = stored_row(&conn, "space", "main").await.unwrap();
        let other_space = stored_row(&conn, "other", "main").await.unwrap().payload;
        let other_name = stored_row(&conn, "space", "copy").await.unwrap().payload;

        let tampered = |edit: &dyn Fn(&mut database_artifact::Model)| {
            let mut row = good.clone();
            edit(&mut row);
            row
        };
        let flip = |bytes: &mut Vec<u8>, at: usize| bytes[at] ^= 1;
        type Expect = fn(&DatabaseArtifactError) -> bool;
        let cases: Vec<(&str, database_artifact::Model, Expect)> = vec![
            (
                "checkpoint byte flipped in its second segment",
                tampered(&|row| flip(&mut row.payload, 64 + 65_536 + 16 + 5)),
                |e| {
                    matches!(
                        e,
                        DatabaseArtifactError::AtRestIntegrity { part: "checkpoint" }
                    )
                },
            ),
            (
                "checkpoint header flipped",
                tampered(&|row| flip(&mut row.payload, 30)),
                |e| {
                    matches!(
                        e,
                        DatabaseArtifactError::AtRestIntegrity { part: "checkpoint" }
                    )
                },
            ),
            (
                "wal byte flipped",
                tampered(&|row| flip(row.delta_payload.as_mut().unwrap(), 1_000)),
                |e| matches!(e, DatabaseArtifactError::AtRestIntegrity { part: "wal" }),
            ),
            (
                "checkpoint of the same database in another space",
                tampered(&|row| row.payload = other_space.clone()),
                |e| {
                    matches!(
                        e,
                        DatabaseArtifactError::AtRestIntegrity { part: "checkpoint" }
                    )
                },
            ),
            (
                "checkpoint of the same database under another name",
                tampered(&|row| row.payload = other_name.clone()),
                |e| {
                    matches!(
                        e,
                        DatabaseArtifactError::AtRestIntegrity { part: "checkpoint" }
                    )
                },
            ),
            (
                "a later format generation",
                tampered(&|row| row.payload_encoding = Some(2)),
                |e| {
                    matches!(
                        e,
                        DatabaseArtifactError::AtRestUnsupported {
                            part: "checkpoint",
                            version: 2
                        }
                    )
                },
            ),
            (
                "an invalid encoding",
                tampered(&|row| row.delta_encoding = Some(0)),
                |e| matches!(e, DatabaseArtifactError::AtRestIntegrity { part: "wal" }),
            ),
            (
                // Claiming legacy never turns ciphertext into data: the
                // manifest binds each part's encoding.
                "sealed bytes marked legacy",
                tampered(&|row| row.payload_encoding = None),
                |e| {
                    matches!(
                        e,
                        DatabaseArtifactError::AtRestIntegrity { part: "manifest" }
                    )
                },
            ),
        ];
        for (what, row, expected) in cases {
            put_parts(&conn, "space", "main", &row).await;
            let error = read_error(&repo, "space", "main").await;
            assert!(expected(&error), "{what}: {error:?}");
        }
        put_parts(&conn, "space", "main", &good).await;
        assert_eq!(
            hydrate(&repo, "space", "main").await,
            (checkpoint, Some(wal.clone()))
        );

        // The same WAL saved again at the next revision: the older revision's
        // ciphertext does not open in its place.
        repo.save_delta("sql", "space", "main", wal, ArtifactExpectation::Any)
            .await
            .unwrap();
        let mut replayed = stored_row(&conn, "space", "main").await.unwrap();
        assert_eq!(replayed.revision, good.revision + 1);
        replayed.delta_payload = good.delta_payload.clone();
        put_parts(&conn, "space", "main", &replayed).await;
        let error = read_error(&repo, "space", "main").await;
        assert!(
            matches!(
                error,
                DatabaseArtifactError::AtRestIntegrity { part: "wal" }
            ),
            "{error:?}"
        );
    }

    /// Sets `edit`'s columns on `space/name` directly, the way someone with
    /// write access to the database could.
    async fn rewrite_row(
        conn: &DatabaseConnection,
        space: &str,
        name: &str,
        edit: impl FnOnce(
            sea_orm::UpdateMany<database_artifact::Entity>,
        ) -> sea_orm::UpdateMany<database_artifact::Entity>,
    ) {
        use database_artifact::Column;
        let update = edit(database_artifact::Entity::update_many())
            .filter(Column::Service.eq("sql"))
            .filter(Column::Space.eq(space))
            .filter(Column::Name.eq(name))
            .exec(conn)
            .await
            .unwrap();
        assert_eq!(update.rows_affected, 1);
    }

    /// The WAL delta of a sealed row is dropped in the database: delta
    /// columns cleared, the unkeyed logical hash and size reset to the
    /// checkpoint's, revision kept. A cold read must fail as integrity, never
    /// hand back the checkpoint alone (which would silently lose the rows the
    /// delta committed).
    #[tokio::test]
    async fn a_dropped_wal_delta_fails_integrity_instead_of_a_partial_read() {
        for mode in [AtRestMode::Encrypt, AtRestMode::Strict] {
            let conn = sqlite_conn().await;
            let (repo, _source) = at_rest_repo(&conn, mode);
            let checkpoint = database_bytes(SQLITE_HEADER, 70_000, 21);
            let wal = database_bytes(WAL_HEADER, 9_000, 22);
            repo.save(
                "sql",
                "space",
                "main",
                checkpoint.clone(),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
            repo.save_delta("sql", "space", "main", wal, ArtifactExpectation::Any)
                .await
                .unwrap();
            let row = stored_row(&conn, "space", "main").await.unwrap();
            assert_eq!(row.revision, 2);
            rewrite_row(&conn, "space", "main", |update| {
                use database_artifact::Column;
                update
                    .col_expr(Column::DeltaPayload, Expr::value(Option::<Vec<u8>>::None))
                    .col_expr(Column::DeltaEncoding, Expr::value(Option::<i16>::None))
                    .col_expr(
                        Column::DeltaContentHash,
                        Expr::value(Option::<String>::None),
                    )
                    .col_expr(Column::DeltaSizeBytes, Expr::value(0_i64))
                    .col_expr(Column::ContentHash, Expr::value(cid(&checkpoint)))
                    .col_expr(Column::SizeBytes, Expr::value(checkpoint.len() as i64))
                    .col_expr(Column::StorageMode, Expr::value("database-blob"))
            })
            .await;
            // A cold read: a repository that never saw the row.
            let (cold, _source) = at_rest_repo(&conn, mode);
            let error = read_error(&cold, "space", "main").await;
            assert!(
                matches!(
                    error,
                    DatabaseArtifactError::AtRestIntegrity { part: "manifest" }
                ),
                "{mode:?}: {error:?}"
            );
            // Clearing the manifest tag as well makes it a row with a sealed
            // part and no tag, which only a tampered row is.
            rewrite_row(&conn, "space", "main", |update| {
                update.col_expr(
                    database_artifact::Column::Manifest,
                    Expr::value(Option::<Vec<u8>>::None),
                )
            })
            .await;
            let error = read_error(&cold, "space", "main").await;
            assert!(
                matches!(
                    error,
                    DatabaseArtifactError::AtRestIntegrity { part: "manifest" }
                ),
                "{mode:?}, no tag: {error:?}"
            );
            // The offline whole-row read refuses it too.
            let row = stored_row(&conn, "space", "main").await.unwrap();
            assert!(matches!(
                open_row(row, Some(keys().as_ref())).await,
                Err(DatabaseArtifactError::AtRestIntegrity { part: "manifest" })
            ));
        }
    }

    /// Parts and revisions from another point of the row's history do not
    /// read in place of the current ones.
    #[tokio::test]
    async fn a_part_or_revision_from_another_revision_fails_integrity() {
        let conn = sqlite_conn().await;
        let (repo, _source) = at_rest_repo(&conn, AtRestMode::Encrypt);
        let first = database_bytes(SQLITE_HEADER, 70_000, 31);
        let second = database_bytes(SQLITE_HEADER, 80_000, 32);
        repo.save(
            "sql",
            "space",
            "main",
            first.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let old = stored_row(&conn, "space", "main").await.unwrap();
        repo.save_delta(
            "sql",
            "space",
            "main",
            database_bytes(WAL_HEADER, 4_000, 33),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        repo.save(
            "sql",
            "space",
            "main",
            second.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let current = stored_row(&conn, "space", "main").await.unwrap();
        assert_eq!((old.revision, current.revision), (1, 3));

        // Revision 1's checkpoint and its metadata, at revision 3.
        rewrite_row(&conn, "space", "main", |update| {
            use database_artifact::Column;
            update
                .col_expr(Column::Payload, Expr::value(old.payload.clone()))
                .col_expr(Column::ContentHash, Expr::value(old.content_hash.clone()))
                .col_expr(
                    Column::CheckpointContentHash,
                    Expr::value(old.checkpoint_content_hash.clone()),
                )
                .col_expr(Column::SizeBytes, Expr::value(old.size_bytes))
                .col_expr(
                    Column::CheckpointSizeBytes,
                    Expr::value(old.checkpoint_size_bytes),
                )
        })
        .await;
        let error = read_error(&repo, "space", "main").await;
        assert!(
            matches!(
                error,
                DatabaseArtifactError::AtRestIntegrity { part: "manifest" }
            ),
            "older checkpoint: {error:?}"
        );

        // The current parts under another revision number.
        put_parts(&conn, "space", "main", &current).await;
        rewrite_row(&conn, "space", "main", |update| {
            use database_artifact::Column;
            update
                .col_expr(
                    Column::ContentHash,
                    Expr::value(current.content_hash.clone()),
                )
                .col_expr(
                    Column::CheckpointContentHash,
                    Expr::value(current.checkpoint_content_hash.clone()),
                )
                .col_expr(Column::SizeBytes, Expr::value(current.size_bytes))
                .col_expr(
                    Column::CheckpointSizeBytes,
                    Expr::value(current.checkpoint_size_bytes),
                )
                .col_expr(Column::Revision, Expr::value(7_i64))
        })
        .await;
        let error = read_error(&repo, "space", "main").await;
        assert!(
            matches!(
                error,
                DatabaseArtifactError::AtRestIntegrity { part: "manifest" }
            ),
            "another revision: {error:?}"
        );
        rewrite_row(&conn, "space", "main", |update| {
            update.col_expr(database_artifact::Column::Revision, Expr::value(3_i64))
        })
        .await;
        assert_eq!(hydrate(&repo, "space", "main").await, (second, None));
    }

    /// Rows written in mode `off`, and legacy rows from before encryption,
    /// carry nothing sealed and still read: legacy parts in `off` and
    /// `encrypt`, a legacy checkpoint under a sealed delta, and a sealed
    /// checkpoint under a delta written in `off`.
    #[tokio::test]
    async fn legacy_and_off_rows_still_read() {
        let conn = sqlite_conn().await;
        let (repo, source) = at_rest_repo(&conn, AtRestMode::Off);
        let checkpoint = database_bytes(SQLITE_HEADER, 70_000, 41);
        let wal = database_bytes(WAL_HEADER, 6_000, 42);
        repo.save(
            "sql",
            "space",
            "legacy",
            checkpoint.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        repo.save_delta(
            "sql",
            "space",
            "legacy",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let both = (checkpoint.clone(), Some(wal.clone()));
        for (mode, encrypting) in [(AtRestMode::Off, false), (AtRestMode::Encrypt, true)] {
            source.set(mode, encrypting);
            assert_eq!(hydrate(&repo, "space", "legacy").await, both, "{mode:?}");
        }

        // A legacy checkpoint, then a delta sealed in `encrypt`.
        source.set(AtRestMode::Off, false);
        repo.save(
            "sql",
            "space",
            "mixed",
            checkpoint.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        source.set(AtRestMode::Encrypt, true);
        repo.save_delta(
            "sql",
            "space",
            "mixed",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        assert_eq!(hydrate(&repo, "space", "mixed").await, both);
        source.set(AtRestMode::Off, false);
        assert_eq!(hydrate(&repo, "space", "mixed").await, both);

        // A sealed checkpoint, then a delta written in `off`.
        source.set(AtRestMode::Encrypt, true);
        repo.save(
            "sql",
            "space",
            "back",
            checkpoint.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        source.set(AtRestMode::Off, false);
        repo.save_delta(
            "sql",
            "space",
            "back",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let row = stored_row(&conn, "space", "back").await.unwrap();
        assert_eq!((row.payload_encoding, row.delta_encoding), (Some(1), None));
        for (mode, encrypting) in [(AtRestMode::Off, false), (AtRestMode::Encrypt, true)] {
            source.set(mode, encrypting);
            assert_eq!(hydrate(&repo, "space", "back").await, both, "{mode:?}");
        }
    }

    /// A sealed part stores exactly `ciphertext_len(size)` bytes: bytes
    /// appended to it, or a part cut short, are integrity failures.
    #[tokio::test]
    async fn a_sealed_part_of_the_wrong_stored_length_fails_integrity() {
        let conn = sqlite_conn().await;
        let (repo, _source) = at_rest_repo(&conn, AtRestMode::Encrypt);
        let checkpoint = database_bytes(SQLITE_HEADER, 70_000, 51);
        let wal = database_bytes(WAL_HEADER, 5_000, 52);
        repo.save(
            "sql",
            "space",
            "main",
            checkpoint.clone(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        repo.save_delta(
            "sql",
            "space",
            "main",
            wal.clone(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let good = stored_row(&conn, "space", "main").await.unwrap();
        type Edit = fn(&mut database_artifact::Model);
        let edits: [(&str, &str, Edit); 3] = [
            ("bytes appended to the checkpoint", "checkpoint", |row| {
                row.payload.extend_from_slice(&[0x5a; 37])
            }),
            ("bytes appended to the wal", "wal", |row| {
                row.delta_payload.as_mut().unwrap().push(0)
            }),
            ("checkpoint cut short", "checkpoint", |row| {
                row.payload.pop();
            }),
        ];
        for (what, part, edit) in edits {
            let mut row = good.clone();
            edit(&mut row);
            put_parts(&conn, "space", "main", &row).await;
            let error = read_error(&repo, "space", "main").await;
            assert!(
                matches!(&error, DatabaseArtifactError::AtRestIntegrity { part: p } if *p == part),
                "{what}: {error:?}"
            );
            let error = open_row(row, Some(keys().as_ref())).await.unwrap_err();
            assert!(
                matches!(&error, DatabaseArtifactError::AtRestIntegrity { part: p } if *p == part),
                "{what}, whole row: {error:?}"
            );
        }
        put_parts(&conn, "space", "main", &good).await;
        assert_eq!(
            hydrate(&repo, "space", "main").await,
            (checkpoint, Some(wal))
        );
    }
}
