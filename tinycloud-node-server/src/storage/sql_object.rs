//! Object stores for the private SQL namespace `sql/v1/` (TC-1491 contract,
//! sections 3, 6 and 11.8).
//!
//! Both backends implement [`SqlObjectStore`] and share one rule: an object is
//! created at most once and never replaced. A key names its content (it ends
//! in the SHA-256 of the bytes), so a second creator of the same key either
//! stores identical bytes (`AlreadyPresent`) or finds different ones
//! (`Conflict`); nothing is ever overwritten.
//!
//! * [`S3SqlObjectStore`] writes into the block store's bucket, key as is,
//!   with a conditional create (`If-None-Match: *`). [`S3SqlObjectStore::probe`]
//!   checks at startup whether the provider honours the header and selects
//!   the write mode; without it the store checks, then creates.
//! * [`FsSqlObjectStore`] writes below `{datadir}/sql-store`: the body goes to
//!   a temporary file in the target directory, is fsynced, and is published
//!   with a hard link, which fails instead of replacing an existing file.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    future::Future,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use aws_sdk_s3::{
    error::{ProvideErrorMetadata, SdkError},
    operation::{
        get_object::GetObjectError, head_object::HeadObjectError, put_object::PutObjectError,
    },
    primitives::ByteStream,
    Client,
};
use sha2::{Digest, Sha256};
use tinycloud_core::{
    sql::store::{
        key::KEY_ROOT, object::sha256, ObjectKey, ObjectMeta, ObjectRange, PutOutcome,
        SqlObjectStore, SqlStoreError,
    },
    storage::ByteRangeSpec,
};

use super::s3::{new_client, S3BlockConfig};

/// Tracing target of everything the SQL store logs.
const LOG_TARGET: &str = "tinycloud::sql_store";

/// How `put_if_absent` creates an object on S3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// One conditional PUT (`If-None-Match: *`); the provider refuses to
    /// replace an existing object.
    Conditional,
    /// HEAD, then an unconditional PUT when the object is absent.
    CheckThenWrite,
}

impl WriteMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conditional => "conditional",
            Self::CheckThenWrite => "check_then_write",
        }
    }
}

// ---------------------------------------------------------------------------
// S3
// ---------------------------------------------------------------------------

/// Key of the object the startup probe writes. It is never deleted.
const PROBE_KEY: &str = "sql/v1/_probe/v1";
const PROBE_BODY: &[u8] = b"tinycloud sql store probe v1";
/// A conditional PUT that loses a race with an in-flight conditional PUT of
/// the same key may be answered 409; it is retried.
const CONFLICT_RETRIES: u32 = 5;

pub struct S3SqlObjectStore {
    client: Client,
    bucket: String,
    mode: WriteMode,
    /// Per-key gates that serialise check-then-create inside this process.
    gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// What one PUT of the probe or of an object came back as.
enum PutResult {
    Created,
    /// 412: the object exists, the condition was honoured.
    PreconditionFailed,
    /// 409 ConditionalRequestConflict: another conditional write of the key
    /// is in flight.
    InFlight,
    /// The provider does not implement the header (501, 400, NotImplemented).
    Unsupported,
    Failed(SqlStoreError),
}

fn status<E>(error: &SdkError<E>) -> Option<u16> {
    error.raw_response().map(|r| r.status().as_u16())
}

fn backend<E: ProvideErrorMetadata>(op: &str, error: &SdkError<E>) -> SqlStoreError {
    // Status and error code only: the message and URL can carry the key.
    let status = status(error).map_or_else(|| "none".to_owned(), |s| s.to_string());
    let code = ProvideErrorMetadata::code(error).unwrap_or("none");
    SqlStoreError::Backend(format!("s3 {op} failed (status {status}, code {code})"))
}

fn classify_put<T>(result: Result<T, SdkError<PutObjectError>>) -> PutResult {
    let error = match result {
        Ok(_) => return PutResult::Created,
        Err(error) => error,
    };
    let code = ProvideErrorMetadata::code(&error).map(str::to_owned);
    match (status(&error), code.as_deref()) {
        (Some(412), _) | (_, Some("PreconditionFailed")) => PutResult::PreconditionFailed,
        (Some(409), Some("ConditionalRequestConflict")) => PutResult::InFlight,
        (Some(501 | 400), _) | (_, Some("NotImplemented")) => PutResult::Unsupported,
        _ => PutResult::Failed(backend("put", &error)),
    }
}

async fn put_object(
    client: &Client,
    bucket: &str,
    key: &str,
    body: Vec<u8>,
    conditional: bool,
) -> PutResult {
    let sha = hex::encode(sha256(&body));
    let request = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .metadata("sha256", sha)
        .body(ByteStream::from(body));
    let request = if conditional {
        request.if_none_match("*")
    } else {
        request
    };
    classify_put(request.send().await)
}

/// Decide the write mode from the answers to two conditional PUTs of one key.
/// The second answering 412 means the provider honours the condition; the
/// second succeeding, or either answering that the header is unsupported,
/// means it does not. A first 412 (the probe object exists from an earlier
/// start) already shows the condition is honoured.
async fn probe_with<F, Fut>(mut put: F) -> Result<WriteMode, SqlStoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = PutResult>,
{
    for attempt in 0..2 {
        match put().await {
            PutResult::PreconditionFailed | PutResult::InFlight => {
                return Ok(WriteMode::Conditional)
            }
            PutResult::Unsupported => return Ok(WriteMode::CheckThenWrite),
            PutResult::Created if attempt == 1 => return Ok(WriteMode::CheckThenWrite),
            PutResult::Created => {}
            PutResult::Failed(error) => return Err(error),
        }
    }
    unreachable!("the second probe request always returns")
}

/// An existing object is the one being created when length and SHA-256 agree.
fn same_object(meta: &ObjectMeta, key: &ObjectKey, len: u64) -> Result<PutOutcome, SqlStoreError> {
    if meta.bytes == len && &meta.sha256 == key.sha256() {
        Ok(PutOutcome::AlreadyPresent)
    } else {
        Err(SqlStoreError::Conflict)
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32], SqlStoreError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| SqlStoreError::Backend("s3 object has an invalid sha256 metadata".into()))
}

/// `bytes first-last/total`.
fn parse_content_range(value: &str) -> Result<(u64, u64, u64), SqlStoreError> {
    let bad = || SqlStoreError::Backend("s3 returned an invalid content range".into());
    let rest = value.strip_prefix("bytes ").ok_or_else(bad)?;
    let (bounds, total) = rest.split_once('/').ok_or_else(bad)?;
    let (first, last) = bounds.split_once('-').ok_or_else(bad)?;
    let first: u64 = first.parse().map_err(|_| bad())?;
    let last: u64 = last.parse().map_err(|_| bad())?;
    let total: u64 = total.parse().map_err(|_| bad())?;
    if first > last || last >= total {
        return Err(bad());
    }
    Ok((first, last, total))
}

impl S3SqlObjectStore {
    /// A store over the block store's bucket and client settings, with the
    /// write mode chosen by [`Self::probe`].
    pub async fn open(config: &S3BlockConfig) -> Result<Self, SqlStoreError> {
        let client = new_client(config).await;
        let mode = Self::probe(&client, &config.bucket).await?;
        Ok(Self::new(client, config.bucket.clone(), mode))
    }

    /// A store with the given write mode and no probe request.
    pub async fn open_with_mode(config: &S3BlockConfig, mode: WriteMode) -> Self {
        Self::new(new_client(config).await, config.bucket.clone(), mode)
    }

    pub fn new(client: Client, bucket: String, mode: WriteMode) -> Self {
        Self {
            client,
            bucket,
            mode,
            gates: Mutex::default(),
        }
    }

    pub fn mode(&self) -> WriteMode {
        self.mode
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Write a fixed small body to `sql/v1/_probe/v1` with `If-None-Match: *`
    /// twice. A 412 on the second request means the provider honours
    /// conditional writes; a second success, or a provider that answers 501,
    /// 400 or NotImplemented for the header, selects the check-then-create
    /// mode. Any other failure is an error, not a fallback. The object stays.
    pub async fn probe(client: &Client, bucket: &str) -> Result<WriteMode, SqlStoreError> {
        let mode =
            probe_with(|| put_object(client, bucket, PROBE_KEY, PROBE_BODY.to_vec(), true)).await?;
        tracing::info!(target: LOG_TARGET, mode = mode.as_str(), "sql object store write mode");
        Ok(mode)
    }

    async fn existing_matches(
        &self,
        key: &ObjectKey,
        len: u64,
    ) -> Result<PutOutcome, SqlStoreError> {
        match self.head(key).await? {
            Some(meta) => same_object(&meta, key, len),
            None => Err(SqlStoreError::Backend(
                "s3 object is missing after the create was refused".into(),
            )),
        }
    }

    async fn create_conditionally(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError> {
        let len = body.len() as u64;
        for attempt in 0..=CONFLICT_RETRIES {
            match put_object(&self.client, &self.bucket, key.as_str(), body.clone(), true).await {
                PutResult::Created => return Ok(PutOutcome::Created),
                PutResult::PreconditionFailed => return self.existing_matches(key, len).await,
                PutResult::InFlight => {
                    tokio::time::sleep(Duration::from_millis(100 * (u64::from(attempt) + 1))).await
                }
                PutResult::Unsupported => {
                    return Err(SqlStoreError::Backend(
                        "s3 provider refused the conditional create".into(),
                    ))
                }
                PutResult::Failed(error) => return Err(error),
            }
        }
        Err(SqlStoreError::Backend(
            "s3 conditional create stayed in conflict".into(),
        ))
    }

    async fn check_then_create(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError> {
        let gate = self
            .gates
            .lock()
            .unwrap()
            .entry(key.as_str().to_owned())
            .or_default()
            .clone();
        let outcome = async {
            let _held = gate.lock().await;
            let len = body.len() as u64;
            match self.head(key).await? {
                Some(meta) => same_object(&meta, key, len),
                None => {
                    match put_object(&self.client, &self.bucket, key.as_str(), body, false).await {
                        PutResult::Created => Ok(PutOutcome::Created),
                        PutResult::Failed(error) => Err(error),
                        _ => Err(SqlStoreError::Backend("s3 put was refused".into())),
                    }
                }
            }
        }
        .await;
        let mut gates = self.gates.lock().unwrap();
        // The map holds one reference and this call one; any other is a waiter.
        if Arc::strong_count(&gate) == 2 {
            gates.remove(key.as_str());
        }
        outcome
    }
}

#[async_trait]
impl SqlObjectStore for S3SqlObjectStore {
    async fn put_if_absent(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError> {
        if &sha256(&body) != key.sha256() {
            return Err(SqlStoreError::BodyMismatch);
        }
        match self.mode {
            WriteMode::Conditional => self.create_conditionally(key, body).await,
            WriteMode::CheckThenWrite => self.check_then_create(key, body).await,
        }
    }

    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<ObjectRange>, SqlStoreError> {
        // Shapes that select nothing in any object need no request.
        match range {
            ByteRangeSpec::Inclusive { start, end } if start > end => return Ok(None),
            ByteRangeSpec::Suffix { length: 0 } => return Ok(None),
            _ => {}
        }
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .range(range.to_http_value())
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                if matches!(error.as_service_error(), Some(GetObjectError::NoSuchKey(_)))
                    || status(&error) == Some(416)
                    || ProvideErrorMetadata::code(&error) == Some("InvalidRange")
                {
                    return Ok(None);
                }
                return Err(backend("get", &error));
            }
        };
        let content_range = output.content_range().map(str::to_owned);
        let data = output
            .body
            .collect()
            .await
            .map_err(|_| SqlStoreError::Backend("s3 get body failed".into()))?
            .into_bytes()
            .to_vec();
        match content_range {
            Some(value) => {
                let (first, last, total) = parse_content_range(&value)?;
                if data.len() as u64 != last - first + 1 {
                    return Err(SqlStoreError::Backend(
                        "s3 get body does not match its range".into(),
                    ));
                }
                Ok(Some(ObjectRange {
                    total_size: total,
                    start: first,
                    data,
                }))
            }
            // A provider that ignored the header sent the whole object.
            None => {
                let total = data.len() as u64;
                Ok(range.resolve(total).map(|r| ObjectRange {
                    total_size: total,
                    start: r.start(),
                    data: data[r.start() as usize..=r.end() as usize].to_vec(),
                }))
            }
        }
    }

    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
        let output = match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                if matches!(error.as_service_error(), Some(HeadObjectError::NotFound(_))) {
                    return Ok(None);
                }
                return Err(backend("head", &error));
            }
        };
        let bytes = u64::try_from(output.content_length().unwrap_or_default())
            .map_err(|_| SqlStoreError::Backend("s3 object has a negative length".into()))?;
        let sha = output
            .metadata()
            .and_then(|metadata| metadata.get("sha256"))
            .ok_or_else(|| SqlStoreError::Backend("s3 object has no sha256 metadata".into()))?;
        Ok(Some(ObjectMeta {
            bytes,
            sha256: parse_sha256(sha)?,
        }))
    }
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

/// Chunk size for hashing an existing file.
const HASH_CHUNK: usize = 1 << 20;
/// Prefix of the temporary files a create writes next to its target. No key
/// component can start with it (a `.` in a key is always followed by two hex
/// digits).
const TEMP_PREFIX: &str = ".tmp-";

pub struct FsSqlObjectStore {
    root: PathBuf,
}

/// Refuse a SQL store root the node must not use: one that is not absolute,
/// or that is equal to, inside, or a parent of the KV block-store root. Both
/// paths are compared as written (they must be absolute and free of `.` and
/// `..`); nothing is read from the filesystem.
pub fn check_fs_root(root: &Path, blocks_root: &Path) -> Result<(), SqlStoreError> {
    if cfg!(windows) {
        return Err(SqlStoreError::Invalid(
            "the filesystem SQL store is not supported on this platform",
        ));
    }
    for path in [root, blocks_root] {
        if !path.is_absolute() {
            return Err(SqlStoreError::Invalid(
                "the SQL store root and the block store root must be absolute paths",
            ));
        }
        if path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        {
            return Err(SqlStoreError::Invalid(
                "the SQL store root and the block store root must not contain . or .. components",
            ));
        }
    }
    if root == blocks_root {
        return Err(SqlStoreError::Invalid(
            "the SQL store root must differ from the block store root",
        ));
    }
    if root.starts_with(blocks_root) {
        return Err(SqlStoreError::Invalid(
            "the SQL store root must not be inside the block store root",
        ));
    }
    if blocks_root.starts_with(root) {
        return Err(SqlStoreError::Invalid(
            "the SQL store root must not contain the block store root",
        ));
    }
    Ok(())
}

fn io_error(op: &str, error: &std::io::Error) -> SqlStoreError {
    // The kind only: a path would put keys in logs.
    SqlStoreError::Backend(format!("filesystem {op} failed ({:?})", error.kind()))
}

/// The file of `key` below `root`. Each component must be an ordinary file
/// name and the result must stay under `root`.
fn resolve_path(root: &Path, key: &str) -> Result<PathBuf, SqlStoreError> {
    let invalid = || SqlStoreError::Invalid("key is not a valid store path");
    if !key.starts_with(KEY_ROOT) {
        return Err(invalid());
    }
    let mut path = root.to_path_buf();
    for part in key.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.starts_with(TEMP_PREFIX)
            || part.contains(['\\', '\0'])
        {
            return Err(invalid());
        }
        path.push(part);
    }
    if path == root || !path.starts_with(root) {
        return Err(invalid());
    }
    Ok(path)
}

fn sync_dir(dir: &Path) -> Result<(), SqlStoreError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_error("directory sync", &e))
}

/// Create the directories from `root` down to `dir`, fsyncing each new one
/// and its parent.
fn create_dirs(root: &Path, dir: &Path) -> Result<(), SqlStoreError> {
    let relative = dir
        .strip_prefix(root)
        .map_err(|_| SqlStoreError::Invalid("key is not a valid store path"))?;
    let mut current = root.to_path_buf();
    for part in relative.components() {
        let parent = current.clone();
        current.push(part);
        match std::fs::create_dir(&current) {
            Ok(()) => {
                sync_dir(&current)?;
                sync_dir(&parent)?;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_error("create directory", &e)),
        }
    }
    Ok(())
}

/// Removes its file on drop, in every outcome of a create.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn hash_file(file: &mut File) -> Result<[u8; 32], SqlStoreError> {
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; HASH_CHUNK];
    loop {
        let n = file.read(&mut chunk).map_err(|e| io_error("read", &e))?;
        if n == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&chunk[..n]);
    }
}

fn fs_head(path: &Path) -> Result<Option<ObjectMeta>, SqlStoreError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("open", &e)),
    };
    let metadata = file.metadata().map_err(|e| io_error("stat", &e))?;
    if !metadata.is_file() {
        return Err(SqlStoreError::Backend(
            "filesystem entry is not a file".into(),
        ));
    }
    Ok(Some(ObjectMeta {
        bytes: metadata.len(),
        sha256: hash_file(&mut file)?,
    }))
}

fn fs_put(
    path: &Path,
    root: &Path,
    sha: &[u8; 32],
    body: &[u8],
) -> Result<PutOutcome, SqlStoreError> {
    let dir = path
        .parent()
        .ok_or(SqlStoreError::Invalid("key is not a valid store path"))?;
    create_dirs(root, dir)?;
    let temp = TempFile(dir.join(format!(
        "{TEMP_PREFIX}{}",
        hex::encode(rand::random::<[u8; 16]>())
    )));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp.0)
            .map_err(|e| io_error("create temp file", &e))?;
        file.write_all(body)
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error("write temp file", &e))?;
    }
    let outcome = match std::fs::hard_link(&temp.0, path) {
        Ok(()) => Ok(PutOutcome::Created),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => match fs_head(path)? {
            Some(meta) if meta.bytes == body.len() as u64 && &meta.sha256 == sha => {
                Ok(PutOutcome::AlreadyPresent)
            }
            Some(_) => Err(SqlStoreError::Conflict),
            None => Err(SqlStoreError::Backend(
                "filesystem object is missing after the link was refused".into(),
            )),
        },
        Err(e) => Err(io_error("link", &e)),
    };
    let synced = sync_dir(dir);
    // The temporary file is removed when `temp` drops, after the sync.
    match outcome {
        Ok(outcome) => synced.map(|()| outcome),
        Err(error) => Err(error),
    }
}

fn fs_get_range(path: &Path, range: ByteRangeSpec) -> Result<Option<ObjectRange>, SqlStoreError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("open", &e)),
    };
    let metadata = file.metadata().map_err(|e| io_error("stat", &e))?;
    if !metadata.is_file() {
        return Err(SqlStoreError::Backend(
            "filesystem entry is not a file".into(),
        ));
    }
    let total = metadata.len();
    let Some(resolved) = range.resolve(total) else {
        return Ok(None);
    };
    let len = usize::try_from(resolved.end() - resolved.start() + 1)
        .map_err(|_| SqlStoreError::Invalid("range does not fit in memory"))?;
    let mut data = vec![0u8; len];
    file.seek(SeekFrom::Start(resolved.start()))
        .and_then(|_| file.read_exact(&mut data))
        .map_err(|e| io_error("read", &e))?;
    Ok(Some(ObjectRange {
        total_size: total,
        start: resolved.start(),
        data,
    }))
}

async fn blocking<T, F>(work: F) -> Result<T, SqlStoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, SqlStoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| SqlStoreError::Backend("filesystem task failed".into()))?
}

impl FsSqlObjectStore {
    /// Open the store at `root` (`{datadir}/sql-store`), creating it if
    /// needed, after [`check_fs_root`] against the KV block-store root.
    pub fn open(root: PathBuf, blocks_root: &Path) -> Result<Self, SqlStoreError> {
        check_fs_root(&root, blocks_root)?;
        std::fs::create_dir_all(&root).map_err(|e| io_error("create root", &e))?;
        sync_dir(&root)?;
        if let Some(parent) = root.parent() {
            sync_dir(parent)?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The file an object is stored in.
    pub fn path_for(&self, key: &ObjectKey) -> Result<PathBuf, SqlStoreError> {
        resolve_path(&self.root, key.as_str())
    }
}

#[async_trait]
impl SqlObjectStore for FsSqlObjectStore {
    async fn put_if_absent(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError> {
        if &sha256(&body) != key.sha256() {
            return Err(SqlStoreError::BodyMismatch);
        }
        let path = self.path_for(key)?;
        let root = self.root.clone();
        let sha = *key.sha256();
        blocking(move || fs_put(&path, &root, &sha, &body)).await
    }

    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<ObjectRange>, SqlStoreError> {
        let path = self.path_for(key)?;
        blocking(move || fs_get_range(&path, range)).await
    }

    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
        let path = self.path_for(key)?;
        blocking(move || fs_head(&path)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(not(windows))]
    #[test]
    fn fs_root_must_be_absolute_and_outside_the_block_store() {
        let blocks = Path::new("/data/blocks");
        for ok in [
            "/data/sql-store",
            "/data/blocks2",
            "/sql-store",
            "/data/sql/store",
        ] {
            assert!(check_fs_root(Path::new(ok), blocks).is_ok(), "{ok}");
        }
        for bad in [
            "/data/blocks",
            "/data/blocks/",
            "/data/blocks/sql-store",
            "/data",
            "/",
            "sql-store",
            "./sql-store",
            "/data/../data/sql-store",
        ] {
            assert!(check_fs_root(Path::new(bad), blocks).is_err(), "{bad}");
        }
        // The block store root is checked the same way.
        assert!(check_fs_root(Path::new("/data/sql-store"), Path::new("blocks")).is_err());
        assert!(check_fs_root(
            Path::new("/data/sql-store"),
            Path::new("/data/../data/blocks")
        )
        .is_err());
    }

    #[test]
    fn resolved_paths_stay_under_the_root() {
        let root = Path::new("/var/tmp/sql-store");
        let ok = resolve_path(root, "sql/v1/a/b/c/snap/x").unwrap();
        assert_eq!(ok, root.join("sql/v1/a/b/c/snap/x"));
        for bad in [
            "",
            "sql/v1/",
            "sql/v1/../../etc/passwd",
            "sql/v1/a/./b",
            "sql/v1//a",
            "sql/v1/a/",
            "/etc/passwd",
            "../sql/v1/a",
            "sql/v1/a\\b",
            "sql/v1/a\0b",
            "sql/v1/a/.tmp-0011",
            "other/v1/a",
        ] {
            assert!(resolve_path(root, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn content_ranges_are_parsed_strictly() {
        assert_eq!(
            parse_content_range("bytes 10-19/300").unwrap(),
            (10, 19, 300)
        );
        assert_eq!(parse_content_range("bytes 0-0/1").unwrap(), (0, 0, 1));
        for bad in [
            "",
            "bytes */300",
            "bytes 10-19/*",
            "bytes 19-10/300",
            "bytes 0-300/300",
            "10-19/300",
            "bytes 10/300",
        ] {
            assert!(parse_content_range(bad).is_err(), "{bad:?}");
        }
    }

    fn scripted(answers: Vec<PutResult>) -> (Result<WriteMode, SqlStoreError>, usize) {
        let calls = AtomicUsize::new(0);
        let answers = Mutex::new(answers.into_iter());
        let result = futures::executor::block_on(probe_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            let next = answers
                .lock()
                .unwrap()
                .next()
                .expect("probe asked too often");
            async move { next }
        }));
        (result, calls.load(Ordering::SeqCst))
    }

    #[test]
    fn probe_selects_the_write_mode_from_the_second_answer() {
        use PutResult::*;
        let (mode, calls) = scripted(vec![Created, PreconditionFailed]);
        assert_eq!((mode.unwrap(), calls), (WriteMode::Conditional, 2));
        // An object left by an earlier start answers the first request.
        let (mode, calls) = scripted(vec![PreconditionFailed]);
        assert_eq!((mode.unwrap(), calls), (WriteMode::Conditional, 1));
        let (mode, calls) = scripted(vec![Created, Created]);
        assert_eq!((mode.unwrap(), calls), (WriteMode::CheckThenWrite, 2));
        let (mode, calls) = scripted(vec![Unsupported]);
        assert_eq!((mode.unwrap(), calls), (WriteMode::CheckThenWrite, 1));
        let (mode, calls) = scripted(vec![Created, Unsupported]);
        assert_eq!((mode.unwrap(), calls), (WriteMode::CheckThenWrite, 2));
    }

    #[test]
    fn probe_failure_is_an_error_not_a_fallback() {
        use PutResult::*;
        let failure = || Failed(SqlStoreError::Backend("down".into()));
        let (mode, calls) = scripted(vec![failure()]);
        assert!(matches!(mode, Err(SqlStoreError::Backend(_))));
        assert_eq!(calls, 1);
        let (mode, _) = scripted(vec![Created, failure()]);
        assert!(matches!(mode, Err(SqlStoreError::Backend(_))));
    }
}
