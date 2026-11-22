//! The SQL object store trait (TC-1491 contract, sections 3 and 6).
//!
//! Deliberately narrow: no delete, no overwrite, no unbounded listing. A
//! backend is the S3 client or the filesystem root of the node's block store,
//! scoped to the private `sql/v1/` namespace (slice 1b). Bodies move as
//! files, never as whole in-memory buffers. The in-memory implementation
//! here is for tests.

use std::path::Path;

use async_trait::async_trait;

use super::key::ObjectKey;
use crate::storage::ByteRangeSpec;

#[derive(Debug, thiserror::Error)]
pub enum SqlStoreError {
    #[error("sql store key error: {0}")]
    Key(#[from] super::key::KeyError),
    /// The key exists with different bytes (length or SHA-256). Never replaced.
    #[error("sql store object exists with different content")]
    Conflict,
    /// The bytes handed in do not hash to the key's `content_hash`.
    #[error("sql store body does not match its key")]
    BodyMismatch,
    #[error("sql store backend error: {0}")]
    Backend(String),
    /// The local file a body is read from or written to failed.
    #[error("sql store local file error: {0}")]
    File(String),
    #[error("sql store manifest error: {0}")]
    Manifest(#[from] sea_orm::DbErr),
    /// A publish found its object not `uploaded` (missing or already
    /// published); the CAS transaction was rolled back.
    #[error("sql store object is not in the uploaded state")]
    ObjectNotUploaded,
    #[error("sql store request is invalid: {0}")]
    Invalid(&'static str),
}

impl SqlStoreError {
    /// An I/O error on a local body file; the kind only (a path could carry a key).
    pub fn file(op: &str, error: &std::io::Error) -> Self {
        Self::File(format!("{op} failed ({:?})", error.kind()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    /// Same key, same length and SHA-256: nothing written.
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRange {
    pub total_size: u64,
    pub start: u64,
    pub data: Vec<u8>,
}

#[async_trait]
pub trait SqlObjectStore: Send + Sync {
    /// Create the object from the `size`-byte file at `path` unless it
    /// exists. The file must be `size` bytes long (`Invalid` otherwise) and
    /// hash to the key's SHA-256 (`BodyMismatch` otherwise); either refusal
    /// comes before anything is stored under the key. An existing object
    /// with the same length and SHA-256 gives `AlreadyPresent`; any other
    /// existing object gives `Conflict`.
    ///
    /// Backends use a conditional PUT (`If-None-Match: *`). A HEAD-then-PUT
    /// fallback is acceptable only while nothing deletes SQL objects; slice 4
    /// must not rely on it (contract 3.3).
    async fn put_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        size: u64,
    ) -> Result<PutOutcome, SqlStoreError>;

    /// Stream the object into `path` (created or truncated). The bytes are
    /// checked against the key's SHA-256 while they stream (`BodyMismatch`).
    /// `None` when the object does not exist.
    async fn get_to_file(
        &self,
        key: &ObjectKey,
        path: &Path,
    ) -> Result<Option<ObjectMeta>, SqlStoreError>;

    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<ObjectRange>, SqlStoreError>;

    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError>;
}

/// SHA-256 of `body`; shared by backends to check a body against its key.
pub fn sha256(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(body).into()
}

/// Read size of [`sha256_file`].
const HASH_CHUNK: usize = 1 << 20;

/// Length and SHA-256 of the file at `path`, read in bounded chunks.
pub async fn sha256_file(path: &Path) -> Result<ObjectMeta, SqlStoreError> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| SqlStoreError::file("open", &e))?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; HASH_CHUNK];
    let mut bytes = 0u64;
    loop {
        let n = file
            .read(&mut chunk)
            .await
            .map_err(|e| SqlStoreError::file("read", &e))?;
        if n == 0 {
            return Ok(ObjectMeta {
                bytes,
                sha256: hasher.finalize().into(),
            });
        }
        hasher.update(&chunk[..n]);
        bytes += n as u64;
    }
}

/// Check a body file against the key and the declared size before any write.
pub async fn check_body_file(
    key: &ObjectKey,
    path: &Path,
    size: u64,
) -> Result<(), SqlStoreError> {
    let meta = sha256_file(path).await?;
    if meta.bytes != size {
        return Err(SqlStoreError::Invalid("body file size does not match"));
    }
    if &meta.sha256 != key.sha256() {
        return Err(SqlStoreError::BodyMismatch);
    }
    Ok(())
}
