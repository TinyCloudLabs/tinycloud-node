//! The SQL object store trait (TC-1491 contract, sections 3 and 6).
//!
//! Deliberately narrow: no delete, no overwrite, no unbounded listing. A
//! backend is the S3 client or the filesystem root of the node's block store,
//! scoped to the private `sql/v1/` namespace (slice 1b). The in-memory
//! implementation here is for tests.

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
    #[error("sql store manifest error: {0}")]
    Manifest(#[from] sea_orm::DbErr),
    /// A publish found its object not `uploaded` (orphaned, missing or already
    /// published); the CAS transaction was rolled back.
    #[error("sql store object is not in the uploaded state")]
    ObjectNotUploaded,
    #[error("sql store request is invalid: {0}")]
    Invalid(&'static str),
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
    /// Create the object unless it exists. The body must hash to the key's
    /// SHA-256. An existing object with the same length and SHA-256 gives
    /// `AlreadyPresent`; any other existing object gives `Conflict`.
    ///
    /// Backends use a conditional PUT (`If-None-Match: *`). A HEAD-then-PUT
    /// fallback is acceptable only while nothing deletes SQL objects; slice 4
    /// must not rely on it (contract 3.3).
    async fn put_if_absent(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError>;

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
