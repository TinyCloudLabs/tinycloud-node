//! The boundary between key continuity (who holds DEKs) and the envelope
//! (what a DEK encrypts). See `docs/at-rest/INTERFACES.md` §2.

use std::future::Future;

use super::key::{DataKey, DekId, ObjectNameKey};
use async_trait::async_trait;

/// Supplies unwrapped data keys. `space` is always the canonical
/// `SpaceId::to_string()` form.
#[async_trait]
pub trait DataKeyProvider: Send + Sync {
    /// The DEK new writes in `space` must use. If the space has none, the
    /// implementation creates one and stores it durably before returning;
    /// concurrent first calls converge on one `DekId`.
    async fn current_key(&self, space: &str) -> Result<DataKey, DataKeyError>;

    /// The DEK a stored blob names in its header. Never creates a key.
    async fn key(&self, space: &str, dek_id: DekId) -> Result<DataKey, DataKeyError>;

    /// Before work that may read `space`'s sealed blobs under the invoke
    /// write lock: put back any of the space's keys the database lost (for
    /// example from an authenticated mirror). Never creates a key. Inside
    /// [`write_locked`], `key` and `current_key` only read.
    async fn prepare_read(&self, space: &str) -> Result<(), DataKeyError>;

    /// The object-name key for sealed S3 names. Constant for a deployment.
    fn object_name_key(&self) -> Result<ObjectNameKey, DataKeyError>;
}

tokio::task_local! {
    static WRITE_LOCKED: ();
}

/// Runs `f` as work under the invoke write lock and transaction. Key
/// providers make no key-store writes there (on SQLite they would wait on the
/// lock this task holds): a key that needs creating or restoring answers
/// [`DataKeyError::NotPrepared`] instead. Callers prepare spaces first
/// (`current_key` for written spaces, `prepare_read` for read ones).
pub async fn write_locked<F: Future>(f: F) -> F::Output {
    WRITE_LOCKED.scope((), f).await
}

/// Whether the current task is inside [`write_locked`].
pub fn in_write_lock() -> bool {
    WRITE_LOCKED.try_with(|_| ()).is_ok()
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DataKeyError {
    /// The node booted locked: its root cannot unseal the at-rest root key.
    #[error("at-rest keys are locked")]
    Locked,
    /// The space never had this key, or it was shredded. Callers treat this as
    /// an integrity failure of the blob, never as "not found".
    #[error("unknown data key {dek_id:?} for space")]
    UnknownKey { dek_id: DekId },
    /// Storage or unwrap failure. Carries no key bytes.
    #[error("data key backend: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The key needed creating or restoring inside [`write_locked`], where
    /// no key-store write may happen: the space was not prepared first.
    #[error("the space's data key was not prepared before the write lock")]
    NotPrepared,
}
