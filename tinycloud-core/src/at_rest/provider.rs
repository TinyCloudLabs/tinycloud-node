//! The boundary between key continuity (who holds DEKs) and the envelope
//! (what a DEK encrypts). See `INTERFACES.md` §2 on TC-887.

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

    /// The object-name key for sealed S3 names. Constant for a deployment.
    fn object_name_key(&self) -> Result<ObjectNameKey, DataKeyError>;
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
}
