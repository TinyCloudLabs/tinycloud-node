pub mod file_system;
pub mod s3;
pub mod size;
pub mod sql_object;

use tinycloud_auth::resource::SpaceId;
use tinycloud_core::hash::Hash;

use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// One physical blob lifetime; a later generation must never share its
/// quota reservation or deletion target with an earlier generation.
type BlobGenerationKey = (SpaceId, Hash, i64);
#[cfg(test)]
type TestPause = Arc<Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>>;

/// Serialize physical I/O for one generation, not the entire store. The weak
/// registry drops inactive keys, so a long-running node does not retain one
/// lock per content hash it has ever written or collected. No DB connection
/// is held while this guard waits or while an object-store request runs.
#[derive(Debug, Clone, Default)]
struct BlobOperationLocks(Arc<Mutex<HashMap<BlobGenerationKey, Weak<Mutex<()>>>>>);

impl BlobOperationLocks {
    async fn lock(&self, key: BlobGenerationKey) -> OwnedMutexGuard<()> {
        let lock = {
            let mut registry = self.0.lock().await;
            registry.retain(|_, weak| weak.strong_count() > 0);
            if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                registry.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}
