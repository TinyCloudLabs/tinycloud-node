pub mod at_rest_mirror;
pub mod file_system;
pub mod s3;
pub mod sealed;
pub mod size;
pub mod sql_object;

use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{hash::Hash, storage::either::Either};

use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::{
    at_rest::{AtRestRuntime, SealPath},
    BlockStores,
};

/// Links the opened block store to the node's at-rest state (TC-887).
///
/// The FileSystem store seals KV blocks when the mode and keys allow, so it
/// declares the blocks seal path. The S3 store does not seal in this build
/// and declares none, so `at_rest::setup` refuses a non-`off` mode with S3
/// block storage rather than write plaintext.
pub fn attach_at_rest(stores: &mut BlockStores, runtime: &Arc<AtRestRuntime>) {
    match stores {
        Either::B(fs) => {
            runtime.declare_seal_path(SealPath::Blocks);
            fs.attach_at_rest(sealed::AtRestHandle::new(runtime.clone()));
        }
        Either::A(_) => {}
    }
}

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
