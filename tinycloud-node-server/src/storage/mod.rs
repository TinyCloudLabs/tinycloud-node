pub mod at_rest_mirror;
pub mod file_system;
pub mod s3;
pub mod sealed;
pub mod size;

use std::sync::Arc;

use crate::{at_rest::AtRestRuntime, BlockStores};
use tinycloud_core::storage::either::Either;

/// Links the opened block store to the node's at-rest state (TC-887).
///
/// The FileSystem store seals KV blocks when the mode and keys allow, so it
/// declares a seal path. The S3 store does not seal yet and declares none,
/// so `at_rest::setup` refuses a non-`off` mode with S3 storage rather than
/// write plaintext.
pub fn attach_at_rest(stores: &mut BlockStores, runtime: Arc<AtRestRuntime>) {
    match stores {
        Either::B(fs) => {
            runtime.declare_seal_path();
            fs.attach_at_rest(sealed::AtRestHandle::new(runtime));
        }
        Either::A(_) => {}
    }
}
