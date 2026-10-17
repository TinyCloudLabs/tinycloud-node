pub mod at_rest_mirror;
pub mod file_system;
pub mod s3;
pub mod sealed;
pub mod size;

use std::sync::Arc;

use crate::{at_rest::AtRestRuntime, BlockStores};
use tinycloud_core::storage::either::Either;

/// Links the opened block store to the node's at-rest state (TC-887): the
/// store seals KV blocks when the mode and keys allow.
pub fn attach_at_rest(stores: &mut BlockStores, runtime: Arc<AtRestRuntime>) {
    let handle = sealed::AtRestHandle::new(runtime);
    match stores {
        Either::A(s3) => s3.attach_at_rest(handle),
        Either::B(fs) => fs.attach_at_rest(handle),
    }
}
