pub mod at_rest_mirror;
pub mod file_system;
pub mod s3;
pub mod sealed;
pub mod size;

use std::sync::Arc;

use crate::{at_rest::AtRestRuntime, config::AtRestMode, BlockStores};
use tinycloud_core::storage::either::Either;

/// Links the opened block store to the node's at-rest state (TC-887).
///
/// The FileSystem store seals KV blocks when the mode and keys allow. The S3
/// store does not seal yet, so a non-`off` mode with S3 storage refuses to
/// boot rather than write plaintext.
pub fn attach_at_rest(stores: &mut BlockStores, runtime: Arc<AtRestRuntime>) -> anyhow::Result<()> {
    match stores {
        Either::B(fs) => {
            fs.attach_at_rest(sealed::AtRestHandle::new(runtime));
            Ok(())
        }
        Either::A(_) if runtime.mode() == AtRestMode::Off => Ok(()),
        Either::A(_) => anyhow::bail!(
            "at_rest.mode = \"{}\" is not supported with S3 block storage in this build",
            runtime.mode_name()
        ),
    }
}
