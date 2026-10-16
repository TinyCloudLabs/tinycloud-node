pub mod file_system;
pub mod s3;
pub mod size;

use tinycloud_auth::resource::SpaceId;
use tinycloud_core::hash::Hash;

/// One physical blob lifetime; a later generation must never share its
/// quota reservation or deletion target with an earlier generation.
type BlobGenerationKey = (SpaceId, Hash, i64);
