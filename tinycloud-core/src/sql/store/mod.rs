//! SQL block-store contract types (TC-1491, design B slice 0).
//!
//! See `docs/sql-block-store-contract.md`. In the funded phase Postgres stays
//! master; everything here is the shadow copy's vocabulary. Nothing in this
//! module is reached unless `[sql_store] enabled = true`.

pub mod key;
pub mod manifest;
pub mod memory;
pub mod object;
pub mod policy;

pub use key::{DbRef, KeyError, Lineage, ObjectKey, ObjectKind, PublishId};
pub use manifest::{
    CasToken, DbSqlManifest, Frontier, ObjectRecord, ObjectState, Publish, PublishKind,
    PublishOutcome, SqlManifest,
};
pub use memory::MemorySqlObjectStore;
pub use object::{ObjectMeta, ObjectRange, PutOutcome, SqlObjectStore, SqlStoreError};
pub use policy::{PendingState, RetentionPolicy, SpaceAllowlist, UploadPolicy};
