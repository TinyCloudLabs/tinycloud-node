//! Key material handed to the at-rest envelope (TC-887).

use zeroize::Zeroizing;

/// Per-space data-key id, stored in the TCE1 header. Unique within a space,
/// not globally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DekId(u32);

impl DekId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An unwrapped 32-byte data key (DEK) and its id. The bytes are zeroized on
/// drop and never exposed outside this module.
#[derive(Clone)]
pub struct DataKey {
    id: DekId,
    bytes: Zeroizing<[u8; 32]>,
}

impl DataKey {
    pub fn new(id: DekId, bytes: [u8; 32]) -> Self {
        Self {
            id,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Take key bytes already in a zeroizing buffer, with no plain copy.
    pub(crate) fn from_zeroizing(id: DekId, bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { id, bytes }
    }

    pub fn id(&self) -> DekId {
        self.id
    }

    #[allow(dead_code)] // read by the envelope module
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The object-name key (NK) used to derive sealed S3 object names. Zeroized on
/// drop; never printed.
#[derive(Clone)]
pub struct ObjectNameKey(Zeroizing<[u8; 32]>);

impl ObjectNameKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take key bytes already in a zeroizing buffer, with no plain copy.
    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    #[allow(dead_code)] // read by the object-name module
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ObjectNameKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectNameKey").finish_non_exhaustive()
    }
}
