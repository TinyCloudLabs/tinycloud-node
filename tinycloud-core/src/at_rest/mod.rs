//! Encryption at rest (TC-887): the TCE1 envelope, the keyring, and the
//! view storage reads of the node's at-rest state. Off unless configured.

mod envelope;
mod hierarchy;
mod key;
pub mod keyring;
mod names;
mod provider;
pub mod store;
mod stream;
#[cfg(any(test, feature = "test-util"))]
mod testing;
#[cfg(test)]
mod tests;
mod view;

pub use envelope::{
    ciphertext_len, format_version, open, plaintext_len, seal, BlobIdentity, EnvelopeError, Header,
    SqlManifestPart, HEADER_LEN, SEGMENT_LEN, TAG_LEN,
};
pub use key::{DataKey, DekId, ObjectNameKey};
pub use names::{sealed_object_name, space_tag, PayloadEncoding, SEALED_NAME_PREFIX};
pub use provider::{in_write_lock, write_locked, DataKeyError, DataKeyProvider};
pub use stream::{DecryptReader, EncryptReader, SegmentOpener, SegmentRange};
#[cfg(any(test, feature = "test-util"))]
pub use testing::{FixedKeyProvider, TestAtRestSource};

pub use keyring::{AtRestKeyring, KeyringConfig, KeyringState};
pub use store::{AtRestStore, KeyMirror};
pub use view::{AtRestMode, AtRestSource, AtRestView};
