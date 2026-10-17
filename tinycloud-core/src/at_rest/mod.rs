//! Encryption at rest (TC-887). Nothing in the node calls this module yet; it
//! is switched off until the key-continuity gate exists.

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

pub use envelope::{
    ciphertext_len, format_version, open, plaintext_len, seal, BlobIdentity, EnvelopeError, Header,
    HEADER_LEN, SEGMENT_LEN, TAG_LEN,
};
pub use key::{DataKey, DekId, ObjectNameKey};
pub use names::{sealed_object_name, space_tag, PayloadEncoding, SEALED_NAME_PREFIX};
pub use provider::{DataKeyError, DataKeyProvider};
pub use stream::{DecryptReader, EncryptReader, SegmentRange};
#[cfg(any(test, feature = "test-util"))]
pub use testing::FixedKeyProvider;

pub use keyring::{AtRestKeyring, KeyringConfig, KeyringState};
pub use store::{AtRestStore, KeyMirror};
