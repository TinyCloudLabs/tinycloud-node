//! Encryption at rest (TC-887). Nothing in the node calls this module yet; it
//! is switched off until the key-continuity gate exists.

mod key;
mod provider;

pub use key::{DataKey, DekId, ObjectNameKey};
pub use provider::{DataKeyError, DataKeyProvider, FixedKeyProvider};
