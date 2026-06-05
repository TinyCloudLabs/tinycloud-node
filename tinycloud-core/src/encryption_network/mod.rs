//! Network-scoped encryption module.
//!
//! Implements the node-side responsibilities of the TinyCloud encryption
//! architecture: network lifecycle, key custody, ceremony state, and decrypt
//! invocation verification. The module deliberately does not expose a node-side
//! encrypt API — clients encrypt to the network public key locally.

pub mod backend;
pub mod canonical;
pub mod network_id;
pub mod protocol;
pub mod service;
pub mod types;

#[cfg(test)]
mod tests;

pub use backend::{KeyBackend, KeyBackendError, LocalOneOfOneBackend};
pub use network_id::{NetworkId, NetworkIdError};
pub use protocol::{
    DecryptFacts, DecryptInvocation, DecryptRequestBody, DecryptResponseBody, InvocationCapability,
    NetworkAdminFacts, NetworkAdminInvocation, DECRYPT_ACTION, DECRYPT_REQUEST_TYPE,
    DECRYPT_RESULT_TYPE, NETWORK_ADMIN_TYPE, NETWORK_CREATE_ACTION, NETWORK_REVOKE_ACTION,
};
pub use service::{
    CreateNetworkRequest, EncryptionService, EncryptionServiceError, VerifiedDecrypt,
    WellKnownRecord,
};
pub use types::{
    InlineEnvelope, KeyBackendKind, NetworkDescriptor, NetworkState, Threshold,
    ALG_X25519_AES256GCM,
};
