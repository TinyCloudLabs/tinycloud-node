//! TEE (Trusted Execution Environment) context and utilities.
//!
//! In dstack mode, this module provides attestation and identity information
//! about the running TEE instance. In classic mode, these are None/absent.

use serde::{Deserialize, Serialize};

/// Runtime context for TEE mode.
/// Populated at startup via `dstack::get_info()` when running inside a TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeContext {
    /// dstack application identifier
    pub app_id: String,
    /// SHA256 hash of the app-compose.json configuration
    pub compose_hash: String,
    /// Unique instance identifier
    pub instance_id: String,
    /// DID derived from the dstack key source used by the node.
    pub enforcer_did: String,
}

impl TeeContext {
    /// A deterministic, non-attested TEE identity derived entirely from the
    /// node's own key material. Used only by the `local-tee` feature (never
    /// part of a production build; see Dockerfile CARGO_FEATURES) and by
    /// tests, so a canonical local launch or test host without real dstack
    /// attestation can still exercise the fail-closed-shaped /share/v2
    /// readiness path with a real, key-bound `enforcer_did` rather than a
    /// fixture or hardcoded value.
    #[cfg(any(test, feature = "local-tee"))]
    pub fn derive_local(key_setup: &tinycloud_core::keys::StaticSecret) -> Self {
        Self {
            app_id: hex::encode(key_setup.derive_key(b"tinycloud/tee/local-dev/app-id")),
            compose_hash: hex::encode(
                key_setup.derive_key(b"tinycloud/tee/local-dev/compose-hash"),
            ),
            instance_id: hex::encode(key_setup.derive_key(b"tinycloud/tee/local-dev/instance-id")),
            enforcer_did: key_setup.node_did(),
        }
    }
}

/// Attestation response returned by the /attestation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum AttestationResponse {
    /// TEE mode: includes TDX quote and app identity
    #[serde(rename = "dstack")]
    Dstack {
        /// Hex-encoded TDX quote
        quote: String,
        /// Hex-encoded event log
        event_log: String,
        /// SHA256 of app-compose.json
        compose_hash: String,
        /// dstack app identifier
        app_id: String,
        /// DID whose public key is bound to this attested instance.
        enforcer_did: String,
        /// The report-data binding input used for the quote.
        key_binding: String,
        /// ISO 8601 timestamp
        timestamp: String,
    },
    /// Classic mode: no TEE available
    #[serde(rename = "classic")]
    Classic { message: String },
}
