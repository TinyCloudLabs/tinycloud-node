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
        /// ISO 8601 timestamp
        timestamp: String,
    },
    /// Classic mode: no TEE available
    #[serde(rename = "classic")]
    Classic { message: String },
}
