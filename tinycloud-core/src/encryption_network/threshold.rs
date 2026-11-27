//! Threshold key backend.
//!
//! A threshold network's key is never held by one node. Each member holds one
//! share of it, from a [`ShareSource`], and issues its share encrypted to the
//! caller's transport key (`tinycloud-threshold` §3.6). The caller verifies and
//! combines t of them. Nothing here holds an X25519 network secret, and the
//! master secret is never assembled.
//!
//! The request check is the canonical identity and key version the node's
//! capability check authorized. The wrapped-key and body-hash checks of the
//! one-of-one decrypt path do not apply here.

use std::sync::Arc;

use rand::rngs::OsRng;
use thiserror::Error;
use tinycloud_threshold::{
    issue_share, AuthorizedDerivation, DecryptRequest, EncryptedKeyShare, Epoch, KeyPath, KeyShare,
    KeyVersion, NetworkUrn, PublicKeySet, VerifiedCertificate,
};

use super::network_id::NetworkId;

/// Failure reported by a [`ShareSource`].
pub type ShareSourceError = Box<dyn std::error::Error + Send + Sync>;

/// This node's threshold key material, per network.
pub trait ShareSource: Send + Sync {
    /// The verified current certificate of `network`, or `None` when this
    /// node holds none.
    fn current_certificate(
        &self,
        network: &NetworkUrn,
    ) -> Result<Option<VerifiedCertificate>, ShareSourceError>;

    /// This member's share bound to the current certificate of `network`, or
    /// `None` when this node holds none.
    fn current_share(&self, network: &NetworkUrn) -> Result<Option<KeyShare>, ShareSourceError>;
}

#[derive(Debug, Error)]
pub enum ThresholdBackendError {
    #[error("no threshold key material for this network")]
    NoKeyMaterial,
    #[error("the requested key generation is not the current one")]
    EpochMismatch,
    #[error("the request is not for the authorized identity and key version")]
    UnauthorizedIdentity,
    #[error("the request does not match the current key context")]
    ContextMismatch,
    #[error("invalid threshold request: {0}")]
    InvalidRequest(tinycloud_threshold::Error),
    #[error("share source failed: {0}")]
    Source(ShareSourceError),
}

/// Key operations of a threshold network member.
pub trait ThresholdKeyBackend: Send + Sync {
    /// The public key set of `network` at `epoch`: its key context, master
    /// public key and member public shares, from the current certificate.
    fn public_material(
        &self,
        network: &NetworkId,
        epoch: Epoch,
    ) -> Result<PublicKeySet, ThresholdBackendError>;

    /// Issues this member's decryption share for `request`, encrypted to the
    /// request's transport key. `key_path` and `key_version` are what the
    /// node's capability check authorized; the request's identity must be
    /// exactly the one they and `network` define.
    fn derive_shares(
        &self,
        network: &NetworkId,
        key_path: &str,
        key_version: u64,
        request: DecryptRequest,
    ) -> Result<EncryptedKeyShare, ThresholdBackendError>;
}

/// [`ThresholdKeyBackend`] over a [`ShareSource`].
pub struct ShareSourceBackend {
    source: Arc<dyn ShareSource>,
}

impl ShareSourceBackend {
    pub fn new(source: Arc<dyn ShareSource>) -> Self {
        Self { source }
    }
}

fn network_urn(network: &NetworkId) -> Result<NetworkUrn, ThresholdBackendError> {
    NetworkUrn::new(network.to_string()).map_err(ThresholdBackendError::InvalidRequest)
}

impl ThresholdKeyBackend for ShareSourceBackend {
    fn public_material(
        &self,
        network: &NetworkId,
        epoch: Epoch,
    ) -> Result<PublicKeySet, ThresholdBackendError> {
        let certificate = self
            .source
            .current_certificate(&network_urn(network)?)
            .map_err(ThresholdBackendError::Source)?
            .ok_or(ThresholdBackendError::NoKeyMaterial)?;
        if certificate.body().epoch() != epoch {
            return Err(ThresholdBackendError::EpochMismatch);
        }
        Ok(certificate.public_key_set().clone())
    }

    fn derive_shares(
        &self,
        network: &NetworkId,
        key_path: &str,
        key_version: u64,
        request: DecryptRequest,
    ) -> Result<EncryptedKeyShare, ThresholdBackendError> {
        let urn = network_urn(network)?;
        let path = KeyPath::new(key_path).map_err(ThresholdBackendError::InvalidRequest)?;
        let authorized = AuthorizedDerivation::from_capability_check(
            request,
            &urn,
            &path,
            KeyVersion::new(key_version),
        )
        .map_err(|err| match err {
            tinycloud_threshold::Error::UnauthorizedIdentity => {
                ThresholdBackendError::UnauthorizedIdentity
            }
            other => ThresholdBackendError::InvalidRequest(other),
        })?;
        let share = self
            .source
            .current_share(&urn)
            .map_err(ThresholdBackendError::Source)?
            .ok_or(ThresholdBackendError::NoKeyMaterial)?;
        issue_share(&share, &authorized, &mut OsRng).map_err(|err| match err {
            tinycloud_threshold::Error::ContextMismatch => ThresholdBackendError::ContextMismatch,
            other => ThresholdBackendError::InvalidRequest(other),
        })
    }
}
