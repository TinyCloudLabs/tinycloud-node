//! Validated exact resource identities and typed admission/drain lifetimes.
use crate::encryption_network::{
    key_id::{self, EncryptionResource},
    NetworkId,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard};

#[derive(Debug, thiserror::Error)]
#[error("invalid exact encryption resource")]
pub struct ResourceTargetError;
#[derive(Clone)]
pub struct ResourceTarget {
    canonical: String,
    owner: String,
    network: String,
}
impl ResourceTarget {
    pub fn parse(raw: &str) -> Result<Self, ResourceTargetError> {
        let parsed = key_id::parse(raw).map_err(|_| ResourceTargetError)?;
        let owner = parsed.owner_did().to_owned();
        let network = match &parsed {
            EncryptionResource::Network(network) => network.to_string(),
            EncryptionResource::Key(key) => NetworkId::new(key.owner_did(), key.network())
                .map_err(|_| ResourceTargetError)?
                .to_string(),
            EncryptionResource::KeyPrefix(_) => return Err(ResourceTargetError),
        };
        Ok(Self {
            canonical: parsed.to_string(),
            owner,
            network,
        })
    }
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
    pub fn owner_did(&self) -> &str {
        &self.owner
    }
    pub fn network_id(&self) -> &str {
        &self.network
    }
    pub(crate) fn targets(&self) -> Vec<(&str, &str)> {
        let mut targets = vec![("owner", self.owner_did()), ("resource", self.network_id())];
        if self.canonical != self.network {
            targets.push(("resource", self.as_str()));
        }
        targets
    }
}
pub struct ResourceOperation {
    pub(crate) _owner: OwnedRwLockReadGuard<()>,
    pub(crate) _resource: OwnedRwLockReadGuard<()>,
    pub(crate) target: ResourceTarget,
}
impl ResourceOperation {
    pub fn resource(&self) -> &ResourceTarget {
        &self.target
    }
}
/// Constructed only after the durable fence is present and owner work drains.
pub struct ResourcePurgeDrain {
    pub(crate) _owner: OwnedRwLockWriteGuard<()>,
    pub(crate) _resource: OwnedRwLockWriteGuard<()>,
    pub(crate) target: ResourceTarget,
}
impl ResourcePurgeDrain {
    pub fn resource(&self) -> &ResourceTarget {
        &self.target
    }
}
