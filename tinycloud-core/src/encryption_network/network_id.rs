//! Parsing for `urn:tinycloud:encryption:<ownerDid>:<network>` network identifiers.
//!
//! The owner DID is the root authority for the network. The network name disambiguates
//! multiple networks owned by the same owner.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use tinycloud_auth::identity::canonicalize_principal;

const NETWORK_ID_PREFIX: &str = "urn:tinycloud:encryption:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkIdError {
    #[error("missing urn:tinycloud:encryption: prefix")]
    MissingPrefix,
    #[error("empty owner DID")]
    EmptyOwnerDid,
    #[error("empty network name")]
    EmptyName,
    #[error("missing owner DID/name separator")]
    MissingSeparator,
    #[error("network name may not contain ':' or '/'")]
    InvalidName,
    #[error("invalid owner principal: {0}")]
    InvalidPrincipal(String),
}

/// Owned, validated network id. Round-trips through [`Display`] and [`FromStr`].
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NetworkId {
    owner_did: String,
    name: String,
}

impl NetworkId {
    pub fn new(
        owner_did: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, NetworkIdError> {
        let owner_did = owner_did.into();
        let name = name.into();
        if owner_did.is_empty() {
            return Err(NetworkIdError::EmptyOwnerDid);
        }
        if name.is_empty() {
            return Err(NetworkIdError::EmptyName);
        }
        if name.contains(':') || name.contains('/') {
            return Err(NetworkIdError::InvalidName);
        }
        let owner_did = canonicalize_principal(&owner_did)
            .map_err(|err| NetworkIdError::InvalidPrincipal(err.to_string()))?;
        Ok(Self { owner_did, name })
    }

    pub fn owner_did(&self) -> &str {
        &self.owner_did
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NETWORK_ID_PREFIX}{}:{}", self.owner_did, self.name)
    }
}

impl fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkId({self})")
    }
}

impl FromStr for NetworkId {
    type Err = NetworkIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix(NETWORK_ID_PREFIX)
            .ok_or(NetworkIdError::MissingPrefix)?;
        // The owner DID itself may contain colons
        // (e.g. did:key:z6Mk...). The network name is the final colon-delimited
        // segment, which is constrained to contain no further ':' or '/'.
        let (owner_did, name) = rest
            .rsplit_once(':')
            .ok_or(NetworkIdError::MissingSeparator)?;
        Self::new(owner_did.to_string(), name.to_string())
    }
}

impl TryFrom<String> for NetworkId {
    type Error = NetworkIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<NetworkId> for String {
    fn from(id: NetworkId) -> Self {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_did_key_network_id() {
        let id: NetworkId = "urn:tinycloud:encryption:did:key:z6MkExampleAbcd:default"
            .parse()
            .unwrap();
        assert_eq!(id.owner_did(), "did:key:z6MkExampleAbcd");
        assert_eq!(id.name(), "default");
        assert_eq!(
            id.to_string(),
            "urn:tinycloud:encryption:did:key:z6MkExampleAbcd:default"
        );
    }

    #[test]
    fn rejects_missing_prefix() {
        let err: Result<NetworkId, _> = "did:key:z6Mk:default".parse();
        assert_eq!(err.unwrap_err(), NetworkIdError::MissingPrefix);
    }

    #[test]
    fn rejects_missing_name() {
        let err: Result<NetworkId, _> = "urn:tinycloud:encryption:did:key:z6Mk:".parse();
        assert_eq!(err.unwrap_err(), NetworkIdError::EmptyName);
    }

    #[test]
    fn rejects_empty_owner_did_with_explicit_name() {
        let err: Result<NetworkId, _> = "urn:tinycloud:encryption::default".parse();
        assert_eq!(err.unwrap_err(), NetworkIdError::EmptyOwnerDid);
    }

    #[test]
    fn rejects_name_with_separator() {
        let err = NetworkId::new("did:key:abc", "bad/name").unwrap_err();
        assert_eq!(err, NetworkIdError::InvalidName);
        let err = NetworkId::new("did:key:abc", "bad:name").unwrap_err();
        assert_eq!(err, NetworkIdError::InvalidName);
    }

    #[test]
    fn canonicalizes_pkh_principal() {
        let id: NetworkId =
            "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266:default"
                .parse()
                .unwrap();
        assert_eq!(
            id.owner_did(),
            "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert_eq!(
            id.to_string(),
            "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:default"
        );
    }

    #[test]
    fn rejects_no_separator() {
        let err: Result<NetworkId, _> = "urn:tinycloud:encryption:standalone".parse();
        assert_eq!(err.unwrap_err(), NetworkIdError::MissingSeparator);
    }
}
