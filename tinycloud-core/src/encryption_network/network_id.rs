//! Parsing for `urn:tinycloud:encryption:<principal>:<network>` network identifiers.
//!
//! The principal is the root authority for the network. The network name disambiguates
//! multiple networks owned by the same principal.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const NETWORK_ID_PREFIX: &str = "urn:tinycloud:encryption:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkIdError {
    #[error("missing urn:tinycloud:encryption: prefix")]
    MissingPrefix,
    #[error("empty principal")]
    EmptyPrincipal,
    #[error("empty network name")]
    EmptyName,
    #[error("missing principal/name separator")]
    MissingSeparator,
    #[error("network name may not contain ':' or '/'")]
    InvalidName,
}

/// Owned, validated network id. Round-trips through [`Display`] and [`FromStr`].
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NetworkId {
    principal: String,
    name: String,
}

impl NetworkId {
    pub fn new(
        principal: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, NetworkIdError> {
        let principal = principal.into();
        let name = name.into();
        if principal.is_empty() {
            return Err(NetworkIdError::EmptyPrincipal);
        }
        if name.is_empty() {
            return Err(NetworkIdError::EmptyName);
        }
        if name.contains(':') || name.contains('/') {
            return Err(NetworkIdError::InvalidName);
        }
        Ok(Self { principal, name })
    }

    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NETWORK_ID_PREFIX}{}:{}", self.principal, self.name)
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
        // The principal itself is a DID-like value that may contain colons
        // (e.g. did:key:z6Mk...). The network name is the final colon-delimited
        // segment, which is constrained to contain no further ':' or '/'.
        let (principal, name) = rest
            .rsplit_once(':')
            .ok_or(NetworkIdError::MissingSeparator)?;
        Self::new(principal.to_string(), name.to_string())
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
        assert_eq!(id.principal(), "did:key:z6MkExampleAbcd");
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
    fn rejects_empty_principal_with_explicit_name() {
        let err: Result<NetworkId, _> = "urn:tinycloud:encryption::default".parse();
        assert_eq!(err.unwrap_err(), NetworkIdError::EmptyPrincipal);
    }

    #[test]
    fn rejects_name_with_separator() {
        let err = NetworkId::new("did:key:abc", "bad/name").unwrap_err();
        assert_eq!(err, NetworkIdError::InvalidName);
        let err = NetworkId::new("did:key:abc", "bad:name").unwrap_err();
        assert_eq!(err, NetworkIdError::InvalidName);
    }

    #[test]
    fn rejects_no_separator() {
        let err: Result<NetworkId, _> = "urn:tinycloud:encryption:standalone".parse();
        assert_eq!(err.unwrap_err(), NetworkIdError::MissingSeparator);
    }
}
