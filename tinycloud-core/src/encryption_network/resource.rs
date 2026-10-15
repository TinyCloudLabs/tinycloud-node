//! Exact raw ReCap resources for network-wide or single-KV-secret decrypt.

use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;
use tinycloud_auth::{identity::did_principal_matches, resource::SpaceId};

use super::network_id::NetworkId;

#[derive(Debug, Error)]
pub enum DecryptResourceError {
    #[error("invalid encryption network")]
    Network,
    #[error("invalid scoped decrypt locator")]
    Scope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedDecryptLocator {
    space_id: SpaceId,
    path: String,
}

impl ScopedDecryptLocator {
    pub fn space_id(&self) -> &SpaceId {
        &self.space_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptResource {
    network: NetworkId,
    scope: Option<ScopedDecryptLocator>,
}

impl DecryptResource {
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    pub fn scope(&self) -> Option<&ScopedDecryptLocator> {
        self.scope.as_ref()
    }

    pub fn scoped(
        network: NetworkId,
        space: &str,
        path: &str,
    ) -> Result<Self, DecryptResourceError> {
        let space_id = space
            .parse::<SpaceId>()
            .map_err(|_| DecryptResourceError::Scope)?;
        if space_id.to_string() != space
            || !did_principal_matches(space_id.did().as_str(), network.owner_did())
            || !valid_secret_path(path)
        {
            return Err(DecryptResourceError::Scope);
        }
        Ok(Self {
            network,
            scope: Some(ScopedDecryptLocator {
                space_id,
                path: path.to_owned(),
            }),
        })
    }

    /// A bare network covers all its scoped children; a scoped resource only
    /// covers itself. A scoped URI is never an admin network identifier.
    pub fn contains(&self, child: &Self) -> bool {
        self.network == child.network && (self.scope.is_none() || self.scope == child.scope)
    }
}

fn valid_secret_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("vault/secrets/") else {
        return false;
    };
    let valid = |part: &str| {
        !part.is_empty()
            && !matches!(part, "." | "..")
            && !part.chars().any(|c| c.is_control() || c == '\\')
    };
    let mut parts = rest.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(name), None, None, None) => valid(name),
        (Some("scoped"), Some(scope), Some(name), None) => valid(scope) && valid(name),
        _ => false,
    }
}

impl FromStr for DecryptResource {
    type Err = DecryptResourceError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if let Some((network_raw, encoded)) = raw.split_once("/kv/") {
            let network = network_raw
                .parse::<NetworkId>()
                .map_err(|_| DecryptResourceError::Network)?;
            if network.to_string() != network_raw {
                return Err(DecryptResourceError::Network);
            }
            let (space, path) = encoded.split_once('/').ok_or(DecryptResourceError::Scope)?;
            let decode = |part: &str| -> Result<String, DecryptResourceError> {
                let bytes = URL_SAFE_NO_PAD
                    .decode(part)
                    .map_err(|_| DecryptResourceError::Scope)?;
                if part.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != part {
                    return Err(DecryptResourceError::Scope);
                }
                String::from_utf8(bytes).map_err(|_| DecryptResourceError::Scope)
            };
            return Self::scoped(network, &decode(space)?, &decode(path)?);
        }
        let network = raw
            .parse::<NetworkId>()
            .map_err(|_| DecryptResourceError::Network)?;
        Ok(Self {
            network,
            scope: None,
        })
    }
}

impl fmt::Display for DecryptResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.network)?;
        if let Some(scope) = &self.scope {
            write!(
                f,
                "/kv/{}/{}",
                URL_SAFE_NO_PAD.encode(scope.space_id.to_string()),
                URL_SAFE_NO_PAD.encode(&scope.path)
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_root_accepts_lowercase_owner_but_new_scope_requires_canonical_owner() {
        let lowercase = "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266:default";
        let canonical = "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:default";
        let root: DecryptResource = lowercase.parse().unwrap();
        assert_eq!(root.to_string(), canonical);
        assert!(root.scope().is_none());

        let space = URL_SAFE_NO_PAD
            .encode("tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:secrets");
        let path = URL_SAFE_NO_PAD.encode("vault/secrets/A");
        let noncanonical_scope = format!("{lowercase}/kv/{space}/{path}");
        assert!(noncanonical_scope.parse::<DecryptResource>().is_err());
    }
}
