use crate::types::{Ability, Resource};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tinycloud_lib::{
    authorization::{TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation},
    cacaos::siwe::Message,
    ipld_core::cid::Cid,
    resource::SpaceId,
    siwe_recap::{Capability as SiweCap, VerificationError as SiweError},
};
use ucan_capabilities_object::Capabilities as UcanCapabilities;

/// Strip the fragment from a DID URL, returning the base DID.
/// For example: `did:key:z6Mk...#z6Mk...` -> `did:key:z6Mk...`
///
/// DID fragments identify specific verification methods, but for identity
/// comparison purposes, the base DID is sufficient. This normalizes all
/// DID strings to ensure consistent matching across delegation chains.
fn strip_fragment(did: &str) -> String {
    did.split('#').next().unwrap_or(did).to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Capability {
    pub resource: Resource,
    pub ability: Ability,
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum CapExtractError {
    #[error("Default actions are not allowed for TinyCloud capabilities")]
    DefaultActions,
    #[error("Invalid Extra Fields")]
    InvalidFields,
    #[error(transparent)]
    Cid(#[from] tinycloud_lib::ipld_core::cid::Error),
}

fn extract_ucan_caps<T>(caps: &UcanCapabilities<T>) -> Vec<Capability> {
    let mut capabilities = Vec::new();

    // Iterate over all capabilities in the Capabilities object
    for (resource_uri, abilities) in caps.abilities() {
        for ability in abilities.keys() {
            // Only process tinycloud capabilities, skip others
            capabilities.push(Capability {
                resource: resource_uri.into(),
                ability: ability.clone().into(),
            });
        }
    }

    capabilities
}

fn extract_siwe_cap(c: SiweCap<()>) -> (Vec<Capability>, Vec<Cid>) {
    let (c, p) = c.into_inner();
    (
        c.into_inner()
            .into_iter()
            .flat_map(|(r, acs)| {
                // r is UriString, acs is BTreeMap<Ability, Caveats<()>>
                acs.into_keys() // Iterate over Ability keys
                    .map(|ability| Capability {
                        resource: Resource::from(r.clone()),
                        ability: ability.into(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect(),
        p,
    )
}

#[derive(Debug, Clone)]
pub struct DelegationInfo {
    pub capabilities: Vec<Capability>,
    pub delegator: String,
    pub delegate: String,
    pub parents: Vec<Cid>,
    pub delegation: TinyCloudDelegation,
    pub expiry: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    pub issued_at: Option<OffsetDateTime>,
}

impl DelegationInfo {
    pub fn spaces(&self) -> impl Iterator<Item = &SpaceId> + '_ {
        self.capabilities.iter().filter_map(|c| c.resource.space())
    }
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum DelegationError {
    #[error(transparent)]
    InvalidCapability(#[from] CapExtractError),
    #[error("Missing Delegator")]
    MissingDelegator,
    #[error("Missing Delegate")]
    MissingDelegate,
    #[error(transparent)]
    SiweConversion(#[from] tinycloud_lib::cacaos::siwe_cacao::SIWEPayloadConversionError),
    #[error(transparent)]
    SiweCapError(#[from] SiweError),
    #[error("Invalid Siwe Statement")]
    InvalidStatement,
}

impl TryFrom<TinyCloudDelegation> for DelegationInfo {
    type Error = DelegationError;
    fn try_from(d: TinyCloudDelegation) -> Result<Self, Self::Error> {
        Ok(match d {
            TinyCloudDelegation::Ucan(ref u) => Self {
                capabilities: extract_ucan_caps(&u.payload().attenuation),
                delegator: strip_fragment(&u.payload().issuer.to_string()),
                delegate: strip_fragment(&u.payload().audience.to_string()),
                parents: u.payload().proof.clone(),
                expiry: OffsetDateTime::from_unix_timestamp_nanos(
                    (u.payload().expiration.as_seconds() * 1_000_000_000.0) as i128,
                )
                .ok(),
                not_before: u.payload().not_before.and_then(|t| {
                    OffsetDateTime::from_unix_timestamp_nanos(
                        (t.as_seconds() * 1_000_000_000.0) as i128,
                    )
                    .ok()
                }),
                delegation: d,
                issued_at: None,
            },
            TinyCloudDelegation::Cacao(ref c) => {
                let m: Message = c.payload().clone().try_into()?;
                // Use the public extract_and_verify, which returns Result<Option<SiweCap<()>>, VerificationError>
                let maybe_siwe_cap = SiweCap::extract_and_verify(&m)?;

                let (capabilities, parents) = match maybe_siwe_cap {
                    Some(siwe_cap) => {
                        // Pass the extracted cap to the helper function
                        extract_siwe_cap(siwe_cap)
                    }
                    None => {
                        // No capabilities found
                        (vec![], vec![])
                    }
                };

                Self {
                    capabilities, // Result from extract_siwe_cap or default
                    delegator: strip_fragment(&c.payload().iss.to_string()),
                    delegate: strip_fragment(&c.payload().aud.to_string()),
                    parents,
                    expiry: c.payload().exp.as_ref().map(|t| *t.as_ref()),
                    not_before: c.payload().nbf.as_ref().map(|t| *t.as_ref()),
                    issued_at: Some(*c.payload().iat.as_ref()),
                    delegation: d,
                }
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct InvocationInfo {
    pub capabilities: Vec<Capability>,
    pub invoker: String,
    pub parents: Vec<Cid>,
    pub invocation: TinyCloudInvocation,
}

impl InvocationInfo {
    pub fn spaces(&self) -> impl Iterator<Item = &SpaceId> + '_ {
        self.capabilities.iter().filter_map(|c| c.resource.space())
    }
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum InvocationError {
    #[error("Missing Resource")]
    MissingResource,
    #[error(transparent)]
    ResourceParse(#[from] CapExtractError),
}

impl TryFrom<TinyCloudInvocation> for InvocationInfo {
    type Error = InvocationError;
    fn try_from(invocation: TinyCloudInvocation) -> Result<Self, Self::Error> {
        Ok(Self {
            capabilities: extract_ucan_caps(&invocation.payload().attenuation),
            invoker: strip_fragment(&invocation.payload().issuer.to_string()),
            parents: invocation.payload().proof.clone(),
            invocation,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RevocationInfo {
    // TODO these should be hash
    pub parents: Vec<Cid>,
    pub revoked: Cid,
    pub revoker: String,
    pub revocation: TinyCloudRevocation,
}

#[derive(thiserror::Error, Debug)]
pub enum RevocationError {
    #[error("Invalid Target")]
    InvalidTarget,
}

impl TryFrom<TinyCloudRevocation> for RevocationInfo {
    type Error = RevocationError;
    fn try_from(r: TinyCloudRevocation) -> Result<Self, Self::Error> {
        match r {
            TinyCloudRevocation::Cacao(ref c) => match c.payload().aud.as_str().split_once(':') {
                Some(("ucan", ps)) => Ok(Self {
                    parents: Vec::new(),
                    revoked: ps.parse().map_err(|_| RevocationError::InvalidTarget)?,
                    revoker: strip_fragment(&c.payload().iss.to_string()),
                    revocation: r,
                }),
                _ => Err(RevocationError::InvalidTarget),
            },
        }
    }
}
