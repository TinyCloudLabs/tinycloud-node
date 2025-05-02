use crate::types::Resource;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tinycloud_lib::siwe_recap::{Capability as SiweCap, VerificationError as SiweError};
use tinycloud_lib::{
    authorization::{TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation},
    cacaos::siwe::Message,
    libipld::Cid,
    resource::OrbitId,
    ssi::ucan::Capability as UcanCap,
};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Capability {
    pub resource: Resource,
    pub action: String,
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum CapExtractError {
    #[error("Default actions are not allowed for TinyCloud capabilities")]
    DefaultActions,
    #[error("Invalid Extra Fields")]
    InvalidFields,
    #[error(transparent)]
    Cid(#[from] tinycloud_lib::libipld::cid::Error),
}

fn extract_ucan_cap<T>(c: &UcanCap<T>) -> Result<Capability, CapExtractError> {
    Ok(Capability {
        resource: c.with.to_string().into(),
        action: c.can.capability.clone(),
    })
}

fn extract_siwe_cap(c: SiweCap<()>) -> Result<(Vec<Capability>, Vec<Cid>), CapExtractError> {
    // Removed check for default_actions as the field doesn't exist
    // Access abilities via the abilities() method
    Ok((
        c.abilities()
            .iter() // Iterate over the BTreeMap provided by abilities()
            .flat_map(|(r, acs)| {
                // r is &UriString, acs is &BTreeMap<Ability, NotaBeneCollection<()>>
                acs.keys() // Iterate over Ability keys
                    .map(|action| Capability {
                        // action is &Ability
                        resource: Resource::from(r.to_string()), // Convert RiString to String before From
                        action: action.to_string(),          // Convert Ability to String
                    })
                    .collect::<Vec<Capability>>()
            })
            .collect(),
        // Access proof CIDs directly via the proof() method
        c.proof().to_vec(),
    ))
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
    pub fn orbits(&self) -> impl Iterator<Item = &OrbitId> + '_ {
        self.capabilities.iter().filter_map(|c| c.resource.orbit())
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
                capabilities: u
                    .payload
                    .attenuation
                    .iter()
                    .map(extract_ucan_cap)
                    .collect::<Result<Vec<Capability>, CapExtractError>>()?,
                delegator: u.payload.issuer.to_string(),
                delegate: u.payload.audience.to_string(),
                parents: u.payload.proof.clone(),
                expiry: OffsetDateTime::from_unix_timestamp_nanos(
                    (u.payload.expiration.as_seconds() * 1_000_000_000.0) as i128,
                )
                .ok(),
                not_before: u.payload.not_before.and_then(|t| {
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
                        extract_siwe_cap(siwe_cap)?
                    }
                    None => {
                        // No capabilities found
                        (vec![], vec![])
                    }
                };

                Self {
                    capabilities, // Result from extract_siwe_cap or default
                    delegator: c.payload().iss.to_string(),
                    delegate: c.payload().aud.to_string(),
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
    pub fn orbits(&self) -> impl Iterator<Item = &OrbitId> + '_ {
        self.capabilities.iter().filter_map(|c| c.resource.orbit())
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
            capabilities: invocation
                .payload
                .attenuation
                .iter()
                .map(extract_ucan_cap)
                .collect::<Result<Vec<Capability>, CapExtractError>>()?,
            invoker: invocation.payload.issuer.to_string(),
            parents: invocation.payload.proof.clone(),
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
                    revoker: c.payload().iss.to_string(),
                    revocation: r,
                }),
                _ => Err(RevocationError::InvalidTarget),
            },
        }
    }
}
