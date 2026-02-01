use crate::resource::ResourceId;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use cacaos::siwe_cacao::SiweCacao;
use iri_string::validate::Error as UriStringError;
use ssi::{
    claims::jwt::NumericDate,
    dids::{DIDBuf, DIDURLBuf, InvalidDID, InvalidDIDURL},
    jwk::JWK,
    ucan::{Payload, Ucan},
};
use std::str::FromStr;
use time::error::ComponentRange as TimestampRangeError;
use ucan_capabilities_object::Ability;
use uuid::Uuid;

pub use ipld_core::cid::Cid;
use serde_ipld_dagcbor;

pub trait HeaderEncode {
    fn encode(&self) -> Result<String, EncodingError>;
    fn decode(s: &str) -> Result<(Self, Vec<u8>), EncodingError>
    where
        Self: Sized;
}

#[derive(Clone, Debug)]
pub enum TinyCloudDelegation {
    Ucan(Box<Ucan>),
    Cacao(Box<SiweCacao>),
}

impl HeaderEncode for TinyCloudDelegation {
    fn encode(&self) -> Result<String, EncodingError> {
        Ok(match self {
            Self::Ucan(u) => u.encode()?,
            Self::Cacao(c) => {
                // Use the imported engine and trait method
                URL_SAFE.encode(serde_ipld_dagcbor::to_vec(c)?)
            }
        })
    }

    fn decode(s: &str) -> Result<(Self, Vec<u8>), EncodingError> {
        Ok(if s.contains('.') {
            (
                Self::Ucan(Box::new(Ucan::decode(s)?)),
                s.as_bytes().to_vec(),
            )
        } else {
            // Use the imported engine and trait method
            let v = URL_SAFE.decode(s)?;
            (
                Self::Cacao(Box::new(serde_ipld_dagcbor::from_slice(&v)?)),
                v,
            )
        })
    }
}

impl TinyCloudDelegation {
    pub fn from_bytes(b: &[u8]) -> Result<Self, EncodingError> {
        match serde_ipld_dagcbor::from_slice(b) {
            Ok(cacao) => Ok(Self::Cacao(Box::new(cacao))),
            Err(_) => Ok(Self::Ucan(Box::new(Ucan::decode(
                &String::from_utf8_lossy(b),
            )?))),
        }
    }
}

// turn everything into url safe, b64-cacao or jwt

pub type TinyCloudInvocation = Ucan;

impl HeaderEncode for TinyCloudInvocation {
    fn encode(&self) -> Result<String, EncodingError> {
        Ok(self.encode()?)
    }
    fn decode(s: &str) -> Result<(Self, Vec<u8>), EncodingError> {
        Ok((Self::decode(s)?, s.as_bytes().to_vec()))
    }
}

#[derive(Debug, Clone)]
pub enum TinyCloudRevocation {
    Cacao(SiweCacao),
}

impl HeaderEncode for TinyCloudRevocation {
    fn encode(&self) -> Result<String, EncodingError> {
        match self {
            // Use the imported engine and trait method
            Self::Cacao(c) => Ok(URL_SAFE.encode(serde_ipld_dagcbor::to_vec(c)?)),
        }
    }
    fn decode(s: &str) -> Result<(Self, Vec<u8>), EncodingError> {
        // Use the imported engine and trait method
        let v = URL_SAFE.decode(s)?;
        Ok((Self::Cacao(serde_ipld_dagcbor::from_slice(&v)?), v))
    }
}

pub fn make_invocation<A: IntoIterator<Item = Ability>>(
    invocation_target: impl IntoIterator<Item = (ResourceId, A)>,
    delegation: &Cid,
    jwk: &JWK,
    verification_method: &str,
    expiration: f64,
    not_before: Option<f64>,
    nonce: Option<String>,
    facts: Option<Vec<serde_json::Value>>,
) -> Result<Ucan, InvocationError> {
    Ok(Payload {
        issuer: DIDURLBuf::from_str(verification_method)?,
        audience: DIDBuf::from_str(
            verification_method
                .split('#')
                .next()
                .unwrap_or(verification_method),
        )?,
        not_before: not_before.map(NumericDate::try_from_seconds).transpose()?,
        expiration: NumericDate::try_from_seconds(expiration)
            .map_err(InvocationError::NumericDateConversionError)?,
        nonce: Some(nonce.unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()))),
        facts,
        proof: vec![*delegation],
        attenuation: {
            let mut caps = ucan_capabilities_object::Capabilities::new();
            for (resource, abilities) in invocation_target {
                caps.with_actions(resource.as_uri(), abilities.into_iter().map(|a| (a, [])));
            }
            caps
        },
    }
    .sign(jwk.get_algorithm().unwrap_or_default(), jwk)?)
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error("Timestamp component out of range: {0}")] // Add variant for ComponentRange
    TimestampRange(#[from] TimestampRangeError),
    #[error("Invalid date format: {0}")]
    NumericDateConversionError(#[from] ssi::claims::jwt::NumericDateConversionError),
    #[error(transparent)]
    UCAN(#[from] ssi::ucan::error::Error),
    #[error(transparent)]
    UriString(#[from] UriStringError),
    #[error("Invalid DID URL: {0}")]
    InvalidDIDURL(#[from] InvalidDIDURL<String>),
    #[error("Invalid DID: {0}")]
    InvalidDID(#[from] InvalidDID<String>),
}

#[derive(Debug, thiserror::Error)]
pub enum EncodingError {
    #[error(transparent)]
    SSIError(#[from] ssi::ucan::error::Error),
    #[error(transparent)]
    IpldEncode(#[from] serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>),
    #[error(transparent)]
    IpldDecode(#[from] serde_ipld_dagcbor::DecodeError<core::convert::Infallible>),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

pub enum CapabilitiesQuery {
    All,
}
