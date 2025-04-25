use crate::resource::{ResourceCapErr, ResourceId};
use cacaos::siwe_cacao::SiweCacao;
use libipld::{cbor::DagCborCodec, prelude::*};
use ssi::{
    dids::{DIDBuf, DIDURLBuf, InvalidDID, InvalidDIDURL},
    jwk::JWK,
    ucan::{Payload, Ucan},
    claims::jwt::NumericDate
};
use iri_string::validate::Error as UriStringError;
use time::error::ComponentRange as TimestampRangeError;
use std::str::FromStr;
use uuid::Uuid;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

pub use libipld::Cid;

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
        use std::ops::Deref;
        Ok(match self {
            Self::Ucan(u) => u.encode()?,
            Self::Cacao(c) => {
                // Use the imported engine and trait method
                URL_SAFE.encode(DagCborCodec.encode(c.deref())?)
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
            (Self::Cacao(Box::new(DagCborCodec.decode(&v)?)), v)
        })
    }
}

impl TinyCloudDelegation {
    pub fn from_bytes(b: &[u8]) -> Result<Self, EncodingError> {
        match DagCborCodec.decode(b) {
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
            Self::Cacao(c) => Ok(URL_SAFE.encode(DagCborCodec.encode(&c)?)),
        }
    }
    fn decode(s: &str) -> Result<(Self, Vec<u8>), EncodingError> {
        // Use the imported engine and trait method
        let v = URL_SAFE.decode(s)?;
        Ok((Self::Cacao(DagCborCodec.decode(&v)?), v))
    }
}

pub async fn make_invocation(
    invocation_target: Vec<ResourceId>,
    delegation: Cid,
    jwk: &JWK,
    verification_method: String,
    expiration: f64,
    not_before: Option<f64>,
    nonce: Option<String>,
) -> Result<Ucan, InvocationError> {
    Ok(Payload {
        issuer: DIDURLBuf::from_str(&verification_method)?,
        audience: DIDBuf::from_str(&verification_method.split('#').next().unwrap_or(&verification_method))?,
        not_before: not_before.map(NumericDate::try_from_seconds).transpose()?,
        expiration: NumericDate::try_from_seconds(expiration).map_err(InvocationError::NumericDateConversionError)?,
        nonce: Some(nonce.unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()))),
        facts: None,
        proof: vec![delegation.into()],
        attenuation: invocation_target
            .into_iter()
            .map(|t| t.try_into())
            .collect::<Result<Vec<ssi::ucan::Capability>, _>>()?,
    }
    .sign(jwk.get_algorithm().unwrap_or_default(), jwk)?)
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error(transparent)]
    ResourceCap(#[from] ResourceCapErr),
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
    IpldError(#[from] libipld::error::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

pub enum CapabilitiesQuery {
    All,
}
