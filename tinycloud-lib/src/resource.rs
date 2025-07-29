use ipld_core::cid::Cid;
use iri_string::types::UriString;
use multihash_codetable::{Code, MultihashDigest};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use ssi::dids::{DIDBuf, DIDURLBuf as DIDURL, DID};

use std::{convert::TryFrom, fmt, str::FromStr};
use thiserror::Error;

#[derive(
    Clone, Hash, PartialEq, Debug, Eq, SerializeDisplay, DeserializeFromStr, PartialOrd, Ord,
)]
pub struct OrbitId {
    base_did: DIDBuf,
    id: String,
}

impl OrbitId {
    pub fn new(base_did: DIDBuf, id: String) -> Self {
        Self { base_did, id }
    }

    pub fn did(&self) -> &DID {
        self.base_did.as_did()
    }

    pub fn suffix(&self) -> &str {
        &self.base_did.as_str()[4..]
    }

    pub fn name(&self) -> &str {
        &self.id
    }

    pub fn get_cid(&self) -> Cid {
        Cid::new_v1(
            0x55, // raw codec
            Code::Blake2b256.digest(self.to_string().as_bytes()),
        )
    }

    pub fn to_resource(
        self,
        service: Option<String>,
        path: Option<String>,
        fragment: Option<String>,
    ) -> ResourceId {
        ResourceId {
            orbit: self,
            service,
            path: path.map(|p| {
                if p.starts_with('/') {
                    p
                } else {
                    format!("/{p}")
                }
            }),
            fragment,
        }
    }
}

impl TryFrom<DIDURL> for OrbitId {
    type Error = KRIParseError;
    fn try_from(did: DIDURL) -> Result<Self, Self::Error> {
        match (
            &did,
            did.fragment().map(|f| f.to_string()), // Use fragment() method and convert to String
        ) {
            (bd, Some(id)) => Ok(Self {
                base_did: bd.did().to_owned(),
                id,
            }),
            _ => Err(KRIParseError::IncorrectForm),
        }
    }
}

#[derive(
    Clone, Hash, PartialEq, Debug, Eq, SerializeDisplay, DeserializeFromStr, PartialOrd, Ord,
)]
pub struct ResourceId {
    orbit: OrbitId,
    service: Option<String>,
    path: Option<String>,
    fragment: Option<String>,
}

impl ResourceId {
    pub fn orbit(&self) -> &OrbitId {
        &self.orbit
    }
    pub fn service(&self) -> Option<&str> {
        self.service.as_ref().map(|s| s.as_ref())
    }
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(|s| s.as_ref())
    }
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_ref().map(|s| s.as_ref())
    }
    pub fn extends(&self, base: &ResourceId) -> Result<(), ResourceCheckError> {
        if base.orbit() != self.orbit() {
            Err(ResourceCheckError::IncorrectOrbit)
        } else if base.service() != self.service() {
            Err(ResourceCheckError::IncorrectService)
        } else if base.fragment() != self.fragment() {
            Err(ResourceCheckError::IncorrectFragment)
        } else if !self
            .path()
            .unwrap_or("")
            .starts_with(base.path().unwrap_or(""))
        {
            Err(ResourceCheckError::DoesNotExtendPath)
        } else {
            Ok(())
        }
    }

    pub fn into_inner(self) -> (OrbitId, Option<String>, Option<String>, Option<String>) {
        (self.orbit, self.service, self.path, self.fragment)
    }

    pub fn get_cid(&self) -> Cid {
        Cid::new_v1(
            0x55, // raw codec
            Code::Blake2b256.digest(self.to_string().as_bytes()),
        )
    }
}

#[derive(Error, Debug)]
pub enum ResourceCapErr {
    #[error("Missing ResourceId fragment")]
    MissingAction,
    #[error("Invalid URI string for capability: {0}")]
    CapabilityUriParse(#[from] ssi::json_ld::iref::uri::InvalidUri<String>), // Add From implementation
}

// Removed TryInto<Capability> and TryFrom<&Capability> implementations
// as they are no longer needed with the new UCAN structure that uses Capabilities<A> directly

#[derive(Error, Debug)]
pub enum ResourceCheckError {
    #[error("Base and Extension Orbits do not match")]
    IncorrectOrbit,
    #[error("Base and Extension Services do not match")]
    IncorrectService,
    #[error("Base and Extension Fragments do not match")]
    IncorrectFragment,
    #[error("Extension does not extend path of Base")]
    DoesNotExtendPath,
}

impl fmt::Display for OrbitId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tinycloud:{}://{}", &self.suffix(), &self.id)
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.orbit)?;
        if let Some(s) = &self.service {
            write!(f, "/{s}")?
        };
        if let Some(p) = &self.path {
            write!(f, "{p}")?
        };
        if let Some(fr) = &self.fragment {
            write!(f, "#{fr}")?
        };
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum KRIParseError {
    #[error("Incorrect Structure")]
    IncorrectForm,
    #[error("Invalid URI string: {0}")]
    UriStringParse(#[from] iri_string::validate::Error),
    #[error("Invalid DID string: {0}")]
    DidParse(#[from] ssi::dids::InvalidDID<String>),
}

impl FromStr for OrbitId {
    type Err = KRIParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix("tinycloud:")
            .ok_or(KRIParseError::IncorrectForm)?;
        let p = match s.find("://") {
            Some(p) if p > 0 => p,
            _ => return Err(Self::Err::IncorrectForm),
        };
        let uri = UriString::from_str(&["dummy", &s[p..]].concat())?;
        match uri.authority_components().map(|a| {
            (
                a.host().to_string(),
                a.port(),
                a.userinfo(),
                uri.path_str(),
                uri.fragment(),
                uri.query_str(),
            )
        }) {
            Some((id, None, None, "", None, None)) => Ok(Self {
                base_did: ["did:", &s[..p]].concat().try_into()?,
                id,
            }),
            _ => Err(Self::Err::IncorrectForm),
        }
    }
}

impl FromStr for ResourceId {
    type Err = KRIParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix("tinycloud:")
            .ok_or(KRIParseError::IncorrectForm)?;
        let p = match s.find("://") {
            Some(p) if p > 0 => p,
            _ => return Err(Self::Err::IncorrectForm),
        };
        let uri = UriString::from_str(&["dummy", &s[p..]].concat())?;
        match uri.authority_components().map(|a| {
            (
                a.host(),
                a.userinfo(),
                uri.path_str().split_once('/').map(|(s, r)| match s {
                    "" => r.split_once('/').unwrap_or((r, "")),
                    _ => (s, r),
                }),
            )
        }) {
            Some((host, None, path)) => Ok(Self {
                orbit: OrbitId {
                    base_did: format!("did:{}", &s[..p]).parse()?,
                    id: host.into(),
                },
                service: path.map(|(s, _)| s.into()),
                path: path.map(|(_, pa)| format!("/{pa}")),
                fragment: uri.fragment().map(|s| s.to_string()),
            }),
            _ => Err(Self::Err::IncorrectForm),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let res: ResourceId = "tinycloud:ens:example.eth://orbit0/kv/path/to/image.jpg"
            .parse()
            .unwrap();

        assert_eq!("ens:example.eth", res.orbit().suffix());
        assert_eq!("did:ens:example.eth", res.orbit().did().as_str());
        assert_eq!("orbit0", res.orbit().name());
        assert_eq!("kv", res.service().unwrap());
        assert_eq!("/path/to/image.jpg", res.path().unwrap());
        assert_eq!(None, res.fragment().as_ref());

        let res2: ResourceId = "tinycloud:ens:example.eth://orbit0#peer".parse().unwrap();

        assert_eq!("ens:example.eth", res2.orbit().suffix());
        assert_eq!("did:ens:example.eth", res2.orbit().did().as_str());
        assert_eq!("orbit0", res2.orbit().name());
        assert_eq!(None, res2.service());
        assert_eq!(None, res2.path());
        assert_eq!("peer", res2.fragment().unwrap());

        let res3: ResourceId = "tinycloud:ens:example.eth://orbit0/kv#list"
            .parse()
            .unwrap();

        assert_eq!("kv", res3.service().unwrap());
        assert_eq!("/", res3.path().unwrap());
        assert_eq!("list", res3.fragment().unwrap());

        let res4: ResourceId = "tinycloud:ens:example.eth://orbit0/kv/#list"
            .parse()
            .unwrap();

        assert_eq!("kv", res4.service().unwrap());
        assert_eq!("/", res4.path().unwrap());
        assert_eq!("list", res4.fragment().unwrap());
    }

    #[test]
    fn failures() {
        let no_suffix: Result<ResourceId, _> = "tinycloud:://orbit0/kv/path/to/image.jpg".parse();
        assert!(no_suffix.is_err());

        let invalid_name: Result<ResourceId, _> =
            "tinycloud:ens:example.eth://or:bit0/kv/path/to/image.jpg".parse();
        assert!(invalid_name.is_err());
    }

    #[test]
    fn little_test() {
        let did: DIDURL = "did:pkh:eth:0xb1fef8ed913821b941a76de9fc7c41b90de3d37f#default"
            .parse()
            .unwrap();
        let _ = OrbitId::try_from(did).unwrap();
    }

    #[test]
    fn roundtrip() {
        let resource_uri: String = "tinycloud:ens:example.eth://orbit0/kv/prefix#list".into();
        let res4: ResourceId = resource_uri.parse().unwrap();
        assert_eq!(resource_uri, res4.to_string());
    }
}
