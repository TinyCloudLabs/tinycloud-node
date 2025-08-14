use ipld_core::cid::Cid;
pub use iri_string;
use iri_string::types::{UriFragmentString, UriQueryString, UriStr};
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use ssi::dids::{DIDBuf, DID};

use std::{convert::TryFrom, fmt, str::FromStr};
use thiserror::Error;

#[derive(Clone, Hash, PartialEq, Debug, Eq, Serialize, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for Name {
    // TODO finish this
    type Error = &'static str;
    fn try_from(n: String) -> Result<Self, Self::Error> {
        Ok(Self(n))
    }
}

#[derive(
    Clone, Hash, PartialEq, Debug, Eq, SerializeDisplay, DeserializeFromStr, PartialOrd, Ord,
)]
pub struct OrbitId {
    base_did: DIDBuf,
    name: Name,
}

impl OrbitId {
    pub fn new(base_did: DIDBuf, name: Name) -> Self {
        Self { base_did, name }
    }

    pub fn did(&self) -> &DID {
        self.base_did.as_did()
    }

    pub fn suffix(&self) -> &str {
        &self.base_did.as_str()[4..]
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn get_cid(&self) -> Cid {
        Cid::new_v1(
            0x55, // raw codec
            Code::Blake2b256.digest(self.to_string().as_bytes()),
        )
    }

    pub fn to_resource(
        self,
        service: Segment,
        path: Vec<Segment>,
        query: Option<UriQueryString>,
        fragment: Option<UriFragmentString>,
    ) -> ResourceId {
        ResourceId {
            orbit: self,
            service,
            path,
            query,
            fragment,
        }
    }
}

impl From<(DIDBuf, Name)> for OrbitId {
    fn from((base_did, name): (DIDBuf, Name)) -> Self {
        Self { base_did, name }
    }
}

#[derive(Clone, Hash, PartialEq, Debug, Eq, Serialize, PartialOrd, Ord)]
pub struct Segment(String);

impl Segment {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(
    Clone, Hash, PartialEq, Debug, Eq, SerializeDisplay, DeserializeFromStr, PartialOrd, Ord,
)]
pub struct ResourceId {
    orbit: OrbitId,
    service: Segment,
    path: Vec<Segment>,
    query: Option<UriQueryString>,
    fragment: Option<UriFragmentString>,
}

impl ResourceId {
    pub fn orbit(&self) -> &OrbitId {
        &self.orbit
    }
    pub fn service(&self) -> &Segment {
        &self.service
    }
    pub fn path(&self) -> &[Segment] {
        self.path.as_slice()
    }
    pub fn query(&self) -> Option<&UriQueryString> {
        self.query.as_ref()
    }
    pub fn fragment(&self) -> Option<&UriFragmentString> {
        self.fragment.as_ref()
    }
    pub fn extends(&self, base: &ResourceId) -> Result<(), ResourceCheckError> {
        if base.orbit() != self.orbit() {
            Err(ResourceCheckError::IncorrectOrbit)
        } else if base.service() != self.service() {
            Err(ResourceCheckError::IncorrectService)
        } else if base.fragment() != self.fragment() {
            Err(ResourceCheckError::IncorrectFragment)
        } else if base.path().len() > self.path().len()
            || !self
                .path()
                .iter()
                .zip(base.path().iter())
                .all(|(seg, base_seg)| seg == base_seg)
        {
            Err(ResourceCheckError::DoesNotExtendPath)
        } else {
            Ok(())
        }
    }

    pub fn into_inner(
        self,
    ) -> (
        OrbitId,
        Segment,
        Vec<Segment>,
        Option<UriQueryString>,
        Option<UriFragmentString>,
    ) {
        (
            self.orbit,
            self.service,
            self.path,
            self.query,
            self.fragment,
        )
    }

    pub fn get_cid(&self) -> Cid {
        Cid::new_v1(
            0x55, // raw codec
            Code::Blake2b256.digest(self.to_string().as_bytes()),
        )
    }
}

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
        write!(f, "tinycloud:{}:{}", &self.suffix(), &self.name)
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", &self.orbit, self.service)?;
        for segment in self.path() {
            write!(f, "/{segment}")?;
        }
        if let Some(query) = self.query() {
            write!(f, "?{query}")?
        };
        if let Some(fr) = &self.fragment() {
            write!(f, "#{fr}")?
        };
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum KRIParseError {
    #[error("Incorrect Structure")]
    IncorrectForm,
    #[error("Invalid Name")]
    InvalidName,
    #[error("Invalid Service")]
    InvalidService,
    #[error("Invalid Path")]
    InvalidPath,
    #[error("Invalid URI string: {0}")]
    UriStringParse(#[from] iri_string::validate::Error),
    #[error("Invalid DID string: {0}")]
    DidParse(#[from] ssi::dids::InvalidDID<String>),
}

impl TryFrom<&UriStr> for OrbitId {
    type Error = KRIParseError;
    fn try_from(uri: &UriStr) -> Result<Self, Self::Error> {
        if uri.scheme_str() != "tinycloud"
            || uri.authority_str().is_some()
            || uri.query_str().is_some()
            || uri.fragment().is_some()
            || uri.path_str().ends_with(':')
            || uri.path_str().contains('/')
            || !uri.is_normalized()
        {
            Err(KRIParseError::IncorrectForm)
        } else if let Some((suf, name)) = uri.path_str().rsplit_once(':').and_then(|(suf, name)| {
            if name.is_empty() {
                None
            } else {
                Some((suf, name))
            }
        }) {
            Ok(Self::new(
                ["did:", suf].concat().try_into()?,
                Name(name.to_string()),
            ))
        } else {
            Err(KRIParseError::IncorrectForm)
        }
    }
}

impl FromStr for OrbitId {
    type Err = KRIParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UriStr::new(s)?.try_into()
    }
}

impl TryFrom<&UriStr> for ResourceId {
    type Error = KRIParseError;
    fn try_from(uri: &UriStr) -> Result<Self, Self::Error> {
        if uri.scheme_str() != "tinycloud"
            || uri.authority_str().is_some()
            || !uri.path_str().contains('/')
            || !uri.is_normalized()
        {
            Err(KRIParseError::IncorrectForm)
        } else if let Some(((suf, name), (service, path))) =
            uri.path_str().split_once('/').and_then(|(orbit, path)| {
                Some((
                    orbit.rsplit_once(':').and_then(|(suf, name)| {
                        if name.is_empty() {
                            None
                        } else {
                            Some((suf, name))
                        }
                    })?,
                    path.split_once('/')
                        .map_or((path, None), |(service, path)| (service, Some(path))),
                ))
            })
        {
            Ok(
                OrbitId::new(["did:", suf].concat().try_into()?, Name(name.to_string()))
                    .to_resource(
                        Segment(service.to_string()),
                        match path {
                            None => Vec::new(),
                            Some(p) => p.split('/').map(|s| Segment(s.to_string())).collect(),
                        },
                        uri.query().map(|q| q.into()),
                        uri.fragment().map(|q| q.into()),
                    ),
            )
        } else {
            Err(KRIParseError::IncorrectForm)
        }
    }
}

impl FromStr for ResourceId {
    type Err = KRIParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UriStr::new(s)?.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let res: ResourceId = "tinycloud:ens:example.eth:orbit0/kv/path/to/image.jpg"
            .parse()
            .unwrap();

        assert_eq!("ens:example.eth", res.orbit().suffix());
        assert_eq!("did:ens:example.eth", res.orbit().did().as_str());
        assert_eq!("orbit0", res.orbit().name().as_str());
        assert_eq!("kv", res.service().as_str());
        assert_eq!(
            "path/to/image.jpg",
            res.path()
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
                .join("/")
        );
        assert_eq!(None, res.fragment().as_ref());
        assert_eq!(None, res.query().as_ref());

        let res2: ResourceId = "tinycloud:ens:example1.eth:orbit1/service#peer"
            .parse()
            .unwrap();

        assert_eq!("ens:example1.eth", res2.orbit().suffix());
        assert_eq!("did:ens:example1.eth", res2.orbit().did().as_str());
        assert_eq!("orbit1", res2.orbit().name().as_str());
        assert_eq!("service", res2.service().as_str());
        println!("{:#?}", res2.path());
        assert!(res2.path().is_empty());
        assert_eq!("peer", res2.fragment().unwrap().as_str());

        let res3: ResourceId = "tinycloud:ens:example2.eth:orbit2/kv/#list"
            .parse()
            .unwrap();

        assert_eq!("ens:example2.eth", res3.orbit().suffix());
        assert_eq!("did:ens:example2.eth", res3.orbit().did().as_str());
        assert_eq!("orbit2", res3.orbit().name().as_str());
        assert_eq!("kv", res3.service().as_str());
        assert_eq!(1, res3.path().len());
        assert_eq!(
            "",
            res3.path()
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
                .join("/")
        );
        assert_eq!("list", res3.fragment().unwrap());

        let res4: ResourceId = "tinycloud:ens:example3.eth:orbit3/other/path/#list"
            .parse()
            .unwrap();

        assert_eq!("ens:example3.eth", res4.orbit().suffix());
        assert_eq!("did:ens:example3.eth", res4.orbit().did().as_str());
        assert_eq!("orbit3", res4.orbit().name().as_str());
        assert_eq!("other", res4.service().as_str());
        assert_eq!(2, res4.path().len());
        assert_eq!(
            "path/",
            res4.path()
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
                .join("/")
        );
        assert_eq!("list", res4.fragment().unwrap());
    }

    #[test]
    fn failures() {
        let no_suffix: Result<ResourceId, _> = "tinycloud::orbit0/kv/path/to/image.jpg".parse();
        assert!(no_suffix.is_err());

        let invalid_name: Result<ResourceId, _> =
            "tinycloud:ens:example.eth:/kv/path/to/image.jpg".parse();
        assert!(invalid_name.is_err());
    }

    #[test]
    fn little_test() {
        let _: OrbitId = "tinycloud:pkh:eth:0xb1fef8ed913821b941a76de9fc7c41b90de3d37f:default"
            .parse()
            .unwrap();
    }

    #[test]
    fn roundtrip() {
        let resource_uri: String = "tinycloud:ens:example.eth:orbit0/kv/prefix#list".into();
        let res: ResourceId = resource_uri.parse().unwrap();
        assert_eq!(resource_uri, res.to_string());
    }
}
