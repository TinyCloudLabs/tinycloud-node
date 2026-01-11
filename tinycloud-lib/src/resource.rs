use ipld_core::cid::Cid;
pub use iri_string;
use iri_string::types::{UriFragmentString, UriQueryString, UriStr, UriString};
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use ssi::dids::{DIDBuf, DID};

use std::{convert::TryFrom, fmt, str::FromStr};
use thiserror::Error;

#[derive(Clone, Hash, PartialEq, Debug, Eq, Serialize, DeserializeFromStr, PartialOrd, Ord)]
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
    type Error = KRIParseError;

    // TODO finish this by doing validation
    fn try_from(n: String) -> Result<Self, Self::Error> {
        Ok(Self(n))
    }
}

impl FromStr for Name {
    type Err = KRIParseError;

    // TODO finish this by doing validation
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(
    Clone, Hash, PartialEq, Debug, Eq, SerializeDisplay, DeserializeFromStr, PartialOrd, Ord,
)]
pub struct SpaceId {
    base_did: DIDBuf,
    name: Name,
}

impl SpaceId {
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
        service: Service,
        path: Option<Path>,
        query: Option<UriQueryString>,
        fragment: Option<UriFragmentString>,
    ) -> ResourceId {
        ResourceId {
            space: self,
            service,
            path,
            query,
            fragment,
        }
    }
}

impl From<(DIDBuf, Name)> for SpaceId {
    fn from((base_did, name): (DIDBuf, Name)) -> Self {
        Self { base_did, name }
    }
}

#[derive(Clone, Hash, PartialEq, Debug, Eq, Serialize, DeserializeFromStr, PartialOrd, Ord)]
pub struct Service(String);

impl Service {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for Service {
    type Error = KRIParseError;

    // TODO finish this by doing validation
    fn try_from(n: String) -> Result<Self, Self::Error> {
        Ok(Self(n))
    }
}

impl FromStr for Service {
    type Err = KRIParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(Clone, Hash, PartialEq, Debug, Eq, Serialize, DeserializeFromStr, PartialOrd, Ord)]
pub struct Path(String);

impl Path {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for Path {
    type Error = KRIParseError;

    // TODO finish this by doing validation
    fn try_from(n: String) -> Result<Self, Self::Error> {
        Ok(Self(n))
    }
}

impl FromStr for Path {
    type Err = KRIParseError;

    // TODO finish this by doing validation
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(
    Clone, Hash, PartialEq, Debug, Eq, SerializeDisplay, DeserializeFromStr, PartialOrd, Ord,
)]
pub struct ResourceId {
    space: SpaceId,
    service: Service,
    path: Option<Path>,
    query: Option<UriQueryString>,
    fragment: Option<UriFragmentString>,
}

impl ResourceId {
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn service(&self) -> &Service {
        &self.service
    }
    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref()
    }
    pub fn query(&self) -> Option<&UriQueryString> {
        self.query.as_ref()
    }
    pub fn fragment(&self) -> Option<&UriFragmentString> {
        self.fragment.as_ref()
    }
    pub fn extends(&self, base: &ResourceId) -> Result<(), ResourceCheckError> {
        if base.space() != self.space() {
            Err(ResourceCheckError::IncorrectSpace)
        } else if base.service() != self.service() {
            Err(ResourceCheckError::IncorrectService)
        } else if base.fragment() != self.fragment() {
            Err(ResourceCheckError::IncorrectFragment)
        } else if match (
            self.path().map(|p| p.as_str()),
            base.path().map(|p| p.as_str()),
        ) {
            (Some(s), Some(b)) => !s.starts_with(b),
            (Some(_), None) | (None, None) => false,
            (None, Some(_)) => true,
        } {
            Err(ResourceCheckError::DoesNotExtendPath)
        } else {
            Ok(())
        }
    }

    pub fn into_inner(
        self,
    ) -> (
        SpaceId,
        Service,
        Option<Path>,
        Option<UriQueryString>,
        Option<UriFragmentString>,
    ) {
        (
            self.space,
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

    // Create the resource URI (safe because resource id is always a uri)
    pub fn as_uri(&self) -> UriString {
        unsafe { UriString::new_unchecked(self.to_string()) }
    }
}

#[derive(Error, Debug)]
pub enum ResourceCheckError {
    #[error("Base and Extension Spaces do not match")]
    IncorrectSpace,
    #[error("Base and Extension Services do not match")]
    IncorrectService,
    #[error("Base and Extension Fragments do not match")]
    IncorrectFragment,
    #[error("Extension does not extend path of Base")]
    DoesNotExtendPath,
}

impl fmt::Display for SpaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tinycloud:{}:{}", &self.suffix(), &self.name)
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", &self.space, self.service)?;
        if let Some(path) = self.path() {
            write!(f, "/{path}")?;
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

impl TryFrom<&UriStr> for SpaceId {
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

impl FromStr for SpaceId {
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
            uri.path_str().split_once('/').and_then(|(space, path)| {
                Some((
                    space.rsplit_once(':').and_then(|(suf, name)| {
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
                SpaceId::new(["did:", suf].concat().try_into()?, Name(name.to_string()))
                    .to_resource(
                        Service(service.to_string()),
                        path.map(|p| Path(p.to_string())),
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
        let res: ResourceId = "tinycloud:ens:example.eth:ns0/kv/path/to/image.jpg"
            .parse()
            .unwrap();

        assert_eq!("ens:example.eth", res.space().suffix());
        assert_eq!("did:ens:example.eth", res.space().did().as_str());
        assert_eq!("ns0", res.space().name().as_str());
        assert_eq!("kv", res.service().as_str());
        assert_eq!(Some("path/to/image.jpg"), res.path().map(|p| p.as_str()));
        assert_eq!(None, res.fragment().as_ref());
        assert_eq!(None, res.query().as_ref());

        let res2: ResourceId = "tinycloud:ens:example1.eth:ns1/service#peer"
            .parse()
            .unwrap();

        assert_eq!("ens:example1.eth", res2.space().suffix());
        assert_eq!("did:ens:example1.eth", res2.space().did().as_str());
        assert_eq!("ns1", res2.space().name().as_str());
        assert_eq!("service", res2.service().as_str());
        println!("{:#?}", res2.path());
        assert!(res2.path().is_none());
        assert_eq!("peer", res2.fragment().unwrap().as_str());

        let res3: ResourceId = "tinycloud:ens:example2.eth:ns2/kv/#list".parse().unwrap();

        assert_eq!("ens:example2.eth", res3.space().suffix());
        assert_eq!("did:ens:example2.eth", res3.space().did().as_str());
        assert_eq!("ns2", res3.space().name().as_str());
        assert_eq!("kv", res3.service().as_str());
        assert_eq!(Some(""), res3.path().map(|p| p.as_str()));
        assert_eq!("list", res3.fragment().unwrap());

        let res4: ResourceId = "tinycloud:ens:example3.eth:ns3/other/path/#list"
            .parse()
            .unwrap();

        assert_eq!("ens:example3.eth", res4.space().suffix());
        assert_eq!("did:ens:example3.eth", res4.space().did().as_str());
        assert_eq!("ns3", res4.space().name().as_str());
        assert_eq!("other", res4.service().as_str());
        assert_eq!(Some("path/"), res4.path().map(|s| s.as_str()));
        assert_eq!("list", res4.fragment().unwrap());
    }

    #[test]
    fn failures() {
        let no_suffix: Result<ResourceId, _> = "tinycloud::ns0/kv/path/to/image.jpg".parse();
        assert!(no_suffix.is_err());

        let invalid_name: Result<ResourceId, _> =
            "tinycloud:ens:example.eth:/kv/path/to/image.jpg".parse();
        assert!(invalid_name.is_err());
    }

    #[test]
    fn little_test() {
        let _: SpaceId = "tinycloud:pkh:eth:0xb1fef8ed913821b941a76de9fc7c41b90de3d37f:default"
            .parse()
            .unwrap();
    }

    #[test]
    fn roundtrip() {
        let resource_uri: String = "tinycloud:ens:example.eth:ns0/kv/prefix#list".into();
        let res: ResourceId = resource_uri.parse().unwrap();
        assert_eq!(resource_uri, res.to_string());
    }
}
