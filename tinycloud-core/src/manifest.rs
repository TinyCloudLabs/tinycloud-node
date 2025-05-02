use libp2p::{Multiaddr, PeerId};
use std::{convert::TryFrom, str::FromStr};
use thiserror::Error;
use tinycloud_lib::resource::OrbitId;
use tinycloud_lib::ssi::dids::document::verification_method;
use tinycloud_lib::ssi::{
    dids::{DIDURLBuf, Document, RelativeDIDURL, document::{Service, DIDVerificationMethod}, DIDResolver},
    one_or_many::OneOrMany,
};

/// An implementation of an Orbit Manifest.
///
/// Orbit Manifests are [DID Documents](https://www.w3.org/TR/did-spec-registries/#did-methods) used directly as the root of a capabilities
/// authorization framework. This enables Orbits to be managed using independant DID lifecycle management tools.
#[derive(Clone, Debug)]
pub struct Manifest {
    id: OrbitId,
    delegators: Vec<DIDURLBuf>,
    invokers: Vec<DIDURLBuf>,
    bootstrap_peers: BootstrapPeers,
}

impl Manifest {
    /// ID of the Orbit, usually a DID
    pub fn id(&self) -> &OrbitId {
        &self.id
    }

    /// The set of Peers discoverable from the Orbit Manifest.
    pub fn bootstrap_peers(&self) -> &BootstrapPeers {
        &self.bootstrap_peers
    }

    /// The set of [Verification Methods](https://www.w3.org/TR/did-core/#verification-methods) who are authorized to delegate any capability.
    pub fn delegators(&self) -> &[DIDURLBuf] {
        &self.delegators
    }

    /// The set of [Verification Methods](https://www.w3.org/TR/did-core/#verification-methods) who are authorized to invoke any capability.
    pub fn invokers(&self) -> &[DIDURLBuf] {
        &self.invokers
    }

    pub async fn resolve<D: DIDResolver>(
        id: &OrbitId,
        resolver: &D,
    ) -> Result<Option<Self>, ResolutionError> {
        let (md, doc, doc_md) = resolver.resolve(&id.did()).await;

        match (md.error, doc, doc_md.and_then(|d| d.deactivated)) {
            (Some(e), _, _) => Err(ResolutionError::Resolver(e)),
            (_, _, Some(true)) => Err(ResolutionError::Deactivated),
            (_, None, _) => Ok(None),
            (None, Some(d), None | Some(false)) => Ok(Some((d, id.name()).into())),
        }
    }
}

#[derive(Clone, Debug, Hash)]
pub struct BootstrapPeers {
    pub id: String,
    pub peers: Vec<BootstrapPeer>,
}

#[derive(Clone, Debug, Hash)]
pub struct BootstrapPeer {
    pub id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

impl<'a> From<(Document, &'a str)> for Manifest {
    fn from((d, n): (Document, &'a str)) -> Self {
        let bootstrap_peers = d
            .select_service(n)
            .and_then(|s| BootstrapPeers::try_from(s).ok())
            .unwrap_or_else(|| BootstrapPeers {
                id: n.into(),
                peers: vec![],
            });
        let (id, capability_delegation, capability_invocation, verification_method) = {
            (
                d.id,
                d.verification_relationships.capability_delegation,
                d.verification_relationships.capability_invocation,
                d.verification_method,
            )
        };
        Self {
            delegators: capability_delegation
                .or_else(|| verification_method.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|vm| id_from_vm(&id, vm))
                .collect(),
            invokers: capability_invocation
                .or_else(|| verification_method.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|vm| id_from_vm(&id, vm))
                .collect(),
            bootstrap_peers,
            id: OrbitId::new(
                id.split_once(':').map(|(_, s)| s.into()).unwrap_or(id),
                n.into(),
            ),
        }
    }
}

#[derive(Error, Debug)]
pub enum ResolutionError {
    #[error("DID Resolution Error: {0}")]
    Resolver(String),
    #[error("DID Deactivated")]
    Deactivated,
}

#[derive(Error, Debug)]
pub enum ServicePeersConversionError {
    #[error(transparent)]
    IdParse(<PeerId as FromStr>::Err),
    #[error("Missing TinyCloudOrbitPeer type string")]
    WrongType,
}

impl TryFrom<&Service> for BootstrapPeers {
    type Error = ServicePeersConversionError;
    fn try_from(s: &Service) -> Result<Self, Self::Error> {
        if s.type_.any(|t| t == "TinyCloudOrbitPeers") {
            Ok(Self {
                id: s
                    .id
                    .rsplit_once('#')
                    .map(|(_, id)| id)
                    .unwrap_or_else(|| &s.id)
                    .into(),
                peers: s
                    .service_endpoint
                    .as_ref()
                    .unwrap_or(&OneOrMany::Many(vec![]))
                    .into_iter()
                    // TODO parse peers from objects or multiaddrs
                    .filter_map(|_| None)
                    .collect(),
            })
        } else {
            Err(Self::Error::WrongType)
        }
    }
}

fn id_from_vm(did: &str, vm: DIDVerificationMethod) -> DIDURLBuf {
    match vm {
        DIDVerificationMethod::DIDURL(d) => d.to_buf(), // Assuming .to_buf() exists
        DIDVerificationMethod::RelativeDIDURL(f) => f.to_absolute(did).to_buf(), // Assuming .to_buf() exists
        DIDVerificationMethod::Map(m) => {
            if let Ok(abs_did_url) = DIDURLBuf::from_str(&m.id) {
                abs_did_url
            } else if let Ok(rel_did_url) = RelativeDIDURL::from_str(&m.id) {
                rel_did_url.to_absolute(did).to_buf() // Assuming .to_buf() exists
            } else {
                // HACK well-behaved did methods should not allow id's which lead to this path
                // This part might need adjustment depending on DIDURLBuf's structure
                DIDURLBuf::from_string(m.id).unwrap() // Assuming a constructor like this
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use tinycloud_lib::resolver::DID_METHODS;
    use tinycloud_lib::ssi::{
        dids::{DIDURLBuf, Source},
        jwk::JWK,
    };

    #[tokio::test]
    async fn basic_manifest() {
        let j = JWK::generate_secp256k1().unwrap();
        let did: DIDURLBuf = DID_METHODS
            .generate(&Source::KeyAndPattern(&j, "pkh:tz"))
            .unwrap()
            .parse()
            .unwrap();
        // TODO: Fix this part if DIDURLBuf doesn't support fragment directly
        // let did_with_fragment = format!("{}#default", did);

        let _md = Manifest::resolve_dyn(&did.try_into().unwrap(), None)
            .await
            .unwrap()
            .unwrap();
    }
}
