use libp2p::{Multiaddr, PeerId};
use std::{convert::TryFrom, str::FromStr};
use thiserror::Error;
use tinycloud_lib::resource::OrbitId;
use tinycloud_lib::ssi::dids::document::verification_method::ValueOrReference;
use tinycloud_lib::ssi::dids::resolution::Output;
use tinycloud_lib::ssi::dids::DID;
use tinycloud_lib::ssi::{
    dids::{document::Service, DIDResolver, DIDURLBuf, Document},
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
        let Output {
            document: doc,
            document_metadata: doc_md,
            ..
        } = resolver.resolve(id.did()).await?;

        match (doc, doc_md.deactivated) {
            (_, Some(true)) => Err(ResolutionError::Deactivated),
            (d, _) => Ok(Some((d.into_document(), id.name()).into())),
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
            .service(n)
            .and_then(|s| BootstrapPeers::try_from(s).ok())
            .unwrap_or_else(|| BootstrapPeers {
                id: n.into(),
                peers: vec![],
            });

        Self {
            delegators: get_authorised_parties(
                &d.id,
                d.verification_relationships.capability_delegation,
                &d.verification_relationships.authentication,
            ),
            invokers: get_authorised_parties(
                &d.id,
                d.verification_relationships.capability_invocation,
                &d.verification_relationships.authentication,
            ),
            bootstrap_peers,
            id: OrbitId::new(d.id, n.into()),
        }
    }
}

#[derive(Error, Debug)]
pub enum ResolutionError {
    #[error("DID Resolution Error: {0}")]
    Resolver(#[from] tinycloud_lib::ssi::dids::resolution::Error),
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

fn id_from_vm(did: &DID, vm: ValueOrReference) -> DIDURLBuf {
    match vm {
        ValueOrReference::Reference(r) => r.resolve(did).into_owned(),
        ValueOrReference::Value(v) => v.id,
    }
}

fn get_authorised_parties(
    did: &DID,
    main: Vec<ValueOrReference>,
    default: &[ValueOrReference],
) -> Vec<DIDURLBuf> {
    if main.is_empty() {
        default
            .iter()
            .map(|vm| id_from_vm(did, vm.clone()))
            .collect()
    } else {
        main.into_iter()
            .map(|vm| id_from_vm(did, vm.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use tinycloud_lib::resolver::DID_METHODS;
    use tinycloud_lib::ssi::dids::AnyDidMethod;
    use tinycloud_lib::ssi::{dids::DIDURLBuf, jwk::JWK};

    #[tokio::test]
    async fn basic_manifest() {
        let j = JWK::generate_secp256k1();
        let mut did = DID_METHODS.generate(&j, "pkh:eth").unwrap().to_string();
        did.push_str("#default");
        let did: DIDURLBuf = did.parse().unwrap();

        println!("DID: {did:#?}");

        let md = Manifest::resolve(&did.try_into().unwrap(), &AnyDidMethod::default())
            .await
            .unwrap()
            .unwrap();
        println!("Manifest: {md:#?}");
    }
}
