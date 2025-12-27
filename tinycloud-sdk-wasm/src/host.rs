use http::uri::Authority;
use serde::Deserialize;
use serde_json::Value;
use serde_with::{serde_as, DisplayFromStr};
use tinycloud_lib::{
    authorization::TinyCloudDelegation,
    cacaos::{
        siwe::{generate_nonce, Message, TimeStamp, Version},
        siwe_cacao::{Header as SiweHeader, Signature, SiweCacao},
    },
    resource::NamespaceId,
    siwe_recap::{Ability, Capability},
};

use tinycloud_sdk_rs::authorization::DelegationHeaders;

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostConfig {
    #[serde(with = "tinycloud_sdk_rs::serde_siwe::address")]
    pub address: [u8; 20],
    pub chain_id: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub domain: Authority,
    #[serde_as(as = "DisplayFromStr")]
    pub issued_at: TimeStamp,
    pub namespace_id: NamespaceId,
    pub peer_id: String,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedMessage {
    #[serde_as(as = "DisplayFromStr")]
    pub siwe: Message,
    #[serde(with = "tinycloud_sdk_rs::serde_siwe::signature")]
    pub signature: Signature,
}

impl TryFrom<HostConfig> for Message {
    type Error = String;
    fn try_from(c: HostConfig) -> Result<Self, String> {
        let mut caps = Capability::<Value>::default();
        let ab: Ability = "tinycloud.namespace/host".parse().unwrap();
        caps.with_action(
            c.namespace_id
                .to_resource("namespace".parse().unwrap(), None, None, None)
                .as_uri(),
            ab,
            [],
        );
        caps.build_message(Self {
            scheme: None,
            address: c.address,
            chain_id: c.chain_id,
            domain: c.domain,
            issued_at: c.issued_at,
            uri: c
                .peer_id
                .try_into()
                .map_err(|e| format!("error parsing peer as a URI: {e}"))?,
            nonce: generate_nonce(),
            statement: None,
            resources: vec![],
            version: Version::V1,
            not_before: None,
            expiration_time: None,
            request_id: None,
        })
        .map_err(|e| format!("error building Host SIWE message: {e}"))
    }
}

pub fn generate_host_siwe_message(config: HostConfig) -> Result<Message, Error> {
    Message::try_from(config).map_err(Error::UnableToGenerateSIWEMessage)
}

pub fn siwe_to_delegation_headers(signed_message: SignedMessage) -> DelegationHeaders {
    DelegationHeaders::new(TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
        signed_message.siwe.into(),
        signed_message.signature,
        SiweHeader,
    ))))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to generate the SIWE message: {0}")]
    UnableToGenerateSIWEMessage(String),
}
