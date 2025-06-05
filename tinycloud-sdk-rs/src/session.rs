use crate::authorization::DelegationHeaders;
use http::uri::Authority;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use siwe_recap::{Capability, ConvertError};
use std::collections::{BTreeMap, HashMap};
use time::{ext::NumericalDuration, Duration, OffsetDateTime};
use tinycloud_lib::{
    authorization::{make_invocation, InvocationError, TinyCloudInvocation},
    cacaos::{
        siwe::{generate_nonce, Message, TimeStamp, Version as SIWEVersion},
        siwe_cacao::SIWESignature,
    },
    libipld::Cid,
    resolver::DID_METHODS,
    resource::OrbitId,
    ssi::jwk::JWK,
};

#[serde_as]
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    // { service: { path: [action] } }
    // e.g. { "kv": { "some/path": ["get", "put", "del"] } }
    pub actions: HashMap<String, HashMap<String, Vec<String>>>,
    #[serde(with = "crate::serde_siwe::address")]
    pub address: [u8; 20],
    pub chain_id: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub domain: Authority,
    #[serde_as(as = "DisplayFromStr")]
    pub issued_at: TimeStamp,
    pub orbit_id: OrbitId,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub not_before: Option<TimeStamp>,
    #[serde_as(as = "DisplayFromStr")]
    pub expiration_time: TimeStamp,
    #[serde_as(as = "Option<Vec<DisplayFromStr>>")]
    #[serde(default)]
    pub parents: Option<Vec<Cid>>,
    #[serde(default)]
    pub jwk: Option<JWK>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSession {
    pub jwk: JWK,
    pub orbit_id: OrbitId,
    #[serde_as(as = "DisplayFromStr")]
    pub siwe: Message,
    pub verification_method: String,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSession {
    #[serde(flatten)]
    pub session: PreparedSession,
    #[serde(with = "crate::serde_siwe::signature")]
    pub signature: SIWESignature,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub delegation_header: DelegationHeaders,
    #[serde_as(as = "DisplayFromStr")]
    pub delegation_cid: Cid,
    pub jwk: JWK,
    pub orbit_id: OrbitId,
    pub verification_method: String,
}

impl SessionConfig {
    fn into_message(self, delegate: &str) -> Result<Message, String> {
        use serde_json::Value;
        self.actions
            .into_iter()
            .try_fold(
                Capability::<Value>::default(),
                |caps, (service, actions)| {
                    actions.into_iter().try_fold(caps, |mut caps, (path, action)| {
                    // weird type here cos we aren't using note benes
                    caps.with_actions_convert::<_, _, [BTreeMap<String, Value>; 0]>(
                        self.orbit_id
                            .clone()
                            .to_resource(Some(service.clone()), Some(path), None)
                            .to_string(),
                        action.into_iter().map(|a| (a, []))
                    )?;
                    Ok(caps)
                })
                },
            )
            .map_err(|e: ConvertError<_, _>| format!("error building capabilities: {e}"))?
            .with_proofs(match &self.parents {
                Some(p) => p.as_slice(),
                None => &[],
            })
            .build_message(Message {
                address: self.address,
                chain_id: self.chain_id,
                domain: self.domain,
                expiration_time: Some(self.expiration_time),
                issued_at: self.issued_at,
                nonce: generate_nonce(),
                not_before: self.not_before,
                request_id: None,
                statement: None,
                resources: vec![],
                uri: delegate
                    .try_into()
                    .map_err(|e| format!("failed to parse session key DID as a URI: {e}"))?,
                version: SIWEVersion::V1,
            })
            .map_err(|e| format!("error building Host SIWE message: {e}"))
    }
}

impl Session {
    pub async fn invoke(
        self,
        actions: Vec<(String, String, String)>,
    ) -> Result<TinyCloudInvocation, InvocationError> {
        let targets = actions
            .into_iter()
            .map(|(s, p, a)| self.orbit_id.clone().to_resource(Some(s), Some(p), Some(a)));
        let now = OffsetDateTime::now_utc();
        let nanos = now.nanosecond();
        let unix = now.unix_timestamp();
        // 60 seconds in the future
        let exp = (unix.seconds() + Duration::nanoseconds(nanos.into()) + Duration::MINUTE)
            .as_seconds_f64();
        make_invocation(
            targets.collect(),
            self.delegation_cid,
            &self.jwk,
            self.verification_method,
            exp,
            None,
            None,
        )
        .await
    }
}

pub async fn prepare_session(config: SessionConfig) -> Result<PreparedSession, Error> {
    let mut jwk = match &config.jwk {
        Some(k) => k.clone(),
        None => JWK::generate_ed25519()?,
    };
    jwk.algorithm = Some(tinycloud_lib::ssi::jwk::Algorithm::EdDSA);

    // HACK bit of a hack here, because we know exactly how did:key works
    // ideally we should use the did resolver to resolve the DID and find the
    // right verification method, to support any arbitrary method.
    let mut verification_method = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = verification_method
        .rsplit_once(':')
        .ok_or_else(|| Error::UnableToGenerateSIWEMessage("Failed to calculate DID VM".into()))?
        .1
        .to_string();
    verification_method.extend(fragment.chars());

    let orbit_id = config.orbit_id.clone();

    let siwe = config
        .into_message(&verification_method)
        .map_err(Error::UnableToGenerateSIWEMessage)?;

    Ok(PreparedSession {
        orbit_id,
        jwk,
        verification_method,
        siwe,
    })
}

pub fn complete_session_setup(signed_session: SignedSession) -> Result<Session, Error> {
    use tinycloud_lib::{
        authorization::TinyCloudDelegation,
        cacaos::siwe_cacao::SiweCacao,
        libipld::{cbor::DagCborCodec, multihash::Code, store::DefaultParams, Block},
    };
    let delegation = SiweCacao::new(
        signed_session.session.siwe.into(),
        signed_session.signature,
        None,
    );
    let delegation_cid =
        *Block::<DefaultParams>::encode(DagCborCodec, Code::Blake3_256, &delegation)
            .map_err(Error::UnableToGenerateCid)?
            .cid();
    let delegation_header =
        DelegationHeaders::new(TinyCloudDelegation::Cacao(Box::new(delegation)));

    Ok(Session {
        delegation_header,
        delegation_cid,
        jwk: signed_session.session.jwk,
        orbit_id: signed_session.session.orbit_id,
        verification_method: signed_session.session.verification_method,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to generate session key: {0}")]
    UnableToGenerateKey(#[from] tinycloud_lib::ssi::jwk::Error),
    #[error("unable to generate the DID of the session key: {0}")]
    UnableToGenerateDID(#[from] tinycloud_lib::ssi::dids::GenerateError),
    #[error("unable to generate the SIWE message to start the session: {0}")]
    UnableToGenerateSIWEMessage(String),
    #[error("unable to generate the CID: {0}")]
    UnableToGenerateCid(tinycloud_lib::libipld::error::Error),
    #[error("failed to translate response to JSON: {0}")]
    JSONSerializing(serde_json::Error),
    #[error("failed to parse input from JSON: {0}")]
    JSONDeserializing(serde_json::Error),
}

#[cfg(test)]
pub mod test {
    use super::*;
    use serde_json::json;
    pub async fn test_session() -> Session {
        let config = json!({
            "actions": { "kv": { "path": vec!["put", "get", "list", "del", "metadata"] },
            "capabilities": { "": vec!["read"] }},
            "address": "0x7BD63AA37326a64d458559F44432103e3d6eEDE9",
            "chainId": 1u8,
            "domain": "example.com",
            "issuedAt": "2022-01-01T00:00:00.000Z",
            "orbitId": "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9://default",
            "expirationTime": "3000-01-01T00:00:00.000Z",
        });
        let prepared = prepare_session(serde_json::from_value(config).unwrap())
            .await
            .unwrap();
        let mut signed = serde_json::to_value(prepared).unwrap();
        signed.as_object_mut()
            .unwrap()
            .insert(
                "signature".into(),
                "361647d08fb3ac41b26d9300d80e1964e1b3e7960e5276b3c9f5045ae55171442287279c83fd8922f9238312e89336b1672be8778d078d7dc5107b8c913299721c".into()
            );
        complete_session_setup(serde_json::from_value(signed).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn create_session_and_invoke() {
        test_session()
            .await
            .invoke(vec![("kv".into(), "path".into(), "get".into())])
            .await
            .expect("failed to create invocation");
    }
}
