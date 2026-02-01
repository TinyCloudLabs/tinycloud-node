use http::uri::Authority;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
use serde_with::{serde_as, DisplayFromStr};
use std::collections::HashMap;
use tinycloud_lib::{
    authorization::{make_invocation, InvocationError, TinyCloudDelegation, TinyCloudInvocation},
    cacaos::{
        siwe::{generate_nonce, Message, TimeStamp, Version as SIWEVersion},
        siwe_cacao::{Header as SiweHeader, Signature, SiweCacao},
    },
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    resource::{
        iri_string::types::{UriFragmentString, UriQueryString},
        Path, ResourceId, Service, SpaceId,
    },
    siwe_recap::{Ability, Capability},
    ssi::{
        claims::chrono::Timelike,
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::JWK,
        ucan::Payload,
    },
};
use tinycloud_sdk_rs::authorization::DelegationHeaders;

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    // { service: { path: [action] } }
    // e.g. { "kv": { "some/path": ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/del"] } }
    // Note: Actions use ReCap ability namespace format (e.g., "tinycloud.kv/get" where
    // "tinycloud.kv" is the ability namespace). This is distinct from the TinyCloud user
    // Space (data container) referenced by space_id below.
    pub abilities: HashMap<Service, HashMap<Path, Vec<Ability>>>,
    #[serde(with = "tinycloud_sdk_rs::serde_siwe::address")]
    pub address: [u8; 20],
    pub chain_id: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub domain: Authority,
    #[serde_as(as = "DisplayFromStr")]
    pub issued_at: TimeStamp,
    /// The TinyCloud user space (data container) that this session targets.
    /// Format: "tinycloud:pkh:eip155:{chainId}:{address}:{name}"
    /// Not to be confused with ReCap ability namespaces (action categories like "kv").
    pub space_id: SpaceId,
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
    /// Optional delegate URI for user-to-user delegation.
    /// If provided, this DID URL is used as the delegation target instead of
    /// deriving one from the jwk. Used when delegating to another user's DID.
    #[serde(default)]
    pub delegate_uri: Option<String>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSession {
    pub jwk: JWK,
    pub space_id: SpaceId,
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
    #[serde(with = "tinycloud_sdk_rs::serde_siwe::signature")]
    pub signature: Signature,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub delegation_header: DelegationHeaders,
    #[serde_as(as = "DisplayFromStr")]
    pub delegation_cid: Cid,
    pub jwk: JWK,
    /// The TinyCloud user space (data container) that this session is bound to.
    /// Not to be confused with ReCap ability namespaces (action categories like "kv").
    pub space_id: SpaceId,
    pub verification_method: String,
}

impl SessionConfig {
    fn into_message(self, delegate: &str) -> Result<Message, String> {
        use serde_json::Value;
        self.abilities
            .into_iter()
            .fold(
                Capability::<Value>::default(),
                |caps, (service, actions)| {
                    actions.into_iter().fold(caps, |mut caps, (path, action)| {
                        // Empty path means wildcard - use None to allow any path to extend
                        let path_opt = if path.as_str().is_empty() {
                            None
                        } else {
                            Some(path)
                        };
                        caps.with_actions(
                            self.space_id
                                .clone()
                                .to_resource(service.clone(), path_opt, None, None)
                                .as_uri(),
                            action.into_iter().map(|a| (a, [])),
                        );
                        caps
                    })
                },
            )
            .with_proofs(match &self.parents {
                Some(p) => p.as_slice(),
                None => &[],
            })
            .build_message(Message {
                scheme: None,
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
    /// Allows invoking ResourceId's with any SpaceId
    pub fn invoke_any<A: IntoIterator<Item = Ability>>(
        &self,
        actions: impl IntoIterator<Item = (ResourceId, A)>,
        facts: Option<Vec<serde_json::Value>>,
    ) -> Result<TinyCloudInvocation, InvocationError> {
        use tinycloud_lib::ssi::claims::chrono;
        // we have to use chrono here because the time crate doesnt support "now_utc" in wasm
        let now = chrono::Utc::now();
        // 60 seconds in the future
        let exp = ((now.timestamp() + 60i64) as f64) + (now.nanosecond() as f64 / 1_000_000_000.0);
        make_invocation(
            actions,
            &self.delegation_cid,
            &self.jwk,
            &self.verification_method,
            exp,
            None,
            None,
            facts,
        )
    }

    pub fn invoke<A: IntoIterator<Item = Ability>>(
        &self,
        actions: impl IntoIterator<
            Item = (
                Service,
                Path,
                Option<UriQueryString>,
                Option<UriFragmentString>,
                A,
            ),
        >,
        facts: Option<Vec<serde_json::Value>>,
    ) -> Result<TinyCloudInvocation, InvocationError> {
        self.invoke_any(
            actions
                .into_iter()
                .map(|(s, p, q, f, a)| (self.space_id.clone().to_resource(s, Some(p), q, f), a)),
            facts,
        )
    }

    /// Create a delegation UCAN from this session to another DID.
    /// Unlike invocations (which are self-issued for immediate use),
    /// delegations are issued to a recipient DID with longer expiry.
    pub fn create_delegation(
        &self,
        delegate_did: &str,
        space_id: &SpaceId,
        path: &Path,
        actions: Vec<Ability>,
        expiration_secs: f64,
        not_before_secs: Option<f64>,
    ) -> Result<DelegationResult, DelegationError> {
        use std::str::FromStr;

        // Build the resource from space_id, service "kv", and path
        let service: Service = "kv".parse().map_err(|_| DelegationError::InvalidService)?;
        let resource = space_id
            .clone()
            .to_resource(service, Some(path.clone()), None, None);

        // Collect action strings for the result before consuming them
        let action_strings: Vec<String> = actions.iter().map(|a| a.to_string()).collect();

        // Build capabilities (type parameter is the caveats type, using empty array)
        let mut caps = tinycloud_lib::ucan_capabilities_object::Capabilities::<[(); 0]>::new();
        caps.with_actions(resource.as_uri(), actions.into_iter().map(|a| (a, [])));

        // Build UCAN payload (F=serde_json::Value for facts, C=[();0] for caveats)
        let payload: Payload<serde_json::Value, [(); 0]> = Payload {
            issuer: DIDURLBuf::from_str(&self.verification_method)
                .map_err(DelegationError::InvalidIssuer)?,
            audience: DIDBuf::from_str(delegate_did).map_err(DelegationError::InvalidAudience)?,
            not_before: not_before_secs
                .map(NumericDate::try_from_seconds)
                .transpose()
                .map_err(DelegationError::InvalidNotBefore)?,
            expiration: NumericDate::try_from_seconds(expiration_secs)
                .map_err(DelegationError::InvalidExpiration)?,
            nonce: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            facts: None,
            proof: vec![self.delegation_cid],
            attenuation: caps,
        };

        // Sign the UCAN
        let ucan = payload
            .sign(self.jwk.get_algorithm().unwrap_or_default(), &self.jwk)
            .map_err(DelegationError::SigningError)?;

        // Encode the UCAN to JWT string
        let delegation_str = ucan.encode().map_err(DelegationError::EncodingError)?;

        // Calculate CID (using raw codec for JWT bytes, like invocations)
        let hash = Code::Blake3_256.digest(delegation_str.as_bytes());
        let cid = Cid::new_v1(0x55, hash); // 0x55 = raw codec

        Ok(DelegationResult {
            delegation: delegation_str,
            cid: cid.to_string(),
            delegate_did: delegate_did.to_string(),
            path: path.to_string(),
            actions: action_strings,
            expiry: expiration_secs,
        })
    }
}

/// Result of creating a delegation UCAN.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResult {
    /// Base64url-encoded UCAN JWT string
    pub delegation: String,
    /// CID of the delegation (for referencing in proof chains)
    pub cid: String,
    /// The DID of the delegate (recipient)
    pub delegate_did: String,
    /// Path scope of the delegation
    pub path: String,
    /// Actions delegated
    pub actions: Vec<String>,
    /// Expiration timestamp in seconds since epoch
    pub expiry: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("invalid service: must be 'kv'")]
    InvalidService,
    #[error("invalid issuer DID URL: {0}")]
    InvalidIssuer(#[from] tinycloud_lib::ssi::dids::InvalidDIDURL<String>),
    #[error("invalid audience DID: {0}")]
    InvalidAudience(tinycloud_lib::ssi::dids::InvalidDID<String>),
    #[error("invalid not_before timestamp: {0}")]
    InvalidNotBefore(tinycloud_lib::ssi::claims::jwt::NumericDateConversionError),
    #[error("invalid expiration timestamp: {0}")]
    InvalidExpiration(tinycloud_lib::ssi::claims::jwt::NumericDateConversionError),
    #[error("failed to sign UCAN: {0}")]
    SigningError(tinycloud_lib::ssi::ucan::error::Error),
    #[error("failed to encode UCAN: {0}")]
    EncodingError(tinycloud_lib::ssi::ucan::error::Error),
}

pub fn prepare_session(config: SessionConfig) -> Result<PreparedSession, Error> {
    let mut jwk = match &config.jwk {
        Some(k) => k.clone(),
        None => JWK::generate_ed25519()?,
    };
    jwk.algorithm = Some(tinycloud_lib::ssi::jwk::Algorithm::EdDSA);

    // Determine the verification method (delegation target)
    let verification_method = if let Some(delegate_uri) = &config.delegate_uri {
        // For user-to-user delegation: use the provided delegate URI directly
        delegate_uri.clone()
    } else {
        // For session key delegation: derive from the JWK
        // HACK bit of a hack here, because we know exactly how did:key works
        // ideally we should use the did resolver to resolve the DID and find the
        // right verification method, to support any arbitrary method.
        let mut vm = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = vm
            .rsplit_once(':')
            .ok_or_else(|| Error::UnableToGenerateSIWEMessage("Failed to calculate DID VM".into()))?
            .1
            .to_string();
        // Create a proper DID URL with fragment: did:key:z6Mk...#z6Mk...
        vm.push('#');
        vm.push_str(&fragment);
        vm
    };

    let space_id = config.space_id.clone();

    let siwe = config
        .into_message(&verification_method)
        .map_err(Error::UnableToGenerateSIWEMessage)?;

    Ok(PreparedSession {
        space_id,
        jwk,
        verification_method,
        siwe,
    })
}

pub fn complete_session_setup(signed_session: SignedSession) -> Result<Session, Error> {
    let delegation = SiweCacao::new(
        signed_session.session.siwe.into(),
        signed_session.signature,
        SiweHeader,
    );
    let serialised = serde_ipld_dagcbor::to_vec(&delegation)?;
    let hash = Code::Blake3_256.digest(&serialised);
    // Use raw codec 0x55 to match server behavior
    // Server always returns CIDs with raw codec for consistency
    let delegation_cid = Cid::new_v1(0x55, hash);
    let delegation_header =
        DelegationHeaders::new(TinyCloudDelegation::Cacao(Box::new(delegation)));

    Ok(Session {
        delegation_header,
        delegation_cid,
        jwk: signed_session.session.jwk,
        space_id: signed_session.session.space_id,
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
    UnableToGenerateCid(#[from] EncodeError<std::collections::TryReserveError>),
}

#[cfg(test)]
pub mod test {
    use super::*;
    use serde_json::json;
    pub fn test_session() -> Session {
        let config = json!({
            "abilities": {
                "kv": {
                    "path": vec![
                        "tinycloud.kv/put",
                        "tinycloud.kv/get",
                        "tinycloud.kv/list",
                        "tinycloud.kv/del",
                        "tinycloud.kv/metadata"
                    ]
                },
            },
            "address": "0x7BD63AA37326a64d458559F44432103e3d6eEDE9",
            "chainId": 1u8,
            "domain": "example.com",
            "issuedAt": "2022-01-01T00:00:00.000Z",
            "spaceId": "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default",
            "expirationTime": "3000-01-01T00:00:00.000Z",
        });
        let prepared = prepare_session(serde_json::from_value(config).unwrap()).unwrap();
        let mut signed = serde_json::to_value(prepared).unwrap();
        signed.as_object_mut()
            .unwrap()
            .insert(
                "signature".into(),
                "361647d08fb3ac41b26d9300d80e1964e1b3e7960e5276b3c9f5045ae55171442287279c83fd8922f9238312e89336b1672be8778d078d7dc5107b8c913299721c".into()
            );
        complete_session_setup(serde_json::from_value(signed).unwrap()).unwrap()
    }

    #[test]
    fn create_session_and_invoke() {
        let s: Service = "kv".parse().unwrap();
        let p: Path = "path".parse().unwrap();
        let a: Ability = "tinycloud.kv/get".parse().unwrap();
        test_session()
            .invoke([(s, p, None, None, [a])])
            .expect("failed to create invocation");
    }
}
