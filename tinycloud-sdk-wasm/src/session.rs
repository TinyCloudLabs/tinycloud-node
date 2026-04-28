use http::uri::Authority;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
use serde_with::{serde_as, DisplayFromStr};
use std::collections::HashMap;
use tinycloud_auth::{
    authorization::{
        make_invocation, InvocationError, InvocationOptions, TinyCloudDelegation,
        TinyCloudInvocation,
    },
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

type AbilitiesMap = HashMap<Service, HashMap<Path, Vec<Ability>>>;

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    // { service: { path: [action] } }
    // e.g. { "kv": { "some/path": ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/del"] } }
    // Note: Actions use ReCap ability namespace format (e.g., "tinycloud.kv/get" where
    // "tinycloud.kv" is the ability namespace). This is distinct from the TinyCloud user
    // Space (data container) referenced by space_id below.
    pub abilities: AbilitiesMap,
    /// Optional per-space abilities map. When present, this replaces the
    /// legacy "primary space + additional spaces all share abilities" shape
    /// and allows one SIWE to request different capabilities in different
    /// spaces.
    #[serde(default)]
    pub space_abilities: Option<HashMap<SpaceId, AbilitiesMap>>,
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
    /// Additional spaces to include in this session's capabilities.
    /// Key is a logical name (e.g., "public"), value is the SpaceId.
    /// All additional spaces receive the same abilities as the primary space.
    #[serde(default)]
    pub additional_spaces: Option<HashMap<String, SpaceId>>,
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
    /// Optional SIWE nonce. If provided, this nonce is used in the SIWE message
    /// instead of generating a random one. Allows the SDK caller to pass through
    /// a server-issued nonce for replay protection.
    #[serde(default)]
    pub nonce: Option<String>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSession {
    pub jwk: JWK,
    pub space_id: SpaceId,
    #[serde(default)]
    pub additional_spaces: Option<HashMap<String, SpaceId>>,
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
    #[serde(default)]
    pub additional_spaces: Option<HashMap<String, SpaceId>>,
    pub verification_method: String,
}

impl SessionConfig {
    fn into_message(self, delegate: &str) -> Result<Message, String> {
        use serde_json::Value;

        let space_abilities = match &self.space_abilities {
            Some(explicit) => explicit.clone(),
            None => {
                // Legacy shape: collect all spaces and apply the same
                // abilities map to each one.
                let mut all_spaces = vec![self.space_id.clone()];
                if let Some(ref additional) = self.additional_spaces {
                    for space_id in additional.values() {
                        all_spaces.push(space_id.clone());
                    }
                }

                all_spaces
                    .into_iter()
                    .map(|space_id| (space_id, self.abilities.clone()))
                    .collect()
            }
        };

        space_abilities
            .into_iter()
            .fold(
                Capability::<Value>::default(),
                |caps, (space_id, abilities)| {
                    abilities.iter().fold(caps, |caps, (service, actions)| {
                        actions.iter().fold(caps, |mut caps, (path, action)| {
                            let path_opt = if path.as_str().is_empty() {
                                None
                            } else {
                                Some(path.clone())
                            };
                            caps.with_actions(
                                space_id
                                    .clone()
                                    .to_resource(service.clone(), path_opt, None, None)
                                    .as_uri(),
                                action.iter().map(|a| (a.clone(), [])),
                            );
                            caps
                        })
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
                nonce: self.nonce.unwrap_or_else(generate_nonce),
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
        use tinycloud_auth::ssi::claims::chrono;
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
            InvocationOptions {
                facts,
                ..Default::default()
            },
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

    /// Create a multi-resource delegation UCAN from this session to another DID.
    ///
    /// Unlike invocations (which are self-issued for immediate use), delegations
    /// are issued to a recipient DID with longer expiry. This method produces a
    /// **single** UCAN that encodes every `(service, path, actions)` entry in
    /// the supplied abilities map, scoped to `space_id`. The resulting UCAN has
    /// one `attenuation` (ReCap capabilities) object with multiple resource URIs
    /// — one per `(service, path)` tuple — each carrying its own action set.
    ///
    /// This is the delegation-side mirror of [`SessionConfig::into_message`]
    /// which encodes the same multi-resource shape into a SIWE recap at
    /// sign-in. Both sides read from
    /// `HashMap<Service, HashMap<Path, Vec<Ability>>>` so a session can
    /// re-delegate exactly the capabilities it holds, or a strict subset,
    /// without any shape conversion.
    ///
    /// # Arguments
    /// * `delegate_did` - The recipient DID (audience of the UCAN).
    /// * `space_id` - The TinyCloud user space the delegation targets.
    /// * `abilities` - Service → path → actions map. An empty map is an error;
    ///   an empty action list under any (service, path) is also an error since
    ///   it would encode a useless delegation.
    /// * `expiration_secs` - UCAN expiration timestamp in seconds since epoch.
    /// * `not_before_secs` - Optional UCAN not-before timestamp.
    ///
    /// # Returns
    /// A [`DelegationResult`] with the signed UCAN JWT, its CID, the delegate
    /// DID, the expiry, and a `resources` list describing each
    /// `(service, space, path, actions)` entry that was granted. The
    /// `resources` list lets JS callers reconstruct the exact shape they sent
    /// without having to re-parse the UCAN.
    pub fn create_delegation(
        &self,
        delegate_did: &str,
        space_id: &SpaceId,
        abilities: HashMap<Service, HashMap<Path, Vec<Ability>>>,
        expiration_secs: f64,
        not_before_secs: Option<f64>,
    ) -> Result<DelegationResult, DelegationError> {
        use std::str::FromStr;

        if abilities.is_empty() {
            return Err(DelegationError::EmptyAbilities);
        }

        // Build capabilities (type parameter is the caveats type, using empty
        // array to match invocation / session capability encoding).
        //
        // We walk the full (service, path, actions) tree so that a single UCAN
        // encodes every entry. `Capabilities::with_actions` is keyed by the
        // resource URI, which already embeds (space, service, path), so
        // distinct (service, path) tuples naturally end up as distinct entries
        // in the underlying `att:` map. This is the same encoding path used
        // by `SessionConfig::into_message`.
        let mut caps = tinycloud_auth::ucan_capabilities_object::Capabilities::<[(); 0]>::new();
        let mut resources: Vec<DelegatedResource> = Vec::new();

        // Sort services and paths so the resulting `resources` vector is
        // deterministic regardless of HashMap iteration order. This keeps
        // test assertions stable and makes the JS side's read-back predictable.
        let mut services: Vec<(Service, HashMap<Path, Vec<Ability>>)> =
            abilities.into_iter().collect();
        services.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));

        for (service, paths_map) in services {
            if paths_map.is_empty() {
                return Err(DelegationError::EmptyPathsForService(service.to_string()));
            }

            let mut paths: Vec<(Path, Vec<Ability>)> = paths_map.into_iter().collect();
            paths.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));

            for (path, path_actions) in paths {
                if path_actions.is_empty() {
                    return Err(DelegationError::EmptyActionsForPath {
                        service: service.to_string(),
                        path: path.to_string(),
                    });
                }

                // Follow the same empty-path convention as `into_message`:
                // an empty-string path means "no path segment" (the resource
                // URI has no path component), which matches how the session's
                // own recap encodes space-wide grants.
                let path_opt = if path.as_str().is_empty() {
                    None
                } else {
                    Some(path.clone())
                };

                let resource = space_id
                    .clone()
                    .to_resource(service.clone(), path_opt, None, None);

                let action_strings: Vec<String> =
                    path_actions.iter().map(|a| a.to_string()).collect();

                // Extend the capability object with this (resource, actions)
                // pair. The ucan-capabilities-object crate keys internally by
                // resource URI, so each iteration adds a distinct entry.
                caps.with_actions(resource.as_uri(), path_actions.into_iter().map(|a| (a, [])));

                resources.push(DelegatedResource {
                    service: service.to_string(),
                    space: space_id.to_string(),
                    path: path.to_string(),
                    actions: action_strings,
                });
            }
        }

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
            expiry: expiration_secs,
            resources,
        })
    }
}

/// A single (service, space, path, actions) entry inside a delegation result.
///
/// Mirrors the manifest `PermissionEntry` shape that the JS SDK uses so the
/// client can reconstruct what it sent without having to re-parse the UCAN.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedResource {
    /// Service name, e.g. "kv", "sql", "duckdb", "capabilities".
    pub service: String,
    /// Full space id string, e.g. "tinycloud:pkh:eip155:1:0x....:default".
    pub space: String,
    /// Resource path; empty string if the resource URI had no path segment.
    pub path: String,
    /// Full-URN ability strings, e.g. ["tinycloud.kv/get", "tinycloud.kv/put"].
    pub actions: Vec<String>,
}

/// Result of creating a multi-resource delegation UCAN.
///
/// The `resources` field describes every `(service, space, path, actions)`
/// entry embedded in the UCAN's capability object. A single delegation may
/// carry grants for multiple services on multiple paths — the UCAN itself is
/// still one signed blob.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResult {
    /// Base64url-encoded UCAN JWT string
    pub delegation: String,
    /// CID of the delegation (for referencing in proof chains)
    pub cid: String,
    /// The DID of the delegate (recipient)
    pub delegate_did: String,
    /// Expiration timestamp in seconds since epoch
    pub expiry: f64,
    /// All (service, space, path, actions) entries granted by this delegation.
    /// Always non-empty on success.
    pub resources: Vec<DelegatedResource>,
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("abilities map must not be empty")]
    EmptyAbilities,
    #[error("service '{0}' has no paths in the abilities map")]
    EmptyPathsForService(String),
    #[error("service '{service}' path '{path}' has no actions in the abilities map")]
    EmptyActionsForPath { service: String, path: String },
    #[error("invalid issuer DID URL: {0}")]
    InvalidIssuer(#[from] tinycloud_auth::ssi::dids::InvalidDIDURL<String>),
    #[error("invalid audience DID: {0}")]
    InvalidAudience(tinycloud_auth::ssi::dids::InvalidDID<String>),
    #[error("invalid not_before timestamp: {0}")]
    InvalidNotBefore(tinycloud_auth::ssi::claims::jwt::NumericDateConversionError),
    #[error("invalid expiration timestamp: {0}")]
    InvalidExpiration(tinycloud_auth::ssi::claims::jwt::NumericDateConversionError),
    #[error("failed to sign UCAN: {0}")]
    SigningError(tinycloud_auth::ssi::ucan::error::Error),
    #[error("failed to encode UCAN: {0}")]
    EncodingError(tinycloud_auth::ssi::ucan::error::Error),
}

/// A single recap permission entry extracted from a signed SIWE message.
///
/// This is the inverse of what `SessionConfig::into_message` produces when it
/// writes resource capabilities into the SIWE `Resources:` list. The `service`,
/// `space`, and `path` fields are pulled from the parsed resource URI; `actions`
/// is the list of full-URN ability strings (e.g. `tinycloud.kv/get`).
///
/// Field names match the manifest `PermissionEntry` shape in the TypeScript SDK
/// so the JS side can consume this directly after `serde_wasm_bindgen::to_value`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedRecapEntry {
    /// Service name, e.g. "kv", "sql", "duckdb", "capabilities".
    pub service: String,
    /// Full space id string, e.g. "tinycloud:pkh:eip155:1:0x....:default".
    pub space: String,
    /// Resource path; empty string if the resource URI had no path segment.
    pub path: String,
    /// Full-URN ability strings, e.g. ["tinycloud.kv/get", "tinycloud.kv/put"].
    pub actions: Vec<String>,
}

/// Parse a signed SIWE message string and extract its recap capabilities.
///
/// Returns an empty vector if the SIWE has no recap resource (plain auth SIWE).
/// Returns an error if:
/// - the string is not a valid SIWE message
/// - the recap resource is present but cannot be decoded
/// - a resource URI inside the recap cannot be parsed as a TinyCloud ResourceId
///
/// This is the inverse of `SessionConfig::into_message` and is used by the SDK
/// layer to decide whether a requested delegation is a subset of the current
/// session's granted capabilities.
pub fn parse_recap_from_siwe(siwe_string: &str) -> Result<Vec<ParsedRecapEntry>, ParseRecapError> {
    let message: Message =
        siwe_string
            .parse()
            .map_err(|e: tinycloud_auth::cacaos::siwe::ParseError| {
                ParseRecapError::InvalidSiwe(format!("{e}"))
            })?;

    // `extract_and_verify` returns:
    //   - Ok(None) when there is no recap resource (plain auth SIWE)
    //   - Ok(Some(cap)) when the recap is present and the statement matches
    //   - Err(...) when the recap is malformed or the statement is tampered
    let cap = match Capability::<serde_json::Value>::extract_and_verify(&message) {
        Ok(Some(cap)) => cap,
        Ok(None) => return Ok(Vec::new()),
        Err(e) => return Err(ParseRecapError::VerificationFailed(e.to_string())),
    };

    let (caps, _proofs) = cap.into_inner();
    let abilities_map = caps.abilities();

    let mut entries: Vec<ParsedRecapEntry> = Vec::new();
    for (resource_uri, ability_map) in abilities_map.iter() {
        let resource: ResourceId = resource_uri.as_str().parse().map_err(
            |e: tinycloud_auth::resource::KRIParseError| {
                ParseRecapError::InvalidResourceUri(resource_uri.to_string(), e.to_string())
            },
        )?;

        let space = resource.space().to_string();
        let service = resource.service().to_string();
        let path = resource
            .path()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default();

        // Collect the full-URN ability strings. `ability_map` is a `BTreeMap`
        // keyed by `Ability`, so iteration yields keys in sorted order — this
        // gives us a deterministic action list without an extra sort pass.
        let actions: Vec<String> = ability_map
            .keys()
            .map(|ability| ability.to_string())
            .collect();

        entries.push(ParsedRecapEntry {
            service,
            space,
            path,
            actions,
        });
    }

    Ok(entries)
}

#[derive(Debug, thiserror::Error)]
pub enum ParseRecapError {
    #[error("invalid SIWE message: {0}")]
    InvalidSiwe(String),
    #[error("failed to verify recap capabilities: {0}")]
    VerificationFailed(String),
    #[error("invalid resource URI in recap ({0}): {1}")]
    InvalidResourceUri(String, String),
}

pub fn prepare_session(config: SessionConfig) -> Result<PreparedSession, Error> {
    let mut jwk = match &config.jwk {
        Some(k) => k.clone(),
        None => JWK::generate_ed25519()?,
    };
    jwk.algorithm = Some(tinycloud_auth::ssi::jwk::Algorithm::EdDSA);

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
    let additional_spaces = config.additional_spaces.clone();

    let siwe = config
        .into_message(&verification_method)
        .map_err(Error::UnableToGenerateSIWEMessage)?;

    Ok(PreparedSession {
        space_id,
        additional_spaces,
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
        additional_spaces: signed_session.session.additional_spaces,
        verification_method: signed_session.session.verification_method,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to generate session key: {0}")]
    UnableToGenerateKey(#[from] tinycloud_auth::ssi::jwk::Error),
    #[error("unable to generate the DID of the session key: {0}")]
    UnableToGenerateDID(#[from] tinycloud_auth::ssi::dids::GenerateError),
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
            .invoke([(s, p, None, None, [a])], None)
            .expect("failed to create invocation");
    }

    #[test]
    fn parse_recap_roundtrip() {
        // Build a SIWE with a known set of capabilities, stringify it, then
        // parse it back via parse_recap_from_siwe and verify we recover the
        // same (service, space, path, actions) tuples.
        let config = json!({
            "abilities": {
                "kv": {
                    "com.listen.app/": vec![
                        "tinycloud.kv/get",
                        "tinycloud.kv/put",
                        "tinycloud.kv/del",
                        "tinycloud.kv/list",
                        "tinycloud.kv/metadata",
                    ],
                },
                "sql": {
                    "com.listen.app/": vec![
                        "tinycloud.sql/read",
                        "tinycloud.sql/write",
                    ],
                },
                "capabilities": {
                    "com.listen.app/": vec![
                        "tinycloud.capabilities/read",
                    ],
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
        let siwe_string = prepared.siwe.to_string();

        let entries = parse_recap_from_siwe(&siwe_string)
            .expect("parse_recap_from_siwe should succeed on a well-formed SIWE");

        // 3 services, each with one path under the primary space.
        assert_eq!(entries.len(), 3, "expected 3 (service, space, path) groups");

        let expected_space =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default";
        for entry in &entries {
            assert_eq!(entry.space, expected_space, "space did not roundtrip");
            assert_eq!(entry.path, "com.listen.app/", "path did not roundtrip");
        }

        // Build a service -> Vec<String> map for easier comparison.
        let by_service: std::collections::HashMap<String, Vec<String>> = entries
            .into_iter()
            .map(|e| (e.service, e.actions))
            .collect();

        assert_eq!(
            by_service.get("kv").cloned().unwrap_or_default(),
            vec![
                "tinycloud.kv/del".to_string(),
                "tinycloud.kv/get".to_string(),
                "tinycloud.kv/list".to_string(),
                "tinycloud.kv/metadata".to_string(),
                "tinycloud.kv/put".to_string(),
            ],
            "kv actions should roundtrip (sorted lexicographically)"
        );
        assert_eq!(
            by_service.get("sql").cloned().unwrap_or_default(),
            vec![
                "tinycloud.sql/read".to_string(),
                "tinycloud.sql/write".to_string(),
            ]
        );
        assert_eq!(
            by_service.get("capabilities").cloned().unwrap_or_default(),
            vec!["tinycloud.capabilities/read".to_string()]
        );
    }

    #[test]
    fn parse_recap_empty_on_plain_siwe() {
        // A plain SIWE with no recap resource should return an empty vec,
        // not an error. This is the spec'd behavior: recap-less sign-ins are
        // valid auth flows and we want the SDK to treat "no granted caps" as
        // "empty granted set" rather than a failure.
        let plain = "example.com wants you to sign in with your Ethereum account:\n\
            0x7BD63AA37326a64d458559F44432103e3d6eEDE9\n\
            \n\
            \n\
            URI: did:key:z6MkkjPSUV3dYfoVwRpyeaTPYiMCmvmSqD4oCxvbFb8xJpbF\n\
            Version: 1\n\
            Chain ID: 1\n\
            Nonce: abcdefgh\n\
            Issued At: 2022-01-01T00:00:00.000Z";
        let entries = parse_recap_from_siwe(plain).expect("plain SIWE should parse");
        assert!(
            entries.is_empty(),
            "plain SIWE must return empty recap entries, got {:?}",
            entries
        );
    }

    #[test]
    fn parse_recap_with_additional_spaces() {
        // When the session is signed with additional spaces (e.g., the public
        // companion), the recap should contain entries for each space. We want
        // the parser to expose them as distinct entries keyed by space.
        let config = json!({
            "abilities": {
                "kv": {
                    "": vec![
                        "tinycloud.kv/get",
                        "tinycloud.kv/put",
                    ],
                },
            },
            "address": "0x7BD63AA37326a64d458559F44432103e3d6eEDE9",
            "chainId": 1u8,
            "domain": "example.com",
            "issuedAt": "2022-01-01T00:00:00.000Z",
            "spaceId": "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default",
            "additionalSpaces": {
                "public": "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:public"
            },
            "expirationTime": "3000-01-01T00:00:00.000Z",
        });
        let prepared = prepare_session(serde_json::from_value(config).unwrap()).unwrap();
        let siwe_string = prepared.siwe.to_string();

        let entries = parse_recap_from_siwe(&siwe_string)
            .expect("parse_recap_from_siwe should succeed on multi-space SIWE");

        // Two spaces, one service each, so we expect two entries.
        assert_eq!(entries.len(), 2, "expected one entry per space");

        let spaces: std::collections::HashSet<String> =
            entries.iter().map(|e| e.space.clone()).collect();
        assert!(spaces
            .contains("tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default"));
        assert!(spaces
            .contains("tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:public"));

        for entry in entries {
            assert_eq!(entry.service, "kv");
            assert_eq!(
                entry.path, "",
                "path should be empty when abilities had empty path key"
            );
            assert_eq!(
                entry.actions,
                vec![
                    "tinycloud.kv/get".to_string(),
                    "tinycloud.kv/put".to_string(),
                ]
            );
        }
    }

    #[test]
    fn parse_recap_with_distinct_space_abilities() {
        let applications_space =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:applications";
        let account_space =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:account";

        let config = json!({
            "abilities": {},
            "spaceAbilities": {
                applications_space: {
                    "sql": {
                        "com.tinycloud.conversation-sync/conversations": vec![
                            "tinycloud.sql/read",
                            "tinycloud.sql/write",
                        ],
                    },
                },
                account_space: {
                    "kv": {
                        "applications/": vec![
                            "tinycloud.kv/get",
                            "tinycloud.kv/put",
                            "tinycloud.kv/list",
                        ],
                    },
                },
            },
            "address": "0x7BD63AA37326a64d458559F44432103e3d6eEDE9",
            "chainId": 1u8,
            "domain": "example.com",
            "issuedAt": "2022-01-01T00:00:00.000Z",
            "spaceId": applications_space,
            "expirationTime": "3000-01-01T00:00:00.000Z",
        });

        let prepared = prepare_session(serde_json::from_value(config).unwrap()).unwrap();
        let entries = parse_recap_from_siwe(&prepared.siwe.to_string())
            .expect("parse_recap_from_siwe should succeed on per-space SIWE");

        assert_eq!(
            entries.len(),
            2,
            "expected one entry for each requested space"
        );
        let app_entry = entries
            .iter()
            .find(|entry| entry.space == applications_space)
            .expect("applications-space recap entry");
        assert_eq!(app_entry.service, "sql");
        assert_eq!(
            app_entry.path,
            "com.tinycloud.conversation-sync/conversations"
        );
        assert_eq!(
            app_entry.actions,
            vec![
                "tinycloud.sql/read".to_string(),
                "tinycloud.sql/write".to_string(),
            ]
        );

        let account_entry = entries
            .iter()
            .find(|entry| entry.space == account_space)
            .expect("account-space recap entry");
        assert_eq!(account_entry.service, "kv");
        assert_eq!(account_entry.path, "applications/");
        assert_eq!(
            account_entry.actions,
            vec![
                "tinycloud.kv/get".to_string(),
                "tinycloud.kv/list".to_string(),
                "tinycloud.kv/put".to_string(),
            ]
        );
    }

    #[test]
    fn session_with_additional_spaces() {
        let config = json!({
            "abilities": {
                "kv": {
                    "": vec![
                        "tinycloud.kv/put",
                        "tinycloud.kv/get",
                    ]
                },
            },
            "address": "0x7BD63AA37326a64d458559F44432103e3d6eEDE9",
            "chainId": 1u8,
            "domain": "example.com",
            "issuedAt": "2022-01-01T00:00:00.000Z",
            "spaceId": "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default",
            "additionalSpaces": {
                "public": "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:public"
            },
            "expirationTime": "3000-01-01T00:00:00.000Z",
        });
        let session_config: SessionConfig = serde_json::from_value(config).unwrap();
        assert!(session_config.additional_spaces.is_some());
        let additional = session_config.additional_spaces.as_ref().unwrap();
        assert_eq!(additional.len(), 1);
        assert!(additional.contains_key("public"));

        let prepared = prepare_session(session_config).unwrap();
        assert!(prepared.additional_spaces.is_some());

        // Verify the SIWE message contains resource URIs for both spaces
        let siwe_str = prepared.siwe.to_string();
        let primary_space =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default";
        let public_space =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:public";
        assert!(
            siwe_str.contains(primary_space),
            "SIWE message should contain primary space resource URI"
        );
        assert!(
            siwe_str.contains(public_space),
            "SIWE message should contain additional space resource URI"
        );
    }

    // ---------------------------------------------------------------------
    // create_delegation multi-resource tests
    // ---------------------------------------------------------------------
    //
    // These exercise the new multi-resource delegation path:
    // - a session holds a multi-service / multi-path recap
    // - it creates ONE UCAN that re-delegates some subset of that shape
    // - we decode the UCAN and verify the attenuation matches what we sent
    //
    // Decoding uses `ssi::ucan::Ucan::decode` which is the same path the
    // server uses when ingesting a delegation, so the round-trip also
    // confirms the delegation is parseable by real consumers, not just
    // our own test helpers.

    fn rich_test_session() -> Session {
        // Session with KV + SQL + capabilities all granted on
        // "com.listen.app/". This is the baseline the SDK produces for a
        // listen-style manifest.
        let config = json!({
            "abilities": {
                "kv": {
                    "com.listen.app/": vec![
                        "tinycloud.kv/get",
                        "tinycloud.kv/put",
                        "tinycloud.kv/del",
                        "tinycloud.kv/list",
                        "tinycloud.kv/metadata",
                    ],
                },
                "sql": {
                    "com.listen.app/": vec![
                        "tinycloud.sql/read",
                        "tinycloud.sql/write",
                    ],
                },
                "capabilities": {
                    "com.listen.app/": vec![
                        "tinycloud.capabilities/read",
                    ],
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
        signed
            .as_object_mut()
            .unwrap()
            .insert(
                "signature".into(),
                "361647d08fb3ac41b26d9300d80e1964e1b3e7960e5276b3c9f5045ae55171442287279c83fd8922f9238312e89336b1672be8778d078d7dc5107b8c913299721c".into(),
            );
        complete_session_setup(serde_json::from_value(signed).unwrap()).unwrap()
    }

    fn build_abilities(
        entries: &[(&str, &str, &[&str])],
    ) -> HashMap<Service, HashMap<Path, Vec<Ability>>> {
        let mut out: HashMap<Service, HashMap<Path, Vec<Ability>>> = HashMap::new();
        for (service, path, actions) in entries {
            let svc: Service = service.parse().expect("valid service");
            let p: Path = path.parse().expect("valid path");
            let abilities: Vec<Ability> = actions
                .iter()
                .map(|a| a.parse().expect("valid ability"))
                .collect();
            out.entry(svc).or_default().insert(p, abilities);
        }
        out
    }

    /// Decode the UCAN JWT we just signed and return its (resource_uri, action)
    /// pairs as a sorted Vec so tests can do deterministic comparisons.
    fn decode_delegation_pairs(jwt: &str) -> Vec<(String, String)> {
        // Decode with the same generic parameters we sign with:
        //   F = serde_json::Value (facts)
        //   A = [(); 0]           (caveats)
        // Mismatched params would deserialize the capability payload into a
        // different shape and silently break the assertions below.
        let ucan: tinycloud_auth::ssi::ucan::Ucan<serde_json::Value, [(); 0]> =
            tinycloud_auth::ssi::ucan::Ucan::decode(jwt).expect("delegation UCAN should decode");
        let caps = &ucan.payload().attenuation;
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (resource_uri, ability_map) in caps.abilities().iter() {
            for ability in ability_map.keys() {
                pairs.push((resource_uri.to_string(), ability.to_string()));
            }
        }
        pairs.sort();
        pairs
    }

    #[test]
    fn create_delegation_single_resource_backward_compat() {
        // Existing behavior: one service, one path, multiple actions. The old
        // signature took (space, path, actions) and hardcoded service="kv".
        // The new signature takes the full abilities map — this test proves a
        // single-entry map still round-trips cleanly through the delegation.
        let session = rich_test_session();
        let delegate_did = "did:pkh:eip155:1:0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF";

        let abilities = build_abilities(&[(
            "kv",
            "com.listen.app/",
            &["tinycloud.kv/get", "tinycloud.kv/put"],
        )]);

        let result = session
            .create_delegation(
                delegate_did,
                &session.space_id,
                abilities,
                4_000_000_000.0,
                None,
            )
            .expect("single-resource delegation should succeed");

        assert_eq!(result.delegate_did, delegate_did);
        assert_eq!(result.expiry, 4_000_000_000.0);
        assert_eq!(result.resources.len(), 1, "one (service, path) entry");
        assert_eq!(result.resources[0].service, "kv");
        assert_eq!(result.resources[0].path, "com.listen.app/");
        assert_eq!(
            result.resources[0].actions,
            vec![
                "tinycloud.kv/get".to_string(),
                "tinycloud.kv/put".to_string()
            ]
        );

        // Decode the UCAN and confirm the attenuation lines up with what we sent.
        // The resource URI format is
        //   "{space_id}/{service}/{path}"
        // as produced by `SpaceId::to_resource` — this is the same URI that
        // shows up in a signed SIWE's Resources list.
        let pairs = decode_delegation_pairs(&result.delegation);
        let expected_resource =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default/kv/com.listen.app/"
                .to_string();
        assert_eq!(
            pairs,
            vec![
                (expected_resource.clone(), "tinycloud.kv/get".to_string()),
                (expected_resource, "tinycloud.kv/put".to_string()),
            ],
            "UCAN attenuation should contain exactly the granted (resource, action) pairs"
        );
    }

    #[test]
    fn create_delegation_multi_service_same_path() {
        // Listen's real use case: grant KV + SQL on the same app path in one
        // delegation. The resulting UCAN must contain both service resource
        // URIs with their respective action sets — and be a single signed blob.
        let session = rich_test_session();
        let delegate_did = "did:pkh:eip155:1:0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF";

        let abilities = build_abilities(&[
            (
                "kv",
                "com.listen.app/",
                &["tinycloud.kv/get", "tinycloud.kv/put"],
            ),
            (
                "sql",
                "com.listen.app/",
                &["tinycloud.sql/read", "tinycloud.sql/write"],
            ),
        ]);

        let result = session
            .create_delegation(
                delegate_did,
                &session.space_id,
                abilities,
                4_000_000_000.0,
                None,
            )
            .expect("multi-service delegation should succeed");

        assert_eq!(
            result.resources.len(),
            2,
            "expected 2 (service, path) entries, got {:?}",
            result.resources
        );

        // The Rust implementation sorts by (service, path). "kv" sorts before
        // "sql" lexicographically, so this order is deterministic.
        assert_eq!(result.resources[0].service, "kv");
        assert_eq!(result.resources[1].service, "sql");
        for r in &result.resources {
            assert_eq!(r.path, "com.listen.app/");
            assert_eq!(r.space, session.space_id.to_string());
        }

        let pairs = decode_delegation_pairs(&result.delegation);
        let base =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default".to_string();
        // Resource URI layout: "{space}/{service}/{path}". Service + path
        // segments are slash-delimited, not colon-delimited.
        let kv_resource = format!("{base}/kv/com.listen.app/");
        let sql_resource = format!("{base}/sql/com.listen.app/");
        assert_eq!(
            pairs,
            vec![
                (kv_resource.clone(), "tinycloud.kv/get".to_string()),
                (kv_resource, "tinycloud.kv/put".to_string()),
                (sql_resource.clone(), "tinycloud.sql/read".to_string()),
                (sql_resource, "tinycloud.sql/write".to_string()),
            ],
            "UCAN attenuation should contain kv + sql entries on the same path"
        );
    }

    #[test]
    fn create_delegation_multi_service_multi_path() {
        // The most general case: different services on different paths in one
        // delegation. This is the "app with multiple backend databases"
        // scenario. We verify each (service, path) pair ends up as its own
        // attenuation entry and no cross-contamination happens.
        let session = rich_test_session();
        let delegate_did = "did:pkh:eip155:1:0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF";

        let abilities = build_abilities(&[
            ("kv", "a", &["tinycloud.kv/get"]),
            ("sql", "b/data.sqlite", &["tinycloud.sql/read"]),
            ("capabilities", "c", &["tinycloud.capabilities/read"]),
        ]);

        let result = session
            .create_delegation(
                delegate_did,
                &session.space_id,
                abilities,
                4_000_000_000.0,
                None,
            )
            .expect("multi-service/multi-path delegation should succeed");

        assert_eq!(result.resources.len(), 3);

        // resources are sorted by (service, path). Services are sorted
        // lexicographically: "capabilities" < "kv" < "sql".
        assert_eq!(result.resources[0].service, "capabilities");
        assert_eq!(result.resources[0].path, "c");
        assert_eq!(result.resources[1].service, "kv");
        assert_eq!(result.resources[1].path, "a");
        assert_eq!(result.resources[2].service, "sql");
        assert_eq!(result.resources[2].path, "b/data.sqlite");

        let pairs = decode_delegation_pairs(&result.delegation);
        let base =
            "tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:default".to_string();
        // Resource URI layout: "{space}/{service}/{path}".
        assert_eq!(
            pairs,
            vec![
                (
                    format!("{base}/capabilities/c"),
                    "tinycloud.capabilities/read".to_string(),
                ),
                (format!("{base}/kv/a"), "tinycloud.kv/get".to_string()),
                (
                    format!("{base}/sql/b/data.sqlite"),
                    "tinycloud.sql/read".to_string(),
                ),
            ],
            "each (service, path) pair should get its own attenuation entry"
        );
    }

    #[test]
    fn create_delegation_rejects_empty_abilities() {
        // Empty map is user error, not a valid "no-op delegation". Surface it
        // with a clear error rather than signing a useless UCAN.
        let session = rich_test_session();
        let err = session
            .create_delegation(
                "did:pkh:eip155:1:0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF",
                &session.space_id,
                HashMap::new(),
                4_000_000_000.0,
                None,
            )
            .expect_err("empty abilities should error");
        assert!(
            matches!(err, DelegationError::EmptyAbilities),
            "expected EmptyAbilities, got {err:?}"
        );
    }

    #[test]
    fn create_delegation_rejects_empty_actions_under_path() {
        // A (service, path) entry with no actions would encode a useless
        // delegation. Catch it at the boundary.
        let session = rich_test_session();
        let mut abilities: HashMap<Service, HashMap<Path, Vec<Ability>>> = HashMap::new();
        let svc: Service = "kv".parse().unwrap();
        let p: Path = "com.listen.app/".parse().unwrap();
        abilities.entry(svc).or_default().insert(p, vec![]);

        let err = session
            .create_delegation(
                "did:pkh:eip155:1:0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF",
                &session.space_id,
                abilities,
                4_000_000_000.0,
                None,
            )
            .expect_err("empty actions should error");
        assert!(
            matches!(err, DelegationError::EmptyActionsForPath { .. }),
            "expected EmptyActionsForPath, got {err:?}"
        );
    }

    #[test]
    fn create_delegation_subset_of_parse_recap() {
        // End-to-end sanity: sign a session with rich recap, re-delegate a
        // strict subset, then parse the delegation and verify each granted
        // (service, space, path, actions) tuple is indeed present in the
        // original session's parsed recap. This is the invariant the JS
        // derivability check in `delegateTo` relies on: the delegation the
        // session key signs must be a subset of what the SIWE granted.
        //
        // We rebuild the same config as `rich_test_session` and use the
        // PreparedSession's SIWE string as the source of truth for what the
        // session was granted — we can't easily reconstruct that string from
        // a `Session` since the SIWE is consumed by `complete_session_setup`.
        let session = rich_test_session();
        let config = json!({
            "abilities": {
                "kv": {
                    "com.listen.app/": vec![
                        "tinycloud.kv/get",
                        "tinycloud.kv/put",
                        "tinycloud.kv/del",
                        "tinycloud.kv/list",
                        "tinycloud.kv/metadata",
                    ],
                },
                "sql": {
                    "com.listen.app/": vec![
                        "tinycloud.sql/read",
                        "tinycloud.sql/write",
                    ],
                },
                "capabilities": {
                    "com.listen.app/": vec![
                        "tinycloud.capabilities/read",
                    ],
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
        let session_siwe = prepared.siwe.to_string();
        let granted = parse_recap_from_siwe(&session_siwe).unwrap();

        // Delegate strict subset: kv/get + sql/read only.
        let delegate_did = "did:pkh:eip155:1:0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF";
        let abilities = build_abilities(&[
            ("kv", "com.listen.app/", &["tinycloud.kv/get"]),
            ("sql", "com.listen.app/", &["tinycloud.sql/read"]),
        ]);
        let result = session
            .create_delegation(
                delegate_did,
                &session.space_id,
                abilities,
                4_000_000_000.0,
                None,
            )
            .expect("subset delegation should succeed");

        // Every resource in the delegation must be derivable from the parsed
        // session recap: same service+space+path with the delegated actions
        // being a subset of the granted actions.
        for delegated in &result.resources {
            let matching_grant = granted.iter().find(|g| {
                g.service == delegated.service
                    && g.space == delegated.space
                    && g.path == delegated.path
            });
            let matching_grant = matching_grant.unwrap_or_else(|| {
                panic!(
                    "delegated resource {:?} has no matching grant in session recap: {:?}",
                    delegated, granted
                )
            });
            for action in &delegated.actions {
                assert!(
                    matching_grant.actions.contains(action),
                    "action {action} not in granted actions {:?}",
                    matching_grant.actions
                );
            }
        }
    }
}
