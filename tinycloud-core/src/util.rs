use crate::types::{Ability, Caveats, Resource};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_auth::identity::principal_did;
use tinycloud_auth::{
    authorization::{TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation},
    cacaos::siwe::Message,
    ipld_core::cid::Cid,
    resource::SpaceId,
    siwe_recap::{
        Capability as SiweCap, DecodingError as SiweDecodingError, DelegationModeFact,
        VerificationError as SiweError, INVALID_DELEGATION_MODE_ERROR,
    },
};
use ucan_capabilities_object::Capabilities as UcanCapabilities;

/// Strip the fragment from a DID URL, returning the base DID.
/// For example: `did:key:z6Mk...#z6Mk...` -> `did:key:z6Mk...`
///
/// DID fragments identify specific verification methods, but for identity
/// comparison purposes, the base DID is sufficient. This normalizes all
/// DID strings to ensure consistent matching across delegation chains.
fn strip_fragment(did: &str) -> String {
    principal_did(did).unwrap_or_else(|_| did.split('#').next().unwrap_or(did).to_string())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub resource: Resource,
    pub ability: Ability,
    /// UCAN-shaped caveats attached to this capability. Persisted with the
    /// delegation row (W1 native contract requirement); MUST NOT be dropped
    /// at save time. For UCAN delegations these come from the per-ability
    /// caveat list; for SIWE-ReCap they are always empty (a non-null SIWE caveat value is refused).
    #[serde(default)]
    pub caveats: Caveats,
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum CapExtractError {
    #[error("Default actions are not allowed for TinyCloud capabilities")]
    DefaultActions,
    #[error("Invalid Extra Fields")]
    InvalidFields,
    #[error(transparent)]
    Cid(#[from] tinycloud_auth::ipld_core::cid::Error),
}

fn extract_ucan_caps<T: serde::Serialize>(caps: &UcanCapabilities<T>) -> Vec<Capability> {
    let mut capabilities = Vec::new();

    // Iterate over all capabilities in the Capabilities object
    for (resource_uri, abilities) in caps.abilities() {
        for (ability, caveat_collection) in abilities.iter() {
            // UCAN caveats are an array of nota-bene maps. Re-encode the
            // array into a single Caveats map keyed by stringified index
            // (i.e. "0", "1", …) so it round-trips through our JSONB column.
            // This is the W1 caveat-persistence requirement — without it,
            // chain-derived caveats (esp. SQL constrained statements) are
            // lost between save and invocation (revocation.md §2.5).
            let mut bmap: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (i, nb) in caveat_collection.as_ref().iter().enumerate() {
                if let Ok(v) = serde_json::to_value(nb) {
                    bmap.insert(i.to_string(), v);
                }
            }
            capabilities.push(Capability {
                resource: resource_uri.into(),
                ability: ability.clone().into(),
                caveats: Caveats(bmap),
            });
        }
    }

    capabilities
}

/// Refusal text for a SIWE ReCap caveat value that is not null. It never
/// includes the value or its key.
const SIWE_CAVEAT_REFUSED: &str = "SIWE delegations accept only null caveat values";

/// A SIWE ReCap caveat value, checked as it is decoded. The check runs on each
/// occurrence, so a key repeated in one object cannot hide a non-null value.
struct SiweCaveatValue;

impl<'de> Deserialize<'de> for SiweCaveatValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Option::<serde::de::IgnoredAny>::deserialize(deserializer)? {
            None => Ok(Self),
            Some(_) => Err(serde::de::Error::custom(SIWE_CAVEAT_REFUSED)),
        }
    }
}

/// Whether a SIWE ReCap verification/decode error was caused by a malformed,
/// null, unknown, or duplicate `xyz.tinycloud.policy/delegationMode` field.
pub(crate) fn is_invalid_delegation_mode_error(e: &SiweError) -> bool {
    let SiweError::Decoding(SiweDecodingError::De(de)) = e else {
        return false;
    };
    let message = de.to_string();
    message.starts_with(INVALID_DELEGATION_MODE_ERROR)
        || message.starts_with(&format!(
            "duplicate field `{}`",
            DelegationModeFact::FIELD_NAME
        ))
}

/// Maps a SIWE ReCap decode failure. Refused caveat values become
/// `UnsupportedCaveat`, malformed or duplicate delegation mode facts become
/// `InvalidDelegationMode`, and every other failure keeps `SiweCapError`.
///
/// Refusals are recognized by the start of the serde message. A parser error
/// could match only if its text begins with one of these exact prefixes; the
/// result is still a refusal, so no caveat or mode is accepted by such a match.
fn siwe_decode_error(e: SiweError) -> DelegationError {
    if is_invalid_delegation_mode_error(&e) {
        return DelegationError::InvalidDelegationMode;
    }
    if let SiweError::Decoding(SiweDecodingError::De(de)) = &e {
        if de.to_string().starts_with(SIWE_CAVEAT_REFUSED) {
            return DelegationError::UnsupportedCaveat(SIWE_CAVEAT_REFUSED.to_string());
        }
    }
    DelegationError::SiweCapError(e)
}

fn extract_siwe_cap(c: SiweCap<SiweCaveatValue>) -> (Vec<Capability>, Vec<Cid>) {
    let (c, p) = c.into_inner();
    let mut capabilities = Vec::new();
    for (r, acs) in c.into_inner() {
        for (ability, _) in acs {
            capabilities.push(Capability {
                resource: Resource::from(r.clone()),
                ability: ability.into(),
                caveats: Caveats::default(),
            });
        }
    }
    (capabilities, p)
}

#[derive(Debug, Clone)]
pub struct DelegationInfo {
    pub capabilities: Vec<Capability>,
    pub delegator: String,
    pub delegate: String,
    pub parents: Vec<Cid>,
    pub delegation: TinyCloudDelegation,
    pub expiry: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    pub issued_at: Option<OffsetDateTime>,
    /// Node-recognized delegation mode marker carried INSIDE the signed
    /// delegation facts. "terminal" forbids redelegation (rejected as a
    /// parent at validate time); "attenuable" allows redelegation under
    /// containment. Defaults to attenuable when absent. See
    /// policy-engine/spec/revocation.md §1 + §2.1.
    pub delegation_mode: DelegationMode,
}

/// W1 + TC-3810 delegation mode marker. Carried in UCAN `facts` and top-level
/// SIWE ReCap JSON under `xyz.tinycloud.policy/delegationMode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DelegationMode {
    Attenuable,
    Terminal,
    /// Pre-upgrade stored CACAO whose signed ReCap carried a malformed, null,
    /// unknown, or duplicate `xyz.tinycloud.policy/delegationMode`. Produced
    /// only by [`DelegationInfo::try_from_stored`]; live ingress rejects it
    /// with [`DelegationError::InvalidDelegationMode`], and authorization paths
    /// treat it as terminal and refused.
    Invalid,
}

impl DelegationMode {
    pub const FACT_KEY: &'static str = "xyz.tinycloud.policy/delegationMode";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attenuable => "attenuable",
            Self::Terminal => "terminal",
            Self::Invalid => "invalid",
        }
    }
}

/// Read the delegation mode marker from a UCAN facts array. Returns
/// Attenuable when no marker is present.
pub(crate) fn read_delegation_mode_from_ucan_facts(
    facts: Option<&Vec<serde_json::Value>>,
) -> DelegationMode {
    let Some(facts) = facts else {
        return DelegationMode::Attenuable;
    };
    for f in facts {
        if let Some(obj) = f.as_object() {
            if let Some(mode) = obj.get(DelegationMode::FACT_KEY).and_then(|v| v.as_str()) {
                if mode == "terminal" {
                    return DelegationMode::Terminal;
                }
            }
        }
    }
    DelegationMode::Attenuable
}

impl DelegationInfo {
    pub fn spaces(&self) -> impl Iterator<Item = &SpaceId> + '_ {
        self.capabilities.iter().filter_map(|c| c.resource.space())
    }
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum DelegationError {
    #[error(transparent)]
    InvalidCapability(#[from] CapExtractError),
    #[error("Missing Delegator")]
    MissingDelegator,
    #[error("Missing Delegate")]
    MissingDelegate,
    #[error(transparent)]
    SiweConversion(#[from] tinycloud_auth::cacaos::siwe_cacao::SIWEPayloadConversionError),
    #[error(transparent)]
    SiweCapError(#[from] SiweError),
    #[error("Invalid Siwe Statement")]
    InvalidStatement,
    #[error("unsupported-caveat: {0}")]
    UnsupportedCaveat(String),
    #[error("invalid-delegation-mode")]
    InvalidDelegationMode,
}

impl TryFrom<TinyCloudDelegation> for DelegationInfo {
    type Error = DelegationError;
    fn try_from(d: TinyCloudDelegation) -> Result<Self, Self::Error> {
        Ok(match d {
            TinyCloudDelegation::Ucan(ref u) => Self {
                capabilities: extract_ucan_caps(&u.payload().attenuation),
                delegator: strip_fragment(&u.payload().issuer.to_string()),
                delegate: strip_fragment(&u.payload().audience.to_string()),
                parents: u.payload().proof.clone(),
                expiry: OffsetDateTime::from_unix_timestamp_nanos(
                    (u.payload().expiration.as_seconds() * 1_000_000_000.0) as i128,
                )
                .ok(),
                not_before: u.payload().not_before.and_then(|t| {
                    OffsetDateTime::from_unix_timestamp_nanos(
                        (t.as_seconds() * 1_000_000_000.0) as i128,
                    )
                    .ok()
                }),
                delegation_mode: read_delegation_mode_from_ucan_facts(u.payload().facts.as_ref()),
                delegation: d,
                issued_at: None,
            },
            TinyCloudDelegation::Cacao(ref c) => {
                let m: Message = c.payload().clone().try_into()?;
                // Each caveat value is checked while it is decoded (SiweCaveatValue).
                let maybe_siwe_cap = SiweCap::<SiweCaveatValue>::extract_and_verify(&m)
                    .map_err(siwe_decode_error)?;

                let (capabilities, parents, delegation_mode) = match maybe_siwe_cap {
                    Some(siwe_cap) => {
                        let mode = match siwe_cap.delegation_mode() {
                            Some(DelegationModeFact::Terminal) => DelegationMode::Terminal,
                            Some(DelegationModeFact::Attenuable) | None => {
                                DelegationMode::Attenuable
                            }
                        };
                        let (capabilities, parents) = extract_siwe_cap(siwe_cap);
                        (capabilities, parents, mode)
                    }
                    None => (vec![], vec![], DelegationMode::Attenuable),
                };

                Self {
                    capabilities, // Result from extract_siwe_cap or default
                    delegator: strip_fragment(c.payload().iss.as_ref()),
                    delegate: strip_fragment(c.payload().aud.as_ref()),
                    parents,
                    expiry: c.payload().exp.as_ref().map(|t| *t.as_ref()),
                    not_before: c.payload().nbf.as_ref().map(|t| *t.as_ref()),
                    issued_at: Some(*c.payload().iat.as_ref()),
                    delegation_mode,
                    delegation: d,
                }
            }
        })
    }
}

impl DelegationInfo {
    /// Decode a previously persisted delegation tolerating a pre-upgrade CACAO
    /// whose top-level `xyz.tinycloud.policy/delegationMode` is malformed, null,
    /// unknown, or duplicated (mapping it to [`DelegationMode::Invalid`]).
    ///
    /// Intended ONLY for stored-row inspection, listing, and purge readers so a
    /// pre-upgrade malformed row cannot break listing or purge. Live admission
    /// must always use [`TryFrom<TinyCloudDelegation>`], and callers must never
    /// authorize a grant whose mode is [`DelegationMode::Invalid`].
    pub fn try_from_stored(d: TinyCloudDelegation) -> Result<Self, DelegationError> {
        match d {
            TinyCloudDelegation::Cacao(ref c) => {
                let m: Message = c.payload().clone().try_into()?;
                let (capabilities, parents, delegation_mode) =
                    match SiweCap::<SiweCaveatValue>::extract_and_verify(&m)
                        .map_err(siwe_decode_error)
                    {
                        Ok(Some(siwe_cap)) => {
                            let mode = match siwe_cap.delegation_mode() {
                                Some(DelegationModeFact::Terminal) => DelegationMode::Terminal,
                                Some(DelegationModeFact::Attenuable) | None => {
                                    DelegationMode::Attenuable
                                }
                            };
                            let (capabilities, parents) = extract_siwe_cap(siwe_cap);
                            (capabilities, parents, mode)
                        }
                        Ok(None) => (vec![], vec![], DelegationMode::Attenuable),
                        Err(DelegationError::InvalidDelegationMode) => {
                            let maybe_siwe_cap =
                                SiweCap::<SiweCaveatValue>::extract_and_verify_ignoring_mode(&m)
                                    .map_err(siwe_decode_error)?;
                            let (capabilities, parents) = match maybe_siwe_cap {
                                Some(siwe_cap) => extract_siwe_cap(siwe_cap),
                                None => (vec![], vec![]),
                            };
                            (capabilities, parents, DelegationMode::Invalid)
                        }
                        Err(err) => return Err(err),
                    };
                Ok(Self {
                    capabilities,
                    delegator: strip_fragment(c.payload().iss.as_ref()),
                    delegate: strip_fragment(c.payload().aud.as_ref()),
                    parents,
                    expiry: c.payload().exp.as_ref().map(|t| *t.as_ref()),
                    not_before: c.payload().nbf.as_ref().map(|t| *t.as_ref()),
                    issued_at: Some(*c.payload().iat.as_ref()),
                    delegation_mode,
                    delegation: d,
                })
            }
            TinyCloudDelegation::Ucan(_) => Self::try_from(d),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvocationInfo {
    pub capabilities: Vec<Capability>,
    pub invoker: String,
    pub parents: Vec<Cid>,
    pub invocation: TinyCloudInvocation,
}

impl InvocationInfo {
    pub fn spaces(&self) -> impl Iterator<Item = &SpaceId> + '_ {
        self.capabilities.iter().filter_map(|c| c.resource.space())
    }
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum InvocationError {
    #[error("Missing Resource")]
    MissingResource,
    #[error(transparent)]
    ResourceParse(#[from] CapExtractError),
}

impl TryFrom<TinyCloudInvocation> for InvocationInfo {
    type Error = InvocationError;
    fn try_from(invocation: TinyCloudInvocation) -> Result<Self, Self::Error> {
        Ok(Self {
            capabilities: extract_ucan_caps(&invocation.payload().attenuation),
            invoker: strip_fragment(&invocation.payload().issuer.to_string()),
            parents: invocation.payload().proof.clone(),
            invocation,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RevocationInfo {
    // TODO these should be hash
    pub parents: Vec<Cid>,
    pub revoked: Cid,
    pub revoker: String,
    pub revocation: TinyCloudRevocation,
}

#[derive(thiserror::Error, Debug)]
pub enum RevocationError {
    #[error("Invalid Target")]
    InvalidTarget,
}

impl TryFrom<TinyCloudRevocation> for RevocationInfo {
    type Error = RevocationError;
    fn try_from(r: TinyCloudRevocation) -> Result<Self, Self::Error> {
        match &r {
            TinyCloudRevocation::Cacao(c) => match c.payload().aud.as_str().split_once(':') {
                Some(("ucan", ps)) => Ok(Self {
                    parents: Vec::new(),
                    revoked: ps.parse().map_err(|_| RevocationError::InvalidTarget)?,
                    revoker: strip_fragment(c.payload().iss.as_ref()),
                    revocation: r,
                }),
                _ => Err(RevocationError::InvalidTarget),
            },
            // The signed UCAN must request revocation of exactly one CID.
            // Proofs authorize that action; they do not select its target.
            TinyCloudRevocation::Ucan(u) => {
                let payload = u.payload();
                let capabilities = payload.attenuation.abilities();
                let (resource, abilities) = capabilities
                    .iter()
                    .next()
                    .ok_or(RevocationError::InvalidTarget)?;
                if capabilities.len() != 1
                    || abilities.len() != 1
                    || !abilities
                        .keys()
                        .any(|ability| ability.as_ref() == "tinycloud.delegation/revoke")
                {
                    return Err(RevocationError::InvalidTarget);
                }
                let revoked = resource
                    .as_str()
                    .strip_prefix("urn:cid:")
                    .and_then(|cid| cid.parse().ok())
                    .ok_or(RevocationError::InvalidTarget)?;
                let revoker = strip_fragment(&payload.issuer.to_string());
                Ok(Self {
                    parents: payload.proof.clone(),
                    revoked,
                    revoker,
                    revocation: r,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCE: &str =
        "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/sql/main";

    /// What the node sees as `cap.caveats` for one ability's caveat list.
    fn seen_by_the_node(list: &str) -> Result<serde_json::Value, serde_json::Error> {
        let capabilities: UcanCapabilities<serde_json::Value> = serde_json::from_str(&format!(
            r#"{{"{RESOURCE}": {{"tinycloud.sql/read": {list}}}}}"#
        ))?;
        let extracted = extract_ucan_caps(&capabilities);
        assert_eq!(extracted.len(), 1);
        Ok(serde_json::to_value(&extracted[0].caveats).unwrap())
    }

    /// TC-1791: how a caveat list reaches `cap.caveats`, the form every
    /// delegated-caveat rule reads.
    #[test]
    fn a_caveat_list_reaches_the_node_as_entries_keyed_by_index() {
        use serde_json::json;
        // One empty entry is collapsed to no caveat at all.
        assert_eq!(seen_by_the_node("[{}]").unwrap(), json!({}));
        // Two empty entries are kept, as two empty objects.
        assert_eq!(
            seen_by_the_node("[{}, {}]").unwrap(),
            json!({"0": {}, "1": {}})
        );
        assert_eq!(
            seen_by_the_node(r#"[{"tables": ["Notes"]}]"#).unwrap(),
            json!({"0": {"tables": ["Notes"]}})
        );
        assert_eq!(
            seen_by_the_node(r#"[{"tables": ["a"]}, {"readOnly": true}]"#).unwrap(),
            json!({"0": {"tables": ["a"]}, "1": {"readOnly": true}})
        );
        // An empty list does not parse at all: no delegation can carry it.
        assert!(seen_by_the_node("[]").is_err());
    }

    /// Caveat entries for one ability, as a ReCap encodes them.
    fn recap_caveats(json: serde_json::Value) -> Vec<BTreeMap<String, serde_json::Value>> {
        serde_json::from_value(json).unwrap()
    }

    /// A SIWE CACAO whose ReCap grants each ability with the given caveat list.
    /// Only the ReCap is read here: `DelegationInfo::try_from` does not check
    /// the signature, so it is left zeroed.
    fn siwe_with_recap(
        grants: &[(&str, Vec<BTreeMap<String, serde_json::Value>>)],
    ) -> TinyCloudDelegation {
        let mut recap = tinycloud_auth::siwe_recap::Capability::<serde_json::Value>::new();
        for (ability, caveats) in grants {
            recap.with_action(
                RESOURCE.parse().unwrap(),
                ability.parse().unwrap(),
                caveats.clone(),
            );
        }
        cacao(recap.build_message(base_message()).unwrap())
    }

    /// A SIWE CACAO whose ReCap resource is `recap_json` verbatim, so a test
    /// controls the JSON text the decoder sees, repeated keys included.
    fn siwe_with_raw_recap(recap_json: &str) -> TinyCloudDelegation {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(recap_json);
        let mut message = base_message();
        message.resources.push(
            format!("{}{encoded}", tinycloud_auth::siwe_recap::RESOURCE_PREFIX)
                .parse()
                .unwrap(),
        );
        cacao(message)
    }

    /// A ReCap whose attenuation is `body`. `@RES` and `@KV` stand in for the
    /// sql and kv resource URIs.
    fn raw_recap(body: &str) -> String {
        let kv =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/kv/main";
        format!(
            r#"{{"att":{},"prf":[]}}"#,
            body.replace("@RES", RESOURCE).replace("@KV", kv)
        )
    }

    /// The message every test CACAO shares. Only its ReCap resource differs.
    fn base_message() -> Message {
        use tinycloud_auth::cacaos::siwe::Version;
        Message {
            scheme: Some("https".parse().unwrap()),
            domain: "tinycloud.invalid".parse().unwrap(),
            address: [1; 20],
            statement: None,
            uri: "did:key:z6MkTestDelegatee".parse().unwrap(),
            version: Version::V1,
            chain_id: 1,
            nonce: "tc1844nonce".into(),
            issued_at: "2020-01-01T00:00:00Z".parse().unwrap(),
            expiration_time: Some("2100-01-01T00:00:00Z".parse().unwrap()),
            not_before: None,
            request_id: None,
            resources: vec![],
        }
    }

    fn cacao(message: Message) -> TinyCloudDelegation {
        use tinycloud_auth::cacaos::siwe_cacao::{Header, Signature, SiweCacao};
        TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
            message.into(),
            Signature::from([0u8; 65]),
            Header,
        )))
    }

    /// TC-1844: a SIWE caveat with a non-null value is refused for every ability.
    #[test]
    fn a_non_null_siwe_caveat_value_is_refused_for_every_ability() {
        use serde_json::json;
        let profile = recap_caveats(json!([{"tables": ["Notes"], "readOnly": true}]));
        for ability in [
            "tinycloud.sql/read",
            "tinycloud.duckdb/read",
            "tinycloud.kv/get",
        ] {
            let delegation = siwe_with_recap(&[(ability, profile.clone())]);
            assert!(
                matches!(
                    DelegationInfo::try_from(delegation),
                    Err(DelegationError::UnsupportedCaveat(_))
                ),
                "{ability} must refuse a non-null SIWE caveat"
            );
        }
    }

    /// TC-1844: each attenuation carries a non-null caveat value somewhere. Each
    /// is refused with the same message, which never includes the value. Repeated
    /// keys reach the decoder as written.
    #[test]
    fn a_non_null_siwe_caveat_value_is_refused_wherever_it_appears() {
        for body in [
            // A caveat value that is a list, a boolean, a number, a string or an object.
            r#"{"@RES":{"tinycloud.sql/read":[{"k":[]}]}}"#,
            r#"{"@RES":{"tinycloud.sql/read":[{"k":false}]}}"#,
            r#"{"@RES":{"tinycloud.sql/read":[{"k":0}]}}"#,
            r#"{"@RES":{"tinycloud.sql/read":[{"k":""}]}}"#,
            r#"{"@RES":{"tinycloud.sql/read":[{"k":{"x":null}}]}}"#,
            // An empty map is still a value.
            r#"{"@RES":{"tinycloud.sql/read":[{"tables":{}}]}}"#,
            r#"{"@RES":{"tinycloud.sql/read":[{"tables":["Notes"],"readOnly":true}]}}"#,
            // A non-null value in a later entry.
            r#"{"@RES":{"tinycloud.sql/read":[{},{"k":"SECRETVALUE"}]}}"#,
            // A repeated key within one entry, with the non-null value first or last.
            r#"{"@RES":{"tinycloud.sql/read":[{"k":"SECRETVALUE","k":null}]}}"#,
            r#"{"@RES":{"tinycloud.sql/read":[{"k":null,"k":"SECRETVALUE"}]}}"#,
            // A repeated ability key whose first occurrence is non-null.
            r#"{"@RES":{"tinycloud.sql/read":[{"k":"SECRETVALUE"}],"tinycloud.sql/read":[{"k":null}]}}"#,
            // A non-null value on a second ability.
            r#"{"@RES":{"tinycloud.sql/read":[{}],"tinycloud.sql/write":[{"k":"SECRETVALUE"}]}}"#,
            // A non-null value on a second resource.
            r#"{"@RES":{"tinycloud.sql/read":[{}]},"@KV":{"tinycloud.kv/get":[{"k":"SECRETVALUE"}]}}"#,
        ] {
            let err =
                DelegationInfo::try_from(siwe_with_raw_recap(&raw_recap(body))).expect_err(body);
            assert!(
                matches!(err, DelegationError::UnsupportedCaveat(_)),
                "{body}: got {err}"
            );
            assert_eq!(
                err.to_string(),
                format!("unsupported-caveat: {}", SIWE_CAVEAT_REFUSED)
            );
            assert!(!err.to_string().contains("SECRETVALUE"), "{body}");
        }
    }

    /// Null values and empty entries carry no restriction. They are accepted
    /// and stored as the empty caveat map.
    #[test]
    fn null_and_empty_siwe_caveats_are_accepted_as_no_restriction() {
        use serde_json::json;
        for caveats in [
            json!([{}]),
            json!([{}, {}]),
            json!([{"tables": null}]),
            json!([{}, {"k": null, "j": null}]),
        ] {
            let delegation =
                siwe_with_recap(&[("tinycloud.sql/read", recap_caveats(caveats.clone()))]);
            let info = DelegationInfo::try_from(delegation)
                .unwrap_or_else(|e| panic!("{caveats} must be accepted: {e}"));
            assert_eq!(info.capabilities.len(), 1);
            assert_eq!(info.capabilities[0].caveats, Caveats::default());
        }
    }

    /// A ReCap that does not decode keeps its decode error. Only a refused
    /// caveat value becomes `UnsupportedCaveat`.
    #[test]
    fn a_malformed_siwe_recap_keeps_its_decode_error() {
        let err = DelegationInfo::try_from(siwe_with_raw_recap(r#"{"att":5,"prf":[]}"#))
            .expect_err("a non-object attenuation must not decode");
        assert!(matches!(err, DelegationError::SiweCapError(_)), "got {err}");
    }

    /// A SIWE CACAO with a valid statement matching `att`, whose ReCap JSON is
    /// `recap_json` verbatim.
    fn siwe_with_verified_raw_recap(recap_json: &str, statement: &str) -> TinyCloudDelegation {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(recap_json);
        let mut message = base_message();
        message.statement = Some(statement.to_string());
        message.resources.push(
            format!("{}{encoded}", tinycloud_auth::siwe_recap::RESOURCE_PREFIX)
                .parse()
                .unwrap(),
        );
        cacao(message)
    }

    fn expected_statement(grants: &[(&str, &str)]) -> String {
        let mut recap = tinycloud_auth::siwe_recap::Capability::<serde_json::Value>::new();
        for (resource, ability) in grants {
            recap.with_action(resource.parse().unwrap(), ability.parse().unwrap(), []);
        }
        recap.to_statement()
    }

    /// TC-3810: top-level `xyz.tinycloud.policy/delegationMode` parses
    /// `terminal`, explicit `attenuable`, and legacy absence accurately across
    /// single- and multi-resource CACAOs.
    #[test]
    fn cacao_delegation_mode_parses_terminal_attenuable_and_absent() {
        let kv =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/kv/main";
        let stmt =
            expected_statement(&[(RESOURCE, "tinycloud.sql/read"), (kv, "tinycloud.kv/get")]);
        let att = format!(
            r#"{{"{RESOURCE}":{{"tinycloud.sql/read":[{{}}]}},"{kv}":{{"tinycloud.kv/get":[{{}}]}}}}"#
        );

        // Terminal
        let terminal_json =
            format!(r#"{{"att":{att},"prf":[],"xyz.tinycloud.policy/delegationMode":"terminal"}}"#);
        let info =
            DelegationInfo::try_from(siwe_with_verified_raw_recap(&terminal_json, &stmt)).unwrap();
        assert_eq!(info.delegation_mode, DelegationMode::Terminal);
        assert_eq!(info.capabilities.len(), 2);

        // Explicit attenuable
        let attenuable_json = format!(
            r#"{{"att":{att},"prf":[],"xyz.tinycloud.policy/delegationMode":"attenuable"}}"#
        );
        let info = DelegationInfo::try_from(siwe_with_verified_raw_recap(&attenuable_json, &stmt))
            .unwrap();
        assert_eq!(info.delegation_mode, DelegationMode::Attenuable);
        assert_eq!(info.capabilities.len(), 2);

        // Absent (legacy)
        let absent_json = format!(r#"{{"att":{att},"prf":[]}}"#);
        let info =
            DelegationInfo::try_from(siwe_with_verified_raw_recap(&absent_json, &stmt)).unwrap();
        assert_eq!(info.delegation_mode, DelegationMode::Attenuable);
        assert_eq!(info.capabilities.len(), 2);

        // Builder omits field when unset (byte-identical legacy) and emits when set.
        let mut legacy_cap = tinycloud_auth::siwe_recap::Capability::<serde_json::Value>::new();
        legacy_cap.with_action(
            RESOURCE.parse().unwrap(),
            "tinycloud.sql/read".parse().unwrap(),
            [],
        );
        let legacy_msg = legacy_cap.build_message(base_message()).unwrap();
        let legacy_info = DelegationInfo::try_from(cacao(legacy_msg.clone())).unwrap();
        assert_eq!(legacy_info.delegation_mode, DelegationMode::Attenuable);
        let legacy_uri = legacy_msg.resources.last().unwrap().as_str();
        let legacy_decoded = String::from_utf8(
            base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                legacy_uri
                    .strip_prefix(tinycloud_auth::siwe_recap::RESOURCE_PREFIX)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!legacy_decoded.contains("delegationMode"));

        let terminal_msg = legacy_cap
            .clone()
            .with_delegation_mode(DelegationModeFact::Terminal)
            .build_message(base_message())
            .unwrap();
        assert_eq!(terminal_msg.statement, legacy_msg.statement);
        let terminal_info = DelegationInfo::try_from(cacao(terminal_msg)).unwrap();
        assert_eq!(terminal_info.delegation_mode, DelegationMode::Terminal);
    }

    /// TC-3810: malformed, null, unknown, and duplicate delegationMode values
    /// (including escaped-key equivalents) refuse the CACAO with
    /// `InvalidDelegationMode`, with no last-key-wins or partial acceptance.
    #[test]
    fn cacao_malformed_or_duplicate_delegation_mode_is_refused() {
        let stmt = expected_statement(&[(RESOURCE, "tinycloud.sql/read")]);
        let att = format!(r#"{{"{RESOURCE}":{{"tinycloud.sql/read":[{{}}]}}}}"#);
        let bad_tails = [
            r#""xyz.tinycloud.policy/delegationMode":null"#,
            r#""xyz.tinycloud.policy/delegationMode":true"#,
            r#""xyz.tinycloud.policy/delegationMode":false"#,
            r#""xyz.tinycloud.policy/delegationMode":0"#,
            r#""xyz.tinycloud.policy/delegationMode":1"#,
            r#""xyz.tinycloud.policy/delegationMode":[]"#,
            r#""xyz.tinycloud.policy/delegationMode":["terminal"]"#,
            r#""xyz.tinycloud.policy/delegationMode":{}"#,
            r#""xyz.tinycloud.policy/delegationMode":{"mode":"terminal"}"#,
            r#""xyz.tinycloud.policy/delegationMode":"""#,
            r#""xyz.tinycloud.policy/delegationMode":"Terminal""#,
            r#""xyz.tinycloud.policy/delegationMode":"TERMINAL""#,
            r#""xyz.tinycloud.policy/delegationMode":"bogus""#,
            r#""xyz.tinycloud.policy/delegationMode":"terminal ""#,
            // Duplicate keys in every order, identical or conflicting, raw or JSON-escaped.
            r#""xyz.tinycloud.policy/delegationMode":"terminal","xyz.tinycloud.policy/delegationMode":"attenuable""#,
            r#""xyz.tinycloud.policy/delegationMode":"attenuable","xyz.tinycloud.policy/delegationMode":"terminal""#,
            r#""xyz.tinycloud.policy/delegationMode":"terminal","xyz.tinycloud.policy/delegationMode":"terminal""#,
            r#""xyz.tinycloud.policy/delegationMode":"attenuable","xyz.tinycloud.policy/delegationMode":"attenuable""#,
            r#""xyz.tinycloud.policy/delegationMode":"bogus","xyz.tinycloud.policy/delegationMode":"terminal""#,
            r#""xyz.tinycloud.policy/delegationMode":"terminal","xyz.tinycloud.policy/delegationMode":"bogus""#,
            r#""xyz.tinycloud.policy/delegationMode":"terminal","xyz.tinycloud.policy\u002fdelegationMode":"attenuable""#,
            r#""xyz.tinycloud.policy\u002fdelegationMode":"attenuable","xyz.tinycloud.policy/delegationMode":"terminal""#,
            r#""xyz.tinycloud.policy/delegationMode":"terminal","xyz.tinycloud.policy\u002fdelegationMode":"terminal""#,
        ];

        for tail in bad_tails {
            let json = format!(r#"{{"att":{att},"prf":[],{tail}}}"#);
            let err = DelegationInfo::try_from(siwe_with_verified_raw_recap(&json, &stmt))
                .expect_err(tail);
            assert!(
                matches!(err, DelegationError::InvalidDelegationMode),
                "expected InvalidDelegationMode for {tail}, got {err}"
            );
            assert_eq!(err.to_string(), "invalid-delegation-mode");
        }
    }

    /// TC-3810: placing delegationMode as an `nb` caveat on one ability is
    /// refused by the existing non-null SIWE caveat rule (no partial mode).
    #[test]
    fn cacao_mode_as_nb_caveat_is_refused_by_existing_caveat_rule() {
        let kv =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/kv/main";
        let stmt =
            expected_statement(&[(RESOURCE, "tinycloud.sql/read"), (kv, "tinycloud.kv/get")]);
        let json = format!(
            r#"{{"att":{{"{RESOURCE}":{{"tinycloud.sql/read":[{{"xyz.tinycloud.policy/delegationMode":"terminal"}}]}},"{kv}":{{"tinycloud.kv/get":[{{}}]}}}},"prf":[]}}"#
        );
        let err =
            DelegationInfo::try_from(siwe_with_verified_raw_recap(&json, &stmt)).expect_err("nb");
        assert!(
            matches!(err, DelegationError::UnsupportedCaveat(_)),
            "got {err}"
        );
    }

    /// TC-3810 mixed-fleet compatibility: an unrelated unknown top-level ReCap
    /// field is still ignored, and a pinned legacy parser (reading only `att`
    /// and `prf`) decodes a terminal ReCap cleanly with identical capabilities,
    /// statement, and raw CACAO bytes/CID.
    #[test]
    fn cacao_unknown_top_level_field_and_old_node_simulation() {
        use sha3::Digest;
        use tinycloud_auth::authorization::HeaderEncode;

        #[derive(serde::Deserialize)]
        struct LegacyRecap {
            att: ucan_capabilities_object::Capabilities<SiweCaveatValue>,
            prf: Vec<String>,
        }

        let stmt = expected_statement(&[(RESOURCE, "tinycloud.sql/read")]);
        let att = format!(r#"{{"{RESOURCE}":{{"tinycloud.sql/read":[{{}}]}}}}"#);

        // Unrelated unknown top-level field is preserved/ignored.
        let with_other = format!(r#"{{"att":{att},"prf":[],"other.vendor/flag":true}}"#);
        let info =
            DelegationInfo::try_from(siwe_with_verified_raw_recap(&with_other, &stmt)).unwrap();
        assert_eq!(info.delegation_mode, DelegationMode::Attenuable);

        // Build a real wallet-signed terminal CACAO and compare canonical
        // DAG-CBOR bytes and CID across the legacy parser (ignoring unknown
        // keys) and new parser.
        let terminal_json =
            format!(r#"{{"att":{att},"prf":[],"xyz.tinycloud.policy/delegationMode":"terminal"}}"#);
        let signing_key = k256::ecdsa::SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
        let pub_uncompressed = signing_key.verifying_key().to_encoded_point(false);
        let addr_hash = sha3::Keccak256::digest(&pub_uncompressed.as_bytes()[1..]);
        let mut signed_msg = base_message();
        signed_msg.address = addr_hash[12..].try_into().unwrap();
        signed_msg.statement = Some(stmt.clone());
        let encoded_terminal = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &terminal_json,
        );
        signed_msg.resources.push(
            format!(
                "{}{encoded_terminal}",
                tinycloud_auth::siwe_recap::RESOURCE_PREFIX
            )
            .parse()
            .unwrap(),
        );
        let (sig, rec) = signing_key
            .sign_prehash_recoverable(&signed_msg.eip191_hash().unwrap())
            .unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = u8::from(rec) + 27;
        let signed_cacao = tinycloud_auth::cacaos::siwe_cacao::Payload::from(signed_msg)
            .sign::<tinycloud_auth::cacaos::siwe_cacao::Eip191>(
            tinycloud_auth::cacaos::siwe_cacao::Signature::from(sig_bytes),
        );
        let terminal_del = TinyCloudDelegation::Cacao(Box::new(signed_cacao));
        let wire_token = terminal_del.encode().unwrap();
        let (decoded_old_del, old_bytes) = TinyCloudDelegation::decode(&wire_token).unwrap();
        let (decoded_new_del, new_bytes) = TinyCloudDelegation::decode(&wire_token).unwrap();
        let old_cid = crate::hash::hash(&old_bytes).to_cid(0x55);
        let new_cid = crate::hash::hash(&new_bytes).to_cid(0x55);
        assert_eq!(old_bytes, new_bytes, "canonical CACAO bytes must match");
        assert_eq!(old_cid, new_cid, "raw CACAO CID must match");

        let TinyCloudDelegation::Cacao(old_cacao) = decoded_old_del else {
            panic!("expected CACAO");
        };
        let old_msg: tinycloud_auth::cacaos::siwe::Message =
            old_cacao.payload().clone().try_into().unwrap();
        let encoded_recap = old_msg
            .resources
            .last()
            .unwrap()
            .as_str()
            .strip_prefix(tinycloud_auth::siwe_recap::RESOURCE_PREFIX)
            .unwrap();
        let raw_recap = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            encoded_recap,
        )
        .unwrap();

        let legacy: LegacyRecap = serde_json::from_slice(&raw_recap).unwrap();
        assert_eq!(legacy.att.abilities().len(), 1);
        assert!(legacy.prf.is_empty());

        let new_cap: SiweCap<SiweCaveatValue> = serde_json::from_slice(&raw_recap).unwrap();
        assert_eq!(new_cap.to_statement(), stmt);
        assert_eq!(old_msg.statement.as_deref(), Some(stmt.as_str()));
        assert_eq!(
            new_cap.delegation_mode(),
            Some(DelegationModeFact::Terminal)
        );
        let new_info = DelegationInfo::try_from(decoded_new_del).unwrap();
        assert_eq!(new_info.delegation_mode, DelegationMode::Terminal);
        assert_eq!(new_info.capabilities.len(), 1);
        let reencoded = TinyCloudDelegation::Cacao(old_cacao).encode().unwrap();
        let (_, redecoded_bytes) = TinyCloudDelegation::decode(&reencoded).unwrap();
        assert_eq!(
            redecoded_bytes, new_bytes,
            "re-encoded legacy CACAO must remain byte-identical"
        );
        assert_eq!(
            crate::hash::hash(&redecoded_bytes).to_cid(0x55),
            new_cid,
            "re-encoded legacy CACAO CID must match"
        );

        // Tolerant stored-row decoder preserves malformed-mode rows as Invalid
        // while live TryFrom still refuses them.
        let malformed_json =
            format!(r#"{{"att":{att},"prf":[],"xyz.tinycloud.policy/delegationMode":"bogus"}}"#);
        let malformed_del = siwe_with_verified_raw_recap(&malformed_json, &stmt);
        assert!(matches!(
            DelegationInfo::try_from(malformed_del.clone()),
            Err(DelegationError::InvalidDelegationMode)
        ));
        let stored_info = DelegationInfo::try_from_stored(malformed_del).unwrap();
        assert_eq!(stored_info.delegation_mode, DelegationMode::Invalid);
        assert_eq!(stored_info.capabilities.len(), 1);
    }
}
