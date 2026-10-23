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
    siwe_recap::{Capability as SiweCap, VerificationError as SiweError},
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
    /// caveat list; for SIWE-ReCap they are always empty (non-empty SIWE caveats are refused).
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

fn extract_siwe_cap(
    c: SiweCap<serde_json::Value>,
) -> Result<(Vec<Capability>, Vec<Cid>), DelegationError> {
    let (c, p) = c.into_inner();
    let mut capabilities = Vec::new();
    for (r, acs) in c.into_inner() {
        for (ability, caveats) in acs {
            // A SIWE caveat is accepted only as an empty placeholder: every
            // value in every entry must be null. Any other value is refused,
            // because nothing enforces it. Caveat values are never echoed.
            for (i, entry) in caveats.into_inner().into_iter().enumerate() {
                if entry.values().any(|v| !v.is_null()) {
                    return Err(DelegationError::UnsupportedCaveat(format!(
                        "{ability} caveat {i} is not accepted; SIWE delegations accept only null caveat values"
                    )));
                }
            }
            capabilities.push(Capability {
                resource: Resource::from(r.clone()),
                ability: ability.into(),
                caveats: Caveats::default(),
            });
        }
    }
    Ok((capabilities, p))
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

/// W1 delegation mode marker. Carried in the signed UCAN delegation's
/// `facts` array under the key `xyz.tinycloud.policy/delegationMode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DelegationMode {
    Attenuable,
    Terminal,
}

impl DelegationMode {
    pub const FACT_KEY: &'static str = "xyz.tinycloud.policy/delegationMode";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attenuable => "attenuable",
            Self::Terminal => "terminal",
        }
    }
}

/// Read the delegation mode marker from a UCAN facts array. Returns
/// Attenuable when no marker is present.
fn read_delegation_mode_from_ucan_facts(facts: Option<&Vec<serde_json::Value>>) -> DelegationMode {
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
                // Decode the ReCap caveats as JSON values so extract_siwe_cap can refuse them explicitly.
                let maybe_siwe_cap = SiweCap::extract_and_verify(&m)?;

                let (capabilities, parents) = match maybe_siwe_cap {
                    // Non-empty caveats are refused inside extract_siwe_cap.
                    Some(siwe_cap) => extract_siwe_cap(siwe_cap)?,
                    None => (vec![], vec![]),
                };

                Self {
                    capabilities, // Result from extract_siwe_cap or default
                    delegator: strip_fragment(c.payload().iss.as_ref()),
                    delegate: strip_fragment(c.payload().aud.as_ref()),
                    parents,
                    expiry: c.payload().exp.as_ref().map(|t| *t.as_ref()),
                    not_before: c.payload().nbf.as_ref().map(|t| *t.as_ref()),
                    issued_at: Some(*c.payload().iat.as_ref()),
                    // CACAO delegations do not currently carry the terminal
                    // marker; only policy-engine-issued UCAN delegations do.
                    delegation_mode: DelegationMode::Attenuable,
                    delegation: d,
                }
            }
        })
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
        use tinycloud_auth::cacaos::{
            siwe::Version,
            siwe_cacao::{Header, Signature, SiweCacao},
        };
        let mut recap = tinycloud_auth::siwe_recap::Capability::<serde_json::Value>::new();
        for (ability, caveats) in grants {
            recap.with_action(
                RESOURCE.parse().unwrap(),
                ability.parse().unwrap(),
                caveats.clone(),
            );
        }
        let message = Message {
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
        };
        let message = recap.build_message(message).unwrap();
        TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
            message.into(),
            Signature::from([0u8; 65]),
            Header,
        )))
    }

    /// TC-1844: a SIWE ReCap caveat with a non-null value is refused for every
    /// ability, because the node has no enforcement for it.
    #[test]
    fn a_siwe_caveat_with_a_value_is_refused_for_every_ability() {
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

    /// An empty map is still a value, so `{"tables": {}}` is refused too.
    #[test]
    fn a_siwe_caveat_holding_an_empty_map_is_refused() {
        use serde_json::json;
        let delegation =
            siwe_with_recap(&[("tinycloud.sql/read", recap_caveats(json!([{"tables": {}}])))]);
        assert!(matches!(
            DelegationInfo::try_from(delegation),
            Err(DelegationError::UnsupportedCaveat(_))
        ));
    }

    /// Null values and empty entries carry no restriction. They are accepted
    /// and stored as the empty caveat map.
    #[test]
    fn null_and_empty_siwe_caveats_are_accepted_as_no_restriction() {
        use serde_json::json;
        for caveats in [json!([{}]), json!([{}, {}]), json!([{"tables": null}])] {
            let delegation =
                siwe_with_recap(&[("tinycloud.sql/read", recap_caveats(caveats.clone()))]);
            let info = DelegationInfo::try_from(delegation)
                .unwrap_or_else(|e| panic!("{caveats} must be accepted: {e}"));
            assert_eq!(info.capabilities.len(), 1);
            assert_eq!(info.capabilities[0].caveats, Caveats::default());
        }
    }
}
