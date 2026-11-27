//! Owner admission for a threshold-member key (D7.1).
//!
//! The admission is a node-bound owner invocation of
//! [`MEMBER_ADMIT_ACTION`] on network N: audience and `targetNode` are this
//! node's DID, its one capability names N, its `bodyHash` covers the request
//! body `{nonce}`, and its nonce is consumed. Owner authority comes from N's
//! URN owner through the node's invocation authorization (delegation chain,
//! including SIWE sessions of `did:pkh` owners). Admission is not a key-state
//! change, so it is not one of the node-bound admin credentials a threshold
//! network refuses.

use async_trait::async_trait;
use serde_json::Value;
use tinycloud_core::encryption_network::{
    canonical::canonical_hash, EncryptionService, NetworkAdminFacts, NetworkId, NETWORK_ADMIN_TYPE,
};
use tinycloud_core::util::InvocationInfo;

use super::MEMBER_ADMIT_ACTION;
use crate::policy_v3::PolicyV3Runtime;
use crate::TinyCloud;

/// Why an admission was refused. Names a check, never a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AdmissionRefused(pub String);

impl AdmissionRefused {
    fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Verifies that a request carries the owner's admission of this member
/// for `network`, over the exact request `body`.
#[async_trait]
pub trait OwnerAdmission: Send + Sync {
    async fn verify(&self, network: &NetworkId, body: &Value) -> Result<(), AdmissionRefused>;
}

/// The node's admission check for one request's invocation.
pub struct InvocationAdmission<'a> {
    pub invocation: &'a InvocationInfo,
    pub tinycloud: &'a TinyCloud,
    pub policy_v3: &'a PolicyV3Runtime,
    pub service: &'a EncryptionService,
}

#[async_trait]
impl OwnerAdmission for InvocationAdmission<'_> {
    async fn verify(&self, network: &NetworkId, body: &Value) -> Result<(), AdmissionRefused> {
        let node_did = self.service.node_did();
        check_admission_shape(self.invocation, node_did, network, body)?;
        self.policy_v3
            .refuse_policy_root_proofs(&self.invocation.parents)
            .await
            .map_err(|error| AdmissionRefused::new(error.to_string()))?;
        let now = time::OffsetDateTime::now_utc();
        // Read-only: signature, time validity and the delegation chain to the
        // resource owner, without recording an invocation.
        self.tinycloud
            .authorize_invocation(self.invocation, now)
            .await
            .map_err(|error| AdmissionRefused::new(error.to_string()))?;
        self.policy_v3
            .authorize_invocation(self.tinycloud, self.invocation, None, now)
            .await
            .map_err(|error| AdmissionRefused::new(error.to_string()))?;
        let payload = self.invocation.invocation.payload();
        let nonce = payload
            .nonce
            .as_deref()
            .ok_or_else(|| AdmissionRefused::new("missing nonce"))?;
        self.service
            .consume_nonce_until(
                &self.invocation.invoker,
                nonce,
                payload.expiration.as_seconds() as i64,
            )
            .await
            .map_err(|error| AdmissionRefused::new(error.to_string()))
    }
}

/// The checks that need no database: audience, the one `member.admit`
/// capability on exactly `network`, and the network-admin fact naming this
/// node, `network`, the action and the hash of `body`.
pub(super) fn check_admission_shape(
    invocation: &InvocationInfo,
    node_did: &str,
    network: &NetworkId,
    body: &Value,
) -> Result<(), AdmissionRefused> {
    if invocation.invocation.payload().audience != node_did {
        return Err(AdmissionRefused::new("audience is not this node"));
    }
    let [capability] = invocation.capabilities.as_slice() else {
        return Err(AdmissionRefused::new("admission must carry one capability"));
    };
    if capability.ability.to_string() != MEMBER_ADMIT_ACTION {
        return Err(AdmissionRefused::new("capability is not member.admit"));
    }
    if capability
        .resource
        .to_string()
        .parse::<NetworkId>()
        .as_ref()
        != Ok(network)
    {
        return Err(AdmissionRefused::new("capability names another network"));
    }
    let facts = invocation
        .invocation
        .payload()
        .facts
        .as_deref()
        .unwrap_or_default();
    let fact = facts
        .iter()
        .find(|fact| fact.get("type").and_then(Value::as_str) == Some(NETWORK_ADMIN_TYPE))
        .ok_or_else(|| AdmissionRefused::new("missing network-admin fact"))?;
    let facts: NetworkAdminFacts = serde_json::from_value(fact.clone())
        .map_err(|_| AdmissionRefused::new("malformed network-admin fact"))?;
    if facts.target_node != node_did {
        return Err(AdmissionRefused::new("targetNode is not this node"));
    }
    if &facts.network_id != network {
        return Err(AdmissionRefused::new("fact names another network"));
    }
    if facts.action != MEMBER_ADMIT_ACTION {
        return Err(AdmissionRefused::new("fact action is not member.admit"));
    }
    if facts.body_hash != canonical_hash(body) {
        return Err(AdmissionRefused::new("bodyHash does not match the request"));
    }
    Ok(())
}
