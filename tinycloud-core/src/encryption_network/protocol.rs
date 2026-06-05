//! Decrypt request/response shapes plus a minimal UCAN-style invocation envelope
//! sufficient to enforce the architecture invariants in v1.
//!
//! NOTE: This is intentionally a self-contained envelope, not the existing
//! TinyCloud CACAO/Ucan invocation. The architecture targets a network resource
//! (`urn:tinycloud:encryption:...`), which the existing `Resource` system does
//! not model natively, and the request flow is a dedicated endpoint rather than
//! the general `/invoke` path. The shape is forward-compatible with promoting
//! `tinycloud.encryption/decrypt` to a first-class capability action later.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::canonical::canonical_hash;
use super::network_id::NetworkId;

pub const DECRYPT_REQUEST_TYPE: &str = "tinycloud.encryption.decrypt/v1";
pub const DECRYPT_RESULT_TYPE: &str = "tinycloud.encryption.decrypt-result/v1";
pub const NETWORK_ADMIN_TYPE: &str = "tinycloud.encryption.network-admin/v1";
pub const DECRYPT_ACTION: &str = "tinycloud.encryption/decrypt";
pub const NETWORK_CREATE_ACTION: &str = "tinycloud.encryption/network.create";
pub const NETWORK_REVOKE_ACTION: &str = "tinycloud.encryption/network.revoke";

/// Body of a POST /encryption/networks/<networkId>/decrypt request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequestBody {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "targetNode")]
    pub target_node: String,
    #[serde(rename = "networkId")]
    pub network_id: NetworkId,
    pub alg: String,
    #[serde(rename = "keyVersion")]
    pub key_version: i64,
    /// Base64-encoded wrapped symmetric key.
    #[serde(rename = "encryptedSymmetricKey")]
    pub encrypted_symmetric_key: String,
    #[serde(rename = "encryptedSymmetricKeyHash")]
    pub encrypted_symmetric_key_hash: String,
    /// Base64-encoded receiver public key (per-request).
    #[serde(rename = "receiverPublicKey")]
    pub receiver_public_key: String,
    #[serde(rename = "receiverPublicKeyHash")]
    pub receiver_public_key_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponseBody {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "targetNode")]
    pub target_node: String,
    #[serde(rename = "networkId")]
    pub network_id: NetworkId,
    #[serde(rename = "invocationCid")]
    pub invocation_cid: String,
    #[serde(rename = "encryptedSymmetricKeyHash")]
    pub encrypted_symmetric_key_hash: String,
    #[serde(rename = "receiverPublicKeyHash")]
    pub receiver_public_key_hash: String,
    /// Base64-encoded symmetric key wrapped to the receiver public key.
    #[serde(rename = "wrappedKey")]
    pub wrapped_key: String,
    pub alg: String,
    #[serde(rename = "keyVersion")]
    pub key_version: i64,
    #[serde(rename = "requestHash")]
    pub request_hash: String,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "nodeSignature")]
    pub node_signature: String,
}

/// UCAN-style invocation envelope for the decrypt action.
///
/// `issuer` is the requester session DID. `audience` MUST equal the serving
/// node's DID. `proof_cid` references the delegation chain that authorizes the
/// decrypt action; verification rooted in the principal embedded in
/// `network_id` is performed by [`crate::encryption_network::service`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptInvocation {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    pub att: Vec<InvocationCapability>,
    pub facts: DecryptFacts,
    pub nonce: String,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    pub exp: i64,
    #[serde(rename = "prf", default)]
    pub proof_cid: Vec<String>,
    /// Signature over the canonical encoding of {iss, aud, att, facts, nonce,
    /// nbf, exp, prf}. The signature scheme is left to the caller; v1
    /// verifies it by recomputing `invocationCid` and validating against the
    /// requester key bound to the invocation issuer.
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationCapability {
    /// Resource URN. For decrypt this MUST equal the network id.
    pub with: String,
    /// Capability action. For decrypt this MUST equal `tinycloud.encryption/decrypt`.
    pub can: String,
    /// Caveats. Decrypt has no caveats in v1.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nb: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptFacts {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "targetNode")]
    pub target_node: String,
    #[serde(rename = "networkId")]
    pub network_id: NetworkId,
    #[serde(rename = "bodyHash")]
    pub body_hash: String,
    #[serde(rename = "encryptedSymmetricKeyHash")]
    pub encrypted_symmetric_key_hash: String,
    #[serde(rename = "receiverPublicKeyHash")]
    pub receiver_public_key_hash: String,
    pub alg: String,
    #[serde(rename = "keyVersion")]
    pub key_version: i64,
}

/// UCAN-style invocation envelope for encryption-network lifecycle actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdminInvocation {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    pub att: Vec<InvocationCapability>,
    pub facts: NetworkAdminFacts,
    pub nonce: String,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    pub exp: i64,
    #[serde(rename = "prf", default)]
    pub proof_cid: Vec<String>,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdminFacts {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "targetNode")]
    pub target_node: String,
    #[serde(rename = "networkId")]
    pub network_id: NetworkId,
    #[serde(rename = "bodyHash")]
    pub body_hash: String,
    pub action: String,
}

impl DecryptInvocation {
    pub fn unsigned_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "iss": self.issuer,
            "aud": self.audience,
            "att": self.att,
            "facts": self.facts,
            "nonce": self.nonce,
            "nbf": self.not_before,
            "exp": self.exp,
            "prf": self.proof_cid,
        })
    }

    /// Stable identifier for the invocation. Used as `invocationCid` in
    /// responses and as part of the request-hash used for audit/replay.
    pub fn cid(&self) -> String {
        canonical_hash(&self.unsigned_payload())
    }
}

impl NetworkAdminInvocation {
    pub fn unsigned_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "iss": self.issuer,
            "aud": self.audience,
            "att": self.att,
            "facts": self.facts,
            "nonce": self.nonce,
            "nbf": self.not_before,
            "exp": self.exp,
            "prf": self.proof_cid,
        })
    }

    pub fn cid(&self) -> String {
        canonical_hash(&self.unsigned_payload())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_invocation() -> DecryptInvocation {
        let net: NetworkId = "urn:tinycloud:encryption:did:key:z6MkPrincipal:default"
            .parse()
            .unwrap();
        DecryptInvocation {
            issuer: "did:key:z6MkRequester".to_string(),
            audience: "did:key:z6MkNode".to_string(),
            att: vec![InvocationCapability {
                with: net.to_string(),
                can: DECRYPT_ACTION.to_string(),
                nb: BTreeMap::new(),
            }],
            facts: DecryptFacts {
                ty: DECRYPT_REQUEST_TYPE.to_string(),
                target_node: "did:key:z6MkNode".to_string(),
                network_id: net,
                body_hash: "aa".repeat(32),
                encrypted_symmetric_key_hash: "bb".repeat(32),
                receiver_public_key_hash: "cc".repeat(32),
                alg: "x25519-aes256gcm/v1".to_string(),
                key_version: 1,
            },
            nonce: "nonce-1".to_string(),
            not_before: None,
            exp: 1_900_000_000,
            proof_cid: vec!["bafy".to_string()],
            sig: "sig".to_string(),
        }
    }

    #[test]
    fn cid_changes_with_facts() {
        let mut a = sample_invocation();
        let cid_a = a.cid();
        a.facts.body_hash = "dd".repeat(32);
        let cid_b = a.cid();
        assert_ne!(cid_a, cid_b);
    }

    #[test]
    fn cid_changes_with_audience() {
        let mut a = sample_invocation();
        let cid_a = a.cid();
        a.audience = "did:key:other".to_string();
        let cid_b = a.cid();
        assert_ne!(cid_a, cid_b);
    }

    #[test]
    fn cid_changes_with_capabilities() {
        let mut a = sample_invocation();
        let cid_a = a.cid();
        a.att[0].can = "tinycloud.encryption/other".to_string();
        let cid_b = a.cid();
        assert_ne!(cid_a, cid_b);
    }

    #[test]
    fn signature_is_not_part_of_cid() {
        let mut a = sample_invocation();
        let cid_a = a.cid();
        a.sig = "another".to_string();
        let cid_b = a.cid();
        assert_eq!(cid_a, cid_b);
    }

    #[test]
    fn body_round_trips() {
        let body = DecryptRequestBody {
            ty: DECRYPT_REQUEST_TYPE.to_string(),
            target_node: "did:key:z6MkNode".to_string(),
            network_id: "urn:tinycloud:encryption:did:key:z6Mk:default"
                .parse()
                .unwrap(),
            alg: "x25519-aes256gcm/v1".to_string(),
            key_version: 1,
            encrypted_symmetric_key: "AQID".to_string(),
            encrypted_symmetric_key_hash: "aa".repeat(32),
            receiver_public_key: "BAUG".to_string(),
            receiver_public_key_hash: "bb".repeat(32),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], json!(DECRYPT_REQUEST_TYPE));
        let parsed: DecryptRequestBody = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.encrypted_symmetric_key, body.encrypted_symmetric_key);
    }
}
