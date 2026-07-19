//! Cryptographic boundary for the accepted #117 delegation profile.
//!
//! The verifier is intentionally small: it authenticates canonical artifact
//! bytes, checks the profile's CID, and returns the sealed `VerifiedDelegation`
//! type. It does not resolve status, attestation, or Share-to-#117 mappings.

use super::{DelegationRole, DelegationSignature, PolicyDelegation, VerifiedDelegation};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use libp2p::identity::ed25519::Keypair;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tinycloud_auth::{
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
};

const RAW_CODEC: u64 = 0x55;
const ROOT_DOMAIN: &[u8] = b"xyz.tinycloud.policy/enforcement-delegation/v1\0";
const EIP191_SUITE: &str = "eip191-secp256k1-sha256-jcs-v1";
const ED25519_SUITE: &str = "eddsa-ed25519-sha256-jcs-v1";

/// A configured node signer for terminal/root #117 artifacts.
#[derive(Clone)]
pub struct ConfiguredNodeRootSigner {
    did: String,
    keypair: Keypair,
}

impl ConfiguredNodeRootSigner {
    pub fn new(did: impl Into<String>, keypair: Keypair) -> Self {
        Self {
            did: did.into(),
            keypair,
        }
    }
}

/// The only signing operation accepted by the authority verifier.
pub trait NodeRootSigner: Send + Sync {
    fn signer_did(&self) -> &str;
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, super::AuthorityError>;
}

impl NodeRootSigner for ConfiguredNodeRootSigner {
    fn signer_did(&self) -> &str {
        &self.did
    }

    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, super::AuthorityError> {
        Ok(self.keypair.sign(bytes))
    }
}

/// Verifies signed #117 artifacts under the frozen v1 profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorityArtifactVerifier;

impl AuthorityArtifactVerifier {
    pub fn verify(&self, bytes: &[u8]) -> Result<VerifiedDelegation, super::AuthorityError> {
        let artifact = PolicyDelegation::from_json(bytes)?;
        verify_artifact(&artifact)?;
        Ok(VerifiedDelegation::from_verified(artifact))
    }

    /// Sign an unsigned node-root artifact with the configured node key and
    /// immediately verify both its signature and CID before returning it.
    pub fn sign_and_verify_root(
        &self,
        mut artifact: PolicyDelegation,
        signer: &dyn NodeRootSigner,
    ) -> Result<VerifiedDelegation, super::AuthorityError> {
        if artifact.role != DelegationRole::PolicySessionRoot
            || artifact.signature.suite != ED25519_SUITE
            || artifact.issuer_did != signer.signer_did()
        {
            return Err(super::AuthorityError::WrongEnforcer);
        }
        let unsigned = canonical_unsigned(&artifact)?;
        let signed = signing_bytes(&unsigned);
        let signature = signer.sign(&signed)?;
        artifact.signature = DelegationSignature {
            suite: ED25519_SUITE.to_owned(),
            value: URL_SAFE_NO_PAD.encode(signature),
        };
        artifact.delegation_cid = cid_for_artifact(&artifact)?;
        let encoded =
            serde_json::to_vec(&artifact).map_err(|_| super::AuthorityError::SchemaInvalid)?;
        let verified = self.verify(&encoded)?;
        if verified.artifact().issuer_did != signer.signer_did() {
            return Err(super::AuthorityError::WrongEnforcer);
        }
        Ok(verified)
    }
}

pub(crate) fn canonical_unsigned(
    artifact: &PolicyDelegation,
) -> Result<Vec<u8>, super::AuthorityError> {
    let mut value =
        serde_json::to_value(artifact).map_err(|_| super::AuthorityError::SchemaInvalid)?;
    value
        .as_object_mut()
        .ok_or(super::AuthorityError::SchemaInvalid)?
        .retain(|key, _| key != "signature" && key != "delegationCid");
    Ok(crate::policy_capability::jcs::canonicalize(&value))
}

fn canonical_cid(artifact: &PolicyDelegation) -> Result<Vec<u8>, super::AuthorityError> {
    let mut value =
        serde_json::to_value(artifact).map_err(|_| super::AuthorityError::SchemaInvalid)?;
    let object = value
        .as_object_mut()
        .ok_or(super::AuthorityError::SchemaInvalid)?;
    object.remove("delegationCid");
    Ok(crate::policy_capability::jcs::canonicalize(&value))
}

fn cid_for_artifact(artifact: &PolicyDelegation) -> Result<String, super::AuthorityError> {
    let hash = Code::Blake3_256.digest(&canonical_cid(artifact)?);
    Ok(Cid::new_v1(RAW_CODEC, hash).to_string())
}

fn signing_bytes(unsigned: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest([ROOT_DOMAIN, unsigned].concat());
    digest.to_vec()
}

fn verify_artifact(artifact: &PolicyDelegation) -> Result<(), super::AuthorityError> {
    let unsigned = canonical_unsigned(artifact)?;
    let hash = Code::Blake3_256.digest(&canonical_cid(artifact)?);
    let expected_cid = Cid::new_v1(RAW_CODEC, hash);
    if artifact.delegation_cid != expected_cid.to_string() {
        return Err(super::AuthorityError::SchemaInvalid);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(artifact.signature.value.as_bytes())
        .map_err(|_| super::AuthorityError::SchemaInvalid)?;
    if URL_SAFE_NO_PAD.encode(&signature) != artifact.signature.value {
        return Err(super::AuthorityError::SchemaInvalid);
    }
    match artifact.signature.suite.as_str() {
        EIP191_SUITE => verify_eip191(artifact, &unsigned, &signature),
        ED25519_SUITE => verify_ed25519(artifact, &unsigned, &signature),
        _ => Err(super::AuthorityError::SchemaInvalid),
    }
}

fn verify_eip191(
    artifact: &PolicyDelegation,
    unsigned: &[u8],
    signature: &[u8],
) -> Result<(), super::AuthorityError> {
    if signature.len() != 65 {
        return Err(super::AuthorityError::SchemaInvalid);
    }
    let recovery = match signature[64] {
        27 | 28 => RecoveryId::try_from(signature[64] - 27),
        0 | 1 => RecoveryId::try_from(signature[64]),
        _ => return Err(super::AuthorityError::SchemaInvalid),
    }
    .map_err(|_| super::AuthorityError::SchemaInvalid)?;
    let digest = Sha256::digest([ROOT_DOMAIN, unsigned].concat());
    let mut preimage = b"\\x19Ethereum Signed Message:\\n32".to_vec();
    preimage.extend_from_slice(&digest);
    let hash = Keccak256::digest(preimage);
    let sig = Signature::from_slice(&signature[..64])
        .map_err(|_| super::AuthorityError::SchemaInvalid)?;
    let key = VerifyingKey::recover_from_prehash(&hash, &sig, recovery)
        .map_err(|_| super::AuthorityError::SchemaInvalid)?;
    let public = key.to_encoded_point(false);
    let address = Keccak256::digest(&public.as_bytes()[1..]);
    let expected = artifact
        .issuer_did
        .rsplit(':')
        .next()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 20)
        .ok_or(super::AuthorityError::SchemaInvalid)?;
    if address[12..] != expected[..] {
        return Err(super::AuthorityError::OwnerMismatch);
    }
    Ok(())
}

fn verify_ed25519(
    artifact: &PolicyDelegation,
    unsigned: &[u8],
    signature: &[u8],
) -> Result<(), super::AuthorityError> {
    if signature.len() != 64 {
        return Err(super::AuthorityError::SchemaInvalid);
    }
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(
        &artifact.issuer_did,
        &signing_bytes(unsigned),
        signature,
    )
    .map_err(|_| super::AuthorityError::SchemaInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_node_root_is_signed_and_reverified_before_acceptance() {
        let keypair = libp2p::identity::ed25519::Keypair::generate();
        let signer_did = crate::keys::public_key_to_did_key(keypair.public().into());
        let mut facts = std::collections::BTreeMap::new();
        for (name, value) in [
            (
                "ownerDid",
                "did:pkh:eip155:1:0x0000000000000000000000000000000000000001",
            ),
            (
                "policyId",
                "pol_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "policyDigestHex",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "capabilityCeilingHashHex",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "capabilityHashHex",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            ("enforcerDid", signer_did.as_str()),
            ("nodeAudience", signer_did.as_str()),
            ("rootClaimantDid", signer_did.as_str()),
            ("sessionSubjectDid", signer_did.as_str()),
            (
                "policyDelegationCid",
                "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "enforcementDelegationCid",
                "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "attestationBindingDigestHex",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
            (
                "claimInvocationDigestHex",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
            (
                "vpDigestHex",
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            ),
            (
                "decisionContextDigestHex",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "issuanceAuditDigestHex",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            ("issuanceId", "peiss_aaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("remainingRedelegationDepth", "2"),
            ("auditProfile", "vp-digest-v1"),
        ] {
            facts.insert(format!("xyz.tinycloud.policy/{name}"), value.to_owned());
        }
        let artifact = PolicyDelegation {
            schema: "xyz.tinycloud.policy/enforcement-delegation/v1".to_owned(),
            role: DelegationRole::PolicySessionRoot,
            delegation_cid: "placeholder".to_owned(),
            issuer_did: signer_did.clone(),
            audience_did: signer_did.clone(),
            capabilities: vec![serde_json::json!({
                "actions": ["tinycloud.kv/get"],
                "path": "documents/readme.md",
                "service": "tinycloud.kv",
                "space": "applications"
            })],
            proof_cids: vec!["policy-parent".to_owned(), "enforcement-parent".to_owned()],
            not_before: "2026-07-19T00:00:00Z".to_owned(),
            expires_at: "2026-07-19T00:05:00Z".to_owned(),
            delegation_mode: super::super::DelegationMode::Attenuable,
            facts,
            signature: DelegationSignature {
                suite: ED25519_SUITE.to_owned(),
                value: String::new(),
            },
        };
        let signed = AuthorityArtifactVerifier
            .sign_and_verify_root(
                artifact,
                &ConfiguredNodeRootSigner::new(signer_did, keypair),
            )
            .unwrap();
        assert_eq!(signed.artifact().signature.suite, ED25519_SUITE);
        assert!(signed.artifact().delegation_cid.starts_with("bafkr4i"));
    }

    #[test]
    fn pinned_contract_rows_require_full_crypto_verification() {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("contract_accepted.json")).unwrap();
        for name in ["policyAuthority", "policyEnforcement", "rootSession"] {
            let bytes = serde_json::to_vec(&value[name]).unwrap();
            let artifact = PolicyDelegation::from_json(&bytes).unwrap();
            assert_eq!(
                cid_for_artifact(&artifact).unwrap(),
                artifact.delegation_cid
            );
            assert!(
                AuthorityArtifactVerifier.verify(&bytes).is_err(),
                "{name} must not bypass signature verification"
            );
        }
    }
}
