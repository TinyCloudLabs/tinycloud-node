use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use tinycloud_core::policy_authority::{
    AuthorityArtifactVerifier, DelegationMode, DelegationRole, DelegationSignature,
    PolicyDelegation,
};

const SCHEMA: &str = "xyz.tinycloud.policy/enforcement-delegation/v1";
const ROOT_DOMAIN: &[u8] = b"xyz.tinycloud.policy/enforcement-delegation/v1\0";
const OWNER_SEED: [u8; 32] = [7; 32];

fn signed_owner_parent(mut parent: PolicyDelegation) -> Vec<u8> {
    use k256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;
    use tinycloud_auth::{
        ipld_core::cid::Cid,
        multihash_codetable::{Code, MultihashDigest},
    };

    let mut unsigned = serde_json::to_value(&parent).expect("parent json");
    let object = unsigned.as_object_mut().expect("parent object");
    object.remove("delegationCid");
    object.remove("signature");
    let unsigned = tinycloud_core::policy_capability::jcs::canonicalize(&unsigned);
    let digest = Sha256::digest([ROOT_DOMAIN, unsigned.as_slice()].concat());
    let mut preimage = b"\x19Ethereum Signed Message:\n32".to_vec();
    preimage.extend_from_slice(&digest);
    let hash = Keccak256::digest(preimage);
    let signing = SigningKey::from_bytes((&OWNER_SEED).into()).expect("owner key");
    let (signature, recovery) = signing
        .sign_prehash_recoverable(&hash)
        .expect("owner signature");
    let mut signature = signature.to_bytes().to_vec();
    signature.push(recovery.to_byte() + 27);
    parent.signature = DelegationSignature {
        suite: "eip191-secp256k1-sha256-jcs-v1".to_owned(),
        value: URL_SAFE_NO_PAD.encode(signature),
    };
    let mut cid_value = serde_json::to_value(&parent).expect("signed parent json");
    cid_value
        .as_object_mut()
        .expect("signed parent object")
        .remove("delegationCid");
    parent.delegation_cid = Cid::new_v1(
        0x55,
        Code::Blake3_256.digest(&tinycloud_core::policy_capability::jcs::canonicalize(
            &cid_value,
        )),
    )
    .to_string();
    tinycloud_core::policy_capability::jcs::canonicalize(
        &serde_json::to_value(parent).expect("canonical parent"),
    )
}

fn parent(role: DelegationRole, audience: &str) -> PolicyDelegation {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    let signing = SigningKey::from_bytes((&OWNER_SEED).into()).expect("owner key");
    let point = signing.verifying_key().to_encoded_point(false);
    let address = Keccak256::digest(&point.as_bytes()[1..]);
    let owner = format!("did:pkh:eip155:1:0x{}", hex::encode(&address[12..]));
    let mut facts = std::collections::BTreeMap::new();
    facts.insert("xyz.tinycloud.policy/ownerDid".to_owned(), owner.clone());
    facts.insert(
        "xyz.tinycloud.policy/policyId".to_owned(),
        "pol_exact_email_boundary".to_owned(),
    );
    facts.insert(
        "xyz.tinycloud.policy/policyDigestHex".to_owned(),
        "a".repeat(64),
    );
    facts.insert(
        "xyz.tinycloud.policy/capabilityCeilingHashHex".to_owned(),
        "b".repeat(64),
    );
    if role == DelegationRole::PolicyEnforcement {
        let attestation_digest = "c".repeat(64);
        for (name, value) in [
            ("enforcerDid", audience),
            ("nodeAudience", audience),
            ("attestationBindingDigestHex", attestation_digest.as_str()),
            ("maxSessionTtlSeconds", "300"),
            ("sessionMode", "attenuable"),
            ("maxRedelegationDepth", "2"),
            ("auditProfile", "vp-digest-v1"),
        ] {
            facts.insert(format!("xyz.tinycloud.policy/{name}"), value.to_owned());
        }
    }
    PolicyDelegation {
        schema: SCHEMA.to_owned(),
        role,
        delegation_cid: String::new(),
        issuer_did: owner,
        audience_did: audience.to_owned(),
        capabilities: vec![json!({
            "service": "tinycloud.kv",
            "space": "applications",
            "path": "documents/plan.md",
            "actions": ["tinycloud.kv/get"]
        })],
        proof_cids: vec![],
        not_before: "2026-07-20T00:00:00Z".to_owned(),
        expires_at: "2026-07-21T00:00:00Z".to_owned(),
        delegation_mode: if role == DelegationRole::PolicyAuthority {
            DelegationMode::PolicySource
        } else {
            DelegationMode::ConditionalMint
        },
        facts,
        signature: DelegationSignature {
            suite: "eip191-secp256k1-sha256-jcs-v1".to_owned(),
            value: String::new(),
        },
    }
}

#[test]
fn public_boundary_accepts_only_owner_signed_parent_bytes() {
    let policy = signed_owner_parent(parent(
        DelegationRole::PolicyAuthority,
        "did:web:node.example",
    ));
    let enforcement = signed_owner_parent(parent(
        DelegationRole::PolicyEnforcement,
        "did:pkh:eip155:1:0x0000000000000000000000000000000000000002",
    ));
    let verifier = AuthorityArtifactVerifier;
    verifier
        .verify(&policy)
        .expect("owner-signed policy parent");
    verifier
        .verify(&enforcement)
        .expect("owner-signed enforcement parent");

    let mut fabricated: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    fabricated["signature"]["value"] = json!(URL_SAFE_NO_PAD.encode([0u8; 65]));
    assert!(verifier
        .verify(&serde_json::to_vec(&fabricated).unwrap())
        .is_err());
}
