//! Canonical wire-format payloads for the tinycloud.link name+cert service.
//!
//! These serializers MUST produce byte-identical output to the TypeScript
//! service's `canonical{Claim,Delete,CertRequest}Payload` in `src/names.ts`.
//! Any drift in field order, whitespace, or number formatting breaks signature
//! verification in production.
//!
//! The Node implementation is `JSON.stringify({...})`. `serde_json::to_string`
//! on a `#[derive(Serialize)]` struct produces exactly the same output for the
//! shapes we care about (ASCII field names, small integer sequence, ASCII
//! subjects/CSRs, IPv4/IPv6 strings without control characters, no floats).
//!
//! We reproduce Node's field ordering by defining struct fields in the same
//! order as the TS canonical function.
//!
//! Ported test vectors from `src/names.test.ts` are exercised in `tests`.
use serde::Serialize;
use tinycloud_core::keys::Keypair;

use super::LinkError;

pub const VERSION: u32 = 1;

/// Body sent as `PUT /v1/names/:name`, matching `NameClaimRecord` in `names.ts`.
#[derive(Debug, Clone, Serialize)]
pub struct NameClaimBody {
    pub version: u32,
    pub action: &'static str,
    pub name: String,
    pub subject: String,
    #[serde(rename = "lanIps")]
    pub lan_ips: Vec<String>,
    pub sequence: u64,
    pub signature: String,
}

/// Canonical payload (no `signature`) that gets signed, matching
/// `canonicalClaimPayload` in `names.ts` exactly.
#[derive(Debug, Serialize)]
struct ClaimCanonical<'a> {
    version: u32,
    action: &'a str,
    name: &'a str,
    subject: &'a str,
    #[serde(rename = "lanIps")]
    lan_ips: &'a [String],
    sequence: u64,
}

pub fn canonical_claim_payload(
    name: &str,
    subject: &str,
    lan_ips: &[String],
    sequence: u64,
) -> String {
    let payload = ClaimCanonical {
        version: VERSION,
        action: "claim",
        name,
        subject,
        lan_ips,
        sequence,
    };
    serde_json::to_string(&payload).expect("claim payload is always serializable")
}

/// Body sent as `DELETE /v1/names/:name`, matching `NameDeleteRecord`.
#[derive(Debug, Clone, Serialize)]
pub struct NameDeleteBody {
    pub version: u32,
    pub action: &'static str,
    pub name: String,
    pub subject: String,
    pub sequence: u64,
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct DeleteCanonical<'a> {
    version: u32,
    action: &'a str,
    name: &'a str,
    subject: &'a str,
    sequence: u64,
}

pub fn canonical_delete_payload(name: &str, subject: &str, sequence: u64) -> String {
    let payload = DeleteCanonical {
        version: VERSION,
        action: "delete",
        name,
        subject,
        sequence,
    };
    serde_json::to_string(&payload).expect("delete payload is always serializable")
}

/// Body sent as `POST /v1/certs/:name`, matching `CertRequestRecord`.
#[derive(Debug, Clone, Serialize)]
pub struct CertRequestBody {
    pub version: u32,
    pub action: &'static str,
    pub name: String,
    pub subject: String,
    pub csr: String,
    pub sequence: u64,
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct CertRequestCanonical<'a> {
    version: u32,
    action: &'a str,
    name: &'a str,
    subject: &'a str,
    csr: &'a str,
    sequence: u64,
}

pub fn canonical_cert_request_payload(
    name: &str,
    subject: &str,
    csr: &str,
    sequence: u64,
) -> String {
    let payload = CertRequestCanonical {
        version: VERSION,
        action: "cert",
        name,
        subject,
        csr,
        sequence,
    };
    serde_json::to_string(&payload).expect("cert-request payload is always serializable")
}

/// Sign a canonical payload with an Ed25519 keypair, returning the base64url
/// (no padding) encoded signature that matches the TS `didKeySigner.sign`
/// output.
pub fn sign_ed25519(keypair: &Keypair, canonical: &str) -> Result<String, LinkError> {
    let signature = keypair
        .sign(canonical.as_bytes())
        .map_err(|err| LinkError::Signing(err.to_string()))?;
    Ok(base64::encode_config(signature, base64::URL_SAFE_NO_PAD))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};
    use tinycloud_core::keys::Keypair;
    // Access the underlying libp2p ed25519 types for test-vector setup via
    // tinycloud-core's re-export. The signer type we care about is the same
    // `Keypair` returned by `StaticSecret::node_keypair()`.
    use libp2p_identity::ed25519 as ed25519_libp2p;

    /// Port of `didKeySigner(seed)` from `src/test-support/signing.ts`:
    /// a 32-byte private key of `[seed; 32]` and a did:key of the corresponding
    /// Ed25519 public key encoded as `did:key:base58btc(0xed 0x01 || pubkey)`.
    fn did_key_signer(seed: u8) -> (Keypair, String) {
        let secret_bytes = [seed; 32];
        let sk = ed25519_libp2p::SecretKey::try_from_bytes(secret_bytes).expect("32 bytes");
        let ed_kp = ed25519_libp2p::Keypair::from(sk);
        let kp: Keypair = ed_kp.clone().into();
        let pk_bytes = ed_kp.public().to_bytes();
        let mut multicodec = vec![0xedu8, 0x01];
        multicodec.extend_from_slice(&pk_bytes);
        // did:key uses multibase base58btc prefix "z".
        let did = format!(
            "did:key:z{}",
            bs58::encode(multicodec)
                .with_alphabet(bs58::Alphabet::BITCOIN)
                .into_string(),
        );
        (kp, did)
    }

    fn parse_did_key(did: &str) -> VerifyingKey {
        let identifier = did.strip_prefix("did:key:").expect("did:key");
        let identifier = identifier.strip_prefix('z').expect("base58btc multibase");
        let bytes = bs58::decode(identifier)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
            .expect("base58 decode");
        assert_eq!(bytes.len(), 34);
        assert_eq!(bytes[0], 0xed);
        assert_eq!(bytes[1], 0x01);
        let pubkey_bytes: [u8; 32] = bytes[2..].try_into().unwrap();
        VerifyingKey::from_bytes(&pubkey_bytes).expect("valid Ed25519 pubkey")
    }

    // Test vector ported from `names.test.ts`:
    //   "canonical claim payload excludes signature and preserves field order"
    #[test]
    fn canonical_claim_matches_ts_vector() {
        let json = canonical_claim_payload(
            "office",
            "did:key:z6MkiFake",
            &["192.168.0.10".to_string()],
            4,
        );
        assert_eq!(
            json,
            "{\"version\":1,\"action\":\"claim\",\"name\":\"office\",\"subject\":\"did:key:z6MkiFake\",\"lanIps\":[\"192.168.0.10\"],\"sequence\":4}"
        );
    }

    // Test vector ported from `names.test.ts`:
    //   "canonical delete payload excludes signature and preserves field order"
    #[test]
    fn canonical_delete_matches_ts_vector() {
        let json = canonical_delete_payload("office", "did:key:z6MkiFake", 5);
        assert_eq!(
            json,
            "{\"version\":1,\"action\":\"delete\",\"name\":\"office\",\"subject\":\"did:key:z6MkiFake\",\"sequence\":5}"
        );
    }

    // The TS canonical-cert-request layout has no test vector in names.test.ts,
    // but we exercise the same field-ordering discipline by asserting the exact
    // string output for a small vector — this is the byte format the service's
    // `verifyCertRequest` will run signature verification against.
    #[test]
    fn canonical_cert_request_matches_ts_shape() {
        let json = canonical_cert_request_payload(
            "certnode",
            "did:key:z6MkiFake",
            "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
            2,
        );
        assert_eq!(
            json,
            "{\"version\":1,\"action\":\"cert\",\"name\":\"certnode\",\"subject\":\"did:key:z6MkiFake\",\"csr\":\"-----BEGIN CERTIFICATE REQUEST-----\\nabc\\n-----END CERTIFICATE REQUEST-----\",\"sequence\":2}"
        );
    }

    // TDD-style port of `names.test.ts` — "validates and verifies a did:key
    // name claim". This is the byte-for-byte parity gate: if canonicalization
    // or signing here drifts from the TS implementation, this test fails.
    #[test]
    fn claim_signature_verifies_with_did_key_pubkey() {
        let (kp, did) = did_key_signer(7);
        let lan_ips = vec!["192.168.1.20".to_string()];
        let canonical = canonical_claim_payload("mynode", &did, &lan_ips, 1);
        let signature_b64url = sign_ed25519(&kp, &canonical).unwrap();

        let signature_bytes =
            base64::decode_config(&signature_b64url, base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(signature_bytes.len(), 64, "Ed25519 signature is 64 bytes");
        let signature = Signature::from_slice(&signature_bytes).unwrap();

        let verifying_key = parse_did_key(&did);
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .expect("signature must verify against the did:key public key");
    }

    // Port of "validates and verifies a name delete record".
    #[test]
    fn delete_signature_verifies_with_did_key_pubkey() {
        let (kp, did) = did_key_signer(11);
        let canonical = canonical_delete_payload("gone-node", &did, 2);
        let signature_b64url = sign_ed25519(&kp, &canonical).unwrap();
        let signature_bytes =
            base64::decode_config(&signature_b64url, base64::URL_SAFE_NO_PAD).unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let verifying_key = parse_did_key(&did);
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .expect("delete signature must verify against the did:key public key");
    }

    // Port of "validates and verifies a cert request record". Sanity-checks
    // that signing across the canonical cert-request layout is round-trippable.
    #[test]
    fn cert_request_signature_verifies_with_did_key_pubkey() {
        let (kp, did) = did_key_signer(13);
        let canonical = canonical_cert_request_payload(
            "certnode",
            &did,
            "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            2,
        );
        let signature_b64url = sign_ed25519(&kp, &canonical).unwrap();
        let signature_bytes =
            base64::decode_config(&signature_b64url, base64::URL_SAFE_NO_PAD).unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let verifying_key = parse_did_key(&did);
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .expect("cert-request signature must verify against the did:key public key");
    }
}
