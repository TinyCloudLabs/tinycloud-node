//! Canonical wire-format payload for the tunnel relay's first-frame auth
//! record (`TunnelAuthRecord` / `canonicalTunnelAuthPayload` in
//! `tinycloud-link/src/names.ts`).
//!
//! This serializer MUST produce byte-identical output to the TypeScript
//! service's `canonicalTunnelAuthPayload`. Any drift in field order,
//! whitespace, or number formatting breaks signature verification in
//! production — see `link::payload`, which this mirrors for the
//! claim/delete/cert-request payloads.
use serde::Serialize;
use tinycloud_core::keys::Keypair;

use crate::link::payload::sign_ed25519;
use crate::link::LinkError;

pub const VERSION: u32 = 1;

/// Body sent as the first WebSocket message on
/// `wss://.../v1/tunnel/:name`, matching `TunnelAuthRecord` in `names.ts`.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelAuthFrame {
    pub version: u32,
    pub action: &'static str,
    pub name: String,
    pub subject: String,
    pub sequence: u64,
    pub signature: String,
}

/// Canonical payload (no `signature`) that gets signed, matching
/// `canonicalTunnelAuthPayload` in `names.ts` exactly: fixed key order
/// `version, action, name, subject, sequence`.
#[derive(Debug, Serialize)]
struct TunnelAuthCanonical<'a> {
    version: u32,
    action: &'a str,
    name: &'a str,
    subject: &'a str,
    sequence: u64,
}

pub fn canonical_tunnel_auth_payload(name: &str, subject: &str, sequence: u64) -> String {
    let payload = TunnelAuthCanonical {
        version: VERSION,
        action: "tunnel",
        name,
        subject,
        sequence,
    };
    serde_json::to_string(&payload).expect("tunnel auth payload is always serializable")
}

/// Sign a fresh tunnel auth frame for `name`/`subject`/`sequence` with the
/// node's Ed25519 identity keypair. `sequence` must already be the next
/// unused value from the name's shared sequence counter (see
/// `link::state::LinkState::next_sequence` — the tunnel action reuses the
/// exact same counter as claim/delete/cert).
pub fn build_auth_frame(
    keypair: &Keypair,
    name: &str,
    subject: &str,
    sequence: u64,
) -> Result<TunnelAuthFrame, LinkError> {
    let canonical = canonical_tunnel_auth_payload(name, subject, sequence);
    let signature = sign_ed25519(keypair, &canonical)?;
    Ok(TunnelAuthFrame {
        version: VERSION,
        action: "tunnel",
        name: name.to_string(),
        subject: subject.to_string(),
        sequence,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};
    use libp2p_identity::ed25519 as ed25519_libp2p;

    /// Port of `didKeySigner(seed)` from `tinycloud-link/src/test-support/signing.ts`
    /// (also ported in `link::payload::tests::did_key_signer`): a 32-byte
    /// private key of `[seed; 32]` and the did:key of the corresponding
    /// Ed25519 public key.
    fn did_key_signer(seed: u8) -> (Keypair, String) {
        let secret_bytes = [seed; 32];
        let sk = ed25519_libp2p::SecretKey::try_from_bytes(secret_bytes).expect("32 bytes");
        let ed_kp = ed25519_libp2p::Keypair::from(sk);
        let kp: Keypair = ed_kp.clone().into();
        let pk_bytes = ed_kp.public().to_bytes();
        let mut multicodec = vec![0xedu8, 0x01];
        multicodec.extend_from_slice(&pk_bytes);
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

    // Test vector ported from `names.test.ts`'s tunnel-auth canonicalization:
    // fixed key order `version, action, name, subject, sequence`, signature
    // excluded from the signed bytes.
    #[::core::prelude::v1::test]
    fn canonical_tunnel_auth_matches_ts_vector() {
        let json = canonical_tunnel_auth_payload("tunnelnode", "did:key:z6MkiFake", 2);
        assert_eq!(
            json,
            "{\"version\":1,\"action\":\"tunnel\",\"name\":\"tunnelnode\",\"subject\":\"did:key:z6MkiFake\",\"sequence\":2}"
        );
    }

    // Port of names.test.ts: "validates and verifies a tunnel auth record" —
    // the byte-for-byte parity gate: if canonicalization or signing here
    // drifts from the TS implementation, this test fails.
    #[::core::prelude::v1::test]
    fn tunnel_auth_signature_verifies_with_did_key_pubkey() {
        let (kp, did) = did_key_signer(21);
        let frame = build_auth_frame(&kp, "tunnelnode", &did, 2).unwrap();

        assert_eq!(frame.version, 1);
        assert_eq!(frame.action, "tunnel");
        assert_eq!(frame.name, "tunnelnode");
        assert_eq!(frame.subject, did);
        assert_eq!(frame.sequence, 2);

        let canonical = canonical_tunnel_auth_payload("tunnelnode", &did, 2);
        let signature_bytes =
            base64::decode_config(&frame.signature, base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(signature_bytes.len(), 64, "Ed25519 signature is 64 bytes");
        let signature = Signature::from_slice(&signature_bytes).unwrap();

        let verifying_key = parse_did_key(&did);
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .expect("signature must verify against the did:key public key");
    }

    // Port of names.test.ts: "rejects a tunnel auth record signed by the
    // wrong key" — same canonical bytes signed by a different key must not
    // verify against the claimed subject's public key.
    #[::core::prelude::v1::test]
    fn tunnel_auth_signature_does_not_verify_for_wrong_signer() {
        let (_owner_kp, owner_did) = did_key_signer(22);
        let (forger_kp, _forger_did) = did_key_signer(23);

        let canonical = canonical_tunnel_auth_payload("tunnelnode", &owner_did, 2);
        let signature = sign_ed25519(&forger_kp, &canonical).unwrap();
        let signature_bytes = base64::decode_config(&signature, base64::URL_SAFE_NO_PAD).unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();

        let owner_key = parse_did_key(&owner_did);
        assert!(owner_key
            .verify_strict(canonical.as_bytes(), &signature)
            .is_err());
    }
}
