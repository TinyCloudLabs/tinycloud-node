use crate::types::{Signature, SignatureSuite};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::{RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1Key};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported-suite")]
    UnsupportedSuite,
    #[error("invalid-signature-encoding")]
    InvalidSignatureEncoding,
    #[error("invalid-did")]
    InvalidDid,
    #[error("signature-invalid")]
    SignatureInvalid,
}

pub fn verify_signature(signature: &Signature, digest: &[u8; 32]) -> Result<(), CryptoError> {
    match signature.suite {
        SignatureSuite::EddsaEd25519Sha256JcsV1 => verify_ed25519(signature, digest),
        SignatureSuite::Eip191Secp256k1Sha256JcsV1 => verify_eip191(signature, digest),
    }
}

fn verify_ed25519(signature: &Signature, digest: &[u8; 32]) -> Result<(), CryptoError> {
    let public_key = ed25519_public_key_from_did(&signature.signer_did)?;
    let verifying_key =
        Ed25519VerifyingKey::from_bytes(&public_key).map_err(|_| CryptoError::InvalidDid)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature.value.as_bytes())
        .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
    let signature = Ed25519Signature::from_slice(&signature_bytes)
        .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(digest, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

fn verify_eip191(signature: &Signature, digest: &[u8; 32]) -> Result<(), CryptoError> {
    let expected_address = did_pkh_eip155_address(&signature.signer_did)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature.value.as_bytes())
        .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
    if signature_bytes.len() != 65 {
        return Err(CryptoError::InvalidSignatureEncoding);
    }
    let signature = Secp256k1Signature::from_slice(&signature_bytes[..64])
        .map_err(|_| CryptoError::SignatureInvalid)?;
    let recovery_byte = match signature_bytes[64] {
        27 => 0,
        28 => 1,
        _ => return Err(CryptoError::InvalidSignatureEncoding),
    };
    let recovery_id =
        RecoveryId::try_from(recovery_byte).map_err(|_| CryptoError::SignatureInvalid)?;
    let message_hash = eip191_digest_hash(digest);
    let verifying_key = Secp256k1Key::recover_from_prehash(&message_hash, &signature, recovery_id)
        .map_err(|_| CryptoError::SignatureInvalid)?;
    let recovered = ethereum_address_from_key(&verifying_key);
    if recovered.eq_ignore_ascii_case(&expected_address) {
        Ok(())
    } else {
        Err(CryptoError::SignatureInvalid)
    }
}

fn ed25519_public_key_from_did(did: &str) -> Result<[u8; 32], CryptoError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or(CryptoError::InvalidDid)?;
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| CryptoError::InvalidDid)?;
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(CryptoError::InvalidDid);
    }
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(&decoded[2..]);
    Ok(public_key)
}

fn did_pkh_eip155_address(did: &str) -> Result<String, CryptoError> {
    let mut parts = did.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("did"), Some("pkh"), Some("eip155"), Some(_chain_id), Some(address), None) => {
            let address = address.to_ascii_lowercase();
            if address.len() == 42
                && address.starts_with("0x")
                && address[2..].chars().all(|ch| ch.is_ascii_hexdigit())
            {
                Ok(address)
            } else {
                Err(CryptoError::InvalidDid)
            }
        }
        _ => Err(CryptoError::InvalidDid),
    }
}

fn eip191_digest_hash(digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(digest);
    hasher.finalize().into()
}

fn ethereum_address_from_key(key: &Secp256k1Key) -> String {
    let encoded = key.to_encoded_point(false);
    let uncompressed = encoded.as_bytes();
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]);
    let hash = hasher.finalize();
    let address = &hash[12..];
    let mut out = String::from("0x");
    out.push_str(&crate::capability::hex_lower(address));
    out
}
