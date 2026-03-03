use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

fn map_vault_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

/// AES-256-GCM encrypt.
/// Returns [12-byte nonce || ciphertext || 16-byte tag].
#[wasm_bindgen]
pub fn vault_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(map_vault_err("key must be 32 bytes"));
    }

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(result)
}

/// AES-256-GCM decrypt.
/// Expects input as [12-byte nonce || ciphertext || 16-byte tag].
#[wasm_bindgen]
pub fn vault_decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(map_vault_err("key must be 32 bytes"));
    }
    if blob.len() < 28 {
        return Err(map_vault_err(
            "blob too short: need at least 28 bytes (12 nonce + 16 tag)",
        ));
    }

    let (nonce_bytes, ciphertext_with_tag) = blob.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| map_vault_err("invalid nonce length"))?;
    let nonce = Nonce::from(nonce_array);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext_with_tag)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(plaintext)
}

/// HKDF-SHA256 key derivation.
/// Returns a 32-byte derived key.
#[wasm_bindgen]
pub fn vault_derive_key(salt: &[u8], signature: &[u8], info: &[u8]) -> Result<Vec<u8>, JsValue> {
    let hk = Hkdf::<Sha256>::new(Some(salt), signature);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(output.to_vec())
}

#[derive(serde::Serialize)]
struct X25519KeyPair {
    #[serde(rename = "publicKey", with = "serde_bytes")]
    public_key: Vec<u8>,
    #[serde(rename = "privateKey", with = "serde_bytes")]
    private_key: Vec<u8>,
}

/// Generate an X25519 keypair from a 32-byte seed.
/// Returns a JS object with `publicKey` and `privateKey` as Uint8Array.
#[wasm_bindgen]
pub fn vault_x25519_from_seed(seed: &[u8]) -> Result<JsValue, JsValue> {
    if seed.len() != 32 {
        return Err(map_vault_err("seed must be 32 bytes"));
    }

    let seed_array: [u8; 32] = seed.try_into().unwrap();
    let secret = StaticSecret::from(seed_array);
    let public = PublicKey::from(&secret);

    let keypair = X25519KeyPair {
        public_key: public.as_bytes().to_vec(),
        private_key: secret.to_bytes().to_vec(),
    };

    serde_wasm_bindgen::to_value(&keypair).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// X25519 Diffie-Hellman shared secret computation.
/// Both private_key and public_key must be 32 bytes.
#[wasm_bindgen]
pub fn vault_x25519_dh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if private_key.len() != 32 {
        return Err(map_vault_err("private_key must be 32 bytes"));
    }
    if public_key.len() != 32 {
        return Err(map_vault_err("public_key must be 32 bytes"));
    }

    let priv_array: [u8; 32] = private_key.try_into().unwrap();
    let pub_array: [u8; 32] = public_key.try_into().unwrap();

    let secret = StaticSecret::from(priv_array);
    let their_public = PublicKey::from(pub_array);

    let shared_secret = secret.diffie_hellman(&their_public);
    Ok(shared_secret.as_bytes().to_vec())
}

/// Generate cryptographically secure random bytes.
#[wasm_bindgen]
pub fn vault_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    let mut buf = vec![0u8; length];
    getrandom::getrandom(&mut buf).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(buf)
}

/// SHA-256 hash of the input data.
#[wasm_bindgen]
pub fn vault_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::new().chain_update(data).finalize().to_vec()
}

/// Convert an Ed25519 seed (32 bytes) to an X25519 key pair.
///
/// Uses the standard Ed25519-to-X25519 conversion:
/// 1. SHA-512(seed) → take first 32 bytes → X25519 private scalar (clamped by StaticSecret)
/// 2. Derive X25519 public key from private scalar
///
/// This allows session keys (Ed25519) to participate in vault encryption
/// without requiring a wallet signature.
#[wasm_bindgen]
pub fn vault_ed25519_seed_to_x25519(ed25519_seed: &[u8]) -> Result<JsValue, JsValue> {
    if ed25519_seed.len() != 32 {
        return Err(map_vault_err("ed25519_seed must be 32 bytes"));
    }

    let hash = Sha512::digest(ed25519_seed);
    let mut x25519_bytes: [u8; 32] = hash[..32].try_into().unwrap();

    // StaticSecret::from applies X25519 clamping internally
    let secret = StaticSecret::from(x25519_bytes);
    let public = PublicKey::from(&secret);

    // Zero the intermediate key material
    x25519_bytes.fill(0);

    let keypair = X25519KeyPair {
        public_key: public.as_bytes().to_vec(),
        private_key: secret.to_bytes().to_vec(),
    };

    serde_wasm_bindgen::to_value(&keypair).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Convert an Ed25519 public key (32 bytes, compressed Edwards Y) to X25519 public key.
///
/// Uses the birational Edwards-to-Montgomery map: u = (1 + y) / (1 - y)
/// This lets us resolve X25519 public keys from did:key DIDs (which encode Ed25519 public keys).
#[wasm_bindgen]
pub fn vault_ed25519_pub_to_x25519(ed25519_pub: &[u8]) -> Result<Vec<u8>, JsValue> {
    if ed25519_pub.len() != 32 {
        return Err(map_vault_err("ed25519_pub must be 32 bytes"));
    }

    let compressed = CompressedEdwardsY::from_slice(ed25519_pub)
        .map_err(|e| JsValue::from_str(&format!("invalid Ed25519 public key: {}", e)))?;
    let edwards_point = compressed
        .decompress()
        .ok_or_else(|| map_vault_err("failed to decompress Ed25519 public key"))?;
    let montgomery = edwards_point.to_montgomery();

    Ok(montgomery.as_bytes().to_vec())
}
