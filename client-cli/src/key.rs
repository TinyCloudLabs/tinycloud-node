use anyhow::{anyhow, Result};
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha3::{Digest, Keccak256};
use tinycloud_lib::ssi::{
    dids::{AnyDidMethod, DIDBuf, DID},
    jwk::{Base64urlUInt, ECParams, Params, JWK},
};

pub struct EthereumKey {
    private_key: [u8; 32],
    signing_key: SigningKey,
    jwk: JWK,
    did: DIDBuf,
    address: String,
}

impl EthereumKey {
    pub fn new(private_key: [u8; 32]) -> Result<Self> {
        // Create secp256k1 signing key
        let signing_key = SigningKey::from_bytes(&private_key.into())
            .map_err(|e| anyhow!("Invalid secp256k1 private key: {}", e))?;

        // Generate Ethereum address
        let verifying_key = VerifyingKey::from(&signing_key);
        let address = ethereum_address_from_public_key(&verifying_key)?;

        // Create JWK
        let jwk = create_secp256k1_jwk(&signing_key)?;

        // Generate DID
        let did = format!("did:pkh:eip155:1:{}", address).parse()?;

        Ok(Self {
            private_key,
            signing_key,
            jwk,
            did,
            address,
        })
    }

    pub fn get_jwk(&self) -> &JWK {
        &self.jwk
    }

    pub fn get_did(&self) -> &DID {
        &self.did
    }

    pub fn get_address(&self) -> &str {
        &self.address
    }

    pub fn get_verification_method(&self) -> String {
        format!("{}#blockchainAccountId", self.did)
    }

    pub fn get_signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

fn ethereum_address_from_public_key(verifying_key: &VerifyingKey) -> Result<String> {
    // Get uncompressed public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key_point.as_bytes();

    // Skip the 0x04 prefix and hash the remaining 64 bytes
    let public_key_hash = Keccak256::digest(&public_key_bytes[1..]);

    // Take last 20 bytes and format as hex with 0x prefix
    let address_bytes = &public_key_hash[12..];
    let address = format!("0x{}", hex::encode(address_bytes));

    Ok(address.to_lowercase())
}

fn create_secp256k1_jwk(signing_key: &SigningKey) -> Result<JWK> {
    let verifying_key = VerifyingKey::from(signing_key);
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key_point.as_bytes();

    // Extract x and y coordinates (skip 0x04 prefix)
    let x = &public_key_bytes[1..33];
    let y = &public_key_bytes[33..65];

    // Create EC params
    let ec_params = ECParams {
        curve: Some("secp256k1".to_string()),
        x_coordinate: Some(Base64urlUInt(x.to_vec())),
        y_coordinate: Some(Base64urlUInt(y.to_vec())),
        ecc_private_key: None, // Don't include private key in JWK
    };

    Ok(JWK {
        params: Params::EC(ec_params),
        public_key_use: None,
        key_operations: None,
        algorithm: Some(tinycloud_lib::ssi::jwk::Algorithm::ES256K),
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_key_from_hex() {
        // Test with 0x prefix
        let key1 = EthereumKey::from_hex(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );
        assert!(key1.is_ok());

        // Test without 0x prefix
        let key2 = EthereumKey::from_hex(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );
        assert!(key2.is_ok());

        // Test invalid length
        let key3 = EthereumKey::from_hex("0x1234");
        assert!(key3.is_err());
    }

    #[test]
    fn test_did_format() {
        let key = EthereumKey::from_hex(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();
        assert!(key.get_did().starts_with("did:pkh:eip155:1:0x"));
        assert_eq!(key.get_address().len(), 42); // 0x + 40 hex chars
    }
}
