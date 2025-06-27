use std::str::FromStr;

use anyhow::{anyhow, Result};
use tinycloud_lib::ssi::{
    crypto::k256::SecretKey,
    dids::{DIDBuf, DIDResolver, DID, DIDPKH},
    jwk::{ECParams, Params, JWK},
};

use crate::error::CliError;

#[derive(Clone)]
pub struct EthereumKey {
    secret_key: SecretKey,
    jwk: JWK,
    did: DIDBuf,
}

impl EthereumKey {
    pub fn new(private_key: [u8; 32]) -> Result<Self> {
        // Create secp256k1 signing key
        let secret_key = SecretKey::from_bytes(&private_key.into())
            .map_err(|e| anyhow!("Invalid secp256k1 private key: {}", e))?;

        // Create JWK
        let mut jwk: JWK = Params::EC(ECParams::from(&secret_key)).into();
        jwk.algorithm = Some(tinycloud_lib::ssi::jwk::Algorithm::ES256KR);

        // Generate DID
        // let did = format!("did:pkh:eip155:1:{}", address).parse()?;
        let did = DIDPKH::generate(&jwk, "eip155:1")?;

        Ok(Self {
            secret_key,
            jwk,
            did,
        })
    }

    pub fn get_jwk(&self) -> &JWK {
        &self.jwk
    }

    pub fn get_did(&self) -> &DID {
        &self.did
    }

    pub fn get_verification_method(&self) -> String {
        format!("{}#blockchainAccountId", self.did)
    }

    pub fn get_secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl FromStr for EthereumKey {
    type Err = anyhow::Error;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        // Remove 0x prefix if present
        let hex = if hex.starts_with("0x") {
            &hex[2..]
        } else {
            hex
        };

        // Ensure the hex string is 64 characters (32 bytes)
        if hex.len() != 64 {
            return Err(CliError::InvalidPrivateKey(format!(
                "Expected 64 hex characters, found {}",
                hex.len()
            ))
            .into());
        }

        // Parse the hex string into bytes
        let bytes = hex::decode(hex).map_err(|e| anyhow!("Invalid hex format: {}", e))?;
        if bytes.len() != 32 {
            return Err(CliError::InvalidPrivateKey(format!(
                "Expected 32 bytes, found {}",
                bytes.len()
            ))
            .into());
        }

        // Convert to array
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&bytes);

        Ok(EthereumKey::new(private_key)?)
    }
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
