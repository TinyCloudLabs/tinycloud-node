use anyhow::{anyhow, Result};
use std::collections::HashMap;
use time::OffsetDateTime;
use tinycloud_lib::{
    authorization::{make_invocation, TinyCloudDelegation, TinyCloudInvocation},
    cacaos::{
        siwe::{generate_nonce, Message, TimeStamp, Version},
        siwe_cacao::{SIWESignature, SiweCacao},
    },
    resource::{OrbitId, ResourceId},
    siwe_recap::Capability,
    ssi::jwk::JWK,
};
use libipld::Cid;
use serde_json::Value;
use k256::{
    ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner},
};

use crate::{key::EthereumKey, error::CliError, utils::extract_address_from_did};

/// Create a SIWE CACAO delegation for orbit hosting
pub async fn create_host_delegation(
    delegator_key: &EthereumKey,
    host_did: &str,
    orbit_id: OrbitId,
    expires_in_seconds: u64,
) -> Result<TinyCloudDelegation> {
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::seconds(expires_in_seconds as i64);

    // Create address bytes from DID
    let address_str = extract_address_from_did(delegator_key.get_did())?;
    let address_bytes = hex::decode(&address_str[2..])
        .map_err(|e| CliError::CryptoError(format!("Failed to decode address: {}", e)))?;
    let address: [u8; 20] = address_bytes.try_into()
        .map_err(|_| CliError::CryptoError("Invalid address length".to_string()))?;
    
    // Build capabilities for orbit hosting
    let mut caps = Capability::<Value>::default();
    caps.with_action_convert(
        orbit_id.to_resource(None, None, None).to_string(),
        "orbit/host",
        [],
    )
    .map_err(|e| CliError::AuthorizationError(format!("Error creating host capability: {}", e)))?;
    
    // Create the SIWE message
    let issued_at = TimeStamp::try_from(now)
        .map_err(|e| CliError::CryptoError(format!("Failed to create timestamp: {}", e)))?;
    let expiration_time = TimeStamp::try_from(expiry)
        .map_err(|e| CliError::CryptoError(format!("Failed to create expiration timestamp: {}", e)))?;
    
    let message = caps.build_message(Message {
        scheme: None,
        address,
        chain_id: 1,
        domain: "tinycloud.xyz".parse()
            .map_err(|e| CliError::AuthorizationError(format!("Invalid domain: {}", e)))?,
        issued_at,
        uri: host_did.parse()
            .map_err(|e| CliError::AuthorizationError(format!("Invalid host DID URI: {}", e)))?,
        nonce: generate_nonce(),
        statement: None,
        resources: vec![],
        version: Version::V1,
        not_before: None,
        expiration_time: Some(expiration_time),
        request_id: None,
    })
    .map_err(|e| CliError::AuthorizationError(format!("Error building SIWE message: {}", e)))?;
    
    // Sign the message
    let signature = sign_siwe_message(&message, delegator_key.get_signing_key())?;
    
    // Create CACAO
    let cacao = SiweCacao::new(message.into(), signature, None);
    Ok(TinyCloudDelegation::Cacao(Box::new(cacao)))
}

/// Create a SIWE CACAO delegation for specific capabilities
pub async fn create_capability_delegation(
    delegator_key: &EthereumKey,
    recipient_did: &str,
    orbit_id: OrbitId,
    capabilities: &[(String, Vec<String>)], // (path, abilities)
    parent_cids: &[Cid],
    expires_in_seconds: u64,
) -> Result<TinyCloudDelegation> {
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::seconds(expires_in_seconds as i64);

    // Create address bytes from DID
    let address_str = extract_address_from_did(delegator_key.get_did())?;
    let address_bytes = hex::decode(&address_str[2..])
        .map_err(|e| CliError::CryptoError(format!("Failed to decode address: {}", e)))?;
    let address: [u8; 20] = address_bytes.try_into()
        .map_err(|_| CliError::CryptoError("Invalid address length".to_string()))?;
    
    // Build KV capabilities
    let actions: HashMap<String, HashMap<String, Vec<String>>> = {
        let mut kv_paths = HashMap::new();
        for (path, abilities) in capabilities {
            kv_paths.insert(path.clone(), abilities.clone());
        }
        let mut service_map = HashMap::new();
        service_map.insert("kv".to_string(), kv_paths);
        service_map
    };
    
    // Build capabilities from actions
    let caps = actions
        .into_iter()
        .try_fold(
            Capability::<Value>::default(),
            |caps, (service, paths)| -> Result<_, CliError> {
                paths
                    .into_iter()
                    .try_fold(caps, |mut caps, (path, actions)| -> Result<_, CliError> {
                        caps.with_actions_convert(
                            orbit_id
                                .clone()
                                .to_resource(Some(service.clone()), Some(path), None)
                                .to_string(),
                            actions
                                .into_iter()
                                .map(|a| (format!("{}/{}", &service, a), [])),
                        )
                        .map_err(|e| CliError::AuthorizationError(format!("Error building capabilities: {}", e)))?;
                        Ok(caps)
                    })
            },
        )?.with_proofs(parent_cids);
    
    // Create the SIWE message
    let issued_at = TimeStamp::try_from(now)
        .map_err(|e| CliError::CryptoError(format!("Failed to create timestamp: {}", e)))?;
    let expiration_time = TimeStamp::try_from(expiry)
        .map_err(|e| CliError::CryptoError(format!("Failed to create expiration timestamp: {}", e)))?;
    
    let message = caps.build_message(Message {
        scheme: None,
        address,
        chain_id: 1,
        domain: "tinycloud.xyz".parse()
            .map_err(|e| CliError::AuthorizationError(format!("Invalid domain: {}", e)))?,
        issued_at,
        uri: recipient_did.parse()
            .map_err(|e| CliError::AuthorizationError(format!("Invalid recipient DID URI: {}", e)))?,
        nonce: generate_nonce(),
        statement: None,
        resources: vec![],
        version: Version::V1,
        not_before: None,
        expiration_time: Some(expiration_time),
        request_id: None,
    })
    .map_err(|e| CliError::AuthorizationError(format!("Error building SIWE message: {}", e)))?;
    
    // Sign the message
    let signature = sign_siwe_message(&message, delegator_key.get_signing_key())?;
    
    // Create CACAO
    let cacao = SiweCacao::new(message.into(), signature, None);
    Ok(TinyCloudDelegation::Cacao(Box::new(cacao)))
}

/// Create a UCAN invocation for KV operations
pub async fn create_kv_invocation(
    invoker_key: &EthereumKey,
    orbit_id: OrbitId,
    path: &str,
    action: &str, // "get", "put", "del", "metadata"
    parent_cids: &[Cid],
    expires_in_seconds: u64,
) -> Result<TinyCloudInvocation> {
    if parent_cids.is_empty() {
        return Err(CliError::AuthorizationError("At least one parent delegation CID is required".to_string()).into());
    }
    
    // Create resource ID
    let resource_id = orbit_id.to_resource(
        Some("kv".to_string()),
        Some(path.to_string()),
        Some(action.to_string()),
    );
    
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::seconds(expires_in_seconds as i64);
    
    // Create invocation
    let invocation = make_invocation(
        vec![resource_id],
        parent_cids[0], // Use first parent as primary delegation
        invoker_key.get_jwk(),
        invoker_key.get_verification_method(),
        expiry.unix_timestamp() as f64,
        None, // not_before
        None, // nonce (will be auto-generated)
    )
    .await
    .map_err(|e| CliError::AuthorizationError(format!("Failed to create invocation: {}", e)))?;
    
    Ok(invocation)
}

/// Sign a SIWE message using secp256k1
fn sign_siwe_message(message: &Message, signing_key: &SigningKey) -> Result<SIWESignature> {
    // Get the EIP-191 hash of the message
    let message_hash = message.eip191_hash()
        .map_err(|e| CliError::CryptoError(format!("Failed to hash SIWE message: {}", e)))?;
    
    // Sign the hash
    let (signature, rec_id) = signing_key.sign_prehash_recoverable(&message_hash)
        .map_err(|e| CliError::CryptoError(format!("Failed to sign message: {}", e)))?;
    
    // Convert to SIWESignature format
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());

    // For Ethereum signatures, we need the recovery ID
    sig_bytes[64] = rec_id.into();
    
    let siwe_signature = SIWESignature::from(sig_bytes);
    
    Ok(siwe_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_host_delegation_creation() {
        let key = EthereumKey::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let orbit = "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890://test/";
        
        let result = create_host_delegation(&key, "did:key:test", orbit, 3600).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_capability_delegation_creation() {
        let key = EthereumKey::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let orbit = "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890://test/";
        let capabilities = vec![
            ("/path1".to_string(), vec!["get".to_string(), "put".to_string()]),
            ("/path2".to_string(), vec!["del".to_string()]),
        ];
        
        let result = create_capability_delegation(&key, "did:key:test", orbit, &capabilities, &[], 3600).await;
        assert!(result.is_ok());
    }
}
