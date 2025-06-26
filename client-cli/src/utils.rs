use anyhow::{anyhow, Result};
use crate::error::CliError;

/// Generate an orbit ID from a DID and name
pub fn generate_orbit_id(did: &str, name: &str) -> Result<String> {
    // Format: tinycloud:{did_suffix}://{name}/
    let did_suffix = did.strip_prefix("did:").unwrap_or(did);
    Ok(format!("tinycloud:{}://{}/", did_suffix, name))
}

/// Parse KV permissions from command line arguments
/// Format: "path=ability1,ability2"
pub fn parse_kv_permissions(permissions: &[String]) -> Result<Vec<(String, Vec<String>)>> {
    permissions.iter()
        .map(|perm| {
            let (path, abilities) = perm.split_once('=')
                .ok_or_else(|| CliError::InvalidCapability(format!("Invalid permission format: {}. Expected format: path=ability1,ability2", perm)))?;
            
            let abilities: Vec<String> = abilities.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            
            if abilities.is_empty() {
                return Err(CliError::InvalidCapability(format!("No abilities specified for path {}", path)).into());
            }
            
            Ok((path.to_string(), abilities))
        })
        .collect()
}

/// Extract Ethereum address from a DID
pub fn extract_address_from_did(did: &str) -> Result<String> {
    // Extract Ethereum address from did:pkh:eip155:1:0x... format
    if let Some(addr) = did.strip_prefix("did:pkh:eip155:1:") {
        if addr.starts_with("0x") && addr.len() == 42 {
            Ok(addr.to_string())
        } else {
            Err(CliError::InvalidDid(format!("Invalid Ethereum address in DID: {}", addr)).into())
        }
    } else {
        Err(CliError::InvalidDid(format!("Invalid DID format for Ethereum address: {}", did)).into())
    }
}

/// Validate that a string is a valid Ethereum address
pub fn validate_ethereum_address(address: &str) -> Result<()> {
    if !address.starts_with("0x") {
        return Err(CliError::InvalidDid("Ethereum address must start with 0x".to_string()).into());
    }
    
    if address.len() != 42 {
        return Err(CliError::InvalidDid("Ethereum address must be 42 characters long".to_string()).into());
    }
    
    // Validate hex characters
    let hex_part = &address[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CliError::InvalidDid("Ethereum address contains invalid hex characters".to_string()).into());
    }
    
    Ok(())
}

/// Validate that a string looks like a valid DID
pub fn validate_did(did: &str) -> Result<()> {
    if !did.starts_with("did:") {
        return Err(CliError::InvalidDid("DID must start with 'did:'".to_string()).into());
    }
    
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return Err(CliError::InvalidDid("DID must have at least method and identifier".to_string()).into());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_orbit_id() {
        let did = "did:pkh:eip155:1:0x1234567890123456789012345678901234567890";
        let orbit_id = generate_orbit_id(did, "myorbit").unwrap();
        assert_eq!(orbit_id, "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890://myorbit/");
    }
    
    #[test]
    fn test_parse_kv_permissions() {
        let perms = vec![
            "/path1=get,put".to_string(),
            "/path2=delete".to_string(),
        ];
        
        let parsed = parse_kv_permissions(&perms).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "/path1");
        assert_eq!(parsed[0].1, vec!["get", "put"]);
        assert_eq!(parsed[1].0, "/path2");
        assert_eq!(parsed[1].1, vec!["delete"]);
    }
    
    #[test]
    fn test_extract_address_from_did() {
        let did = "did:pkh:eip155:1:0x1234567890123456789012345678901234567890";
        let address = extract_address_from_did(did).unwrap();
        assert_eq!(address, "0x1234567890123456789012345678901234567890");
        
        // Test invalid DID
        let invalid_did = "did:key:invalid";
        assert!(extract_address_from_did(invalid_did).is_err());
    }
    
    #[test]
    fn test_validate_ethereum_address() {
        // Valid address
        assert!(validate_ethereum_address("0x1234567890123456789012345678901234567890").is_ok());
        
        // Invalid addresses
        assert!(validate_ethereum_address("1234567890123456789012345678901234567890").is_err()); // No 0x
        assert!(validate_ethereum_address("0x12345").is_err()); // Too short
        assert!(validate_ethereum_address("0x1234567890123456789012345678901234567890XX").is_err()); // Too long
        assert!(validate_ethereum_address("0x123456789012345678901234567890123456789G").is_err()); // Invalid hex
    }
    
    #[test]
    fn test_validate_did() {
        // Valid DIDs
        assert!(validate_did("did:pkh:eip155:1:0x1234567890123456789012345678901234567890").is_ok());
        assert!(validate_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_ok());
        
        // Invalid DIDs
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did("did:").is_err());
        assert!(validate_did("did:method").is_err());
    }
}