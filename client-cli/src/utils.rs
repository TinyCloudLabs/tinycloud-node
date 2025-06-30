use crate::error::CliError;
use anyhow::Result;
use tinycloud_lib::{resource::OrbitId, ssi::dids::DID};

/// Generate an orbit ID from a DID and name
pub fn generate_orbit_id(did: &str, name: &str) -> Result<OrbitId> {
    // Format: tinycloud:{did_suffix}://{name}
    let did_suffix = did.strip_prefix("did:").unwrap_or(did);
    Ok(format!("tinycloud:{}://{}", did_suffix, name).parse()?)
}

/// Parse KV permissions from command line arguments
/// Format: "path=ability1,ability2"
pub fn parse_kv_permissions(permissions: &[String]) -> Result<Vec<(String, Vec<String>)>> {
    permissions
        .iter()
        .map(|perm| {
            let (path, abilities) = perm.split_once('=').ok_or_else(|| {
                CliError::InvalidCapability(format!(
                    "Invalid permission format: {}. Expected format: path=ability1,ability2",
                    perm
                ))
            })?;

            let abilities: Vec<String> = abilities
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if abilities.is_empty() {
                return Err(CliError::InvalidCapability(format!(
                    "No abilities specified for path {}",
                    path
                ))
                .into());
            }

            Ok((path.to_string(), abilities))
        })
        .collect()
}

/// Extract Ethereum address from a DID
pub fn extract_address_from_did(did: &DID) -> Result<String> {
    // Extract Ethereum address from did:pkh:eip155:1:0x... format
    if let Some(addr) = did.strip_prefix("did:pkh:eip155:1:") {
        if addr.starts_with("0x") && addr.len() == 42 {
            Ok(addr.to_string())
        } else {
            Err(CliError::InvalidDid(format!("Invalid Ethereum address in DID: {}", addr)).into())
        }
    } else {
        Err(
            CliError::InvalidDid(format!("Invalid DID format for Ethereum address: {}", did))
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use tinycloud_lib::ssi::dids::DIDBuf;

    use super::*;

    #[test]
    fn test_generate_orbit_id() {
        let did = "did:pkh:eip155:1:0x1234567890123456789012345678901234567890";
        let orbit_id = generate_orbit_id(did, "myorbit").unwrap();
        assert_eq!(
            orbit_id.to_string(),
            "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890://myorbit"
        );
    }

    #[test]
    fn test_parse_kv_permissions() {
        let perms = vec!["/path1=get,put".to_string(), "/path2=delete".to_string()];

        let parsed = parse_kv_permissions(&perms).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "/path1");
        assert_eq!(parsed[0].1, vec!["get", "put"]);
        assert_eq!(parsed[1].0, "/path2");
        assert_eq!(parsed[1].1, vec!["delete"]);
    }

    #[test]
    fn test_extract_address_from_did() {
        let did: DIDBuf = "did:pkh:eip155:1:0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let address = extract_address_from_did(&did).unwrap();
        assert_eq!(address, "0x1234567890123456789012345678901234567890");

        // Test invalid DID
        let invalid_did: DIDBuf = "did:key:invalid".parse().unwrap();
        assert!(extract_address_from_did(&invalid_did).is_err());
    }
}
