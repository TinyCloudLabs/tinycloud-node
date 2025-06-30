use anyhow::Result;
use std::io::{self, Read, Write};
use std::path::Path;
use std::fs::File;
use libipld::Cid;
use tinycloud_lib::{resource::OrbitId, ssi::dids::DIDURL};

use crate::{
    auth::{create_host_delegation, create_capability_delegation, create_kv_invocation},
    client::TinyCloudClient,
    error::CliError,
    key::EthereumKey,
    utils::{generate_orbit_id, parse_kv_permissions},
};

/// Handle the host command - creates and hosts a new orbit
pub async fn handle_host_command(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit_name: &str,
) -> Result<()> {
    // 1. Generate orbit ID from user's DID
    let orbit_id = generate_orbit_id(key.get_did(), orbit_name)?;
    
    // 2. Get host DID from server
    let host_did = client.generate_host_key(&orbit_id).await?;
    
    // 3. Create SIWE delegation for orbit hosting
    let delegation = create_host_delegation(key, &host_did, orbit_id.clone(), 3600).await?;
    
    // 4. Submit delegation to server
    let _cid = client.delegate(&delegation).await?;
    
    // 5. Output the orbit ID for user reference
    println!("{}", orbit_id);
    Ok(())
}

/// Handle the delegate command - creates capability delegations
pub async fn handle_delegate_command(
    key: &EthereumKey,
    client: &TinyCloudClient,
    recipient: &DIDURL,
    orbit: OrbitId,
    permissions: &[String],
    parent_cids: &[Cid],
) -> Result<()> {
    // Parse permissions (format: "service/path=ability1,ability2")
    let capabilities = parse_kv_permissions(permissions)?;
    
    if capabilities.is_empty() {
        return Err(CliError::InvalidCapability("No capabilities specified".to_string()).into());
    }
    
    // Create capability delegation
    let delegation = create_capability_delegation(
        key,
        recipient,
        orbit,
        &capabilities,
        parent_cids,
        3600, // 1 hour expiration
    ).await?;
    
    // Submit delegation to server
    let cid = client.delegate(&delegation).await?;
    
    // Output the delegation CID
    println!("{}", cid);
    Ok(())
}

/// Handle KV get operation
pub async fn handle_invoke_kv_get(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit: OrbitId,
    path: &str,
    parent_cids: &[Cid],
    file_path: Option<&Path>,
) -> Result<()> {
    // Check if file exists before making HTTP request
    if let Some(file_path) = file_path {
        if file_path.exists() {
            return Err(CliError::IoError(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("File already exists: {}", file_path.display())
            )).into());
        }
    }
    
    // Create invocation for KV get operation
    let invocation = create_kv_invocation(key, orbit, path, "get", parent_cids, 300).await?;
    
    // Execute the invocation
    let data = client.invoke_get(&invocation).await?;
    
    // Write data to file or stdout
    match file_path {
        Some(file_path) => {
            let mut file = File::create(file_path)?;
            file.write_all(&data)?;
            file.flush()?;
        }
        None => {
            io::stdout().write_all(&data)?;
            io::stdout().flush()?;
        }
    }
    
    Ok(())
}

/// Handle KV head operation (get metadata)
pub async fn handle_invoke_kv_head(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit: OrbitId,
    path: &str,
    parent_cids: &[Cid],
) -> Result<()> {
    // Create invocation for KV metadata operation
    let invocation = create_kv_invocation(key, orbit, path, "metadata", parent_cids, 300).await?;
    
    // Execute the invocation
    let metadata = client.invoke_head(&invocation).await?;
    
    // Output metadata
    println!("{}", metadata);
    Ok(())
}

/// Handle KV put operation (reads from stdin or file)
pub async fn handle_invoke_kv_put(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit: OrbitId,
    path: &str,
    parent_cids: &[Cid],
    file_path: Option<&Path>,
) -> Result<()> {
    // Read data from file or stdin
    let mut data = Vec::new();
    match file_path {
        Some(file_path) => {
            let mut file = File::open(file_path)?;
            file.read_to_end(&mut data)?;
        }
        None => {
            io::stdin().read_to_end(&mut data)?;
        }
    }
    
    if data.is_empty() {
        let source = file_path.map(|p| p.display().to_string()).unwrap_or_else(|| "stdin".to_string());
        return Err(CliError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("No data provided from {}", source)
        )).into());
    }
    
    // Create invocation for KV put operation
    let invocation = create_kv_invocation(key, orbit, path, "put", parent_cids, 300).await?;
    
    // Execute the invocation
    client.invoke_put(&invocation, data).await?;
    
    Ok(())
}

/// Handle KV delete operation
pub async fn handle_invoke_kv_delete(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit: OrbitId,
    path: &str,
    parent_cids: &[Cid],
) -> Result<()> {
    // Create invocation for KV delete operation
    let invocation = create_kv_invocation(key, orbit, path, "del", parent_cids, 300).await?;
    
    // Execute the invocation
    client.invoke_delete(&invocation).await?;
    
    Ok(())
}

/// Handle capability list operation
pub async fn handle_invoke_cap_list(
    _key: &EthereumKey,
    _client: &TinyCloudClient,
    _orbit: OrbitId,
    _parent_cids: &[Cid],
) -> Result<()> {
    // TODO: Implement capability listing
    // This would need client support for capability listing
    println!("Capability listing not yet implemented");
    Ok(())
}

/// Handle capability get operation
pub async fn handle_invoke_cap_get(
    _key: &EthereumKey,
    _client: &TinyCloudClient,
    _orbit: OrbitId,
    _cid: Cid,
    _parent_cids: &[Cid],
) -> Result<()> {
    // TODO: Implement capability retrieval
    // This would need client support for capability retrieval
    println!("Capability retrieval not yet implemented");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Mock, Server};
    
    #[tokio::test]
    async fn test_handle_host_command() {
        let key: EthereumKey = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
        
        // Mock server setup would go here
        // This is a placeholder for actual integration tests
        let orbit_id = generate_orbit_id(key.get_did(), "test").unwrap();
        assert!(orbit_id.to_string().contains("test"));
    }
    
    #[test]
    fn test_permission_parsing() {
        let permissions = vec![
            "/path1=get,put".to_string(),
            "/path2=del".to_string(),
        ];
        
        let parsed = parse_kv_permissions(&permissions).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "/path1");
        assert_eq!(parsed[0].1, vec!["get", "put"]);
    }
}
