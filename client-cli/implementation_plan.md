# TinyCloud Client CLI Implementation Plan

## Overview

This document outlines the implementation plan for a stateless CLI client that provides programmatic access to the TinyCloud HTTP API. The CLI is designed for application integration rather than interactive human use, implementing capabilities-based authorization through SIWE (Sign-In with Ethereum) and UCAN delegation/invocation mechanisms.

## Architecture

### Core Components

1. **Command Line Interface** - Using `clap` for structured command parsing
2. **Cryptographic Operations** - Using `ssi.workspace` for DID operations and signing
3. **HTTP Client** - Using `reqwest` for async HTTP communications
4. **Authorization System** - Creating SIWE CACAO delegations and UCAN invocations
5. **Error Handling** - Using `anyhow` for comprehensive error management

### Dependencies Structure

```toml
[dependencies]
# CLI framework
clap = { version = "4.0", features = ["derive"] }

# Async runtime and HTTP client
tokio = { version = "1.0", features = ["full"] }
reqwest = { version = "0.12.20", features = ["json", "stream"] }

# Error handling
anyhow = "1.0"

# Workspace dependencies and crypto operations
tinycloud-lib = { path = "../tinycloud-lib" }
tinycloud-sdk-rs = { path = "../tinycloud-sdk-rs" }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Utilities
uuid = { version = "1.0", features = ["v4"] }
time = "0.3"
hex = "0.4"
```

## Command Structure

### Global Arguments

All commands support these global arguments:

- `--ethkey <HEX>` - Hex-encoded Ethereum private key (required)
- `--url <URL>` - TinyCloud orbit host URL (default: "https://demo.tinycloud.xyz")
- `--parent <CID>...` - Vec of parent capability CIDs (default: empty)
- `--orbit <ORBIT_ID>` - Target orbit ID (default: derived from issuer DID)

### Command Hierarchy

```
tinycloud-client
├── host --name <ORBIT_NAME>
├── delegate <RECIPIENT> --kv/path=abilities...
└── invoke
    └── kv
        ├── get <PATH>
        ├── head <PATH>
        ├── put <PATH>
        └── delete <PATH>
```

## Implementation Details

### 1. Core CLI Structure

```rust
use clap::{Parser, Subcommand};
use tinycloud_lib::resource::OrbitId;
use libipld::Cid;

#[derive(Parser)]
#[command(name = "tinycloud-client")]
pub struct Cli {
    /// Hex-encoded Ethereum private key
    #[arg(long, env = "TINYCLOUD_ETHKEY")]
    pub ethkey: String,
    
    /// TinyCloud orbit host URL
    #[arg(long, default_value = "https://demo.tinycloud.xyz")]
    pub url: String,
    
    /// Parent capability CIDs
    #[arg(long)]
    pub parent: Vec<String>,
    
    /// Target orbit ID
    #[arg(long)]
    pub orbit: Option<String>,
    
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Host {
        #[arg(long, default_value = "default")]
        name: String,
    },
    Delegate {
        recipient: String,
        #[arg(long = "kv")]
        kv_permissions: Vec<String>,
    },
    Invoke {
        #[command(subcommand)]
        operation: InvokeCommands,
    },
}

#[derive(Subcommand)]
pub enum InvokeCommands {
    Kv {
        #[command(subcommand)]
        action: KvCommands,
    },
}

#[derive(Subcommand)]
pub enum KvCommands {
    Get { path: String },
    Head { path: String },
    Put { path: String },
    Delete { path: String },
}
```

### 2. Ethereum Key Management

```rust
use tinycloud_lib::ssi::jwk::{JWK, ECParams, Params};
use tinycloud_lib::ssi::dids::DIDURLBuf;

pub struct EthereumKey {
    private_key: [u8; 32],
    jwk: JWK,
    did: String,
}

impl EthereumKey {
    pub fn from_hex(hex_key: &str) -> anyhow::Result<Self> {
        let private_key_bytes = hex::decode(hex_key.strip_prefix("0x").unwrap_or(hex_key))?;
        let private_key: [u8; 32] = private_key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
        
        // Convert to secp256k1 JWK
        let jwk = create_secp256k1_jwk(&private_key)?;
        
        // Generate did:pkh:eip155:1:0x... DID from public key
        let did = generate_pkh_did(&jwk)?;
        
        Ok(Self {
            private_key,
            jwk,
            did,
        })
    }
    
    pub fn get_jwk(&self) -> &JWK { &self.jwk }
    pub fn get_did(&self) -> &str { &self.did }
    pub fn get_verification_method(&self) -> String {
        format!("{}#blockchainAccountId", self.did)
    }
}

fn create_secp256k1_jwk(private_key: &[u8; 32]) -> anyhow::Result<JWK> {
    // Implementation using ssi workspace functionality
    // Convert private key to JWK format for secp256k1
}

fn generate_pkh_did(jwk: &JWK) -> anyhow::Result<String> {
    // Generate Ethereum address from public key
    // Format as did:pkh:eip155:1:0x{address}
}
```

### 3. HTTP Client Implementation

```rust
use reqwest::Client;
use tinycloud_lib::authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation};

pub struct TinyCloudClient {
    client: Client,
    base_url: String,
}

impl TinyCloudClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }
    
    pub async fn generate_host_key(&self, orbit: &str) -> anyhow::Result<String> {
        let url = format!("{}/peer/generate/{}", self.base_url, orbit);
        let response = self.client.get(&url).send().await?;
        let host_did = response.text().await?;
        Ok(host_did)
    }
    
    pub async fn delegate(&self, delegation: &TinyCloudDelegation) -> anyhow::Result<String> {
        let url = format!("{}/delegate", self.base_url);
        let auth_header = delegation.encode()?;
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", auth_header))
            .send()
            .await?;
            
        let cid = response.text().await?;
        Ok(cid)
    }
    
    pub async fn invoke_get(&self, invocation: &TinyCloudInvocation) -> anyhow::Result<Vec<u8>> {
        let url = format!("{}/invoke", self.base_url);
        let auth_header = invocation.encode()?;
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", auth_header))
            .send()
            .await?;
            
        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }
    
    pub async fn invoke_put(&self, invocation: &TinyCloudInvocation, data: Vec<u8>) -> anyhow::Result<()> {
        let url = format!("{}/invoke", self.base_url);
        let auth_header = invocation.encode()?;
        
        let _response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", auth_header))
            .body(data)
            .send()
            .await?;
            
        Ok(())
    }
    
    pub async fn invoke_head(&self, invocation: &TinyCloudInvocation) -> anyhow::Result<String> {
        // Similar to invoke_get but expecting metadata response
    }
    
    pub async fn invoke_delete(&self, invocation: &TinyCloudInvocation) -> anyhow::Result<()> {
        // Similar to invoke_put but with no body
    }
}
```

### 4. SIWE CACAO Creation

```rust
use tinycloud_lib::cacaos::siwe_cacao::SiweCacao;
use tinycloud_lib::cacaos::siwe::Message;
use tinycloud_lib::siwe_recap::Capability as SiweCapability;
use time::OffsetDateTime;

pub async fn create_host_delegation(
    delegator_key: &EthereumKey,
    host_did: &str,
    orbit: &str,
    expires_in_seconds: u64,
) -> anyhow::Result<TinyCloudDelegation> {
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::seconds(expires_in_seconds as i64);
    
    // Create SIWE message for orbit hosting capability
    let message = Message {
        domain: "tinycloud.xyz".parse()?,
        address: extract_address_from_did(delegator_key.get_did())?,
        statement: Some(format!("Delegate orbit hosting capability for {}", orbit)),
        uri: host_did.parse()?,
        version: siwe::Version::V1,
        chain_id: 1,
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at: now,
        expiration_time: Some(expiry),
        not_before: None,
        request_id: None,
        resources: vec![
            format!("{}#orbit/host", orbit).parse()?
        ],
    };
    
    // Sign the message to create CACAO
    let cacao = create_siwe_cacao(&message, delegator_key).await?;
    Ok(TinyCloudDelegation::Cacao(Box::new(cacao)))
}

pub async fn create_capability_delegation(
    delegator_key: &EthereumKey,
    recipient_did: &str,
    orbit: &str,
    capabilities: &[(String, Vec<String>)], // path -> abilities
    parent_cids: &[libipld::Cid],
    expires_in_seconds: u64,
) -> anyhow::Result<TinyCloudDelegation> {
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::seconds(expires_in_seconds as i64);
    
    // Build resources list from capabilities
    let resources: Vec<String> = capabilities.iter()
        .flat_map(|(path, abilities)| {
            abilities.iter().map(|ability| {
                format!("{}/kv{}#{}", orbit, path, ability)
            })
        })
        .collect();
    
    let message = Message {
        domain: "tinycloud.xyz".parse()?,
        address: extract_address_from_did(delegator_key.get_did())?,
        statement: Some("Delegate capabilities".to_string()),
        uri: recipient_did.parse()?,
        version: siwe::Version::V1,
        chain_id: 1,
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at: now,
        expiration_time: Some(expiry),
        not_before: None,
        request_id: None,
        resources: resources.into_iter().map(|r| r.parse()).collect::<Result<Vec<_>, _>>()?,
    };
    
    let cacao = create_siwe_cacao(&message, delegator_key).await?;
    Ok(TinyCloudDelegation::Cacao(Box::new(cacao)))
}
```

### 5. UCAN Invocation Creation

```rust
use tinycloud_lib::authorization::{make_invocation, TinyCloudInvocation};
use tinycloud_lib::resource::ResourceId;

pub async fn create_kv_invocation(
    invoker_key: &EthereumKey,
    orbit: &str,
    path: &str,
    action: &str, // "get", "put", "delete", "metadata"
    parent_cids: &[libipld::Cid],
    expires_in_seconds: u64,
) -> anyhow::Result<TinyCloudInvocation> {
    let resource_uri = format!("{}/kv{}#{}", orbit, path, action);
    let resource_id: ResourceId = resource_uri.parse()?;
    
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::seconds(expires_in_seconds as i64);
    
    // Use the existing make_invocation function from tinycloud-lib
    let invocation = make_invocation(
        vec![resource_id],
        parent_cids[0], // Primary parent delegation
        invoker_key.get_jwk(),
        invoker_key.get_verification_method(),
        expiry.unix_timestamp() as f64,
        None, // not_before
        None, // nonce (will be auto-generated)
    ).await?;
    
    Ok(invocation)
}
```

### 6. Command Handlers

```rust
pub async fn handle_host_command(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit_name: &str,
) -> anyhow::Result<()> {
    // 1. Generate orbit ID from user's DID
    let orbit_id = generate_orbit_id(key.get_did(), orbit_name)?;
    
    // 2. Get host DID from server
    let host_did = client.generate_host_key(&orbit_id).await?;
    
    // 3. Create SIWE delegation for orbit hosting
    let delegation = create_host_delegation(key, &host_did, &orbit_id, 3600).await?;
    
    // 4. Submit delegation
    let _cid = client.delegate(&delegation).await?;
    
    // 5. Return orbit ID
    println!("{}", orbit_id);
    Ok(())
}

pub async fn handle_delegate_command(
    key: &EthereumKey,
    client: &TinyCloudClient,
    recipient: &str,
    orbit: &str,
    kv_permissions: &[String],
    parent_cids: &[libipld::Cid],
) -> anyhow::Result<()> {
    // Parse kv permissions (format: "path=ability1,ability2")
    let capabilities = parse_kv_permissions(kv_permissions)?;
    
    // Create capability delegation
    let delegation = create_capability_delegation(
        key,
        recipient,
        orbit,
        &capabilities,
        parent_cids,
        3600
    ).await?;
    
    // Submit delegation
    let cid = client.delegate(&delegation).await?;
    
    // Return CID
    println!("{}", cid);
    Ok(())
}

pub async fn handle_invoke_kv_get(
    key: &EthereumKey,
    client: &TinyCloudClient,
    orbit: &str,
    path: &str,
    parent_cids: &[libipld::Cid],
) -> anyhow::Result<()> {
    let invocation = create_kv_invocation(key, orbit, path, "get", parent_cids, 300).await?;
    let data = client.invoke_get(&invocation).await?;
    
    // Stream to stdout
    use std::io::{self, Write};
    io::stdout().write_all(&data)?;
    Ok(())
}

// Similar handlers for put, head, delete...
```

### 7. Utility Functions

```rust
fn generate_orbit_id(did: &str, name: &str) -> anyhow::Result<String> {
    // Format: tinycloud:{did_suffix}://{name}/
    let did_suffix = did.strip_prefix("did:").unwrap_or(did);
    Ok(format!("tinycloud:{}://{}/", did_suffix, name))
}

fn parse_kv_permissions(permissions: &[String]) -> anyhow::Result<Vec<(String, Vec<String>)>> {
    permissions.iter()
        .map(|perm| {
            let (path, abilities) = perm.split_once('=')
                .ok_or_else(|| anyhow::anyhow!("Invalid permission format: {}", perm))?;
            let abilities: Vec<String> = abilities.split(',')
                .map(|s| s.trim().to_string())
                .collect();
            Ok((path.to_string(), abilities))
        })
        .collect()
}

fn extract_address_from_did(did: &str) -> anyhow::Result<String> {
    // Extract Ethereum address from did:pkh:eip155:1:0x... format
    if let Some(addr) = did.strip_prefix("did:pkh:eip155:1:") {
        Ok(addr.to_string())
    } else {
        Err(anyhow::anyhow!("Invalid DID format for Ethereum address"))
    }
}
```

## Error Handling Strategy

### Custom Error Types

```rust
#[derive(thiserror::Error, Debug)]
pub enum CliError {
    #[error("Invalid Ethereum private key: {0}")]
    InvalidPrivateKey(String),
    
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("Authorization failed: {0}")]
    AuthorizationError(String),
    
    #[error("Invalid orbit ID format: {0}")]
    InvalidOrbitId(String),
    
    #[error("Invalid capability format: {0}")]
    InvalidCapability(String),
    
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}
```

## Testing Strategy

### Unit Tests

1. **Key Management Tests** - Verify Ethereum key parsing and DID generation
2. **SIWE/CACAO Creation Tests** - Test delegation creation with various capabilities
3. **UCAN Creation Tests** - Test invocation creation with different resources
4. **HTTP Client Tests** - Mock server tests for API interactions
5. **Command Parsing Tests** - Verify CLI argument parsing

### Integration Tests

1. **End-to-End Flow Tests** - Full host → delegate → invoke workflows
2. **Error Scenario Tests** - Invalid keys, expired tokens, unauthorized access
3. **Real Server Tests** - Tests against actual TinyCloud instance

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ethereum_key_from_hex() {
        let key = EthereumKey::from_hex("0x1234...").unwrap();
        assert!(key.get_did().starts_with("did:pkh:eip155:1:0x"));
    }
    
    #[tokio::test]
    async fn test_host_delegation_creation() {
        let key = EthereumKey::from_hex("0x1234...").unwrap();
        let delegation = create_host_delegation(&key, "did:test", "orbit", 3600).await.unwrap();
        assert!(matches!(delegation, TinyCloudDelegation::Cacao(_)));
    }
    
    #[tokio::test]
    async fn test_full_workflow() {
        // Test complete host → delegate → invoke flow
    }
}
```

## Security Considerations

1. **Private Key Handling**
   - Keys should be passed via environment variables when possible
   - Clear keys from memory after use
   - Warn users about command-line argument exposure

2. **Token Expiration**
   - Use short-lived tokens by default
   - Allow customization of expiration times
   - Implement proper time validation

3. **Network Security**
   - Validate HTTPS URLs
   - Implement proper certificate validation
   - Handle network errors gracefully

4. **Input Validation**
   - Validate all DIDs and resource URIs
   - Sanitize file paths
   - Validate capability formats

## Performance Considerations

1. **Async Operations** - All network operations are async
2. **Memory Efficiency** - Stream large file uploads/downloads
3. **Connection Reuse** - HTTP client connection pooling
4. **Minimal Dependencies** - Only essential dependencies included

## Future Enhancements

1. **Configuration File Support** - Store common settings
2. **Interactive Mode** - Optional interactive prompts
3. **Batch Operations** - Multiple invocations in single request
4. **Progress Indicators** - For large file transfers
5. **Alternative DID Methods** - Support for other DID methods beyond did:pkh
6. **Custom SIWE Domains** - Allow different SIWE domains
7. **Token Caching** - Cache valid tokens for reuse

## Conclusion

This implementation plan provides a comprehensive roadmap for building a robust, stateless CLI client for TinyCloud. The design emphasizes security, performance, and maintainability while providing all functionality specified in the PRD. The modular architecture allows for easy testing and future enhancements.
