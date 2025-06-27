use clap::{Parser, Subcommand};
use reqwest::Url;
use tinycloud_lib::{libipld::Cid, resource::OrbitId, ssi::dids::DIDURLBuf};

#[derive(Parser)]
#[command(name = "tinycloud-client")]
#[command(about = "A CLI client for TinyCloud Protocol")]
pub struct Cli {
    /// Hex-encoded Ethereum private key
    #[arg(long, env = "TINYCLOUD_ETHKEY", value_parser = key_from_hex)]
    pub ethkey: [u8; 32],

    /// TinyCloud orbit host URL
    #[arg(long, default_value = "https://demo.tinycloud.xyz")]
    pub url: Url,

    /// Parent capability CIDs
    #[arg(long)]
    pub parent: Vec<Cid>,

    #[command(subcommand)]
    pub command: Commands,
}

fn key_from_hex(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create and host a new orbit
    Host {
        /// Name of the orbit to create
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Delegate capabilities to another entity
    Delegate {
        /// Target orbit ID
        #[arg(long)]
        orbit: OrbitId,
        /// DID of the recipient
        recipient: DIDURLBuf,
        /// KV permissions in format "path=ability1,ability2"
        #[arg(long = "kv")]
        kv_permissions: Vec<String>,
    },
    /// Invoke an operation using existing capabilities
    Invoke {
        /// Target orbit ID
        #[arg(long)]
        orbit: OrbitId,
        #[command(subcommand)]
        operation: InvokeCommands,
    },
}

#[derive(Subcommand)]
pub enum InvokeCommands {
    /// Key-value store operations
    Kv {
        #[command(subcommand)]
        action: KvCommands,
    },
}

#[derive(Subcommand)]
pub enum KvCommands {
    /// Get a value from the key-value store
    Get {
        /// Path to the key
        path: String,
    },
    /// Get metadata about a key
    Head {
        /// Path to the key
        path: String,
    },
    /// Put a value into the key-value store (reads from stdin)
    Put {
        /// Path to the key
        path: String,
    },
    /// Delete a key from the key-value store
    Delete {
        /// Path to the key
        path: String,
    },
}
