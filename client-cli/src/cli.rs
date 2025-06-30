use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tinycloud_lib::{libipld::Cid, resource::OrbitId, ssi::dids::DIDURLBuf};

use crate::{client::TinyCloudClient, key::EthereumKey};

#[derive(Parser)]
#[command(name = "tinycloud-client")]
#[command(about = "A CLI client for TinyCloud Protocol")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

fn key_from_hex(hex: &str) -> Result<EthereumKey> {
    hex.parse()
}

#[derive(Debug, Args)]
pub struct Common {
    /// Hex-encoded Ethereum private key
    #[arg(long, env = "TINYCLOUD_ETHKEY", value_parser = key_from_hex)]
    pub ethkey: EthereumKey,

    /// Target orbit ID
    #[arg(long, env = "TINYCLOUD_ORBIT_ID")]
    pub orbit: OrbitId,

    /// TinyCloud orbit host URL
    #[arg(
        long,
        default_value = "https://demo.tinycloud.xyz",
        env = "TINYCLOUD_URL"
    )]
    pub url: TinyCloudClient,

    /// Parent capability CIDs
    #[arg(long, env = "TINYCLOUD_PERMISSIONS")]
    pub parents: Vec<Cid>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create and host a new orbit
    Host {
        /// Name of the orbit to create
        #[arg(long, default_value = "default")]
        name: String,

        /// Name of the orbit to create
        #[arg(long, default_value = "3600")]
        ttl: u64,

        #[arg(long, env = "TINYCLOUD_ETHKEY", value_parser = key_from_hex)]
        ethkey: EthereumKey,

        /// TinyCloud orbit host URL
        #[arg(
            long,
            default_value = "https://demo.tinycloud.xyz",
            env = "TINYCLOUD_URL"
        )]
        url: TinyCloudClient,
    },
    /// Delegate capabilities to another entity
    Delegate {
        /// DID of the recipient
        recipient: DIDURLBuf,

        /// Name of the orbit to create
        #[arg(long, default_value = "3600")]
        ttl: u64,

        /// Orbit permissions in format "<service>/<path>=ability1,ability2"
        #[arg(long = "permissions")]
        permissions: Vec<String>,

        #[command(flatten)]
        common: Common,
    },
    /// Invoke an operation using existing capabilities
    Invoke {
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
    Capabilities {
        #[command(subcommand)]
        action: CapCommands,
    },
}

#[derive(Subcommand)]
pub enum KvCommands {
    /// Get a value from the key-value store
    Get {
        /// Path to the key
        path: String,

        /// File to write the value to (if not specified, writes to stdout)
        #[arg(long)]
        file: Option<PathBuf>,

        #[command(flatten)]
        common: Common,
    },
    /// Get metadata about a key
    Head {
        /// Path to the key
        path: String,

        #[command(flatten)]
        common: Common,
    },
    /// Put a value into the key-value store (reads from stdin or file)
    Put {
        /// Path to the key
        path: String,

        /// File to read the value from (if not specified, reads from stdin)
        #[arg(long)]
        file: Option<PathBuf>,

        #[command(flatten)]
        common: Common,
    },
    /// Delete a key from the key-value store
    Delete {
        /// Path to the key
        path: String,

        #[command(flatten)]
        common: Common,
    },
}

#[derive(Subcommand)]
pub enum CapCommands {
    /// List capabilities
    List {
        #[command(flatten)]
        common: Common,
    },
    /// Get details of a specific capability
    Get {
        /// Capability CID
        cid: Cid,

        #[command(flatten)]
        common: Common,
    },
}
