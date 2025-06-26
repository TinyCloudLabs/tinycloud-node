use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tinycloud-client")]
#[command(about = "A CLI client for TinyCloud Protocol")]
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
    /// Create and host a new orbit
    Host {
        /// Name of the orbit to create
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Delegate capabilities to another entity
    Delegate {
        /// DID of the recipient
        recipient: String,
        /// KV permissions in format "path=ability1,ability2"
        #[arg(long = "kv")]
        kv_permissions: Vec<String>,
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
}

#[derive(Subcommand)]
pub enum KvCommands {
    /// Get a value from the key-value store
    Get { 
        /// Path to the key
        path: String 
    },
    /// Get metadata about a key
    Head { 
        /// Path to the key
        path: String 
    },
    /// Put a value into the key-value store (reads from stdin)
    Put { 
        /// Path to the key
        path: String 
    },
    /// Delete a key from the key-value store
    Delete { 
        /// Path to the key
        path: String 
    },
}