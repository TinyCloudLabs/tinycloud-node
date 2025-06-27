use anyhow::Result;
use clap::Parser;

mod auth;
mod cli;
mod client;
mod commands;
mod error;
mod key;
mod utils;

use cli::{Cli, Commands, InvokeCommands, KvCommands};
use client::TinyCloudClient;
use commands::{
    handle_host_command, handle_delegate_command, handle_invoke_kv_get,
    handle_invoke_kv_head, handle_invoke_kv_put, handle_invoke_kv_delete,
};

async fn app() -> Result<()> {
    let args = Cli::parse();

    // Initialize the Ethereum key from hex string
    let key = args.ethkey;

    // Create HTTP client
    let client = TinyCloudClient::new(args.url);

    // Parse parent CIDs if provided
    let parent_cids = args.parent;

    // Route and execute commands
    match args.command {
        Commands::Host { name } => {
            handle_host_command(&key, &client, &name).await?;
        }
        Commands::Delegate { recipient, kv_permissions, orbit } => {
            handle_delegate_command(&key, &client, &recipient, orbit, &kv_permissions, &parent_cids).await?;
        }
        Commands::Invoke { operation, orbit } => {
            match operation {
                InvokeCommands::Kv { action } => {
                    match action {
                        KvCommands::Get { path } => {
                            handle_invoke_kv_get(&key, &client, orbit, &path, &parent_cids).await?;
                        }
                        KvCommands::Head { path } => {
                            handle_invoke_kv_head(&key, &client, orbit, &path, &parent_cids).await?;
                        }
                        KvCommands::Put { path } => {
                            handle_invoke_kv_put(&key, &client, orbit, &path, &parent_cids).await?;
                        }
                        KvCommands::Delete { path } => {
                            handle_invoke_kv_delete(&key, &client, orbit, &path, &parent_cids).await?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    app().await.inspect_err(|e| println!("{e}"))
}
