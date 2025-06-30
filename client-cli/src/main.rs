use anyhow::Result;
use clap::Parser;

mod auth;
mod cli;
mod client;
mod commands;
mod error;
mod key;
mod utils;

use cli::{Cli, Commands, InvokeCommands, KvCommands, CapCommands};
use commands::{
    handle_host_command, handle_delegate_command, handle_invoke_kv_get,
    handle_invoke_kv_head, handle_invoke_kv_put, handle_invoke_kv_delete,
    handle_invoke_cap_list, handle_invoke_cap_get,
};

async fn app() -> Result<()> {
    let args = Cli::parse();

    // Route and execute commands
    match args.command {
        Commands::Host { name, ethkey, url } => {
            handle_host_command(&ethkey, &url, &name).await?;
        }
        Commands::Delegate { recipient, permissions, common } => {
            handle_delegate_command(&common.ethkey, &common.url, &recipient, common.orbit, &permissions, &common.parents).await?;
        }
        Commands::Invoke { operation } => {
            match operation {
                InvokeCommands::Kv { action } => {
                    match action {
                        KvCommands::Get { path, common } => {
                            handle_invoke_kv_get(&common.ethkey, &common.url, common.orbit, &path, &common.parents).await?;
                        }
                        KvCommands::Head { path, common } => {
                            handle_invoke_kv_head(&common.ethkey, &common.url, common.orbit, &path, &common.parents).await?;
                        }
                        KvCommands::Put { path, common } => {
                            handle_invoke_kv_put(&common.ethkey, &common.url, common.orbit, &path, &common.parents).await?;
                        }
                        KvCommands::Delete { path, common } => {
                            handle_invoke_kv_delete(&common.ethkey, &common.url, common.orbit, &path, &common.parents).await?;
                        }
                    }
                }
                InvokeCommands::Capabilities { action } => {
                    match action {
                        CapCommands::List { common } => {
                            handle_invoke_cap_list(&common.ethkey, &common.url, common.orbit, &common.parents).await?;
                        }
                        CapCommands::Get { cid, common } => {
                            handle_invoke_cap_get(&common.ethkey, &common.url, common.orbit, cid, &common.parents).await?;
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
