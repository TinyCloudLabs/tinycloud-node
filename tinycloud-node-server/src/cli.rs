use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::{node_control::paths::Profile, node_control::service, runtime};

#[derive(Debug, Parser)]
#[command(name = "tinycloud", version, disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the server in foreground mode.
    Serve(ServeArgs),
    /// Node service management and diagnostics.
    Node(NodeArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Base config file to load.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct NodeArgs {
    #[command(subcommand)]
    command: NodeCommand,
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    Service(ServiceArgs),
    Status(JsonArgs),
    Logs(LogsArgs),
    Doctor(JsonArgs),
}

#[derive(Debug, Args)]
struct ServiceArgs {
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status(JsonArgs),
}

#[derive(Debug, Args, Default)]
struct JsonArgs {
    /// Emit JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args, Default)]
struct LogsArgs {
    /// Emit JSON.
    #[arg(long)]
    json: bool,

    /// Number of log lines to tail.
    #[arg(long)]
    lines: Option<u32>,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => run_legacy_server().await,
        Some(Commands::Serve(args)) => run_serve(args).await,
        Some(Commands::Node(args)) => run_node(args),
    }
}

async fn run_legacy_server() -> Result<()> {
    runtime::launch_with_figment(runtime::legacy_config_figment()).await
}

async fn run_serve(args: ServeArgs) -> Result<()> {
    let config_path = args
        .config
        .unwrap_or_else(|| runtime::serve_profile_config_path(Profile::default_for_host()));
    let figment = runtime::serve_config_figment(&config_path)?;
    runtime::launch_with_figment(figment).await
}

fn run_node(args: NodeArgs) -> Result<()> {
    match args.command {
        NodeCommand::Service(service_args) => run_service(service_args.command),
        NodeCommand::Status(args) => emit_value(service::node_status()?, args.json),
        NodeCommand::Logs(args) => emit_value(service::node_logs(args.lines)?, args.json),
        NodeCommand::Doctor(args) => {
            emit_value(serde_json::to_value(service::node_doctor()?)?, args.json)
        }
    }
}

fn run_service(command: ServiceCommand) -> Result<()> {
    match command {
        ServiceCommand::Install => service::install(),
        ServiceCommand::Uninstall => service::uninstall(),
        ServiceCommand::Start => service::start(),
        ServiceCommand::Stop => service::stop(),
        ServiceCommand::Restart => service::restart(),
        ServiceCommand::Status(_args) => {
            let status = service::service_status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
    }
}

fn emit_value(value: Value, _json: bool) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
