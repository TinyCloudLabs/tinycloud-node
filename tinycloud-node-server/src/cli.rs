use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde_json::Value;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

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
    Key(KeyArgs),
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

#[derive(Debug, Args)]
struct KeyArgs {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    Backup(BackupArgs),
    Export(JsonArgs),
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

#[derive(Debug, Args, Default)]
struct BackupArgs {
    /// Output path for the sealed backup bundle.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Read the passphrase from a file instead of prompting.
    #[arg(long = "passphrase-file")]
    passphrase_file: Option<PathBuf>,

    #[command(flatten)]
    json: JsonArgs,
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
        NodeCommand::Status(args) => emit_control_json(service::node_status_body()?, args.json),
        NodeCommand::Logs(args) => {
            emit_control_json(service::node_logs_body(args.lines)?, args.json)
        }
        NodeCommand::Doctor(args) => emit_json(&service::node_doctor()?, args.json),
        NodeCommand::Key(args) => run_key(args.command),
    }
}

fn run_key(command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Backup(args) => {
            let passphrase = load_passphrase(args.passphrase_file)?;
            let result = service::node_key_backup(&passphrase, args.output)?;
            emit_json(&result, args.json.json)
        }
        KeyCommand::Export(args) => emit_control_json(service::node_key_export_body()?, args.json),
    }
}

fn run_service(command: ServiceCommand) -> Result<()> {
    match command {
        ServiceCommand::Install => service::install(),
        ServiceCommand::Uninstall => service::uninstall(),
        ServiceCommand::Start => service::start(),
        ServiceCommand::Stop => service::stop(),
        ServiceCommand::Restart => service::restart(),
        ServiceCommand::Status(args) => {
            let status = service::service_status()?;
            emit_json(&status, args.json)
        }
    }
}

fn emit_json<T: serde::Serialize>(value: &T, json: bool) -> Result<()> {
    if json {
        print!("{}", serde_json::to_string(value)?);
        io::stdout().flush()?;
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn emit_control_json(body: String, json: bool) -> Result<()> {
    if json {
        print!("{}", body);
        io::stdout().flush()?;
        return Ok(());
    }

    match serde_json::from_str::<Value>(&body) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{}", body),
    }
    Ok(())
}

fn load_passphrase(passphrase_file: Option<PathBuf>) -> Result<Vec<u8>> {
    match passphrase_file {
        Some(path) => {
            let mut bytes = fs::read(&path)?;
            while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                bytes.pop();
            }
            if bytes.is_empty() {
                return Err(anyhow::anyhow!("passphrase file is empty"));
            }
            Ok(bytes)
        }
        None => {
            let passphrase = rpassword::prompt_password("Passphrase: ")?;
            if passphrase.is_empty() {
                return Err(anyhow::anyhow!("passphrase is required"));
            }
            Ok(passphrase.into_bytes())
        }
    }
}
