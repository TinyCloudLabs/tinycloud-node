//! One-shot attested root export. Inputs and output are public JSON only.
#[path = "../cli.rs"]
mod cli;
use clap::Parser;
use std::path::PathBuf;
use tinycloud_root_transfer::{export_root, GuestClient, TargetDocument, TransferConfig};

#[derive(Parser)]
#[command(about = "Seal a guest's root to an offline-verified attested import key")]
struct Args {
    /// Explicit Unix guest-agent socket; no implicit environment/default fallback.
    #[arg(long)]
    socket: PathBuf,
    /// JSON {policy, expected_old_did}; all trust pins are required.
    #[arg(long)]
    config: PathBuf,
    /// Original target quote, offline collateral, and hex X25519 public key.
    #[arg(long)]
    target: PathBuf,
    #[command(flatten)]
    output: cli::Output,
}

fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let config: TransferConfig = cli::read(&args.config)?;
    let target: TargetDocument = cli::read(&args.target)?;
    let sealed = export_root(
        &GuestClient::new(&args.socket),
        &target,
        &config,
        cli::now()?,
    )?;
    args.output.write(&sealed)
}

fn main() -> std::process::ExitCode {
    cli::finish(run())
}
