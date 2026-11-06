//! Prepare an import target or validate a sealed transfer. No migration job here.
#[path = "../cli.rs"]
mod cli;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tinycloud_root_transfer::{
    import_for_job, prepare_target, AttestationPolicy, GuestClient, SealedRoot, TargetDocument,
    TransferConfig,
};

#[derive(Parser)]
#[command(about = "Prepare an attested import key or validate a transfer (not database migration)")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish an UNVERIFIED target quote/key; export/import must verify it.
    Prepare {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        /// Offline Intel DCAP collateral JSON; no live collateral fetch.
        #[arg(long)]
        collateral: PathBuf,
        #[command(flatten)]
        output: cli::Output,
    },
    /// Verify target policy, decrypt, and check old DID, then erase the root.
    /// Does NOT persist roots, re-encrypt rows, or claim to migrate a database.
    VerifyOnly {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        sealed: PathBuf,
    },
}

fn run() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::Prepare {
            socket,
            policy,
            collateral,
            output,
        } => {
            let policy: AttestationPolicy = cli::read(&policy)?;
            let collateral = cli::read(&collateral)?;
            output.write(&prepare_target(
                &GuestClient::new(socket),
                &policy,
                collateral,
            )?)
        }
        Command::VerifyOnly {
            socket,
            config,
            target,
            sealed,
        } => {
            let config: TransferConfig = cli::read(&config)?;
            let target: TargetDocument = cli::read(&target)?;
            let sealed: SealedRoot = cli::read(&sealed)?;
            // This callback intentionally only validates custody. Applications
            // supply an actual re-encryption job through import_for_job instead.
            import_for_job(
                &GuestClient::new(socket),
                &target,
                &config,
                &sealed,
                cli::now()?,
                |_| Ok(()),
            )?;
            println!("{{\"transfer_validated\":true,\"database_migrated\":false}}");
            Ok(())
        }
    }
}

fn main() -> std::process::ExitCode {
    cli::finish(run())
}
