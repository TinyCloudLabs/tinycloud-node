//! `tinycloud-at-rest`: escrow ceremony and recovery tool (TC-887).
//!
//! Secrets are never accepted on argv. A decrypted share is read from stdin
//! only (pipe it from `age -d`), and nothing here writes one to disk.

mod attest;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use tinycloud_at_rest_escrow::{
    validate_holders, wrap_share, EscrowBundle, HolderRecipient, RecipientKind, RecoveryInfo,
    VerificationRecord,
};
use zeroize::Zeroizing;

use attest::TrustPolicy;

#[derive(Parser)]
#[command(
    name = "tinycloud-at-rest",
    about = "TinyCloud at-rest key escrow ceremony and recovery"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the three holder recipients and print the node config for them.
    Recipients {
        /// `NAME=RECIPIENT`, three times (e.g. `sam=age1tag1…`).
        #[arg(long = "holder", required = true)]
        holders: Vec<String>,
    },
    /// Print a fresh 256-bit nonce for a recovery request.
    Nonce,
    /// Validate a bundle and print its fingerprint, canary and holders.
    Inspect {
        #[arg(long)]
        bundle: PathBuf,
        /// Fail unless the bundle's EFP equals this value.
        #[arg(long)]
        expect_efp: Option<String>,
    },
    /// Print one holder's sealed share (an armored age file) to stdout.
    ExtractShare {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        holder: String,
    },
    /// Offline check: read a decrypted share on stdin (from `age -d`) and
    /// check it against the bundle's commitment. Prints no share bytes.
    CheckShare {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Verify a node's recovery key: DCAP quote, measurements, event log,
    /// and the binding to your nonce. Releases nothing.
    VerifyNode(NodeArgs),
    /// Verify the node exactly as `verify-node` does, then read a decrypted
    /// share on stdin, check it, and print it sealed to the node's recovery key.
    ShareWrap(NodeArgs),
    /// Check that a verification record covers the bundle and print the value
    /// to pin as `at_rest.escrow.verified_fp`.
    VerifyRecord {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        record: PathBuf,
    },
}

#[derive(Args)]
struct NodeArgs {
    /// The escrow bundle you were given (not the node's copy).
    #[arg(long)]
    bundle: PathBuf,
    /// The node's `GET /at-rest/recovery?nonce=…` response.
    #[arg(long)]
    recovery: PathBuf,
    /// The nonce you generated for that request.
    #[arg(long)]
    nonce: String,
    /// Trusted measurements (JSON; see ESCROW-CEREMONY.md).
    #[arg(long)]
    trust: PathBuf,
    /// DCAP collateral JSON for offline verification. Without it, collateral
    /// is fetched from `--pccs-url`.
    #[arg(long)]
    collateral: Option<PathBuf>,
    #[arg(long, default_value = dcap_qvl::collateral::PHALA_PCCS_URL)]
    pccs_url: String,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading {what} {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {what} {}", path.display()))
}

fn read_bundle(path: &Path) -> Result<EscrowBundle> {
    let bundle: EscrowBundle = read_json(path, "bundle")?;
    bundle.validate()?;
    Ok(bundle)
}

/// A decrypted share from stdin, bounded and zeroized.
fn read_share_stdin(bundle: &EscrowBundle) -> Result<tinycloud_at_rest_escrow::SharePayload> {
    let mut buf = Zeroizing::new(Vec::with_capacity(64));
    std::io::stdin()
        .lock()
        .take(4096)
        .read_to_end(&mut buf)
        .context("reading the decrypted share from stdin")?;
    if buf.is_empty() {
        bail!("no share on stdin; pipe it from `age -d -i <identity> <share.age>`");
    }
    Ok(bundle.open_share(&buf)?)
}

async fn verify_node(args: &NodeArgs) -> Result<(EscrowBundle, RecoveryInfo)> {
    let bundle = read_bundle(&args.bundle)?;
    let info: RecoveryInfo = read_json(&args.recovery, "recovery response")?;
    let trust: TrustPolicy = read_json(&args.trust, "trust policy")?;
    trust.validate()?;
    if info.mode != "dstack" {
        bail!(
            "the node is not in a TEE (mode {:?}); a share is only released to an attested TEE",
            info.mode
        );
    }
    let quote =
        hex::decode(info.quote.as_deref().unwrap_or_default()).context("quote is not hex")?;
    if quote.is_empty() {
        bail!("the node sent no TDX quote");
    }
    let collateral = match &args.collateral {
        Some(path) => read_json(path, "collateral")?,
        None => attest::fetch_collateral(&quote, &args.pccs_url).await?,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let td = attest::verify_quote(&quote, &collateral, now)?;
    attest::check_recovery(&info, &bundle, &args.nonce, &trust, &td)?;
    eprintln!(
        "OK: genuine TDX quote ({}), measurements match the trust policy, recovery key {} bound to your nonce and escrow {}",
        td.tcb_status, info.recovery_recipient, info.efp
    );
    Ok((bundle, info))
}

fn print_holders(bundle: &EscrowBundle) {
    for s in &bundle.shares {
        println!(
            "share {}  holder {:<10} recipient {}",
            s.index, s.holder, s.recipient
        );
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Recipients { holders } => {
            let parsed = holders
                .iter()
                .map(|h| {
                    let (holder, recipient) = h
                        .split_once('=')
                        .context("each --holder must be NAME=RECIPIENT")?;
                    Ok(HolderRecipient {
                        holder: holder.into(),
                        recipient: recipient.into(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let kinds = validate_holders(&parsed)?;
            for (h, kind) in parsed.iter().zip(&kinds) {
                if *kind == RecipientKind::SoftwareX25519 {
                    eprintln!(
                        "WARNING: holder {:?} uses an X25519 (software) recipient, not a hardware key",
                        h.holder
                    );
                }
            }
            let inline = parsed
                .iter()
                .map(|h| format!("{{holder=\"{}\",recipient=\"{}\"}}", h.holder, h.recipient))
                .collect::<Vec<_>>()
                .join(",");
            println!("# tinycloud.toml");
            println!("[at_rest.escrow]");
            println!("recipients = [");
            for h in &parsed {
                println!(
                    "  {{ holder = \"{}\", recipient = \"{}\" }},",
                    h.holder, h.recipient
                );
            }
            println!("]");
            println!();
            println!("# or compose environment");
            println!("TINYCLOUD_AT_REST__ESCROW__RECIPIENTS=[{inline}]");
        }
        Command::Nonce => {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            println!(
                "{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
            );
        }
        Command::Inspect { bundle, expect_efp } => {
            let bundle = read_bundle(&bundle)?;
            let efp = bundle.fingerprint();
            println!("efp        {efp}");
            println!("ark_id     {}", bundle.ark_id);
            println!("generation {}", bundle.generation);
            println!("canary_fp  {}", bundle.canary_fp);
            print_holders(&bundle);
            if let Some(expected) = expect_efp {
                if expected != efp.to_string() {
                    bail!("bundle EFP {efp} is not the expected {expected}");
                }
                eprintln!("OK: EFP matches");
            }
        }
        Command::ExtractShare { bundle, holder } => {
            let bundle = read_bundle(&bundle)?;
            let share = bundle
                .share_for(&holder)
                .with_context(|| format!("no holder {holder:?} in this bundle"))?;
            std::io::stdout().write_all(share.ciphertext.as_bytes())?;
        }
        Command::CheckShare { bundle } => {
            let bundle = read_bundle(&bundle)?;
            let share = read_share_stdin(&bundle)?;
            let holder = &bundle.shares[usize::from(share.index) - 1].holder;
            eprintln!(
                "OK: share {} ({holder}) matches escrow {} (ARK {})",
                share.index,
                bundle.fingerprint(),
                bundle.ark_id
            );
        }
        Command::VerifyNode(args) => {
            verify_node(&args).await?;
        }
        Command::ShareWrap(args) => {
            let (bundle, info) = verify_node(&args).await?;
            let share = read_share_stdin(&bundle)?;
            let wrapped = wrap_share(&info.recovery_recipient, &share)?;
            std::io::stdout().write_all(wrapped.as_bytes())?;
            eprintln!(
                "OK: share {} sealed to the node's recovery key; POST it to /at-rest/recovery/shares",
                share.index
            );
        }
        Command::VerifyRecord { bundle, record } => {
            let bundle = read_bundle(&bundle)?;
            let record: VerificationRecord = read_json(&record, "verification record")?;
            record.covers(&bundle)?;
            eprintln!(
                "OK: record covers shares {:?} and pairs {:?} of escrow {} (verified {})",
                record.verified_indices, record.pairs, record.efp, record.verified_at
            );
            println!("TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP={}", record.efp);
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = runtime.block_on(run(cli)) {
        eprintln!("REFUSED: {e:#}");
        std::process::exit(1);
    }
}
