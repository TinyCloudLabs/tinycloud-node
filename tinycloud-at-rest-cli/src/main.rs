//! `tinycloud-at-rest`: escrow ceremony and recovery tool (TC-887).
//!
//! Secrets are never accepted on argv. A decrypted share is read from stdin
//! only (pipe it from `age -d`), and nothing here writes one to disk.
//!
//! Exit codes: 0 OK; 1 REFUSED (a check failed: don't release, don't pin);
//! 2 usage error; 3 ERROR (a file, stdin or network input couldn't be read).

#![forbid(unsafe_code)]

mod attest;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use tinycloud_at_rest_escrow::{
    validate_holders, wrap_share, Ark, ArkId, EscrowBundle, HolderRecipient, RecipientKind,
    RecipientPolicy, RecoveryInfo, VerificationRecord,
};
use zeroize::Zeroizing;

use attest::TrustPolicy;

/// An input couldn't be read at all (as opposed to a check that failed).
#[derive(Debug)]
struct InputError(String);

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InputError {}

fn input_err(msg: String) -> anyhow::Error {
    InputError(msg).into()
}

#[derive(Parser)]
#[command(
    name = "tinycloud-at-rest",
    about = "TinyCloud at-rest key escrow ceremony and recovery"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Software (X25519) holders are refused unless this is given.
#[derive(Args)]
struct SoftwareFlag {
    /// Accept X25519 software-key holders. Tests and self-hosted nodes only;
    /// every command warns loudly while it is in effect.
    #[arg(long)]
    allow_software: bool,
}

impl SoftwareFlag {
    fn policy(&self) -> RecipientPolicy {
        if self.allow_software {
            RecipientPolicy::AllowSoftware
        } else {
            RecipientPolicy::HardwareOnly
        }
    }
}

/// The bundle a command works on.
#[derive(Args)]
struct BundleArgs {
    /// The escrow bundle you were given.
    #[arg(long)]
    bundle: PathBuf,
    /// Refuse unless the bundle's EFP equals this (from Sam, out of band).
    #[arg(long)]
    expect_efp: Option<String>,
    #[command(flatten)]
    software: SoftwareFlag,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the three holder recipients and print the node config for them.
    Recipients {
        /// `NAME=RECIPIENT`, three times (e.g. `sam=age1yubikey1…`).
        #[arg(long = "holder", required = true)]
        holders: Vec<String>,
        #[command(flatten)]
        software: SoftwareFlag,
    },
    /// Ceremony step 0: seal a throwaway share to RECIPIENT with the exact
    /// code the TEE uses, so a holder can prove their YubiKey and age tooling
    /// decrypt it. Writes selftest-bundle.json and selftest-share.age to --out.
    SelfTest {
        #[arg(long)]
        recipient: String,
        #[arg(long, default_value = ".")]
        out: PathBuf,
        #[command(flatten)]
        software: SoftwareFlag,
    },
    /// Print the compressed P-256 public key (hex) inside an age1yubikey1 or
    /// age1tag1 recipient, to compare with a YubiKey attestation certificate.
    RecipientKey {
        #[arg(long)]
        recipient: String,
    },
    /// Print a fresh 256-bit nonce for a recovery request.
    Nonce,
    /// Validate a bundle and print its fingerprint, canary and holders.
    Inspect(BundleArgs),
    /// Print one holder's sealed share (an armored age file) to stdout.
    ExtractShare {
        #[command(flatten)]
        bundle: BundleArgs,
        #[arg(long)]
        holder: String,
    },
    /// Offline check: read a decrypted share on stdin (from `age -d`) and
    /// check it against the bundle's commitment. Prints no share bytes.
    CheckShare(BundleArgs),
    /// Check a deployment's app-compose.json against the trust policy's
    /// compose_hash and require every image to be pinned by @sha256: digest.
    VerifyCompose {
        #[arg(long)]
        app_compose: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
    /// Verify a node's recovery key: DCAP quote, TCB status, measurements,
    /// event log, and the binding to your nonce. Releases nothing.
    VerifyNode(NodeArgs),
    /// Verify the node exactly as `verify-node` does, then read a decrypted
    /// share on stdin, check it, and print it sealed to the node's recovery key.
    ShareWrap(NodeArgs),
    /// Print the EFP a ceremony record names, after checking that it names
    /// this bundle and claims all three shares. Its authenticity (MAC) can't
    /// be checked offline; the node checks it before enabling encryption.
    RecordEfp {
        #[command(flatten)]
        bundle: BundleArgs,
        #[arg(long)]
        record: PathBuf,
    },
}

#[derive(Args)]
struct NodeArgs {
    #[command(flatten)]
    bundle: BundleArgs,
    /// The node's `GET /at-rest/recovery?nonce=…` response.
    #[arg(long)]
    recovery: PathBuf,
    /// The nonce you generated for that request.
    #[arg(long)]
    nonce: String,
    /// Trusted measurements (JSON; see docs/at-rest-escrow.md).
    #[arg(long)]
    trust: PathBuf,
    /// DCAP collateral JSON for offline verification. Without it, collateral
    /// is fetched from `--pccs-url`.
    #[arg(long)]
    collateral: Option<PathBuf>,
    /// PCCS to fetch collateral from (Phala's, or Intel PCS
    /// `https://api.trustedservices.intel.com`).
    #[arg(long, default_value = dcap_qvl::collateral::PHALA_PCCS_URL)]
    pccs_url: String,
}

fn read_file(path: &Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| input_err(format!("reading {what} {}: {e}", path.display())))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let bytes = read_file(path, what)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| input_err(format!("parsing {what} {}: {e}", path.display())))
}

fn warn_software(holders: &[HolderRecipient], kinds: &[RecipientKind]) {
    for (h, kind) in holders.iter().zip(kinds) {
        if kind.is_software() {
            eprintln!(
                "!!! WARNING: holder {:?} uses an X25519 SOFTWARE key, not a hardware key. \
                 Accepted only because --allow-software was given (tests and self-host only). !!!",
                h.holder
            );
        }
    }
}

/// Read and validate a bundle, apply the recipient policy and `--expect-efp`.
fn read_bundle(args: &BundleArgs) -> Result<(EscrowBundle, Vec<RecipientKind>)> {
    let bytes = read_file(&args.bundle, "bundle")?;
    let bundle = EscrowBundle::from_json(&bytes)?;
    let kinds = bundle.check_recipients(args.software.policy())?;
    warn_software(&bundle.holders(), &kinds);
    if let Some(expected) = &args.expect_efp {
        let efp = bundle.fingerprint().to_string();
        if !expected.trim().eq_ignore_ascii_case(&efp) {
            bail!(
                "bundle {} has EFP {efp}, not the expected {expected}: it is stale or not the one Sam pinned",
                args.bundle.display()
            );
        }
    }
    Ok((bundle, kinds))
}

/// A decrypted share from stdin, bounded and zeroized.
fn read_share_stdin(bundle: &EscrowBundle) -> Result<tinycloud_at_rest_escrow::SharePayload> {
    let mut buf = Zeroizing::new(Vec::with_capacity(64));
    std::io::stdin()
        .lock()
        .take(4096)
        .read_to_end(&mut buf)
        .map_err(|e| input_err(format!("reading the decrypted share from stdin: {e}")))?;
    if buf.is_empty() {
        return Err(input_err(
            "no share on stdin: did `age -d` fail (wrong identity, YubiKey not inserted or not touched, wrong file)? \
             Pipe it as `age -d -i <identity> <share.age> | tinycloud-at-rest …`"
                .into(),
        ));
    }
    Ok(bundle.open_share(&buf)?)
}

async fn verify_node(args: &NodeArgs) -> Result<(EscrowBundle, RecoveryInfo)> {
    let (bundle, _) = read_bundle(&args.bundle)?;
    let info = RecoveryInfo::from_json(&read_file(&args.recovery, "recovery response")?)?;
    let trust: TrustPolicy = read_json(&args.trust, "trust policy")?;
    trust.validate()?;
    // Everything that needs no network first, so its cause is what's reported.
    let quote = attest::require_attested(&info)?;
    let digest = attest::check_local(&info, &bundle, &args.nonce)?;
    let collateral = match &args.collateral {
        Some(path) => read_json(path, "collateral")?,
        None => attest::fetch_collateral(&quote, &args.pccs_url)
            .await
            .map_err(|e| input_err(format!("{e:#}")))?,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let td = attest::verify_quote(&quote, &collateral, now)?;
    let tcb = attest::check_attestation(&info, &trust, &td, &digest)?;
    eprintln!("OK: genuine TDX quote; {tcb}");
    eprintln!("    {}", attest::collateral_dates(&collateral));
    eprintln!(
        "    MRTD, RTMR0-2, app-id and compose-hash match the trust policy; recovery key {} is bound to your nonce and escrow {}",
        info.recovery_recipient, info.efp
    );
    eprintln!(
        "    node state: {} ({}); shares it holds this boot: {:?}",
        info.state,
        if info.state == "locked" {
            "recovery: two shares unlock it"
        } else {
            "ceremony test-unlock: all three shares are checked"
        },
        info.shares_held
    );
    Ok((bundle, info))
}

fn print_holders(bundle: &EscrowBundle, kinds: &[RecipientKind]) {
    for (s, kind) in bundle.shares.iter().zip(kinds) {
        println!(
            "share {}  holder {:<10} {:<8} recipient {}",
            s.index,
            s.holder,
            match kind {
                RecipientKind::PivP256 => "piv-p256",
                RecipientKind::P256Tag => "p256tag",
                RecipientKind::X25519 => "X25519!",
            },
            s.recipient
        );
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Recipients { holders, software } => {
            let parsed = holders
                .iter()
                .map(|h| {
                    let (holder, recipient) = h.split_once('=').ok_or_else(|| {
                        input_err(format!("--holder {h:?} must be NAME=RECIPIENT"))
                    })?;
                    Ok(HolderRecipient {
                        holder: holder.into(),
                        recipient: recipient.into(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let kinds = validate_holders(&parsed, software.policy())?;
            warn_software(&parsed, &kinds);
            eprintln!(
                "Note: a holder name is only a label. Check each recipient really is that holder's key; \
                 the ceremony test-unlock is what proves it."
            );
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
        Command::SelfTest {
            recipient,
            out,
            software,
        } => {
            // Two throwaway co-holders: fresh P-256 keys whose private halves
            // are dropped here. The ARK is random and discarded too.
            let dummy = || {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let pk = p256::SecretKey::random(&mut rand::rngs::OsRng).public_key();
                let hrp = bech32::Hrp::parse("age1yubikey").expect("valid HRP");
                bech32::encode::<bech32::Bech32>(hrp, pk.to_encoded_point(true).as_bytes())
                    .expect("33-byte key encodes")
            };
            let holders = vec![
                HolderRecipient {
                    holder: "selftest".into(),
                    recipient,
                },
                HolderRecipient {
                    holder: "dummy-a".into(),
                    recipient: dummy(),
                },
                HolderRecipient {
                    holder: "dummy-b".into(),
                    recipient: dummy(),
                },
            ];
            let kinds = validate_holders(&holders, software.policy())?;
            warn_software(&holders, &kinds);
            let bundle = EscrowBundle::create(
                &Ark::generate(),
                ArkId::generate(),
                1,
                &holders,
                software.policy(),
            )?;
            let bundle_path = out.join("selftest-bundle.json");
            let share_path = out.join("selftest-share.age");
            std::fs::write(&bundle_path, serde_json::to_vec_pretty(&bundle)?)
                .map_err(|e| input_err(format!("writing {}: {e}", bundle_path.display())))?;
            std::fs::write(&share_path, bundle.shares[0].ciphertext.as_bytes())
                .map_err(|e| input_err(format!("writing {}: {e}", share_path.display())))?;
            eprintln!(
                "Wrote a THROWAWAY test escrow ({:?} kind, sealed by the TEE's code). Now run:",
                kinds[0]
            );
            eprintln!(
                "  age -d -i <your identity file> {} | tinycloud-at-rest check-share --bundle {}{}",
                share_path.display(),
                bundle_path.display(),
                if software.allow_software {
                    " --allow-software"
                } else {
                    ""
                }
            );
            eprintln!("Expect: OK: share 1 (selftest) matches escrow …");
        }
        Command::RecipientKey { recipient } => {
            tinycloud_at_rest_escrow::parse_recipient("recipient", &recipient)?;
            let (hrp, key) = bech32::decode(&recipient)
                .map_err(|e| input_err(format!("recipient is not Bech32: {e}")))?;
            if !matches!(hrp.as_str(), "age1yubikey" | "age1tag") || key.len() != 33 {
                bail!("{recipient} is not a P-256 (age1yubikey1/age1tag1) recipient");
            }
            println!("{}", hex::encode(key));
        }
        Command::Nonce => {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            println!(
                "{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
            );
        }
        Command::Inspect(args) => {
            let (bundle, kinds) = read_bundle(&args)?;
            println!("efp        {}", bundle.fingerprint());
            println!("ark_id     {}", bundle.ark_id);
            println!("generation {}", bundle.generation);
            println!("canary_fp  {}", bundle.canary_fp);
            print_holders(&bundle, &kinds);
        }
        Command::ExtractShare { bundle, holder } => {
            let (bundle, _) = read_bundle(&bundle)?;
            let Some(share) = bundle.share_for(&holder) else {
                let names: Vec<String> = bundle.holders().into_iter().map(|h| h.holder).collect();
                return Err(input_err(format!(
                    "no holder {holder:?} in this bundle (holders: {names:?})"
                )));
            };
            std::io::stdout().write_all(share.ciphertext.as_bytes())?;
        }
        Command::CheckShare(args) => {
            let (bundle, _) = read_bundle(&args)?;
            let share = read_share_stdin(&bundle)?;
            let holder = &bundle.shares[usize::from(share.index) - 1].holder;
            eprintln!(
                "OK: share {} ({holder}) matches escrow {} (ARK {})",
                share.index,
                bundle.fingerprint(),
                bundle.ark_id
            );
        }
        Command::VerifyCompose { app_compose, trust } => {
            let trust: TrustPolicy = read_json(&trust, "trust policy")?;
            trust.validate()?;
            let bytes = read_file(&app_compose, "app-compose.json")?;
            let images = attest::check_app_compose(&bytes, &trust)?;
            eprintln!(
                "OK: app-compose.json matches compose_hash {}; every image is pinned by digest:",
                trust.compose_hash
            );
            for image in images {
                eprintln!("    {image}");
            }
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
                "OK: share {} sealed to this node's recovery key. POST it to the same node's /at-rest/recovery/shares \
                 before it restarts (the key is per boot).",
                share.index
            );
        }
        Command::RecordEfp { bundle, record } => {
            let (bundle, _) = read_bundle(&bundle)?;
            let record = VerificationRecord::from_json(&read_file(&record, "record")?)?;
            record.covers(&bundle)?;
            eprintln!(
                "NOT AUTHENTICATED: this record names escrow {} and claims shares {:?} and pairs {:?} (verified_at {}),",
                record.efp, record.verified_indices, record.pairs, record.verified_at
            );
            eprintln!(
                "but its MAC can only be checked inside the TEE. Pin this value only after you saw the node answer \
                 the third share with \"verified\"; the node refuses to encrypt unless the stored record verifies."
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
        if e.downcast_ref::<InputError>().is_some() {
            eprintln!("ERROR: {e:#}");
            std::process::exit(3);
        }
        eprintln!("REFUSED: {e:#}");
        std::process::exit(1);
    }
}
