//! Node wiring for encryption at rest (TC-887 S1): config → keyring, the
//! boot-time escrow gate, and the runtime state the routes use.
//!
//! Two phases, because block storage opens before migrations and the
//! keyring needs its tables: [`AtRestRuntime::new`] before storage, then
//! [`setup`] after migrations installs the keyring.
//!
//! Block storage declares its seal path when it is attached
//! ([`crate::storage::attach_at_rest`] calls
//! [`AtRestRuntime::declare_seal_path`] for a store that seals every
//! write); without it `setup` refuses every mode but `off` and
//! `encrypting()` stays false.
//!
//! With the default config (`mode = "off"`, no recipients, no
//! `escrow_none`) nothing is set up: no key reads, no rows, no mirror.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{bail, ensure, Context, Result};
use sha2::Digest as _;
use tinycloud_at_rest_escrow::compose::{AppCompose, RECIPIENTS_ENV, VERIFIED_FP_ENV};
use tinycloud_at_rest_escrow::{Efp, HolderRecipient, RecipientPolicy};
use tinycloud_core::{
    at_rest::{
        keyring::{GatePass, GateRefusal},
        AtRestKeyring, AtRestStore, DataKeyProvider, KeyMirror, KeyringConfig, KeyringState,
    },
    storage::either::Either,
    RecoveringConnection,
};

use crate::config::{AtRestConfig, AtRestEscrowConfig, AtRestMode, Storage};
use crate::storage::at_rest_mirror::{FsKeyMirror, S3KeyMirror};
use crate::tee::TeeContext;

/// At-rest state shared by the routes, `/info` and block storage. Rocket
/// manages it as `Arc<AtRestRuntime>`.
///
/// The contract for the storage seal path (TC-887 S3): mode `off` behaves
/// exactly as without at-rest. Otherwise writes are sealed only while
/// [`encrypting`](Self::encrypting) (else 503, never plaintext); a sealed
/// read whose key is `Locked` is a 503; legacy plaintext reads are allowed
/// unless the mode is `strict`.
pub struct AtRestRuntime {
    mode: AtRestMode,
    escrow_none: bool,
    keyring: OnceLock<Arc<AtRestKeyring>>,
    /// The gate passed for a non-`off` mode and the keys are unlocked: new
    /// writes may be encrypted. Set at boot, or after a recovery unlocks a
    /// node whose gate then passes.
    encrypting: AtomicBool,
    /// Set by block storage when it is attached with a seal path (TC-887
    /// S3). Without it a mode other than `off` is refused at boot and
    /// `encrypting` stays false.
    seal_path: AtomicBool,
    share_failures: ShareFailureLimiter,
}

/// Failed share submissions per client: a share that doesn't decrypt to
/// this boot's recovery key or match a commitment. A client that keeps
/// failing is refused for a while. Failures never spend the keyring's
/// per-boot share budget, which only authenticated shares count against.
///
/// Bounded: an LRU of [`Self::MAX_CLIENTS`] entries, O(1) per call. When
/// full, the least recently seen client is forgotten (so its budget
/// resets), which only weakens a best-effort limit (TC-1357), never the
/// per-boot budget.
pub struct ShareFailureLimiter {
    clients: parking_lot::Mutex<lru::LruCache<std::net::IpAddr, (f64, std::time::Instant)>>,
}

impl ShareFailureLimiter {
    /// Failures a client may make at once, then one more per minute.
    pub const BURST: f64 = 5.0;
    const REFILL_PER_SEC: f64 = 1.0 / 60.0;
    pub const MAX_CLIENTS: usize = 4096;

    fn new() -> Self {
        Self {
            clients: parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(Self::MAX_CLIENTS).expect("non-zero"),
            )),
        }
    }

    fn refilled(entry: &mut (f64, std::time::Instant)) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * Self::REFILL_PER_SEC).min(Self::BURST);
        entry.1 = now;
    }

    /// Whether `ip` may submit now.
    pub fn allows(&self, ip: std::net::IpAddr) -> bool {
        let mut clients = self.clients.lock();
        match clients.get_mut(&ip) {
            None => true,
            Some(entry) => {
                Self::refilled(entry);
                entry.0 >= 1.0
            }
        }
    }

    pub fn record_failure(&self, ip: std::net::IpAddr) {
        let mut clients = self.clients.lock();
        let entry = clients.get_or_insert_mut(ip, || (Self::BURST, std::time::Instant::now()));
        Self::refilled(entry);
        entry.0 = (entry.0 - 1.0).max(0.0);
    }
}

/// The node's [`AtRestRuntime`], if it manages one. Unlike a `State` guard it
/// never fails, so a node without it (a test fixture) still launches.
pub struct AtRestState<'r>(pub Option<&'r AtRestRuntime>);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for AtRestState<'r> {
    type Error = std::convert::Infallible;

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        rocket::request::Outcome::Success(AtRestState(
            request
                .rocket()
                .state::<Arc<AtRestRuntime>>()
                .map(|r| r.as_ref()),
        ))
    }
}

impl AtRestRuntime {
    /// Phase one, before block storage opens. No keys yet: `provider()` is
    /// `None` and `encrypting()` is false until [`setup`] runs.
    pub fn new(config: &AtRestConfig) -> Arc<Self> {
        Arc::new(Self {
            mode: config.mode,
            escrow_none: config.escrow_none,
            keyring: OnceLock::new(),
            encrypting: AtomicBool::new(false),
            seal_path: AtomicBool::new(false),
            share_failures: ShareFailureLimiter::new(),
        })
    }

    pub fn mode(&self) -> AtRestMode {
        self.mode
    }

    /// Whether new writes may be sealed now: storage has a seal path, the
    /// gate passed (non-`off` mode) and the keys are unlocked.
    pub fn encrypting(&self) -> bool {
        self.encrypting.load(Ordering::SeqCst)
    }

    /// Storage calls this when it opens with a seal path for every write
    /// (the capability S3 turns on). Without it `setup` refuses any mode
    /// other than `off`, so the node never claims to encrypt while storage
    /// writes plaintext.
    pub fn declare_seal_path(&self) {
        self.seal_path.store(true, Ordering::SeqCst);
    }

    pub fn has_seal_path(&self) -> bool {
        self.seal_path.load(Ordering::SeqCst)
    }

    pub fn share_failures(&self) -> &ShareFailureLimiter {
        &self.share_failures
    }

    /// The data-key provider, once [`setup`] installed a keyring. `None`
    /// when at-rest isn't configured. A locked keyring is still returned;
    /// its calls fail with `DataKeyError::Locked`.
    pub fn provider(&self) -> Option<Arc<dyn DataKeyProvider>> {
        self.keyring
            .get()
            .map(|k| k.clone() as Arc<dyn DataKeyProvider>)
    }

    pub fn keyring(&self) -> Option<&Arc<AtRestKeyring>> {
        self.keyring.get()
    }

    /// Re-run the gate, e.g. after a recovery unlocked the keys. Only a
    /// non-`off` mode can turn encryption on.
    pub async fn reevaluate(&self) -> Result<GatePass, GateRefusal> {
        let Some(keyring) = self.keyring.get() else {
            return Err(GateRefusal::NotProvisioned);
        };
        let result = keyring.gate(self.escrow_none).await;
        let on = self.mode != AtRestMode::Off && self.has_seal_path() && result.is_ok();
        self.encrypting.store(on, Ordering::SeqCst);
        result
    }

    /// While a mode other than `off` is configured and encryption is off on
    /// an unlocked node (for example the gate hit a transient store or
    /// mirror error after a recovery), re-run the gate every `every`.
    pub fn spawn_gate_retry(self: &Arc<Self>, every: std::time::Duration) {
        if self.mode == AtRestMode::Off {
            return;
        }
        let runtime = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let Some(runtime) = runtime.upgrade() else {
                    return;
                };
                let unlocked = runtime
                    .keyring()
                    .is_some_and(|k| k.state() == KeyringState::Unlocked);
                if unlocked && !runtime.encrypting() {
                    match runtime.reevaluate().await {
                        Ok(_) if runtime.encrypting() => {
                            ::tracing::info!(
                                "at-rest escrow gate passed on retry; encryption enabled"
                            )
                        }
                        Ok(_) => {}
                        Err(reason) => {
                            ::tracing::warn!(%reason, "at-rest escrow gate still closed")
                        }
                    }
                }
            }
        });
    }

    pub fn mode_name(&self) -> &'static str {
        match self.mode {
            AtRestMode::Off => "off",
            AtRestMode::Encrypt => "encrypt",
            AtRestMode::Strict => "strict",
        }
    }

    pub fn state_name(&self) -> &'static str {
        match self.keyring.get().map(|k| k.state()) {
            None => "disabled",
            Some(KeyringState::NotProvisioned) => "not_provisioned",
            Some(KeyringState::Locked) => "locked",
            Some(KeyringState::Unlocked) => "unlocked",
        }
    }
}

/// Phase two, after migrations ran: open the keyring and run the gate.
///
/// Refuses (an error, so the node does not start):
/// - `mode` other than `off` while storage has no seal path
///   ([`AtRestRuntime::declare_seal_path`]);
/// - in a TEE, escrow recipients or a pin that are not literal values in
///   the measured compose ([`check_measured_escrow`]);
/// - `encrypt` or `strict` when the keys are unlocked but the escrow gate
///   fails.
///
/// A node that boots **locked** starts anyway, with encryption
/// unavailable, so two holders can recover it.
pub async fn setup(
    runtime: &AtRestRuntime,
    config: &AtRestConfig,
    storage: &Storage,
    root: &[u8],
    db: RecoveringConnection,
    sqlite_writer_lock: Option<Arc<tokio::sync::Mutex<()>>>,
    tee: Option<&TeeContext>,
) -> Result<()> {
    let escrow = &config.escrow;
    if !enabled(config) {
        return Ok(());
    }
    if config.mode != AtRestMode::Off && !runtime.has_seal_path() {
        bail!(
            "at_rest.mode = \"{}\" is refused: this build's storage has no at-rest seal path, so nothing would be encrypted; use mode = \"off\"",
            runtime.mode_name()
        );
    }
    if config.escrow_none && !escrow.recipients.is_empty() {
        bail!("set at_rest.escrow.recipients or at_rest.escrow_none, not both");
    }
    if tee.is_some() && config.escrow_none {
        bail!("at_rest.escrow_none is only for self-hosted Static-root nodes; a TEE node must escrow its key");
    }
    if tee.is_some() && escrow.allow_software {
        bail!("at_rest.escrow.allow_software is refused inside a TEE: escrow holders must use hardware keys");
    }
    // In a TEE every at-rest configuration is checked against the measured
    // compose; see `check_tee_escrow`.
    if let Some(tee) = tee {
        check_tee_escrow(crate::dstack::get_app_compose().await, tee, escrow)?;
    }
    let pinned_efp = escrow.verified_fp.as_deref().map(parse_efp).transpose()?;
    let mirror: Arc<dyn KeyMirror> = match &storage.blocks {
        Either::A(s3) => Arc::new(S3KeyMirror::new(s3).await),
        Either::B(_) => Arc::new(FsKeyMirror::new(storage.datadir.join("at-rest"))),
    };
    let keyring = AtRestKeyring::open(
        AtRestStore::new(db).with_sqlite_writer_lock(sqlite_writer_lock),
        mirror,
        root,
        KeyringConfig {
            provision: true,
            holders: escrow.recipients.clone(),
            recipient_policy: if escrow.allow_software {
                RecipientPolicy::AllowSoftware
            } else {
                RecipientPolicy::HardwareOnly
            },
            pinned_efp,
            app_id: tee.map(|t| t.app_id.clone()),
            compose_hash: tee.map(|t| t.compose_hash.clone()),
            // Once keys may seal data, the mirror must hold a copy of every
            // key; with mode off, mirror contents never stop the node.
            require_mirror: config.mode != AtRestMode::Off,
            allow_resplit_before_verify: escrow.allow_resplit_before_verify,
        },
    )
    .await
    .context("at-rest keys")?;
    if runtime.keyring.set(Arc::new(keyring)).is_err() {
        bail!("at-rest keys were already set up");
    }
    match runtime.keyring().map(|k| k.state()) {
        Some(KeyringState::Unlocked) => {
            let gate = runtime.reevaluate().await;
            match (config.mode, gate) {
                (AtRestMode::Off, Ok(GatePass::Verified { .. })) => {
                    ::tracing::info!("at-rest keys unlocked; escrow verified; mode off")
                }
                (AtRestMode::Off, Ok(GatePass::Unescrowed)) => ::tracing::info!(
                    "at-rest keys unlocked; no escrow (escrow_none acknowledged); mode off"
                ),
                (AtRestMode::Off, Err(refusal)) => ::tracing::warn!(
                    reason = %refusal,
                    "at-rest keys unlocked; the escrow gate is not satisfied yet"
                ),
                (mode, Ok(_)) => ::tracing::info!(?mode, "at-rest encryption enabled"),
                (mode, Err(refusal)) => {
                    bail!("at_rest.mode = {mode:?} is refused: {refusal}")
                }
            }
        }
        Some(KeyringState::Locked) => ::tracing::error!(
            mode = runtime.mode_name(),
            "at-rest keys are LOCKED: encrypted data is unavailable until two escrow holders recover the key (POST /at-rest/recovery/shares)"
        ),
        _ => bail!("at-rest keys were not provisioned"),
    }
    Ok(())
}

/// Whether any at-rest setting is configured (otherwise nothing is set up).
pub fn enabled(config: &AtRestConfig) -> bool {
    config.mode != AtRestMode::Off || !config.escrow.recipients.is_empty() || config.escrow_none
}

/// The dstack socket exists but its Info couldn't be read, so the node
/// can't tell whether it runs in a TEE. Booting as non-TEE would skip the
/// TEE-only checks (measured compose, no `escrow_none`, no software
/// holders), so with any at-rest setting the node refuses to start.
pub fn refuse_unknown_tee(config: &AtRestConfig, info_error: &anyhow::Error) -> Result<()> {
    if enabled(config) {
        bail!(
            "refusing to start: the dstack socket is present but its Info could not be read ({info_error:#}), so the at-rest TEE checks can't run"
        );
    }
    Ok(())
}

/// The TEE boot check: `app_compose` is what the guest agent returned for
/// `tcb_info.app_compose`. If it couldn't be read, or doesn't parse, or the
/// escrow config doesn't match its literals, the node refuses to start: it
/// never runs at-rest in a TEE without the check. (The guest agent's Info
/// shape is to be confirmed on a live CVM before the escrow ceremony.)
pub fn check_tee_escrow(
    app_compose: Result<String>,
    tee: &TeeContext,
    escrow: &AtRestEscrowConfig,
) -> Result<()> {
    let app_compose = app_compose.context(
        "refusing to start: at-rest needs the measured app-compose (dstack Info tcb_info.app_compose) to check the escrow config, and it could not be read",
    )?;
    check_measured_escrow(&app_compose, &tee.compose_hash, escrow).context(
        "refusing to start: the at-rest escrow config does not match the measured app-compose",
    )
}

fn parse_efp(s: &str) -> Result<Efp> {
    s.trim()
        .to_ascii_lowercase()
        .parse::<Efp>()
        .map_err(|_| anyhow::anyhow!("at_rest.escrow.verified_fp must be 64 hex characters"))
}

/// In a TEE, the escrow recipients and the pinned fingerprint decide who can
/// rebuild the root key, so they must come from the attested compose: each
/// must equal a literal value in the measured `app-compose.json` (covered by
/// `compose_hash`), never the encrypted environment, a file or any other
/// runtime source. Either one configured without a matching literal, or a
/// literal the effective config doesn't match, is refused.
pub fn check_measured_escrow(
    app_compose: &str,
    compose_hash: &str,
    escrow: &AtRestEscrowConfig,
) -> Result<()> {
    let digest = hex::encode(sha2::Sha256::digest(app_compose.as_bytes()));
    ensure!(
        digest.eq_ignore_ascii_case(compose_hash.trim()),
        "the app-compose the guest agent reports hashes to {digest}, not the measured compose_hash {compose_hash}"
    );
    let compose =
        AppCompose::parse(app_compose.as_bytes()).context("reading the measured app-compose")?;
    let literal_recipients = compose.literal_env(RECIPIENTS_ENV)?;
    match literal_recipients {
        None => ensure!(
            escrow.recipients.is_empty(),
            "at_rest.escrow.recipients must be set as a literal {RECIPIENTS_ENV} in the measured compose, not from the environment or a file"
        ),
        Some(literal) => {
            let value: rocket::figment::value::Value =
                literal.parse().unwrap_or_else(|never| match never {});
            let measured: Vec<HolderRecipient> = value
                .deserialize()
                .with_context(|| format!("the measured {RECIPIENTS_ENV} does not parse"))?;
            ensure!(
                measured == escrow.recipients,
                "at_rest.escrow.recipients differ from the literal {RECIPIENTS_ENV} in the measured compose"
            );
        }
    }
    let literal_fp = compose.literal_env(VERIFIED_FP_ENV)?;
    let configured = escrow.verified_fp.as_deref().map(parse_efp).transpose()?;
    match (literal_fp, configured) {
        (None, None) => {}
        (None, Some(_)) => bail!(
            "at_rest.escrow.verified_fp must be set as a literal {VERIFIED_FP_ENV} in the measured compose, not from the environment or a file"
        ),
        (Some(_), None) => bail!(
            "the measured compose pins {VERIFIED_FP_ENV}, but the effective config has no at_rest.escrow.verified_fp"
        ),
        (Some(literal), Some(configured)) => ensure!(
            parse_efp(&literal)? == configured,
            "at_rest.escrow.verified_fp differs from the literal {VERIFIED_FP_ENV} in the measured compose"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "[{holder=\"sam\",recipient=\"age1yubikey1qg3fps8csqk30gjdt552hf7jyjnmt753z9yhk4p8f0x5vvr5m53mju3vr5u\"},{holder=\"hunter\",recipient=\"age1yubikey1qg3fps8csqk30gjdt552hf7jyjnmt753z9yhk4p8f0x5vvr5m53mju3vr5u\"},{holder=\"safe\",recipient=\"age1yubikey1qg3fps8csqk30gjdt552hf7jyjnmt753z9yhk4p8f0x5vvr5m53mju3vr5u\"}]";

    fn app_compose(env: &str) -> String {
        let digest = "a".repeat(64);
        serde_json::to_string(&serde_json::json!({
            "manifest_version": 2,
            "runner": "docker-compose",
            "docker_compose_file": format!(
                "services:\n  tinycloud:\n    image: n@sha256:{digest}\n    environment:\n{env}"
            ),
        }))
        .unwrap()
    }

    fn hash(s: &str) -> String {
        hex::encode(sha2::Sha256::digest(s.as_bytes()))
    }

    fn escrow(recipients: &str, fp: Option<&str>) -> AtRestEscrowConfig {
        let value: rocket::figment::value::Value = recipients.parse().unwrap();
        AtRestEscrowConfig {
            recipients: value.deserialize().unwrap(),
            verified_fp: fp.map(str::to_owned),
            allow_software: false,
            allow_resplit_before_verify: false,
        }
    }

    #[test]
    fn literal_compose_values_pass() {
        let fp = "b".repeat(64);
        let doc = app_compose(&format!(
            "      {RECIPIENTS_ENV}: '{R}'\n      {VERIFIED_FP_ENV}: {fp}\n"
        ));
        check_measured_escrow(&doc, &hash(&doc), &escrow(R, Some(&fp.to_uppercase()))).unwrap();
        // No pin yet (before the ceremony): only the recipients.
        let doc = app_compose(&format!("      - {RECIPIENTS_ENV}={R}\n"));
        check_measured_escrow(&doc, &hash(&doc), &escrow(R, None)).unwrap();
    }

    #[test]
    fn escrow_values_from_anywhere_but_the_measured_compose_are_refused() {
        let fp = "b".repeat(64);
        let cases = [
            // Recipients from the encrypted env (interpolated or passed through).
            (
                format!("      {RECIPIENTS_ENV}: ${{RECIPIENTS}}\n"),
                escrow(R, None),
                "literal",
            ),
            (
                format!("      - {RECIPIENTS_ENV}\n"),
                escrow(R, None),
                "literal",
            ),
            // Configured, but not in the compose at all (env file, config file).
            ("      A: '1'\n".to_string(), escrow(R, None), "literal"),
            // The compose names other holders than the node uses.
            (
                format!("      {RECIPIENTS_ENV}: '{}'\n", R.replace("sam", "eve")),
                escrow(R, None),
                "differ",
            ),
            // A pin from the environment, or a different one.
            (
                format!("      {RECIPIENTS_ENV}: '{R}'\n"),
                escrow(R, Some(&fp)),
                "verified_fp must be set",
            ),
            (
                format!(
                    "      {RECIPIENTS_ENV}: '{R}'\n      {VERIFIED_FP_ENV}: {}\n",
                    "c".repeat(64)
                ),
                escrow(R, Some(&fp)),
                "differs",
            ),
            (
                format!("      {RECIPIENTS_ENV}: '{R}'\n      {VERIFIED_FP_ENV}: {fp}\n"),
                escrow(R, None),
                "no at_rest.escrow.verified_fp",
            ),
        ];
        for (env, config, needle) in cases {
            let doc = app_compose(&env);
            let err = format!(
                "{:#}",
                check_measured_escrow(&doc, &hash(&doc), &config).unwrap_err()
            );
            assert!(err.contains(needle), "{env:?}: {err}");
        }
        // An app-compose that isn't the measured one.
        let doc = app_compose(&format!("      {RECIPIENTS_ENV}: '{R}'\n"));
        let err = check_measured_escrow(&doc, &"0".repeat(64), &escrow(R, None)).unwrap_err();
        assert!(err.to_string().contains("measured compose_hash"), "{err}");
    }

    #[test]
    fn a_tee_node_refuses_to_start_without_a_readable_measured_compose() {
        let doc = app_compose(&format!("      {RECIPIENTS_ENV}: '{R}'\n"));
        let tee = TeeContext {
            app_id: "a".into(),
            compose_hash: hash(&doc),
            instance_id: "i".into(),
            enforcer_did: "did:key:z".into(),
        };
        // The guest agent's Info had no tcb_info.app_compose, or it isn't
        // an app-compose at all: never start without the check.
        for app_compose in [
            Err(anyhow::anyhow!("dstack Info has no tcb_info")),
            Ok("not json".to_string()),
        ] {
            let err = format!(
                "{:#}",
                check_tee_escrow(app_compose, &tee, &escrow(R, None)).unwrap_err()
            );
            assert!(err.starts_with("refusing to start"), "{err}");
        }
        // Readable and matching: the boot may continue.
        check_tee_escrow(Ok(doc), &tee, &escrow(R, None)).unwrap();
    }

    #[test]
    fn an_unreadable_dstack_info_refuses_at_rest_instead_of_booting_as_non_tee() {
        let info_error = anyhow::anyhow!("dstack Info request: connection reset");
        let configured = [
            AtRestConfig {
                mode: AtRestMode::Encrypt,
                ..Default::default()
            },
            AtRestConfig {
                escrow: escrow(R, None),
                ..Default::default()
            },
            AtRestConfig {
                escrow_none: true,
                ..Default::default()
            },
        ];
        for config in configured {
            let err = refuse_unknown_tee(&config, &info_error)
                .unwrap_err()
                .to_string();
            assert!(err.starts_with("refusing to start"), "{err}");
        }
        // Nothing at rest configured: the node keeps its old behaviour.
        refuse_unknown_tee(&AtRestConfig::default(), &info_error).unwrap();
    }

    #[test]
    fn the_share_failure_limiter_stays_bounded_and_fast() {
        let limiter = ShareFailureLimiter::new();
        let one: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..ShareFailureLimiter::BURST as usize {
            assert!(limiter.allows(one));
            limiter.record_failure(one);
        }
        assert!(!limiter.allows(one));
        // 100k distinct clients: O(1) each, and the map never grows past
        // its cap (the review measured 10 s per 10k with the old map).
        let started = std::time::Instant::now();
        for i in 0..100_000u32 {
            limiter.record_failure(std::net::IpAddr::from(i.to_be_bytes()));
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(
            limiter.clients.lock().len(),
            ShareFailureLimiter::MAX_CLIENTS
        );
    }
}
