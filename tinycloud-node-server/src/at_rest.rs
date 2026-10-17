//! Node wiring for encryption at rest (TC-887 S1): config → keyring, the
//! boot-time encrypt gate, and the runtime state storage and routes use.
//!
//! Two phases, because block storage opens before migrations and the
//! keyring needs its tables: [`AtRestRuntime::new`] before storage (storage
//! keeps the `Arc`), then [`setup`] after migrations installs the keyring.
//!
//! With the default config (`mode = "off"`, no recipients, no
//! `escrow_none`) nothing is set up: no key reads, no rows, no mirror.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context, Result};
use tinycloud_at_rest_escrow::{Efp, RecipientPolicy};
use tinycloud_core::{
    at_rest::{
        keyring::{GatePass, GateRefusal},
        AtRestKeyring, AtRestStore, DataKeyProvider, KeyMirror, KeyringConfig, KeyringState,
    },
    storage::either::Either,
    RecoveringConnection,
};

use crate::config::{AtRestConfig, AtRestMode, Storage};
use crate::storage::at_rest_mirror::{FsKeyMirror, S3KeyMirror};
use crate::tee::TeeContext;

/// At-rest state shared by block storage, the routes and `/info`. Rocket
/// manages it as `Arc<AtRestRuntime>`.
///
/// Storage rules (S3): mode `off` behaves exactly as without at-rest.
/// Otherwise writes are sealed only while [`encrypting`](Self::encrypting)
/// (else 503, never plaintext); a sealed read whose key is `Locked` is a
/// 503; legacy plaintext reads are allowed unless the mode is `strict`.
pub struct AtRestRuntime {
    mode: AtRestMode,
    escrow_none: bool,
    keyring: OnceLock<Arc<AtRestKeyring>>,
    /// The gate passed for a non-`off` mode and the keys are unlocked: new
    /// writes may be encrypted. Set at boot, or after a recovery unlocks a
    /// node whose gate then passes.
    encrypting: AtomicBool,
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
        })
    }

    pub fn mode(&self) -> AtRestMode {
        self.mode
    }

    /// Whether new writes may be sealed now: the gate passed (non-`off`
    /// mode) and the keys are unlocked.
    pub fn encrypting(&self) -> bool {
        self.encrypting.load(Ordering::SeqCst)
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
        let on = self.mode != AtRestMode::Off && result.is_ok();
        self.encrypting.store(on, Ordering::SeqCst);
        result
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
/// Refuses (an error, so the node does not start) when `mode` is `encrypt`
/// or `strict` and the keys are unlocked but the escrow gate fails. A node
/// that boots **locked** starts anyway, with encryption unavailable, so two
/// holders can recover it.
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
    let enabled =
        config.mode != AtRestMode::Off || !escrow.recipients.is_empty() || config.escrow_none;
    if !enabled {
        return Ok(());
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
    let pinned_efp = escrow
        .verified_fp
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase().parse::<Efp>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("at_rest.escrow.verified_fp must be 64 hex characters"))?;
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
                (AtRestMode::Off, Ok(_)) => {
                    ::tracing::info!("at-rest keys unlocked; escrow verified; mode off")
                }
                (AtRestMode::Off, Err(refusal)) => ::tracing::warn!(
                    reason = %refusal,
                    "at-rest keys unlocked; encryption could not be enabled yet"
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
