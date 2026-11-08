//! Node wiring for encryption at rest (TC-887 S1): config → keyring, the
//! boot-time escrow gate, and the runtime state the routes use.
//!
//! Two phases, because block storage opens before migrations and the
//! keyring needs its tables: [`AtRestRuntime::new`] before storage, then
//! [`setup`] after migrations installs the keyring.
//!
//! In this build no storage seals anything yet: nothing calls
//! [`AtRestRuntime::declare_seal_path`], so `setup` refuses every mode
//! but `off` and `encrypting()` is always false.
//!
//! With the default config (`mode = "off"`, `root_source = "escrow"`, no
//! recipients, no `escrow_none`) nothing is set up: no key reads, no rows, no
//! mirror.
//!
//! The root that seals the at-rest root key (ARK) is the node's own root
//! (`root_source = "escrow"`, with the escrow gate) or a 32-byte key from
//! [`ROOT_KEY_ENV`] (`root_source = "env"`, no escrow). Either way the ARK
//! and everything below it are the same, so moving between them re-seals
//! the ARK rows ([`PREVIOUS_ROOT_KEY_ENV`]) and rewrites no data.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, ensure, Context, Result};
use sha2::Digest as _;
use tinycloud_at_rest_escrow::compose::{AppCompose, EnvSetting, RECIPIENTS_ENV, VERIFIED_FP_ENV};
use tinycloud_at_rest_escrow::{Efp, HolderRecipient, RecipientPolicy};
use tinycloud_core::{
    at_rest::{
        keyring::{GatePass, GateRefusal},
        AtRestKeyring, AtRestSource, AtRestStore, AtRestView, DataKeyProvider, KeyMirror,
        KeyringConfig, KeyringState,
    },
    storage::either::Either,
    RecoveringConnection,
};
use zeroize::Zeroizing;

use crate::config::{AtRestConfig, AtRestEscrowConfig, AtRestMode, AtRestRootSource, Storage};
use crate::dstack::MeasuredInfo;
use crate::storage::at_rest_mirror::{FsKeyMirror, S3KeyMirror};
use crate::tee::TeeContext;

/// The at-rest root when `root_source = "env"`: 32 bytes, standard base64.
pub const ROOT_KEY_ENV: &str = "TINYCLOUD_AT_REST_ROOT_KEY";
/// The root the stored ARK rows were sealed under before a root change. The
/// node re-seals them under the current root at boot; remove it afterwards.
pub const PREVIOUS_ROOT_KEY_ENV: &str = "TINYCLOUD_AT_REST_PREVIOUS_ROOT_KEY";
/// In a TEE, `root_source = "env"` must be this literal in the measured compose.
pub const ROOT_SOURCE_ENV: &str = "TINYCLOUD_AT_REST__ROOT_SOURCE";
/// The variable that gives a dstack CVM SSH authorized keys.
const SSH_KEYS_ENV: &str = "DSTACK_AUTHORIZED_KEYS";
/// dstack production (not dev) OS images a TEE node may use
/// `root_source = "env"` on: `dstack-0.5.12`, as pinned by the deploy
/// (`PHALA_OS_IMAGE_HASH` in `.github/workflows/docker.yml`). Moving to
/// another OS image adds its hash here in a node release first.
pub const PRODUCTION_OS_IMAGE_HASHES: &[&str] =
    &["8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd"];

/// Whether this build's storage seals every write when at-rest is set up:
/// both KV block storage and SQL artifacts ([`SealPath`]). `--validate-config`
/// decides the seal-path refusal from this; startup checks that the seal
/// paths storage actually declared agree with it.
pub const STORAGE_SEALS_EVERY_WRITE: bool = false;

/// The root variables as read from the process environment, held only in
/// zeroizing buffers. Debug is redacted.
#[derive(Default)]
pub struct RootEnv {
    current: Option<Zeroizing<String>>,
    previous: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for RootEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootEnv")
            .field("current", &self.current.is_some())
            .field("previous", &self.previous.is_some())
            .finish()
    }
}

/// [`RootEnv::take`] in `main`, before the config loader and any other
/// thread start; the node takes it from here at boot.
static STASHED_ROOT_ENV: std::sync::Mutex<Option<RootEnv>> = std::sync::Mutex::new(None);

impl RootEnv {
    /// Explicit values (tests, and callers that already hold them).
    pub fn new(current: Option<Zeroizing<String>>, previous: Option<Zeroizing<String>>) -> Self {
        Self { current, previous }
    }

    /// Takes [`ROOT_KEY_ENV`] and [`PREVIOUS_ROOT_KEY_ENV`] out of the process
    /// environment: copies each value into a zeroizing buffer, overwrites the
    /// environment's own bytes, and unsets the variable, so neither the
    /// config loader nor `/proc/<pid>/environ` sees it again. With either set,
    /// it also turns core dumps off for the process (Linux: not dumpable,
    /// core size limit 0), and refuses if that fails.
    ///
    /// Call it before other threads run where possible (`main` does): it
    /// writes the environment.
    pub fn take() -> Result<Self> {
        let env = Self {
            current: take_var(ROOT_KEY_ENV),
            previous: take_var(PREVIOUS_ROOT_KEY_ENV),
        };
        if env.current.is_some() || env.previous.is_some() {
            disable_core_dumps()?;
        }
        Ok(env)
    }

    /// Keeps `self` for [`Self::for_boot`].
    pub fn stash(self) {
        *STASHED_ROOT_ENV.lock().unwrap_or_else(|p| p.into_inner()) = Some(self);
    }

    /// The stashed root variables if `main` took them, else [`Self::take`].
    pub fn for_boot() -> Result<Self> {
        match STASHED_ROOT_ENV
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            Some(env) => Ok(env),
            None => Self::take(),
        }
    }
}

fn take_var(name: &str) -> Option<Zeroizing<String>> {
    use std::os::unix::ffi::OsStringExt as _;
    let raw = Zeroizing::new(std::env::var_os(name)?.into_vec());
    // The environment block holds its own copy: overwrite it, then unset.
    if let Ok(c_name) = std::ffi::CString::new(name) {
        // SAFETY: getenv returns NUL-terminated memory owned by the
        // environment; we only overwrite the value's own bytes before
        // unsetting it. `main` calls this before other threads start.
        unsafe {
            let value = libc::getenv(c_name.as_ptr());
            if !value.is_null() {
                std::ptr::write_bytes(value, 0, libc::strlen(value));
            }
        }
    }
    std::env::remove_var(name);
    // A value that isn't UTF-8 isn't a key; keep a stand-in that fails to
    // parse rather than a lossy copy of the bytes.
    let mut value = Zeroizing::new(String::new());
    match std::str::from_utf8(&raw) {
        Ok(text) => value.push_str(text),
        Err(_) => value.push('\u{fffd}'),
    }
    Some(value)
}

fn disable_core_dumps() -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: plain syscalls on this process with valid arguments.
    unsafe {
        ensure!(
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0,
            "could not turn off core dumps (prctl PR_SET_DUMPABLE)"
        );
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        ensure!(
            libc::setrlimit(libc::RLIMIT_CORE, &none) == 0,
            "could not turn off core dumps (RLIMIT_CORE)"
        );
    }
    Ok(())
}

/// An operator-supplied at-rest root: exactly 32 bytes. Debug is redacted;
/// only [`Self::fingerprint`] is ever logged.
pub struct RootKey(Zeroizing<[u8; 32]>);

impl RootKey {
    /// Standard base64 with padding (44 characters, canonical) of 32 bytes.
    /// A trailing newline is ignored; anything else is refused, as is a key
    /// of one repeated byte (a placeholder, not a key). Decoding and the
    /// canonical check use fixed zeroizing buffers, no heap copies.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value
            .strip_suffix("\r\n")
            .or_else(|| value.strip_suffix('\n'))
            .unwrap_or(value);
        ensure!(
            value.len() == 44,
            "must be the standard base64 of exactly 32 bytes (44 characters)"
        );
        // 44 characters decode to at most 33 bytes.
        let mut decoded = Zeroizing::new([0u8; 33]);
        let len = base64::decode_config_slice(value, base64::STANDARD, &mut decoded[..])
            .map_err(|_| anyhow!("is not standard base64"))?;
        ensure!(len == 32, "does not decode to exactly 32 bytes");
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&decoded[..32]);
        let mut encoded = Zeroizing::new([0u8; 44]);
        base64::encode_config_slice(key.as_slice(), base64::STANDARD, &mut encoded[..]);
        ensure!(
            encoded.as_slice() == value.as_bytes(),
            "is not canonical standard base64"
        );
        ensure!(
            key.iter().any(|b| *b != key[0]),
            "is one repeated byte, not a key"
        );
        Ok(Self(key))
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// `hex(SHA-256("tinycloud/at-rest/root-fingerprint/v1" ‖ key))[..16]`:
    /// names the key in logs and `/at-rest/status`, and can be computed
    /// offline (`(printf '<label>'; base64 -d) | sha256sum`). It identifies a
    /// key, it doesn't authenticate one, and equal fingerprints show that
    /// two deployments share a root.
    pub fn fingerprint(&self) -> String {
        let mut h = sha2::Sha256::new();
        h.update(b"tinycloud/at-rest/root-fingerprint/v1");
        h.update(self.bytes());
        hex::encode(h.finalize())[..16].to_string()
    }
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RootKey({})", self.fingerprint())
    }
}

/// The at-rest roots for this boot, from config and the environment.
#[derive(Debug)]
pub struct Roots {
    /// `Some` for `root_source = "env"`; otherwise the node root is used.
    pub env: Option<RootKey>,
    pub previous: Option<RootKey>,
}

impl Roots {
    /// Parses the root variables taken by [`RootEnv::take`].
    /// Refuses: `root_source = "env"` without a valid key; a malformed value
    /// (never ignored); a root key with `root_source = "escrow"`; a previous
    /// root equal to the current one.
    pub fn read(config: &AtRestConfig, node_root: &[u8], env: &RootEnv) -> Result<Self> {
        let read = |name: &str, value: &Option<Zeroizing<String>>| -> Result<Option<RootKey>> {
            value
                .as_ref()
                .map(|v| RootKey::parse(v).with_context(|| format!("{name} is invalid")))
                .transpose()
        };
        let current = read(ROOT_KEY_ENV, &env.current)?;
        let previous = read(PREVIOUS_ROOT_KEY_ENV, &env.previous)?;
        let env_root = match (config.root_source, current) {
            (AtRestRootSource::Env, Some(key)) => Some(key),
            (AtRestRootSource::Env, None) => {
                bail!("at_rest.root_source = \"env\" needs {ROOT_KEY_ENV}: the standard base64 of 32 bytes")
            }
            (AtRestRootSource::Escrow, Some(_)) => bail!(
                "{ROOT_KEY_ENV} is set but at_rest.root_source is \"escrow\"; set root_source = \"env\", or pass the key as {PREVIOUS_ROOT_KEY_ENV} to re-seal under the node root"
            ),
            (AtRestRootSource::Escrow, None) => None,
        };
        let roots = Self {
            env: env_root,
            previous,
        };
        if let Some(previous) = &roots.previous {
            ensure!(
                previous.bytes() != roots.root(node_root),
                "{PREVIOUS_ROOT_KEY_ENV} is the current at-rest root; remove it"
            );
        }
        Ok(roots)
    }

    /// The root the keyring seals the ARK under.
    pub fn root<'a>(&'a self, node_root: &'a [u8]) -> &'a [u8] {
        self.env.as_ref().map_or(node_root, RootKey::bytes)
    }
}

/// Whether, and why, the node is meant to run in a dstack TEE, and whether
/// its guest agent answered.
#[derive(Debug, Clone, Copy)]
pub struct TeeState<'a> {
    /// What indicates a TEE (TEE mode, key type, a socket), if anything.
    pub indicated: Option<&'a str>,
    /// The guest agent's Info was read (the node has a TEE context).
    pub present: bool,
}

/// The at-rest checks that need no key store, database, block store or
/// guest-agent measurement. Startup runs them before opening the keyring,
/// and `--validate-config` runs the same function, so the preflight refuses
/// whatever these refuse at boot. `storage_seals`: whether storage seals
/// every write (startup: the declared seal paths; validation:
/// [`STORAGE_SEALS_EVERY_WRITE`]).
pub fn check_config(
    config: &AtRestConfig,
    roots: &Roots,
    storage_seals: bool,
    tee: TeeState<'_>,
) -> Result<()> {
    let escrow = &config.escrow;
    if !enabled(config) {
        ensure!(
            roots.previous.is_none(),
            "{PREVIOUS_ROOT_KEY_ENV} is set but at-rest is not configured; remove it"
        );
        return Ok(());
    }
    if config.mode != AtRestMode::Off && !storage_seals {
        bail!(
            "at_rest.mode = \"{}\" is refused: this build's storage has no at-rest seal path, so nothing would be encrypted; use mode = \"off\"",
            mode_name(config.mode)
        );
    }
    if config.escrow_none && !escrow.recipients.is_empty() {
        bail!("set at_rest.escrow.recipients or at_rest.escrow_none, not both");
    }
    if config.root_source == AtRestRootSource::Env
        && (config.escrow_none || *escrow != AtRestEscrowConfig::default())
    {
        bail!("at_rest.root_source = \"env\" has no escrow: remove at_rest.escrow and at_rest.escrow_none");
    }
    if let (Some(hint), false) = (tee.indicated, tee.present) {
        bail!(
            "refusing to start: {hint} indicates a dstack TEE, but its guest agent's Info is not available here, so the at-rest TEE checks can't run (they run at boot inside the TEE)"
        );
    }
    if tee.present && config.escrow_none {
        bail!("at_rest.escrow_none is only for self-hosted Static-root nodes; a TEE node must escrow its key");
    }
    if tee.present && escrow.allow_software {
        bail!("at_rest.escrow.allow_software is refused inside a TEE: escrow holders must use hardware keys");
    }
    Ok(())
}

fn mode_name(mode: AtRestMode) -> &'static str {
    match mode {
        AtRestMode::Off => "off",
        AtRestMode::Encrypt => "encrypt",
        AtRestMode::Strict => "strict",
    }
}

/// The storage that must seal its writes before a mode other than `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealPath {
    /// KV block storage (S3 or the file system).
    Blocks,
    /// SQL and DuckDB artifacts (`database_artifact`).
    SqlArtifacts,
}

/// At-rest state shared by the routes and `/info` (and, once it seals
/// writes, block storage). Rocket manages it as `Arc<AtRestRuntime>`.
///
/// The contract for the storage seal path (TC-887 S3), not yet wired: mode
/// `off` behaves exactly as without at-rest. Otherwise writes are sealed
/// only while [`encrypting`](Self::encrypting) (else 503, never plaintext);
/// a sealed read whose key is `Locked` is a 503; legacy plaintext reads are
/// allowed unless the mode is `strict`.
pub struct AtRestRuntime {
    mode: AtRestMode,
    escrow_none: bool,
    root_source: AtRestRootSource,
    /// Set at boot for `root_source = "env"`.
    root_fingerprint: OnceLock<String>,
    keyring: OnceLock<Arc<AtRestKeyring>>,
    /// The gate passed for a non-`off` mode and the keys are unlocked: new
    /// writes may be encrypted. Set at boot, or after a recovery unlocks a
    /// node whose gate then passes.
    encrypting: AtomicBool,
    /// Set by block storage and by the SQL artifact store when each seals
    /// its writes. Until both are set a mode other than `off` is refused at
    /// boot and `encrypting` stays false.
    blocks_seal: AtomicBool,
    sql_seal: AtomicBool,
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
            root_source: config.root_source,
            root_fingerprint: OnceLock::new(),
            keyring: OnceLock::new(),
            encrypting: AtomicBool::new(false),
            blocks_seal: AtomicBool::new(false),
            sql_seal: AtomicBool::new(false),
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

    /// Block storage and the SQL artifact store each call this when they
    /// open with a seal path for every write. Until both have, `setup`
    /// refuses any mode other than `off`, so the node never claims to
    /// encrypt while some storage writes plaintext.
    pub fn declare_seal_path(&self, path: SealPath) {
        match path {
            SealPath::Blocks => &self.blocks_seal,
            SealPath::SqlArtifacts => &self.sql_seal,
        }
        .store(true, Ordering::SeqCst);
    }

    pub fn has_seal_path(&self) -> bool {
        self.blocks_seal.load(Ordering::SeqCst) && self.sql_seal.load(Ordering::SeqCst)
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
    /// non-`off` mode can turn encryption on. With `root_source = "env"`
    /// there is no escrow by design, so the gate needs only unlocked keys.
    pub async fn reevaluate(&self) -> Result<GatePass, GateRefusal> {
        let Some(keyring) = self.keyring.get() else {
            return Err(GateRefusal::NotProvisioned);
        };
        let unescrowed = self.escrow_none || self.root_source == AtRestRootSource::Env;
        let result = keyring.gate(unescrowed).await;
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

    pub fn root_source_name(&self) -> &'static str {
        match self.root_source {
            AtRestRootSource::Escrow => "escrow",
            AtRestRootSource::Env => "env",
        }
    }

    /// [`RootKey::fingerprint`] of the env root, for `root_source = "env"`.
    pub fn root_fingerprint(&self) -> Option<&str> {
        self.root_fingerprint.get().map(String::as_str)
    }
}

impl AtRestSource for AtRestRuntime {
    fn view(&self) -> AtRestView {
        AtRestView {
            mode: self.mode,
            encrypting: self.encrypting(),
            provider: self.provider(),
        }
    }
}

/// Phase two, after migrations ran: open the keyring and run the gate.
/// `node_root` is the node's own root; the env roots come from `root_env`
/// ([`RootEnv::take`]); `tee_indicated` is what marks this host as a dstack
/// TEE, if anything.
///
/// Refuses (an error, so the node does not start):
/// - everything [`check_config`] refuses (the same checks as
///   `--validate-config`), with the seal paths storage declared
///   ([`AtRestRuntime::declare_seal_path`]);
/// - a missing, malformed or misplaced root key ([`Roots::read`]);
/// - in a TEE, escrow recipients or a pin that are not literal values in
///   the measured compose ([`check_measured_escrow`]), and for
///   `root_source = "env"` the checks in [`check_tee_env_root`];
/// - `encrypt` or `strict` when the keys are unlocked but the gate fails;
/// - `root_source = "env"` when the key doesn't open the stored keys: there
///   is no escrow to recover with.
///
/// An escrow node that boots **locked** starts anyway, with encryption
/// unavailable, so two holders can recover it.
#[allow(clippy::too_many_arguments)]
pub async fn setup(
    runtime: &AtRestRuntime,
    config: &AtRestConfig,
    storage: &Storage,
    node_root: &[u8],
    root_env: &RootEnv,
    db: RecoveringConnection,
    sqlite_writer_lock: Option<Arc<tokio::sync::Mutex<()>>>,
    tee: Option<&TeeContext>,
    tee_indicated: Option<&str>,
) -> Result<()> {
    let escrow = &config.escrow;
    let roots = Roots::read(config, node_root, root_env)?;
    ensure!(
        runtime.has_seal_path() == STORAGE_SEALS_EVERY_WRITE,
        "at-rest: the seal paths storage declared don't match this build (STORAGE_SEALS_EVERY_WRITE)"
    );
    check_config(
        config,
        &roots,
        runtime.has_seal_path(),
        TeeState {
            indicated: tee_indicated,
            present: tee.is_some(),
        },
    )?;
    if !enabled(config) {
        return Ok(());
    }
    // In a TEE every at-rest configuration is checked against the measured
    // compose and, for an env root, the OS image.
    if let Some(tee) = tee {
        let measured = crate::dstack::get_measured_info()
            .await
            .context("refusing to start: at-rest needs the guest agent's Info")?;
        match config.root_source {
            AtRestRootSource::Escrow => check_tee_escrow(measured.app_compose, tee, escrow)?,
            AtRestRootSource::Env => check_tee_env_root(measured, tee)?,
        }
    }
    if let Some(key) = &roots.env {
        let fingerprint = key.fingerprint();
        ::tracing::info!(root_fingerprint = %fingerprint, "at-rest root from the environment");
        let _ = runtime.root_fingerprint.set(fingerprint);
    }
    if let Some(previous) = &roots.previous {
        ::tracing::warn!(
            previous_root_fingerprint = %previous.fingerprint(),
            "a previous at-rest root is set; keys sealed under it are re-sealed under the current root"
        );
    }
    let pinned_efp = escrow.verified_fp.as_deref().map(parse_efp).transpose()?;
    let mirror: Arc<dyn KeyMirror> = match &storage.blocks {
        Either::A(s3) => Arc::new(S3KeyMirror::new(s3).await),
        Either::B(_) => Arc::new(FsKeyMirror::new(storage.datadir.join("at-rest"))),
    };
    let keyring = AtRestKeyring::open_with_previous_root(
        AtRestStore::new(db).with_sqlite_writer_lock(sqlite_writer_lock),
        mirror,
        roots.root(node_root),
        roots.previous.as_ref().map(RootKey::bytes),
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
    let env_root = config.root_source == AtRestRootSource::Env;
    match runtime.keyring().map(|k| k.state()) {
        Some(KeyringState::Unlocked) => {
            let gate = runtime.reevaluate().await;
            match (config.mode, gate) {
                (AtRestMode::Off, Ok(GatePass::Verified { .. })) => {
                    ::tracing::info!("at-rest keys unlocked; escrow verified; mode off")
                }
                (AtRestMode::Off, Ok(GatePass::Unescrowed)) if env_root => {
                    ::tracing::info!("at-rest keys unlocked; root from the environment; mode off")
                }
                (AtRestMode::Off, Ok(GatePass::Unescrowed)) => ::tracing::info!(
                    "at-rest keys unlocked; no escrow (escrow_none acknowledged); mode off"
                ),
                (AtRestMode::Off, Err(refusal)) => ::tracing::warn!(
                    reason = %refusal,
                    "at-rest keys unlocked; the escrow gate is not satisfied yet"
                ),
                (mode, Ok(_)) => {
                    ::tracing::info!(
                        ?mode,
                        root_source = runtime.root_source_name(),
                        "at-rest encryption enabled"
                    );
                    if tee.is_none() {
                        ::tracing::warn!(
                            "at-rest encryption seals KV blocks and SQL artifacts in external storage; local working, cache, staging and export files stay plaintext on this host (no TEE): protect the data directory, swap and file backups"
                        );
                    }
                }
                (mode, Err(refusal)) => {
                    bail!("at_rest.mode = {mode:?} is refused: {refusal}")
                }
            }
        }
        Some(KeyringState::Locked) if env_root => bail!(
            "refusing to start: the at-rest root from {ROOT_KEY_ENV} (fingerprint {}) does not open the stored at-rest keys; set the root they were sealed under, or pass it as {PREVIOUS_ROOT_KEY_ENV} to re-seal them",
            runtime.root_fingerprint().unwrap_or("?")
        ),
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
    config.mode != AtRestMode::Off
        || config.root_source == AtRestRootSource::Env
        || !config.escrow.recipients.is_empty()
        || config.escrow_none
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
    let compose = measured_compose(app_compose, compose_hash)?;
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

/// `app_compose` parsed, after checking it is the measured one.
fn measured_compose(app_compose: &str, compose_hash: &str) -> Result<AppCompose> {
    let digest = hex::encode(sha2::Sha256::digest(app_compose.as_bytes()));
    ensure!(
        digest.eq_ignore_ascii_case(compose_hash.trim()),
        "the app-compose the guest agent reports hashes to {digest}, not the measured compose_hash {compose_hash}"
    );
    AppCompose::parse(app_compose.as_bytes()).context("reading the measured app-compose")
}

/// The TEE boot check for `root_source = "env"`. Refuses to start unless:
/// - the measured compose sets [`ROOT_SOURCE_ENV`] to the literal `env`, so
///   the attested compose shows that the at-rest root comes from the
///   environment;
/// - every setting of either root key, in every service, is exactly one
///   plain reference to a variable of the encrypted environment (`${NAME}`,
///   or `${NAME:?message}` / `${NAME?message}`, which fail when unset): never
///   a literal, a default or alternate value, a pass-through or anything
///   else docker compose would expand (the compose is public);
/// - the measured app-compose does not allow [`SSH_KEYS_ENV`] (SSH into the
///   CVM would expose the key);
/// - the guest agent reports a production OS image
///   ([`PRODUCTION_OS_IMAGE_HASHES`]), not a dev image.
pub fn check_tee_env_root(measured: MeasuredInfo, tee: &TeeContext) -> Result<()> {
    let app_compose = measured.app_compose.context(
        "refusing to start: at-rest needs the measured app-compose (dstack Info tcb_info.app_compose), and it could not be read",
    )?;
    check_measured_env_root(&app_compose, &tee.compose_hash)
        .context("refusing to start: at_rest.root_source = \"env\" is not allowed by the measured app-compose")?;
    let os_image_hash = measured.os_image_hash.context(
        "refusing to start: at_rest.root_source = \"env\" needs the OS image hash from dstack Info",
    )?;
    ensure!(
        PRODUCTION_OS_IMAGE_HASHES.contains(&os_image_hash.as_str()),
        "refusing to start: at_rest.root_source = \"env\" runs only on a production dstack OS image; this CVM runs OS image {os_image_hash}"
    );
    Ok(())
}

/// The compose part of [`check_tee_env_root`].
pub fn check_measured_env_root(app_compose: &str, compose_hash: &str) -> Result<()> {
    let compose = measured_compose(app_compose, compose_hash)?;
    match compose.literal_env(ROOT_SOURCE_ENV) {
        Ok(Some(source)) if source == "env" => {}
        _ => bail!("the measured compose must set {ROOT_SOURCE_ENV} to the literal value env"),
    }
    for key in [ROOT_KEY_ENV, PREVIOUS_ROOT_KEY_ENV] {
        // A compose this reader can't read is refused, never assumed safe.
        for setting in compose.env_settings(key).with_context(|| {
            format!("{key}: the measured compose's environment could not be read")
        })? {
            let plain = match &setting {
                EnvSetting::Value { value, .. } => is_plain_env_reference(value),
                EnvSetting::FromRuntime { .. } => false,
            };
            // The message never quotes the value: it may hold a key.
            ensure!(
                plain,
                "service {:?} must set {key} to a plain reference to the encrypted environment (${{NAME}}); it must come from the encrypted environment, not a literal, a default or a pass-through in the compose",
                setting.service()
            );
        }
    }
    let doc: serde_json::Value = serde_json::from_str(app_compose)?;
    let allows_ssh = doc
        .get("allowed_envs")
        .and_then(|v| v.as_array())
        .is_some_and(|names| names.iter().any(|n| n.as_str() == Some(SSH_KEYS_ENV)));
    ensure!(
        !allows_ssh,
        "the measured app-compose allows {SSH_KEYS_ENV} (SSH into the CVM)"
    );
    Ok(())
}

/// `${NAME}`, `${NAME:?message}` or `${NAME?message}` and nothing else: one
/// braced reference to a variable name, with at most an error message for
/// when it is unset (the message can't expand anything).
fn is_plain_env_reference(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };
    let name_len = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    let (name, rest) = inner.split_at(name_len);
    let valid_name = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let message = rest.strip_prefix(":?").or_else(|| rest.strip_prefix('?'));
    valid_name
        && match message {
            None => rest.is_empty(),
            Some(message) => !message.contains(['$', '{', '}']),
        }
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

    /// The standard base64 of bytes 0..32.
    fn key_b64(offset: u8) -> String {
        let bytes: Vec<u8> = (0..32u8).map(|b| b.wrapping_add(offset)).collect();
        base64::encode_config(bytes, base64::STANDARD)
    }

    fn env_config() -> AtRestConfig {
        AtRestConfig {
            root_source: AtRestRootSource::Env,
            ..Default::default()
        }
    }

    #[test]
    fn a_root_key_is_exactly_32_bytes_of_canonical_standard_base64() {
        let good = key_b64(0);
        let key = RootKey::parse(&good).unwrap();
        assert_eq!(key.bytes(), (0..32u8).collect::<Vec<_>>().as_slice());
        assert_eq!(key.fingerprint().len(), 16);
        assert_eq!(
            RootKey::parse(&format!("{good}\n")).unwrap().fingerprint(),
            key.fingerprint()
        );
        let mut url_bytes = [0xfb; 32];
        url_bytes[31] = 1;
        let url_safe = base64::encode_config(url_bytes, base64::URL_SAFE);
        let bad = [
            String::new(),
            format!(" {good}"),
            format!("{good}\n\n"),
            good.trim_end_matches('=').to_string(),
            base64::encode_config([7u8; 31], base64::STANDARD),
            base64::encode_config([7u8; 33], base64::STANDARD),
            base64::encode_config([7u8; 32], base64::STANDARD),
            url_safe,
            format!("{}B=", &good[..42]),
        ];
        for value in bad {
            let err = format!("{:#}", RootKey::parse(&value).unwrap_err());
            if !value.is_empty() {
                assert!(!err.contains(value.trim()), "error echoes the value: {err}");
            }
        }
        assert!(!format!("{key:?}").contains(&good));
    }

    #[test]
    fn roots_refuse_a_missing_misplaced_or_malformed_key() {
        let node_root = [5u8; 64];
        let env = |pairs: Vec<(&'static str, String)>| {
            let get = |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| Zeroizing::new(v.clone()))
            };
            RootEnv::new(get(ROOT_KEY_ENV), get(PREVIOUS_ROOT_KEY_ENV))
        };
        let roots = Roots::read(
            &env_config(),
            &node_root,
            &env(vec![(ROOT_KEY_ENV, key_b64(0))]),
        )
        .unwrap();
        assert_eq!(
            roots.root(&node_root),
            RootKey::parse(&key_b64(0)).unwrap().bytes()
        );
        let roots = Roots::read(&AtRestConfig::default(), &node_root, &env(vec![])).unwrap();
        assert_eq!(roots.root(&node_root), &node_root[..]);

        let refused = [
            (env_config(), vec![]),
            (env_config(), vec![(ROOT_KEY_ENV, "not a key".to_string())]),
            (AtRestConfig::default(), vec![(ROOT_KEY_ENV, key_b64(0))]),
            (
                env_config(),
                vec![
                    (ROOT_KEY_ENV, key_b64(0)),
                    (PREVIOUS_ROOT_KEY_ENV, "x".to_string()),
                ],
            ),
            (
                env_config(),
                vec![
                    (ROOT_KEY_ENV, key_b64(0)),
                    (PREVIOUS_ROOT_KEY_ENV, key_b64(0)),
                ],
            ),
        ];
        for (config, pairs) in refused {
            let shown = format!("{pairs:?}");
            assert!(
                Roots::read(&config, &node_root, &env(pairs)).is_err(),
                "{shown}"
            );
        }
        // Moving from an env root to the node root: the env key becomes the
        // previous root.
        let roots = Roots::read(
            &AtRestConfig::default(),
            &node_root,
            &env(vec![(PREVIOUS_ROOT_KEY_ENV, key_b64(0))]),
        )
        .unwrap();
        assert_eq!(roots.root(&node_root), &node_root[..]);
        assert!(roots.previous.is_some());
    }

    fn env_root_compose(env: &str, allowed_envs: &[&str]) -> String {
        let digest = "a".repeat(64);
        serde_json::to_string(&serde_json::json!({
            "manifest_version": 2,
            "runner": "docker-compose",
            "allowed_envs": allowed_envs,
            "docker_compose_file": format!(
                "services:\n  tinycloud:\n    image: n@sha256:{digest}\n    environment:\n{env}"
            ),
        }))
        .unwrap()
    }

    /// An app-compose with the `tinycloud` service (environment `env`) and an
    /// optional second service (environment `other_env`).
    fn two_service_compose(env: &str, other_env: Option<&str>) -> String {
        let digest = "a".repeat(64);
        let other = other_env.map_or(String::new(), |e| {
            format!("  other:\n    image: o@sha256:{digest}\n    environment:\n{e}")
        });
        serde_json::to_string(&serde_json::json!({
            "manifest_version": 2,
            "runner": "docker-compose",
            "allowed_envs": ["K", "P"],
            "docker_compose_file": format!(
                "services:\n  tinycloud:\n    image: n@sha256:{digest}\n    environment:\n{env}{other}"
            ),
        }))
        .unwrap()
    }

    #[test]
    fn a_root_key_in_the_compose_is_only_ever_a_plain_reference_to_the_encrypted_env() {
        let source = format!("      {ROOT_SOURCE_ENV}: env\n");
        // Throwaway values, never real keys.
        let (k, p) = (key_b64(11), key_b64(12));
        let accepted = [
            format!("{source}      {ROOT_KEY_ENV}: ${{K}}\n"),
            format!("{source}      {ROOT_KEY_ENV}: \"${{K:?seal the key}}\"\n"),
            format!("{source}      {ROOT_KEY_ENV}: ${{K?seal the key}}\n"),
            format!(
                "{source}      {ROOT_KEY_ENV}: ${{K}}\n      {PREVIOUS_ROOT_KEY_ENV}: ${{P}}\n"
            ),
            format!("      - {ROOT_SOURCE_ENV}=env\n      - {ROOT_KEY_ENV}=${{K}}\n"),
        ];
        for env in &accepted {
            let doc = two_service_compose(env, None);
            check_measured_env_root(&doc, &hash(&doc)).unwrap_or_else(|e| panic!("{env:?}: {e:#}"));
        }
        let refused = [
            // A default publishes the real key in the measured compose.
            (format!("{source}      {ROOT_KEY_ENV}: ${{UNSET:-{k}}}\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}: ${{UNSET-{k}}}\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}: ${{K}}\n      {PREVIOUS_ROOT_KEY_ENV}: ${{UNSET:-{p}}}\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}: ${{K:+{k}}}\n"), None),
            // Not exactly one braced reference.
            (format!("{source}      {ROOT_KEY_ENV}: $K\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}: x${{K}}\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}: ${{K}}${{P}}\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}: ${{K:?${{P}}}}\n"), None),
            // Passed through from the runtime environment, or empty.
            (format!("{source}      - {ROOT_KEY_ENV}\n"), None),
            (format!("{source}      {ROOT_KEY_ENV}:\n"), None),
            // A literal key in a second service.
            (
                format!("{source}      {ROOT_KEY_ENV}: ${{K}}\n"),
                Some(format!("      {ROOT_KEY_ENV}: {k}\n")),
            ),
            (
                format!("{source}      {ROOT_KEY_ENV}: ${{K}}\n"),
                Some(format!("      {PREVIOUS_ROOT_KEY_ENV}: {p}\n")),
            ),
        ];
        for (env, other) in refused {
            let doc = two_service_compose(&env, other.as_deref());
            let err = check_measured_env_root(&doc, &hash(&doc));
            assert!(err.is_err(), "accepted {env:?} / {other:?}");
            let shown = format!("{:#}", err.unwrap_err());
            assert!(
                !shown.contains(&k) && !shown.contains(&p),
                "error shows a key: {shown}"
            );
        }
    }

    #[test]
    fn an_env_root_needs_a_measured_literal_and_no_key_or_ssh_in_the_compose() {
        let source = format!("      {ROOT_SOURCE_ENV}: env\n");
        let key = format!("      {ROOT_KEY_ENV}: ${{AT_REST_ROOT_KEY}}\n");
        let doc = env_root_compose(&format!("{source}{key}"), &["AT_REST_ROOT_KEY"]);
        check_measured_env_root(&doc, &hash(&doc)).unwrap();

        let refused = [
            // Not declared in the measured compose, or not literally.
            (env_root_compose(&key, &[]), "literal value env"),
            (
                env_root_compose(&format!("      {ROOT_SOURCE_ENV}: ${{SOURCE}}\n{key}"), &[]),
                "literal value env",
            ),
            (
                env_root_compose(&format!("      {ROOT_SOURCE_ENV}: escrow\n{key}"), &[]),
                "literal value env",
            ),
            // A key published in the compose.
            (
                env_root_compose(
                    &format!("{source}      {ROOT_KEY_ENV}: {}\n", key_b64(0)),
                    &[],
                ),
                "encrypted environment",
            ),
            (
                env_root_compose(
                    &format!(
                        "{source}{key}      {PREVIOUS_ROOT_KEY_ENV}: {}\n",
                        key_b64(1)
                    ),
                    &[],
                ),
                "encrypted environment",
            ),
            // SSH keys may be provisioned into the CVM.
            (
                env_root_compose(
                    &format!("{source}{key}"),
                    &["AT_REST_ROOT_KEY", "DSTACK_AUTHORIZED_KEYS"],
                ),
                "SSH",
            ),
        ];
        for (doc, needle) in refused {
            let err = format!(
                "{:#}",
                check_measured_env_root(&doc, &hash(&doc)).unwrap_err()
            );
            assert!(err.contains(needle), "{needle}: {err}");
        }
        // Not the measured compose.
        assert!(check_measured_env_root(&doc, &"0".repeat(64)).is_err());
    }

    #[test]
    fn an_env_root_runs_only_on_a_production_os_image() {
        let doc = env_root_compose(
            &format!("      {ROOT_SOURCE_ENV}: env\n      {ROOT_KEY_ENV}: ${{K}}\n"),
            &["K"],
        );
        let tee = TeeContext {
            app_id: "a".into(),
            compose_hash: hash(&doc),
            instance_id: "i".into(),
            enforcer_did: "did:key:z".into(),
        };
        let measured = |os: Result<String>| MeasuredInfo {
            app_compose: Ok(doc.clone()),
            os_image_hash: os,
        };
        check_tee_env_root(measured(Ok(PRODUCTION_OS_IMAGE_HASHES[0].into())), &tee).unwrap();
        // dstack-dev-0.5.12, an unknown image, and no hash at all.
        for os in [
            Ok("e866e987221db357129ebc3f066b6706ef955889ea95e5510acbdf3d3055186b".to_string()),
            Ok("0".repeat(64)),
            Err(anyhow!("dstack Info has no os_image_hash")),
        ] {
            let err = format!("{:#}", check_tee_env_root(measured(os), &tee).unwrap_err());
            assert!(err.starts_with("refusing to start"), "{err}");
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
