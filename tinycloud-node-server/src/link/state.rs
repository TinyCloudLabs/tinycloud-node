//! Persistence for link state (`state.json`) and TLS artifacts.
//!
//! Layout (all under `dataPath/link/`):
//!   - `state.json`          — {name, serviceUrl, sequence, lastLanIps, certNotAfter, bind}
//!   - `tls/key.pem`         — CSR private key (0600)
//!   - `tls/cert.pem`        — signed cert chain from the service (0600)
//!   - `listener-state.json` — last-observed LAN TLS listener bind result (see `ListenerState`)
//!   - `state.lock`          — advisory lock guarding `state.json`'s sequence counter
//!
//! `sequence` is monotonic: `next_sequence` returns the next unused value and
//! callers write it back into `state.json` (via `write_state`) once it has
//! been consumed. This mirrors the server-side
//! "existing.sequence >= request.sequence => 409" semantics in `server.ts`.
//! See `commands::send_with_sequence` for where that value is persisted
//! *before* the network round-trip.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::DEFAULT_SERVICE_URL;

pub const LINK_DIR: &str = "link";
pub const STATE_FILE: &str = "state.json";
pub const TLS_DIR: &str = "tls";
pub const TLS_KEY_FILE: &str = "key.pem";
pub const TLS_CERT_FILE: &str = "cert.pem";
pub const LISTENER_STATE_FILE: &str = "listener-state.json";
pub const LOCK_FILE: &str = "state.lock";

/// Persistent state.json shape written to disk with 0600 perms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkState {
    /// Persisted schema version so we can migrate later without breaking reads.
    pub version: u32,
    /// The claimed name label (`office` in `office.local.tinycloud.link`).
    pub name: String,
    /// Service base URL — usually the default, but overridable via CLI/config.
    pub service_url: String,
    /// The last sequence value the node USED. Next PUT/POST must use
    /// `sequence + 1` to avoid the service's stale-record 409.
    pub sequence: u64,
    /// Last LAN IPs the node claimed. The auto-renew task re-claims when the
    /// current LAN IP set differs from this snapshot.
    pub last_lan_ips: Vec<String>,
    /// ISO-8601 UTC notAfter from the most recent cert, if any. Used to drive
    /// the "renew when <30 days from expiry" branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_not_after: Option<String>,
    /// Bind address the LAN TLS listener should use when `serve` starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
}

impl LinkState {
    pub fn new(name: String, service_url: String, bind: Option<String>) -> Self {
        Self {
            version: 1,
            name,
            service_url,
            sequence: 0,
            last_lan_ips: Vec::new(),
            cert_not_after: None,
            bind,
        }
    }

    /// Next monotonic sequence to send with a signed request.
    pub fn next_sequence(&self) -> u64 {
        self.sequence.saturating_add(1)
    }
}

pub struct LinkPaths {
    pub root: PathBuf,
    pub state_path: PathBuf,
    pub tls_dir: PathBuf,
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub listener_state_path: PathBuf,
    pub lock_path: PathBuf,
}

impl LinkPaths {
    pub fn from_data_root(data_root: &Path) -> Self {
        let root = data_root.join(LINK_DIR);
        let tls_dir = root.join(TLS_DIR);
        let key_path = tls_dir.join(TLS_KEY_FILE);
        let cert_path = tls_dir.join(TLS_CERT_FILE);
        let state_path = root.join(STATE_FILE);
        let listener_state_path = root.join(LISTENER_STATE_FILE);
        let lock_path = root.join(LOCK_FILE);
        Self {
            root,
            state_path,
            tls_dir,
            key_path,
            cert_path,
            listener_state_path,
            lock_path,
        }
    }
}

pub fn ensure_link_dirs(paths: &LinkPaths) -> Result<()> {
    fs::create_dir_all(&paths.root)
        .with_context(|| format!("failed to create {}", paths.root.display()))?;
    fs::create_dir_all(&paths.tls_dir)
        .with_context(|| format!("failed to create {}", paths.tls_dir.display()))?;
    Ok(())
}

pub fn read_state(paths: &LinkPaths) -> Result<Option<LinkState>> {
    match fs::read(&paths.state_path) {
        Ok(bytes) => {
            let state: LinkState = serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", paths.state_path.display()))?;
            Ok(Some(state))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read {}", paths.state_path.display()))?
        }
    }
}

pub fn write_state(paths: &LinkPaths, state: &LinkState) -> Result<()> {
    ensure_link_dirs(paths)?;
    let rendered = serde_json::to_vec_pretty(state)?;
    write_private_file(&paths.state_path, &rendered)
}

pub fn write_tls_material(paths: &LinkPaths, key_pem: &str, cert_pem: &str) -> Result<()> {
    ensure_link_dirs(paths)?;
    write_private_file(&paths.key_path, key_pem.as_bytes())?;
    write_private_file(&paths.cert_path, cert_pem.as_bytes())?;
    Ok(())
}

pub fn remove_link_dir(paths: &LinkPaths) -> Result<()> {
    match fs::remove_dir_all(&paths.root) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", paths.root.display())),
    }
}

pub fn default_service_url() -> String {
    DEFAULT_SERVICE_URL.to_string()
}

/// Write `contents` to `path` with mode `0600` from the moment the file is
/// created — no separate `chmod` call, so there is no window where the file
/// exists with the platform-default (typically world-readable) permissions.
#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

/// Observed bind result for the LAN TLS listener, written by `serve` and read
/// by `service status --json` so the reported `linkListener` state reflects
/// what actually happened (a failed bind) rather than being inferred purely
/// from whether the node process is running.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListenerState {
    pub bound: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn write_listener_state(paths: &LinkPaths, state: &ListenerState) -> Result<()> {
    ensure_link_dirs(paths)?;
    let rendered = serde_json::to_vec_pretty(state)?;
    fs::write(&paths.listener_state_path, rendered)
        .with_context(|| format!("failed to write {}", paths.listener_state_path.display()))
}

pub fn read_listener_state(paths: &LinkPaths) -> Result<Option<ListenerState>> {
    match fs::read(&paths.listener_state_path) {
        Ok(bytes) => {
            let state: ListenerState = serde_json::from_slice(&bytes).with_context(|| {
                format!("failed to parse {}", paths.listener_state_path.display())
            })?;
            Ok(Some(state))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read {}", paths.listener_state_path.display())),
    }
}

/// Advisory exclusive lock over `state.json`'s sequence counter, held for the
/// duration of a `link enable`/`disable`/`renew` call. Guards against two
/// races: the CLI and the in-process auto-renew loop mutating `state.json`
/// concurrently, and two overlapping CLI invocations doing the same.
#[cfg(unix)]
pub struct StateLock {
    _file: fs::File,
}

#[cfg(unix)]
impl StateLock {
    pub fn acquire(paths: &LinkPaths) -> Result<Self> {
        ensure_link_dirs(paths)?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            // The lock file's contents are never read — only its existence
            // and the `flock` held on it matter — so there's nothing to
            // preserve across opens.
            .truncate(false)
            .open(&paths.lock_path)
            .with_context(|| format!("failed to open {}", paths.lock_path.display()))?;
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` stays alive for the lifetime of the returned lock,
        // so `fd` remains valid for the `flock` call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to lock {}", paths.lock_path.display()));
        }
        Ok(Self { _file: file })
    }
}

#[cfg(not(unix))]
pub struct StateLock;

#[cfg(not(unix))]
impl StateLock {
    pub fn acquire(_paths: &LinkPaths) -> Result<Self> {
        Ok(Self)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn state_roundtrip_and_permissions_are_0600() {
        let tmp = tempdir().unwrap();
        let paths = LinkPaths::from_data_root(tmp.path());
        let state = LinkState {
            version: 1,
            name: "mynode".to_string(),
            service_url: "https://api.tinycloud.link".to_string(),
            sequence: 3,
            last_lan_ips: vec!["192.168.1.5".to_string()],
            cert_not_after: Some("2026-08-15T00:00:00Z".to_string()),
            bind: Some("0.0.0.0:8443".to_string()),
        };

        write_state(&paths, &state).unwrap();
        let mode = fs::metadata(&paths.state_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "state.json must be 0600");

        let reloaded = read_state(&paths).unwrap().unwrap();
        assert_eq!(reloaded, state);
    }

    #[test]
    fn tls_material_written_with_0600_permissions() {
        let tmp = tempdir().unwrap();
        let paths = LinkPaths::from_data_root(tmp.path());
        write_tls_material(&paths, "-----KEY-----\n", "-----CERT-----\n").unwrap();

        for path in [&paths.key_path, &paths.cert_path] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600", path.display());
        }
    }

    #[test]
    fn sequence_is_monotonic_across_restarts() {
        let tmp = tempdir().unwrap();
        let paths = LinkPaths::from_data_root(tmp.path());

        let mut state = LinkState::new(
            "office".to_string(),
            default_service_url(),
            Some("0.0.0.0:8443".to_string()),
        );
        assert_eq!(state.sequence, 0);
        // simulate first successful claim: consumed sequence 1
        state.sequence = state.next_sequence();
        write_state(&paths, &state).unwrap();

        // "restart"
        let reloaded = read_state(&paths).unwrap().unwrap();
        assert_eq!(reloaded.sequence, 1);
        // second action must use 2
        assert_eq!(reloaded.next_sequence(), 2);
    }

    #[test]
    fn missing_state_returns_none() {
        let tmp = tempdir().unwrap();
        let paths = LinkPaths::from_data_root(tmp.path());
        assert!(read_state(&paths).unwrap().is_none());
    }

    #[test]
    fn listener_state_roundtrips() {
        let tmp = tempdir().unwrap();
        let paths = LinkPaths::from_data_root(tmp.path());
        assert!(read_listener_state(&paths).unwrap().is_none());

        let state = ListenerState {
            bound: false,
            bind_addr: Some("0.0.0.0:8443".to_string()),
            error: Some("address already in use".to_string()),
        };
        write_listener_state(&paths, &state).unwrap();
        assert_eq!(read_listener_state(&paths).unwrap().unwrap(), state);
    }

    #[test]
    fn state_lock_can_be_reacquired_after_release() {
        let tmp = tempdir().unwrap();
        let paths = LinkPaths::from_data_root(tmp.path());
        {
            let _lock = StateLock::acquire(&paths).unwrap();
        }
        // Dropping the first lock must release it — acquiring again must not
        // deadlock.
        let _lock = StateLock::acquire(&paths).unwrap();
    }
}
