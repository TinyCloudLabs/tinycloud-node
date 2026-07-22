//! High-level actions invoked by the CLI: `tunnel enable`, `tunnel disable`,
//! `tunnel status`.
//!
//! Unlike `link enable`, these do not themselves make a network call: the
//! actual WebSocket connect + auth handshake happens inside `serve`'s tunnel
//! task (see `runtime::spawn_tunnel_task`), the same way `link enable`
//! provisions state that the LAN TLS listener picks up on next `serve`
//! (re)start. `enable`/`disable` here only read/write the shared
//! `dataPath/link/state.json` under its existing advisory lock — see
//! `link::state`'s module doc for why the tunnel flag lives on that same
//! file rather than a separate one.
use anyhow::{anyhow, Result};
use serde::Serialize;
use std::path::Path;

use crate::link::state::{self, LinkPaths, StateLock, TunnelRuntimeState};

/// Sentinel error message `bump_sequence_for_tunnel` returns when the tunnel
/// flag has been turned off (e.g. a concurrent `tunnel disable`). The
/// connection loop (`tunnel::connection::run`) matches on this exact string
/// to distinguish "stop reconnecting, this is permanent until re-enabled"
/// from an ordinary retry-worthy failure.
pub const TUNNEL_DISABLED_ERROR: &str = "tunnel: disabled";

/// JSON emitted from `tunnel enable`, `tunnel disable`, and `tunnel status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatusReport {
    pub tunnel_enabled: bool,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Args for `tunnel enable`.
#[derive(Debug, Clone, Default)]
pub struct TunnelEnableArgs {
    /// Override for the tunnel relay base URL (defaults to the link
    /// service's own `serviceUrl`).
    pub service_url: Option<String>,
}

/// The public HTTPS URL a tunnel-enabled node is reachable at, once
/// connected: `https://<name>.tinycloud.link`.
pub fn remote_url(name: &str) -> String {
    format!("https://{name}.{}", super::REMOTE_DOMAIN_SUFFIX)
}

pub fn enable(data_root: &Path, args: TunnelEnableArgs) -> Result<TunnelStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let _lock = StateLock::acquire(&paths)?;

    let mut link_state = state::read_state(&paths)?.ok_or_else(|| {
        anyhow!(
            "link is not enabled — run `tinycloud node link enable <name>` first; \
             the tunnel reuses that claimed name and its sequence counter"
        )
    })?;

    link_state.tunnel_enabled = true;
    link_state.tunnel_service_url = args.service_url;
    state::write_state(&paths, &link_state)?;

    build_status(&paths, Some(&link_state))
}

pub fn disable(data_root: &Path) -> Result<TunnelStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let _lock = StateLock::acquire(&paths)?;

    let Some(mut link_state) = state::read_state(&paths)? else {
        return Ok(disabled_report());
    };

    link_state.tunnel_enabled = false;
    state::write_state(&paths, &link_state)?;
    // Clear the runtime marker so a stale `connected: true` doesn't linger.
    // If a tunnel task is running inside `serve`, it only notices the flag
    // flipping off on its *next* connection attempt (`bump_sequence_for_tunnel`
    // returns the `TUNNEL_DISABLED_ERROR` sentinel), at which point it stops
    // reconnecting and clears this same marker itself — see
    // `tunnel::connection::run`. A socket already live at the moment of this
    // call keeps serving until its next reconnect or a `serve` restart; this
    // call's removal here covers the window before that loop notices, and
    // the case where no `serve` process is running at all.
    state::remove_tunnel_runtime_state(&paths)?;

    Ok(disabled_report())
}

pub fn status(data_root: &Path) -> Result<TunnelStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let link_state = state::read_state(&paths)?;
    build_status(&paths, link_state.as_ref())
}

fn disabled_report() -> TunnelStatusReport {
    TunnelStatusReport {
        tunnel_enabled: false,
        connected: false,
        remote_url: None,
        service_url: None,
        last_error: None,
    }
}

fn build_status(
    paths: &LinkPaths,
    link_state: Option<&crate::link::state::LinkState>,
) -> Result<TunnelStatusReport> {
    let Some(link_state) = link_state else {
        return Ok(disabled_report());
    };
    if !link_state.tunnel_enabled {
        return Ok(disabled_report());
    }

    let runtime = state::read_tunnel_runtime_state(paths)?.unwrap_or_default();
    Ok(TunnelStatusReport {
        tunnel_enabled: true,
        connected: runtime.connected,
        remote_url: Some(remote_url(&link_state.name)),
        service_url: Some(link_state.effective_tunnel_service_url()),
        last_error: runtime.last_error,
    })
}

/// Convenience for `serve`: load link state and, if the tunnel is enabled,
/// return it — otherwise `None` (mirrors `link::commands::load_state` but
/// additionally gates on the tunnel flag so `runtime.rs` doesn't need to
/// duplicate that check).
pub fn load_enabled_state(data_root: &Path) -> Result<Option<crate::link::state::LinkState>> {
    let paths = LinkPaths::from_data_root(data_root);
    Ok(state::read_state(&paths)?.filter(|s| s.tunnel_enabled))
}

/// Record the tunnel connection's live state to disk so `service status
/// --json` / `tunnel status --json` (run from a separate CLI invocation)
/// can observe it. Called from the tunnel task in `runtime.rs`.
pub fn record_runtime_state(data_root: &Path, state: &TunnelRuntimeState) -> Result<()> {
    let paths = LinkPaths::from_data_root(data_root);
    state::write_tunnel_runtime_state(&paths, state)
}

/// Removes the on-disk tunnel-runtime marker. Called from the connection
/// loop when it detects mid-flight that the tunnel was disabled, so its own
/// state doesn't resurrect the marker `tunnel disable` already removed.
pub fn clear_runtime_state(data_root: &Path) -> Result<()> {
    let paths = LinkPaths::from_data_root(data_root);
    state::remove_tunnel_runtime_state(&paths)
}

/// Bump-before-connect: consume the name's next shared sequence value
/// (plus `extra_jump`, used only when resyncing after a stale-sequence
/// close) and persist it to `state.json` *before* the caller dials the
/// relay — mirrors `link::commands::send_with_sequence`. Returns the
/// claimed `name`, the effective tunnel service URL, and the sequence to
/// sign the auth frame with.
///
/// Fails if link is not enabled at all, or if the tunnel flag has been
/// turned off since `serve` started (e.g. a concurrent `tunnel disable`) —
/// the caller (the connection loop) treats this as fatal for this attempt,
/// not one more thing to retry past.
pub fn bump_sequence_for_tunnel(
    data_root: &Path,
    extra_jump: u64,
) -> Result<(String, String, u64)> {
    let paths = LinkPaths::from_data_root(data_root);
    let _lock = StateLock::acquire(&paths)?;

    let mut link_state =
        state::read_state(&paths)?.ok_or_else(|| anyhow!("tunnel: link state.json is missing"))?;
    if !link_state.tunnel_enabled {
        return Err(anyhow!(TUNNEL_DISABLED_ERROR));
    }

    let sequence = link_state.next_sequence().saturating_add(extra_jump);
    link_state.sequence = sequence;
    state::write_state(&paths, &link_state)?;

    Ok((
        link_state.name.clone(),
        link_state.effective_tunnel_service_url(),
        sequence,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::state::LinkState;
    use tempfile::tempdir;

    fn seed_link_state(data_root: &Path, name: &str) {
        let paths = LinkPaths::from_data_root(data_root);
        let link_state = LinkState::new(
            name.to_string(),
            "https://api.tinycloud.link".to_string(),
            Some("0.0.0.0:8443".to_string()),
        );
        state::write_state(&paths, &link_state).unwrap();
    }

    #[::core::prelude::v1::test]
    fn enable_fails_without_an_existing_link_claim() {
        let tmp = tempdir().unwrap();
        let err = enable(tmp.path(), TunnelEnableArgs::default()).unwrap_err();
        assert!(err.to_string().contains("link is not enabled"));
    }

    #[::core::prelude::v1::test]
    fn enable_persists_flag_on_the_shared_link_state_file() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");

        let report = enable(tmp.path(), TunnelEnableArgs::default()).unwrap();
        assert!(report.tunnel_enabled);
        assert!(!report.connected);
        assert_eq!(
            report.remote_url.as_deref(),
            Some("https://office.tinycloud.link")
        );

        let paths = LinkPaths::from_data_root(tmp.path());
        let reloaded = state::read_state(&paths).unwrap().unwrap();
        assert!(reloaded.tunnel_enabled);
        // The link name/sequence file must be untouched otherwise — no
        // separate sequence bump for `tunnel enable` itself.
        assert_eq!(reloaded.sequence, 0);
        assert_eq!(reloaded.name, "office");
    }

    #[::core::prelude::v1::test]
    fn enable_respects_service_url_override() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        let report = enable(
            tmp.path(),
            TunnelEnableArgs {
                service_url: Some("https://staging.tinycloud.link".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            report.service_url.as_deref(),
            Some("https://staging.tinycloud.link")
        );
    }

    #[::core::prelude::v1::test]
    fn disable_clears_flag_and_runtime_marker() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        enable(tmp.path(), TunnelEnableArgs::default()).unwrap();

        let paths = LinkPaths::from_data_root(tmp.path());
        state::write_tunnel_runtime_state(
            &paths,
            &TunnelRuntimeState {
                connected: true,
                last_error: None,
            },
        )
        .unwrap();

        let report = disable(tmp.path()).unwrap();
        assert!(!report.tunnel_enabled);
        assert!(!report.connected);
        assert!(state::read_tunnel_runtime_state(&paths).unwrap().is_none());

        // The link claim itself (name/sequence) must survive `tunnel
        // disable` — only `link disable` removes it.
        let reloaded = state::read_state(&paths).unwrap().unwrap();
        assert_eq!(reloaded.name, "office");
        assert!(!reloaded.tunnel_enabled);
    }

    #[::core::prelude::v1::test]
    fn disable_without_any_state_is_a_no_op() {
        let tmp = tempdir().unwrap();
        let report = disable(tmp.path()).unwrap();
        assert!(!report.tunnel_enabled);
    }

    #[::core::prelude::v1::test]
    fn status_reports_disabled_when_link_is_not_enabled() {
        let tmp = tempdir().unwrap();
        let report = status(tmp.path()).unwrap();
        assert!(!report.tunnel_enabled);
        assert!(!report.connected);
    }

    #[::core::prelude::v1::test]
    fn status_surfaces_runtime_connection_state() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        enable(tmp.path(), TunnelEnableArgs::default()).unwrap();

        let paths = LinkPaths::from_data_root(tmp.path());
        state::write_tunnel_runtime_state(
            &paths,
            &TunnelRuntimeState {
                connected: false,
                last_error: Some("stale sequence".to_string()),
            },
        )
        .unwrap();

        let report = status(tmp.path()).unwrap();
        assert!(report.tunnel_enabled);
        assert!(!report.connected);
        assert_eq!(report.last_error.as_deref(), Some("stale sequence"));
    }

    #[::core::prelude::v1::test]
    fn bump_sequence_for_tunnel_requires_tunnel_enabled() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        // Not yet enabled.
        assert!(bump_sequence_for_tunnel(tmp.path(), 0).is_err());
    }

    #[::core::prelude::v1::test]
    fn bump_sequence_for_tunnel_persists_before_returning() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        enable(tmp.path(), TunnelEnableArgs::default()).unwrap();

        let (name, service_url, sequence) = bump_sequence_for_tunnel(tmp.path(), 0).unwrap();
        assert_eq!(name, "office");
        assert_eq!(service_url, "https://api.tinycloud.link");
        assert_eq!(sequence, 1);

        let paths = LinkPaths::from_data_root(tmp.path());
        let reloaded = state::read_state(&paths).unwrap().unwrap();
        assert_eq!(
            reloaded.sequence, 1,
            "sequence must be persisted before the network round-trip"
        );

        let (_, _, next) = bump_sequence_for_tunnel(tmp.path(), 0).unwrap();
        assert_eq!(next, 2);
    }

    #[::core::prelude::v1::test]
    fn bump_sequence_for_tunnel_applies_resync_jump() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        enable(tmp.path(), TunnelEnableArgs::default()).unwrap();

        let (_, _, sequence) = bump_sequence_for_tunnel(tmp.path(), 100).unwrap();
        assert_eq!(sequence, 101);
    }

    #[::core::prelude::v1::test]
    fn load_enabled_state_is_none_when_tunnel_disabled() {
        let tmp = tempdir().unwrap();
        seed_link_state(tmp.path(), "office");
        assert!(load_enabled_state(tmp.path()).unwrap().is_none());

        enable(tmp.path(), TunnelEnableArgs::default()).unwrap();
        assert!(load_enabled_state(tmp.path()).unwrap().is_some());
    }
}
