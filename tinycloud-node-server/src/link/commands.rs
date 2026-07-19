//! High-level actions invoked by the CLI: `enable`, `disable`, `status`, `renew`.
//!
//! These functions:
//!   1. Resolve the node identity via the `KeyProvider` (the documented trust
//!      boundary — the CLI links the KeyProvider library in-process and holds
//!      secret material only long enough to sign the service payloads).
//!   2. Enumerate current LAN IPs.
//!   3. Sign canonical payloads and call the link service HTTP client.
//!   4. Persist the resulting sequence, cert-notAfter, and TLS material under
//!      `dataPath/link/`.
//!
//! Sequence handling: every signed action consumes `link_state.next_sequence()`
//! and persists it to `state.json` *before* the network round-trip (see
//! `send_with_sequence`) — the service commits its own sequence bump as soon
//! as the underlying write lands, which can be before a later step fails
//! (e.g. the ACME round-trip for `POST /v1/certs/:name` in `server.ts`), so a
//! failure on our side must never leave the client behind the service's
//! record. If the service reports a stale-sequence 409 anyway, we resync by
//! jumping the local counter forward and retrying once (`GET
//! /v1/names/:name` doesn't expose the service's stored sequence, so an
//! exact resync isn't possible — see docs/specs/node-control-plane-v1.md
//! §3.9).
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::path::Path;

use crate::link::{
    client::{CertIssuanceResponse, LinkClient},
    csr, ip,
    payload::{self, CertRequestBody, NameClaimBody, NameDeleteBody},
    state::{self, LinkPaths, LinkState, StateLock},
    LinkError, DEFAULT_BIND_ADDR,
};
use crate::node_control::key_provider::{self, IdentityPurpose};

/// Args for `link enable`.
#[derive(Debug, Clone)]
pub struct EnableArgs {
    pub name: String,
    pub service_url: Option<String>,
    pub bind: Option<String>,
}

/// JSON emitted from `link enable`, `link renew`, and `link status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkStatusReport {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub link_listener: LinkListenerState,
}

/// The observed state of the LAN TLS terminator.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LinkListenerState {
    /// Link is not enabled — the LAN listener is intentionally absent.
    Disabled,
    /// Link is enabled but the listener has not been observed running yet
    /// (typically because `serve` is not running). It will start on next boot.
    Stopped,
    /// The LAN terminator is bound and accepting connections.
    Running,
}

pub fn enable(
    data_root: &Path,
    keys: Option<&crate::config::Keys>,
    args: EnableArgs,
) -> Result<LinkStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let _lock = StateLock::acquire(&paths)?;

    // 0. Normalize the name the same way the service does before it's used
    // in anything we sign or embed in the CSR — see `normalize_name_label`.
    let name = crate::link::normalize_name_label(&args.name).map_err(anyhow::Error::from)?;

    // 1. Trust boundary: derive the node identity in-process.
    let identity_state =
        key_provider::resolve_identity_state(keys, data_root, IdentityPurpose::Backup)?;
    let secret = identity_state
        .secret
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let node_did = identity_state
        .node_did
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let keypair = secret.node_keypair();

    // 2. Enumerate LAN IPs.
    let lan_ips = ip::discover_lan_ips().map_err(anyhow::Error::from)?;
    let lan_ip_strings = ip::format_lan_ips(&lan_ips);

    // 3. Resolve state (may pre-exist).
    let service_url = args.service_url.unwrap_or_else(state::default_service_url);
    let bind = args.bind.unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());

    let mut link_state = state::read_state(&paths)?
        .unwrap_or_else(|| LinkState::new(name.clone(), service_url.clone(), Some(bind.clone())));
    link_state.name = name.clone();
    link_state.service_url = service_url.clone();
    link_state.bind = Some(bind.clone());

    let client = LinkClient::new(service_url.clone()).map_err(anyhow::Error::from)?;

    // 4. Claim the name.
    send_with_sequence(&mut link_state, &paths, "PUT /v1/names/:name", |sequence| {
        let canonical =
            payload::canonical_claim_payload(&name, &node_did, &lan_ip_strings, sequence);
        let signature = payload::sign_ed25519(&keypair, &canonical)?;
        let claim = NameClaimBody {
            version: payload::VERSION,
            action: "claim",
            name: name.clone(),
            subject: node_did.clone(),
            lan_ips: lan_ip_strings.clone(),
            sequence,
            signature,
        };
        client.put_name_claim(&claim)
    })?;
    link_state.last_lan_ips = lan_ip_strings.clone();
    state::write_state(&paths, &link_state)?;

    // 5. Issue cert.
    let issuance = request_cert(&client, &keypair, &name, &node_did, &mut link_state, &paths)?;

    // 6. Compute a status report to hand back to the CLI.
    build_status(&paths, &link_state, Some(&issuance))
}

pub fn disable(data_root: &Path, keys: Option<&crate::config::Keys>) -> Result<LinkStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let _lock = StateLock::acquire(&paths)?;
    let Some(mut link_state) = state::read_state(&paths)? else {
        return Ok(disabled_report());
    };

    let identity_state =
        key_provider::resolve_identity_state(keys, data_root, IdentityPurpose::Backup)?;
    let secret = identity_state
        .secret
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let node_did = identity_state
        .node_did
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let keypair = secret.node_keypair();

    let client = LinkClient::new(link_state.service_url.clone()).map_err(anyhow::Error::from)?;
    let name = link_state.name.clone();
    let delete_result = send_with_sequence(
        &mut link_state,
        &paths,
        "DELETE /v1/names/:name",
        |sequence| {
            let canonical = payload::canonical_delete_payload(&name, &node_did, sequence);
            let signature = payload::sign_ed25519(&keypair, &canonical)?;
            let body = NameDeleteBody {
                version: payload::VERSION,
                action: "delete",
                name: name.clone(),
                subject: node_did.clone(),
                sequence,
                signature,
            };
            // The name never existing at all is not a failure worth
            // retrying/reporting — treat it the same as a successful delete.
            match client.delete_name(&body) {
                Ok(()) | Err(LinkError::UnexpectedStatus { status: 404, .. }) => Ok(()),
                Err(err) => Err(err),
            }
        },
    );

    // Clean up local state regardless of the outcome above: keeping it
    // around after a failed delete wedges the node under a name/cert it no
    // longer controls on the service side (see
    // docs/specs/node-control-plane-v1.md §3.9).
    state::remove_link_dir(&paths)?;

    if let Err(err) = delete_result {
        tracing::warn!(%err, %name, "link disable: service delete failed; local state removed anyway");
        return Err(err);
    }

    Ok(disabled_report())
}

fn disabled_report() -> LinkStatusReport {
    LinkStatusReport {
        enabled: false,
        link_name: None,
        local_url: None,
        cert_not_after: None,
        service_url: None,
        bind: None,
        sequence: None,
        link_listener: LinkListenerState::Disabled,
    }
}

pub fn status(data_root: &Path) -> Result<LinkStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let Some(link_state) = state::read_state(&paths)? else {
        return Ok(disabled_report());
    };
    build_status(&paths, &link_state, None)
}

pub fn renew(data_root: &Path, keys: Option<&crate::config::Keys>) -> Result<LinkStatusReport> {
    let paths = LinkPaths::from_data_root(data_root);
    let _lock = StateLock::acquire(&paths)?;
    let mut link_state = state::read_state(&paths)?
        .ok_or_else(|| anyhow!("link is not enabled — run `tinycloud node link enable <name>`"))?;

    let identity_state =
        key_provider::resolve_identity_state(keys, data_root, IdentityPurpose::Backup)?;
    let secret = identity_state
        .secret
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let node_did = identity_state
        .node_did
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let keypair = secret.node_keypair();

    let client = LinkClient::new(link_state.service_url.clone()).map_err(anyhow::Error::from)?;

    // Re-claim if the IP set has changed since the last claim.
    let current_ips = ip::discover_lan_ips().map_err(anyhow::Error::from)?;
    let current_ip_strings = ip::format_lan_ips(&current_ips);
    if current_ip_strings != link_state.last_lan_ips {
        let name = link_state.name.clone();
        send_with_sequence(&mut link_state, &paths, "PUT /v1/names/:name", |sequence| {
            let canonical =
                payload::canonical_claim_payload(&name, &node_did, &current_ip_strings, sequence);
            let signature = payload::sign_ed25519(&keypair, &canonical)?;
            let body = NameClaimBody {
                version: payload::VERSION,
                action: "claim",
                name: name.clone(),
                subject: node_did.clone(),
                lan_ips: current_ip_strings.clone(),
                sequence,
                signature,
            };
            client.put_name_claim(&body)
        })?;
        link_state.last_lan_ips = current_ip_strings;
        state::write_state(&paths, &link_state)?;
    }

    let issuance = request_cert(
        &client,
        &keypair,
        &link_state.name.clone(),
        &node_did,
        &mut link_state,
        &paths,
    )?;
    build_status(&paths, &link_state, Some(&issuance))
}

/// How far to jump the local sequence counter when recovering from a
/// stale-sequence 409. The link service does not expose its stored sequence
/// via `GET /v1/names/:name` (see `tinycloud-link/src/server.ts`), so an
/// exact resync isn't possible — jumping forward and retrying once is the
/// documented recovery path (docs/specs/node-control-plane-v1.md §3.9).
const SEQUENCE_RESYNC_JUMP: u64 = 100;

/// Run a signed action against the link service using `link_state`'s next
/// sequence value.
///
/// The sequence consumed for this attempt is persisted to `state.json`
/// *before* `send` runs (see the module doc for why). If the service comes
/// back with a stale-sequence 409 anyway, the local counter has fallen
/// behind the service's record (e.g. `state.json` was restored from a
/// backup, or a previous attempt crashed after the service's write landed
/// but before we could see the response) — jump the counter forward by
/// [`SEQUENCE_RESYNC_JUMP`] and retry once. A second failure is surfaced to
/// the caller.
fn send_with_sequence<T>(
    link_state: &mut LinkState,
    paths: &LinkPaths,
    ctx: &'static str,
    mut send: impl FnMut(u64) -> Result<T, LinkError>,
) -> Result<(u64, T)> {
    let sequence = link_state.next_sequence();
    link_state.sequence = sequence;
    state::write_state(paths, link_state)?;

    match send(sequence) {
        Ok(value) => Ok((sequence, value)),
        Err(LinkError::StaleSequence { .. }) => {
            let resynced = link_state.sequence.saturating_add(SEQUENCE_RESYNC_JUMP);
            link_state.sequence = resynced;
            state::write_state(paths, link_state)?;
            match send(resynced) {
                Ok(value) => Ok((resynced, value)),
                Err(err) => Err(link_error_context(err, ctx)),
            }
        }
        Err(err) => Err(link_error_context(err, ctx)),
    }
}

/// Request a fresh cert for `name` and persist the resulting key/cert/notAfter.
fn request_cert(
    client: &LinkClient,
    keypair: &tinycloud_core::keys::Keypair,
    name: &str,
    node_did: &str,
    link_state: &mut LinkState,
    paths: &LinkPaths,
) -> Result<CertIssuanceResponse> {
    let bundle = csr::generate_csr(name).map_err(anyhow::Error::from)?;
    let (_sequence, issuance) =
        send_with_sequence(link_state, paths, "POST /v1/certs/:name", |sequence| {
            let canonical =
                payload::canonical_cert_request_payload(name, node_did, &bundle.csr_pem, sequence);
            let signature = payload::sign_ed25519(keypair, &canonical)?;
            let body = CertRequestBody {
                version: payload::VERSION,
                action: "cert",
                name: name.to_string(),
                subject: node_did.to_string(),
                csr: bundle.csr_pem.clone(),
                sequence,
                signature,
            };
            client.post_cert_request(&body)
        })?;

    state::write_tls_material(paths, &bundle.private_key_pem, &issuance.cert_chain_pem)?;
    link_state.cert_not_after = Some(issuance.not_after.clone());
    state::write_state(paths, link_state)?;
    Ok(issuance)
}

fn build_status(
    _paths: &LinkPaths,
    link_state: &LinkState,
    issuance: Option<&CertIssuanceResponse>,
) -> Result<LinkStatusReport> {
    let bind_port = link_state
        .bind
        .as_deref()
        .and_then(parse_bind_port)
        .unwrap_or(8443);
    let local_url = crate::link::local_url(&link_state.name, bind_port);
    let cert_not_after = issuance
        .map(|iss| iss.not_after.clone())
        .or_else(|| link_state.cert_not_after.clone());

    Ok(LinkStatusReport {
        enabled: true,
        link_name: Some(link_state.name.clone()),
        local_url: Some(local_url),
        cert_not_after,
        service_url: Some(link_state.service_url.clone()),
        bind: link_state.bind.clone(),
        sequence: Some(link_state.sequence),
        // The CLI can't observe the running serve process; report Stopped and
        // let `service status --json` fill in Running from within `serve`.
        link_listener: LinkListenerState::Stopped,
    })
}

fn parse_bind_port(bind: &str) -> Option<u16> {
    let (_host, port) = bind.rsplit_once(':')?;
    port.parse().ok()
}

fn link_error_context(err: LinkError, ctx: &str) -> anyhow::Error {
    anyhow!(err).context(ctx.to_string())
}

/// Load effective link state (used by `serve` bootstrapping).
pub fn load_state(data_root: &Path) -> Result<Option<LinkState>> {
    let paths = LinkPaths::from_data_root(data_root);
    state::read_state(&paths)
}

/// Read link state alongside the on-disk TLS material for the given data root.
pub fn load_tls_material(data_root: &Path) -> Result<Option<(LinkState, String, String)>> {
    let paths = LinkPaths::from_data_root(data_root);
    let Some(link_state) = state::read_state(&paths)? else {
        return Ok(None);
    };
    let key_pem = std::fs::read_to_string(&paths.key_path)
        .with_context(|| format!("failed to read {}", paths.key_path.display()))?;
    let cert_pem = std::fs::read_to_string(&paths.cert_path)
        .with_context(|| format!("failed to read {}", paths.cert_path.display()))?;
    Ok(Some((link_state, key_pem, cert_pem)))
}

/// Convenience for callers that want to derive the LAN bind address from the
/// stored state.
pub fn effective_bind_address(state: &LinkState) -> String {
    state
        .bind
        .clone()
        .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string())
}

/// The FQDN this node serves under, if link is enabled.
pub fn link_fqdn(state: &LinkState) -> String {
    crate::link::csr::fqdn_for_name(&state.name)
}

/// Where the loopback public API is bound. `serve` reads the port from Rocket
/// config and passes it through so the LAN proxy targets the same socket.
pub fn loopback_api_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}
