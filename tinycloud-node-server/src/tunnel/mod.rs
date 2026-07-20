//! `tinycloud node tunnel` — the outbound Rust tunnel client for the
//! tinycloud.link relay (TC-85 service-side, TC-252 this node-side client).
//!
//! Overview
//!
//! `https://<name>.tinycloud.link` (the public apex zone, distinct from the
//! LAN-only `<name>.local.tinycloud.link` the `link` module manages) is
//! served by the relay proxying each HTTPS request down a WebSocket this
//! node opens and keeps alive. The node never needs an inbound port, a
//! public IP, or NAT configuration.
//!
//! A tunnel requires a name already claimed via `link enable` — the tunnel
//! auth frame reuses that name's `did:key` subject and its single shared
//! `sequence` counter (claim/delete/cert/tunnel all bump the same counter;
//! see `link::state`'s module doc). `tunnel enable` only persists a flag on
//! that existing `state.json`; the actual WebSocket connect + auth handshake
//! happens inside `serve`'s tunnel task (`runtime::spawn_tunnel_task`), the
//! same way `link enable` provisions state that the LAN TLS listener picks
//! up on next `serve` (re)start.
//!
//! Module layout:
//!   - `protocol` — the post-auth frame wire format (mirrors
//!     `tinycloud-link/src/tunnel/protocol.ts`).
//!   - `auth` — the signed first-frame auth record (mirrors
//!     `TunnelAuthRecord`/`canonicalTunnelAuthPayload` in
//!     `tinycloud-link/src/names.ts`).
//!   - `reconnect` — pure backoff/resync/stop decision logic, kept free of
//!     networking so it's exhaustively unit-testable.
//!   - `connection` — the async WebSocket engine: connect, authenticate,
//!     multiplex proxied requests to the loopback public API.
//!   - `commands` — `enable`/`disable`/`status` CLI actions.
pub mod auth;
pub mod commands;
pub mod connection;
pub mod protocol;
pub mod reconnect;

/// The tunnel relay's public namespace: `<name>.tinycloud.link` (the apex
/// zone, not the LAN-only `local.tinycloud.link` zone `link` manages).
pub const REMOTE_DOMAIN_SUFFIX: &str = "tinycloud.link";
