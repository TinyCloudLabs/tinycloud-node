# TinyCloud patch to sqlx-core 0.8.6 (TC-1054)

This is crates.io `sqlx-core` 0.8.6 (`sqlx-core-0.8.6.crate`, sha256
`ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6`),
unpacked verbatim in one commit and patched in the next. It is wired into
the workspace through `[patch.crates-io]` in the root `Cargo.toml` (and in
the excluded `test/m1-realdata-e2e` and `test/w5-policy-runtime-node-e2e`
manifests).

## Why

A PostgreSQL connection that the network drops silently (no FIN, no RST)
hung a statement for up to about 15 minutes. While it waited, it held the
node's per-database SQL lock (TC-1054). TCP keepalive and `TCP_USER_TIMEOUT`
bound that to tens of seconds. sqlx 0.8 can't set either: `connect_tcp` only
calls `TcpStream::connect` and `set_nodelay`, and it offers no socket or
connector hook.

## The delta

- `src/net/tcp_keepalive.rs` (new): a process-global registry of
  `TcpKeepalive` settings, keyed by connect target (host, port), with
  `set_tcp_keepalive`, `tcp_keepalive` and `sockets_configured`.
- `src/net/socket/mod.rs`, `connect_tcp` (tokio runtime): right after
  `set_nodelay`, before the stream is used for anything (TLS, startup), the
  connected stream is configured if its target is registered:
  - on Linux: `TCP_USER_TIMEOUT`, then `SO_KEEPALIVE` with `TCP_KEEPIDLE`,
    `TCP_KEEPINTVL` and `TCP_KEEPCNT` (through socket2);
  - elsewhere: `SO_KEEPALIVE` with the idle time only.

  A failure fails the connect (fail-closed), with a `tracing` warning.
- `src/net/mod.rs`: `pub mod tcp_keepalive;`.
- `src/lib.rs`: `#![allow(warnings)]`. Cargo caps the lints of a crates.io
  dependency, but not of a path dependency, so without it the workspace's
  `-D warnings` CI would fail on upstream's own warnings.
- `Cargo.toml`: a `socket2` 0.5 dependency (`all` features), which is
  already in the lock graph through tokio.

The async-std path of `connect_tcp` is not patched; the node uses tokio.

## Removal

Drop this directory and the `[patch]` entries when upstream sqlx supports
TCP keepalive or user timeout, or when sea-orm moves to an sqlx that does
(TC-1061).
