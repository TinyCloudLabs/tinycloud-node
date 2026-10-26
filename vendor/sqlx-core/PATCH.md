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

## Request-local database timing (TC-959)

`src/request_telemetry.rs` contains data-free, per-request atomic counters and
poll-scoped context propagation. No SQL, bind values, identity strings, or errors
are stored in these counters. `QueryLogger` captures one timer when constructed
and records it once on drop, independent of diagnostic `finish()` calls.

`PoolInner::acquire` measures the actual acquisition future, including closed
pools, timeout, and cancellation. Its connection establishment, health checks,
and acquisition hooks are polled without request query attribution; their time
still belongs to acquisition. SQL executed through acquired connections and
transactions retains the request context.

PostgreSQL raw BEGIN/SAVEPOINT needs the paired `sqlx-postgres` driver hook:
SeaORM calls its transaction manager directly, bypassing the generic SQLx
transaction wrapper. Invalid nested custom-BEGIN validation does not count SQL.
MySQL awaited controls already use the logger. SQLite worker propagation and
raw awaited controls use the accompanying `sqlx-sqlite` patch.

Detached drop-triggered rollback, connection release/health checks, startup
initialization, and explicit prepare/describe metadata operations are excluded.
Query timing follows the driver execution/logger lifetime, including streaming
execution; it is not server-side CPU time. The PostgreSQL driver hook covers
both direct SQLx and direct SeaORM transaction-manager callers.

Boundary regressions live in `tinycloud-core/tests/sqlx_request_telemetry.rs` so
they run in the root workspace against the paired patched crates and lockfile.
Remove these request-telemetry patches once an upstream equivalent supplies
request-scoped acquisition and driver-execution hooks.

The PostgreSQL boundary regressions use `TINYCLOUD_TEST_POSTGRES_URL` only at
test runtime, require it in CI, and otherwise print an explicit local skip.
They use SELECT-only statements and test raw BEGIN/SAVEPOINT through SQLx and
SeaORM, validation, success/failure, awaited commit/rollback, and acquisition
timeout/closed-pool failure. MySQL has no integration-test server in this suite.

## Bounded release ping (TC-2035)

### Why

sqlx returns a dropped connection to the pool through
`Floating::return_to_pool`, which pings it first. A connection whose statement
future was dropped mid-flight (a caller's timeout, a cancelled request) still
owes that statement's reply, and the ping waits for it. If the peer never
answers (a stalled proxy or socket), nothing bounds that wait: the spawned
release task, the socket and the pool permit are held for good. The read-audit
drain hit this: a batch commit that never returned stopped the drain, and
dropping its future from a timeout would have held the pool slot instead.

### The delta

- `src/pool/connection.rs`: `RELEASE_PING_TIMEOUT` (5 s). In
  `Floating::return_to_pool`, the release ping runs under
  `crate::rt::timeout(self.guard.pool.options.release_ping_timeout, ..)`. A
  timeout is handled like a failed ping: `warn!` log, then `close_hard()`, itself
  bounded by `CLOSE_ON_DROP_TIMEOUT` (on that timeout the future is dropped, which
  closes the socket and releases the permit). The pool opens a replacement on
  the next acquire; the permit is released on every path.
- `src/pool/options.rs`: `PoolOptions::release_ping_timeout(Duration)` and a
  `release_ping_timeout` field (default `RELEASE_PING_TIMEOUT`, copied in `Clone`
  and `new`). The node leaves the default; a test shortens it for one pool.

### Effect

Pool-wide. Any released connection whose ping does not answer within the bound is
closed instead of held. A live server finishing a long dropped statement is no
longer waited for; closing the socket makes the server abort it.

### Re-applying on a vendor bump

Re-apply the two hunks above to the new `pool/connection.rs` (the ping in
`return_to_pool`, and the new const) and `pool/options.rs` (the field, `Clone`,
`new`, the setter). The regression is
`read_audit::tests::tc2035_a_stalled_connection_is_closed_and_its_pool_slot_freed`
in `tinycloud-core`, which uses a listener that never answers after startup. Drop
this patch when upstream bounds the release ping.
