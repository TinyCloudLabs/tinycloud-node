# TinyCloud patch to sqlx-sqlite 0.8.6 (TC-959)

Source: the crates.io `sqlx-sqlite` 0.8.6 package, checksum
`c2d12fe70b2c1b4401038055f90f151b78208de1f9f89a7dbfd41587a10c3eea`,
copied from Cargo's extracted registry package. The registry-only `.cargo-ok`
marker is not included. The root `[patch.crates-io]` selects this directory.

## Why this driver patch is necessary

SQLite executes on one dedicated thread per connection, outside the caller's
async task. Its `QueryLogger` is created on that worker thread. Without explicit
command context propagation, request-local SQL counters cannot observe that
execution. Transaction controls also bypass `QueryLogger` and execute directly
through the native handle.

## Delta

- `src/connection/worker.rs`: extend the existing command/span envelope with the
  current request metrics for execution and awaited transaction commands, then
  enter/restore those metrics for that worker command. No identity, SQL, bind
  value, or error is added to telemetry context. Metadata/maintenance commands
  and detached drop-triggered or cancelled-BEGIN cleanup rollback have no
  request context. Timing begins on the worker, not when a command is queued.
  Execution timing is published before first-row or error replies, so a request
  completion cannot race its worker's counter publication.
- `src/connection/execute.rs`: construct `QueryLogger` before fallible statement
  cache/preparation setup so failed attempts also count once.
- `src/connection/handle.rs`: a request `QueryTimer` spans native `exec`, covering
  awaited BEGIN/SAVEPOINT/COMMIT/ROLLBACK and their failures. Commands with no
  request context do not update any counters.

Query timing uses the execution iterator/logger lifetime, including streaming
execution and backpressure; it is not SQLite server/VM CPU time. Pool acquisition
and initialization exclusions are implemented by the paired `sqlx-core` patch.
Explicit prepare/describe metadata operations are not counted as executions.

The root-workspace regressions are in
`tinycloud-core/tests/sqlx_request_telemetry.rs`. Remove this vendored crate and
its patch override once upstream SQLx supplies equivalent request context and
execution-boundary hooks.
