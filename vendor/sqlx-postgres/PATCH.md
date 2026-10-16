# TinyCloud patch to sqlx-postgres 0.8.6 (TC-959)

Source: crates.io `sqlx-postgres` 0.8.6, SHA-256
`db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46`.
The extracted package is otherwise unchanged; the registry-only `.cargo-ok`
marker is omitted. Root and excluded harness `[patch.crates-io]` entries select
this directory alongside the matching sqlx-core/sqlx-sqlite patches.

## Boundary

`src/transaction.rs`, `PgTransactionManager::begin`, creates a request
`QueryTimer` after nested-custom-BEGIN validation and before queueing the raw
BEGIN/SAVEPOINT. Its lifetime covers the actual awaited readiness response,
including failure and cancellation, after pool acquisition has completed.

These controls do not use SQLx's `QueryLogger`. SeaORM also calls this transaction
manager directly, bypassing SQLx's generic `Transaction::begin` wrapper. A hook
only in that wrapper therefore misses real node transactions. The core generic
wrapper is deliberately unchanged; the driver hook covers both callers without
double-counting. Awaited commit/rollback already execute through `QueryLogger`.
Detached drop/cancel-cleanup rollback is excluded, not timed as mere queueing.

No SQL, values, identities or error strings are copied into telemetry. A scope
without request metrics adds no query count or timer clock read. Connection
initialization/acquisition housekeeping is unscoped by sqlx-core's acquisition
hook, while its full elapsed time remains pool acquisition time.

## Evidence and removal

`tinycloud-core/tests/sqlx_request_telemetry.rs` exercises direct SQLx and direct
SeaORM transactions, controls, failures and pool exhaustion on local PostgreSQL.
The SeaORM regression failed before this hook with query_count=0 at successful
BEGIN. A real-node `/healthz` smoke exposed the same missing boundary; it reports
one BEGIN after this patch. See `docs/request-telemetry.md` for complete semantics.

Remove this vendored driver and its overrides once upstream SQLx provides an
equivalent driver-level request execution hook; removing only the generic wrapper
instrumentation is not an equivalent replacement.
