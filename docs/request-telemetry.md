# Request correlation and database telemetry

[TC-959](https://linear.app/tinycloud-labs/issue/TC-959), N2. This is node-source instrumentation, independent of N0's shipper/schema work and N1. It neither installs a shipper nor enables ingestion or a deployment. The aggregate Prometheus sampler is unchanged and is not the source of these request measurements.

## Request event

With INFO logging enabled, Rocket emits one `tinycloud::request` completion event per dispatched HTTP response. Use `TINYCLOUD_LOG__FORMAT=Json` and `TINYCLOUD_LOG_LEVEL=normal` for JSON output. There is no request-event sampling or source volume throttle. The event is emitted when the response has been constructed, before streaming its body; `latency_us` is not full body-transfer time.

| Field | Type / meaning |
| --- | --- |
| `event` | Fixed `node_request` |
| `svc` | Fixed `api` |
| `method` | Rocket HTTP method, preserving the incoming HEAD method |
| `route` | Mounted Rocket route template, including template query parameters; fixed `<unmatched>` for an unmatched request |
| `status` | Integer HTTP response status |
| `latency_us` | Nonnegative integer elapsed microseconds from the request fairing to response construction |
| `request_id` | Effective lowercase, hyphenated RFC-variant UUID, versions 1–8 |
| `request_id_replaced` | Boolean: rejected incoming value, not a replacement reason or rejected input |
| `account_hash` | Optional 64-lowercase-hex HMAC of the unique target space-owner DID |
| `space_hash` | Optional 64-lowercase-hex HMAC of the unique canonical target SpaceId |
| `pool_wait_ms` | Nonnegative numeric elapsed time inside actual pooled-connection acquisition |
| `query_time_ms` | Nonnegative numeric driver execution elapsed time; not database CPU time |
| `query_count` | Nonnegative integer execution-attempt count, including failed attempts and awaited transaction controls |

All production route handlers are wrapped, including generated request/data guards and responder construction. Request identity and counters are installed only for each future poll, restored on every return/yield, and explicitly carried to database workers. They are not globals keyed by a caller-supplied request ID. Reusing the same accepted UUID does not share counters between requests.

Request IDs and pseudonyms are event fields, never Prometheus labels. Methods, route templates, and status retain the existing bounded metric labels. No request URI, query text, SQL parameters, raw space/DID/wallet, or raw database error is added to the event. SQLx (including notices/pool errors), SeaORM, and sqlparser diagnostic output is filtered before all subscriber sinks, independently of log level. Request-related application database warnings use fixed operation/error classes instead of raw causes. HTTP error responses retain their existing behavior.

## UUID contract and forwarding

The canonical contract and exact corpus are `ops/logging/request-id.md` and `request-id-vectors.json` in tinycloud-dev at commit `76bd10752a52f179ac2a49214f488236d02f8192`. This repository vendors the corpus at `tinycloud-node-server/tests/fixtures/request-id-vectors.json`, SHA-256 `d995cd9065a9e1c51bc4d3ed041c3bf2a0363e9a04a90f1d07914437d8dd9a80`.

At the application-visible header boundary, accept exactly one complete 36-character hyphenated UUID, version 1–8 and variant `10xx`. Input hex is case-insensitive; echo, spans, events and forwarding use lowercase. Reject nil/max, other versions/variants, nonhex, wrong length, braces, URNs, unhyphenated forms, padding, comma lists and repeated fields, including identical repeated fields. Rejection mints a cryptographic UUIDv4 and sets `request_id_replaced=true`; absence also mints v4 but sets it false. Never record or echo the rejected value. Correlation is not authentication, ownership, authorization or an idempotency key.

The two test boundaries are intentional: all 30 canonical field-value cases run unchanged through Rocket's application-visible parser; all exact cases are also sent to the real binary as raw HTTP. Hyper removes HTTP optional whitespace and recognizes line delimiters before middleware sees field values. A physical padded header or a bare-LF line delimiter is therefore not an application-visible padded/newline value: the raw-HTTP test uses the corresponding canonical oracle for the fields Hyper actually presents. Application-visible padding/LF is still rejected by the unchanged corpus test. Invalid HTTP syntax may be rejected before Rocket creates a request; no request completion/echo is promised for a request the HTTP parser never dispatches. The implementation does not weaken HTTP parsing or log original wire bytes to recover this information.

Only quota HTTP calls currently forward correlation, and only after **explicit** first-party origin classification:

```toml
[global.log]
request_id_first_party_origins = ["http://billing.internal:9000"]
```

The equivalent environment value is `TINYCLOUD_LOG__REQUEST_ID_FIRST_PARTY_ORIGINS='["http://billing.internal:9000"]'`. The list defaults empty. Configuring `TINYCLOUD_QUOTA_URL` alone does not classify its destination first-party. Entries must be HTTP(S) origins only, without credentials, paths, queries or fragments. Matching includes scheme, canonical host and effective port, not host suffixes or paths. Classification is resolved at startup, not from request input. Invalid origin configuration fails startup/config preflight without rendering its raw value.

Quota clients disable automatic redirects, including same-origin redirects. A cold synchronous lookup forwards the effective ID only to a listed origin. A deferred quota refresh may retain that UUID for the same classified HTTP call, but never the request's database counters. Webhooks, S3, Unix sidecars and SSI-owned opt-in network resolution receive no added request ID. The legacy `SpaceAllowListService` has no live production caller in current application composition and remains unchanged/unclassified; it does not forward correlation.

## Stable target pseudonyms

The key comes from the node's **existing resolved** `StaticSecret`: static configuration, the existing dstack application key `tinycloud/keys/primary`, or the existing key-provider resolution into that same setup. Startup already requires this key source. N2 neither reads a new credential nor generates a fallback key.

Derive `K = key_setup.derive_key(b"tinycloud/telemetry/pseudonyms/v1")` using the existing domain-separated node-key pattern, then:

- `account_hash = hex_lower(HMAC-SHA256(K, b"account\0" || canonical_space_owner_DID))`
- `space_hash = hex_lower(HMAC-SHA256(K, b"space\0" || canonical_SpaceId_display))`

The canonical SpaceId display includes `tinycloud:` and the canonical DID suffix/name. PKH addresses use the parser's checksum canonicalization; do not lowercase identity input. The account is the resource's space owner, **not** a session signer, policy owner, receiver, ticket ID, network ID, CID or arbitrary asserted Authorization issuer. A public target's pseudonym does not authenticate its caller.

Hashes survive process restarts with the same node key; rotating that key rotates pseudonyms. No common key or cross-service join scope is assumed. The context retains only two bounded keyed digests and conflict state, not raw identities. Repeated observations deduplicate by digest. Two spaces of one owner omit `space_hash` but retain `account_hash`; different owners omit both. A later observation cannot overwrite ambiguity. Unknown or unverified target identity is omitted rather than substituted.

Observation points cover admitted invocation resources, verified delegations and their existing-row fast path, authorized affected revocation spaces, public KV targets after the public-space gate, validated signed-ticket scope, hook scopes, validated policy roots, authenticated admin targets/usage enumeration, quota refusals and host-key staging. Invalid/expired tickets, refused private public-route targets and unverified policy registration do not establish identity there. Encryption-only resources without a SpaceId remain unattributed. No additional database lookup or delegation walk is performed for logging.

## Database path coverage

Pool acquisition and SQL execution are measured separately at their real boundaries. Acquisition includes semaphore wait, connection establishment, health/revalidation and acquisition hooks, including timeout, closed-pool and cancellation paths. SQL performed solely to prepare/check a pooled connection is excluded from query counters, not misclassified as user SQL; its elapsed time remains acquisition time. A failed acquisition therefore has wait time but zero query attempts. Driver timers start after acquisition, never by subtracting process-wide metric aggregates.

SQLx query timing follows the execution/logger lifetime, including network I/O and streamed-result backpressure. Native rusqlite/DuckDB timers wrap prepare/execute/query/step calls and pause around result/JSON/Arrow formatting. These are elapsed client-observed execution times, not server CPU or exclusive resource costs. A count is one driver execution lifecycle/native execute or execute_batch call, not the number of semicolon-separated statements in a batch string. Rejection before a driver SQL attempt does not fabricate a query.

| Path | Boundary and attribution |
| --- | --- |
| Shared SQLite capability pool | `vendor/sqlx-core` acquisition plus `vendor/sqlx-sqlite` worker envelopes/execute iterator/native transaction controls; timing is published before first-row/error replies |
| Shared PostgreSQL capability pool | `vendor/sqlx-core` acquisition/query logger plus `vendor/sqlx-postgres` raw BEGIN/SAVEPOINT boundary; covers both SQLx callers and SeaORM's direct transaction-manager calls |
| Shared MySQL capability pool | Common SQLx acquisition/query logger; its awaited transaction controls use that logger. Compiled coverage; no local MySQL-server integration proof is claimed |
| Recovery and retry | Hooks lie below `RecoveringConnection`; failed and successful retry attempts each contribute. Existing retry policy is unchanged |
| Acquired connections, nested transactions, unprepared SQL, bulk artifact transactions | Same concrete driver hooks; a raw SeaORM transaction cannot bypass the driver instrumentation |
| Delegation, invocation, revocation, epochs and authority graph | Shared capability pool, including failure paths and sequence/chain-lock SQL |
| KV read/write/list/metadata/sync and public/signed access | Shared pool for graph, metadata, change feed and ticket work; block bytes are not SQL |
| Policy-v3, hooks/tickets/subscriptions, encryption persistence, replay INSERT | Shared pool for all request-owned database operations |
| Quota/admin | In-memory overrides and size mirrors do not invent queries; usage/hosted-space enumeration and any actual pool work are counted |
| SQL/DuckDB identity/fence/alias resolution and durable artifact load/save/CAS/delta | Shared pool, including PostgreSQL bulk scopes; cache hits perform only their actual work |
| Request-awaited read audit | Separate measured batch context, fanned out before durable receipts; details below |
| User SQL rusqlite actor | Context on every work message; actual statement/schema/batch/growth-control SQL, prepare/constraint errors, cold-open PRAGMAs, size/promotion/checkpoint SQL |
| SQL publication | The current withdrawn publication handler executes no SQL; it is not an uninstrumented database path |
| Optional DuckDB actor | Context on every message; JSON/Arrow queries, schema/batch/transaction/growth/catalog SQL, security settings and promotion/copy/describe SQL |
| DuckDB import/cold export blocking workers | Explicit worker context for validation/security/checkpoint/copy SQL; artifact repository work is measured separately by SQLx |
| `/healthz` | Real BEGIN is counted. Its drop-triggered rollback is detached cleanup, excluded below |
| `/version`, `/info`, public node-key descriptions and CORS | No database work: known numeric zeros, no borrowed maintenance counters |

### Shared read-audit batches

An authenticated read waits for `ReadAuditPipeline`'s durable commit. Multiple requests can share one physical batch, so assigning its work only to the first request or subtracting a global counter would be wrong. Each command carries its request context. Persistence executes under an independent batch-local counter at the same physical driver hooks, after the queue/writer-lock wait. Completed totals, including failure attempts, are charged once to each pointer-distinct participating request **before any receipt is sent**. Repeated commands from one context do not duplicate its charge. Unrelated requests remain untouched.

Each participant receives the full physical batch's execution/wait/count contribution. Consequently these per-request metrics are **non-additive across requests**: summing them is not physical database throughput, CPU consumption, billing cost or unique query count. They describe the measured batch work on which each response depended.

### Inspected exclusions and limits

- Detached drop/cancellation-cleanup rollback and connection-release health/close work: may complete after the response. Awaited BEGIN/SAVEPOINT/COMMIT/ROLLBACK is counted; queueing detached rollback is not mislabeled execution.
- Database startup/migrations/SQL-size seeding and the separate offline SQL-identity CLI: no HTTP request context.
- Periodic pool sampler, replay cleanup, retention sweeper, webhook dispatcher and egress refresh: detached maintenance, not whichever HTTP request runs concurrently.
- Detached post-commit SQL/DuckDB webhook enqueue: does not mutate a response's finalized counters. Synchronous KV post-commit hook reads remain counted.
- SQL/DuckDB operation locks, actor queues, parser/admission work, native connection open/implicit close, filesystem/WAL/blob I/O and result formatting: not SQL execution time.
- SQLite native backup and DuckDB native appender transfer: native non-SQL operations, explicitly not fabricated SQL attempts. Explicit checkpoint/catalog/copy SQL is counted.
- Explicit SQLx prepare/describe metadata APIs: not execution attempts. Preparation performed as part of an execution, including its errors, is counted.
- Unmounted legacy Share-v1 and custom-cfg legacy Share-v2 are not current production routes. Their database calls would require a request scope if composed separately; N2 does not pretend they are mounted.
- SSE/KV response-body transmission occurs after event construction. Current streams do not perform new database queries after that boundary.

These are defined SQL/acquisition measurements, not a claim that a zero query count means no filesystem, native database-transfer, network or CPU work occurred.

## Verification

The real-binary suites use only synthetic identities, isolated configuration/data and local HTTP stubs. They check accepted/minted UUIDs, the shared corpus and replacement flag, one bounded event per response, canonical keyed hashes, restart stability, failures, authenticated KV/SQL work, concurrency isolation, first-party positive propagation, unclassified-origin and redirect negative controls, and complete stdout/stderr canaries at DEBUG/TRACE. Core regressions cover actual SQLite/PostgreSQL acquisition, direct SeaORM transactions, worker scopes, native actor errors and shared audit fanout.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
TINYCLOUD_TEST_POSTGRES_URL=<isolated-local-postgres> cargo test --workspace
TINYCLOUD_TEST_POSTGRES_URL=<isolated-local-postgres> cargo test -p tinycloud-core --features duckdb
```

The existing full workspace suite requires PostgreSQL 16+ with ICU collation support; PostgreSQL 14 cannot run its existing ICU `rules` regression. The existing privileged black-hole tests additionally require their explicit opt-in and host/network authorization; they are not implied by a telemetry smoke or a shared build slot. Never point tests at production databases. No local Docker proof, production ingestion, deployment or merge is implied by these commands.
