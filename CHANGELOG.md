# Changelog

## [1.3.0] - 2026-04-10

- Add `parseRecapFromSiwe` WASM export that parses a signed SIWE message and returns its recap capabilities as `{ service, space, path, actions }` entries. This is the inverse of the recap encoding done during session preparation and enables the SDK layer to perform capability subset checks for session-key-signed delegations (capability chain delegation).
- Add write-hooks support through Phase 4 for KV, SQL, and DuckDB, including SSE subscriptions plus webhook CRUD and durable delivery paths.

## [1.2.1] - 2026-03-17

- Fix SQL data loss: flush in-memory databases to file on actor shutdown.

SQL database actors start in-memory and only promote to file when data exceeds the 10 MiB memory threshold. Small databases never hit this, so when the actor idles out after 5 minutes, all data is silently lost. This adds a flush step on shutdown that persists any in-memory database to disk via the SQLite backup API, regardless of size.

## [1.2.0] - 2026-03-12

- Add `datadir` config to centralize all data paths under a single root directory.

Previously, database, blocks, SQL, and DuckDB paths each had independent hardcoded defaults. Now all derive from `storage.datadir` (default: `./data`). Set `TINYCLOUD_STORAGE_DATADIR=/var/lib/tinycloud` to relocate all data with one variable. Individual paths can still be overridden explicitly.
- Add dstack TEE support for confidential deployment. Keys can now be derived deterministically from TEE KMS, sensitive database columns are encrypted with AES-256-GCM, and a new `/attestation` endpoint provides TDX hardware attestation quotes. The `/version` endpoint now includes an `inTEE` flag. Enabled via `--features dstack`.
- Fix SQL database actor recovery: dead actors are now automatically removed from the registry and respawned on next request.

Previously, when a SQL actor died (idle timeout, panic), its dead handle stayed in the DashMap forever, causing all subsequent requests to that database to fail permanently with "Database actor not available". The actor now self-cleans from the registry on shutdown (matching the DuckDB actor pattern), and the service retries with a fresh actor when a dead handle is detected.

## [1.1.0] - 2026-03-09

- Add DuckDB analytical database service (tinycloud.duckdb/*) with per-space isolation, UCAN capability model, SQL parser security, Arrow IPC support, and binary export/import. Fix SQLite concurrency deadlock for concurrent requests.
- Add multi-space session support. SessionConfig accepts optional additionalSpaces so a single SIWE signature covers multiple spaces.
- Add vault WASM crypto functions (AES-256-GCM, HKDF-SHA256, X25519) and sanitize public endpoint metadata headers

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-02-01

Fix DID fragment normalization for consistent identity matching

- Add `strip_fragment()` helper in `util.rs` to normalize DID URLs to base DIDs
- Apply normalization to all DID fields: delegator, delegate, invoker, revoker
- Add actor insertion before invocation save to prevent foreign key constraint errors
- Fixes sharing link flow where DID URL fragments (`did:key:z6Mk...#z6Mk...`) caused mismatches with base DIDs (`did:key:z6Mk...`) in the actor table

