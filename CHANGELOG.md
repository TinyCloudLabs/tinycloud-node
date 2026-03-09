# Changelog

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

