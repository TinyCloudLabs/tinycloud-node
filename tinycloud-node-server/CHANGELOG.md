# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.26.8](https://github.com/TinyCloudLabs/tinycloud-node/compare/v0.0.1...v1.26.8) - 2026-11-17

### Added

- *(TC-2917)* account replacement credits and reclaim checkpoint parts
- *(TC-2917)* add opt-in streamed SQL checkpoint parts
- *(TC-2917)* report disk headroom as a shipped log event and metrics
- *(TC-2961)* artifact read limit and a cap on concurrent large transfers

### Fixed

- *(TC-2986)* do not re-verify or re-evaluate a policy mint or registration under its locks
- *(TC-2917)* preserve statement caps and checkpoint backoff
- *(TC-2917)* isolate reclamation and permit non-growing replacements
- *(TC-2917)* round shipped headroom to 64 MiB, own log target, gate-reason tests
- *(TC-2986)* refuse a KV write mixed with a read on /invoke before any work; adopt review tests
- *(TC-2961)* save whole checkpoints in autocommit and remove the bulk statement scope
- *(TC-2961)* no back-off for a save still queued for its transfer slot; DuckDB 507; cap cross-check; review tests
- *(TC-2954)* bound PostgreSQL timeouts at INT_MAX and skip the session idle timeout in local mode
- default the idle-in-transaction timeout to 300 s and refuse values within the 240 s upload hold (TC-2954)
- end PostgreSQL transactions left idle for 15 s (TC-2954)

### Other

- Merge pull request #612 from TinyCloudLabs/hotfix/1.26.8-admin-secret
- Merge main (1.26.6) into hotfix 1.26.7 (TC-3076)
- *(tinycloud-node)* release 1.26.6
- Merge pull request #596 from TinyCloudLabs/feat/tc-2986-mint-no-revalidation
- Merge pull request #600 from TinyCloudLabs/skgbafa/tc-2917-disk-free-metric
- *(TC-2986)* a mint input changed before the locks refuses the mint
- Merge pull request #602 from TinyCloudLabs/fix/tc-2954-digest-tamper-flake
- *(TC-2954)* always change the tampered request digest's first character
- *(TC-2961)* pin the CAS revision and no-retry outcomes; warn on the removed bulk timeout; serialize large-transfer tests
- an ended idle transaction is one prompt connection-class error and one replacement connection (TC-2954)

- Preserve database failures during delegation and authorization lookups,
  including hook routes, as server errors. Transient failures before any
  data-plane write use `503 unavailable_retryable` instead of an authorization
  refusal (TC-2514).

- Recheck hook ticket delegation revocation when event streams open and use
  literal segment-prefix matching for hook subscriptions.

## [1.14.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.13.0...v1.14.0) - 2026-08-05

### Added

- Add the Policy/v3 owner-root registration, attested-enforcer binding,
  credential challenge, and ordinary delegation mint path
  ([#208](https://github.com/TinyCloudLabs/tinycloud-node/pull/208),
  [#209](https://github.com/TinyCloudLabs/tinycloud-node/pull/209)).
- Admit holder-bound OpenCredentials evidence into Policy/v3 delegation
  minting for the Share receiver flow
  ([#210](https://github.com/TinyCloudLabs/tinycloud-node/pull/210)).
- Add a synthetic end-to-end write probe for production health
  ([#195](https://github.com/TinyCloudLabs/tinycloud-node/pull/195)).

### Fixed

- Accept non-TinyCloud resource URIs in verifier capability extraction and
  expose the authority-matching verifier helpers
  ([#192](https://github.com/TinyCloudLabs/tinycloud-node/pull/192),
  [#213](https://github.com/TinyCloudLabs/tinycloud-node/pull/213)).
- Accept Blake3 delegation CIDs in the share-email claim path
  ([#198](https://github.com/TinyCloudLabs/tinycloud-node/pull/198)).
- Preserve Share delivery authorization across browser CORS preflight
  ([#190](https://github.com/TinyCloudLabs/tinycloud-node/pull/190)).

## [1.10.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.9.0...v1.10.0) - 2026-07-28

### Added

- Add owner-rooted sharing v2 registration
  ([#168](https://github.com/TinyCloudLabs/tinycloud-node/pull/168))
- Support sharing experience flows end to end
  ([#159](https://github.com/TinyCloudLabs/tinycloud-node/pull/159))

### Changed

- *(perf)* Add missing request-path secondary indexes
  ([#160](https://github.com/TinyCloudLabs/tinycloud-node/pull/160))
- *(perf)* Enable release build optimizations and replace the musl allocator
  ([#161](https://github.com/TinyCloudLabs/tinycloud-node/pull/161))
- *(perf)* Fix shipped runtime defaults (log level, SQLite pragmas, blocking pool)
  ([#162](https://github.com/TinyCloudLabs/tinycloud-node/pull/162))
- *(perf)* Bound Prometheus route-label cardinality
  ([#163](https://github.com/TinyCloudLabs/tinycloud-node/pull/163))
- *(perf)* Stream object responses in useful chunks
  ([#164](https://github.com/TinyCloudLabs/tinycloud-node/pull/164))
- *(perf)* Enlarge the upload copy buffer and fix partial-write hashing
  ([#165](https://github.com/TinyCloudLabs/tinycloud-node/pull/165))
- *(perf)* Allowlist stored object metadata headers
  ([#166](https://github.com/TinyCloudLabs/tinycloud-node/pull/166))

### Fixed

- Add revision CAS to full-checkpoint artifact save
  ([#169](https://github.com/TinyCloudLabs/tinycloud-node/pull/169))
- Use an ungrouped per-space `MAX(seq)` lookup in transact
  ([#170](https://github.com/TinyCloudLabs/tinycloud-node/pull/170))
- TTL prune for terminal `hook_delivery` rows and expired signed tickets
  ([#172](https://github.com/TinyCloudLabs/tinycloud-node/pull/172))

### Other

- *(ci)* Pin the phala CLI to 1.1.19 to unbreak the Phala deploy
  ([#171](https://github.com/TinyCloudLabs/tinycloud-node/pull/171))

## [1.9.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.8.0...v1.9.0) - 2026-07-25

### Added

- Add a reproducible production invoke performance baseline and stage-level
  instrumentation ([#147](https://github.com/TinyCloudLabs/tinycloud-node/pull/147))
- Execute KV batch reads in one authenticated invocation
  ([#151](https://github.com/TinyCloudLabs/tinycloud-node/pull/151))
- Add range-capable signed blob reads
  ([#155](https://github.com/TinyCloudLabs/tinycloud-node/pull/155))
- Add a benchmark-enabled node container image
  ([#154](https://github.com/TinyCloudLabs/tinycloud-node/pull/154))

### Changed

- Snapshot the authorization graph once per invocation
  ([#148](https://github.com/TinyCloudLabs/tinycloud-node/pull/148))
- Persist replay protection across restarts
  ([#150](https://github.com/TinyCloudLabs/tinycloud-node/pull/150))
- Materialize current KV state for direct reads
  ([#149](https://github.com/TinyCloudLabs/tinycloud-node/pull/149))
- Group-commit authenticated read audits
  ([#152](https://github.com/TinyCloudLabs/tinycloud-node/pull/152))
- Persist incremental SQL and DuckDB WAL artifacts
  ([#153](https://github.com/TinyCloudLabs/tinycloud-node/pull/153))

## [1.6.1](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.6.0...v1.6.1) - 2026-07-18

### Fixed

- *(sql)* allow schema-authorized `DROP TABLE` operations ([#134](https://github.com/TinyCloudLabs/tinycloud-node/pull/134))
- *(sql)* scope DDL authorization to the exact operation and database, rejecting unauthorized cascading writes ([#136](https://github.com/TinyCloudLabs/tinycloud-node/pull/136))

## [1.6.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.5.0...v1.6.0) - 2026-07-18

### Added

- *(kv)* add bounded conditional CRUD primitives ([#128](https://github.com/TinyCloudLabs/tinycloud-node/pull/128))
- *(sql)* enforce bounded single-statement queries ([#127](https://github.com/TinyCloudLabs/tinycloud-node/pull/127))

## [1.4.10](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.9...v1.4.10) - 2026-07-16

### Added

- add signed account-scoped delegation history queries with lifecycle filtering and pagination

### Other

- update Cargo.toml dependencies

## [1.4.9](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.8...v1.4.9) - 2026-07-16

### Fixed

- quota: never block writes on the quota service — stale-while-revalidate cache, bounded ≤3s first-sight fetch, fail-open to last-known/env default, failure backoff (#104, #105)
- clear clippy 1.97 lints in vendored siwe, tinycloud-auth, tinycloud-core (#118)

## [1.4.8](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.7...v1.4.8) - 2026-07-15

### Other

- update Cargo.toml dependencies

## [1.4.7](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.6...v1.4.7) - 2026-07-14

### Fixed

- prevent PostgreSQL epoch serialization conflicts during concurrent authenticated operations ([#110](https://github.com/TinyCloudLabs/tinycloud-node/pull/110))
- report retryable serialization failures and deadlocks as service-unavailable errors instead of authorization failures ([#110](https://github.com/TinyCloudLabs/tinycloud-node/pull/110))

## [1.4.6](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.5...v1.4.6) - 2026-07-13

### Other

- update Cargo.toml dependencies

## [1.4.5](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.4...v1.4.5) - 2026-07-08

### Other

- update Cargo.toml dependencies

## [1.4.4](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.3...v1.4.4) - 2026-07-04

### Other

- update Cargo.toml dependencies

## [1.4.2](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.1...v1.4.2) - 2026-06-08

### Fixed

- canonicalize PKH DID addresses ([#71](https://github.com/TinyCloudLabs/tinycloud-node/pull/71))
- vendor OpenSSL for aarch64 release builds ([#72](https://github.com/TinyCloudLabs/tinycloud-node/pull/72))

### Other

- align owner DID terminology ([#69](https://github.com/TinyCloudLabs/tinycloud-node/pull/69))
- hard migrate encryption owner did column ([#70](https://github.com/TinyCloudLabs/tinycloud-node/pull/70))

## [1.4.1](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.4.0...v1.4.1) - 2026-06-05

### Other

- update Cargo.toml dependencies

## [1.4.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.3.5...v1.4.0) - 2026-06-05

### Added

- Add the TinyCloud encryption network module and one-of-one decrypt flow.

## [1.3.5](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.3.4...v1.3.5) - 2026-06-05

### Added

- Add the TinyCloud encryption network module and one-of-one decrypt flow.

## [1.3.4](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.3.3...v1.3.4) - 2026-05-18

### Other

- update Cargo.toml dependencies

## [1.3.3](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.3.2...v1.3.3) - 2026-04-28

### Other

- update Cargo.toml dependencies

## [1.3.2](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.3.1...v1.3.2) - 2026-04-27

### Other

- update Cargo.toml dependencies

## [1.3.1](https://github.com/TinyCloudLabs/tinycloud-node/compare/v1.3.0...v1.3.1) - 2026-04-27

### Other

- update Cargo.toml dependencies

## [1.3.0](https://github.com/TinyCloudLabs/tinycloud-node/releases/tag/v1.3.0) - 2026-04-27

### Added

- add write hooks server support through phase 4 ([#44](https://github.com/TinyCloudLabs/tinycloud-node/pull/44))
- add per-space storage quotas with admin API ([#32](https://github.com/TinyCloudLabs/tinycloud-node/pull/32))

### Fixed

- update dstack GetKey response to match new API format ([#35](https://github.com/TinyCloudLabs/tinycloud-node/pull/35))

### Other

- replace changesets with release-plz + cargo-dist ([#49](https://github.com/TinyCloudLabs/tinycloud-node/pull/49))
- version packages ([#46](https://github.com/TinyCloudLabs/tinycloud-node/pull/46))
- version packages ([#41](https://github.com/TinyCloudLabs/tinycloud-node/pull/41))
- version packages ([#30](https://github.com/TinyCloudLabs/tinycloud-node/pull/30))
- rename crates and reorganize workspace ([#31](https://github.com/TinyCloudLabs/tinycloud-node/pull/31))
