# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
