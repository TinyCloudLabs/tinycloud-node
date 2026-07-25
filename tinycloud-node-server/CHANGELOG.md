# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v0.0.1...v1.8.0) - 2026-07-25

### Added

- export production Share invitation descriptor
- expose production share policy runtime
- integrate node share email trust bundle
- converge node email claim authority path
- inject authenticated share authority providers
- close node authority seam

### Fixed

- *(TC-274)* satisfy current node clippy
- use vendored email claim test paths
- make node CI contract fixtures deterministic
- fix CI control assertions and hermetic email fixture
- fix CI server module and test compilation
- fix CI async tests and server clippy
- fix CI for verifier wasm and share email runtime
- include mounted n4 crate in Docker planner
- require shared trust bundle in node production
- mount shared email trust bundle
- restore frozen node share route surface
- harden share email node deployment
- align authority audit with canonical root time
- bind policy recipient digest to email bytes
- bind holder session to challenge body
- avoid release diagnostic warnings
- keep mounted authorization diagnostics compilable
- pin node email vectors to authoritative manifest
- align email claim wire responses
- reconcile node email claim authority bridge
- close email claim node review blockers

### Other

- Merge pull request #155 from TinyCloudLabs/skgbafa/tc-275-blob-data-plane
- Merge pull request #154 from TinyCloudLabs/skgbafa/tc-277-bench-image
- Merge pull request #152 from TinyCloudLabs/skgbafa/tc-273-concurrent-read-audit
- *(TC-273)* group-commit authenticated read audits
- keep live control status separate from service manager
- keep fixture trust exception test-scoped
- repin email claim contract
- remove mounted SQL diagnostics
- trace mounted SQL read failure
- fix mounted invitation trace
- trace mounted invitation rejection
- remove mounted authorization diagnostics
- trace mounted read authorization
- remove mounted boundary diagnostics
- trace mounted read preflight
- trace mounted read denial
- trace mounted authority denial
- diagnose mounted policy session denial
- diagnose mounted authorization stage
- align mounted signer with frozen enrollment
- Harden email claim Node bindings and read responses
- Compose exact-email share authorization routes

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
