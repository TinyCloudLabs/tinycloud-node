# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0](https://github.com/TinyCloudLabs/tinycloud-node/compare/v0.0.1...v1.8.0) - 2026-07-20

### Added

- *(kv)* add bounded conditional CRUD primitives ([#128](https://github.com/TinyCloudLabs/tinycloud-node/pull/128))
- *(sql)* enforce bounded single-statement queries ([#127](https://github.com/TinyCloudLabs/tinycloud-node/pull/127))
- *(node)* local node CLI, control plane, keychain keys, and Homebrew packaging
- add account delegation history query (TC-178)
- *(policy-capability)* wire capability registry into live invoke/delegate paths (TC-119) ([#102](https://github.com/TinyCloudLabs/tinycloud-node/pull/102))
- meter SQL/DuckDB artifact bytes in store_size + enforce storage quota on write-class database requests ([#89](https://github.com/TinyCloudLabs/tinycloud-node/pull/89))
- add telemetry spans ([#76](https://github.com/TinyCloudLabs/tinycloud-node/pull/76))
- *(node)* support KV batch put invocations
- make DuckDB support opt-in ([#68](https://github.com/TinyCloudLabs/tinycloud-node/pull/68))
- add encryption network module
- TC-1368 Add signed KV URLs  ([#60](https://github.com/TinyCloudLabs/tinycloud-node/pull/60))
- add write hooks server support through phase 4 ([#44](https://github.com/TinyCloudLabs/tinycloud-node/pull/44))
- add per-space storage quotas with admin API ([#32](https://github.com/TinyCloudLabs/tinycloud-node/pull/32))

### Fixed

- *(node)* package LICENSE.md inside the crate so cargo-dist asset copy works
- *(db)* avoid epoch serialization conflicts (TC-212) ([#110](https://github.com/TinyCloudLabs/tinycloud-node/pull/110))
- *(quota)* add timeouts to sidecar quota client; bump 1.4.3 ([#91](https://github.com/TinyCloudLabs/tinycloud-node/pull/91))
- distinguish epoch-insert DB errors from missing spaces ([#90](https://github.com/TinyCloudLabs/tinycloud-node/pull/90))
- vendor openssl for aarch64 release builds ([#72](https://github.com/TinyCloudLabs/tinycloud-node/pull/72))
- update dstack GetKey response to match new API format ([#35](https://github.com/TinyCloudLabs/tinycloud-node/pull/35))

### Other

- *(release)* tinycloud-node 1.8.0
- gate tunnelConnected on process liveness like linkListener
- fix tunnel client SSRF, dead backoff reset, and reconnect-loop bugs
- make the tunnel-disabled sentinel a shared constant
- cap consecutive stale-sequence resyncs before backing off
- Merge main to pick up TC-250 link_listener pid-gating fix
- add tunnel integration tests against a mock relay
- wire tunnel enable/disable/status into the CLI and serve
- add the outbound tunnel WebSocket client
- add tunnel enable/disable/status commands
- extend link state.json with tunnel config + runtime marker
- add tunnel wire protocol, auth canonicalization, and reconnect policy
- add tokio-tungstenite dependency for the tunnel client
- align binstall metadata with cargo-dist artifacts
- *(release)* tinycloud-node 1.7.0
- Merge pull request #133 from TinyCloudLabs/skgbafa/tc-87-node-link
- 120s cert-request timeout + first-run ordering doc
- fix sequence protocol, 409 disambiguation, cert hot-reload + review polish
- fix link LAN listener bind wiring and CSR key algorithm
- tinycloud node link — LAN HTTPS via tinycloud.link
- *(tinycloud-node)* release v1.6.0 ([#124](https://github.com/TinyCloudLabs/tinycloud-node/pull/124))
- *(release)* tinycloud-node 1.5.0
- fix linting and homebrew audit blockers
- reconcile control plane permissions and contract
- harden system profile install and permissions
- reconcile control plane snapshot and logs
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-58-node-service
- include delegation history in v1.4.10 changelog
- Merge branch 'main' into release-plz-2026-07-16T04-32-31Z
- *(tinycloud-node)* release v1.4.9
- never block writes on the quota service (stale-while-revalidate) ([#104](https://github.com/TinyCloudLabs/tinycloud-node/pull/104)) ([#105](https://github.com/TinyCloudLabs/tinycloud-node/pull/105))
- *(tinycloud-node)* release v1.4.8
- *(tinycloud-node)* release v1.4.7
- Merge branch 'main' into release-plz-2026-07-13T19-02-35Z
- *(tinycloud-node)* release v1.4.6
- *(tinycloud-node)* release v1.4.5 ([#99](https://github.com/TinyCloudLabs/tinycloud-node/pull/99))
- *(tinycloud-node)* release v1.4.3 ([#95](https://github.com/TinyCloudLabs/tinycloud-node/pull/95))
- Add admin GET /admin/usage aggregate space usage endpoint (TC-108) ([#97](https://github.com/TinyCloudLabs/tinycloud-node/pull/97))
- Move database webhook delivery off write path
- Drop SQL DDL permission ([#84](https://github.com/TinyCloudLabs/tinycloud-node/pull/84))
- Accept sql schema permission ([#83](https://github.com/TinyCloudLabs/tinycloud-node/pull/83))
- Support SQL DDL capability ([#82](https://github.com/TinyCloudLabs/tinycloud-node/pull/82))
- Suppress duplicate invoke requests ([#81](https://github.com/TinyCloudLabs/tinycloud-node/pull/81))
- *(node)* cover policy runtime issued native read cutoff
- Close W1 native enforcement audit residuals ([#79](https://github.com/TinyCloudLabs/tinycloud-node/pull/79))
- Require SQL admin for PRAGMA ([#77](https://github.com/TinyCloudLabs/tinycloud-node/pull/77))
- *(tinycloud-node)* release v1.4.2 ([#73](https://github.com/TinyCloudLabs/tinycloud-node/pull/73))
- align owner DID terminology ([#69](https://github.com/TinyCloudLabs/tinycloud-node/pull/69))
- *(tinycloud-node)* release v1.4.1 ([#67](https://github.com/TinyCloudLabs/tinycloud-node/pull/67))
- *(tinycloud-node)* release v1.4.0
- *(tinycloud-node)* release v1.3.5
- *(tinycloud-node)* release v1.3.4 ([#64](https://github.com/TinyCloudLabs/tinycloud-node/pull/64))
- Persist SQL and DuckDB artifacts in storage database ([#62](https://github.com/TinyCloudLabs/tinycloud-node/pull/62))
- *(tinycloud-node)* release v1.3.3 ([#59](https://github.com/TinyCloudLabs/tinycloud-node/pull/59))
- *(tinycloud-node)* release v1.3.2 ([#57](https://github.com/TinyCloudLabs/tinycloud-node/pull/57))
- *(tinycloud-node)* release v1.3.1 ([#55](https://github.com/TinyCloudLabs/tinycloud-node/pull/55))
- *(tinycloud-node)* release v1.3.0 ([#51](https://github.com/TinyCloudLabs/tinycloud-node/pull/51))
- replace changesets with release-plz + cargo-dist ([#49](https://github.com/TinyCloudLabs/tinycloud-node/pull/49))
- version packages ([#46](https://github.com/TinyCloudLabs/tinycloud-node/pull/46))
- version packages ([#41](https://github.com/TinyCloudLabs/tinycloud-node/pull/41))
- version packages ([#30](https://github.com/TinyCloudLabs/tinycloud-node/pull/30))
- rename crates and reorganize workspace ([#31](https://github.com/TinyCloudLabs/tinycloud-node/pull/31))

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
