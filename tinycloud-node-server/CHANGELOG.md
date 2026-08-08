# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.15.1](https://github.com/TinyCloudLabs/tinycloud-node/compare/v0.0.1...v1.15.1) - 2026-08-08

### Added

- *(TC-500)* publish enforcer DID in readiness ([#221](https://github.com/TinyCloudLabs/tinycloud-node/pull/221))
- *(TC-500)* admit accountless policy presentations ([#218](https://github.com/TinyCloudLabs/tinycloud-node/pull/218))
- *(TC-470)* admit holder-bound policy credentials
- bind share decryption delegation ([#189](https://github.com/TinyCloudLabs/tinycloud-node/pull/189))
- owner-rooted sharing v2 registration ([#168](https://github.com/TinyCloudLabs/tinycloud-node/pull/168))
- support sharing experience flows
- export production Share invitation descriptor
- expose production share policy runtime
- integrate node share email trust bundle
- converge node email claim authority path
- inject authenticated share authority providers
- close node authority seam
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

- *(TC-498)* authorize Policy v3 share notifications ([#217](https://github.com/TinyCloudLabs/tinycloud-node/pull/217))
- *(TC-470)* validate decrypted policy graph roots
- *(TC-470)* report policy admission failures precisely
- *(TC-470)* mint canonical policy session UCANs
- *(TC-470)* admit credential namespace authority
- *(TC-470)* serialize encryption network writes
- *(TC-470)* serialize policy writes with SQLite
- *(TC-470)* authenticate recipient credential space
- *(share-v2)* say which check denied a policy challenge ([#196](https://github.com/TinyCloudLabs/tinycloud-node/pull/196))
- allow authorization on Share delivery preflight ([#190](https://github.com/TinyCloudLabs/tinycloud-node/pull/190))
- *(share-v2)* TC-349 stop the readiness probe condemning a populated graph ([#181](https://github.com/TinyCloudLabs/tinycloud-node/pull/181))
- preserve sharing compatibility contracts
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
- *(db)* avoid epoch serialization conflicts (TC-212) ([#110](https://github.com/TinyCloudLabs/tinycloud-node/pull/110))
- *(quota)* add timeouts to sidecar quota client; bump 1.4.3 ([#91](https://github.com/TinyCloudLabs/tinycloud-node/pull/91))
- distinguish epoch-insert DB errors from missing spaces ([#90](https://github.com/TinyCloudLabs/tinycloud-node/pull/90))
- vendor openssl for aarch64 release builds ([#72](https://github.com/TinyCloudLabs/tinycloud-node/pull/72))
- update dstack GetKey response to match new API format ([#35](https://github.com/TinyCloudLabs/tinycloud-node/pull/35))

### Other

- *(release)* tinycloud-node 1.15.1 (TC-500) ([#222](https://github.com/TinyCloudLabs/tinycloud-node/pull/222))
- *(release)* tinycloud-node 1.15.0 (TC-500) ([#219](https://github.com/TinyCloudLabs/tinycloud-node/pull/219))
- *(release)* prepare Policy v3 node 1.14.0 (TC-465) ([#214](https://github.com/TinyCloudLabs/tinycloud-node/pull/214))
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-405-unified-delegation-resolver
- harden delegation runtime boundaries
- preserve ordinary authorization compatibility
- checkpoint policy delegation resolver
- Merge pull request #204 from TinyCloudLabs/skgbafa/tc-294-conditional-get
- implement TC-409 optimization ([#200](https://github.com/TinyCloudLabs/tinycloud-node/pull/200))
- accept emailOrigin in the trust bundle, and give the bundle a way into the container ([#188](https://github.com/TinyCloudLabs/tinycloud-node/pull/188))
- *(release)* 1.13.0 ([#186](https://github.com/TinyCloudLabs/tinycloud-node/pull/186))
- publish the node's derived share key, fail closed on mismatch, and let verify-full use the default trust roots ([#185](https://github.com/TinyCloudLabs/tinycloud-node/pull/185))
- bump to 1.12.0 for the chain-guard deploy ([#184](https://github.com/TinyCloudLabs/tinycloud-node/pull/184))
- cap the prod DB pool below the instance limit, bump to 1.11.0 ([#179](https://github.com/TinyCloudLabs/tinycloud-node/pull/179))
- verify and lifetime-cap invocations before the replay-cache write ([#178](https://github.com/TinyCloudLabs/tinycloud-node/pull/178))
- activate and refine invocation telemetry ([#176](https://github.com/TinyCloudLabs/tinycloud-node/pull/176))
- reconcile version to 1.10.0 across Cargo.toml, tag, and image ([#175](https://github.com/TinyCloudLabs/tinycloud-node/pull/175))
- TTL prune for terminal hook_delivery and expired signed tickets ([#172](https://github.com/TinyCloudLabs/tinycloud-node/pull/172))
- Merge pull request #166 from TinyCloudLabs/skgbafa/tc-296-header-allowlist
- refresh share-email authority vectors
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-295-upload-buffer
- Merge pull request #164 from TinyCloudLabs/skgbafa/tc-285-response-streaming
- Merge pull request #162 from TinyCloudLabs/skgbafa/tc-284-runtime-defaults
- Merge pull request #163 from TinyCloudLabs/skgbafa/tc-286-metrics-cardinality
- Merge pull request #161 from TinyCloudLabs/skgbafa/tc-283-release-profile-allocator
- apply rustfmt to sharing route
- remove unused sharing route import
- Merge remote-tracking branch 'origin/main' into feat/sharing-experience-e2e
- Integrate sharing policy and native wire repairs
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
