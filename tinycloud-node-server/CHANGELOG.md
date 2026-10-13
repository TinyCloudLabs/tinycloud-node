# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.20.4](https://github.com/TinyCloudLabs/tinycloud-node/compare/v0.0.1...v1.20.4) - 2026-10-13

### Added

- storage-full reads and structured storage errors, forward-port of #244 (TC-626) ([#245](https://github.com/TinyCloudLabs/tinycloud-node/pull/245))
- *(TC-908)* allow root kv sync
- *(TC-780)* port SQL identity cutover to production release line
- *(tc-780)* migrate legacy SQL identities through quarantined aliases
- *(TC-732)* ordered prefix-scoped KV change feed behind tinycloud.kv/sync ([#247](https://github.com/TinyCloudLabs/tinycloud-node/pull/247))
- *(TC-500)* integrate native sharing with TinyChat release ([#234](https://github.com/TinyCloudLabs/tinycloud-node/pull/234))
- *(TC-498)* authorize exact native share email delivery ([#229](https://github.com/TinyCloudLabs/tinycloud-node/pull/229))
- *(TC-500)* publish enforcer DID in readiness ([#221](https://github.com/TinyCloudLabs/tinycloud-node/pull/221))
- *(TC-500)* admit accountless policy presentations ([#218](https://github.com/TinyCloudLabs/tinycloud-node/pull/218))
- *(TC-470)* admit holder-bound policy credentials
- bind share decryption delegation ([#189](https://github.com/TinyCloudLabs/tinycloud-node/pull/189))
- owner-rooted sharing v2 registration ([#168](https://github.com/TinyCloudLabs/tinycloud-node/pull/168))
- support sharing experience flows
- *(TC-275)* add range-capable signed blob reads
- *(TC-272)* execute KV batch reads in one invocation
- export production Share invitation descriptor
- expose production share policy runtime
- integrate node share email trust bundle
- converge node email claim authority path
- inject authenticated share authority providers
- close node authority seam
- *(kv)* add bounded conditional CRUD primitives ([#128](https://github.com/TinyCloudLabs/tinycloud-node/pull/128))
- *(sql)* enforce bounded single-statement queries ([#127](https://github.com/TinyCloudLabs/tinycloud-node/pull/127))
- *(node)* local node CLI, control plane, keychain keys, and Homebrew packaging
- add account delegation history query (TC-178)
- *(auth)* add delegation status endpoint
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

- *(audit)* retry the one-statement PostgreSQL read audit after a lost connection (TC-951)
- *(pool)* classify 57P05 as a lost connection, retry only provably pure reads, recheck long-idle connections (TC-951)
- *(hooks)* re-authorize webhook subscribers at dispatch (TC-991) ([#274](https://github.com/TinyCloudLabs/tinycloud-node/pull/274))
- *(TC-961)* keep request URIs, signed-KV tickets and space IDs out of node logs (1.20.x) ([#262](https://github.com/TinyCloudLabs/tinycloud-node/pull/262))
- *(TC-899)* reserve the SQLite write lock when a graph transaction begins ([#268](https://github.com/TinyCloudLabs/tinycloud-node/pull/268))
- *(TC-908)* unify KV root authorization spellings
- *(TC-780)* align cutover with 1.19.2 and make abort paths operable
- *(TC-780)* reject remote host overrides in offline fingerprint mode
- *(TC-780)* make release cutover metadata-only and safe to roll back
- *(TC-730)* recheck hook ticket revocation at stream open; literal subscription prefixes; complete ancestor traversal (TC-815) ([#251](https://github.com/TinyCloudLabs/tinycloud-node/pull/251))
- *(TC-730)* recheck hook ticket revocation at stream open; literal subscription prefixes; complete ancestor traversal (TC-815) ([#251](https://github.com/TinyCloudLabs/tinycloud-node/pull/251))
- *(tc-780)* cache identity fence and stage Phala cutover
- *(tc-780)* harden SQL identity cutover and verification
- accept covering SQL delegation branches
- close TC-780 N2 SQL isolation review gaps
- *(TC-780)* isolate SQL and DuckDB by full resource path
- *(TC-541)* authorize hooks requests like other invocation routes ([#243](https://github.com/TinyCloudLabs/tinycloud-node/pull/243))
- *(TC-541)* list only webhook subscriptions inside the authorized scope
- *(TC-541)* spend a hooks ticket invocation only on success
- *(TC-541)* make hooks authorization read-only, replay-safe, and reset hook state
- *(TC-541)* authorize hooks requests like other invocation routes
- *(TC-731)* segment- and case-exact KV list prefixes; honour the read-only list cursor ([#246](https://github.com/TinyCloudLabs/tinycloud-node/pull/246))
- *(TC-500)* preflight sealed Node startup configuration ([#236](https://github.com/TinyCloudLabs/tinycloud-node/pull/236))
- withdraw meeting publication and restore legacy SQL writes
- serialize artifact saves with SQLite graph transactions
- serialize replay writes with SQLite graph transactions
- *(ci)* probe embedded Policy v3 routes (TC-500) ([#228](https://github.com/TinyCloudLabs/tinycloud-node/pull/228))
- *(TC-500)* retain embedded policy and remove share data routes ([#226](https://github.com/TinyCloudLabs/tinycloud-node/pull/226))
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
- *(TC-274)* satisfy current node clippy
- *(TC-275)* satisfy current node clippy
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
- *(node)* package LICENSE.md inside the crate so cargo-dist asset copy works
- *(db)* avoid epoch serialization conflicts (TC-212) ([#110](https://github.com/TinyCloudLabs/tinycloud-node/pull/110))
- *(auth)* reject qualified root control scopes
- *(auth)* bind control proofs to target scope
- *(auth)* require exact control proofs
- *(auth)* authorize wallet sessions through cited proofs
- *(quota)* add timeouts to sidecar quota client; bump 1.4.3 ([#91](https://github.com/TinyCloudLabs/tinycloud-node/pull/91))
- distinguish epoch-insert DB errors from missing spaces ([#90](https://github.com/TinyCloudLabs/tinycloud-node/pull/90))
- vendor openssl for aarch64 release builds ([#72](https://github.com/TinyCloudLabs/tinycloud-node/pull/72))
- update dstack GetKey response to match new API format ([#35](https://github.com/TinyCloudLabs/tinycloud-node/pull/35))

### Other

- *(release)* 1.20.4 ([#278](https://github.com/TinyCloudLabs/tinycloud-node/pull/278))
- *(node)* lower the round-trip budgets to the counts with #259 (TC-951)
- *(node)* 57P05, idle reaping, side-effecting SELECTs and a concurrent wave on the production pool (TC-951)
- *(hooks)* webhook dispatch survives lost pool connections without deactivating (TC-951, TC-991)
- *(node)* kill pooled Postgres connections and show requests recover (TC-951)
- *(node)* recover from lost pool connections without the pre-acquire ping (TC-951)
- *(node)* route the capability database through one pool connection type (TC-951)
- *(node)* budget PostgreSQL round trips for sign-in, KV put and KV get
- *(node)* skip the pre-acquire ping on the Postgres pool
- *(release)* 1.20.3 ([#275](https://github.com/TinyCloudLabs/tinycloud-node/pull/275))
- *(release)* 1.20.2 ([#271](https://github.com/TinyCloudLabs/tinycloud-node/pull/271))
- *(TC-957)* node refuses a cross-space account-index SQL grant ([#266](https://github.com/TinyCloudLabs/tinycloud-node/pull/266))
- Merge feat/tc-780-release-line (prod 1.20.1, 18caf93) into main (TC-940)
- *(TC-894)* keep the explicit empty KV path in ported test helpers
- *(release)* tinycloud-node 1.20.1 with TC-894, TC-908 and TC-910
- *(TC-894)* port TC-825 SQL/DuckDB chain-authority tests to 1.20
- Merge release line 1.19.2 into TC-780 cutover
- *(release)* tinycloud-node 1.19.2 with TC-730 and TC-815
- *(release)* tinycloud-node 1.19.1 with TC-541
- merge TC-541 hotfix into 1.19 release line
- *(release)* tinycloud-node 1.19.0 — kv/sync change feed and list fixes (TC-746) ([#248](https://github.com/TinyCloudLabs/tinycloud-node/pull/248))
- *(release)* tinycloud-node 1.17.4 (TC-541)
- *(release)* tinycloud-node 1.18.0 (TC-626) ([#244](https://github.com/TinyCloudLabs/tinycloud-node/pull/244))
- *(server)* cache CORS preflight responses with Access-Control-Max-Age ([#240](https://github.com/TinyCloudLabs/tinycloud-node/pull/240))
- *(release)* tinycloud-node 1.17.3 (TC-529, TC-530, TC-597) ([#239](https://github.com/TinyCloudLabs/tinycloud-node/pull/239))
- *(release)* tinycloud-node 1.17.1 (TC-500) ([#235](https://github.com/TinyCloudLabs/tinycloud-node/pull/235))
- *(release)* tinycloud-node 1.16.1 (TC-500) ([#232](https://github.com/TinyCloudLabs/tinycloud-node/pull/232))
- Merge branch 'workspace/tinychat-publication-v3-20260914' into Codex/roman/tinychat-native-release-20260915
- Bound authorization error sizes for current Rust Clippy
- Merge branch 'workspace/tinychat-publication-v3-20260914' into Codex/roman/tinychat-native-release-20260915
- Fix publication comparison lint and native formatting
- *(release)* prepare tinycloud-node 1.17.0
- Add temporary generation-checked legacy meeting write barrier
- Carry fixed publication commands on the existing SQL write ability
- Fence TinyChat meeting publication in native SQL and KV boundary
- *(release)* tinycloud-node 1.16.0 (TC-500) ([#227](https://github.com/TinyCloudLabs/tinycloud-node/pull/227))
- *(release)* tinycloud-node 1.15.2 ([#224](https://github.com/TinyCloudLabs/tinycloud-node/pull/224))
- *(release)* tinycloud-node 1.15.1 (TC-500) ([#222](https://github.com/TinyCloudLabs/tinycloud-node/pull/222))
- *(release)* tinycloud-node 1.15.0 (TC-500) ([#219](https://github.com/TinyCloudLabs/tinycloud-node/pull/219))
- *(release)* prepare Policy v3 node 1.14.0 (TC-465) ([#214](https://github.com/TinyCloudLabs/tinycloud-node/pull/214))
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-405-unified-delegation-resolver
- harden delegation runtime boundaries
- Merge pull request #207 from TinyCloudLabs/skgbafa/tc-467-weak-etag
- preserve ordinary authorization compatibility
- *(TC-467)* use weak comparison for If-None-Match
- checkpoint policy delegation resolver
- Merge pull request #204 from TinyCloudLabs/skgbafa/tc-294-conditional-get
- implement TC-409 optimization ([#200](https://github.com/TinyCloudLabs/tinycloud-node/pull/200))
- *(TC-294)* honor conditional GET before range errors
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-294-conditional-get
- accept emailOrigin in the trust bundle, and give the bundle a way into the container ([#188](https://github.com/TinyCloudLabs/tinycloud-node/pull/188))
- *(release)* 1.13.0 ([#186](https://github.com/TinyCloudLabs/tinycloud-node/pull/186))
- publish the node's derived share key, fail closed on mismatch, and let verify-full use the default trust roots ([#185](https://github.com/TinyCloudLabs/tinycloud-node/pull/185))
- bump to 1.12.0 for the chain-guard deploy ([#184](https://github.com/TinyCloudLabs/tinycloud-node/pull/184))
- cap the prod DB pool below the instance limit, bump to 1.11.0 ([#179](https://github.com/TinyCloudLabs/tinycloud-node/pull/179))
- verify and lifetime-cap invocations before the replay-cache write ([#178](https://github.com/TinyCloudLabs/tinycloud-node/pull/178))
- activate and refine invocation telemetry ([#176](https://github.com/TinyCloudLabs/tinycloud-node/pull/176))
- reconcile version to 1.10.0 across Cargo.toml, tag, and image ([#175](https://github.com/TinyCloudLabs/tinycloud-node/pull/175))
- TTL prune for terminal hook_delivery and expired signed tickets ([#172](https://github.com/TinyCloudLabs/tinycloud-node/pull/172))
- *(TC-294)* rebase conditional GET onto header allowlist
- Merge pull request #166 from TinyCloudLabs/skgbafa/tc-296-header-allowlist
- refresh share-email authority vectors
- *(TC-296)* allowlist stored object metadata headers
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-295-upload-buffer
- Merge pull request #164 from TinyCloudLabs/skgbafa/tc-285-response-streaming
- *(TC-294)* make signed response policies authoritative
- *(TC-294)* keep signed KV responses private
- Merge pull request #162 from TinyCloudLabs/skgbafa/tc-284-runtime-defaults
- Merge pull request #163 from TinyCloudLabs/skgbafa/tc-286-metrics-cardinality
- Merge pull request #161 from TinyCloudLabs/skgbafa/tc-283-release-profile-allocator
- *(TC-295)* enlarge upload copy buffer
- *(TC-285)* prove real responder streaming
- *(TC-294)* add conditional KV read caching
- *(TC-285)* prove response streaming on wire
- apply rustfmt to sharing route
- remove unused sharing route import
- Merge remote-tracking branch 'origin/main' into feat/sharing-experience-e2e
- *(TC-285)* fix streamed response chunking and headers
- *(TC-283)* enable release build optimizations and replace the musl allocator
- *(TC-285)* stream object responses in useful chunks
- *(TC-284)* fix shipped runtime defaults (log level, SQLite pragmas, blocking pool)
- *(TC-286)* bound Prometheus route-label cardinality
- *(tinycloud-node)* release v1.9.0
- *(tinycloud-node)* release v1.8.0
- Merge pull request #155 from TinyCloudLabs/skgbafa/tc-275-blob-data-plane
- Merge pull request #154 from TinyCloudLabs/skgbafa/tc-277-bench-image
- Merge main into TC-275 blob data plane
- Merge pull request #152 from TinyCloudLabs/skgbafa/tc-273-concurrent-read-audit
- build benchmark-enabled node image
- *(TC-273)* group-commit authenticated read audits
- make invocation replay protection durable
- Integrate sharing policy and native wire repairs
- add production invoke performance baseline
- keep live control status separate from service manager
- fix tc-bench routes mutability for feature-gated build
- align bench recap matcher with canonical reference
- align tc-bench matcher semantics
- TC-255 TC-256 bench conformance
- Merge main into feature/tc-231-bench-v1-endpoints
- keep fixture trust exception test-scoped
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
- fix linkListener false-stopped status and exclude VM bridges from LAN IPs
- repin email claim contract
- remove mounted SQL diagnostics
- trace mounted SQL read failure
- fix mounted invitation trace
- trace mounted invitation rejection
- remove mounted authorization diagnostics
- trace mounted read authorization
- remove mounted boundary diagnostics
- trace mounted read preflight
- align binstall metadata with cargo-dist artifacts
- trace mounted read denial
- trace mounted authority denial
- diagnose mounted policy session denial
- diagnose mounted authorization stage
- align mounted signer with frozen enrollment
- Harden email claim Node bindings and read responses
- Compose exact-email share authorization routes
- *(release)* tinycloud-node 1.7.0
- Merge pull request #133 from TinyCloudLabs/skgbafa/tc-87-node-link
- 120s cert-request timeout + first-run ordering doc
- fix sequence protocol, 409 disambiguation, cert hot-reload + review polish
- fix link LAN listener bind wiring and CSR key algorithm
- *(tinycloud-node)* release v1.6.1 ([#137](https://github.com/TinyCloudLabs/tinycloud-node/pull/137))
- tinycloud node link — LAN HTTPS via tinycloud.link
- *(tinycloud-node)* release v1.6.0 ([#124](https://github.com/TinyCloudLabs/tinycloud-node/pull/124))
- harden tc-bench nonce handling
- fix tc-bench health hashes and timing stages
- add tc-bench v1 endpoints
- *(release)* tinycloud-node 1.5.0
- fix linting and homebrew audit blockers
- reconcile control plane permissions and contract
- harden system profile install and permissions
- reconcile control plane snapshot and logs
- Merge remote-tracking branch 'origin/main' into skgbafa/tc-58-node-service
- include delegation history in v1.4.10 changelog
- Merge branch 'main' into release-plz-2026-07-16T04-32-31Z
- *(tinycloud-node)* release v1.4.10
- *(tinycloud-node)* release v1.4.9
- never block writes on the quota service (stale-while-revalidate) ([#104](https://github.com/TinyCloudLabs/tinycloud-node/pull/104)) ([#105](https://github.com/TinyCloudLabs/tinycloud-node/pull/105))
- *(tinycloud-node)* release v1.4.8
- *(tinycloud-node)* release v1.4.7
- Merge branch 'main' into release-plz-2026-07-13T19-02-35Z
- *(tinycloud-node)* release v1.4.6
- *(tinycloud-node)* release v1.4.5 ([#99](https://github.com/TinyCloudLabs/tinycloud-node/pull/99))
- *(tinycloud-node)* release v1.4.3 ([#95](https://github.com/TinyCloudLabs/tinycloud-node/pull/95))
- Add admin GET /admin/usage aggregate space usage endpoint (TC-108) ([#97](https://github.com/TinyCloudLabs/tinycloud-node/pull/97))
- wire systemd group access for control runtime files
- harden control auth and source-aware log cursors
- fix control runtime permissions and clearable storage limits
- add local control API listener and client wiring
- fix non-macOS compilation of keychain test helpers
- fix fmt gate, stop keychain item leakage from tests
- harden macos keychain fallback
- restore env config and doctor warnings
- revert file system rustfmt noise
- restore provider auto mode and keychain fallback
- keep sync node commands out of async runtime
- restore env key configuration
- fix macOS keychain fallback
- apply rustfmt cleanup
- tighten live control reporting
- add provider-backed identity storage
- use security-framework password helpers
- harden macOS keychain item attributes
- enable macOS security-framework feature flags
- finalize macOS keychain handling
- wire node identity through control plane
- add key provider backends
- make bootstrap config Rocket-parseable and surface config parse failures
- address CLI review findings (revert rename, publicApi source, manager labeling, install bootstrap config)
- address CLI review findings (revert rename, publicApi source, manager labeling, install bootstrap config)
- address CLI review findings (revert rename, publicApi source, manager labeling, install bootstrap config)
- update release automation for tinycloud-node-server
- wire node CLI JSON output
- add node control path and service management logic
- align package metadata with cargo smoke tests
- wire the tinycloud CLI and serve lifecycle
- add node control paths and service management
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
