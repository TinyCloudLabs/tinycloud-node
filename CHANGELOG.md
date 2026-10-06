# Changelog

## [Unreleased]

## [1.19.0] - 2026-10-05

- KV list prefixes are segment- and case-exact: a `tinycloud.kv/list` on `docs` no longer lists `docsecret/...` (or, on SQLite, `DOCS/...`), wherever lists run, including public `GET /public/<space>/kv?prefix=`. A list-only invocation now honours its cursor instead of returning page 1 forever, and a cursor outside the listed prefix is a 400 (TC-731). A cursor sent with more than one `kv/list` capability is now a 400, and the list cursor is checked before any write in the same invocation (TC-732).
- Add `tinycloud.kv/sync`: an ordered, resumable, delete-aware feed of the latest state of every key under a KV prefix, served through `/invoke` and advertised as the `kv-sync-v1` feature in `/info`. It must be granted explicitly; no wildcard or default session implies it. Responses carry a node-attested `authority` window, and a separate, never-invoked `tinycloud.kv/retain` grant named in `x-tinycloud-retention-grant` adds `retainUntil`. See `docs/kv-sync.md` (TC-732).
- A KV invocation may carry at most 4096 mutations (`kv/put` plus `kv/del`); larger ones are refused with 400 `{"error":{"code":"TOO_MANY_MUTATIONS","max":4096}}`. HTTP/1's request-header limit already caps an invocation at roughly 2,400 puts, so existing batches are unaffected; the cap bounds HTTP/2 over TLS (TC-732).
- Writes to one space are now serialized through commit, so per-space event sequence numbers are unique and commit-ordered on PostgreSQL. Previously, concurrent writers in one space shared sequence numbers (45–161 duplicated `(space, seq)` groups per 640 writes in the benchmark). Measured with `postgres_kv_write_throughput` (release build, PostgreSQL 16, 640 puts per cell, median of 4 interleaved runs), same-space write throughput drops from 99 to 77 ops/s at 8 writers and from 309 to 89 ops/s at 32 writers with S3 block storage (from 135 to 93 and from 402 to 180 ops/s with in-memory blocks). Writes spread across spaces are unaffected. The S3 upload runs inside the serialized section (TC-732).
- Rolling deploys: commit ordering holds only once every node process sharing a database runs this version. While older processes still write to the same PostgreSQL, they assign sequence numbers without the lock, and `kv/sync` clients can miss changes. Upgrade every replica before relying on `kv/sync` (TC-732).
- Conditional KV writes (`If-Match`, `If-None-Match: *`) run under READ COMMITTED behind the space lock instead of SERIALIZABLE; a conflicting write is a 412, and the retryable 503 serialization-conflict response is gone (TC-732).

## [1.18.0] - 2026-10-05

- Return structured storage-full 402/413 JSON with the existing message, space usage and optional billing account totals; authenticate quota fetches with `TINYCLOUD_ADMIN_SECRET` (TC-626).
- Add the authenticated `tinycloud.space/info` usage read through `/invoke`, including the billing management URL. Existing sessions need explicit authority for this read (TC-626).
- Allow non-growing SQLite writes at full storage with rollback on page growth, and allow DuckDB deletes, drops and existing `IF NOT EXISTS` objects. Checkpoint guarded writes without accumulating WAL charges and preserve rejected-write rollback across rehydration (TC-626).
- Harden full-storage guards against SQLite transaction escapes and partial failed requests; keep absent-database no-ops uncharged and reject serialized SQLite/DuckDB artifact growth. Recheck delegated authority at the current time before returning delayed storage rejections (TC-626).
- Close the full-space export bypass: discard absent SQLite/DuckDB actors after rejected guarded requests and return `DatabaseNotFound` for exports without a durable artifact. DuckDB exports no longer persist checkpoints or alter the live WAL base (TC-626).

## [1.17.4] - 2026-10-06

Security hotfix on the 1.17.3 line; contains TC-541 only.

- `/hooks/tickets` and `/hooks/webhooks` authorize every request like `/invoke`: signature, lifetime cap, delegation chain, revocation, time windows and the Policy/v3 gate are checked before any scope is read. A claimed capability is no longer trusted; clients must hold a delegated `tinycloud.hooks/*` ability for the scope they request. Authorization is read-only: a refused request writes nothing, and the invocation is spent in the replay cache only when the request succeeds. Unregistering a subscription the caller may not touch returns the same 404 as a missing one (TC-541).
- The `m20261005_000000_deactivate_hook_subscriptions` migration deactivates every existing webhook subscription, since rows registered before this fix cannot be re-verified. Pending deliveries dead-letter as "subscription inactive"; owners must re-register. The migration is irreversible (TC-541).
- The hook ticket MAC key moves to the `tinycloud/hooks/tickets/v2` derivation context, so tickets minted before this release stop verifying and clients must mint new ones (TC-541).
- `GET /hooks/webhooks` returns only subscriptions inside the authorized scope. Its prefix filter was an unescaped SQL `LIKE`, so `_`, `%` and ASCII case differences let a list grant return other subscribers' rows, including their `callbackUrl` and `subscriberDid` (TC-541).
- Roll-forward only: 1.17.3 refuses to start on a database this release has migrated (`Migration file of version 'm20261005_000000_deactivate_hook_subscriptions' is missing`). An emergency rollback requires deleting that row from `seaql_migrations` first. Subscriptions stay inactive, but rolling back reopens TC-541.
- Accepted residual: an open `/hooks/events` stream's ticket is bounded by its immediate parent delegation's expiry and `hooks.max_ticket_ttl_seconds` (300 s by default), not by ancestors, so revoking a delegation can take up to 300 s to stop a stream that is already open, or a reconnect with an unexpired ticket (TC-541).

## [1.17.3] - 2026-10-01

- Policy/v3 sessions can be long-lived. `/policy/v3/delegations` accepts an optional `requestedExpiresAt`, bounded by the policy, its roots and, on the account path, the account authorization. Requests without it keep the 60-second session, so deployed SDKs are unchanged. Each policy invocation is still capped at 60 seconds and re-checks root liveness and revocation (TC-529).
- Policy-session chains can be re-delegated beyond one hop: each descendant is admitted against its immediate parent (TC-529).
- The encryption decrypt route and `/signed/kv` apply the same policy gate as `/invoke`, so a revoked or expired policy also stops them (TC-529).
- Email-domain shares can be emailed. Delivery authorization admits any canonical mailbox at exactly the policy's domain, names it in the Node-signed admission, and accepts the request only from the policy owner's key. The envelope's `deliveryEmail` is optional, and any share that grants read can be emailed (TC-530).
- Pin the 300-second credential freshness for the `tinycloud.email-domain-proof/v1` profile (TC-500).
- Policy registration requires the policy owner to hold every capability its roots grant, as root authority or through its own delegations, checked by the same rules as an invocation. Minting checks the same as of the policy's registration time, which covers earlier registrations too (TC-597).
- Exact-email delivery keeps the 1.17.2 contract for mixed-case mailboxes. Only email-domain deliveries require the canonical lowercase mailbox (TC-530).

## [1.17.2] - 2026-09-15

- Withdraw meeting publication v3 mutations and restore ordinary SQL authorization for legacy meeting catalogs. Capabilities report the withdrawn features as unavailable; existing legacy write pauses remain inspectable and releasable with their exact generation. Existing snapshot protection and applied migration history are retained for safe recovery.
- Preserve the 1.17.1 sharing changes and SQL artifact persistence fixes. This compatible rollback does not automatically modify meeting records or release existing pauses.

## [1.17.1] - 2026-09-15

- Integrate the reviewed native sharing correction into the TinyChat production lineage: exact-email delivery is authorized by embedded Policy v3, retries preserve strict request-body, JTI, and sender-DID replay binding, and recipient access remains scoped to the ordinary `/delegate` then `/invoke` storage-enforcer path. TinyChat meeting publication, legacy write guards, and digest-pinned deployment are unchanged (TC-500, #234).

## [1.17.0] - 2026-09-15

- Box large unauthorized resource payloads for current Rust Clippy checks; the two Rust error constructors now take `Box<Resource>`, with unchanged authorization decisions and error messages.
- Add the fixed TinyChat meeting publication v3 boundary: conditional reservation and publication, immutable digest-verified snapshots, retained aliases, and idempotent cleanup. Activation is explicit and fences legacy catalog writes; it does not automatically convert old records.
- Add a per-space pause for legacy meeting artifact writes with generation-checked freeze/release controls. The pause drains earlier KV commits, persists across restart, preserves ordinary chat and native snapshot publication, and remains releasable when content storage is full. This adds the central `meeting_legacy_write_guard` migration. Older binaries that do not recognize that migration cannot be used as a direct rollback; activated catalogs also require the compatible publication protocol.
- Preserve integral, fractional and null legacy REAL durations during meeting reservation and publication.
- Serialize SQLite graph transactions for invocation replay and SQL artifact persistence to avoid competing local writers.

## [1.16.0] - 2026-08-21

- Embed Policy v3 admission and control in the Node and move its routes off the Share namespace: `/share/v3/{policy/challenges,policy/delegations,policies,enforcer-bindings,deliveries/authorize,policy/status}` are now Node-owned `/policy/v3/{challenges,delegations,policies,enforcer-bindings,deliveries/authorize,status}`. Browser holder-bound exact-email credentials are admitted there, and the delegation the Node mints is then exercised over the ordinary `/delegate` and `/invoke` data plane, so no Share-specific data path remains on the Node (TC-500).
- Remove every mounted `/share/*` route. The `/share/v1/*` share-email routes and the legacy `/share/v2/*` runtime are gone — the latter retired ahead of its 2027-01-05 read cutoff — along with the Share-specific `application/vnd.tinycloud.delegation+json` and `application/vnd.tinycloud.share+json` handlers on `/delegate` and `/invoke`. `/info` and `/version` no longer report the `shareEmail` and `shareV2` descriptors or the `share-email-claim` and `share-v2` feature flags. This breaks any client still calling those paths, so it is a coordinated hard cutover: Node 1.16.0 and the paired Share release roll out, and roll back, together (TC-500).

## [1.15.2] - 2026-08-13

- Fix the per-app SQL/DuckDB artifact store's cold-start hydration path: hydration is now serialized per `(space, db)` (per-key singleflight with a double-checked actor re-check), cache writes use unique temp paths with magic-byte validation instead of the colliding `.db.tmp` name, and saves carry a content-lineage CAS (`StaleLineage`) so a stale actor re-hydrates instead of silently reverting an app database to an old checkpoint and persisting it. Adds checkpoint-shrink warnings and load-side artifact logging; artifact blobs that fail validation now error loudly at hydration instead of silently serving stale data (#223).

## [1.15.1] - 2026-08-08

- Publish the runtime Policy v3 enforcer DID from `/share/v2/readiness`, allowing Share to bind joined accountless receiver proofs to the exact deployed Node authority instead of a configured guess (TC-500).

## [1.15.0] - 2026-08-07

- Add strict accountless `PolicyCredentialPresentation/v4` admission for canonical Ed25519 `did:key` recipients. The Node independently verifies the issuer credential, exact requirement, fresh holder proof, challenge, audience, expiry, replay key, and requested capability ceiling before minting the existing ordinary S0 delegation to the receiver key. Legacy account-backed v3 admission remains byte-compatible (TC-500).
- Bind v4 audit correlation to domain-separated credential-ID and presentation-JTI digests without disclosing either raw identifier, and prove the resulting delegation through ordinary `/delegate` and same-holder `/invoke` paths (TC-500).
- Authorize Policy v3 share notifications against the enrolled runtime/enforcer binding and harden the production deploy probes for the complete Policy v3 route set (TC-498, TC-465).

## [1.13.0] - 2026-07-29

- Add `GET /.well-known/tinycloud/node-keys`, publishing the node's `nodeDid` and `shareInvitationPublicKey` (public halves only, unauthenticated, read-only). The share invitation key is derived inside the CVM from the dstack KMS, and until now no route exposed it — so `share.tinycloud.xyz` published a hardcoded development fixture as `nodeInvitationPublicKey` and every invitation it composed was rejected by verifiers. The route is correct under every `Keys` backend including `Dstack`, and is deliberately independent of the share-email runtime so the key can be read before `shareEmail.enabled` is turned on (TC-359).
- `share_v2::compose` now refuses to build a runtime when the configured invitation key is not the key the node actually signs with. Previously nothing compared the two, so a mismatch surfaced only as silent non-delivery: composition succeeded, readiness reported `ready: true`, invitations were minted and signed, and every verifier rejected them. The check only runs when share-email is enabled (TC-359).
- `validate_database_tls` no longer requires `root_cert_path` to point at an existing file when `sslmode=verify-full`. A managed database whose certificate chains to a public CA has no bundle to point at, which made this boot-fatal gate impossible to satisfy. `verify-full` remains mandatory and `require`, `verify-ca`, `disable` and a missing `sslmode` are all still refused; only the source of the trust roots changed, falling back to sqlx's default webpki/Mozilla anchors. An explicitly configured bundle is still honoured and must still resolve (TC-363).

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
