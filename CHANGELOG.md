# Changelog

## [Unreleased]

### Changes

- `POST /revoke` authorizes the delegation's issuer, the owner of a space its abilities target, or the holder of a revoke control grant issued by one of them. The delegatee alone is no longer an authorized revoker, directly or through a control grant it issued; an intermediate delegator still revokes the delegations it issued. Delegation status visibility is unchanged (TC-1436).
- An owner can activate a parentless `tinycloud.delegation/revoke` grant on exactly `urn:cid:<target>` (for example the CLI's raw-CID revoke permission) when the stored target's abilities name a space the owner owns. Every non-root capability of such a grant must be one of these. Unknown targets, targets without abilities, and signers who are only the target's delegator or delegatee are refused with `Cannot find parent delegation` (TC-821).
- Revocation and delegation status accept a canonical CID that names a stored historical encoding. An exact-CID revoke or status grant covers every stored encoding of its target. The signed CID is kept as signed, and authorization uses the stored row (TC-821).

## [1.21.0] - 2026-10-18

### Release notes

- Request telemetry (TC-959 N2): no measurable latency change in a 10-pair A/B; CPU per request about +2% (median, within noise).
- **Rollback is restore-only.** Four migrations are unknown to v1.20.x (m20261014 delegation_cid_alias #291, m20261015 delegation_cursor_index #296, m20261017 epoch_order_space_index #341, m20261018 epoch_head #343); a binary-only rollback to v1.20.x is unsupported.
- The epoch_head backfill ships disabled (`TINYCLOUD_EPOCH_HEAD_BACKFILL__ENABLED=false`); it's enabled later once DB CPU has headroom.
- Upload bodies are capped at 95 MiB (413).
- `/attestation` is fixed (#295).

### Changes

- Production compose disables the epoch_head backfill at boot; enable it later once DB CPU has headroom.
- New migration `m20261017_000000_epoch_order_space_index` adds `idx_epoch_order_space_parent_child ON epoch_order (space, parent, child)` for the head-epoch anti-join that every write runs under its space lock (TC-1274). On a fresh database the build is instant. On PostgreSQL, if a valid index of that name and shape already exists, the migration issues no DDL and takes no lock on `epoch_order`. If the index of that name is INVALID or has a different shape, the boot fails, and nothing is applied, with an error naming the fix. On an existing database **without** the index, the migration builds it inside the boot's migration transaction. That holds a SHARE lock that blocks writes for the whole build, and the lock wait is bounded by the 30 s `lock_timeout` (TC-1176). **Runbook (PostgreSQL, before upgrading a node with history):** in autocommit, run `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_epoch_order_space_parent_child ON epoch_order (space, parent, child);`. Then confirm `SELECT indisvalid FROM pg_index WHERE indexrelid = 'idx_epoch_order_space_parent_child'::regclass;` returns `t`. If it returns `f`, run `DROP INDEX CONCURRENTLY idx_epoch_order_space_parent_child;` and build it again. `down` keeps the index. MySQL is covered only by the generated statement, because the full MySQL migration chain does not run (TC-1314). Rolling back to v1.20.x: the older node refuses to start while `seaql_migrations` lists this migration (`Migration file of version 'm20261017_000000_epoch_order_space_index' is missing`). Delete that row first, and keep the index: v1.20.x runs the same anti-join, and a later upgrade finds the valid index and does nothing.
- Writes no longer scan a space's whole epoch history to find its head epochs (TC-1274). A new `epoch_head` table (migration `m20261018_000000_epoch_head`) caches each space's heads. Every write maintains it in the same transaction, under the space's existing sequence lock. A write now reads O(heads) rows, normally one, instead of running the `epoch`/`epoch_order` anti-join, and usually costs one more statement, an `UPDATE` of the cached head. The cache is used only when its newest `seq` is the space's newest. Otherwise that space falls back to the old anti-join once and the write repairs the cache, so epochs appended by older releases (a rolling deploy, or a rollback and upgrade) never produce wrong parents. Heads are taken in `id` byte order. Previously the anti-join returned them in no defined order. This affects only a merge after a pre-TC-732 fork, and nothing re-derives an epoch hash from its parents. The migration only creates the empty table, without foreign keys, so it takes no locks on existing tables. After the node starts serving, a gentle online backfill checks each space once. It runs in one short transaction per space, under that space's lock, at no more than `epoch_head_backfill.spaces_per_second` (default 2) and pauses after each space for at least as long as the space took. It stops at its first error with one log line, and logs progress every `progress_every` spaces (default 500). Turn it off with `[epoch_head_backfill] enabled = false` or `TINYCLOUD_EPOCH_HEAD_BACKFILL__ENABLED=false`. Writes stay correct without it. Keep the `idx_epoch_order_space_parent_child` index: the fallback and the backfill use it. Rolling back to v1.20.x: as for `m20261017_000000_epoch_order_space_index`, the older node refuses to start until its rows are gone. Run `DELETE FROM seaql_migrations WHERE version IN ('m20261017_000000_epoch_order_space_index', 'm20261018_000000_epoch_head');` first. Keep the index and the `epoch_head` table: v1.20.x ignores the table. A later upgrade re-applies both migrations as no-ops (the index check and `CREATE TABLE IF NOT EXISTS`), and the `seq` check repairs every space the older node wrote to.
- Request events include validated/echoed UUID correlation, typed replacement flags, node-keyed target account/space pseudonyms and per-request database acquisition/execution timings and attempt counts. Driver/actor instrumentation includes failures and request-awaited audit batches; forwarding requires explicit first-party origin classification. A shared core `Pseudonymizer` preserves existing account/space hashes, adds the service/space-scoped database hash primitive for F6, and is derived once at startup for injection into consumers. See `docs/request-telemetry.md` for the wire contract, key custody, restart joinability and coverage/exclusions (TC-959 N2).
- The log sidecar now forwards the validated N2 correlation fields on `node_request` events: `request_id`, `request_id_replaced`, `account_hash` and `space_hash` (TC-959). Each is copied only when it has exactly the node's emitted shape; a malformed value is dropped and the event still ships. Ingress events and diagnostics never carry them, and `db_hash` stays on the F6 typed events. The embedded Vector configuration is regenerated; byte budgets now count the widest valid node request with these fields.
- CACAO/SIWE delegation ingestion normalizes ECDSA recovery IDs 0/1 to 27/28 before hashing and persisting the canonical DAG-CBOR bytes (TC-1071). Equivalent low-s signatures now share one delegation CID, including the CID used for revocation lookup. High-s signatures are rejected during decoding, matching the existing EIP-191 verifier and EIP-2 low-s convention; UCAN/JWS bytes remain unchanged. Existing stored delegation IDs are not rewritten.
- Synchronize the standalone M1, W5 and load-signer Cargo locks with CACAO's `k256` dependency so `--locked` dependency resolution succeeds (TC-1071). Keep the load signer compatible with the SDK's default invocation lifetime.

- Historical CACAO revocations now apply to every stored encoding of the same delegation, in both directions (TC-1071). A persisted CID-alias index derives identities from current ingestion's canonical bytes, including recovery-ID, issuer-address/chain, and accepted CBOR representation normalization. Startup backfills aliases transactionally after loading the column encryption key and fails closed on undecodable or mismatched history or missing/wrong keys. Historical IDs, signed bytes, revocation targets, and signed child proof references remain unchanged; legacy list/chain responses retain their exact raw-header/CID relationship. This closes reuse of an already owner-signed grant under another accepted encoding; it does not involve forging new rights.
- CACAO issuer address casing and numeric chain spelling now serialize to the verifier's same EIP-55/u64 identity without changing the signed SIWE message. SDK session setup checks and normalizes wallet signatures before deriving its proof CID, including direct Rust sessions; low-v wallet signatures no longer produce `MissingParents` (TC-1071).
- Serialize concurrent PostgreSQL/MySQL historical backfills before their first history read; failed startup still rolls back aliases and preserves signed records. MySQL alias columns retain full variable-length multihashes, and encrypted-key validation avoids its unsupported limited `IN` subquery. Native alias checks do not waive the separately reproduced older MySQL 8.0.46 full-schema error 1074 (TC-1071).
- Policy v3 account-owner admission, its transactional recheck, and legacy Share v2 revocation consumers now use the same effective historical-CID revocation lookup. Account-owner proofs retain shared canonical chain guards through commit or rollback, so a same-registry sibling revocation cannot pass an in-flight admission; a separately committed sibling revocation fails the transaction recheck (TC-1071).
- Rust API cutover: pass encryption through `SpaceDatabase::new_with_encryption`; list/chain outcomes carry serialized delegation wrappers. SDK exhaustive error matches must handle the new `session::Error::InvalidSIWESignature` variant (TC-1071).
- Harden optional DuckDB statement and settings policy (TC-1304).
- Tighten revocation scope checks (TC-1302).
- Account delegation session discovery keyset-pages delegation rows independently of ability fan-out, using a composite delegator/id index so large grant sets are not truncated (TC-1195).
- On PostgreSQL, the boot's schema migrations wait at most 30 s for any lock (`SET LOCAL lock_timeout`, in the same transaction that lifts `statement_timeout`) (TC-1176). If another session holds a conflicting lock on a table a migration changes, such as an open write on `delegation` during the first boot after 1.20.6, the node now fails to start with an error naming the lock wait instead of hanging. All pending migrations roll back together, so nothing is applied or recorded, and the next start applies them. The limit ends with that transaction and does not reach pooled sessions. SQLite and MySQL are unchanged.
- `/attestation` quotes the SHA-256 of `key_binding` as REPORTDATA and returns it as `key_binding_sha256`; the quote no longer carries the raw binding. Before answering 200 the node checks that the returned TDX v4 quote's REPORTDATA field holds that digest (a structural check; it does not verify the quote). When the TEE can't produce a bound quote, the endpoint returns 503 instead of 200 `mode: "classic"`, and the dstack client reports a guest-agent error status instead of a parse error. `nonce` must be 1-64 characters of `A-Z a-z 0-9 - _` (400 otherwise), and the endpoint now shares the public routes' per-IP rate limit. Verifiers recompute the digest from their own nonce and expected DID and must still verify the quote; see `docs/attestation.md` (TC-963).
- `/invoke` upload bodies are capped at 95 MiB (99,614,720 bytes), and a longer body gets 413 (TC-1012). This applies to a KV put, a multipart KV batch put (the whole multipart body) and a DuckDB import, whether the body is declared or chunked. Before, a KV put kept only the first 1 GB of a longer body without an error, a batch put over 1 GB got 400, and a DuckDB import was cut off at 100 MB. The ingress test now expects `CLIENT_MAX_BODY_SIZE=95m`. The release compose line changes with the TC-959 N0 compose (#315).
- Prepare a compose-only GELF-to-Vector sidecar for the unchanged node 1.20.6 and ingress image digests. The default unsampled `errors_slow` profile emits valid requests with status >=400 or duration strictly over one second; explicit `all_requests` remains available, and all accepted typed WARN/ERROR diagnostics remain eligible for bounded count aggregation. Document eligible-request volume accounting, accepted BEST-EFFORT outage loss, the failed local burst evidence and required zero-observed-loss healthy hosted burst, plus the config-only deployment/rollback privacy packet. No Rust or application image change and no deployment authorization; see `docs/runbooks/tc-959-n0-log-shipping.md` (TC-959 N0).

## [1.20.7] - 2026-10-14

A security hardening release (TC-1132, #292) for webhook, quota and tunnel egress.

- Security (TC-1132, TC-1080 Parts C–D): webhook registration and every delivery attempt share an egress policy covering special-use IPv4/IPv6, embedded IPv4 (mapped, compatible, NAT64 and 6to4), Teredo and site-local IPv6. Ambiguous local-use NAT64 is refused if any valid IPv4 interpretation is forbidden. Corrected public controls such as `192.2.1.1` and `198.51.0.1` are no longer over-blocked. Mixed DNS answers retain only permitted addresses.
- Webhooks deny the resolved addresses of the configured network database, quota URL, space allowlist and explicit S3 endpoint on every port, including aliases and embedded IPv4 forms. The service deny-set refreshes every ten minutes; validation waits for an in-progress refresh, and failed/stale resolution closes egress until recovery. Temporary DNS/policy failures retry on the existing bounded schedule; invalid or forbidden callbacks dead-letter. Existing subscriptions whose destinations become forbidden dead-letter on the next attempt.
- Webhook DNS is bounded to one second. Each delivery resolves once and gives only vetted addresses to reqwest through a sealed, immutable-target sender. A fresh policy lease rechecks literal and hostname addresses and remains held through connection/send, so refresh cannot invalidate a vetted target before it connects. Proxy environment variables are ignored, redirects/non-HTTPS destinations refused, connect time capped at two seconds, and the configured total timeout includes lease/freshness work and sending. No production private-destination/development flag was added; body bytes, headers and HMAC signing are unchanged.
- Registration caps both raw and canonical callback URLs at 2,048 bytes and secrets at 256 bytes. Retry attempts 6 and later keep the one-hour backoff; `hooks.webhook_max_attempts` must not exceed 10.
- Quota requests encode the original SpaceId as one path segment and do not follow redirects; cache/override keys and fallback remain unchanged. Tunnel upstream requests do not follow redirects and have a 30-second total timeout, including body reads; 3xx responses and existing per-request errors retain their framing.
- Network DID methods remain disabled by default. Full TC-1080 Part B (node-owned did:web fetcher, destination policy, timeouts, body limits, and refusal tests) is **required before any future re-enable**; this change does not implement or enable that fetcher. No schema migration.
- The test-only DID resolution source guard now also covers SSI verification-method adapters, `into_vm_resolver` spellings and production auth-helper paths (#290).

## [1.20.6] - 2026-10-14

A security fix (TC-1080, Part A). UCAN issuer resolution no longer dereferences network DID methods by default, so a request can't make the node fetch arbitrary or internal hosts through a crafted issuer DID (#284).

- Issuer DIDs resolve offline only for `did:key`, `did:pkh` and `did:jwk`. Any other method (`web`, `tz`, `ion`, `ethr`, unknown) is refused with `did_method_disabled:` before any dereference or socket. Issuer DID URL queries are always refused (`did_url_query_rejected:`).
- New setting `did_resolution.network_methods` (default `false`; env `TINYCLOUD_DID_RESOLUTION__NETWORK_METHODS`). Setting it to `true` and restarting restores the previous method dispatch, except that queries stay refused.
- `GET /info` reports `did_resolution: { network_methods, refused_total }`. Prometheus counts refusals as `tinycloud_did_resolution_refused_total{method,reason}`.
- The production deploy now also turns the CVM's public system-info page off (#286).

## [1.20.5] - 2026-10-14

A reliability hotfix (TC-1054). A PostgreSQL connection that dies silently (failover, a NAT or proxy idle drop, a network black hole) can no longer hang a request, or the per-database SQL operation lock it holds, for minutes (#283).

- Every pool connection now sets TCP keepalive and `TCP_USER_TIMEOUT` on its own socket as it connects, so a dead connection errors in about 30 s instead of about 15 min. This is done in a vendored crates.io sqlx-core 0.8.6 (the pristine copy plus one small patch commit); setting the options fails the connect rather than silently skipping them.
- A session `statement_timeout` (30 s) bounds slow statements on live connections.
- These failures are classified for clients: `503 unavailable_retryable` with `Retry-After` when no write can have taken effect, `500 outcome_unknown` when one may have committed. The per-database lock is released on every one of these paths.
- `GET /info` reports `postgres: { sockets_configured, connections_opened }` so a deploy can confirm the socket options are applied.

## [1.20.4] - 2026-10-13

A performance release. The node spends fewer Postgres round trips per request: the pool no longer pings a connection before every statement (#276), and resolve, the read audit and the KV sequence lock each take fewer statements (#277). In the TC-946 lab at a prod-like 65 ms database RTT, an owner SQL `SELECT 1` drops from 3.8 s to 1.25 s, a KV get from 1.77 s to 0.73 s, and an SDK sign-in with a fresh key from 26.8 s to 18.2 s. A connection lost while idle is now recovered by a one-time retry of `BEGIN` and pure reads plus revalidation, not by a ping on every acquire; see the first entry for what can still fail. New metric `tinycloud_db_connection_events_total`. No schema change, so rolling back to 1.20.3 is DB-safe (TC-951).

- The Postgres pool no longer pings an idle connection before every statement, which removes about half of the node's Postgres round trips. A connection lost while idle (a failover, an idle-session timeout, a dropped socket) is handled instead. `BEGIN` and read-only statements that fail on a lost connection are retried once; writes, `COMMIT` and any statement that might have a side effect (an allowlist decides, so a call such as `nextval` is never retried) are not. Once a loss is seen, every later acquisition checks a connection that was already idle at that moment, and a connection idle for 60 s or more is always checked, which covers idle reapers slower than that. Statements that already held a dead connection when the first loss was seen can each still fail if they are writes; under concurrency right after a failover that can be several. Idle-session timeouts (57P05) and the other "session ended" codes now count as lost connections. New metric: `tinycloud_db_connection_events_total{event="lost|retried|revalidated|revalidation_failed"}` (TC-951).
- The SQL/DuckDB identity-fence cache refresh finds unregistered legacy artifacts with one `NOT EXISTS` query instead of loading every legacy row and artifact name into the node. The fence decision and the 1 s cache TTL are unchanged; MySQL keeps the exact comparison. No schema change (TC-951, from #254).
- SQL and DuckDB requests resolve a database identity (alias, legacy name, digest) with one statement instead of one lookup per step on PostgreSQL and SQLite, saving 2-3 round trips per resolve and two resolves per request. The precedence and fence rules are unchanged, and the old statement-per-lookup path stays for MySQL and as the test oracle. No schema change (TC-951, from #259).
- On PostgreSQL each read-audit batch (KV get, SQL/DuckDB reads, capabilities) commits as one `WITH ... INSERT` statement instead of `BEGIN`, one INSERT per table and `COMMIT`; the rows and `ON CONFLICT DO NOTHING` targets are the same. A batch past PostgreSQL's parameter limit, and SQLite and MySQL, keep the transaction. Because every INSERT in it is idempotent, the statement is retried once after a lost pool connection, like `BEGIN`. No schema change (TC-951, from #259).
- A KV write transaction no longer takes the per-space sequence advisory lock a second time when it already holds it, which saves one round trip per KV put. Writers still serialize per space as before. No schema change (TC-951, from #259).

## [1.20.3] - 2026-10-13

A security release. Up to 1.20.2, a webhook subscription registered under a delegated `tinycloud.hooks/register` grant kept receiving signed write events (key names, writer DIDs) after that grant was revoked or expired, because delivery never re-checked the subscriber's authority. From 1.20.3 the dispatcher re-checks the subscriber's current authority when it delivers (once per subscription per dispatch pass), so such a subscription stops delivering once that delegation is revoked or expires, unless another live grant still gives the subscriber that authority (TC-991, #274). It also caps the ingress and node containers' Docker logs (TC-970, #273). No schema change, so rolling back to 1.20.2 is DB-safe.

- Security: webhook deliveries re-check the subscriber's authority at send time. A subscription whose subscriber no longer holds `tinycloud.hooks/register` on its space and path — revoked, expired, narrowed, or a revoked or expired ancestor — is deactivated when the dispatcher next tries to deliver to it. Its deliveries in that dispatch pass dead-letter as "subscription authority lapsed"; pending deliveries processed in later passes dead-letter as "subscription inactive". A subscriber that still holds the authority through another live grant keeps receiving deliveries. Owner (root-authority) subscriptions are unaffected. SDK webhooks are registered by the session key, so they stop when the session grant expires unless another live grant covers the session key; re-register with a live session. No schema change; rollback to 1.20.2 is DB-safe (TC-991).
- The ingress and node containers' Docker logs are capped at 3 × 50 MB each (`logging: json-file`, `max-size: 50m`, `max-file: 3` in `docker-compose.dstack-postgres.yaml`), so their per-request stdout lines no longer depend on the CVM daemon's default rotation (TC-970).

## [1.20.2] - 2026-10-13

The first production release built from `main`. It carries the 1.20.1 release line forward (TC-940), plus the Exo upload fix, TC-899, TC-961 and TC-970.

- On SQLite, graph write transactions take the write lock as their first statement (a no-op write, as `BEGIN IMMEDIATE` would), so concurrent writers wait in the busy handler and no longer fail with `SQLITE_BUSY_SNAPSHOT` (517, returned as HTTP 500). Postgres behaviour is unchanged (TC-899).
- CORS preflight (`OPTIONS`) responses on the generic data plane carry `Access-Control-Max-Age: 7200`, so browsers reuse a preflight instead of repeating it before most `/invoke` calls. Share-owned `/policy/v3/*` responses are unchanged (#240, carried from `main` when the 1.20.1 release line merged into `main`, TC-940).
- The production ingress accepts request bodies up to 32 MB (`CLIENT_MAX_BODY_SIZE=32m`) instead of nginx's 1 MB default, so Exo voice-note uploads (1 MiB KV parts plus framing on `/invoke`) no longer get a 413. Proxy timeouts stay at nginx's defaults. The wrapper's base moves from `dstack-ingress:20250924` to `dstack-ingress:1.4`, the newest upstream image that honours `CLIENT_MAX_BODY_SIZE`, and keeps the TC-910 32 KB header buffers. This release ships it in wrapper `sha256:63c1c44e2ded5b73a5f174807b91ca677826974df0f9ab3045f6ec87865a5744`, which adds TC-970's redacted logging (below) to #261's `sha256:08cf3ee4ab4054cc2657da12304ae344d6b2156c1fa11ffd7da5e64cd1bca416` (#261, carried to `main` and capped at 32 MB by TC-940).
- The node's own logs no longer carry request URIs, so signed-KV and hook ticket ids, space IDs and KV keys stay out of them; TC-970 below does the same for the ingress. Rocket's per-request logging is dropped at every level; each request is logged once at INFO under `tinycloud::request` with method, route template, status and latency. Space IDs, DB names, DIDs and paths are removed from application log lines. SQL statement text, including sqlx's slow-statement warnings, moves to DEBUG. sea-orm's TRACE spans (which carry bound values) and reqwest and AWS SDK output below INFO (which carry outbound URLs, S3 keys and signed requests) are dropped. Handler panics are reported by location only (TC-961).
- `TINYCLOUD_LOG_LEVEL` now sets the default log level when `RUST_LOG` is unset: `normal` is INFO, `critical` is WARN, `debug` is DEBUG and `off` silences logging. Before, it had no effect. A release build with no `log_level` setting at all gets Rocket's release default, `critical` (TC-961).
- The ingress wrapper no longer writes raw request lines, client addresses, `Referer` or `User-Agent` to `/var/log/nginx/access.log`, which nothing rotated. It logs one JSON line per request to stdout with method, route template (for example `/signed/kv/<ticket_id>`, or `<other>` for unknown paths), status, bytes and request/upstream timings. Request-context nginx errors, which carry the client address and the raw request line, are logged only at `emerg`; methods outside GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS log as `<other>`; a failed upstream shows as `status`/`upstream_status` in the access line. `deploy/ingress/test-redacted-logging.sh` checks this in CI, along with the TC-910 header buffers and the 32 MB body limit. Pinned wrapper: `sha256:63c1c44e2ded5b73a5f174807b91ca677826974df0f9ab3045f6ec87865a5744` (TC-970).
- A test pins that the node refuses a default-space proof for an account-index SQL grant (`{owner}:account/sql/account`, 401) and accepts the same grant on the account space (200). Test-only; the client fix shipped in js-sdk #504 (TC-957).
- Deploys: `docker.yml` promotes to production only from `main` or a `vX.Y.Z` tag on `main` (`scripts/ci/check-deploy-ref.sh`, run in `version-guard` and again in `deploy-phala`). An emergency rollback's recorded revision must be in `main`'s history, so a rollback no longer needs `allow_non_descendant`. See `docs/releasing.md` (TC-940).
- Deploys: the Phala deploy passes `--no-public-logs`, so the CVM's container logs aren't publicly readable (TC-959, #260).
- Deploys: the post-deploy probe of `/policy/v3/deliveries/authorize` requires exactly 401 for an unsigned request again, not 400 or 422 (TC-940).

## [1.20.1] - 2026-10-11

- SQL and DuckDB invocations: the covering-chain check stops at a delegation issued by the owner of the invoked space, as registration already does. An owner's SQL/DuckDB grant that also cites a foreign proof (for example another user's KV grant) no longer gets 401. Every non-owner ancestor must still cover the invoked database, ability and caveats (TC-894, port of TC-825).
- `tinycloud.kv/sync` may be granted on the whole-space KV root (`{space}/kv` or `{space}/kv/`), advertised as `kv-sync-root` in `/info`. Prefix grants still cannot reach the root (TC-908).
- Add the `tinycloud-node-ingress` wrapper image: the pinned dstack-ingress base plus `large_client_header_buffers 4 32k`, so signed delegation `Authorization` headers over 8 KiB are no longer rejected with 400 (TC-910).

## [1.20.0] - 2026-10-08

- Isolate SQL and DuckDB databases by full resource path, require exact non-slash database grants and covering delegation chains, and keep hook and share-email SQL reads within the authorized identity (TC-780).
- Add a write-fenced migration from legacy physical names to quarantined aliases, with a preflight migration inventory, transaction-time fingerprint verification, and an explicit cutover runbook (TC-780).
- Keep the production release line's meeting guard, TC-541 and TC-730/TC-815 hook fixes, and KV-sync migrations; add the TC-780 migrations after them. Gate image publishing and require manual digest promotion for the cutover (TC-780).

## [1.19.2] - 2026-10-07

- Re-check hook-ticket delegation revocation and stream expiry at open, prioritize the absolute deadline over queued events, and match literal subscription prefixes; tickets minted under the prior v2 key context must be re-minted (TC-730).
- Bound proof-DAG ancestor traversal to 64 nodes with fixed-size parent pages and fail closed when the closure exceeds the limit (TC-815).

## [1.19.1] - 2026-10-06

- Include the TC-541 hooks authorization, replay-safety and subscription-reset fixes, including the `m20261005_000000_deactivate_hook_subscriptions` migration.
- Add a Phala deploy guard that requires the running production revision to be an ancestor of the selected commit; deliberate non-descendant deployments require an explicit workflow-dispatch override.

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

## [1.16.1] - 2026-09-15

- Complete the embedded Policy v3 admission path for exact native credential invitations: validate the sealed share envelope and canonical recipient link, bind delivery authorization to the ephemeral holder key, and issue a deterministic signed receipt with strict nonce, request-body, and sender-DID replay protection. Shared content remains in the owner's TinyCloud storage and is accessed through the ordinary `/delegate` then `/invoke` storage-enforcer flow; no Share-specific data plane is introduced (TC-500, #229).

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
