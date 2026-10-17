# TC-959 N0: unchanged-binary request logging

Tracking: [TC-959](https://linear.app/tinycloud-labs/issue/TC-959). This change prepares a compose-only sidecar, not a deployment authorization. Existing operator promotion holds remain in force. No Rust, application image build, database migration, ingress image change, automatic deployment or secret provisioning is part of N0.

## Immutable runtime

- Node 1.20.6-dstack, revision `e18578ff9162986ddd813259c60f73866e3e60d1`: `ghcr.io/tinycloudlabs/tinycloud-node@sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f`.
- Existing ingress: `ghcr.io/tinycloudlabs/tinycloud-node-ingress@sha256:63c1c44e2ded5b73a5f174807b91ca677826974df0f9ab3045f6ec87865a5744`.
- Vector 0.59.0: `timberio/vector:0.59.0-alpine@sha256:0e36bc2a290039e9b6a5e92f04bd2f133223506f72d09682c1df16c015172b7a`.

Only node JSON formatting (`TINYCLOUD_LOG__FORMAT=Json`), Docker logging drivers/labels, and the sidecar are changed. App environment, ingress ports/certificate settings, storage, SSH helper, authentication and routing are otherwise unchanged. The node and ingress do not depend on Vector or join its network. A separate future operator action must provision the source's ingest token in the sealed environment. Compose refuses a missing token; Vector's entrypoint independently fails with a fixed message. Do not read or print any production token to test this change.

The host Docker daemon sends labelled stdout/stderr over UDP to the Vector listener published **only on 127.0.0.1:12201**. The app cannot select a different destination by including text in a message. Labels select a source; they are not cryptographic authentication. Host/Docker-daemon principals can forge a labelled message and already control the containers.

Vector has UID/GID 10001, a read-only root, all capabilities dropped, no-new-privileges, CPU 0.5, memory and swap capped at 64 MiB, and an 8 MiB tmpfs. It has no Docker/dstack socket, app data, host files or application-network membership. Its production network needs outbound HTTPS to the configured sink; this is not a general outbound sandbox. Do not equate separate network membership with proof that every host-published app port is unreachable. The local acceptance reports reverse reachability explicitly.

## Wire contract and privacy boundary

`log-shipper/sanitize.vrl` reconstructs fresh bounded objects. `scripts/tc959-logship.mjs` compiles route/method/code enums from the vendored canonical schema and embeds the same program in compose. No raw envelope field, arbitrary key, free-text error/message, target, span, SQL, URI/query value, address, DID/wallet, token, body or header reaches the HTTP sink.

GELF chunk/decompression framing feeds a **bytes** decoder, then explicit VRL
parses the outer JSON and retains only the selected label and short message.
The native GELF JSON codec is deliberately not used: malformed metadata can
make its diagnostic quote the raw value in Vector's console. A real native
regression observed one console canary hit before this change and zero after;
five valid safe request controls reach the local HTTP sink after the change.
Parsing failures become fixed counters; no log-level suppression is used.

| Event | Fields beyond `ts`, `level`, `event`, `svc` | Delivery policy |
| --- | --- | --- |
| `node_request`, `svc=api` | `method`, canonical `route` template, integer `status`, nonnegative integer `latency_us` | Individually when valid and eligible under the selected request profile; no sampling |
| `ingress_request`, `svc=ingress` | Same method/route/status, distinct numeric `request_time_seconds` | Individually when valid and eligible under the selected request profile; no sampling |
| `node_warning` / `node_error`, `svc=api` | Fixed `event_code`, integer `event_count` | All accepted typed application WARN/ERROR records remain eligible under either profile; grouped counts approximately every 60 seconds |
| `node_warning` / `node_error`, `svc=api`, TC-1274 SQL contention `event_code` | `event_count=1` plus only that code's declared fields (`log-shipper/diagnostics.json` `typed`): integer `*_ms`, `ahead_approx`, `suppressed_count`, `pool_size`/`pool_idle`/`pool_max`; fixed `op`/`phase`/`kind`/`outcome`/`class`; keyed `space_hash`/`db_hash`, each exactly 64 lowercase hex | Individually, one record per occurrence, under either profile; never reduced |
| `logship_gate_summary_total`, `svc=logship` | Fixed `reason`, integer `count` | Count every rejection that reaches the boundary; emit approximately every 60 seconds per fixed reason |

### Request profiles

Sam approved **`errors_slow` as the deployment default**. Compose exposes `TINYCLOUD_LOGSHIP_PROFILE`, defaulting to `errors_slow`; the sidecar entrypoint accepts only `errors_slow` or `all_requests`. The profile is selected at Vector startup, not by per-record environment lookup.

- `errors_slow`: forward each valid node request with `status >= 400` **or** `latency_us > 1000000`; forward each valid ingress request with `status >= 400` **or** `request_time_seconds > 1.0`.
- Exactly one second does **not** qualify as slow. A request at that equality still qualifies when its status is at least 400.
- `all_requests`: explicitly forward every valid node/ingress request, including 1xx, 2xx and 3xx. It is an operator-selected alternative, not an automatic fallback.

Both profiles are unsampled: there is no sampler, random selection, throttle or byte-budget drop. All accepted typed WARN/ERROR diagnostics bypass request-profile filtering. Untyped codes retain their fixed-code count aggregation; the seven TC-1274 SQL contention codes are shipped per occurrence instead (next section). Invalid records still go to content-free gate counts, not to request output. Profile selection does not make transport durable or imply a volume allowance.

### TC-1274 SQL contention diagnostics

`sql_operation_lock_wait`, `sql_operation_lock_still_waiting`, `sql_operation_lock_held` and `sql_operation_still_running` from `tinycloud_core::sql::service`, `sql_actor_message_slow` from `tinycloud_core::sql::database`, and `db_pool_acquire_timeout` and `db_connect_failed` from `tinycloud_core::db_pool` are matched by exact (target, message) and fixed level. Each record carries only the fields `diagnostics.json` declares for its code, each checked against its closed schema type. A missing field, a wrong type, an out-of-range integer, a value outside its enum, a hash that is not exactly 64 lowercase hex, or a wrong level rejects the whole record into the `invalid_fields` gate count; no partial record is shipped. Undeclared fields, including a raw `db` name, the pool `operation` label, error text and nested values, are never copied. The same message from any other target stays `unclassified`. The field sets and enums must match the emitted F6 PR before promotion.

Rocket logs template query parts such as `/attestation?<nonce>` and `/public/<space_id>/kv?<prefix>`. Only explicit literal aliases map to canonical paths; arbitrary input is never split at `?` or normalized into a supposedly safe URI. `<unmatched>` is a fixed sentinel. TRACE/CONNECT map to `<other>`; ingress's existing `<other>` route maps to `<unmatched>`. All other unexpected typed fields are rejected and counted, never relayed.

Every node-labelled JSON WARN/ERROR record with a valid formatter timestamp is eligible, including dependency targets, missing targets and missing message fields. Only the actual `tinycloud` / `tinycloud::*` and `tinycloud_core` / `tinycloud_core::*` targets may map known messages to internal fixed codes. Other targets always become `unclassified`; a dependency cannot borrow an internal code by matching its message. No target/message/error value is copied. Plaintext, malformed JSON/timestamps and oversized records remain content-free gate rejections, not a promise to classify unstructured stderr.

**No fatal-panic claim:** 1.20.6's panic hook emits plain text, not a typed JSON panic event. Non-JSON panic lines contribute only to a content-free rejection count if received. N0 neither emits nor declares `node_fatal_panic`, and cannot distinguish a panic from other non-JSON output. Request IDs, replacement flags, account HMACs, per-request DB timings and trace propagation require N2. N0 ignores and omits them, including forged input values; the only hashes it ships are the SQL contention diagnostics' `space_hash`/`db_hash`. Shared future contract: canonical `ops/logging/request-id.md` and `request-id-vectors.json`, version 1, at the revision in `log-shipper/canonical.json`.

## Volume: explicit limit, never hidden sampling

Run `node log-shipper/budget.mjs <eligible-request-pairs-per-minute>`. The decimal **requests-only** allocation is **480,000,000 bytes per 30 days**, not a promise of free ingestion. A through-ingress request whose node and ingress records both qualify contributes one eligible pair. Representative long valid fields cost 198 node bytes + 223 ingress bytes = **421 bytes/eligible pair** including NDJSON newlines. These are exact serialized representative records, not a proven float-serializer ceiling or provider billing formula.

Under `errors_slow`, node and ingress eligibility are evaluated independently: a slow record on only one side is one event, not a full eligible pair. Measure eligible node and ingress event rates separately where they differ; use their measured byte rates rather than assuming every incoming request contributes a pair. Under `all_requests`, each valid through-ingress request normally contributes a pair. No error fraction, slow-request fraction, gzip discount, HTTP overhead, provider enrichment or retry duplication is assumed.

| Eligible request pairs/minute | Request bytes / 30 days | Requests-only allocation |
| ---: | ---: | --- |
| 1 | 18,187,200 | Within |
| 26 | 472,867,200 | Within |
| 27 | 491,054,400 | Exceeds |
| 60 | 1,091,232,000 | Exceeds |
| 600 | 10,912,320,000 | Exceeds |

The representative requests-only rate is **26.39 eligible pairs/minute**, or **26 whole eligible pairs/minute**. A singleton JSON-array framing assumption gives 423 bytes/pair and 26.27/minute; production explicitly uses NDJSON. This is arithmetic, not a claim that either profile fits a budget at actual traffic.

Diagnostics are **additional**, not secretly subtracted, sampled or dropped. The continuous storm model covers all 59 codes at both severities (118 groups/minute) plus nine rejection groups/minute: **912,340,800 bytes/30 days** with maximum-width count records, separate from the request allocation. Real idle/no-diagnostic traffic is lower; grouped reduce flush timing is not a strict calendar-minute emission ceiling. At 60 **eligible pairs/minute** plus that continuous storm, the model totals 2,003,572,800 bytes. The SQL contention diagnostics are per occurrence and are NOT in that model: a maximum-width record is at most 475 bytes with its newline, the shipper applies no cap, and their rate is bounded only by the node's own per-(space, database, event) limiter, so it scales with the number of contended databases. Measure it separately. [Public Better Stack pricing](https://betterstack.com/pricing), read 2026-10-16, lists 3 GB/month retained for three days. That allowance is shared with other sources; it is not a service allocation, spend approval or assurance that an account cannot exceed it. Measure actual eligible traffic and billing before an authorized promotion; profile approval alone does not establish budget fit.

## Known transport and process risks

- The release formatter has **uncapped lines**. Vector rejects inner messages above 64 KiB after GELF framing and safe envelope parsing, but this does not cap emitter allocation, Docker framing, UDP chunk reassembly or decompression. The socket's configured maximum is 256 KiB; truncated/malformed framing may fail before VRL and cannot be reconstructed or fully counted there. Malformed outer JSON is counted by VRL without native decoder free text. Vector's memory cap bounds its process, not upstream allocations.
- **BEST-EFFORT outage loss is accepted.** GELF/UDP is not lossless or durable. Missing chunks, kernel queues, decoder failures and an absent/paused/OOM shipper can lose messages before the gate. Docker uses a bounded 4 MiB nonblocking queue; overflow can drop logs. This keeps the app independent of sink availability, not loss-free. Acceptance of outage loss does not waive the healthy unpaced 500-request burst gate below.
- Vector has a 1,000-event memory queue with `when_full=block`. HTTP retries/temporary outages can fill it, then backpressure the UDP reader and lose packets upstream. Process restart loses queued events and unfinished diagnostic groups. HTTP retries may duplicate events; no event ID exists in N0 to deduplicate reliably. The UDP source requests `receive_buffer_bytes=8388608`; this is a request, not evidence of the effective kernel socket buffer. Measure the effective buffer in the hosted runner without changing sysctls. Initial isolation remains 0.5 CPU / 64 MiB.
- **Docker logs are intentionally unavailable** for node/ingress after the GELF cutover: raw log caching is disabled. The dstack `/logs` API and `docker logs` are not a fallback. Do not restore raw cache or relay raw startup/panic/tunnel output as a workaround. A separate authorized privileged attach may inspect process output; N0 grants no such production access.
- Gate counters account for processed rejects, not all transport loss. Compare emitted synthetic canary counts, source/sink component metrics where available, and sink arrival; a zero gate count alone does not prove complete delivery or silence health. There is no new production monitor/alert in this PR.
- The sealed token is written only to the sidecar tmpfs and unset before Vector exec. Docker configuration and init's initial environment remain visible to Docker-daemon/equivalent principals. This is not a protection against that host authority.

## Verification and maintenance

```sh
node --test log-shipper/budget.test.mjs log-shipper/profile.test.mjs scripts/tc959-docker.test.mjs scripts/tc959-readiness.test.mjs
node scripts/tc959-logship.mjs render-tests /tmp/tc959-errors-slow.json errors_slow
vector test /tmp/tc959-errors-slow.json
node scripts/tc959-logship.mjs render-tests /tmp/tc959-all-requests.json all_requests
vector test /tmp/tc959-all-requests.json
node log-shipper/native-check.mjs /path/to/vector
node scripts/tc959-logship.mjs render-vector /tmp/tc959-vector.json http://127.0.0.1:9599/
vector validate --no-environment --skip-healthchecks /tmp/tc959-vector.json
```

The canonical repo is private. CI verifies the vendored bytes against the reviewed canonical commit/hash pin, the immutable image pins, the process/network constraints, and structural equality of compiled/embedded Vector config without env interpolation (`--env-file /dev/null`). It does not pretend unauthenticated CI can follow private canonical `main`. A schema change must land in a separate canonical PR, update both identical copies and the explicit provenance pin, and pass canonical consumer tests. The canonical active-vendor drift mechanism remains pending until this shipper is merged; promotion must reconcile its activation deliberately.

After changing VRL/schema/compiler sources, regenerate the embedded `VECTOR_CONFIG_JSON` scalar and rerun the parity gate in CI. Preserve `$${TINYCLOUD_LOGSHIP_PROFILE}` in YAML so Compose passes the literal `${TINYCLOUD_LOGSHIP_PROFILE}` to Vector's startup interpolation. The source program is authoritative; never maintain a second hand-edited VRL copy. The application image is not rebuilt for this validation.

### Local evidence: failed acceptance, no further host Docker

No further local host Docker run is authorized. Do not create, restart, recreate or remove Docker resources to extend this evidence. Local evidence is historical and does not replace the hosted-runner acceptance gate.

Earlier attempts included combined readiness failure and a run with source/gate/sink counters all zero despite healthy node/ingress; each cleaned all labelled resources. Native reproduction delivered 0/3 packets sent before the UDP socket opened and 3/3 after it opened, establishing a startup-loss race but not the cause of a separate Docker failure. Missing metrics are unknown, never fabricated zeroes.

The **last local run** passed real node+ingress flow, actual loopback port-binding checks, and both app-injection-blocked gates. It then failed after an **unpaced 500-request burst sent by one `printf` in one exec**. The totals below span **controls plus burst**, not the burst alone:

| Observed stage | Total events |
| --- | ---: |
| Source | 203 |
| Gate | 203 |
| Allowlist | 202 |
| HTTP sink | 201 |
| Capture | 201 |

At least **299 burst events were not captured**, but the exact missing subset was not persisted. These totals do not establish a root cause. No OOM or startup errors were observed. Remaining continuity and diagnostic gates were not reached. Cleanup reported **0 containers / 0 networks / 0 volumes** and no active proof resources; Clarissa directly acknowledged closure at **18:29:07**, and QA's **18:33** post-sanity confirmed browser starts and stable interfaces. This is a failed burst gate, not an absolute zero-loss result. Sam's remaining proof is CI-only; no further host Docker is authorized.

### Required GitHub Actions evidence

The healthy, unpaced, mostly-error **500-request burst must show zero observed loss** in the GitHub Actions runner, under the selected profile and unchanged image pins. Compare the exact eligible request set and capture, not just aggregate totals spanning controls. Outage/paused-sink experiments are separate BEST-EFFORT evidence and may lose records; they must not hide a healthy-burst failure.

Collect per-stage counters through source, gate, request-profile/allowlist, HTTP sink and capture, plus socket/kernel/cgroup evidence sufficient to distinguish transport, filtering and resource pressure. Record requested and effective UDP receive buffers; do not change sysctls. Preserve 0.5 CPU / 64 MiB initially. Report positive leak controls, actual host port binding, app-injection isolation, continuity and diagnostic aggregation results separately. No local Docker rerun or production requests are authorized for this evidence.

The `logship / hosted-compose-proof` job runs only on a disposable GitHub-hosted Linux VM, with public immutable images, a synthetic bearer and a complete synthetic Compose environment. It renders this exact production compose, derives container settings, and compares actual image/logging/network/mount/security/resource/entrypoint/configuration values. SQLite/static keys/TEE-off, local ingress bootstrap, dynamic loopback ports and the local capture sink are explicit test substitutions; this is logging-boundary proof, not dstack/TLS deployment proof. The job has read-only repository permission and an `always()` owner-only cleanup step; it never prunes or reads production/GitHub secrets.

The single-exec burst has 500 distinct status-503 requests with safe latency markers 100000–100499 microseconds: fast errors, not success records made eligible by synthetic slow timings. The proof records exact marker sets, duplicates, timed per-hop plateaus, socket drops/effective receive capacity versus `rmem_max`, and CPU throttling. It also checks known and dependency WARN/ERROR controls by summed occurrence counts, not output rows. An 8 MiB receive buffer is requested; the kernel may cap/double it, so configuration alone is not evidence of effective capacity.

## Amos: config-only deployment packet and hold

This packet is preparation only. Keep node Draft PR **#309** Draft until required CI and Astra review pass. **Do not merge, dispatch or deploy now.** There are no Rust/app-image changes. Future operator notices go **directly to Clarissa / the lead**, not to sitrep or roci-board chat.

### Source, sealed input and exact runtime

- Better Stack source: **2795437**.
- GitHub production secret **name only**: `PROD_TINYCLOUD_BETTERSTACK_SOURCE_TOKEN` → sealed runtime variable `BETTERSTACK_SOURCE_TOKEN`, supplied only to the sidecar. Never print/read token values or an actual production env file. Compose/entrypoint must reject a missing token; there is no silent raw-log fallback.
- Compose deployment artifact: repository-root **`docker-compose.dstack-postgres.yaml`**, resolved with the exact pinned images above. The actual node image remains **1.20.6-dstack**, revision **`e18578ff9162986ddd813259c60f73866e3e60d1`**; inputs, labels and summaries must remain truthful to that image.
- Node digest remains **`sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f`**; ingress remains **`sha256:63c1c44e2ded5b73a5f174807b91ca677826974df0f9ab3045f6ec87865a5744`**.
- Deploy profile is `TINYCLOUD_LOGSHIP_PROFILE=errors_slow`; switching to `all_requests` requires an explicit operator choice, never an automatic outage response.
- Previously recorded live privacy flags: **`public_logs=false`, `public_sysinfo=false`, `public_tcbinfo=true`**. These supplied observations are not a new production check. Preserve the private-log/private-sysinfo settings; do not silently change TCB-info exposure.

### Before/after compose identity and rollback

The preserved **current pre-N0** rollback compose is **`/home/tinycloud/scratch/tc959-n0-release/rollback-compose.yaml`**, mode **0600**, with no inline secret values. Local metadata/hash inspection confirmed mode 0600 and raw-file SHA-256 **`df239749ca0a9c09893a855ae2a8abb94090b8556515ad002105c58ac91f4c91`** without reading its contents or any env file.

Keep these identities distinct:

| Identity | Recorded value / meaning |
| --- | --- |
| Before: verifier `docker_compose_file` / hash | Raw preserved pre-N0 compose: `df239749ca0a9c09893a855ae2a8abb94090b8556515ad002105c58ac91f4c91` |
| Before: application `compose_hash` | `bfe9028a58b23238188aa7d70b82282a7cd6414cd83dcc47a3b295c6f64fe2f8`; a distinct reported identity, not the raw-file hash |
| After: current profile-enabled raw compose | `ca110b0bae6d5a06a1002fb80df3f71cffec11659c9f9dbfa5d72624735546f6`; bind this artifact to the final reviewed PR head before any promotion |

The raw after hash identifies the profile-enabled compose, not deployment approval. Record its final reviewed PR head and required CI evidence in the officer handoff. Do not infer a raw-file hash from the distinct application-reported compose hash.

### Approved workflow contract: no deployment authorization

The canonical release contract is [#313 `docs/releasing.md` at `63d11dd67e07378acb9213ecd8e3b895c7be5931`](https://github.com/TinyCloudLabs/tinycloud-node/blob/63d11dd67e07378acb9213ecd8e3b895c7be5931/docs/releasing.md), approved by the same Astra in [comment 6226203726](https://github.com/TinyCloudLabs/tinycloud-node/pull/313#issuecomment-6226203726). It supersedes the earlier N0-specific quota snapshot input and the separate #310 candidate packet.

**HOLD:** #313 remains unmerged until Holden/Sam provision the runner-only `PROD_TINYCLOUD_BILLING_ADMIN_SECRET`. This document does not provision or read it. The billing credential never belongs in the CVM environment or `allowed_envs`. Workflow/security recovery must land as the approved combined lineage first; the N0 sidecar compose belongs only to a later separately approved logging window. No command below is merge, privacy-choice or dispatch authorization.

| Operation | Required inputs / approval | Effect |
| --- | --- | --- |
| Every `deploy_phala=true` dispatch | Explicit `authorize_quota_values=true` and fresh authorization for the reviewed values and authority in `ops/quota-overrides.json` | One-dispatch authorization, not an N0-only snapshot or evergreen permission to reuse old values |
| Current-compose promotion or same-image recovery | Recorded immutable image identity; no captured-rollback/privacy inputs | Uses current main compose and preserves its current logging policy |
| Captured pre-N0 compose rollback | `rollback_pre_n0=true`, plus explicit `rollback_privacy_mode` matching Sam's approved repository variable `TC959_ROLLBACK_PRIVACY_MODE` | Uses the fixed-path/hash rollback source and the selected logging policy |

Missing quota authorization or unknown authority fails before compose, CVM or whitelist mutation. Sealed-runtime preflight remains mandatory on forward, recovery and rollback paths. Quota reconciliation follows the final environment operation and required version/ingress health, before ancillary Policy probes; attempted restart without verified reconciliation is fatal **`OVERRIDES UNVERIFIED`**. See the pinned canonical guide for the node-override/billing authority checks and operator fallback.

#### Current-compose same-image promotion or recovery

After the combined workflow is reviewed/landed, a named operator is approved and fresh quota-values authorization exists, the canonical command is:

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f image_version=1.20.6 \
  -f deploy_image_digest=sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f \
  -f rollback_image_version=1.20.6 \
  -f rollback_image_revision=e18578ff9162986ddd813259c60f73866e3e60d1 \
  -f sql_identity_fence=false
```

This is not a captured compose rollback and does not automatically install the sidecar: it uses the current main compose, whether approved pre-N0 or exact reviewed N0 bytes. Served/OCI identity remains **1.20.6-dstack / e18578ff9162986ddd813259c60f73866e3e60d1**; it is not an unrelated checkout crate version.

#### Captured pre-N0 rollback: explicit privacy choice

The reviewed repository source is `ops/rollback/pre-n0-compose.yaml`, byte-identical to the captured raw hash `df239749ca0a9c09893a855ae2a8abb94090b8556515ad002105c58ac91f4c91`. Fixed-path/hash validation rejects other paths, symlinks and source drift. Selecting the same node digest alone is **not** this compose rollback.

**There is no automatic privacy choice.** `unselected` refuses rollback. Sam must explicitly select the policy; Amos records it in repository variable `TC959_ROLLBACK_PRIVACY_MODE`, and the dispatch's `rollback_privacy_mode` must match. Neither conditional command chooses or authorizes that policy.

If Sam selects **`keep-json-file`**, retain the captured node/ingress 3×50 MB local logging policy:

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f rollback_pre_n0=true \
  -f rollback_privacy_mode=keep-json-file \
  -f image_version=1.20.6 \
  -f deploy_image_digest=sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f \
  -f rollback_image_version=1.20.6 \
  -f rollback_image_revision=e18578ff9162986ddd813259c60f73866e3e60d1 \
  -f sql_identity_fence=false
```

If Sam selects **`stop-future-local-logs`**, the reviewed derivative changes only the node and ingress logging drivers to `none`:

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f rollback_pre_n0=true \
  -f rollback_privacy_mode=stop-future-local-logs \
  -f image_version=1.20.6 \
  -f deploy_image_digest=sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f \
  -f rollback_image_version=1.20.6 \
  -f rollback_image_revision=e18578ff9162986ddd813259c60f73866e3e60d1 \
  -f sql_identity_fence=false
```

That derivative's raw SHA256 is `315ceca54bf8bfefe2b395b4097fe38ed8ec847fa0688bc873220bd65efc99ec`. **Stopping future logs does not delete existing files. There is no truncation/deletion path.** Any destructive action requires separate explicit authorization and a reviewed procedure. Keeping prior json-file logging may restore raw retention; never install a stealth fallback.

Privacy inputs are rollback-only and mutually exclusive with ordinary current-compose promotion. Preserve the private logs/sysinfo settings and the previously recorded logs/sysinfo/tcbinfo flags **false/false/true**. Keep actual versions/revisions in main history; no bypass flags or retired refs. A binary rollback across a database schema migration still needs its separate DB-safety decision.

Before any later authorized promotion, reconcile canonical/vendor activation, required exact-head CI/reviews, final artifact hash, the approved logging window and measured volume allowance, fresh quota authority/values and sealed-token presence without exposing it. Record source/sink arrival with positive leak controls. No production checks, Phala API calls, secret reads, merge, dispatch or deployment are authorized by this packet.
