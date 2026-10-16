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
| `node_request`, `svc=api` | `method`, canonical `route` template, integer `status`, nonnegative integer `latency_us` | Every valid INFO `tinycloud::request` record individually; no sampling, throttle, aggregation or byte-budget drop |
| `ingress_request`, `svc=ingress` | Same method/route/status, distinct numeric `request_time_seconds` | Every valid ingress access record individually, including 1xx/3xx/4xx/5xx |
| `node_warning` / `node_error`, `svc=api` | Fixed `event_code`, integer `event_count` | Count all accepted application diagnostics by fixed code and severity; emit grouped counts approximately every 60 seconds |
| `logship_gate_summary_total`, `svc=logship` | Fixed `reason`, integer `count` | Count every rejection that reaches the boundary; emit approximately every 60 seconds per fixed reason |

Rocket logs template query parts such as `/attestation?<nonce>` and `/public/<space_id>/kv?<prefix>`. Only explicit literal aliases map to canonical paths; arbitrary input is never split at `?` or normalized into a supposedly safe URI. `<unmatched>` is a fixed sentinel. TRACE/CONNECT map to `<other>`; ingress's existing `<other>` route maps to `<unmatched>`. All other unexpected typed fields are rejected and counted, never relayed.

Application warning/error targets are the actual `tinycloud` / `tinycloud::*` and `tinycloud_core` / `tinycloud_core::*` crate targets. Known messages map to fixed codes, including the release's network-DID warning, invalid link/loopback addresses and missing renewed-cert state. Unknown application warnings/errors, including the raw tunnel-close message, become `unclassified` counts without their message. Dependency/unknown targets and filtered levels are counted separately.

**No fatal-panic claim:** 1.20.6's panic hook emits plain text, not a typed JSON panic event. Non-JSON panic lines contribute only to a content-free rejection count if received. N0 neither emits nor declares `node_fatal_panic`, and cannot distinguish a panic from other non-JSON output. Request IDs, replacement flags, account/space HMACs, DB timings and trace propagation require N2. N0 ignores and omits them, including forged input values. Shared future contract: canonical `ops/logging/request-id.md` and `request-id-vectors.json`, version 1, at the revision in `log-shipper/canonical.json`.

## Volume: explicit limit, never hidden sampling

Run `node log-shipper/budget.mjs <requests-per-minute>`. Decimal request allowance is **480,000,000 bytes per 30 days**, not a promise of free ingestion. One through-ingress request produces two events. Representative long valid fields cost 198 node bytes + 223 ingress bytes = **421 bytes/request** including NDJSON newlines. These are exact serialized representative records, not a proven float-serializer ceiling or provider billing formula. No gzip discount, HTTP overhead, provider enrichment or retry duplication is assumed. Actual traffic and billing must be measured before any authorized promotion.

| Requests/minute | Request bytes / 30 days | Request allocation |
| ---: | ---: | --- |
| 1 | 18,187,200 | Within |
| 26 | 472,867,200 | Within |
| 27 | 491,054,400 | Exceeds |
| 60 | 1,091,232,000 | Exceeds |
| 600 | 10,912,320,000 | Exceeds |

Sustainable representative rate is **26.39 requests/minute**, or 26 whole requests/minute. A singleton JSON-array framing assumption gives 423 bytes/pair and 26.27/minute; production explicitly uses NDJSON.

Diagnostics are **additional**, not secretly subtracted or dropped. The storm model covers all 52 codes at both severities (104 groups/minute) plus nine rejection groups/minute: 811,339,200 bytes/30 days with maximum-width count records. Real idle/no-diagnostic traffic is lower; grouped reduce flush timing is not a strict calendar-minute emission ceiling. At 60 requests/minute plus that continuous storm, the model totals 1,902,571,200 bytes. [Public Better Stack pricing](https://betterstack.com/pricing), read 2026-10-16, lists 3 GB/month retained for three days. That allowance is shared with other sources; this is not a service allocation, spend approval or assurance that an account cannot exceed it. The operator must approve traffic allowance or an explicitly reviewed launch scope before production. This PR has **one full-request profile only**; no error/slow-only fallback, priority-based drop or silent switch is implemented.

## Known transport and process risks

- The release formatter has **uncapped lines**. Vector rejects inner messages above 64 KiB after GELF framing and safe envelope parsing, but this does not cap emitter allocation, Docker framing, UDP chunk reassembly or decompression. The socket's configured maximum is 256 KiB; truncated/malformed framing may fail before VRL and cannot be reconstructed or fully counted there. Malformed outer JSON is counted by VRL without native decoder free text. Vector's memory cap bounds its process, not upstream allocations.
- GELF/UDP is not lossless or durable. Missing chunks, kernel queues, decoder failures and an absent/paused/OOM shipper can lose messages before the gate. Docker uses a bounded 4 MiB nonblocking queue; overflow can drop logs. This keeps the app independent of sink availability, not loss-free.
- Vector has a 1,000-event memory queue with `when_full=block`. HTTP retries/temporary outages can fill it, then backpressure the UDP reader and lose packets upstream. Process restart loses queued events and unfinished diagnostic groups. HTTP retries may duplicate events; no event ID exists in N0 to deduplicate reliably.
- **Docker logs are intentionally unavailable** for node/ingress after the GELF cutover: raw log caching is disabled. The dstack `/logs` API and `docker logs` are not a fallback. Do not restore raw cache or relay raw startup/panic/tunnel output as a workaround. A separate authorized privileged attach may inspect process output; N0 grants no such production access.
- Gate counters account for processed rejects, not all transport loss. Compare emitted synthetic canary counts, source/sink component metrics where available, and sink arrival; a zero gate count alone does not prove complete delivery or silence health. There is no new production monitor/alert in this PR.
- The sealed token is written only to the sidecar tmpfs and unset before Vector exec. Docker configuration and init's initial environment remain visible to Docker-daemon/equivalent principals. This is not a protection against that host authority.

## Verification and maintenance

```sh
node --test log-shipper/budget.test.mjs scripts/tc959-docker.test.mjs scripts/tc959-readiness.test.mjs
node scripts/tc959-check.mjs --canonical /path/to/tinycloud-dev/ops/logging/fields.json
node scripts/tc959-logship.mjs render-tests /tmp/tc959-tests.json
vector test /tmp/tc959-tests.json
node log-shipper/native-check.mjs /path/to/vector
node scripts/tc959-logship.mjs render-vector /tmp/tc959-vector.json http://127.0.0.1:9599/
vector validate --no-environment --skip-healthchecks /tmp/tc959-vector.json
```

The canonical repo is private. CI verifies the vendored bytes against the reviewed canonical commit/hash pin, the immutable image pins, the process/network constraints, and structural equality of compiled/embedded Vector config without env interpolation (`--env-file /dev/null`). It does not pretend unauthenticated CI can follow private canonical `main`. A schema change must land in a separate canonical PR, update both identical copies and the explicit provenance pin, and pass canonical consumer tests. The canonical active-vendor drift mechanism remains pending until this shipper is merged; promotion must reconcile its activation deliberately.

After changing VRL/schema/compiler sources, regenerate the embedded `VECTOR_CONFIG_JSON` scalar and rerun the parity gate. The source program is authoritative; never maintain a second hand-edited VRL copy. The application image is not rebuilt for this validation.

### Local Docker gate

Requires the QA coordinator's explicit window and a valid shared claim; no production inputs, URLs or secrets. Before every create/remove, the harness checks `host-slot check --owner tc959-n0`. Announce immediately before first create, get QA browser/host pre-state, and obtain post-cleanup browser/host sanity acknowledgement. Create one labelled network and all five containers once, reuse them for real node/ingress requests, local HTTP capture, injection/isolation controls, burst and pause/continuity; remove only this run's labelled resources in one final batch. No restart/recreate loop, host networking, network/resolver change or prune.

```sh
node scripts/tc959-docker.mjs --go --deadline <explicit-authorized-UTC-end>
```

The harness reports only typed status/error classes and counts. A readiness failure records each endpoint separately plus running/exit/OOM flags and fixed startup error classes from bounded synthetic-only attach buffers. It never prints raw container logs, headers, env values or canary strings. If a run fails, do not retry a lifecycle in the same window: diagnose offline and obtain a new explicit clearance. Record both failure and cleanup; no Docker acceptance is claimed until a successful complete run is recorded. First attempt failed combined readiness, then removed every labelled resource (0 containers, 0 networks, 0 volumes); its root cause was not established from that coarse probe.

Fixture readiness checks the actual Vector UDP socket and capture HTTP listener **before** measured application requests; a running container is insufficient. Native reproduction delivered 0/3 packets sent before the UDP socket opened and 3/3 after it opened. This establishes a startup-loss race, not a confirmed diagnosis of an earlier Docker timeout. Local-only internal metrics expose numeric source/gate/allowlist/sink hop counters on a container-loopback port for failure classification; this instrumentation is absent from production. Missing metrics remain unknown, not fabricated zeroes. The capture sink is also exercised natively with plain and gzip HTTP input. An earlier Docker attempt passed node/ingress health with all five containers running but observed no real request events; it was cleaned to zero labelled resources and does not satisfy acceptance.

## Promotion and rollback hold

Merge/review is not deployment. Before any later operator-authorized N0 promotion: approve the measured volume allowance, reconcile the sealed token's presence without exposing it, preserve both application/ingress digests, verify private-log settings and the production hold, and record source/sink arrival with positive leak controls. Never dispatch a release workflow from this runbook now. Rollback requires the separately reviewed previous compose/logging configuration; restoring json-file reintroduces raw retention and is an operator privacy decision, not an automatic fallback.
