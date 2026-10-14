# TC-959: tinycloud-node Better Stack log shipping

## Phase 1 data path

The node app emits JSON tracing records (`TINYCLOUD_LOG__FORMAT=Json`). The ingress emits its TC-970 redacted access records. Docker forwards only these two services to the local Vector Fluent source using the asynchronous Fluentd driver. `log-shipper/vector.yaml` is the source config; the generator embeds an escaped copy into Compose and CI checks parity.

The VRL remap starts from an empty object. Node records require a known fixed message; variable error text is matched only by a fixed prefix and never copied. Unknown messages, non-JSON, non-object JSON, malformed typed fields, and Docker partial records are dropped and increment the Vector remap component's internal discarded-event counters. Those counters are not exposed through an API or metrics sink. Ingress routes, methods, status, duration, response bytes, and upstream status are validated against `log-shipper/fields.json`; only route templates are emitted. Raw paths, query strings, request headers, error text, and arbitrary nested values are not forwarded. Remap failures are dropped.

Ingress failures are counted per minute by `(route, status_class)`, successful requests by route, and slow requests remain bounded warning events; a slow 2xx is both counted and marked slow. Panic has a dedicated 2/min lane and node ERROR has a dedicated 5/min lane. Node WARN is capped at 5/min and then shares the request lane with ingress aggregates and slow requests, capped at 27/min. Request traffic and WARN cannot consume the panic or ERROR lanes. The sink retains at most 1,000 events in memory and drops newest when full. There is no Vector API or exposed metrics port; Fluent input is published only on `127.0.0.1:24224`.

The ingest hostname is configured once as `BETTERSTACK_SOURCE_HOST` in the Vector service environment; the entrypoint validates it and substitutes it into the generated config's placeholder before Vector starts. The source token is the GitHub `production` environment secret `PROD_TINYCLOUD_BETTERSTACK_SOURCE_TOKEN`; deploy writes it into the sealed environment as `BETTERSTACK_SOURCE_TOKEN` and synchronizes `allowed_envs` after compose startup. An absent token leaves only Vector idle; the node and ingress have no dependency on it. Docker container environment metadata is visible to principals with `docker inspect` access, so restrict CVM Docker access accordingly. No token value belongs in this repository or logs.

At go-live, create a Better Stack alert for `event = node_fatal_panic`.

## Redaction boundary

The allowlist excludes signed-KV tickets, authorization headers, tokens, transcript text, SQL values, meeting URLs, X-Forwarded-For and CF-Connecting-IP values, IPv4/IPv6 addresses, raw paths/IDs, UCAN/SIWE/delegation strings, owner DIDs or wallet addresses, space IDs, e-mail addresses, nested objects, arrays, and all unknown keys. Unknown ingress paths collapse to `<unmatched>` only after the raw route string passes its 256-character bound. The panic hook emits only a fixed JSON message and does not serialize panic text or source location; a WARN cannot forge that alert. See `log-shipper/vector.tests.yaml` for forbidden-value, malformed-value, priority-lane flood, route-template, multi-upstream, and fixed-panic cases.

## Resource and volume budget

The node CVM is tdx.medium: 2 vCPU, 4 GiB RAM, 20 GiB disk. Vector is hard-capped at 64 MiB (1.56% of RAM) and 0.25 CPU (12.5% of 2 vCPU). Measured node Vector memory and CPU peaks are **PENDING** the reviewed Docker burst check; the ptx-batch observation of 16.83 MiB under a 7,000-event burst is a reference only, not a node measurement.
The Linux/amd64 `ghcr.io/tinycloudlabs/tinycloud-node:dstack` registry manifest measured 17,115,015 compressed layer bytes across seven layers. The Docker check uses that registry image; no local build is needed for the small pull.

The conservative monthly calculation charges each cap independently: `2 + 5 + 5 + 27 = 39 events/minute`. Over 30 days: `39 × 60 × 24 × 30 × 281 = 473,428,800 bytes` (about 0.473 GB, 452 MiB), below the node's 0.48 GB allocation of the shared 3 GB free quota. Per-cap arithmetic: panic `2 × 60 × 24 × 30 × 281 = 24,278,400 bytes`; app ERROR and WARN each `5 × 60 × 24 × 30 × 281 = 60,696,000 bytes`; shared request lane `27 × 60 × 24 × 30 × 281 = 327,758,400 bytes`. WARN is counted in both its own 5/min cap and the 27/min request cap in this conservative estimate.

The successful-counter route enum has 36 members (35 known templates plus `<unmatched>`). A route string longer than 256 characters is dropped before normalization; other unknown paths map to `<unmatched>`. Failure counts aggregate by route and status class. The transformed event-size guard and per-lane throttles cap emitted bytes; excess events are dropped in their own lane rather than borrowing another lane's quota. These limits bound node output, not other services' shared quota usage.

Each of the two Fluentd producers has a 1,000-event queue. The planning assumption of a 16 KiB raw line plus 1 KiB event/driver overhead gives `17 KiB × 1,000 × 2 = 34,816,000 bytes` (33.2 MiB). Adding Vector's 64 MiB cap gives 97.2 MiB (2.37% of 4 GiB). Docker does not enforce the assumed 16 KiB raw-line ceiling, so this is not a guaranteed producer-queue byte bound. The explicit Compose `mem_limit` sum is 64 MiB (Vector only); the node, ingress, and ssh helper have no Compose memory caps, so this is not a bounded whole-guest memory total. Do not treat remaining guest memory as guaranteed headroom.

## Local log retention exceptions

The node app and ingress use the asynchronous Fluentd driver with a 1,000-event limit and `20m × 5` cache settings each. The Vector sidecar and ssh gateway retain capped `json-file` logs (`10m × 3`) and are not sent to themselves; this prevents a feedback loop and keeps helper logs local. Postgres is managed outside this Compose file, so there is no database container log stream to ship. No service depends on Vector for startup or request handling.

## Verification and deploy gate

Non-Docker CI checks the canonical common + `services.tinycloud-node` schema, generated VRL, generated Compose parity, and generator tests. The single `/tmp/tc-959-node-docker-check.sh` review script runs the pinned Vector VRL suite, Compose render parity, node-serving checks with Vector stopped/restarted, and a Vector memory burst; it is intentionally not run by this change. Production deployment remains Amos-owned. Compose hash, app-id, KMS attestation, and `allowed_envs` must be checked by the release gate; the node Vector peak remains pending until that window.
