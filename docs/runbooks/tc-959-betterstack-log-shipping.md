# TC-959: tinycloud-node Better Stack log shipping

## Phase 1 data path

The node app emits JSON tracing records (`TINYCLOUD_LOGGING__FORMAT=json`). The ingress emits its TC-970 redacted access records. Docker forwards only these two services to the local Vector Fluent source using the asynchronous Fluentd driver. `log-shipper/vector.yaml` is the source config; the generator embeds an escaped copy into Compose and CI checks parity.

The VRL remap starts from an empty object. Node records require a known fixed message; variable error text is matched only by a fixed prefix and never copied. Unknown messages, non-JSON, non-object JSON, malformed typed fields, and Docker partial records are dropped and increment the Vector remap component's internal discarded-event counters. Those counters are not exposed through an API or metrics sink. Ingress routes, methods, status, duration, response bytes, and upstream status are validated against `log-shipper/fields.json`; only route templates are emitted. Raw paths, query strings, request headers, error text, and arbitrary nested values are not forwarded. Remap failures are dropped.

Every ingress 4xx/5xx and request taking at least one second is sent as a bounded request event. Every 2xx contributes to a per-minute counter grouped by route template; a slow 2xx also emits its slow-request event. Vector throttles the combined output at 300 events per 60 seconds. The sink retains at most 1,000 events in memory and drops newest when full. There is no Vector API or exposed metrics port; Fluent input is published only on `127.0.0.1:24224`.

The ingest hostname is configured once as `BETTERSTACK_SOURCE_HOST` in the Vector service environment; the entrypoint validates it and substitutes it into the generated config's placeholder before Vector starts. The source token is the GitHub `production` environment secret `PROD_TINYCLOUD_BETTERSTACK_SOURCE_TOKEN`; deploy writes it into the sealed environment as `BETTERSTACK_SOURCE_TOKEN`, synchronizes `allowed_envs`, and Vector writes it into its directory-secret mount. No token value belongs in this repository or logs.

At go-live, create a Better Stack alert for `event = node_fatal_panic`.

## Redaction boundary

The allowlist excludes signed-KV tickets, authorization headers, tokens, transcript text, SQL values, meeting URLs, IP addresses, raw paths/IDs, owner DIDs or wallet addresses, space IDs, e-mail addresses, nested objects, arrays, and all unknown keys. The panic hook emits only a fixed JSON message and does not serialize panic text or source location. See `log-shipper/vector.tests.yaml` for forbidden-value, malformed-value, unknown-key, route-template, and fixed-panic cases.

## Resource and volume budget

The node CVM is tdx.medium: 2 vCPU, 4 GiB RAM, 20 GiB disk. Vector is hard-capped at 64 MiB (1.56% of RAM) and 0.25 CPU (12.5% of 2 vCPU). Measured node Vector memory and CPU peaks are **PENDING** the reviewed Docker burst check; the ptx-batch observation of 16.83 MiB under a 7,000-event burst is a reference only, not a node measurement.

Each of the two Fluentd producers has a 1,000-event queue. Budgeting with the ptx-batch assumption of a 16 KiB raw line plus 1 KiB event/driver overhead gives `17 KiB × 1,000 × 2 = 34,816,000 bytes` (33.2 MiB). Adding Vector's 64 MiB cap gives 97.2 MiB (2.37% of 4 GiB). Docker does not enforce the assumed 16 KiB raw-line ceiling. The explicit Compose `mem_limit` sum is 64 MiB (Vector only); the node, ingress, and ssh helper currently have no Compose memory caps, so this is not a bounded whole-guest memory total. Do not treat remaining guest memory as guaranteed headroom.

The supplied raw baseline is about 250,000 ingress lines/day. With 36 route templates, successful requests can emit at most 51,840 per-minute route counters/day (`36 × 1,440`); at the maximum serialized counter size of 172 bytes, that is about 8.9 MB/day before compression. Failed, slow, and application warning/error events add to this. The strict throttle ceiling is 432,000 shipped events/day; the largest bounded ingress event is 280 bytes, so continuous saturation could reach 120.96 MB/day (about 3.63 GB per 30 days). No production traffic sample is available here; the routine daily estimate is therefore **not measured**, and the saturation bound can exceed the free-plan monthly allowance. Check Better Stack ingestion during the Docker/release window before go-live.

## Local log retention exceptions

The node app and ingress use the asynchronous Fluentd driver with a 1,000-event limit and `20m × 5` cache settings each. The Vector sidecar and ssh gateway retain capped `json-file` logs (`10m × 3`) and are not sent to themselves; this prevents a feedback loop and keeps helper logs local. Postgres is managed outside this Compose file, so there is no database container log stream to ship. No service depends on Vector for startup or request handling.

## Verification and deploy gate

Non-Docker CI checks the canonical common + `services.tinycloud-node` schema, generated VRL, generated Compose parity, and generator tests. The single `/tmp/tc-959-node-docker-check.sh` review script runs the pinned Vector VRL suite, Compose render parity, node-serving checks with Vector stopped/restarted, and a Vector memory burst; it is intentionally not run by this change. Production deployment remains Amos-owned. Compose hash, app-id, KMS attestation, and `allowed_envs` must be checked by the release gate; the node Vector peak remains pending until that window.
