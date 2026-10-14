# TC-959: tinycloud-node Better Stack log shipping

## Transport and gate

The node and `dstack-ingress` use Docker's `gelf` logging driver with the exact service labels `tc.logship=tinycloud-node` and `tc.logship=tinycloud-ingress`. Both send UDP to `127.0.0.1:12201`. Vector listens inside its own bridge network at fixed address `10.255.253.2`; that network is not shared with app or Postgres services and has egress for Better Stack. The only published Vector port is `127.0.0.1:12201:12201/udp`. Vector has no `docker.sock` or `/var/lib/docker` mount. There is no DockerRootDir pre-deploy check.

`logship_gate` is the first transform. It reads `_tc.logship` as a string and accepts only the two exact labels. Missing/empty labels increment the fixed `logship_gate_dropped_total{reason="unlabelled"}` counter without content; every other label emits one fixed `logship_unexpected_label` event, throttled to about one per minute. After the gate, `strip_gelf_fields` reconstructs the event from only the approved label and GELF `message`, dropping all underscore-prefixed fields and dockerd metadata. `parse_gelf_message` then parses `.message`, the app's JSON line. The existing inner allowlist, schema projection, event enum, priority lanes, throttle, `budget_size_guard`, and sole sink input remain unchanged. Ingress non-JSON stderr is dropped after the gate.

Docker splits lines over 16 KiB into GELF fragments. An incomplete fragment does not parse as the app JSON line and increments the bounded malformed-envelope counter; no partial text is forwarded. The GELF socket source accepts chunked and gzip-compressed messages, with no checkpoint or replay state.

The node and ingress do not depend on Vector. Their GELF logging driver is UDP and does not require Vector to start. A missing Better Stack token leaves Vector idle. Postgres and every non-shipped service remain unlabelled and use capped `json-file` logs.

## Redaction and alerting

The allowlist excludes signed-KV tickets, authorization headers, tokens, transcript text, SQL values, meeting URLs, X-Forwarded-For and CF-Connecting-IP values, IPv4/IPv6 addresses, raw paths/IDs, UCAN/SIWE/delegation strings, owner DIDs or wallet addresses, space IDs, e-mail addresses, nested objects, arrays, and all unknown keys. Unknown ingress paths collapse to `<unmatched>` only after the raw route string passes its 256-character bound. The panic hook emits only a fixed JSON message and does not serialize panic text or source location; input level cannot forge the panic alert. See `log-shipper/vector.tests.yaml` for forbidden-value, malformed-value, priority-lane flood, route-template, multi-upstream, fixed-panic, GELF gate, metadata-stripping, and counter tests.

At go-live, create a Better Stack alert for `event = node_fatal_panic` and one source-silence alert per service, within free-plan limits. The lead's GELF/UDP spike passed restart/recreate recovery, 500-line outage-burst recovery, sibling forgery, and external-interface isolation. It also observed no app blocking. The full node-specific Docker acceptance script is review-only and has not been run here.

## Priority and monthly volume budget

The panic lane allows 2 events/minute; node app ERROR and WARN each allow 5/minute; ingress allows 27/minute. WARN and fixed gate counters pass through their own 5/minute warning lane, then feed `budget_size_guard` directly without entering the ingress throttle. The ingress lane carries per-minute `(route, status_class)` failure counts, per-minute route-only success counts, and slow requests. A 2xx/slow request is counted and marked slow; route cardinality is bounded to 35 known templates plus `<unmatched>`.

At the 281-byte final event-size limit, the worst case is `(2 + 5 + 5 + 27) × 60 × 24 × 30 × 281 = 473,428,800 bytes` (0.473 GB/30d), within the node's 0.48 GB allocation of the shared 3 GB free quota. The individual lane ceilings are 24,278,400 bytes for panic, 60,696,000 bytes each for app ERROR and WARN, and 327,758,400 bytes for ingress. These are hard ceilings assuming every allowed event reaches the sink; shared quota use by other sources is separate.

## CVM resource and disk budget

The CVM is tdx.medium: 2 vCPU, 4 GiB RAM, 20 GB disk. Vector runs as UID 10001 with 64 MiB memory/swap and 0.25 CPU limits, read-only root, all capabilities dropped, and `no-new-privileges`. Its `data_dir` is an 8 MiB tmpfs; the token file is mode 0600 under that same tmpfs. There is no volume initializer, Docker log-tree mount, or persistent checkpoint volume. Vector and ssh-gateway each have capped `json-file` logs (`10m × 3`), a 60 MB combined retention ceiling. Node and ingress logs travel through GELF rather than a local log file. The review-only acceptance harness measures Vector peak memory and reports 5,000-line burst loss; neither value has been measured by this change.

## Secrets and local-log exceptions

The ingest host is configured once as `BETTERSTACK_SOURCE_HOST` and substituted into the sink URL. The source token is GitHub `production` environment secret `PROD_TINYCLOUD_BETTERSTACK_SOURCE_TOKEN`, written to the sealed environment as `BETTERSTACK_SOURCE_TOKEN`. The entrypoint writes `SECRET[bs.bs_token]` into `/var/lib/vector/secrets/bs_token` on Vector's tmpfs, with a restrictive umask, then unsets the token and config environment variables before executing Vector. The token is not committed or logged. Docker daemon/API principals can inspect the container's configured environment; restrict daemon/API access.

Only node and ingress logs carry `tc.logship`. Vector and ssh-gateway retain capped, unlabelled `json-file` logs and are not shipped, preventing self-ingestion. Postgres is not mounted into Vector.

## Verification and deploy gate

CI checks the canonical common + `services.tinycloud-node` schema, generated VRL, byte-identical embedded Compose config, packaging restrictions (`configs.*.file`, `env_file`, and relative bind sources), and native Vector 0.59.0 validation/tests after verifying the release tarball SHA256. The review-only `tc-959-node-docker-check.review.sh` covers 5× each Vector restart, crash/restart-policy, and recreate; 3× Vector-down 500-line bursts; app service continuity; source-metric isolation; external-interface probes; and Vector memory. It includes a test-only node override with a local Postgres, a Static test key, TEE Off, and no dstack socket. It must only run after explicit Docker authorization. Amos owns production deployment and go-live alerts; do not use this runbook to deploy or change secrets.
