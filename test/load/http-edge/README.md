# HTTP edge protocol probe (TC-408)

Diagnostic CLI for measuring ALPN negotiation, HTTP/1.1 vs HTTP/2 connection
reuse, and latency at a TLS ingress in front of tinycloud-node, **without**
changing Rocket, deployment, CORS, authorization, replay, revocation, or the
LAN proxy. This tool is read-only: it only ever issues unauthenticated GET
requests against `/healthz`.

## What it measures

- Certificate identity/fingerprint, negotiated ALPN protocol, response
  protocol/status, remote address, HTTP/2 peer settings, request timings,
  errors, connection/socket counts, and HTTP/2 stream IDs.
- HTTP/1.1 traffic uses one bounded keep-alive `https.Agent`; HTTP/2 traffic
  uses one explicitly created `http2` client session. Socket and session
  creation are counted directly by wrapping each connection factory, not
  inferred from request completion.
- Warm HTTP/1.1 and HTTP/2 rounds alternate at concurrency 1, 8, and 32. DNS
  lookup, TCP connect, and TLS handshake time are recorded separately from
  request latency; one warm-up round per concurrency level is executed but
  excluded from the reported p50/p95/p99.

## What it never records

Authorization headers, cookies, request/response bodies, credentials, or any
URL containing user data. The CLI only accepts a bare `https://` origin (no
embedded credentials, path, query, or fragment) and requires `--path` to be
on a fixed allowlist that today contains exactly `/healthz` — the only
unauthenticated, side-effect-free GET route tinycloud-node exposes. Every
other route either requires an Authorization header or mutates state and is
out of scope for this tool. Errors are reported as a sanitized `{ code, kind
}` pair; raw Node error messages (which can echo connection options) are
never surfaced. This redaction is sentinel-tested in `probe.test.mjs`.

## Fail-closed validation

The probe exits non-zero and sets `"ok": false` in its JSON output whenever:

- ALPN is missing, or a forced HTTP/1.1 connection fails to negotiate
  `http/1.1`, or the HTTP/2 session fails to negotiate `h2`.
- A response status does not match `--expected-status`, a request times out,
  or a response is truncated by the `--max-response-bytes` bound.
- Sample counts are incomplete (fewer successes than attempted requests).
- HTTP/2 stream IDs are not distinct (accounting ambiguity).
- **Concurrency-32 HTTP/2 specifically** also requires 32 distinct successful
  streams multiplexed on exactly one client TLS connection, and a peer
  `maxConcurrentStreams >= 32`. Anything else — including a mid-run
  reconnect — fails that result closed.

The full JSON report is built in memory and written in a single atomic write
at the end of the run, so a crash mid-run cannot produce truncated or
malformed output; any uncaught error instead yields a minimal
`{ ok: false, fatal: true, reason }` envelope.

## Usage

```bash
node test/load/http-edge/probe.mjs \
  --origin https://node.tinycloud.xyz \
  --path /healthz \
  --out /tmp/tc408-node-probe.json

npm run probe:http-edge -- --origin https://node.tinycloud.xyz --path /healthz
npm run test:http-edge-probe
```

Key flags (all bounded; see `probe.mjs` for exact limits): `--concurrency`
(default `1,8,32`), `--rounds`, `--warmup-rounds`, `--max-response-bytes`,
`--request-timeout-ms`, `--connection-max-lifetime-ms`, `--expected-status`,
and `--ca` (adds a trusted CA for verification, e.g. for a private ingress —
it never disables certificate validation).

## Results as of 2026-07-31 (provisional)

Ran once against each of `node.tinycloud.xyz` and `tee.node.tinycloud.xyz`
using the command above at default settings (concurrency 1/8/32, 3 measured
rounds, 1 warm-up round). **These two runs are provisional spot checks of
the ingress in front of these two hosts on this date — they are not a
complete inventory of every TinyCloud ingress, and they are not a substitute
for a proper production ALPN trace** (see follow-ups below). Treat any
numbers here as indicative, not as an SLA baseline.

| Host | ALPN (h1 forced / h2) | Connections at c=1/8/32 (h1 / h2) | h2 peer maxConcurrentStreams | p50 ms h1 vs h2 (c=32) | Overall verdict |
|---|---|---|---|---|---|
| `node.tinycloud.xyz` | `http/1.1` / `h2` | 1,8,32 / 1,1,1 | 100 | 425.9 / 421.4 | `ok: true` |
| `tee.node.tinycloud.xyz` | `http/1.1` / `h2` | 1,8,32 / 1,1,1 | 100 | 405.5 / 406.1 | `ok: true` |

Both hosts already negotiate `h2` at the TLS edge and hold every
HTTP/2 concurrency level (1, 8, and 32) on exactly one client TLS
connection, while forced HTTP/1.1 opens one socket per concurrent request
(up to the bound). Neither run is a complete picture of production
behavior under real client traffic; re-run the two commands above and
attach fresh JSON artifacts before relying on these numbers for a
go/no-go decision.

## Follow-ups that do not block this PR

- **Production ALPN traces**: a longer-running, packet-level capture (e.g.
  via the ingress's own access logs or a `tcpdump`/`tshark` trace) across all
  production ingresses, not just the two spot-checked above.
- **Deployed ingress inspection**: enumerate every TinyCloud ingress/host and
  confirm HTTP/2 is enabled and configured consistently across all of them.
- **Upstream socket telemetry**: instrument the ingress-to-Rocket keep-alive
  pool itself (connection count, reuse rate, queueing) rather than inferring
  it from the client side, as this probe does.
- **Rollout and fallback plan**: a staged plan for enabling `h2` at each
  ingress with a documented fallback to HTTP/1.1 if a client or intermediary
  misbehaves.
- **HTTP/3 evaluation on a representative network**: measure on a
  lossy/high-latency network profile (e.g. simulated mobile 3G/4G) before
  deciding whether HTTP/3 is worth pursuing.

## Why HTTP/3 is deferred

An `alt-svc` header advertising `h3` does not, by itself, prove a client
actually used QUIC or that doing so improved anything — it has to be
measured on a representative lossy network, which is one of the follow-ups
above. Direct-ingress QUIC/HTTP/3 support has not been verified for our
deployment target. Separately, TLS/QUIC 0-RTT resumption is a replay risk
for mutating invocations and requires its own security review before it can
be enabled for anything beyond idempotent GETs — it is out of scope here and
remains disabled.
