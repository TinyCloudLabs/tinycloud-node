# Cloudflare-only ingress wrapper (TC-4194 P5)

## Status and scope

`scripts/ingress-cf-only.py {preflight,plan,apply-patch,verify,undo}` wraps the
merged local switch ([http-ingress-switch.md](http-ingress-switch.md),
`scripts/ingress-switch.py`, unmodified, run as a subprocess). It replaces the
hand-built `verified-origin.json` and the manual checks with automated reads and
probes. It is **not an installed production control**.

- **The script never executes the Phala `port_policy` PATCH, holds no Phala
  credential and makes no Phala call.** `apply-patch` and `undo` only EMIT the exact
  `phala api ... -X PATCH` command and the JSON payload file. Running it stays a
  Sam/Amos action under a Naomi GO.
- The only network access is read-only: Cloudflare API `GET`s (a scoped
  **read** token from `CLOUDFLARE_READ_TOKEN`, never printed) and HTTPS/TCP
  probes. All of it is behind injectable clients.
- The tunnel, the Worker change and the connector deploy (P1 to P4) are
  prerequisites, not done by this script. Closing `-8000` before they are verified
  breaks both HTTP routes; `preflight` refuses unless they are observed.

## What is and is not tested

LOCAL, no external network: `/usr/bin/env python3 scripts/test-ingress-cf-only.py` and
the existing `scripts/test-ingress-switch.py`. The real switch runs on temp files;
Cloudflare and `/info` clients are fakes; `NetworkProbe`'s signal classifier is run
against a loopback-only TLS server (throwaway certificate from `openssl`) covering a
normal node 200, a chunked 200, 404, 502, 421, 301, an unparsed 200, a TLS alert, a TLS
close with no response, silence (timeout), a closed port and an SSH banner; reset and
no-route connect errors are injected with a patched `socket.create_connection`.
**Not run, ever, by this change:** the real Cloudflare reader and the real network
probe against any live system or gateway, any Phala call, any drill. The Cloudflare
endpoint shapes (tunnel, configurations, DNS records, routes) are [INFERENCE] from API
documentation. **[INFERENCE, not run]:** the Worker deployment list (newest by
`created_on`, one 100% version) and the version-bound binding read
(`GET /accounts/{id}/workers/scripts/{name}/versions/{version_id}`, `resources.bindings`
containing a binding named `ORIGIN_URL` of type `secret_text`, no value returned);
the script-level `/settings` endpoint is deliberately not used because it may reflect
an uploaded but not deployed version. If any read does not match (absent or duplicated
binding, or any type other than `secret_text`), preflight refuses rather than guessing.

## Honest operating characteristics

- **It is a restart, not an instant switch.** The PATCH restarts the CVM: both HTTP
  paths are interrupted. Phala gives no convergence bound.
- **No timings have been measured.** No drill has run; there is no
  time-to-restrict or time-to-undo figure and none should be quoted.
- The only no-restart lever against an attack is on the Cloudflare side
  (Worker/WAF/route); it does not close the origin gateway. This policy does not stop
  L3/L4 floods at the Phala host.
- Clients still on `tee.*` lose HTTP when it is withdrawn (see the switch runbook).
- **The drill is a later, separately authorized GO** (restrict, measure
  acceptance, restart and recovery in UTC, undo, measure). Until then this is an
  untested action.

## Commands

Shared inputs: `--expect-app-id`, `--tunnel-id`, `--tunnel-host` (an independent
tunnel hostname, never `node.*`, `tee.node.*`, `*.phala.network`,
`*.cfargotunnel.com`), `--account-id`, `--zone-id`, `--worker-script` (default
`tinycloud-tee-proxy`), optional `--expect-worker-version`, and
`--attest-origin-is-tunnel-host` (required, see preflight item 5). Capture
`target.json`, `app-compose.json` and `network.json` as in the switch runbook.

### preflight

```sh
CLOUDFLARE_READ_TOKEN=... python3 scripts/ingress-cf-only.py preflight <shared> --out receipt.json
```

Builds the receipt from real reads and writes it `0600`, exclusively. Labelled
**operator evidence from automated reads, not a cryptographic attestation.** It
refuses unless **all** hold:

1. the tunnel exists, is the expected id, not deleted, `healthy`, with at least one
   connection and none pending reconnect. The receipt's `connector_authenticated` is
   exactly that Cloudflare-API-derived state and says so; it is not an independent
   authentication test;
2. its ingress's **first** rule for the tunnel host (no catch-all before it, no path
   restriction) routes to `http://tinycloud:8000`;
3. the tunnel host has exactly one proxied CNAME to `<tunnel-id>.cfargotunnel.com`;
4. the Worker has a readable single 100% version of the newest deployment (and
   `--expect-worker-version` if given); **exactly one** binding named `ORIGIN_URL` of
   type `secret_text` exists on **that deployed version** (P3 stores the origin as a
   Worker secret). **Presence and type only: the Cloudflare API never returns a secret
   value, so the origin value is not compared.** A `plain_text` `ORIGIN_URL` is
   refused, not accepted, because the secret is the approved path (redeploy it as a
   secret); an absent, duplicated or other-type binding is refused.
   `node.tinycloud.xyz/*` must route to that script and no more specific
   `node.tinycloud.xyz/...` route may point at another script. The Worker source is
   never read and there is no source-constant fallback;
5. the operator passed `--attest-origin-is-tunnel-host`, attesting that the P3
   set-origin step received exactly `https://<--tunnel-host>`. This is recorded in the
   receipt and in plan/preflight/verify output as **operator-attested, NOT verified**;
6. `/info` on the tunnel host and on `node.tinycloud.xyz` returns 200 with the same
   non-empty `nodeId`. Before the restriction this does not show which origin the
   Worker uses.

`--account-id` and `--zone-id` must be 32 hex characters and `--worker-script` a plain
script name; they are validated before any URL is built.

Node ids are printed only as a short SHA-256 fingerprint. The receipt file holds the
real value (it is private); do not commit it.

### plan

```sh
python3 scripts/ingress-cf-only.py plan <shared> \
  --compose app-compose.json --target target.json --network network.json --snapshot previous-policy.json
```

Runs preflight, then the switch dry-run. Prints the intended change, the exact undo
payload, the snapshot path and a **plan hash** over app/CVM, compose digest, tunnel,
Worker origin and version, node id, before/after policy, patch and snapshot path.
Changes nothing. The receipt it uses is temporary and deleted.

### apply-patch

```sh
python3 scripts/ingress-cf-only.py apply-patch <shared> <plan inputs> \
  --confirm <plan-hash> --patch-out restrict.patch.json --receipt-out receipt.json
```

Checks that the patch file, the receipt file and the snapshot are new paths in
writable directories **before** staging anything. Re-runs preflight and the plan;
refuses unless `--confirm` equals the fresh hash (any evidence, compose or policy
change makes the old hash stale). Then stages the local compose through the switch
(new `0600` snapshot, exclusive), writes the payload file and the fresh `0600`
receipt for `verify`, and **prints** `phala api /cvms/<cvm> -X PATCH --input
restrict.patch.json` for the authorized operator. Nothing is sent. It can be used once
per snapshot path. The printed `verify` command has quoted placeholders for the
instance id and gateway domain, which only you know.

### verify

```sh
python3 scripts/ingress-cf-only.py verify --expect restricted --expect-app-id ... \
  --instance-id ... --gateway-domain ... --tunnel-host ... \
  --snapshot previous-policy.json --receipt receipt.json [--allow-no-aaaa]
```

Run after the operator has applied the PATCH and the restart finished. The result is
`pass` (exit 0) or `FAIL` (exit 1). **There is no "indeterminate" outcome: only `pass`
is evidence.** It opens TLS/TCP connections to Phala **gateway** hostnames (network
contact with Phala infrastructure, not an API call and not a credentialed one).

**Closed means a positive refusal, nothing else:** a connect error (`tcp_refused`), a
reset (`tcp_reset`) or no route (`no_route`, ENETUNREACH/EHOSTUNREACH at connect).
Anything that completes TLS or HTTP is open or unknown, and open or unknown **fails**:
that includes a TLS alert (`tls_rejected`), a close after the handshake
(`closed_after_tls`), any HTTP status (`http_404`, `http_421`, `http_502`, ...),
`http_200_unparsed`, `malformed_http`, a node answer (`node_info`), a timeout, a
resolver failure and any other error. There is no flag to widen the set. A `/info` body
is de-chunked before the node id is read, so a chunked 200 counts as the node answering.

**Known consequence [INFERENCE, not observed]:** the gateway hostnames share an
SNI-routed IP, so a restricted gateway may deny by a TLS or HTTP signature rather than
by refusing the TCP connection. If so, `verify` will FAIL on a correctly restricted
host. That is the intended conservative behaviour: the drill must observe what a closed
gateway really does, and any change to the closed set is a reviewed code change, not an
operator flag. Checks:

- `/info` on `node.tinycloud.xyz` and on the tunnel host is 200 with the receipt's
  node id (equal ids): otherwise FAIL;
- fresh connections to `tee.node.tinycloud.xyz` and to the app and instance
  gateway hosts `-8000`, `-8000g`, `-443`, `-443s`, `-443g` (plus any
  `--extra-host`) over **IPv4 and IPv6** must each be positively refused. An IPv6
  name with no AAAA record fails unless `--allow-no-aaaa`: that flag is an explicit
  operator acknowledgement, because the absence of an AAAA answer is a dated DNS
  observation, not proof that no IPv6 path exists;
- management: **INFERENCE (not run, not observed)** that SSH is reached through the
  gateway TLS route `<app>-10022.<gateway>:443` (the compose comment, with
  `port_mappings` required empty), not a host port 10022. The probe does TLS with that
  SNI on 443 and requires an `SSH-2.0-` banner for "open"; the host is derived from
  `--expect-app-id` and `--gateway-domain`. Expected open (the snapshot policy keeps
  10022): only a banner passes. Expected denied: only a positive refusal passes (a
  banner, a TLS alert, HTTP or a timeout fail). If `phala ssh` actually reaches
  management another way, this check is wrong and must be corrected from evidence
  before relying on it. Key-authenticated access is not tested;
- the receipt (owner-only file) is not older than `--max-receipt-age` (default 3600 s),
  names the same tunnel host as `--tunnel-host` and the same tunnel id as the
  snapshot's recorded origin, and the snapshot is an owner-only file for the same app.

What the passing end-to-end checks can show: `node.tinycloud.xyz` answers `/info`
with the recorded node id **while every probed gateway path is positively refused**, so
the Worker reaches the node by some route other than the closed gateway. What they
**cannot** show: that the Worker's secret equals the tunnel host (another independent
origin serving the same node would also pass), that no unprobed gateway host or address
is used, or anything before the restriction (while the gateway is open, `node.*` passes
even if the secret still points at it). The script prints these limits.

It also lists what it does **not** cover: independent external networks (one vantage),
cached or literal-IP paths, existing long-lived connections, the provider read-back
of `/network` and `/compose_file`, streaming/SSE. Do those by hand per the switch
runbook.

### undo

```sh
python3 scripts/ingress-cf-only.py undo --compose app-compose.json --target target.json \
  --expect-app-id ... --instance-id ... --gateway-domain ... --tunnel-host ... \
  --receipt receipt.json --snapshot previous-policy.json --patch-out undo.patch.json [--apply]
```

Requires the `0600` snapshot from `apply-patch`, validates every operator value it
prints back, runs the switch `--restore` (dry-run unless `--apply`, which stages the
local restore), writes the reverse payload and prints the PATCH command and the
`verify --expect restored` command with your real receipt path (all values
shell-quoted). **HTTP first:** keep the tunnel and Worker unchanged; do not point the
Worker at the public `-8000` origin before `verify --expect restored` passes. Before
running the PATCH, compare the live provider policy to the snapshot `after` printed by
`undo`; on drift stop and reconcile (the script cannot read Phala). `restored`
requires the tee host to serve the same node id over IPv4 (otherwise FAIL) and the
management check to match the previous policy; if the previous policy was restrictive
it refuses to automate and you check by hand.

## Rollback of this change

Delete `scripts/ingress-cf-only.py`, `scripts/test-ingress-cf-only.py` and this
file. Nothing else references them and no deploy, config or policy depends on them.
