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

LOCAL, fakes only: `/usr/bin/env python3 scripts/test-ingress-cf-only.py` and the
existing `scripts/test-ingress-switch.py` (real switch on temp files, fake
clients for everything remote). **Not run, ever, by this change:** the real
Cloudflare reader and the real network probe against any live system, any
Phala call, any drill. The Cloudflare endpoint shapes (tunnel, configurations,
DNS records, Worker deployments, routes) are [INFERENCE] from API documentation.
**The Worker script settings/bindings endpoint
(`GET /accounts/{id}/workers/scripts/{name}/settings`, a `plain_text` binding named
`ORIGIN_URL`) is [INFERENCE] and was not run.** If any read does not match
(absent, duplicated, secret or other type), preflight refuses rather than guessing.

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
`tinycloud-tee-proxy`), optional `--expect-worker-version`. Capture
`target.json`, `app-compose.json` and `network.json` as in the switch runbook.

### preflight

```sh
CLOUDFLARE_READ_TOKEN=... python3 scripts/ingress-cf-only.py preflight <shared> --out receipt.json
```

Builds the receipt from real reads and writes it `0600`, exclusively. Labelled
**operator evidence from automated reads, not a cryptographic attestation.** It
refuses unless **all** hold:

1. the tunnel exists, is the expected id, not deleted, `healthy`, with at least one
   connection and none pending reconnect (connector authenticated);
2. its ingress routes the tunnel host to `http://tinycloud:8000`;
3. the tunnel host has exactly one proxied CNAME to `<tunnel-id>.cfargotunnel.com`;
4. the Worker has a readable single 100% version (and `--expect-worker-version` if
   given), its **deployed** variable `ORIGIN_URL` (plain-text binding read from the
   script settings, set with `wrangler deploy --var ORIGIN_URL:<origin>`) is exactly
   `https://<tunnel-host>` and not a `*.phala.network` host, and
   `node.tinycloud.xyz/*` routes to that script. The Worker source is never read, and
   there is no source-constant fallback;
5. `/info` on the tunnel host and on `node.tinycloud.xyz` returns 200 with the same
   non-empty `nodeId`.

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
  --confirm <plan-hash> --patch-out restrict.patch.json
```

Re-runs preflight and the plan; refuses unless `--confirm` equals the fresh hash (any
evidence, compose or policy change makes the old hash stale). Then stages the local
compose through the switch (new `0600` snapshot, exclusive), writes the payload file
and **prints** `phala api /cvms/<cvm> -X PATCH --input restrict.patch.json` for the
authorized operator. Nothing is sent. It can be used once per snapshot path.

### verify

```sh
python3 scripts/ingress-cf-only.py verify --expect restricted --expect-app-id ... \
  --instance-id ... --gateway-domain ... --management-endpoint HOST:10022 \
  --tunnel-host ... --snapshot previous-policy.json --receipt receipt.json
```

Run after the operator has applied the PATCH and the restart finished. Passes only
if:

- `/info` on `node.tinycloud.xyz` and on the tunnel host is 200 with the receipt's
  node id (equal ids);
- fresh connections to `tee.node.tinycloud.xyz` and to the app and instance
  gateway hosts `-8000`, `-8000g`, `-443`, `-443s`, `-443g` (plus any
  `--extra-host`) are **refused over IPv4 and IPv6**. A timeout, error, resolver
  failure or a node response is a failure. An IPv6 name with no AAAA record fails
  unless `--allow-no-aaaa`, because the absence of an AAAA answer is a dated DNS
  observation, not proof that no IPv6 path exists;
- the management endpoint (`HOST:10022`, supplied by the operator, never guessed) is
  still TCP-reachable when the snapshot's policy keeps management, or refused if it
  denies it. This is a connect check only; key-authenticated access is not tested;
- the receipt is not older than `--max-receipt-age` (default 3600 s) and the snapshot
  is an owner-only file for the same app.

It lists what it does **not** cover: independent external networks (one vantage),
cached or literal-IP paths, existing long-lived connections, the provider read-back
of `/network` and `/compose_file`, streaming/SSE. Do those by hand per the switch
runbook. Exit status is non-zero on any failure.

### undo

```sh
python3 scripts/ingress-cf-only.py undo --compose app-compose.json --target target.json \
  --expect-app-id ... <verify inputs> --snapshot previous-policy.json --patch-out undo.patch.json [--apply]
```

Requires the `0600` snapshot from `apply-patch`, runs the switch `--restore`
(dry-run unless `--apply`, which stages the local restore), writes the reverse
payload and prints the PATCH command and the `verify --expect restored` command.
**HTTP first:** keep the tunnel and Worker unchanged; do not point the Worker at the
public `-8000` origin before `verify --expect restored` passes. Before running the
PATCH, compare the live provider policy to the snapshot `after` printed by `undo`;
on drift stop and reconcile (the script cannot read Phala). `restored` expects the
tee host to serve the same node id over IPv4 and the management check to match the
previous policy; if the previous policy was restrictive it refuses to automate and
you check by hand.

## Rollback of this change

Delete `scripts/ingress-cf-only.py`, `scripts/test-ingress-cf-only.py` and this
file. Nothing else references them and no deploy, config or policy depends on them.
