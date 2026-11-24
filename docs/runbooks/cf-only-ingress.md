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
  probes (`verify` also opens TLS connections to Phala gateway hostnames). All of it is
  behind injectable clients.
- **`verify --expect restricted` cannot pass yet.** The accepted closed-signature set is
  empty: on a shared SNI gateway a TCP refusal can never be app-specific, and the real
  denial signature has not been observed. Output says "no accepted closed signature
  yet: drill required". A drill must record the signature; it is then added in code under
  review. `--expect restored` does not depend on the set (IPv6 management note below).
- The tunnel, the Worker change and the connector deploy (P1 to P4) are
  prerequisites, not done by this script. Closing `-8000` before they hold breaks both
  HTTP routes. `preflight` observes the tunnel, DNS, ingress, Worker version, the
  `ORIGIN_URL` binding type and `/info` on both routes. **It does not observe the
  origin value**: the Worker's `ORIGIN_URL` is a secret that Cloudflare never returns, so
  it rests on the operator's `--attest-origin-is-tunnel-host`. **If that attestation is
  wrong (the secret still points at the `-8000` gateway), `node.*` goes down after the
  PATCH restart; `verify` then fails, and `undo` is a second restart.** Nothing here can
  detect that before the restart. Check the set-origin step's own record first.

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

**Rollback snapshot.** The unmodified switch stores `verified_origin.worker_origin` in
the snapshot, and its gate "Worker origin must be the independently verified tunnel
hostname" is satisfied here only because both values come from `--tunnel-host`.
`apply-patch` therefore annotates the snapshot in place (atomic replace, still `0600`;
the switch ignores the added keys on restore) with
`verified_origin.worker_origin_status = "operator-attested, NOT verified ..."` and a
top-level `verified_origin_note`, and `verify` refuses a snapshot without that
annotation. Read `snapshot.verified_origin.worker_origin` as the **attested** value, not
a read, whatever the switch's key name says. The P3 runbook's "independent origin
verification" premise is met by attestation, not by observation. The receipt keeps the
switch's `verified_at_utc` key (the switch requires it); the wrapper prints it as
`reads_observed_at_utc`.

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
`result: pass` (exit 0) or `result: FAIL`, and a FAIL carries a **verdict** with a
distinct exit code. Only `pass` is evidence, and there is no "indeterminate" pass.
It opens TLS/TCP connections to Phala **gateway** hostnames (network
contact with Phala infrastructure, not an API call and not a credentialed one).

**Decision table (key on exit code AND `verdict`; the output prints `verdict`, `exit_code`, `exit_codes` and a per-mode `next_action`):**

| exit | verdict | meaning | action |
|---|---|---|---|
| 0 | `pass` | every check proven; **unreachable for `--expect restricted` until a drill signature is accepted** | continue |
| 1 | `open`, `--expect restricted` | a probed gateway path answered 2xx (the node or not), management answered although the policy denies it, expected-open management accepted the connection but gave no SSH banner (not a connect-time refusal or reset), or `node.*` or the tunnel host is unhealthy | **undo** (restore) when `confirm_before_undo` is `false`. When it is `true` (only `/info` transport failures from this vantage, or only the management route failing after accept) **confirm from a second network or another app first, then undo** |
| 1 | `open`, `--expect restored` | the node path is broken after the restore (tee not serving the node, `/info` or management unhealthy) | **do NOT undo again** (the restore is already applied); investigate the tunnel, the Worker secret and the connector, confirm from a second network |
| 3 | `not_proven_closed`, `--expect restricted` | not proven closed, nothing seen open (every restricted check under the empty set: refusals, resets, TLS alerts, non-2xx HTTP, timeouts, no route, resolver failures, a failed control or instance binding; plus vantage/DNS limits and connect-time refusals/resets on management) | **hold; do NOT undo and do NOT restart on this alone.** From a **second, IPv6-capable network** check that the `-8000` hosts and `tee.node.tinycloud.xyz` `/info` do not return the node **and that the management route (`<app-id>-10022` on the gateway) still answers an `SSH-2.0` banner**, then run the drill. With the empty set a **correct** restriction reads `not_proven_closed` today |
| 3 | `not_proven_closed`, `--expect restored` | restored not proven from this vantage (typically an IPv4-only vantage while management has an AAAA record) | re-run from a second IPv6-capable network; do NOT undo again; no drill needed |
| 4 | (none: refused) | bad operator input or a failed read: stale receipt, loose file modes, wrong app, bad id or host, missing or odd snapshot, refused validation, a Cloudflare/Phala read that failed, an IO or parse error, an unexpected exception (stderr: "No verdict was computed: do NOT treat this as closed and do NOT undo on this alone; rerun"). **No verdict.** Nothing was changed or judged. A failed **receipt write** after the checks ran is NOT exit 4: the verdict keeps its own exit code (1/3), `receipt_record` says `FAILED` and stderr warns | **fix the input and re-run; never undo on exit 4** |

**`confirm_before_undo` (machine-readable, in the `verify` JSON).** `true` whenever an
exit 1 carries a hedge: every failing check is an `/info` transport failure seen from this
vantage, or every failing check is on the management route after the connection was
accepted (TLS alert, close, 502; the same signature as "the PATCH broke management", so
undo stays defensible, but confirm first). `false` for every other result: an exit 1
where a gateway path answered 2xx or management answers although denied (undo needs no
extra confirmation), restored exit 1 (never an undo), and exits 0 and 3. Exit 4 prints no
JSON. **A wrapper must not undo on exit 1 and `verdict=open` alone: undo only when
`confirm_before_undo` is `false`, otherwise confirm from a second network (or another
app) first.**

When a receipt write fails after the checks ran, stderr warns first (naming the leftover
`<receipt>.record` path), then the verdict JSON follows on stdout; the JSON's
`receipt_record` says `FAILED`.

**A stale receipt is likely**: the receipt's default max age is 3600 s and the restart
time is unmeasured, so a verify run after a slow restart is refused (exit 4, stderr
"Refused ... stale", empty stdout) until you rerun `preflight`. That is not a verdict.

**Exit codes, every subcommand.** `1` is reserved for the `open` verdict of `verify`, so a
wrapper or tired operator that undoes on exit 1 never undoes a correct restriction
because of a stale receipt. `3` is `verify` only (hold). `4` is returned by every
subcommand (`preflight`, `plan`, `apply-patch`, `verify`, `undo`) for a refusal or a
failed read; the reason is on stderr, with "never undo on this exit". `0` is success
(`preflight`/`plan`/`apply-patch`/`undo`: staged or printed, nothing executed; `verify`:
pass). `2` is argparse (bad flags). `preflight`, `plan`, `apply-patch` and `undo` never
return 1 or 3. `apply-patch` prints the table under `after_verify` (no `if_bad`: it used
to say "undo", which is wrong for `not_proven_closed`).

**The accepted closed-signature set is EMPTY, so `verify --expect restricted` cannot
pass yet: no accepted closed signature yet: drill required.** Reason: on an SNI-routed
shared gateway a TCP refusal happens before the SNI is seen, so it can never be
app-specific. `tcp_refused` means a local or on-path cause (a REJECT rule, wrong DNS,
a stale or split-horizon answer) or a gateway-wide outage, so it is not accepted.
`tcp_reset` is not accepted either. A connect-time `tcp_reset` happens before the SNI is
sent, exactly like a refusal, so it is never app-specific either. If a reset is ever
accepted it will count only
when the connect itself is reset: a reset after the TCP connect succeeded (during TLS
or HTTP, e.g. an RST on the ClientHello) is recorded as `reset_after_connect` and is
never eligible. The real denial signature of a restricted gateway has
never been observed [INFERENCE]; the drill must record it and the signature is then
added to `ACCEPTED_CLOSED_SIGNALS` in code, under review. No flag, environment variable
or file widens the set (`--accept-closed-signal` was removed). The output says so
(`blocked`). `--expect restored` does not depend on the set, but see the IPv6 management note below. Everything else
FAILs as well: `no_route` (it describes this verifier's network, not the target), a TLS
alert `tls_rejected`, `closed_after_tls`, a non-2xx HTTP status, `malformed_http`, a
timeout, a resolver failure and any other error are `not_proven_closed` (exit 3). **A 2xx
from a restricted path is `open` (exit 1) even when the body is not the node's**
(`node_info`, `http_200_unparsed`, any `http_2xx`); 404, 502, 301, TLS alerts and closes
stay exit 3. A `/info` body is de-chunked before the node id is read, so a chunked 200
counts as the node answering. Open and not-proven-closed results FAIL, never
"indeterminate".

**S9 caveat [INFERENCE].** A 2xx from a restricted path is `open`. If the gateway's real
status for a denied port is 2xx, or a TLS-intercepting proxy answers 200, that is a
false positive (exit 1). **The drill must record the real denied-port status.**

**Inherent one-vantage limits (documented, not fixable by this script).** (B) A local
REJECT rule or an on-path reset produces the same `tcp_refused` as a closed gateway;
that is why a refusal is never accepted. (A5) An open path reachable only over IPv6 is
not seen from an IPv4-only vantage: the v6 probe is `no_route`, which is exit 3, never
pass. Run verify from a second, IPv6-capable network. (NODATA) `--allow-no-aaaa` skips
IPv6 for a name whose DNS has no AAAA; the gateway's own IPv6 listener may still
answer that SNI when reached by a literal address or another resolver, and nothing here
probes it. Checks:

- `/info` on `node.tinycloud.xyz` and on the tunnel host is 200 with the receipt's
  node id (equal ids): otherwise FAIL;
- **`--instance-id` and `--extra-host` are bound to evidence.** The gateway probably
  answers an unknown SNI (a typo) like a closed one, so a typo could read as "closed".
  The instance id passes only if its own route `<instance>-10022.<gateway>:443` answers an
  `SSH-2.0-` banner [INFERENCE: that the instance has this route]; otherwise FAIL (always
  FAIL when management is denied). An `--extra-host` must be
  `<app-id|instance-id>-<port>.<gateway-domain>` or the command is refused before any
  probe. There is no `--accept-closed-signal` flag; it was removed;
- **A signature accepted later needs a same-address positive control.** For any
  signature added to the (empty) set, every address a probe resolved and found
  closed gets a control: `verify` connects to **that exact IP** (same family) with TLS
  SNI `<app-id>-10022.<gateway>` and requires an `SSH-2.0-` banner in the same run. A
  failing control (refused, timeout, TLS alert, HTTP, no route, anything else) makes the
  check **FAIL**; a closed signal with no recorded address also fails. The control
  dials the probe's own address, so IPv6 is covered without relying on a management
  AAAA. The mechanism is built and exercised in tests with a **test-only injected**
  entry; it cannot be reached from the CLI. The resolved addresses and control results
  are printed per check (`addresses`, `controls`) and **appended to the receipt**
  under `verify_runs` (UTC time, result, per-check addresses and controls; atomic
  replace, still `0600`), pass or FAIL. **What a control cannot exclude [INFERENCE]:** a
  path that rejects only the app's SNI after the handshake begins, and a gateway that
  changes between the control and the probe (separate connections seconds apart, one
  vantage). **Limit of the control [INFERENCE, tested only with a test-injected set]:**
  the control uses a different SNI (the management host) than the probe, so it cannot
  exclude SNI-based filtering or an RST on the app's ClientHello: with a test set that
  contains `tcp_reset`, an RST-at-hello would pass the control. Never add `tcp_reset`
  (or any signature) to `ACCEPTED_CLOSED_SIGNALS` without drill proof that the real
  gateway emits it only for a closed app. The `--allow-no-aaaa` waiver skips IPv6 for
  that name entirely; a stronger control (later, not built) would probe the control
  host's own IPv6 addresses with the app SNI;
- fresh connections to `tee.node.tinycloud.xyz` and to the app and instance
  gateway hosts `-8000`, `-8000g`, `-443`, `-443s`, `-443g` (plus any
  `--extra-host`) over **IPv4 and IPv6** must each show an accepted closed signature
  (none exists today, so each FAILs). An IPv6
  probe whose DNS answer is NODATA for AAAA (`no_aaaa`: the name resolves over IPv4 but
  has no AAAA record) fails unless `--allow-no-aaaa`. That flag is an explicit operator
  waiver and covers **only** that case: an AAAA record that exists is still probed and
  anything but a refusal (including no route) fails; NXDOMAIN, resolver errors and
  timeouts (`no_address`) are never waived. A DNS answer is a dated observation, not
  proof that no IPv6 path exists. When the flag is given, the waiver (UTC time, scope,
  hosts waived) is appended to the receipt's `verify_waivers` (atomic replace, still
  `0600`) and printed under `waivers` in the output. Only a resolver answer of NONAME
  or NODATA for the AAAA lookup, **with the IPv4 lookup of the same name succeeding**,
  counts as NODATA; every other resolver failure (EAI_AGAIN, SERVFAIL, EAI_FAIL, any
  other `gaierror`) is `no_address` and FAILs, never waived. A resolver that filters
  AAAA answers is indistinguishable from NODATA, which is exactly what the flag
  accepts (INFERENCE). NODATA is told apart from
  NXDOMAIN by a second IPv4 lookup of the same name (resolver error codes differ by
  platform) [INFERENCE: not run against real DNS];
- management: **INFERENCE (not run, not observed)** that SSH is reached through the
  gateway TLS route `<app>-10022.<gateway>:443` (the compose comment, with
  `port_mappings` required empty), not a host port 10022. The probe does TLS with that
  SNI on 443 over **IPv4 and IPv6** and requires an `SSH-2.0-` banner for "open"; the
  host is derived from `--expect-app-id` and `--gateway-domain`. Expected open (the
  snapshot policy keeps 10022): both families must give a banner. An IPv6 NODATA
  (`no_aaaa`) is waived only by `--allow-no-aaaa` (same rule and same receipt waiver as
  above); an AAAA that exists and is not answering with a banner FAILs; IPv4 is never
  waived. Expected denied: **always FAIL**, because with management denied no
  known-open SNI exists for any positive control, so a refusal cannot be corroborated (a
  banner, a TLS alert, HTTP or a timeout fail too). If `phala ssh` actually reaches
  management another way, this check and the controls are wrong and must be corrected
  from evidence before relying on them. Key-authenticated access is not tested.
  **Class of a management FAIL:** expected-open management that **accepted the connection**
  but gave no banner (reset after connect, TLS alert, close, non-SSH data, HTTP) is class
  `open` (exit 1). A `tcp_refused` or connect-time `tcp_reset` is pre-SNI, and management
  is the same gateway IP:443, so it cannot be about this app (a gateway-wide outage, a
  local REJECT): it stays `not_proven_closed` (exit 3), like a timeout, `no_route`,
  `no_aaaa`, `no_address` or other error, never an undo signal. Blackholed management
  can therefore hide at exit 3 (harm is limited to SSH); the exit-3 checklist above
  includes the management banner check. Management expected denied and answering a
  banner is class `open`.
  **`--expect restored` and IPv6 (decision):** restored keeps the IPv6 management
  probe, because an AAAA that exists must be probed. So restored needs a vantage with
  IPv6 when management has an AAAA record; from an IPv4-only vantage the probe is
  `no_route`, restored reports exit 3 (hold, re-run from an IPv6 vantage), not exit 1.
  NODATA is waived only by `--allow-no-aaaa`;
- the receipt (owner-only file) is not older than `--max-receipt-age` (default 3600 s),
  names the same tunnel host as `--tunnel-host` and the same tunnel id as the
  snapshot's recorded origin, and the snapshot is an owner-only file for the same app.

What the passing end-to-end checks would show (they cannot pass today, see above):
`node.tinycloud.xyz` answers `/info`
with the recorded node id **while every probed gateway path shows an accepted closed
signature**, so
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
