# Node HTTP ingress switch (TC-1387)

## Status and scope

This PR supplies a **local-config switch**, not an installed production control.
The independent Cloudflare Tunnel origin and Worker routing below are **undeployed
prerequisites**. This runbook does not authorize their creation or any production
execution. No release, application default, DNS record or production policy is
changed by merging these files.

The intended operation is: keep `https://node.tinycloud.xyz` serving through
Cloudflare while withdrawing the Phala gateway's node HTTP ports. Port **10022**
keeps whatever the prior policy gave it. It was the SSH management relay; since
TC-3838 the compose publishes nothing there, so an allowed 10022 reaches no
service. This is not a switch that removes all CVM ingress or guarantees upstream
DDoS protection.

**The current recorded Worker fetches the public Phala `-8000` origin. Closing
that port BEFORE the independent tunnel and Worker routing are verified breaks
BOTH the Cloudflare HTTP route and the direct HTTP route.** Do not use this
switch against that topology.

## Recovered topology and boundaries

Read-only Phala metadata on 2026-11-19 identified app
`350d124c81d53a57e8899e9f85a904918e663b61`, CVM `cvm_9wPWBOKk`:

| Entry | Route / control |
| --- | --- |
| `node.tinycloud.xyz` | Cloudflare edge → `tinycloud-tee-proxy` Worker → app `-8000.dstack-pha-prod5.phala.network` in the recorded Worker source |
| `tee.node.tinycloud.xyz` | Gateway custom-domain TLS passthrough → in-CVM ingress `443` → `tinycloud:8000` |
| App **and instance** gateway URLs | Published guest ports `443`, `8000`; `10022` only under a pre-TC-3838 compose (the SSH relay); also inspect passthrough (`s`) and HTTP/2 (`g`) variants |
| Direct host port mappings | `/network` and `/network-config` returned empty mappings at inspection; inventory again before operating |
| Gateway policy | `gateway_enabled=true`, `port_policy=null` at inspection |
| Host firewall API | `/firewall-status` reported `available=true`, `capabilities.acl=true`; this describes host port mappings, not gateway visitor filtering |

Sources: live read-only CVM/compose/network APIs and repository
`docker-compose.dstack-postgres.yaml`; Worker implementation and route definitions
in the tinycloud-dev operations tree,
`ops/cloudflare/tinycloud-tee-proxy/{src/index.js,wrangler.toml,README.md}`.
The Worker source is a repository capture, **not a fresh authenticated live
Worker read**. Current Worker deployment/routing must be read back by the operator.
Provider network responses alone are not application reachability evidence.
No production application probe was performed for this PR.

A published port and an allocated direct host mapping are different layers.
The [Phala network API](https://docs.phala.com/api-reference/cvms/get-cvm-network-info)
reports gateway ingress, host mappings and infrastructure endpoints separately.
Its [gateway URL suffixes](https://docs.phala.com/phala-cloud/networking/architecture)
select HTTP, TLS passthrough or HTTP/2, not a separate node identity.

Inventory every app/instance ID, gateway domain, custom hostname, resolved A and
AAAA address, public guest NIC and host mapping. At inspection, DNS returned an A
record but no AAAA answer for the direct tee/gateway names; that is a dated DNS
observation, not evidence that every possible IPv6 path is absent. Include
cached addresses and literal IP connections with the original SNI/Host in checks.

## Chosen prerequisite: independent outbound tunnel

Use a named **Cloudflare Tunnel** whose connector reaches `http://tinycloud:8000`
over the existing private Docker network. Outbound tunnel traffic does not
traverse the guest HTTP gateway port policy. Keep the application, its image,
keys, database configuration and ingress certificate service unchanged.

This prerequisite is a separately authorized infrastructure change, not a
provisioner supplied by this PR:

1. Select an operator-owned named tunnel and hostname in the existing Cloudflare
   account. If none exists, stop and obtain separate provisioning authorization.
   Do not create an account, tunnel, purchase, token or DNS record under this PR.
2. Pin a reviewed `cloudflare/cloudflared` image digest. Add a connector on the
   same private network as `tinycloud`, with **no published ports**, no host
   networking and no fallback to a Phala public URL. Preserve all existing
   services/volumes/env. The local tunnel configuration is exactly:

   ```json
   {
     "tunnel": "OPERATOR_SELECTED_TUNNEL_UUID",
     "credentials-file": "/run/secrets/cloudflared-credentials",
     "ingress": [
       {"hostname": "OPERATOR_SELECTED_ORIGIN_HOST", "service": "http://tinycloud:8000"},
       {"service": "http_status:404"}
     ]
   }
   ```

   Supply the real UUID/hostname, not these explanatory values. Run the pinned
   image with `tunnel --no-autoupdate --config /etc/cloudflared/config.json run`.
   Deliver that JSON as a Docker Compose config at `/etc/cloudflared/config.json`;
   deliver existing tunnel credentials as a Docker secret at the path above,
   from an encrypted Phala environment variable. Compose `configs.content` and
   `secrets.environment` require support in the actual guest Compose version;
   verify that before this separately reviewed setup. Do not put credential
   contents into the compose JSON, shell arguments, snapshots or logs.
   Use the [documented local configuration/validation commands](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/).
3. Route the selected origin hostname to the tunnel's UUID using the
   [same-account tunnel DNS record](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/).
   Record the complete prior DNS record, or its absence, including ID, type,
   name, content, proxied flag and TTL. Preserve `node.*`'s existing Worker route.
4. In a separate reviewed Worker change, replace its `PHALA_ORIGIN` value with
   `https://` plus that tunnel hostname. Preserve streaming, headers, size limits,
   CORS and route definitions. **No fallback to the public Phala origin.** Record
   the exact previous Worker version and read back the new version and origin.
5. Verify connector authentication/connection state, hostname-to-tunnel binding,
   ingress target, and healthy `/info` through both the tunnel hostname and
   `node.*`, with matching node IDs. Check the actual Worker points only to the
   independently verified origin. Confirm browser preflight and streaming/SSE
   behavior on an authorized non-sensitive scenario. This is future operator
   verification, not a check performed by this PR.

The alternative is a Cloudflare-IP allowlist **at a source-preserving public
origin before NAT**. A guest proxy may see only the Phala gateway address;
allowing Cloudflare IPs there does not establish visitor provenance. Host mapping
ACLs are [IPv4 source allowlists](https://docs.phala.com/api-reference/cvms/set-port-mappings),
and do not control the existing gateway HTTP path. A PROXY-protocol design also
needs a trusted sender boundary and compatible listener. Neither alternative is
implemented or assumed here. A header such as `CF-Connecting-IP` is not a firewall.

## Before operating

All commands in the remaining operational sections require separate production
execution authority. The switch itself uses Python 3's standard library and
performs **no network calls**. Use a private operator directory and current
captures; these can contain deployment configuration. Do not commit them.

```sh
umask 077
: "${CVM_ID:?explicit CVM target}" "${APP_ID:?explicit expected 40-hex app ID}"
phala cvms get "$CVM_ID" --json | jq '{id,app_id}' > target.json
phala api "/cvms/$CVM_ID/compose_file" > app-compose.json
phala api "/cvms/$CVM_ID/network" |
  jq --arg cvm "$CVM_ID" '. + {cvm_id:$cvm}' > network.json
```

Read the live Worker/tunnel configuration using **existing** authorized read
access; absent access is a stop, not permission to create credentials. Check
there are no direct host mappings or public guest NIC HTTP paths. If there are,
stop: this gateway-only switch intentionally refuses host mappings rather than
rewriting unrelated firewall config. Close those paths with a separately reviewed
upstream/provider control before using this topology. A local guest firewall
alone cannot repair a saturated upstream link or a shared gateway.

Record baseline `node.*` and direct-path status, node identity, Worker version,
tunnel ID/connector authentication, route DNS records and policy. Use `/info` for
node identity; no DB queries or `/healthz` DB-health probes are needed for this
switch. An authorized functional health scenario is separate.

Save an **operator-attested verification receipt** as `verified-origin.json`:

| Required field | Value from the preceding independent verification |
| --- | --- |
| `app_id` | Exact expected app ID |
| `public_url` | `https://node.tinycloud.xyz` |
| `worker_origin` | Exact HTTPS tunnel hostname read back from the active Worker |
| `tunnel_hostname` | Same hostname, without scheme, with its tunnel DNS binding verified |
| `tunnel_id` | Named tunnel UUID read back from the connector/configuration |
| `verified_at_utc` | Actual UTC observation timestamp, ISO 8601 with `Z` or `+00:00` |
| `connector_authenticated` | `true` only after observing authenticated connector connections |
| `origin_status`, `public_status` | Observed `/info` HTTP status, both `200` |
| `origin_node_id`, `public_node_id` | The matching IDs actually returned by those requests |

The receipt is **operator evidence, not a cryptographic attestation**. The local
switch checks its consistency, target and independent origin, not the live
Cloudflare service. Do not manufacture a receipt from intended configuration.
Reverify immediately before use and after any route/connector change. An absent,
unauthenticated, dependent or inconsistent origin causes refusal. A successful
local plan does not prove production protection.

## Switch: preview, stage, then separately execute

```sh
python3 scripts/ingress-switch.py --help
python3 scripts/ingress-switch.py \
  --compose app-compose.json --target target.json --expect-app-id "$APP_ID" \
  --network network.json --verified-origin verified-origin.json \
  --snapshot previous-policy.json --dry-run > plan.json
```

Inspect `plan.json`: it contains only before/after policy and the provider PATCH,
not the compose's environment or credential contents. No files are changed by
the default or explicit dry-run. The desired policy is `restrict_mode=true`,
allowing only `10022` (retaining its recorded PROXY-protocol attributes); no
service listens there since TC-3838. If a previous restrictive policy already
denied 10022, it stays denied. Unknown additional policy ports are refused, not
silently removed.

Stage it with the **same arguments**, replacing `--dry-run` with `--apply` and
redirecting output to `staged.json`. This writes only local `app-compose.json`
and exclusively creates a mode-0600 `previous-policy.json`; it never calls Phala,
Cloudflare, Docker, a database or DNS. It records whether the old policy was
absent, null or an exact object. Keep the snapshot on the same path for undo.
Do not repeat staging with a new snapshot and lose the original previous state.

After independent route verification and a separately approved execution window:

```sh
# Review again: ONLY compose.port_policy is sent, never the whole app compose.
jq '.patch' staged.json > restrict.patch.json
phala api "/cvms/$CVM_ID" -X PATCH --input restrict.patch.json
```

This is the real supported [Phala compose patch](https://docs.phala.com/phala-cloud/update/update-cvm-configuration).
Omitted fields retain their values. It restricts gateway HTTP on all app/instance,
custom-host and IP/SNI routes to this CVM, while keeping the tunnel's private
container path and prior management access. **It restarts a running CVM**;
plan for an interruption to both HTTP paths during that restart. Do not combine
it with a node release or a default-host flip. No host mappings, firewall rules,
KMS URLs, IAM, credentials or DNS records are changed by this patch.

## After / propagation / verification

Read back `/network` and `/compose_file` until the operation has completed and
confirm the exact intended policy. Phala documents asynchronous `202` updates
and a CVM restart, but gives no fixed convergence bound. Measure acceptance →
restart → read-back → application recovery in UTC; do not substitute a guessed
seconds estimate. Treat a failed or incomplete update as unknown, not success.

There is **no DNS change at switch time**. Setup/undo DNS changes follow the
[recorded prior TTL](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/):
Cloudflare proxied Auto is 300 seconds; DNS-only records have their configured
TTL (Auto also 300 seconds). Allow the old TTL window and account for longer
local caches. DNS expiry does not close an existing connection or a literal-IP
path. For connector replacement, Cloudflare documents dropped long-lived
connections when the old connector stops; no fixed readiness time is promised.

From independent external IPv4 **and** IPv6 networks where available:

- `https://node.tinycloud.xyz/info` returns the expected status and node ID.
  Verify the active Worker version, tunnel connections and observed routing;
  a DNS answer or receipt alone is insufficient.
- Fresh connections to `tee.node.tinycloud.xyz` must not reach the node HTTP API.
  Test cached/current addresses using `curl --resolve tee.node.tinycloud.xyz:443:ADDRESS`
  with the correct SNI; use `[IPv6]` syntax for IPv6 address overrides.
- Test **every** inventoried app and instance gateway hostname on `-8000`, `-443`,
  TLS passthrough `-443s`, applicable `g` variants, every custom domain and each
  alternate gateway/IP. Check both 443 and direct public 8000 when inventoried.
  Gateway rejection/closed connection is expected; a working node `/info` is not.
  Distinguish a local resolver error from actual gateway refusal.
- Check every provider host mapping and public NIC path, including IPv6; a
  nonempty new mapping invalidates this runbook's gateway-only assumption.
- `10022` keeps its previous policy and is deliberately **not** counted as node
  HTTP. Since TC-3838 it should refuse connections; an answer there means a
  pre-TC-3838 compose (the SSH relay) is running. Verify without printing credentials.
- Check existing long-lived connections as well as fresh ones. Do not declare
  withdrawal complete while an old direct stream can still deliver node data.

Use normal harmless connectivity checks, not load generation. Record statuses,
UTC observations and the path inventory. Report only what was actually observed.

## Undo: exact recorded values, HTTP first

Keep the independent tunnel/Worker route running during policy restoration.
Do **not** point the Worker back at public `-8000` before gateway HTTP is verified
restored. First capture the current provider policy and compare it to the saved
snapshot's `after`. On drift, stop and reconcile with the other change's owner;
do not overwrite it with an old snapshot. The local restore checks local drift,
not remote drift.

```sh
python3 scripts/ingress-switch.py \
  --compose app-compose.json --target target.json --expect-app-id "$APP_ID" \
  --restore previous-policy.json --dry-run > undo-plan.json
# After reviewing the live-policy comparison and local plan:
python3 scripts/ingress-switch.py \
  --compose app-compose.json --target target.json --expect-app-id "$APP_ID" \
  --restore previous-policy.json --apply > undo-staged.json
jq '.patch' undo-staged.json > undo.patch.json
phala api "/cvms/$CVM_ID" -X PATCH --input undo.patch.json
```

The patch restores the exact previous policy object, or sends `port_policy:null`
for an originally absent/null policy (JSON Merge Patch removes that key). Local
restore also preserves the original absent-versus-null representation and every
unrelated current compose field. It does not require a healthy tunnel, so route
failure cannot prevent local undo planning. Read back the provider's effective
policy and recheck all direct and Cloudflare paths after the restart.

If also undoing the separately approved setup: only after direct `-8000` is
healthy, restore the **recorded previous Worker version**, verify `node.*`, then
stop the connector. Restore the origin DNS record's exact recorded fields, or
delete only the setup-created record if it was originally absent. The emergency
switch itself never changes DNS, so normally there is no DNS undo. Leave tunnel
and credential deletion to their separately authorized owner; this script does
not perform either.

## Clients and endpoint semantics

Clients still targeting `tee.*` (stored CLI/MCP profiles, explicit SDK/courier
hosts, billing/admin callers, mobile/desktop settings, bookmarks and monitors)
lose that HTTP route during withdrawal. Inventory actual deployed overrides;
repository defaults are not proof of live callers. Migrate them under their own
change owners, not this PR. Direct TEE-TLS clients must explicitly accept the
Cloudflare transport trust model or remain unavailable during this mode.

OpenKey #588's endpoint alias accepts both spellings for identity/authorization;
it does **not** change a client's URL, redirect packets, migrate a stored host
or create network failover. Matching node IDs establish endpoint equivalence,
not transport independence or availability.

## Local verification

Run only `python3 scripts/test-ingress-switch.py -v` and the switch's `--help` for
this change. The suite invokes the real CLI with temporary local files, checks
default dry-run, private snapshots, exact null/absent/object undo, drift refusal,
unknown/direct-path refusal and missing/dependent origin evidence. Its local
HTTP fake-origin scenario models gateway policy: tee/app/instance routes are
denied while the independent path and management remain healthy, then restored.
This does **not** exercise the Phala data plane, a real tunnel, Cloudflare, TLS,
IPv6 enforcement or production protection. The tunnel/routing prerequisite remains
undeployed until separately authorized and verified.
