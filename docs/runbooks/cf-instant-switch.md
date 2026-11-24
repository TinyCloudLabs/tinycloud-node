# Instant Cloudflare-side switch (TC-4194)

## Status and scope

`scripts/ingress-cf-switch.py` is a **built but never-run** tool. It has been tested
only against fakes (`scripts/test-ingress-cf-switch.py`); the real Cloudflare client
has not made a single request, and no token exists for it yet. Merging these files
changes nothing in Cloudflare. Any real use needs its own GO and a scoped token
supplied by the operator (see Tokens).

It is the **no-restart** counterpart to `http-ingress-switch.md` (which restarts the CVM
when the Phala port policy changes). Effect time on Cloudflare's side is expected to
be seconds [INFERENCE: not measured; measure it in the first drill].

## What it can and cannot do

- It acts **only on requests that reach Cloudflare for a proxied (orange-cloud)
  hostname**. It does **not** close the Phala `-8000`/`-443`/`-10022` origin hostnames
  and does **not** stop L3/L4 floods at the Phala host. Anyone who knows an origin
  hostname bypasses it.
- **tee.node is DNS-only on the recorded topology.** The Worker README (capture
  2026-10-16) says the `tee.node.tinycloud.xyz/*` route "is inert while that hostname
  is DNS-only": Cloudflare never sees that traffic, so no lever here affects it. The
  script reads the host's DNS record and **refuses to apply an inert lever**
  (`--allow-inert` is for drills only). The lever becomes effective once `tee.node`
  is fronted by Cloudflare (the CF-only ingress plan). Re-read DNS before relying on it.
- `node.tinycloud.xyz` must keep working. `apply` records a "node guard" (node.* and
  any `--protect-host` Worker routes and DNS records, plus every other WAF rule) in the
  snapshot and `verify` fails (exit 4) if any of it changed.

## Levers

| `--lever` | What | Stops traffic? | Blast radius | Extra flag | Token scope |
| --- | --- | --- | --- | --- | --- |
| `waf` (**default**) | A rule inserted first in the zone custom-rules entrypoint (rule-level POST; undo is a rule-level DELETE of only that rule): `http.host eq "<host>"`, action `block` (or `--action managed_challenge\|js_challenge\|challenge`) | Yes, at the edge, before the Worker runs | Only that host. A challenge action breaks API/native clients; `block` stops all tee.* clients (intended) | none | Zone WAF: Edit |
| `security-level` | Zone `security_level` to `under_attack` | Challenges browsers; API clients fail | **Whole zone, including node.*** | `--allow-zone-wide` | Zone Settings: Edit |
| `worker-route` | Route `<host>/*` gets `script: null` (route id kept) | **No.** Proxied requests go straight to the DNS origin, i.e. more exposure | That pattern only | `--allow-no-block` | Workers Routes: Edit |
| `dns-proxy-flip` | PATCH the host's DNS record with only `{"proxied": true}` (ttl becomes automatic, set by Cloudflare [INFERENCE]); undo PATCHes only `{"proxied": false, "ttl": <recorded>}`. Other fields are recorded and reported, never written | **No, it is the enabler**: makes the Worker route and the WAF rule live so Cloudflare fronts the host. Follow with `waf` | That record only. **TLS trust changes**: Cloudflare terminates TLS instead of passthrough to the TEE cert; the existing `tee.node/*` Worker route goes live and forwards to the Worker's configured origin, bypassing the in-CVM ingress (nginx limits/CORS). **Edge-certificate prerequisite**: Universal SSL covers only `*.tinycloud.xyz` [INFERENCE], so a host below `tee.node` needs ACM/Total TLS/a custom certificate first, or every tee.node TLS handshake FAILS | `--accept-tls-change`, `--expect-type` | Zone DNS: Edit (+ Read) |
| `dns-remove` | DELETE the host's A/AAAA/CNAME record; the full record (type, name, content, ttl, proxied, comment, tags) is snapshotted and undo re-creates it | Yes, but **in minutes, NOT instantly**: resolvers keep the old answer until the recorded TTL expires (plan prints it; TTL 1 = automatic, about 300 s [INFERENCE]). Anyone with a cached answer or the literal origin address is unaffected | tee.node becomes unresolvable after caches expire; node.* record untouched. Undo restores every field except the record id (Cloudflare allocates a new one) | `--i-understand-ttl`, `--expect-type` | Zone DNS: Edit (+ Read) |

DNS levers refuse a missing record, a record of a different type than `--expect-type`, and more than one A/AAAA/CNAME record at the name. The write also refuses if the record id is no longer the planned one. `dstack-ingress` holds a Cloudflare DNS token and may re-write or re-create the tee.node record when the CVM restarts [INFERENCE: not read]; re-run `verify` after any restart. A Worker-side kill switch is not implemented: the Worker has no bindings, so it needs a separate reviewed Worker change and deploy first.

## Tokens

`--token-file PATH` (regular file, mode 0600, symlinks refused) or `--token-env NAME`
(the variable **name**). The token is sent only in the `Authorization` header of the
in-memory request; it is never printed, errors are scrubbed of it, and it is never
written to a snapshot. Use a short-lived token scoped to the one lever's permission
and the one zone. Never paste a token into chat, tickets or the command line.

## Output and ids

Zone, route and rule ids are not credentials but are printed as `…last4` in all
output. Full ids exist only in the 0600 snapshot (needed for undo). Other WAF rules are
shown only as a count and a sha256, never their expressions.

## Procedure

Dry-run is the default everywhere. Use an operator-private directory for snapshots,
not a repository checkout.

```sh
S=scripts/ingress-cf-switch.py
# 1. Read-only: exact change, exact undo, blockers, plan_hash
python3 $S plan --token-env CF_TOKEN_VAR --zone-id <zone> [--host H] [--lever L]
# 2. Execute (without --confirm this only prints the plan again)
python3 $S apply --token-env CF_TOKEN_VAR --zone-id <zone> [same flags] \
    --snapshot /private/dir/cf-switch-<utc>.json --confirm <plan_hash>
# 3. Re-check any time
python3 $S verify --token-env CF_TOKEN_VAR --snapshot /private/dir/cf-switch-<utc>.json
# 4. Undo (dry-run first, then with --confirm <plan_hash from the snapshot>)
python3 $S undo --token-env CF_TOKEN_VAR --snapshot /private/dir/cf-switch-<utc>.json --confirm <plan_hash>
python3 $S verify --token-env CF_TOKEN_VAR --snapshot ... --expect undone
```

Guarantees (all tested against fakes):

- `plan` is read-only. `apply` refuses unless `--confirm` equals the hash of the
  **current** state + change; any change between plan and apply invalidates it.
- The snapshot (0600, exclusive create, fsynced, exact prior values) exists **before**
  the first change. An existing snapshot path is never overwritten.
- `apply` is idempotent: if the lever is already in place it reports so and changes
  nothing (and creates no new snapshot; undo with the snapshot of the run that applied it).
- `undo` restores the recorded prior state. If the current state is neither that nor
  what `apply` produced, it refuses; `--force-drift` proceeds and records what it
  found under `forced_undo` in the snapshot. WAF undo deletes only our rule (never
  rewrites the list). `dns-proxy-flip` undo sends only `proxied` and `ttl`; if
  `type`/`name`/`content`/`comment`/`tags` changed meanwhile (for example
  `dstack-ingress` rewrote the target) they are reported as
  `unmanaged_changes_reported_not_written` and never written back.
- Targets are pinned: the default `--host` is `tee.node.tinycloud.xyz`; any other host
  needs `--other-host`. `node.tinycloud.xyz` is always protected and can not be
  targeted (nor a parent domain of it); `--protect-host H` (repeatable) adds more
  protected hosts, it never removes `node.*`.
- Exit codes: 0 ok, 1 refused (nothing changed), 3 Cloudflare/IO failure, 4 verify failed.

## Failure recovery

If `apply` fails mid-way it prints `APPLY FAILED` and the snapshot path (status
`pending`). The state may be unchanged or changed. Run `undo` on that snapshot (dry-run
first): it restores the prior state, or says there is nothing to undo and marks the
snapshot `aborted`. If undo itself fails, restore by hand from the exact values in the
snapshot (`before`) in the Cloudflare dashboard.

## Unverified (check in the first drill, not run)

Nothing in this tool has run against Cloudflare. Everything below is from API docs only.

- WAF rule-level endpoints: `POST /zones/{z}/rulesets/{id}/rules` with
  `position.index` (insert first), `DELETE /zones/{z}/rulesets/{id}/rules/{rule_id}`,
  and `PUT .../phases/http_request_firewall_custom/entrypoint` only when the ruleset
  does not exist yet. `undo` only deletes the rule carrying this tool's marker; other
  rules are never written, so a rule someone else adds between our read and write
  survives (`verify` then reports the list differs and exits 4; nothing is lost).
- A missing entrypoint ruleset is restored as an empty rule list, not deleted.
- DNS: that PATCH `{"proxied": true}` forces `ttl=1`, and that `{"proxied": false,
  "ttl": N}` restores the prior state; that the DNS record has a `settings` object that
  is recorded and accepted back on create (recorded only when non-empty); how Cloudflare
  proxying behaves in front of the Phala TLS passthrough gateway (SSL mode, SNI to
  origin).
- `script: null` on a Workers route meaning "no Worker".
- Propagation time of a custom rule, and that the rule applies before the Worker.
- **Host-header variants (drill before relying on `waf`).** The rule is
  `http.host eq "<host>"`. Send each of these at the proxied host and confirm all are
  blocked; if any gets through, widen the expression (`lower(http.host)` and the
  trailing-dot form) before an incident:
  `curl -H 'Host: TEE.NODE.TINYCLOUD.XYZ'`, `-H 'Host: tee.node.tinycloud.xyz.'`,
  `-H 'Host: tee.node.tinycloud.xyz:443'`. UNVERIFIED.
- Unit tests are not wired into CI (the existing `test-ingress-switch.py` is not
  either); run `python3 scripts/test-ingress-cf-switch.py` locally.

## Rollback of this change

Delete the three new files. Nothing else references them.
