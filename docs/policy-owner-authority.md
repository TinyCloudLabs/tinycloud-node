# Policy/v3 owner authority (TC-1423)

A Policy/v3 policy root is parentless and signed by the policy owner, so the
ordinary delegation graph cannot say which of the owner's delegations its
authority came from. The node records that at registration.

## What is recorded

Two tables, created by migration `m20261019_000000_policy_v3_owner_authority`:

- `policy_v3_owner_binding`, one row per policy: `state`, `authority_expires_at`
  (minimum expiry over the recorded closure, RFC 3339 UTC, NULL when nothing
  expires), `unknown_reason`, `classifier_version`, `registered_mode`,
  `created_at`. A missing row means the policy has not been classified yet.
- `policy_v3_owner_authority`, `(policy_cid, delegation_id, depth)`: the whole
  ancestor closure of the delegations the owner used, at most 64 nodes (the
  core traversal limit). Indexed by `(delegation_id, policy_cid)`.

| state | meaning |
|---|---|
| `bound` | at least one delegation recorded; the root expires no later than it |
| `bound-uncapped` | at least one delegation recorded; the root outlives it |
| `root-authority` | every root capability is held as root authority (space or network owner) |
| `unknown` | no authority found (`revoked`, `missing`, `starved`), a policy whose stored networks or `kv` spaces do not belong to its content owner (`foreign_network`), or a post-cutover registration that breaks the current rules (`lifetime-exceeded`, `outlives-authority`) |

`registered_mode` is the mode (`record` or `enforce`) a policy is classified
under, or `backfill` for policies registered before the legacy cutover and
classified later.

## Root lifetime and mode

At registration, in both modes, a root that expires later than
`registered_at + 31 days + 5 minutes` is refused with `403
policy-root-lifetime-exceeded`. (A root that isn't valid yet is already refused
by the signed time check, `policy-root-signature-invalid`; the node also
requires `nbf <= exp` when it classifies an unclassified registration later.)
Released SDKs sign `nbf` at signing time with `exp - nbf <= 31 days`, so their
roots pass.

The cap and the `enforce` check run before the idempotent re-registration
shortcut, so re-posting an existing registration that breaks the current rules
gets the same `403`.

```toml
[policy_v3]
owner_authority_expiry = "record"  # or "enforce"; TINYCLOUD_POLICY_V3__OWNER_AUTHORITY_EXPIRY
```

- `record` (default): a root that outlives the recorded authority is
  accepted as `bound-uncapped` and counted in
  `tinycloud_policy_owner_authority_expiry_exceeded_total`.
- `enforce`: such a root is refused with `403
  policy-root-outlives-owner-authority`.

Policies registered before the legacy cutover are never capped; roots longer
than 31 days are counted in
`tinycloud_policy_legacy_root_lifetime_exceeded_total`. A policy registered
after the cutover with no binding row (by an older binary) gets the current
mode's rules when it is classified: `unknown` with `lifetime-exceeded`, or
under `enforce` `outlives-authority`.

### Advertised mode

`GET /info` (and `/version`) lists `policy-owner-authority-v1` in `features`,
plus exactly one of `policy-owner-authority-record` and
`policy-owner-authority-enforce`. A client treats the node as enforcing only
if `policy-owner-authority-enforce` is listed. The response carries no
`Cache-Control` header.

### Metrics

Always counted, independent of the request-telemetry sampling. They are
exported on the node's Prometheus port, which runs only when
`telemetry.enabled` is set; without it, use the counting queries below.

| metric | labels | counts |
|---|---|---|
| `tinycloud_policy_owner_authority_expiry_exceeded_total` | `authority_ttl_bucket` = `le_1h`, `le_30d`, `gt_30d` (authority time left at registration; `le_1h` includes exactly one hour) | `record` registrations whose root outlives the authority |
| `tinycloud_policy_root_lifetime_refused_total` | | lifetime-cap refusals |
| `tinycloud_policy_legacy_root_lifetime_exceeded_total` | | legacy roots longer than 31 days, when classified |
| `tinycloud_policy_owner_binding_backfill_total` | `outcome` = `bound`, `bound_uncapped`, `root_authority`, `unknown`, `write_failed_served` | classifications after registration |

### Counting queries (PostgreSQL, read-only)

The fallback when the metrics aren't scraped. `registered_at`, `expires_at`
and `authority_expires_at` are RFC 3339 UTC text.

Q1, the `enforce` flip signal, by authority lifetime (`le_1h`: released Share
signing with a login session; `le_30d`: CLI device sessions). A
`bound-uncapped` row always has an authority expiry:

```sql
SELECT CASE WHEN b.authority_expires_at::timestamptz - r.registered_at::timestamptz <= interval '1 hour' THEN 'le_1h'
            WHEN b.authority_expires_at::timestamptz - r.registered_at::timestamptz <= interval '30 days' THEN 'le_30d'
            ELSE 'gt_30d' END AS authority_ttl_bucket,
       count(*), count(DISTINCT r.owner_did)
FROM policy_v3_owner_binding b JOIN policy_v3_registration r ON r.policy_cid = b.policy_cid
WHERE b.registered_mode = 'record' AND b.state = 'bound-uncapped'
  AND r.registered_at::timestamptz >= now() - interval '7 days'
GROUP BY 1;
```

Q2, policies without authority:

```sql
SELECT unknown_reason, count(*) FROM policy_v3_owner_binding WHERE state = 'unknown' GROUP BY unknown_reason;
```

Q3, live legacy roots longer than 31 days:

```sql
SELECT count(*) FROM policy_v3_registration r
LEFT JOIN policy_v3_owner_binding b ON b.policy_cid = r.policy_cid
WHERE (b.registered_mode IS NULL OR b.registered_mode = 'backfill')
  AND r.expires_at::timestamptz - r.registered_at::timestamptz > interval '31 days'
  AND r.expires_at::timestamptz > now();
```

Q4, an upper bound on admitted sessions a legacy denial could affect (run
before deploying):

```sql
SELECT count(*) FROM policy_v3_session s JOIN policy_v3_registration r ON r.policy_cid = s.policy_cid
WHERE s.state = 'admitted' AND s.expires_at::timestamptz > now();
```

### Flipping to `enforce`

Set `owner_authority_expiry = "enforce"` once the cap-compliant publisher has
run for at least 7 days, Q1 shows no `le_1h` rows over the trailing 7 days
(and the `le_30d` remainder is accepted), and no rollback is pending. Clients
see the flip in `/info` on their next read of it.

## Selection

Both roots carry the same capabilities, so one selection covers both. For
each capability:

1. Root authority needs no delegation.
2. Owner-first: delegations to the owner issued by the owner of the
   capability's space or encryption network (newest first, 64 rows). Only that
   principal can create them, so delegations from other principals cannot
   push them out of the window.
3. Otherwise the general window: the 256 newest delegations to the owner that
   carry an ability on the capability's space or network (only holders of
   authority derived from that space or network can create those), of which
   at most 32 are tried.

A candidate whose ancestor closure (the candidate included) contains a
delegation issued by the policy owner is skipped, without using up a try.
Among candidates that grant the capability, the first, newest first, whose
closure outlives the policy root is chosen, else the newest. `starved` is
recorded only when both steps found nothing and more candidates exist than
were examined; unlike the other `unknown` reasons it is not final and is
classified again on a later use.

### Register grant (classifier version 3)

A policy owner who holds no owner-first or general-window delegation for a
root can be authorised by a register grant. Selection tries it only
when the ordinary selection above returns nothing, so an owner who already
holds the capabilities keeps the ordinary path. The space owner delegates
`tinycloud.policy/register` on exactly `<S>/policy/<h>`, where `h` is the
template digest of the policy:

    h = lowercase hex SHA-256("xyz.tinycloud.policy/RegisterTemplate/v1\0"
        || JCS(policy without policyId, createdAt, expiresAt, signature))

For a root R with owner O, space S, and time t, a delegation D is a register
grant when:

1. `D.delegatee` is O.
2. D carries `tinycloud.policy/register` on `<S>/policy/<h>`, and `h` is the
   template digest of R's policy.
3. `D.delegator` is the owner of S.
4. D has no parents, its ancestor closure is exactly `{D}`, and D is not a
   policy-fact row.
5. D is not revoked (alias-aware), and `t` is in `[D.nbf, D.exp)`.
6. `R.exp <= D.exp`. Otherwise the registration is refused with
   `policy-root-outlives-register-grant` in both modes, since the grant cannot
   cover the root's lifetime.

A registration accepted by a register grant is bound with authority until
`D.exp` and the closure `{D}`.

`/delegate` refuses any delegation with parents that carries a
`tinycloud.policy/*` ability (`policy-register-grant-must-be-parentless`), so
a register grant is always a root delegation.

## Source networks

A registration is also held to the source-network rule that new registrations
must meet (`content_owner_networks`): every encryption network the policy
names, and every `kv` ceiling entry, must belong to the owner of the content
source's space. A policy registered before that rule, or by a binary that
predates it, that does not meet it is classified `unknown` with reason
`foreign_network`, in either mode, whatever delegations the owner holds. The
rule is a pure check of the stored policy: it does not look up whether the
network exists. `foreign_network` is final: the row is not classified again
unless `classifier_version` changes.

## Policies registered earlier

A policy with no final binding row is classified on first use, because the
use is checked against the result: the selection runs as of its registration
time (delegations issued after it are not considered; UCANs carry no issue
time and stay eligible), the request is served from that result, and the
write runs in the background: one transaction inserts the binding row first
and its closure after it, and a concurrent writer that stored a row first
wins. One write runs per policy, and at most three in the whole process. A
result that isn't final (its write failed or found no free slot, or it is
`starved`) is reused for 60 seconds before it is computed again. An `unknown`
row written by an older `classifier_version` is classified again.

The opt-in sweep classifies pending policies off the request path:

```toml
[policy_v3.owner_binding_backfill]
enabled = false          # TINYCLOUD_POLICY_V3__OWNER_BINDING_BACKFILL__ENABLED
policies_per_second = 1  # TINYCLOUD_POLICY_V3__OWNER_BINDING_BACKFILL__POLICIES_PER_SECOND
```

It visits every pending policy once after boot, at most `policies_per_second`,
pausing after each policy at least as long as it took.

## Legacy cutover

Only policies registered before the cutover are `backfill`. The cutover is the
applied-at time of the migration above, unless configured:

```toml
[policy_v3]
legacy_cutover = "2026-10-20T00:00:00Z"  # TINYCLOUD_POLICY_V3__LEGACY_CUTOVER
```

The node logs the effective cutover and its source (`config` or `migration`)
at boot: at `warn` when the source is the migration and its applied-at time is
less than a day before boot (a fresh migration, or a re-upgrade that needs the
override), otherwise at `info`.

## Rollback

The migration is unknown to the previous release image (1.22.0), which refuses to boot while `seaql_migrations` lists it. To roll back, run on the database: `DROP TABLE IF EXISTS policy_v3_owner_authority; DROP TABLE IF EXISTS policy_v3_owner_binding; DELETE FROM seaql_migrations WHERE version = 'm20261019_000000_policy_v3_owner_authority';` (the same as the migration's `down`), then deploy 1.22.0. If a migration released after this one has also been applied, delete its row too, as its release notes say. Policies registered while this release ran stay registered and get only the checks 1.22.0 has. On the re-upgrade, `policy_v3.legacy_cutover` must be set to this release's first deploy time; otherwise every policy registered during the rollback window, including roots longer than 31 days, is treated as legacy.

Checklist (tick each step):

1. [ ] Run the three statements above on the database.
2. [ ] If a migration released after this one has been applied, delete its `seaql_migrations` row as well, as its release notes say.
3. [ ] Deploy 1.22.0 and check that the node boots.
4. [ ] Before the re-upgrade starts, set `policy_v3.legacy_cutover` (`TINYCLOUD_POLICY_V3__LEGACY_CUTOVER`) to this release's first deploy time, as an RFC 3339 UTC timestamp. This is the time of the first deploy of this release, not the time of the re-upgrade.
5. [ ] After the re-upgrade, check that the boot log shows the effective cutover with source `config` and the value from step 4.

## Listing

`POST /policy/v3/authorized` with body `{"cid": "<delegation CID>", "cursor": null}`
lists the policies whose recorded closure contains that delegation (or a CID
persisted as the same delegation). It is authorized like `/delegation/status`
on `urn:cid:<cid>`: one `tinycloud.delegation/status` capability on that
resource, from the delegation's issuer or delegatee, a space owner it targets,
or the holder of a status control. Anyone else gets `403`.

```json
{
  "policies": [{
    "policyCid": "...",
    "policyRootCid": "...",
    "enforcementRootCid": "...",
    "registeredAt": "...",
    "expiresAt": "...",
    "rootState": "active | expired | revoked",
    "ownerAuthorityState": "bound | bound-uncapped | root-authority | unknown"
  }],
  "nextCursor": "<opaque>"
}
```

Pages hold at most 100 policies in policy-CID order; `nextCursor` is set when a
page is full and passed back as `cursor`. There is no total count. Policies
not yet classified (legacy policies not used since the upgrade, with the sweep
off) are not listed. Database errors return `503 policy-listing-unavailable`.

## Checking at use

Every use of a policy checks its recorded owner authority, after the root
checks: reads and decrypts by admitted sessions (and their re-shared
children), re-share admission, signed-KV and hook-ticket mints, challenge,
mint (again on the mint's locked transaction), S0 admission, and delivery
authorization.

| state | at use |
|---|---|
| `bound`, `bound-uncapped` | denied if any recorded delegation or ancestor is revoked, directly or under an alias CID (`403 policy-owner-authority-revoked`); a `bound` authority past its expiry is denied (`403 policy-owner-authority-expired`), except for legacy (`backfill`) rows, which are never expiry-checked |
| `root-authority` | nothing more |
| `unknown` | denied (`403 policy-owner-authority-unknown`) |

The mint does not rescan the owner's delegations as of registration for
policies with a recorded authority.

What to check is cached in process once a classification is final (bounded);
liveness is not cached. A steady-state use costs one indexed revocation query
for a recorded closure and none for root authority. A policy without a final
classification is classified in the request, served from that result, and
stored in the background; a result that isn't final is reused for 60 seconds.
Concurrent first uses of one policy share a single classification.

A revocation takes effect on commit; a request already past the check may
finish. Signed-KV tickets minted before a revocation last at most 60 seconds.

Other codes: an expired root gives `root-expired` (other non-live status
gives `root-not-live`); S0 admission returns the owner-authority code itself;
delivery keeps `delivery-authorization-invalid`. No code carries a CID or DID.
`policy-owner-authority-expired` is not reached by stored rows: a `bound`
root expires no later than its authority, and the root and session expiry
checks run first (`policy-session-expired` on reads, `root-expired` on
challenge and mint). It stays as a defence in depth.

### Legacy escape

```toml
[policy_v3]
legacy_unknown_allow = false  # TINYCLOUD_POLICY_V3__LEGACY_UNKNOWN_ALLOW
```

When true, legacy (`backfill`) policies classified `unknown` are served with
the root-only checks (and the mint's registration-time rescan); when false they
are denied. The node logs a warning at boot, and per policy at most once an
hour when it serves one; uses are counted in
`tinycloud_policy_owner_authority_unknown_allowed_total{reason}`. Denials are
counted in `tinycloud_policy_owner_authority_denied_total{reason=revoked|expired|unknown}`.

### Hook streams

A hook ticket carries the delegations that authorized it, plus, for a policy
session, the recorded owner-authority closure; a ticket with more than 16 is
refused (`403 hook-ticket-authority-too-large`). An open `/hooks/events`
stream re-checks them (one closure query plus one revocation query) before
delivering an event, at most every `hooks.authority_recheck_seconds` (5), and
every `hooks.idle_authority_recheck_seconds` (30) while idle. It closes on a
revocation, or after three consecutive failed checks, each at least an
interval after the last; until a check succeeds, events are withheld (dropped)
without querying, so a burst of events during a brief database error doesn't
close the stream. Streams don't see a JSON-route
`RootRevocation` (it writes no core revocation) or an authority expiry; those
end at the ticket deadline (at most 300 seconds), as before.
