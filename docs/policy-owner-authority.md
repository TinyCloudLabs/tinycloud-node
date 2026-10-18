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
| `unknown` | no authority found (`revoked`, `missing`, `starved`), or a post-cutover registration that breaks the current rules (`lifetime-exceeded`, `outlives-authority`) |

`registered_mode` is the mode (`record` or `enforce`) a policy was classified
under, or `backfill` for policies registered before the legacy cutover and
classified later.

## Root lifetime and mode

At registration, in both modes, a root is refused with `403
policy-root-lifetime-exceeded` unless `exp <= registered_at + 31 days + 5
minutes` and `nbf <= exp`. Released SDKs sign `nbf` at signing time with
`exp - nbf <= 31 days`, so their roots pass.

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

Always counted, independent of `telemetry.enabled`:

| metric | labels | counts |
|---|---|---|
| `tinycloud_policy_owner_authority_expiry_exceeded_total` | `authority_ttl_bucket` = `le_1h`, `le_30d`, `gt_30d`, `none` | `record` registrations whose root outlives the authority (authority lifetime from registration) |
| `tinycloud_policy_root_lifetime_refused_total` | | lifetime-cap refusals |
| `tinycloud_policy_legacy_root_lifetime_exceeded_total` | | legacy roots longer than 31 days, when classified |
| `tinycloud_policy_owner_binding_backfill_total` | `outcome` = `bound`, `bound_uncapped`, `root_authority`, `unknown`, `write_failed_served` | classifications after registration |

### Counting queries (PostgreSQL, read-only)

The fallback when the metrics aren't scraped. `registered_at`, `expires_at`
and `authority_expires_at` are RFC 3339 UTC text.

Q1, the `enforce` flip signal, by authority lifetime (`le_1h`: released Share
signing with a login session; `le_30d`: CLI device sessions):

```sql
SELECT CASE WHEN b.authority_expires_at IS NULL THEN 'none'
            WHEN b.authority_expires_at::timestamptz - r.registered_at::timestamptz <= interval '1 hour' THEN 'le_1h'
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
3. Otherwise the general window: the 256 newest delegations to the owner, of
   which at most 32 are tried.

A candidate whose ancestor closure (the candidate included) contains a
delegation issued by the policy owner is skipped. Among candidates that grant
the capability, the first, newest first, whose closure outlives the policy root
is chosen, else the newest. `starved` is recorded only when both steps found
nothing and more delegations exist than were examined.

## Policies registered earlier

A policy with no binding row is classified on first use: the selection runs in
memory as of its registration time (delegations issued after it are not
considered; UCANs carry no issue time and stay eligible), then one transaction
inserts the binding row first and its closure after it. A concurrent writer
that stored a row first wins. If the write fails (lock timeout, SQLite busy),
the in-memory result is used for that request and the row stays pending. An
`unknown` row written by an older `classifier_version` is classified again.

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
at boot.

## Rollback

The migration is unknown to 1.21.0, which refuses to boot with it applied. To
roll back, run the migration's `down` (it drops both tables), then deploy
1.21.0. While rolled back, policies have only the checks 1.21.0 has.

On the re-upgrade, set `policy_v3.legacy_cutover` to the first deploy time:
`down` erased the original applied-at time, and without the override every
policy registered during the rollback window would be classified as legacy.

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
not yet classified are not listed.
