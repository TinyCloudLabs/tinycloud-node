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
| `unknown` | no authority found; `unknown_reason` is `revoked`, `missing` or `starved` |

`registered_mode` is `record` for policies classified at registration, and
`backfill` for policies registered before the legacy cutover and classified
later.

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
