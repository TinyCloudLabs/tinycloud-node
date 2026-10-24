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
| `unknown` | no authority found; `unknown_reason` is `revoked`, `missing`, `starved` or `foreign_network` |

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

A policy with no binding row is classified in the background on first use,
off the request: the selection runs as of its registration time (delegations
issued after it are not considered; UCANs carry no issue time and stay
eligible), then one transaction inserts the binding row first and its closure
after it. A concurrent writer that stored a row first wins. One task runs per
policy, and at most three in the whole process; a use that finds no free slot
starts none (a later use does). If the write fails (lock timeout, SQLite busy) or the result
is `starved`, the row stays pending and the request path doesn't start another
attempt for 60 seconds. Policies whose stored classification is final are
remembered in process (bounded), so steady-state reads add no query. An
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
