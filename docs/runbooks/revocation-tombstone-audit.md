# Revocation tombstones and the past-purge audit (TC-4092)

## What a tombstone is

A space purge deletes signed records, including the `revocation` rows of the delegations it deletes, because a `revocation` row names its revoker and carries signed bytes. Before 1.26.24 nothing remembered the revocation after that, so the same signed bytes posted to `/delegate` again were registered as new. From 1.26.24, purge first writes one `revocation_tombstone` row per revoked delegation, and `/delegate` refuses a delegation with a tombstone: 401, code `delegation_revoked`.

`revocation_tombstone` has four columns and nothing else: `delegation_canonical` (primary key, the delegation's canonical content hash, so every encoding of it is covered), `delegation_expiry` (NULL: never pruned), `revoked_at` (NULL when unknown) and `recorded_at`. It holds no DID, space, owner or resource. Nothing prunes it yet; it grows by about 100 bytes per revoked-and-purged delegation. A restore that re-runs a purge rewrites the same rows (`ON CONFLICT DO NOTHING`).

A purge also deletes the `renewal_lease` and `renewal_stamp` rows of a delegation it deletes. Before 1.26.24 a lease row outlived its delegation.

## Audit of purges that ran before 1.26.24

**Do not run this against production until Bobbie has approved this exact text.** It is read-only, runs on a replica, returns counts only and names no DID, space or resource.

```sql
SELECT
  (SELECT count(*) FROM renewal_lease)                               AS renewal_lease_rows,
  (SELECT count(*) FROM renewal_lease l
     WHERE NOT EXISTS (SELECT 1 FROM delegation d WHERE d.id = l.lease_cid)) AS lease_delegation_gone,
  (SELECT count(*) FROM renewal_lease l
     WHERE NOT EXISTS (SELECT 1 FROM delegation d WHERE d.id = l.original_canonical)
       AND NOT EXISTS (SELECT 1 FROM delegation_cid_alias a
                         WHERE a.canonical = l.original_canonical))  AS original_delegation_gone,
  (SELECT count(*) FROM revocation_tombstone)                        AS tombstones,
  (SELECT count(*) FROM space_purge_job WHERE phase = 'complete')    AS completed_space_purges;
```

Reading it:

- `lease_delegation_gone` and `original_delegation_gone` count leases whose delegation a purge deleted. Each such row is a lease the node could still treat as stored. They are the only trace a purge that ran before 1.26.24 left of a revoked lease; the revocation row itself is gone.
- A revoked plain delegation (not a lease) that a past purge deleted leaves no row, so no query counts it. `completed_space_purges` is the upper bound on how many purges could have deleted revocations. A completed purge fences its space permanently, so a re-post naming the purged space is refused by the fence; the remaining exposure is a delegation that names no purged space.
- `tombstones` is 0 on the first day. It grows only with purges run by 1.26.24 or later.

No action follows from a non-zero count in this runbook. Report the counts to the incident owner. Do not delete the leftover `renewal_lease` rows by hand: the next purge of the same delegation deletes them.

## Rollback

`revocation_tombstone` is created at boot by the node's own database role, which therefore owns it (docs/releasing.md, TC-3755). An operator role cannot `DROP` it. Roll back by fix-forward, or by deregistering only: `DELETE FROM seaql_migrations WHERE version = 'm20261125_000000_revocation_tombstone'`; the previous image then boots with the table left in place, and the migration's `up` is idempotent for the way forward. The down SQL is `DROP TABLE IF EXISTS revocation_tombstone`, run as the node role. Take a backup first. **Rolling back reopens the gap**: a purge run by the previous image deletes revocations without a tombstone.

After a deploy, check the owner on the replica:

```sql
SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'revocation_tombstone';
```
