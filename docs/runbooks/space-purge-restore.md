# Space purge restore runbook v1.4 (TC-2871)

Restoring a node database backup brings back every space and key that was deleted after the backup was taken. This runbook keeps those deletions deleted. It replaces restore runbook v1.3 (`tc-2871-space-delete-restore-runbook-v1.3.md`, SHA-256 `73059c50…5bef`), which assumed the purge ledger lived under `_purge-ledger/` in the data bucket.

Storage rules it relies on: `docs/runbooks/space-purge-storage.md`.

## What is restored and what is not

| Store | On restore |
|---|---|
| Node Postgres (backup or point-in-time) | Restored. Holds deleted spaces and keys again. |
| Data bucket (`tinycloud-production-blocks`, us-west-1; KV blocks, SQL objects) | Not restored. It is unversioned and has no lifecycle rules, so purged prefixes stay purged and no old version remains. If versioning is ever turned on, a 7-day noncurrent-version rule must be added with it. |
| Purge ledger (`[storage.purge_ledger]`: `tinycloud-node-purge-ledger`, us-west-1; Object Lock COMPLIANCE, 365 days) | Not restored. It is read live and is the record of every accepted and completed purge. |
| Encryption-network key-deletion log (`encryption_network.deletion_ledger_path`, `deletions.jsonl`) | Not restored. It lives on the node's volume and has no backup (Sam, 10-25). If the volume is lost, so is the log. |

The database is the only store that goes back in time. Every step below re-applies the two logs to it.

## Before restore

1. Fence the node: no ingress, no route served, no worker running. Reads, writes, `space/create`, `space/host` and sync all stay off until step 9. Once the operator purge path (S12) exists: its window is off (`[lifecycle.operator_purge] enabled_until` absent) and `TINYCLOUD_PURGE_OPERATOR_SECRET` is unset.
2. Check the purge ledger bucket `tinycloud-node-purge-ledger`:
   - Object Lock is on, with a COMPLIANCE default retention of 365 days; versioning is on; public access is blocked.
   - The bucket policy denies `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention` and any request without TLS.
   - The node IAM user's policy (the node uses a static IAM user key, not a role) allows only `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on the bucket. It explicitly denies `s3:DeleteObject`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold` and `s3:PutBucketObjectLockConfiguration`. This grant is a Sam step and is not applied yet; until it is, this check fails by design.
   - No lifecycle rule expires ledger objects.
3. Check that every integrity key named by a ledger record's `keyId` is available. Never regenerate or guess a missing key.
4. Check that `deletions.jsonl` is present and its lock file is not held by another process.

If any check in steps 2-4 fails, stop. Keep the node fenced and alert with counts and opaque hashes only.

## Restore

5. Restore the database. Do not restore the data bucket, the ledger bucket or `deletions.jsonl` from any copy.

## Re-apply

6. Replay the key-deletion log: `tinycloud node deletion-ledger replay --config <config>`. It is idempotent; the node also replays it at every start. Any `refused` count is an alert; every valid entry is still applied.
7. Reconcile the purge ledger against the restored database:
   - Verify every record's HMAC before using it. An invalid record is an alert; do not skip it and do not serve.
   - Re-apply every owner retirement to the registry and to each configured TinyCloud-operated host. Every host must import the retirement before `space/create` or `space/host` is allowed.
   - Re-create the fence of every accepted purge and resume it. The worker lists the exact `{SpaceId}/` prefix, deletes, and lists again until empty. A purge is never un-fenced.
   - Re-create the completion tombstone of every completed purge. A completed space ID stays unavailable; no new space is created under it.
   - Where the database and the ledger disagree, the ledger wins: resume or re-run the purge. Never delete a ledger record or treat a database-only state as authoritative.
   - Ledger records lock for 365 days, and a record older than that may legally be gone. A missing record never means "never purged". For a space purged more than a year before the backup was taken, the restored database still carries its tombstone, and that tombstone stays even with no ledger record behind it.

   Step 7 has no command yet. The node has the reconcile code but does not call it at startup or after a restore; S5 wires it. **Until S5 ships, a restore of node-prod cannot complete this runbook, so the node stays fenced after any restore until Naomi or Sam decides.**

## Resume service

8. An operator confirms:
   - every ledger record is applied;
   - every accepted purge is complete;
   - every configured host has imported every retirement;
   - step 6 reported no refused entries.
9. Only then remove the fence. If any evidence is missing or inconsistent, keep the node fenced and escalate. Never bypass reconciliation.

## Invariants for later work

- `deletions.jsonl` is pruned per purged owner (Naomi 11-19). An owner's lines are removed only after that owner's purge completion record is in the locked ledger, and that purge deletes the owner's encryption-network key rows. After a restore, step 7 then re-deletes those keys instead of step 6.
- OpenKey has the matching step: after a Neon restore, replay `account_deletion_job` receipts before serving. That belongs to the OpenKey restore procedure, not this one.

## What this runbook does not erase

It removes deleted data from live storage after a restore. Copies outside live storage are bounded by their own expiry, not by this runbook: database backups and point-in-time history (14-day cap) and logs. The data bucket holds no old versions while it stays unversioned; if versioning is ever turned on, old versions last up to 7 days under the rule that must be added with it.
