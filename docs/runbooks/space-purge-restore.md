# Space purge restore runbook v1.7 (TC-2871)

Restoring a node database backup brings back every space and key that was deleted after the backup was taken. This runbook keeps those deletions deleted. It replaces four earlier versions:
- v1.6 (#645 head `a5ccf1fd`, frozen as `tc-2871-space-delete-restore-runbook-v1.6.md`, SHA-256 `40486d9f…1e22`). v1.7 keeps its text and adds the S5 changes: step 7's `purge-ledger reconcile` command, the re-deletion of erased owners' keys, the erased-record pruning rule and the no-rollback line, and the stated reader-ID residual.
- v1.5 (#645 head `58980fde`, never frozen). Its review found the node user's ledger policy had lost "allows only", so a broad allow on the shared key could reach the ledger, and the filesystem KV prefix was wrong.
- v1.4 (`tc-2871-space-delete-restore-runbook-v1.4.md`, SHA-256 `a09c01bf…9eeb`). Its freeze was voided on review: its data-bucket facts went unchecked, its re-purge covered only `{SpaceId}/`, and it lacked the lifecycle deny.
- v1.3 (`tc-2871-space-delete-restore-runbook-v1.3.md`, SHA-256 `73059c50…5bef`). It assumed the purge ledger lived under `_purge-ledger/` in the data bucket.

Storage rules it relies on: `docs/runbooks/space-purge-storage.md`.

## What is restored and what is not

| Store | On restore |
|---|---|
| Node Postgres (backup or point-in-time) | Restored. Holds deleted spaces and keys again. |
| Data bucket (`tinycloud-production-blocks`, us-west-1; KV blocks and SQL objects) | Not restored. Purged prefixes stay purged. Whether old versions of purged objects remain depends on the bucket's versioning and lifecycle state. Step 2 reads that state at every restore; the rule is in `space-purge-storage.md` §2. |
| Purge ledger (`[storage.purge_ledger]`: `tinycloud-node-purge-ledger`, us-west-1; Object Lock COMPLIANCE, 365 days) | Not restored. It is read live and is the record of every accepted and completed purge. |
| Encryption-network key-deletion log (`encryption_network.deletion_ledger_path`, `deletions.jsonl`) | Not restored. It lives on the node's volume and has no backup (Sam, 10-25). If the volume is lost, so is the log. |

The database is the only store that goes back in time. Every step below re-applies the two logs to it.

## Before restore

1. Fence the node: no ingress, no route served, no worker running. Reads, writes, `space/create`, `space/host` and sync all stay off until step 9. Once the operator purge path (S12) exists: its window is off (`[lifecycle.operator_purge] enabled_until` absent) and `TINYCLOUD_PURGE_OPERATOR_SECRET` is unset.
2. Check both buckets, read-only, with operator credentials, not the node key (the node key is denied these read-backs on the ledger). Keep each command's output with the restore record.

   Ledger bucket `tinycloud-node-purge-ledger`:
   - Object Lock is on, with a COMPLIANCE default retention of 365 days; versioning is on; public access is blocked.
   - The bucket policy denies `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention` and any request without TLS.
   - The node authenticates with a static IAM user key (`AWS_KEY` / `AWS_SECRET`), not a role, and the data bucket uses the same key. A broad allow on that user (`s3:*` or `Resource: *`) would therefore also reach the ledger bucket, so the policy denies everything on the ledger except the node's three calls. That user's policy:
     - allows **only** `s3:PutObject` and `s3:GetObject` on the ledger objects (`arn:aws:s3:::tinycloud-node-purge-ledger/_purge-ledger/*`, plus `_operator-audit/*` once S12 exists), and `s3:ListBucket` on `arn:aws:s3:::tinycloud-node-purge-ledger`;
     - has one `Deny` with `NotAction: [s3:PutObject, s3:GetObject, s3:ListBucket]` on both ledger ARNs, `arn:aws:s3:::tinycloud-node-purge-ledger` and `arn:aws:s3:::tinycloud-node-purge-ledger/*`. This covers `DeleteObject`, `DeleteObjectVersion`, `PutObjectRetention`, `PutObjectLegalHold`, `PutBucketObjectLockConfiguration`, `PutLifecycleConfiguration`, `PutBucketPolicy` / `DeleteBucketPolicy`, `PutBucketPublicAccessBlock` and ACL changes, whatever else the user is allowed;
     - names neither the data bucket nor `Resource: "*"` in any of these statements.

     Read-only check, with output kept. Each result must match exactly; `implicitDeny` on a deny row means the `NotAction` deny is missing.
     ```
     U=<node user ARN>; L=arn:aws:s3:::tinycloud-node-purge-ledger
     Q='EvaluationResults[].[EvalActionName,EvalResourceName,EvalDecision]'
     aws iam simulate-principal-policy --policy-source-arn "$U" --action-names s3:DeleteObject s3:DeleteObjectVersion s3:PutObjectRetention s3:PutObjectLegalHold --resource-arns "$L/_purge-ledger/x" --query "$Q" --output text
     aws iam simulate-principal-policy --policy-source-arn "$U" --action-names s3:PutBucketObjectLockConfiguration s3:PutLifecycleConfiguration s3:PutBucketPolicy s3:DeleteBucketPolicy --resource-arns "$L" --query "$Q" --output text
     aws iam simulate-principal-policy --policy-source-arn "$U" --action-names s3:PutObject s3:GetObject --resource-arns "$L/_purge-ledger/x" --query "$Q" --output text
     aws iam simulate-principal-policy --policy-source-arn "$U" --action-names s3:ListBucket --resource-arns "$L" --query "$Q" --output text
     ```
     Expected: the first two commands return `explicitDeny` on every row, and the last two return `allowed`:
     - `explicitDeny` for `s3:DeleteObject`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold`, `s3:DeleteObjectVersion`, `s3:PutBucketObjectLockConfiguration`, `s3:PutLifecycleConfiguration`, `s3:PutBucketPolicy` and `s3:DeleteBucketPolicy`;
     - `allowed` for `s3:PutObject` and `s3:GetObject` on `arn:aws:s3:::tinycloud-node-purge-ledger/_purge-ledger/x`, and for `s3:ListBucket` on the bucket ARN.

     This grant is a Sam step and has not been applied yet. Until it is, this check fails by design.
   - `aws s3api get-bucket-lifecycle-configuration --bucket tinycloud-node-purge-ledger` shows no rule that expires ledger objects.

   Data bucket `tinycloud-production-blocks`:
   - `aws s3api get-bucket-versioning --bucket tinycloud-production-blocks` returns no `Status`, meaning versioning has never been enabled.
   - `aws s3api get-bucket-lifecycle-configuration --bucket tinycloud-production-blocks` returns `NoSuchLifecycleConfiguration`.
   - Together, these two results mean a purge's deletes are final and no old version of a purged object remains. That is the state Amos read on 11-19.
   - If `Status` is `Enabled` or `Suspended`, old versions of purged objects can still exist. The lifecycle configuration must then hold a rule that expires noncurrent versions 7 days after they become noncurrent and removes expired delete markers.
     - Without that rule, stop: purged bytes are still in the bucket.
     - With it, write in the restore record that old versions of purged objects last up to 7 days plus the provider's lifecycle lag.
   - `aws s3api get-object-lock-configuration --bucket tinycloud-production-blocks` returns `ObjectLockConfigurationNotFoundError` (storage doc §3).
3. Check that every integrity key named by a ledger record's `keyId` is available. Never regenerate or guess a missing key. A missing key stops step 7 and every node start (`space-purge-storage.md` section 6).
4. Check that `deletions.jsonl` is present and its lock file is not held by another process.

If any check in steps 2-4 fails, stop. Keep the node fenced and alert with counts and opaque hashes only.

## Restore

5. Restore the database. Do not restore the data bucket, the ledger bucket or `deletions.jsonl` from any copy.

## Re-apply

6. Replay the key-deletion log: `tinycloud node deletion-ledger replay --config <config>`. It is idempotent; the node also replays it at every start. Any `refused` count is an alert; every valid entry is still applied.
7. Reconcile the purge ledger against the restored database, with the node stopped:

   ```sh
   tinycloud node purge-ledger reconcile --config <config>
   ```

   It reads `TINYCLOUD_HOST_ID` and `TINYCLOUD_PURGE_LEDGER_KEYS` from the environment, applies pending migrations, runs the node's startup reconciliation once, and prints counts only. Run it again until a run re-creates nothing; how to read the report is in `space-purge-storage.md` section 5. It does the following:
   - Verify every record's HMAC before using it. An invalid record is an alert; do not skip it and do not serve.
   - Re-apply every owner retirement to the registry and to each configured TinyCloud-operated host. Every host must import the retirement before `space/create` or `space/host` is allowed.
   - Re-create the fence of every accepted purge and resume it. A purge is never un-fenced. A record authenticates each prefix it purges by an HMAC tied to a store kind. The worker lists candidate prefixes in each store and acts only on a candidate whose HMAC is in the record (`VerifiedPurgePrefix::verify_candidate` in `tinycloud-node-server/src/storage/purge_reconcile.rs`; `purge_restore_prefix_batch` in `purge_restore.rs`). The prefixes, by store:
     - KV blocks: `{SpaceId}/` in the S3 block store; `{owner}/{name}/` (the SpaceId's suffix and name) in the filesystem block store.
     - SQL objects: the space's namespace `sql/v1/{enc(SpaceId)}/`, or the hashed form `sql/v1/~{sha256}/` when the encoded ID is too long. A hashed namespace is purged as it is. No space ID or owner is recovered from it.
     - The space's SQLite and DuckDB caches: drained and evicted.

     Each block-store and SQL prefix is listed from the start, deleted, and listed again until empty. A provider cursor never counts as progress.
   - Re-create the completion tombstone of every completed purge. A completed space ID stays unavailable; no new space is created under it.
   - **Re-delete every erased owner's keys.** For every verified `("owner","erased")` record (`_purge-ledger/owners-erased/<key_id>/<owner HMAC>`), delete that owner's `encryption_network`, `encryption_network_key`, `encryption_network_member`, `encryption_ceremony` and `encryption_audit` rows again, then drop the owner's settled operations from `deletions.jsonl`. The owner is found by matching the record's HMAC over the DIDs the tables and `deletions.jsonl` name; an HMAC is never reversed. Report fields: `owners_erased_redeleted`, `owners_pruned`, and `blocked_rows_present` (key rows remain; run again, escalate if it stays above 0).
   - Where the database and the ledger disagree, the ledger wins: resume or re-run the purge. Never delete a ledger record or treat a database-only state as authoritative.
   - Ledger records lock for 365 days, and a record older than that may legally be gone. A missing record never means "never purged". For a space purged more than a year before the backup was taken, the restored database still carries its tombstone, and that tombstone stays even with no ledger record behind it.

   Any failure exits non-zero and leaves nothing a later run cannot finish. Fix the cause and run it again; do not serve.

## Resume service

8. An operator confirms:
   - every ledger record is applied;
   - every accepted purge is complete;
   - every configured host has imported every retirement;
   - step 6 reported no refused entries;
   - step 7's last run re-created nothing and reported `blocked_rows_present` 0.
9. Only then remove the fence. If any evidence is missing or inconsistent, keep the node fenced and escalate. Never bypass reconciliation.

## Invariants for later work

- `deletions.jsonl` is pruned per erased owner (Naomi 11-19, ruling A). An owner's lines are removed only when that owner's `("owner","erased")` record verifies in the locked ledger **and** zero `encryption_network_key` rows remain for the owner's networks. After a restore, step 7 re-deletes those keys from the `erased` record, not step 6.
- **No rollback past the release that adds the `erased` record; recovery = fix forward** (`space-purge-storage.md` section 5).
- OpenKey has the matching step: after a Neon restore, replay `account_deletion_job` receipts before serving. That belongs to the OpenKey restore procedure, not this one.

## What this runbook does not erase

It removes deleted data from live storage after a restore. Copies outside live storage are bounded by their own expiry, not by this runbook: database backups and point-in-time history (14-day cap) and logs. Old versions in the data bucket are bounded by whatever step 2 found: none while the bucket is unversioned; up to 7 days plus the provider's lifecycle lag under the noncurrent rule if versioning is on.

**Stated residual (Sam, 2026-11-19 12:05:36Z: "Keep it, with the conditions (recommended)"):** if a deleted person had read data in someone else's space, their ID stays in that space owner's access log until that space is deleted. It is the owner's own record of the access; we never build a list of people from it or search it by person.

In the node, that ID is in the space's `actor`, `invocation` (the signed request) and `invoked_abilities` rows. They are not scrubbed or keyed, because the signed request would stop being verifiable evidence. Conditions:
- No list of people is built from these rows. Today `encryption_owners` reads only the five encryption tables, and `data_owners` (admin stats) reads only `space`, `current_kv` and `database_artifact`.
- No new lookup by reader ID.
- This runbook names it, here.
