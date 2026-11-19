# Space purge storage (TC-2871)

Three storage rules for space purge. A purge must actually erase the data and leave a record that the erasure happened.

## 1. The purge ledger has its own store

Purge acceptance and completion records go to `[storage.purge_ledger]`. They never go to the block (KV and SQL object) store they describe.

- **S3 block storage** has no default ledger. Set `TINYCLOUD_STORAGE__PURGE_LEDGER__TYPE=S3` and `TINYCLOUD_STORAGE__PURGE_LEDGER__BUCKET`. Optionally set `__ENDPOINT`, `__REGION`, `__ACCESS_KEY_ID` and `__SECRET_ACCESS_KEY`. Credentials come as a pair or not at all. Without them the node uses its default AWS credential chain.
- **Local block storage** defaults to `<datadir>/purge-ledger`. An explicit `Local` path must not be the block directory, inside it, or contain it.
- Startup and `--validate-config` refuse a ledger that shares the block bucket (same name and endpoint) or overlaps the block directory.

The ledger bucket:

- Production: `tinycloud-node-purge-ledger` (us-west-1). It has versioning on, Object Lock with a COMPLIANCE default retention of 365 days, all public access blocked, and SSE-S3. The node sets `TINYCLOUD_STORAGE__PURGE_LEDGER__TYPE=S3`, `TINYCLOUD_STORAGE__PURGE_LEDGER__BUCKET=tinycloud-node-purge-ledger` and `TINYCLOUD_STORAGE__PURGE_LEDGER__REGION=us-west-1`.
- Retention must cover the restore window plus the backup retention, because a restore can bring back data that only the ledger proves was purged. 365 days covers the 14-day backup cap. A record older than 365 days may legally be gone, so reconciliation must never read a missing record as "never purged".
- The node authenticates with a static IAM user key (`AWS_KEY` / `AWS_SECRET`), not a role. The node IAM user's policy allows `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on the ledger bucket; reconciliation and restore read and list the ledger. The same policy denies `s3:DeleteObject`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold`, `s3:PutBucketObjectLockConfiguration` and `s3:PutLifecycleConfiguration`. That grant is a Sam step and is not applied yet.
- The bucket policy denies `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention` and any request without TLS.
- In a versioned bucket, a plain `DeleteObject` adds a delete marker that hides a locked record from reads. Object Lock does not stop that; only the IAM deny does.
- Ledger PUTs carry a SHA-256 checksum, as Object Lock buckets require.

## 2. Old versions in the data bucket

The production data bucket is `tinycloud-production-blocks` (us-west-1). Versioning has never been enabled on it, and it has no lifecycle rules, so a purge's delete is final: no old version remains. The node never deletes versions and needs no `s3:DeleteObjectVersion` permission.

If versioning is ever turned on, a lifecycle rule must be added in the same change. It must expire noncurrent versions 7 days after they become noncurrent and remove expired delete markers. With that rule, purged bytes leave the bucket at most 7 days after the purge, plus the provider's lifecycle lag. Without it, a purge leaves every old version behind.

## 3. Never Object Lock on the data bucket

The block / SQL object bucket must never have Object Lock, nor a default retention or legal hold. A locked version cannot be deleted before its retention ends. Purge would then report success while the bytes stayed. Object Lock belongs only on the ledger bucket.

## 4. Turning space lifecycle on

Space lifecycle (the `/space/list`, `/space/retire-owner`, `/space/purge` and `/space/purge/status` routes and the purge worker) is on only when both of these are set:

- `TINYCLOUD_HOST_ID`: the stable, non-secret host name owners sign into lifecycle requests, `[a-z0-9-]{1,63}`, e.g. `node-prod-1`.
- `TINYCLOUD_PURGE_LEDGER_KEYS`: a secret. It takes only the JSON form `{"active_key_id":"plk-YYYYMMDD","keys":{"plk-YYYYMMDD":"<base64url, at least 32 bytes>"}}`. Startup and `--validate-config` refuse a bare key and never print the value. Keep every retired key ID in `keys` for as long as its records can be in the ledger.

Setting only one of them is a configuration error. On also needs PostgreSQL and a `[storage.purge_ledger]` (section 1).

With both unset, the node starts as before and the lifecycle routes answer 404. If the database or the configured ledger already holds lifecycle state (records, fences, retirements or purge jobs), startup refuses: removing the settings cannot bypass the ledger. With lifecycle off and an S3 ledger configured, startup lists the ledger bucket, so the IAM grant in section 1 must be in place first.

When on, the node does this before it serves anything:

1. Verify every ledger record's HMAC, in the ledger store and in the database copy. One bad or conflicting record stops the start.
2. Reconcile the database to the ledger: re-create owner fences and retirements, space fences and completion tombstones, and re-create the job of an accepted purge whose job is missing. The ledger wins; nothing is un-fenced.
3. Match each signed storage prefix against the stores: purge a prefix that is still present, record one that is absent.

Any failure stops the start. Once the node is up, if a lifecycle request cannot confirm its ledger write, the node refuses all space traffic (503) and reconciles again until it succeeds. The startup log line `purge ledger reconciled` carries counts only.

## 5. Reconcile after a restore (restore runbook step 7)

With the node stopped and the database restored, run:

```sh
tinycloud node purge-ledger reconcile --config <config>
```

It reads the database, the stores and the ledger from the config, and `TINYCLOUD_HOST_ID` and `TINYCLOUD_PURGE_LEDGER_KEYS` from the environment. It applies pending database migrations, as node start does, then runs the reconciliation the node runs at startup, once. It prints a JSON report with counts only, never a space, owner or purge ID. It is idempotent: a second run re-creates nothing, and its `purges_in_progress` counts the purges the first run resumed. `--json` prints the report on one line.

Read the report:

- `purges_resumed` and `purges_in_progress`: the worker finishes these once the node starts.
- `purges_unresumable`: completed purges whose space is back but whose acceptance record has aged out of the ledger. The space stays fenced; escalate.
- `prefixes_unavailable`: signed prefixes in a store this node does not run. They were not checked; escalate.
- `prefixes_deferred`: prefixes still inside the upload grace. Run the command again after the grace, or let the node finish them.
- `owners_erased_redeleted`: owners with an `erased` record whose encryption rows the restore brought back; the pass deleted them again.
- `owners_pruned`: erased owners whose settled operations it dropped from `deletions.jsonl` (`[global.encryption_network] deletion_ledger_path`; the command opens it, which is one more reason the node must be stopped).
- `blocked_rows_present`: erased owners whose key rows are still there, so `deletions.jsonl` keeps them. Run the command again; escalate if it stays above 0.

### Owner erasure records

Once a retired owner has no live space and every purge of the owner is complete, the purge worker erases the owner's encryption rows in this order:

1. It writes a signed `("owner","erased")` record to the purge ledger, at `_purge-ledger/owners-erased/<key_id>/<owner HMAC>`, beside the owner's `retired` record.
2. In one transaction, it deletes the owner's `encryption_network`, `encryption_network_key`, `encryption_network_member`, `encryption_ceremony` and `encryption_audit` rows.
3. It drops the owner's settled operations from `deletions.jsonl`, but only when the record verifies and no key row remains.

A crash between steps leaves the record in place; the worker's next pass and this command finish steps 2 and 3. After a restore, this command (step 7) deletes the rows again for every `erased` record.

**No rollback past this release; recovery = fix forward.** This applies from the first deploy of the release, whether or not any `erased` record exists yet. An earlier release refuses an `erased` record when it verifies the ledger, so it does not start, and this release's `m20261112_*` purge migrations refuse `down`. Records under `_purge-ledger/owners-erased/` are locked and cannot be removed to allow a rollback. The release ships on its own (no other features in it), so a fix forward touches only this change.

A failure exits non-zero and changes nothing that a later run cannot finish. Fix the cause and run it again. Only `deletions.jsonl` is locked (the command waits up to 60 seconds for it, then fails); nothing else stops it running beside a serving node, so never run it while the node is serving.

## 6. Ledger HMAC key: custody, rotation and loss

**Production values (Amos, 11-19):**
- `TINYCLOUD_PURGE_LEDGER_KEYS` comes from the production secret `PROD_TINYCLOUD_NODE_PURGE_LEDGER_KEYS`, sealed into the node's environment like the other `PROD_TINYCLOUD_NODE_*` secrets. JSON form only (section 4); key IDs are `plk-YYYYMMDD`.
- `TINYCLOUD_HOST_ID=node-prod-1` is a plain, non-secret variable.
- Amos generates the key, holds it, and sets the secret from a file. Agents never see it, and tests use fixture keys.
- **Escrow:** a second copy goes in Sam's TinyCloud Secrets. It is set on Sam's card when S5 ships, before lifecycle is turned on.

**Rotation:**
1. Add the new key ID to `keys` and make it `active_key_id`.
2. Keep every earlier ID in `keys` for as long as a record signed with it can still be in the ledger or the database copy: at least 365 days after the last record it signed.
3. Update the escrow copy in the same change.

**What a lost key means.** Every record is verified against the key its `key_id` names, and an ID missing from `keys` fails verification like a forged record. With lifecycle on, both node startup and `tinycloud node purge-ledger reconcile` stop at the first record that fails. So without the key, **the node does not start at all**: on any restart, not only after a restore.

Neither of these gets around it:
- **Turning lifecycle off:** startup refuses whenever the database or the ledger already holds lifecycle state.
- **Removing the records:** they are under Object Lock COMPLIANCE for 365 days, so nobody can delete them, including the account root. After that they leave only if a lifecycle rule or an operator removes them, and the database copies stay until someone deletes them.

**Recovery:**
1. Restore the lost key from Sam's escrow into `PROD_TINYCLOUD_NODE_PURGE_LEDGER_KEYS` under its **original key ID**, alongside the current active key. Redeploy.
2. Confirm that startup logs `purge ledger reconciled`. After a restore, run section 5 first.
3. If the escrow copy is also gone, there is no supported path: the node stays down. Escalate to Sam. Any way forward, such as an operator-acknowledged retirement of that key ID, needs a design and a code change, and Sam decides it, because it means trusting records that can no longer be verified.
