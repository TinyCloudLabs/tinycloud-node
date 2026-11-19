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
- The node authenticates with a static IAM user key (`AWS_KEY` / `AWS_SECRET`), not a role, and the data bucket uses the same key. Grant the node only `s3:PutObject`, `s3:GetObject` and `s3:ListBucket`. Reconciliation and restore read and list the ledger.
- Deny every other action on both ledger ARNs (bucket and `/*`) to every node credential, with one `NotAction` deny. This covers `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold`, `s3:PutBucketObjectLockConfiguration`, lifecycle and bucket-policy changes. Because the key is shared, a broad allow elsewhere must not reach the ledger. That grant is a Sam step and is not applied yet.
- The bucket policy denies `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention` and any request without TLS.
- In a versioned bucket, a plain `DeleteObject` adds a delete marker that hides a locked record from reads. Object Lock does not stop that; only the IAM deny does.
- Ledger PUTs carry a SHA-256 checksum, as Object Lock buckets require.

## 2. Old versions in the data bucket

The production data bucket is `tinycloud-production-blocks` (us-west-1). Per Amos's read-only check on 11-19, versioning has never been enabled on it and it has no lifecycle rules. In that state a purge's deletes are final and no old version remains. The node never deletes versions and needs no `s3:DeleteObjectVersion` permission. This is a dated readback, not a guarantee: restore runbook step 2 reads the state again at every restore (`get-bucket-versioning`, `get-bucket-lifecycle-configuration`).

If versioning is ever turned on, the same change must add a lifecycle rule that expires noncurrent versions 7 days after they become noncurrent and removes expired delete markers. With that rule, purged bytes leave the bucket at most 7 days after the purge, plus the provider's lifecycle lag. Without it, a purge leaves every old version behind.

## 3. Never Object Lock on the data bucket

The block / SQL object bucket must never have Object Lock, nor a default retention or legal hold. A locked version cannot be deleted before its retention ends. Purge would then report success while the bytes stayed. Object Lock belongs only on the ledger bucket.
