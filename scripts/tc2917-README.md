# TC-2917 operator procedure

The storage setting is an optimisation. PostgreSQL 18 takes ACCESS EXCLUSIVE
for ALTER COLUMN SET STORAGE, conflicting with ordinary reads and writes.
The node tries three times with a 500 ms lock timeout. If all three attempts
encounter lock contention, it warns and continues startup with the migration
recorded as applied. It will not automatically retry this migration on restart.
Other SQL errors still fail startup. Existing compressed values remain readable.

Before deploying, prefer applying the catalog setting in a quiet window using
an operator session. This also recovers a setting deferred at startup. The
statement is idempotent; it does not rewrite values. A timeout rolls back both
settings: retry later instead of increasing the time queries queue behind DDL.

```sql
BEGIN;
SET LOCAL lock_timeout = '500ms';
ALTER TABLE database_artifact
  ALTER COLUMN payload SET STORAGE EXTERNAL,
  ALTER COLUMN delta_payload SET STORAGE EXTERNAL;
COMMIT;
```

Immediately after rollout, query the catalog below for `payload` and
`delta_payload`; if either is not `attstorage = 'e'`, schedule the quiet-window
operator DDL above, since a deferred migration is not retried automatically.

Verify both catalog rows have `attstorage = 'e'` before re-toast:

```sql
SELECT attname, attstorage FROM pg_attribute
WHERE attrelid = 'database_artifact'::regclass
  AND attname IN ('payload', 'delta_payload');
```

Before the one-off rewrite, check free database disk headroom for expanded
payloads, new row versions and WAL. The three observed large checkpoints grow
by approximately 291 MiB before TOAST overhead; rewriting every checkpoint
would grow stored checkpoint data by approximately 575 MiB. Delta payloads,
WAL and retained old versions require additional headroom.

Run one explicitly selected row at a time, off-peak, using
`tc2917-retoast-artifact.sql` as shown in its header. Each rewrite writes the
full value to WAL. Watch replica lag between rows and defer the next row if
replication has not caught up. Concurrent writers to that artifact wait on its
row lock for the duration of the rewrite; reads continue against their snapshot.
The script has a 500 ms lock timeout and 120 s statement timeout. It aborts if
the catalog settings are absent, the selected large row is missing, revision
or hash metadata changes, bytes/lengths change, or compression remains.

This is a separately planned operator action, not an automatic backfill or
authorisation to execute against production. No migration-history edits are
needed. Existing revision and content hashes stay unchanged.
