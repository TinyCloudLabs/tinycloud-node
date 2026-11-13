# Opt-in SQL checkpoint parts

The first TC-2917 slice stores SQL checkpoints as immutable PostgreSQL parts.
Each payload statement carries at most 1 MiB. A metadata-only compare-and-swap
publishes a sealed part; successful writes retain the existing durability and
lineage semantics. Hydration verifies the part CID before publishing its cache.

The switch is off by default. Set explicit capacities before enabling:

```toml
[storage.sql]
chunked_artifacts = false
chunked_artifact_max_bytes = 0
chunked_account_max_bytes = 0
```

Both capacities must be positive when enabled. No capacity defaults are chosen
by this slice. The account capacity is charged to the space owner, across its
spaces, including legacy live artifacts, staged uploads and retained parts.
Reservations are atomic per owner. Quota refusal uses the SQL storage refusal.

This slice publishes a full checkpoint for each SQL mutation. WAL parts,
conversion of existing artifacts follow separately.
Aborted and superseded parts enter a fenced deleting state; reclamation deletes
at most one payload chunk per statement and releases its charge only after all
bytes are gone. A periodic collector recovers uploads whose 120-second lease
expired. Lease expiry determines eligibility; part identity and state fence
uploads against concurrent reclamation. Active sealed uploads retain their lease
until publication. Deleted artifacts are reclaimed by the same mechanism.
It does not enable chunked DuckDB writes. Legacy data remains readable. Drain
older writers before enabling this format; turning the switch off does not
convert published parts back to legacy blobs. Current readers understand both
layouts; legacy persistence refuses a database already using parts.

Do not enable for prolonged operation until the approved ceiling load acceptance and
remaining migration/WAL slices are complete. On each test release, report
reserved, staged and retained bytes from the following metadata-only inventory:

```sql
SELECT a.owner, a.legacy_bytes, a.reserved_bytes, a.credit_bytes,
  a.legacy_bytes+a.reserved_bytes-a.credit_bytes AS quota_bytes,
  (SELECT COALESCE(sum(octet_length(c.payload)),0)
   FROM artifact_chunk c JOIN artifact_part stored
   USING (service,space,name,part_id) WHERE stored.owner=a.owner) AS stored_chunk_bytes,
  COALESCE(sum(p.size_bytes) FILTER (WHERE p.state='uploading'),0) AS uploading_bytes,
  COALESCE(sum(p.size_bytes) FILTER (
    WHERE p.state IN ('sealed','deleting') AND NOT EXISTS (
      SELECT 1 FROM database_artifact d WHERE d.service=p.service
        AND d.space=p.space AND d.name=p.name
        AND (d.checkpoint_part_id=p.part_id OR d.delta_part_id=p.part_id)
    )),0) AS retained_bytes
FROM artifact_account a LEFT JOIN artifact_part p ON p.owner=a.owner
GROUP BY a.owner,a.legacy_bytes,a.reserved_bytes,a.credit_bytes;
```

No content is selected by this inventory. Existing-row conversion and the
approved isolated-copy procedure are outside this first slice. Explicit SQL
exports still return their complete response body; the transfer-buffer bound
applies to persistence and hydration, not that public response format.

Quota enforcement is activated atomically with an exact-owner metadata inventory.
After activation, the same database owner-row lock accounts for legacy SQL and
DuckDB writes, including writes made by an older binary. This activation remains
in force if a reader starts with the feature switch off. Database triggers also
refuse a legacy update of a published checkpoint-parts layout atomically; the
layout marker and generation are metadata, not payload contents. A flag-off
legacy read or write adds no client-side layout probe.

Before the first activation, the quota trigger is disabled: legacy requests add
no client layout probes or quota queries. The field-only layout guard remains
installed for mixed-version writes. First activation enables owner accounting
under the same short writer fence used for its initial inventory.
After activation, switching off new chunked databases does not disable support
for already-published parts: current nodes continue their file-based writes
using the persisted capacities, and keep the collector running.

Operators use the value-free `artifact_part_collection_failed` event to investigate deferred reclamation.

A replacement may overlap its current database's bytes: at most one replacement
per database receives a credit, bounded by the smaller of current and staged
sizes. Full staged bytes remain visible in `reserved_bytes`. A pending shrink
never releases capacity for another database. Credit is released only when the
old part is reclaimed, or the staged upload is reclaimed after abort; legacy
replacement credit is released atomically with publication. Admission evaluates
account usage minus the current database size plus its proposed replacement.
Thus a full account can shrink, cannot grow above its quota, and cannot reuse
the same database's credit for a second simultaneous replacement.

Published parts have a distinct state and infinite lease, and are excluded from
both global and owner-local reclamation indexes. Inline cleanup is best effort,
scoped to the uploading owner, at most 16 steps and 100 ms per pass; its errors
do not fail the save. Background passes are limited to 128 steps and one second
per 10-second tick. GC lock acquisition waits at most 50 ms per statement.
An owner already above its quota can replace a database with an equal or
smaller image; that exception admits no growth and does not free pending shrink
capacity for other databases.
