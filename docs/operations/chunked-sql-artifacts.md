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
conversion of existing artifacts and bounded reclamation follow separately.
It does not enable chunked DuckDB writes. Legacy data remains readable. Drain
older writers before enabling this format; turning the switch off does not
convert published parts back to legacy blobs. Current readers understand both
layouts; legacy persistence refuses a database already using parts.

Do not enable for prolonged operation until retained-part reclamation and the
approved ceiling load acceptance are complete. On each test release, report
reserved, staged and retained bytes from the following metadata-only inventory:

```sql
SELECT a.owner, a.reserved_bytes,
  COALESCE(sum(p.size_bytes) FILTER (WHERE NOT p.sealed),0) AS uploading_bytes,
  COALESCE(sum(p.size_bytes) FILTER (
    WHERE p.sealed AND NOT EXISTS (
      SELECT 1 FROM database_artifact d WHERE d.service=p.service
        AND d.space=p.space AND d.name=p.name
        AND (d.checkpoint_part_id=p.part_id OR d.delta_part_id=p.part_id)
    )),0) AS retained_bytes
FROM artifact_account a LEFT JOIN artifact_part p ON p.owner=a.owner
GROUP BY a.owner,a.reserved_bytes;
```

No content is selected by this inventory. Existing-row conversion and the
approved isolated-copy procedure are outside this first slice. Explicit SQL
exports still return their complete response body; the transfer-buffer bound
applies to persistence and hydration, not that public response format.
