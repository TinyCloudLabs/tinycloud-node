# TC-822: bounded artifact reads and the Postgres `payload` storage setting

Tracking: [TC-822](https://linear.app/tinycloud-labs/issue/TC-822), under TC-1491. This is an **operator step on Postgres**, not a migration: it is not run at boot and rewrites no data. The PR that introduces the bounded reads contains no migration or schema change (schema freeze).

## What the node does now

The node never reads a whole `database_artifact` row. `load_meta` selects the metadata columns only. Hydration (`read_chunks`) reads `payload`, then `delta_payload`, in 4 MiB `substr(column, offset, length)` slices, each its own statement under the pool's base statement timeout and guarded by `WHERE revision = <meta.revision> AND checkpoint_content_hash = <meta.checkpoint_content_hash>`. The slices are hashed as they stream and compared with `checkpoint_content_hash` / `delta_content_hash` / `content_hash`. A slice that finds no row (the artifact was saved or deleted meanwhile) restarts the hydration from fresh metadata, at most twice; any hash or size mismatch fails the hydration and seeds nothing.

Round trips per artifact hydration: an artifact of at most 8 MiB stored bytes (`BASE_TIMEOUT_PAYLOAD_BYTES`) is `1 + 1` (+1 with a WAL delta); a larger one is `1 + ceil(checkpoint_bytes / 4 MiB) + ceil(delta_bytes / 4 MiB)`.

## Why Postgres needs `STORAGE EXTERNAL` on `payload`

`bytea` columns default to `STORAGE EXTENDED`: large values are pglz-compressed in TOAST. `substr` on a compressed value decompresses the whole **prefix** up to `offset + length` inside the server, so slice cost and server memory grow with the offset. Measured on PostgreSQL 14 (`shared_buffers=64MB`, SQLite-like data compressing 3.4x):

| artifact | slice offset | EXTENDED (compressed) | EXTERNAL |
|---|---|---|---|
| 256 MiB | 250 MB | 360 ms, 325 MB backend RSS | 1 ms, ~4 MB |
| 1000 MiB | 1,044 MB | 1.4 s, 1.3 GB backend RSS | 1 ms, ~7 MB |
| 1000 MiB, all 250 slices | | 214 s | 0.67 s |

Without the setting, the node stays correct and its own memory stays bounded, but a large, compressed artifact hydrates slowly and costs the database server as much memory as one slice reaches into the value, and with a tight base statement timeout a deep slice can be cancelled (a 500 ms timeout is exceeded past ~100 MB offsets). Apply it before relying on large artifacts.

## The step

```sql
SET lock_timeout = '3s';          -- ACCESS EXCLUSIVE, metadata only; retry if it times out
ALTER TABLE database_artifact ALTER COLUMN payload SET STORAGE EXTERNAL;
```

- Idempotent: running it again is a no-op. Check with `SELECT attstorage FROM pg_attribute WHERE attrelid = 'database_artifact'::regclass AND attname = 'payload'` (`e` = external, `x` = extended).
- Not a rewrite. **Existing rows keep their compressed form** until their next full checkpoint save, which writes `payload` anew (WAL-only saves touch `delta_payload`, bounded to 8 MiB, and do not need the setting). Measured: `ALTER` alone leaves an existing compressed row as slow as before.
- A schema created fresh by the migrations stays `EXTENDED`; run the statement once per database.
- Do not run it inside a migration or the boot transaction. Do not mass-rewrite rows without a separate decision (an `UPDATE ... SET payload = payload || ''::bytea` rewrites every TOAST chunk and is WAL-heavy).

## Production plan

- Run the `ALTER` on the **new US-West** branch **before** the logical-replication initial copy: every row then arrives fresh and uncompressed, sliceable, and no rewrite is ever needed.
- On us-east the `ALTER` alone converts nothing; each artifact converts at its next full checkpoint. Until then a large, compressed artifact hydrates on the slow path (numbers above: ~360 ms and ~325 MB server memory for a slice at 250 MB of a 256 MiB artifact; 214 s to hydrate 1000 MiB). Node RAM stays bounded either way.
- The `ALTER` is DDL: run it once per side, outside the replication-copy-to-GO schema freeze window. This change's merge/deploy must not land inside that window either. This PR contains no migration or schema change.

## Cost: `EXTERNAL` disables compression

Compressible rows get larger on disk by `stored_bytes x (ratio - 1)` once they convert (PlanetScale bills above 10 GB; the database is about 6.4 GB in total). Measure the exact figure first with a metadata-only query (it reads the stored datum size and the raw size from the TOAST header; it does not detoast or decompress, verified on a 1000 MiB compressible row: 1 ms, 1 shared buffer hit, no TOAST pages read):

```sql
SELECT count(*), pg_size_pretty(sum(pg_column_size(payload))) AS stored,
       pg_size_pretty(sum(octet_length(payload))) AS raw,
       round(sum(octet_length(payload))::numeric / NULLIF(sum(pg_column_size(payload)), 0), 2) AS ratio
FROM database_artifact;
```

The production figure is **unmeasured** until ops runs it (no production role here). Scenarios, growth = X x (r - 1) GB, X = stored `payload` GB, r = raw/stored ratio (3.45 is the synthetic pglz ratio of the test data; real SQLite ratios are likely lower), total 6.4 GB before:

| stored X | r = 1.5 | r = 2.5 | r = 3.45 |
|---|---|---|---|
| 0.5 GB | +0.25 GB | +0.75 GB | +1.2 GB |
| 1 GB | +0.5 GB | +1.5 GB | +2.5 GB |
| 2 GB | +1.0 GB | +3.0 GB | +4.9 GB (11.3 GB total, over 10) |
| 4 GB | +2.0 GB | +6.0 GB (12.4 GB, over 10) | +9.8 GB (16.2 GB, over 10) |

The 10 GB line is crossed when growth exceeds 3.6 GB: X = 4 GB at r = 2.5 or 3.45, and X = 2 GB at r = 3.45. All other cells stay under it.

SQLite deployments need nothing, but note that SQLite's `substr` on a BLOB materialises the whole blob inside the SQLite library for every slice (about one blob of transient memory, ~0.3 s per slice per 256 MiB), so the "one slice" memory bound holds for the node's own heap and for Postgres, not for SQLite's internal buffer.

## Adapting for at-rest encoding (TC-887)

`ArtifactMeta` would gain the encoding columns; chunking applies to the **stored** bytes, so decoding belongs in the `ArtifactSink` (or a decoding wrapper) and the verified hashes are the stored-bytes hashes. `load_meta` / `read_chunks` documentation says the same.
