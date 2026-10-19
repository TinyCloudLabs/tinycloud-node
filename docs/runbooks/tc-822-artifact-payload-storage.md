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

SQLite deployments need nothing, but note that SQLite's `substr` on a BLOB materialises the whole blob inside the SQLite library for every slice (about one blob of transient memory, ~0.3 s per slice per 256 MiB), so the "one slice" memory bound holds for the node's own heap and for Postgres, not for SQLite's internal buffer.

## Adapting for at-rest encoding (TC-887)

`ArtifactMeta` would gain the encoding columns; chunking applies to the **stored** bytes, so decoding belongs in the `ArtifactSink` (or a decoding wrapper) and the verified hashes are the stored-bytes hashes. `load_meta` / `read_chunks` documentation says the same.
