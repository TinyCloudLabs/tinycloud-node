# Incremental SQL and DuckDB artifact durability

TinyCloud stores file-backed SQL and DuckDB databases as a durable checkpoint
plus the database engine's current write-ahead log (WAL).

## Acknowledgement contract

- A mutation is not acknowledged until either its WAL or a replacement
  checkpoint commits to `storage.database`.
- WAL capture runs through the per-database actor, so it cannot race an engine
  write and produce a torn sidecar.
- If durable persistence fails, the response fails and the local actor/cache is
  discarded. The last acknowledged checkpoint+WAL remains recoverable.
- On cold start, TinyCloud writes the checkpoint and WAL to a fresh cache before
  opening the engine. SQLite and DuckDB perform their normal deterministic WAL
  recovery.

## Checkpoint policy

File-backed mutations replace only the WAL blob while it is below 8 MiB.
At 8 MiB, TinyCloud checkpoints the engine, stores the new content-addressed
database image, and clears the WAL atomically in the artifact row. In-memory
databases continue to checkpoint because they have no durable WAL sidecar.

SQLite automatic checkpoints are disabled. DuckDB's automatic checkpoint
threshold is raised above the TinyCloud threshold. This prevents either engine
from advancing the local checkpoint without advancing the durable checkpoint.

Explicit DuckDB exports checkpoint the engine and durably install that
checkpoint before returning. SQLite exports use a non-destructive backup, so
they do not disturb the WAL baseline.

## Observability

Every persistence operation emits structured fields:

- `service`: `sql` or `duckdb`
- `mode`: `wal` or `checkpoint`
- `bytes`: bytes transferred for this persistence operation
- `logical_bytes`: checkpoint plus WAL bytes used for quota accounting
- `revision`: durable artifact revision

The existing `server.sql.execute` and `server.duckdb.execute` span histograms
measure end-to-end mutation latency. Together, these provide the before/after
latency and transfer-byte comparison without a benchmark-only endpoint.
