# Incremental SQL and DuckDB artifact durability

TinyCloud stores file-backed SQL and DuckDB databases as a durable checkpoint
plus the database engine's current write-ahead log (WAL).

## Database identity (TC-780 N2)

SQL and DuckDB select databases by the complete resource path within a space.
The path is encoded injectively into a file-safe physical name, preserving
empty segments, trailing slashes, case, and percent escapes. A pathless resource
has its own identity, distinct from an explicitly empty path and from a path
named `default`. The old final-segment selectors remain available only for the
explicit N3 legacy-artifact migration; N2 performs no migration or fallback.
DuckDB paths ending in an empty or formerly invalid final segment now get their
own encoded identities instead of opening the old `default` artifact.
At the N3 cutover, the resolver must reserve every preexisting physical name:
only an explicit `(service, space, logical identity)` alias may reach a legacy
artifact, even if its physical name happens to equal a newly encoded identity.
Unresolved legacy artifacts remain inaccessible.

SQL and DuckDB grants without a trailing slash match one exact path. Grants
ending in `/`, and pathless grants, still cover a namespace. KV matching is
unchanged. The share-email named SQL adapter keys by its authorized `path`,
using the same identity as `/invoke`; its separately pinned `database` field
does not select a physical artifact.

SQL and DuckDB hook event paths now use the **full logical database path**
followed by the table name (`appA/connectors/items`), not the former final
segment (`connectors/items`) or the encoded artifact name. A pathless database
uses `default/<table>`. Subscribers filtering on old paths need to update their
path prefixes.

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
