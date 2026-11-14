# Opt-in database artifact parts

Opt-in SQL and DuckDB persistence stores checkpoints and cumulative WAL as immutable PostgreSQL parts.
Each payload statement carries at most 1 MiB. A metadata-only compare-and-swap
publishes a sealed part; successful writes retain the existing durability and
lineage semantics. Hydration verifies the part CID before publishing its cache.

A database stored in parts is not held to the single-row read limit
(`storage.sql.max_artifact_read_bytes`, TC-2961): each statement reads at most
1 MiB, hydration stages the parts in files beside the cache, and the artifact
and account capacities bound its size. A read that keeps the whole database in
memory (a DuckDB export) still waits for one of the node's large-transfer slots
when it exceeds 8 MiB.

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

After a checkpoint, file-backed SQL mutations can publish an owned cumulative WAL
smaller than 8 MiB without rewriting the checkpoint. Larger WALs and writes
forbidden from growing use a fresh checkpoint. In-memory databases use
checkpoints. Both kinds of part use the same 1 MiB statement limit, and the
artifact ceiling covers checkpoint plus WAL together. Conversion of existing
artifacts follows separately.
Aborted and superseded parts enter a fenced deleting state; reclamation deletes
at most one payload chunk per statement and releases its charge only after all
bytes are gone. A periodic collector recovers uploads whose 120-second lease
expired. Lease expiry determines eligibility; part identity and state fence
uploads against concurrent reclamation. Active sealed uploads retain their lease
until publication. Deleted artifacts are reclaimed by the same mechanism.
DuckDB uses owned checkpoint and WAL files under the same capacities. Its
imports stream the already-buffered public request into bounded artifact
statements. Legacy data remains readable. Drain
older writers before enabling this format; turning the switch off does not
convert published parts back to legacy blobs. Current readers understand both
layouts; legacy persistence refuses a database already using parts.

Do not enable for prolonged operation until the approved ceiling load acceptance and
remaining conversion slice is complete. On each test release, report
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
do not fail the save. A writer first prioritizes its own database's eligible
predecessors for at most two seconds; active upload leases are never stolen.
Failed owners are excluded for the remainder of a collection pass so other
owners can continue. Owner-lock waits at reservation are bounded at 50 ms. Background passes are limited to 128 steps and one second
per 10-second tick. GC lock acquisition waits at most 50 ms per statement.
An owner already above its quota can replace a database with an equal or
smaller image; that exception admits no growth and does not free pending shrink
capacity for other databases.

A WAL publication checks the exact durable revision and checkpoint CID. It
replaces only the WAL pointer and logical CID, advancing the layout generation;
the checkpoint pointer and bytes remain unchanged. Readers verify each part CID
and the combined logical CID, then recheck both pointers and the generation
before publishing the cache. A full checkpoint retires both previous parts.
Each retired part releases its charge and associated overlap credit only after
its final chunk is removed, so a partially collected pair stays accounted.

Roll out WAL-capable readers to every instance before enabling the switch.
Checkpoint-only part readers fail closed on WAL layouts. Schema changes are
forward-only; switching the feature off keeps existing layouts readable and
writable by the current binary, and does not downgrade their format.

New DuckDB databases with parts enabled start file-backed under the existing
node data directory, regardless of the in-memory threshold. Their actor fence
protects checkpoint/WAL copies. Closing or idle-evicting an actor removes its
cache files after the native connection is closed; the next access rehydrates
from durable parts. The files are renamed aside while the actor's registration
is held and deleted after it is released, so other databases' lookups do not
wait on the deletion; if the process stops in between, the next hydration of
that database removes them. A spill directory left by a stopped process does
not block hydration, and an import that fails leaves no staged or imported
file. Legacy actors retain their existing storage behavior.

For disk headroom, each successfully persisted open database retains at most
the configured artifact ceiling in checkpoint plus cumulative WAL. A full
checkpoint also needs an owned temporary copy while streaming, and old/new
versions overlap in PostgreSQL until their deletions commit. PostgreSQL can reuse deleted storage after vacuum; relation files need not
shrink. Size refusal occurs after native execution.

DuckDB keeps disk headroom on the filesystem behind its cache. With parts
enabled, `storage.duckdb.min_free_bytes` defaults to 2 GiB and
`storage.duckdb.max_temp_directory_size` to 1 GiB per connection; with parts
off both stay off unless set. The 2 GiB floor is provisional until the
`storage_headroom` event shows real headroom on production nodes; operators tune
it by config. With parts enabled, the node refuses to start unless the floor is
at least `storage.sql.chunked_artifact_max_bytes`: a write's save copies the
database once more, outside the write's reservation. Leave a margin above that.

- A write is any request that can change the database: executes, batches,
  imports, and a query whose SQL is not read-only (the parser decides, as for
  authorization).
- Before a write runs, it reserves its local database files' size (the bound
  of the snapshot copy its save can take); an import reserves twice its size.
  Reservations share the node-wide budget with SQL. A reservation that would
  leave less than the floor is refused with `507 duckdb_disk_headroom` and
  nothing runs.
- While a write runs, it is interrupted whenever free space is below what
  other operations hold plus the floor. It answers `507 duckdb_disk_headroom`,
  and the database's local copy is dropped and reloaded from its last saved
  artifact on the next request. So nothing from the request is kept: not a
  transaction that committed just before the interrupt was reported, and not
  the earlier statements of a non-transactional batch.
- A statement that spills past the per-connection limit also answers
  `507 duckdb_disk_headroom`. Read-only queries and exports reserve nothing and
  are not interrupted for headroom; only the spill limit applies to them.
- Hydration is not gated: it writes at most the artifact ceiling and is freed
  at eviction.
- At startup, before it serves, the node removes what a stopped process left in
  the DuckDB cache: spill directories and staging or renamed-aside files. The
  cache files themselves stay, because a legacy database reopens them.

Artifact, account and single-statement capacity refusals return 507. Existing
per-space growth refusals retain 402. A concurrent replacement or contended
reservation returns a retryable 503 without checkpoint back-off; staged
bookkeeping does not turn this positive pre-publication refusal into an
unknown write outcome. A genuinely lost publish reply retains its existing
unknown-outcome behavior. Expired uploads remain counted until collection.

An old-format checkpoint can be replaced by a full owned snapshot before WAL
parts attach. For DuckDB, both legacy and owned-WAL persistence first compare
the local main file's length and CID with the stored checkpoint under the
actor fence. A mismatch requires a complete checkpoint, including blocks
written directly to the main file by a large insert.

The feature remains off. Conversion and the ceiling-load benchmark still need
their separate acceptance before activation.
