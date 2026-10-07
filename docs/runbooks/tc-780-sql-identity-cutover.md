# TC-780 SQL/DuckDB identity cutover

This runbook migrates the pre-N2 physical database names without renaming
artifacts or touching their checkpoint and WAL columns. Use the N3
`tinycloud-sql-identity` binary built from the reviewed N1+N2+N3 stack. The
production snapshot dry-run and actual cutover are deploy-gate operations;
they are not part of the N3 implementation branch.

## 1. Prevent an unfenced deploy

Do **not** merge the N1+N2+N3 stack into `main`, create a `v*` tag, or run a
manual `docker.yml` deployment until steps 2–6 are complete. `release-plz.yml`
tags version bumps on every push to `main`; a `v*` tag triggers `docker.yml`,
whose `deploy-phala` job previously deployed automatically. The N3 workflow
now requires the repository variable for image publishing, including the
`latest` image used by self-hosters:
`TC780_CUTOVER_READY=true`; Phala deployment additionally requires
`workflow_dispatch` with `deploy_phala=true`. Keep that variable unset until
step 7. Hold the stack merge until production is prepared, and tell
self-hosters to pin their current image digest until they have run this
cutover on their own volume; `docker-compose.dstack.yaml` otherwise pulls
`latest`.

Build the reviewed N3 binary from the branch before the maintenance window.
For a self-hoster, use the matching binary for the server architecture and
run all commands below against their mounted data volume.

## 2. Fence

The old binary has no N3 fence. Configure the ingress or load balancer to
return 503 for `/invoke` and the share-email SQL read surface, stop new
connections, and verify SQL and DuckDB requests receive 503. Keep the ingress
fence until step 9. Configure the replacement node with
`[database] write_fence = true` (or `TINYCLOUD_DATABASE__WRITE_FENCE=true`)
before starting it. This flag rejects all SQL and DuckDB `/invoke` requests,
including reads, and the share-email SQL store. Keep unrelated KV service
available if the ingress can route it separately.

## 3. Drain and checkpoint

Wait for outstanding SQL/DuckDB requests to finish, then stop the old node.
The durable `database_artifact` rows are saved on every write. With the node
stopped, run `sqlite3 /path/to/data/caps.db 'PRAGMA wal_checkpoint(TRUNCATE);'`
for a SQLite metadata DB. Checkpoint all local caches with the N3 CLI built
with DuckDB support (required when DuckDB files exist):

```sh
cargo run --locked -p tinycloud-node --features duckdb \
  --bin tinycloud-sql-identity -- --datadir /path/to/data \
  checkpoint --fence-confirmed
```

The command runs SQLite `wal_checkpoint(TRUNCATE)` and DuckDB `CHECKPOINT`
on each cache file while it has exclusive access.
If an artifact uses PostgreSQL/MySQL metadata, use that database's native
backup procedure; cache checkpointing remains the same. Do not proceed while
any writer or open actor remains.

## 4. Back up

Take a transactionally consistent metadata DB backup, including
`database_artifact`, `invoked_abilities`, `ability`, and any alias or
quarantine tables already present. For SQLite, use
`sqlite3 /path/to/data/caps.db ".backup '/path/to/backup/caps.db'"`.
Copy the entire `sql/` and `duckdb/` cache
directories with their `-wal`, `-shm`, and `.wal` files. Record checksums and
keep the copy read-only. Do not rename or move source artifacts.

## 5. Inventory and dry-run

On a **copied** data directory, first restore the metadata backup into
`<copy>/caps.db`, then copy `sql/` and `duckdb/` under `<copy>/`. Run:

```sh
cargo run --locked -p tinycloud-node --bin tinycloud-sql-identity -- \
  --datadir /path/to/copy dry-run > inventory.json
```

For a non-SQLite metadata store, pass `--database <snapshot-url>` so no live
database is read. Inspect every `(service, space, physical_name)` row.
`unique` means exactly one historical path was found in stored delegation or
invocation history. `ambiguous` means several paths shared a physical name;
`unattributed` means no history. A cache-only entry (`durable=false`) must be
recovered into the durable artifact table before aliasing. Resolve every
`collision=true` against the existing digest artifact before proceeding;
the transaction refuses a collision. Compare table lists, schema hashes, and
row counts for web paths with the backup.

## 6. Alias transaction

Against the stopped, fenced **live** data directory, run:

```sh
cargo run --locked -p tinycloud-node --bin tinycloud-sql-identity -- \
  --datadir /path/to/data apply --fence-confirmed
cargo run --locked -p tinycloud-node --bin tinycloud-sql-identity -- \
  --datadir /path/to/data report > aliases.json
```

`apply` quarantines all discovered legacy artifacts, including cache-only
files, and inserts aliases for uniquely attributed paths in one transaction. Ambiguous and
unattributed artifacts remain inaccessible. For an owner/admin approved
resolution, use `set` (also available as `resolve`):
`set <sql|duckdb> <space> <physical> --path <logical-path>
--authorized --fence-confirmed` (or `--pathless`); the CLI checks the physical
row, quarantine record, logical path, exact legacy selector, existing aliases,
and digest collision.
It maps a physical artifact to only one identity. Keep the written approval
and reason with the report. `clear <service> <space> --path <logical-path>
--fence-confirmed` removes an alias while leaving its artifact quarantined.

## 7. Deploy the N3 binary while fenced

Only after step 6 succeeds, merge the reviewed stack. Keep the ingress fence
and `write_fence=true`. Set `TC780_CUTOVER_READY=true` in the repository
variables, then run `docker.yml` manually with `deploy_phala=true` for the
reviewed `vX.Y.Z` tag as the `workflow_dispatch` ref. Set
`include_duckdb=true` if any DuckDB artifacts are present. Do not use the
automatic `v*` tag event for this cutover.
Self-hosters should pin the new version and start it with the same fence flag
before allowing traffic. Do not lift either fence if the alias report is
missing or incomplete.

## 8. Restart verification

Restart the N3 node while fenced. Check that the aliases persist in `report`.
Temporarily allow only the owner verification client through the ingress and
disable the node fence for that isolated check, then read every aliased web
database through the real `/invoke` path at its original full logical path.
Compare table lists, schema hashes, and row counts with the pre-cutover
report. Confirm short legacy paths and unresolved names return a rejection,
and a fresh SQL/DuckDB write receives 503 after restoring the node fence.
Return to full ingress isolation before any further change.

## 9. Unfence

Set `write_fence=false`, restart, remove the ingress 503 rule, and monitor
SQL/DuckDB errors and new digest artifacts. Keep the backup until the
post-cutover verification window ends.

## Rollback

Re-enable the ingress fence and `write_fence=true` before changing anything.
Stop the N3 node and take another backup. Use `clear` for applied aliases, or
restore the pre-cutover metadata backup and cache copy as one unit, then
redeploy the pre-N2 production binary while ingress remains fenced. Verify old paths and
only then remove the ingress fence. Once new-identity writes exist, an old
binary cannot read or merge those digest artifacts; reverting would discard
or strand those writes. Reconcile them explicitly before attempting rollback.
