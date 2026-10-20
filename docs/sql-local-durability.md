# SQL local durability and reservation before commit (TC-1491, slice 1a)

Postgres stays the master copy of every SQL database. This slice makes the node's
**local** commit durable and refuses, before COMMIT, a write that would not fit.
It adds no migration, no schema change and no new storage.

## What a request does

A write request runs in one transaction (an outermost `SAVEPOINT`, so a
`Batch` or an `Execute` with `schema` statements is all-or-nothing):

1. **Limits.** `PRAGMA max_page_count = min(per-database cap, current pages + owner budget / page size)`. SQLite enforces it itself, mid-statement, so the bound is exact. Not applied to the `Forbid` path (budget 0), which keeps its own guard.
2. The statements run.
3. **Pre-commit gate** (`precommit_gate` in `sql/database.rs`).
   - Owner budget and cap are re-checked against the page growth of the open transaction.
   - Disk: reserve `unspilled WAL bound + page growth * page size` in the node-wide `DiskBudget`. The reservation succeeds only if `free bytes - other in-flight reservations - this reservation >= min_free_bytes`.
4. `COMMIT` (`RELEASE` of the outermost savepoint). With `synchronous = FULL` the WAL is fsynced before it returns.
5. The reservation shrinks to the checkpoint growth (the WAL bytes are on disk now) and is released by `SqlService` when the request's outcome is known: after the Postgres save, or its failure.

Any error before COMMIT is a `ROLLBACK` of the whole transaction. Nothing is committed and then reported as failed.

### Why the disk bound is sound for index, trigger and foreign-key amplification

At COMMIT SQLite appends one WAL frame (`page size + 24` bytes) per dirty page that has not already spilled to the WAL. Dirty pages are a subset of the connection's page cache, so `SQLITE_DBSTATUS_CACHE_USED` (heap bytes of the cache) bounds them, whatever the SQL text or payload was: index entries, the pages of every b-tree touched, freelist, overflow and trigger-written pages are all just pages. A page dirtied twice in a transaction still costs one frame. WAL bytes that already spilled are on disk and already out of the free space the gate reads. The main file grows at the next checkpoint by the transaction's page growth, which is why that term is reserved and held until the save is done.

`the_unspilled_wal_bound_covers_what_commit_appends` checks the bound against real commits (1 to 100 000 rows, six indexes, plus an update of half the rows).

What is **not** exact: `free bytes` is a `statvfs` snapshot, so another process on the same filesystem can still take the space after the check (the `min_free_bytes` floor is the margin for that). The reservation covers this process's concurrent databases only. The progress handler that stops a statement early only watches free space, not the cache.

If free space cannot be read the write is refused (`Internal`), never allowed.

## fsync policy

- `PRAGMA synchronous` is set on every file-backed connection: `FULL` by default, in `open_connection` and, before the copy, in `promote_to_file`. With WAL, `FULL` fsyncs the WAL on every COMMIT. `NORMAL` (the rollback flag) fsyncs only at checkpoints.
- SQLite itself fsyncs the directory when it first creates a `-wal` file (the unix VFS `UNIXFILE_DIRSYNC` flag on a new WAL), but not for the main database file. So the node fsyncs: the directories it creates for a database (`create_dir_all_durable`), the directory after `promote_to_file` creates the database file, and the directory after the renames in `CacheFileSink::commit` (the parts are already `sync_all`'d before the rename).
- Deleting stale cache files before a hydration is not directory-synced: Postgres is master and the cache is re-creatable.
- Databases below `memory_threshold` (10 MiB) are in-memory SQLite; their durable copy is the Postgres save, as before.

## Outcomes in this phase

| | meaning |
|---|---|
| **Rejected** | Rolled back before COMMIT: no effect on the local file, Postgres or any later snapshot. Reservation refusals (`sql_database_size_limit`, `sql_disk_headroom`, owner budget `402`), `SQLITE_FULL`, any statement error (the whole request), and a COMMIT that returns an error. |
| **Committed** | The local COMMIT returned and, for a file-backed database with `FULL`, its WAL fsync did; and the Postgres save succeeded. Only then is success returned. |
| **Unknown** | Unchanged TC-1274 `outcome_unknown`: the Postgres save was sent and its outcome is not known. |

A failed Postgres save discards the local state, and a local commit that was not released is dropped when the service next re-hydrates from Postgres.

**COMMIT error.** If COMMIT returns an error the request is reported as rejected (`sql_commit_failed`); the node discards the local state and re-hydrates from Postgres.

The kill -9 tests use `before_commit`, `after_commit` and `before_response` seams to cut the request at each step.

## Settings

`[global.storage.sql]`; env `TINYCLOUD_STORAGE__SQL__<NAME>` (the legacy single-underscore form works for names without an underscore).

| key | default | meaning |
|---|---|---|
| `synchronous` | `"full"` | `"full"` or `"normal"`; the rollback flag. This is the durability fix, not a limit. |
| `max_database_bytes` | `0` (no cap) | per-database size cap, enforced by SQLite's `max_page_count` |
| `min_free_bytes` | `0` (check off) | disk kept free after all in-flight reservations; `0` disables the gate, the reservation and the free-space reads |

**The two limits are off by default** and are set by config. The mechanism is tested with explicit values. What stays on by default besides `synchronous`: the transaction per write request and the owner-budget limit below.

**The owner budget is not switchable.** `max_page_count` is set from the owner's remaining quota (`limit - used`, the same `storage_check` read as before), so a write that would exceed the remaining quota is refused with 402 before COMMIT. The comparison is the database's page growth against the remainder, the unit the quota already charges (logical database size); growth that frees pages elsewhere in the file is not counted.

## Errors

| error | HTTP | body prefix |
|---|---|---|
| per-database size cap | 507 | `sql_database_size_limit:` |
| disk headroom | 507 | `sql_disk_headroom:` |
| owner budget (existing `StorageWouldGrow`) | 402 | the TC-619 quota body |
| local COMMIT failed | 500 | `sql_commit_failed:` |

507, not 413: the SQL client maps 413 to `SQL_RESPONSE_TOO_LARGE`, the KV and quota clients read it as an exhausted storage plan, and TC-1012's 413 is the request body cap.

## Scope notes

**What counts as a write.** `Execute`, `Batch` and `ExecuteStatement` are always wrapped (a read inside a batch is wrapped too; only telemetry notices). A single `Query` is wrapped, gated and reserved when `parser::classify_sql` says it is not read-only. That classification covers writes nested in a query tree (TC-1585): a `WITH … INSERT` or `WITH … UPDATE` is a write, so it gets the transaction, the owner budget, the size cap and the pre-commit gate like any other write. The answer does not depend on the caller's abilities; a read-tier grant is only a shortcut (its writes are refused anyway). The route uses the same classifier (`sql_request_is_write`) to decide whether to read the owner's budget, and calls the `*_authorized` service entry points (`execute_with_budget_authorized`, `execute_without_growth_authorized`, `execute_authorized`), so the budget path carries the per-statement authority of TC-1581. `needs_transaction` is the one place this is decided for a request.

**PRAGMA.** A request that carries a `PRAGMA` (admin only) is not wrapped and not gated. This also keeps the actor's connection reset after a request that held a non-report `PRAGMA` (TC-1586) outside any transaction: the reset runs after the request, after the transaction has ended. `PRAGMA synchronous` is not on the admin allow-list, so it cannot be read or set through a request.

**Retire order.** When that reset fails, the actor is retired. The pre-commit gate and the reservation release are on the same path as before: the reservation is released by a drop guard in `SqlService::execute_locked` when the request returns, whatever the actor did, so the retire order does not change it. A request that triggers the reset held a `PRAGMA`, so it was never wrapped, gated or reserved in the first place.

`Publication` commands are not gated either. DuckDB is untouched.

Details: TC-1491
