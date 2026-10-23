# SQL local durability and reservation before commit (TC-1491, slice 1a)

Postgres stays the master copy of every SQL database. This slice makes the node's
**local** commit durable and refuses, before COMMIT, a write that would not fit.
It adds no migration, no schema change and no new storage.

## What a request does

A write request runs in one transaction (an outermost `SAVEPOINT`, so every
write request, whether a single statement, a `Batch` or an `Execute` with `schema` statements, is all-or-nothing):

1. **Limits.** `PRAGMA max_page_count = min(per-database cap, current pages + owner budget / page size)`. SQLite enforces it itself, mid-statement, so the bound is exact. Not applied to the `Forbid` path (budget 0), which keeps its own guard.
2. The statements run.
3. **Pre-commit gate** (`precommit_gate` in `sql/database.rs`).
   - Owner budget and cap are re-checked against the page growth of the open transaction.
   - Disk: reserve `unspilled WAL bound + pending checkpoint growth` in the node-wide `DiskBudget`, where pending checkpoint growth is the growth of the main file that the next checkpoint will cause (all pages committed since the last checkpoint). A request that wrote nothing reserves nothing. The reservation succeeds only if `free bytes - other in-flight reservations - this reservation >= min_free_bytes`.
4. `COMMIT` (`RELEASE` of the outermost savepoint). With `synchronous = FULL` the WAL is fsynced before it returns.
5. The reservation shrinks to the checkpoint growth (the WAL bytes are on disk now). The in-flight part ends at COMMIT and is released by `SqlService` when the request's outcome is known; the checkpoint growth stays held until a checkpoint runs or the connection closes.

Any error before COMMIT is a `ROLLBACK` of the whole transaction. Nothing is committed and then reported as failed.

### Why the disk bound is sound for index, trigger and foreign-key amplification

At COMMIT SQLite appends one WAL frame (`page size + 24` bytes) per dirty page that has not already spilled to the WAL. Dirty pages are a subset of the connection's page cache, so `SQLITE_DBSTATUS_CACHE_USED` (heap bytes of the cache) bounds them, whatever the SQL text or payload was: index entries, the pages of every b-tree touched, freelist, overflow and trigger-written pages are all just pages. A page dirtied twice in a transaction still costs one frame. WAL bytes that already spilled are on disk and already out of the free space the gate reads. The main file grows at the next checkpoint by the transaction's page growth, which is why that term is reserved and held until a checkpoint runs.

`the_unspilled_wal_bound_covers_what_commit_appends` checks the bound against real commits (1 to 100 000 rows, six indexes, plus an update of half the rows).

What is **not** exact: `free bytes` is a `statvfs` snapshot, so another process on the same filesystem can still take the space after the check (the `min_free_bytes` floor is the margin for that). The reservation covers this process's concurrent databases only. The progress handler that stops a statement early only watches free space, not the cache.

If free space cannot be read the write is refused (`Internal`), never allowed.

## fsync policy

- `PRAGMA synchronous` is set on every file-backed connection: `FULL` by default, in `open_connection` and, before the copy, in `promote_to_file`. With WAL, `FULL` fsyncs the WAL on every COMMIT. `NORMAL` (the rollback flag) fsyncs only at checkpoints.
- SQLite itself fsyncs the directory when it first creates a `-wal` file (the unix VFS `UNIXFILE_DIRSYNC` flag on a new WAL), but not for the main database file. So the node fsyncs: the directories it creates for a database (`create_dir_all_durable`), the directory after `promote_to_file` creates the database file, and the directory after the renames in `CacheFileSink::commit` (the parts are already `sync_all`'d before the rename).
- Deleting stale cache files before a hydration is not directory-synced: Postgres is master and the cache is re-creatable.
- `FULL` is necessary, not sufficient. It does not prove the CVM volume honours flushes.
- Databases below `memory_threshold` (10 MiB) are in-memory SQLite: there is no local file to fsync, and their durability is the Postgres save, as before. Store-master (1b) needs them file-backed.

## Outcomes in this phase

| | meaning |
|---|---|
| **Rejected** | Rolled back before COMMIT: no effect on the local file, Postgres or any later snapshot. Reservation refusals (`sql_database_size_limit`, `sql_disk_headroom`, owner budget `402`), `SQLITE_FULL`, any statement error (the whole request), and a COMMIT that returns an error. |
| **Committed** | The local COMMIT returned and, for a file-backed database with `FULL`, its WAL fsync did; and the Postgres save succeeded. Only then is success returned. |
| **Unknown** | Unchanged TC-1274 `outcome_unknown`: the Postgres save was sent and its outcome is not known. |

Unchanged on purpose: a failed Postgres save discards the local state. A local commit that was never released (the process died after COMMIT, before the response) is dropped when the service next re-hydrates from Postgres, which is correct while Postgres is master.

**COMMIT error.** If COMMIT's fsync fails after the WAL frames were written, SQLite reports the error and the request is reported as rejected, but the commit can still appear when the file is next opened. That is harmless here: the node discards the local state (`CommitFailed`) and re-hydrates from Postgres, which never saw the write. Under store-master (1b and later) it is an outcome-unknown case: keep the local WAL and answer `outcome_unknown`.

A kill -9 test cannot inject "after COMMIT, before its fsync completed"; `before_commit`, `after_commit` and `before_response` seams cover the cuts that exist. SIGKILL does not drop the page cache, so the tests prove the commit protocol, not power loss.

## Settings

`[global.storage.sql]`; env `TINYCLOUD_STORAGE__SQL__<NAME>` (the legacy single-underscore form works for names without an underscore).

| key | default | meaning |
|---|---|---|
| `synchronous` | `"full"` | `"full"` or `"normal"`; the rollback flag. This is the durability fix, not a limit. |
| `max_database_bytes` | `0` (no cap) | per-database size cap, enforced by SQLite's `max_page_count` |
| `min_free_bytes` | `0` (check off) | disk kept free after all in-flight reservations; `0` disables the gate, the reservation and the free-space checks before COMMIT (a full-disk error still reads free space once, see Errors) |

**The two limits are off by default.** They are Sam's decision (card `sql-storage-report-read`) and are set by config once he answers; an unmeasured cap could refuse real users' databases. The mechanism is fully tested with explicit values. What stays on by default besides `synchronous`: the transaction per write request and the owner-budget limit below.

**Owner budget is not switchable and can refuse a write today's code allows.** `max_page_count` is set from the owner's remaining quota (`limit - used`, the same `storage_check` read as before). Today a write that overshoots a non-zero remainder is allowed once and only the next one is refused with 402; now the overshooting write itself is refused with 402 before COMMIT. The comparison is the database's page growth against the remainder, the unit the quota already charges (logical database size); growth that frees pages elsewhere in the file is not counted, so it is never stricter than the charge.

## Errors

| error | HTTP | body prefix |
|---|---|---|
| per-database size cap | 507 | `sql_database_size_limit:` |
| disk headroom | 507 | `sql_disk_headroom:` |
| owner budget (existing `StorageWouldGrow`) | 402 | the TC-619 quota body |
| local COMMIT failed | 500 | `sql_commit_failed:` |

507, not 413: the SQL client maps 413 to `SQL_RESPONSE_TOO_LARGE`, the KV and quota clients read it as an exhausted storage plan, and TC-1012's 413 is the request body cap.

A write that fails because the disk is full is answered as `sql_disk_headroom` (507) in every configuration. When SQLite reports the database full, the node reads the free space once; if it is below a fixed floor of 16 database pages, the disk is the cause, whatever `min_free_bytes` is set to. Otherwise the owner budget (402) or the per-database cap (`sql_database_size_limit`, 507) is the cause.

## Scope notes

**What counts as a write.** `Execute`, `Batch` and `ExecuteStatement` are always wrapped (a read inside a batch is wrapped too; only telemetry notices). A single `Query` is wrapped, gated and reserved when `parser::classify_sql` says it is not read-only. That classification covers writes nested in a query tree (TC-1585): a `WITH … INSERT` or `WITH … UPDATE` is a write, so it gets the transaction, the owner budget, the size cap and the pre-commit gate like any other write. The answer does not depend on the caller's abilities; a read-tier grant is only a shortcut (its writes are refused anyway). The route uses the same classifier (`sql_request_is_write`) to decide whether to read the owner's budget, and calls the `*_authorized` service entry points (`execute_with_budget_authorized`, `execute_without_growth_authorized`, `execute_authorized`), so the budget path carries the per-statement authority of TC-1581. `needs_transaction` is the one place this is decided for a request.

**PRAGMA.** A request that carries a `PRAGMA` (admin only) runs in the same transaction as any other write request, and is limited, gated and reserved like one. The actor's connection reset after a request that held a non-report `PRAGMA` (TC-1586) runs after the request, after the transaction has ended. `PRAGMA synchronous` is not on the admin allow-list, so it cannot be read or set through a request.

**Retire order.** When that reset fails, the actor is retired (deregistered before the error reply, TC-1594 tracks closing the connection first). The pre-commit gate and the reservation release are on the same path as before: the reservation is released by a drop guard in `SqlService::execute_locked` when the request returns, whatever the actor did, so the retire order does not change it. A request that triggers the reset held a `PRAGMA`; its transaction and its reservation have ended before the reset runs. The actor also retires when a connection is still inside a transaction after a request.

`Publication` commands are not gated either. DuckDB is untouched.
