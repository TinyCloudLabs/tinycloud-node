# SQL schema authority (TC-1581)

`tinycloud.sql/write` covers data statements. Statements that change the schema need `tinycloud.sql/schema`.

| Statement | Needs |
|---|---|
| `SELECT` | `read`, `write`, `admin` or `*` |
| `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, and `WITH … INSERT/UPDATE` | `write`, `admin` or `*` |
| `CREATE`/`ALTER`/`DROP` of tables, views and indexes (including `CREATE TABLE … AS SELECT` and temp objects) | `schema`, `admin` or `*` |
| `PRAGMA` | `admin` or `*` (unchanged) |
| `ATTACH`, `DETACH`, `VACUUM`, `ANALYZE`, `REINDEX`, `CREATE VIRTUAL TABLE`, `CREATE TRIGGER`, transaction control | never |

`admin` implies `schema` in the capability registry (`capabilities.json`); `*` implies every SQL ability. `write` does not imply `schema`, and `schema` does not imply `write` or `read`: a holder of `schema` alone can run schema statements only.

## How a request is judged

An invocation can carry several SQL abilities. The node judges each statement against all of them, so a request that holds both `write` and `schema` can run data and schema statements together. That is what the SDK sends for `execute({ schema: [...] })` and for `migrations.apply`. A request that mixes the two statement kinds and holds only one of the abilities is refused.

This applies to every request path that runs SQL: `query`, `execute`, each entry of the `schema` list of `execute`, `batch`, and named statements (`executeStatement`). A named statement that holds DDL needs `schema` on the invocation like the same SQL sent directly.

The SQLite authorizer enforces the same rule on the engine's own callbacks, so a statement the parser misclassifies is still refused.

## Configuration

`[global.storage.sql] ddl_requires_schema` in `tinycloud.toml` (env `TINYCLOUD_STORAGE__SQL__DDL_REQUIRES_SCHEMA`; a new CVM env name needs `allowed_envs`):

| Value | Behaviour |
|---|---|
| `"enforce"` (default) | A schema statement without a schema-conferring ability is refused with `403`. |
| `"log"` | The statement runs as before. Each such statement increments `tinycloud_ddl_without_schema_total{service="sql",kind=…}` and the request logs one constant warning (`sql ddl allowed without schema ability (ddl_requires_schema = log)`). Neither carries SQL text, space ids, DIDs or table names. `kind` is one of `create_table`, `create_view`, `create_index`, `alter_table`, `drop`. |
| `"off"` | The earlier rule: `write` also suffices for the schema statements `log` counts. The other changes in this document (the `CREATE TRIGGER` refusal, nested block comments, CTE write classification, schema-table and PRAGMA restrictions) apply in every mode. |

`log` counts only statements the parser classifies as schema-changing. A statement the parser does not recognise as such is still refused by the SQLite authorizer unless the policy allows it, and is not counted.

A request that carries both `schema` entries and `sql` is not transactional. The `schema` entries run first and can stay applied if a later statement is refused (only the storage-quota guard rolls a refused request back).

A statement that nests block comments (`/* … /* … */ … */`) is refused for every ability: SQLite ends a comment at the first `*/`, the SQL parser nests them, and the two would read different statements.

The warning is not mapped in the log shipper (`log-shipper/diagnostics.json`), so it ships as an unclassified `node_warning` until it is.

## Clients

The SDK has requested `tinycloud.sql/schema` for DDL since js-sdk 2.5.0 and sends `[write, schema]` for requests that mix both. A client or manifest that runs DDL under `sql/write` only needs `tinycloud.sql/schema` added to its grant.

## Connection state and SQLite's schema tables (TC-1586)

A database's SQLite connection is shared by every request on it, so connection-level state must not outlive the request that set it.

- The SQLite authorizer allows anyone only the plain schema reports (`table_info`, `table_list`, `table_xinfo`, `database_list`, `index_list`, `index_info`, `foreign_key_list`).
- An `admin` (or `*`) holder may also set and read `user_version` and `application_id` (database header values), run the check pragmas `integrity_check`, `quick_check` and `foreign_key_check`, and read (not set) `schema_version`, `page_count`, `page_size`, `freelist_count`, `data_version`, `encoding`, `journal_mode`, `foreign_keys`, `writable_schema`, `query_only`, `collation_list`, `compile_options` and `pragma_list`.
- Every other PRAGMA is refused for everyone, including all forms that set connection-level or process-wide settings and maintenance forms such as `wal_checkpoint`, `optimize` and `incremental_vacuum`.
- After any request in which the authorizer allowed a PRAGMA outside the plain schema reports, the node resets the connection to the state it was opened in, for an in-memory database (journal mode `memory`) and a file-backed one (WAL). If the reset fails, the database's actor is retired and the next request rebuilds it from the durable copy.

The SQLite authorizer also refuses a data statement that writes `sqlite_master`, `sqlite_schema` or their temp counterparts. Only a schema change (which writes them internally), a pure query (a `pragma_*` table-valued function reads the schema through them) and `admin` may.
