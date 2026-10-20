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
| `"off"` | The earlier behaviour: `write` also suffices. |

The warning is not mapped in the log shipper (`log-shipper/diagnostics.json`), so it ships as an unclassified `node_warning` until it is.

## Clients

The SDK has requested `tinycloud.sql/schema` for DDL since js-sdk 2.5.0 and sends `[write, schema]` for requests that mix both. A client or manifest that runs DDL under `sql/write` only needs `tinycloud.sql/schema` added to its grant.

## Connection state and SQLite's schema tables (TC-1586)

A database's SQLite connection is shared by every request on it. After a request that held a `PRAGMA` (admin only), the node returns the connection to the state it was opened in: `writable_schema`, `query_only`, `foreign_keys`, `ignore_check_constraints`, `recursive_triggers`, `case_sensitive_like`, and WAL mode for a file-backed database.

The SQLite authorizer also refuses a data statement that writes `sqlite_master`, `sqlite_schema` or their temp counterparts. Only a schema change (which writes them internally), a pure query (a `pragma_*` table-valued function reads the schema through them) and `admin` may.
