# Delegated SQL caveats

A `tinycloud.sql/*` delegation can limit the tables and columns a holder may touch, and make the grant read-only. The node applies the limit to every SQL request that cites the delegation, however many hops sit between the owner and the holder.

The feature is behind `[global.sql] delegated_caveats_enforced` (env `TINYCLOUD_SQL__DELEGATED_CAVEATS_ENFORCED`), off by default. When on, `GET /info` lists `sql-delegated-caveats-v1` in `features`. When off, the form below is refused like any other unsupported caveat (`unsupported-caveat: ...`) and `/info` does not list the feature. DuckDB: `tinycloud.duckdb/*` takes empty caveats only.

## Grammar

The caveats of one ability are a list of objects. One entry may be:

| Entry | Meaning |
|---|---|
| `{}` | no restriction |
| `{"tables": [...], "columns": [...], "readOnly": true}` | the delegated form; keys are any subset of the three |
| a constrained-statements profile (`mode` key, or nested `constrained-statements`) | the request is bound to the profile's statements |

- `tables` and `columns` are lists of 0 to 256 names, each non-empty. A name is 1 to 128 bytes, has no `.` (so no `table.column`), no control character, and no leading or trailing whitespace. There are no wildcards: a name matches only itself.
- Names compare ASCII-case-insensitively, on both sides, everywhere (admission, containment, execution). Only the ASCII letters fold: the Kelvin sign (U+212A) is a different name from `k`.
- `readOnly` is a boolean. `false` is the same as absent. An absent key is no restriction on that axis. An empty list is a restriction: `"tables": []` allows no table, and `"columns": []` allows no column (a read that names no column, such as `count(*)`, is still allowed when its table is).
- A list with a delegated entry has exactly that one entry. Entries of a list are alternatives, so a second entry, even an empty one, is refused. A list of only empty entries (`[{}]`, `[{}, {}]`) restricts nothing. An entry that has `mode` and also `tables` or `columns` is refused.
- Anything else (unknown key, wrong type, empty or over-long name, too many names) is refused at `/delegate` with `unsupported-caveat: <ability> caveat <index> <reason>`; the reason never repeats a name from the request.

## Chains

At `/delegate`, a child must be at least as narrow as the parent grant it relies on: its `tables` and `columns` are subsets of the parent's (an absent parent axis allows anything; a child that drops a restricted axis is refused), and `readOnly` may be turned on but not off. A widening hop is refused with `child-caveats-not-subset-of-parent`. A grant issued by the space owner is unconstrained.

At `/invoke`, the node computes the effective caveat from the stored delegations on the chain the invocation cites by CID, without relying on how each was admitted: `tables` and `columns` are the intersection over every hop that grants the invoked ability on the invoked resource, and `readOnly` is true if any hop sets it. A hop without the ability contributes nothing. A hop wider than its parent, for example one stored without the per-hop check, can only be narrowed by the intersection. If a matching hop's caveat cannot be read, the request is refused with 403 `sql_caveat_violation: chain`. The invocation's own `sqlCaveats` fact can narrow the result further and never widen it (`readOnly: false` does not lift a `readOnly` chain). A request that carries only an invocation fact, with no delegated form on its chain, is judged by the same rules: names fold, and `count(*)` is allowed under `columns`. Invocations carry no delegations of their own; a cited CID with no stored delegation is refused.

## Refusals

A request the effective caveat does not allow fails with 403 and the text `sql_caveat_violation: write`, `sql_caveat_violation: table` or `sql_caveat_violation: column`. The text names the arm and nothing else: no SQL, table or column name. When several arms apply, `write` wins over `table` over `column`. The abilities are checked first: a `read` grant that writes is refused by the ability check. A request with several statements is refused whole: nothing it did is kept. A named statement (`executeStatement`) is judged like any other statement.

## Additional refusals

Four kinds of refusal are not decided by one statement's table, column or write. All are 403.

| Request | Limit | Text |
|---|---|---|
| `{"action":"query","sql":"PRAGMA table_info(<table>)"}` (any PRAGMA schema report: `table_info`, `table_xinfo`, `table_list`, `database_list`, `index_list`, `index_info`, `foreign_key_list`; admin ability), and `SELECT ... FROM pragma_table_info('<table>')` even when the function is listed | `tables` or `columns` | `sql_caveat_violation: table` |
| `{"action":"query","sql":"PRAGMA integrity_check"}`, `quick_check`, `foreign_key_check` (with or without a table argument; admin ability) | `tables` or `columns` | `sql_caveat_violation: table` |
| `{"action":"query","sql":"PRAGMA user_version = <n>"}`, `application_id = <n>` (admin ability) | `tables` or `columns` (and `readOnly`) | `sql_caveat_violation: write` |
| `{"action":"export"}` | `tables` | `sql_caveat_violation: table` |
| `{"action":"export"}` | `columns` without `tables` | `sql_caveat_violation: column` |
| any request whose chain has an unreadable caveat on a hop that grants the invoked ability, or mixes a constrained-statements profile with the delegated form | any | `sql_caveat_violation: chain` |

Under `readOnly` alone, the PRAGMA schema reports, the checks and the export are allowed; a PRAGMA that sets a value is a write.

## What each limit does

- **`readOnly`** refuses every write and schema statement, a `PRAGMA` that sets a value (`PRAGMA user_version = 5`), and any statement the parser does not classify as read-only. Such a statement is refused at its first callback, whatever the action.
- **`tables`** lists every table a statement reads, writes or changes, including the tables reached through a view, a trigger or a foreign key. Writing to a table with a trigger or a foreign key needs the tables they touch listed too. Reading a view needs the view and its underlying tables. A statement that creates, alters or drops a table, an index, a view or a trigger needs that table or view listed, as well as `sqlite_master` (`sqlite_temp_master` for a temporary object) for the schema bookkeeping. `sqlite_master` and the `pragma_*` table functions are refused unless listed (see Additional refusals for the PRAGMA they report).
- **`columns`** lists every column a statement reads, plus the columns an `UPDATE` sets; `SELECT *` needs every column of the table listed. `INSERT` and `DELETE` name no column and are refused. A read that names no column, such as `count(*)` or `SELECT 1 FROM t`, is allowed when the table is allowed; it shows the row count and nothing else. A table without an integer primary key reads as the column `rowid`, which must be listed to be read.
- `REPLACE INTO` is judged as the `INSERT` it reports; under `columns` it is refused, under `readOnly` it is a write.
- The grant is checked against the names as created, folded: `SELECT body FROM NOTES` against `tables: ["notes"]` is allowed.

## Settings

`[global.sql] delegated_caveats_enforced = true` turns on admission, enforcement and the `/info` feature together. With it off the delegated form is refused at `/delegate` with `unsupported-caveat: <ability> caveat <index> is not a constrained-statements profile`; a stored delegation that carries a non-profile caveat on a `tinycloud.sql/*` ability, as one stored while the setting was on does, does not cover an invocation (`invocation-caveats-not-subset-of-chain`), and nothing runs under it; `/info` does not list the feature.
