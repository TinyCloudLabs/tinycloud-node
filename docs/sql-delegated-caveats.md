# Delegated SQL caveats

A `tinycloud.sql/*` delegation can limit the tables and columns a holder may touch, and make the grant read-only. The node applies the limit to every SQL request that cites the delegation, through any number of hops up to the walk limit of 64 delegations (`MAX_CHAIN_TRAVERSAL_NODES`, `tinycloud-core/src/models/revocation.rs:64`).

The feature is behind `[global.sql] delegated_caveats_enforced` (env `TINYCLOUD_SQL__DELEGATED_CAVEATS_ENFORCED`), off by default. When on, `GET /info` lists `sql-delegated-caveats-v1` in `features`. When off, the form below is refused with 401 like any other unsupported caveat (`unsupported-caveat: ...`) and `/info` does not list the feature. DuckDB: `tinycloud.duckdb/*` takes empty caveats only.

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
- A list with a delegated entry has exactly that one entry. Entries of a list are alternatives, so a second entry, even an empty one, is refused. With the setting on, a list of only empty entries imposes no restriction on a grant (`tinycloud-core/src/models/invocation.rs:673-677`). `[{}]` is stored as no caveat (`tinycloud-core/src/util.rs:351-352`). On a non-owner invocation, `[{}, {}]` is refused (see Chains). An entry that has `mode` and also `tables` or `columns` is refused.
- Anything else (unknown key, wrong type, empty or over-long name, too many names) is refused at `/delegate` with 401 and `unsupported-caveat: <ability> caveat <index> <reason>`; the reason never repeats a name from the request.

## Chains

At `/delegate`, a child must be at least as narrow as the parent grant it relies on: its `tables` and `columns` are subsets of the parent's (an absent parent axis allows anything; a child that drops a restricted axis is refused), and `readOnly` may be turned on but not off. A widening hop is refused with 401 `child-caveats-not-subset-of-parent`. A capability the delegator holds as the space owner relies on no parent grant, so this check does not run on it (`tinycloud-core/src/models/delegation.rs:364-371`; `is_root_authority` at `tinycloud-core/src/models/delegation.rs:968-982`).

At `/invoke`, the node computes the effective caveat from the stored delegations on the chain the invocation cites by CID: `tables` and `columns` are the intersection over every hop that grants the invoked ability on the invoked resource, and `readOnly` is true if any hop sets it. A hop without the ability contributes nothing. A hop wider than its parent does not widen the result: the intersection only narrows. Profile caveats are carried on the invocation capability: when the cited grant carries a constrained-statements profile and the invocation carries none, the request is refused 401 `invocation-caveats-not-subset-of-chain: containment-caveat-required` (`tinycloud-core/src/models/invocation.rs:637`). With the setting on, when the cited grant carries a delegated form, an invocation caveat that is a delegated form, a profile, or unreadable is refused 401 `invocation-caveats-not-subset-of-chain` (`tinycloud-core/src/models/invocation.rs:670-672`); an invocation `[{}]` is accepted. For a non-owner invoker, an invocation `[{}, {}]` is refused 401 `unsupported-caveat: <ability> caveat 0 is not a constrained-statements profile` (`tinycloud-core/src/models/invocation.rs:583`). For a non-owner invoker, a walk over more than 64 delegations is refused 401 `delegation-chain-traversal-limit-exceeded` at admission (`tinycloud-core/src/models/invocation.rs:420-421`), and a cited CID with no stored delegation is refused 401 `MissingParents` (`tinycloud-core/src/models/invocation.rs:438-439`). The space owner's invocation skips the admission walk (`tinycloud-core/src/models/invocation.rs:393-405`). With the setting on, the route walk refuses any invoker with 403 `sql_caveat_violation: chain` when the walk exceeds 64 delegations (`tinycloud-node-server/src/routes/mod.rs:3398-3408`) or reaches a walked delegation with no stored row (`tinycloud-core/src/sql/delegated_caveats.rs:365-367`). For a non-owner invoker, a matching hop whose caveat cannot be read does not cover the invocation: the request is refused 401 `Unauthorized Action: <resource> / <ability>` when no other hop covers (`tinycloud-core/src/models/invocation.rs:589-619`; test `tinycloud-node-server/src/routes/mod.rs:12380-12393`), and 403 `sql_caveat_violation: chain` when another hop still covers (test `tinycloud-node-server/src/routes/mod.rs:12372-12376`). The invocation's own `sqlCaveats` fact can narrow the result further and never widen it: `tables`, `columns` and `readOnly` are intersected with the chain, and `statements` is taken from the fact (`readOnly: false` does not lift a `readOnly` chain). A request that carries only an invocation fact, with no delegated form on its chain, is judged by the same rules: names fold, and `count(*)` is allowed under `columns`. Invocations carry no delegations of their own; a cited CID with no stored delegation is refused (`tinycloud-core/src/models/invocation.rs:430-439`).

## Refusals

A request the effective caveat does not allow fails with 403 and the text `sql_caveat_violation: write`, `sql_caveat_violation: table` or `sql_caveat_violation: column`. The text names the arm and nothing else: no SQL, table or column name. When several arms apply, `write` wins over `table` over `column`. The abilities are checked first: a `read` grant that writes is refused by the ability check (`tinycloud-core/src/sql/authorizer.rs:280-283`) before any caveat arm runs, and that refusal does not carry a `sql_caveat_violation` text. A request with several statements is refused whole: nothing it did is kept. A named statement (`executeStatement`) is judged like any other statement.

## Additional refusals

The refusals in the table below are not decided by one statement's table, column or write. All are 403.

| Request | Limit | Text |
|---|---|---|
| `{"action":"query","sql":"PRAGMA table_info(<table>)"}` (any PRAGMA schema report: `table_info`, `table_xinfo`, `table_list`, `database_list`, `index_list`, `index_info`, `foreign_key_list`; admin ability), and `SELECT ... FROM pragma_table_info('<table>')` even when the function is listed | `tables` or `columns` | `sql_caveat_violation: table` |
| `{"action":"query","sql":"PRAGMA integrity_check"}`, `quick_check`, `foreign_key_check` (with or without a table argument; admin ability) | `tables` or `columns` | `sql_caveat_violation: table` |
| `{"action":"query","sql":"PRAGMA user_version = <n>"}`, `application_id = <n>` (admin ability) | `tables` or `columns` (and `readOnly`) | `sql_caveat_violation: write` |
| `{"action":"export"}` | `tables` | `sql_caveat_violation: table` |
| `{"action":"export"}` | `columns` without `tables` | `sql_caveat_violation: column` |
| an unreadable caveat on a hop that grants the invoked ability (for a non-owner invoker, when another hop of the chain still covers the invocation); a walked delegation with no stored row; or a constrained-statements profile mixed with the delegated form | any | `sql_caveat_violation: chain` |

Under `readOnly` alone, the PRAGMA schema reports, the checks and the export are allowed; a PRAGMA that sets a value is a write.

## What each limit does

- **`readOnly`** refuses every write and schema statement, a `PRAGMA` that sets a value (`PRAGMA user_version = 5`), and any statement the parser does not classify as read-only. Such a statement is refused at its first callback, whatever the action.
- **`tables`** lists every table a statement reads, writes or changes, including the tables reached through a view, a trigger or a foreign key. Writing to a table with a trigger or a foreign key needs the tables they touch listed too. Reading a view needs the view and its underlying tables. A statement that creates, alters or drops a table, an index, a view or a trigger needs that table or view listed, as well as `sqlite_master` (`sqlite_temp_master` for a temporary object) for the schema bookkeeping. `sqlite_master` and the `pragma_*` table functions are refused unless listed (see Additional refusals for the PRAGMA they report).
- **`columns`** lists every column a statement reads, plus the columns an `UPDATE` sets; `SELECT *` needs every column of the table listed. `INSERT` and `DELETE` name no column and are refused. A read that names no column, such as `count(*)` or `SELECT 1 FROM t`, is allowed when the table is allowed; it shows the row count and nothing else. A table without an integer primary key reads as the column `rowid`, which must be listed to be read.
- `REPLACE INTO` is judged as the `INSERT` it reports; under `columns` it is refused, under `readOnly` it is a write.
- The grant is checked against the names as created, folded: `SELECT body FROM NOTES` against `tables: ["notes"]` is allowed.

## Settings

`[global.sql] delegated_caveats_enforced = true` turns on admission, enforcement and the `/info` feature together. With it off, the delegated form is refused at `/delegate` with 401 and `unsupported-caveat: <ability> caveat <index> is not a constrained-statements profile`, and `/info` does not list the feature.

### Setting turned off after delegations were stored

A delegation stored while the setting was on keeps its row. An invocation that cites such a delegation with the setting off is refused 401, and nothing runs under it:

- The cited delegation carries the delegated form: `invocation-caveats-not-subset-of-chain` (`tinycloud-core/src/models/invocation.rs:638-646`).
- The cited delegation carries a list of two or more empty entries (`[{}, {}]`): `invocation-caveats-not-subset-of-chain` (`tinycloud-core/src/models/invocation.rs:638-646`; test `tinycloud-node-server/src/routes/mod.rs:12411-12427`).
- The delegated form is an ancestor of the cited delegation: the form hop does not cover (`tinycloud-core/src/models/invocation.rs:589-608`), and the request is refused with `Unauthorized Action: <resource> / <ability>` (`tinycloud-core/src/models/invocation.rs:614-619`).
