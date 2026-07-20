use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

use super::caveats::SqlCaveats;
use crate::policy_capability::{ability_matches, resolve_alias};

fn can_write_data(ability: &str, is_admin: bool) -> bool {
    // TC-119: confers-write gate (registry-aware). `admin` is covered by the
    // `is_admin` flag; `write` matches directly; `sql/*` matches via the
    // registry implication `* ⊃ write`. Identical to the prior
    // `admin | write | *` set. NOTE: `schema` does NOT confer write here (the
    // registry declares `admin ⊃ schema`, not `schema ⊃ write`).
    is_admin || ability_matches(ability, "tinycloud.sql/write")
}

fn is_sqlite_schema_table(table_name: &str) -> bool {
    matches!(
        table_name,
        "sqlite_master" | "sqlite_schema" | "sqlite_temp_master" | "sqlite_temp_schema"
    )
}

fn can_write_table(ability: &str, is_admin: bool, table_name: &str) -> bool {
    // The second clause is an exact-tier match on `schema` (writes to the
    // sqlite schema tables during DDL), NOT a confers-check — so compare the
    // alias-resolved URN rather than using `ability_matches`.
    can_write_data(ability, is_admin)
        || (resolve_alias(ability) == "tinycloud.sql/schema" && is_sqlite_schema_table(table_name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaDdlKind {
    AlterTable,
    DropIndex,
    DropTable,
}

#[derive(Debug)]
struct SchemaDdlState {
    database_name: Option<String>,
    kind: SchemaDdlKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaDropKind {
    Table,
    View,
}

#[derive(Debug)]
struct SchemaDropTarget {
    database_name: Option<String>,
    object_name: String,
    kind: SchemaDropKind,
}

fn schema_ddl_matches_database(
    database_name: Option<&str>,
    schema_ddl_state: Option<&SchemaDdlState>,
    kinds: &[SchemaDdlKind],
) -> bool {
    schema_ddl_state.is_some_and(|state| {
        state.database_name.as_deref() == database_name && kinds.contains(&state.kind)
    })
}

fn is_sqlite_stat_table(table_name: &str) -> bool {
    matches!(table_name, "sqlite_stat1" | "sqlite_stat4")
}

fn can_update_table(
    ability: &str,
    is_admin: bool,
    database_name: Option<&str>,
    table_name: &str,
    schema_ddl_state: Option<&SchemaDdlState>,
) -> bool {
    can_write_table(ability, is_admin, table_name)
        || (resolve_alias(ability) == "tinycloud.sql/schema"
            && matches!(
                table_name,
                "sqlite_sequence" | "sqlite_stat1" | "sqlite_stat4"
            )
            && schema_ddl_matches_database(
                database_name,
                schema_ddl_state,
                &[SchemaDdlKind::AlterTable],
            ))
}

fn can_delete_table(
    ability: &str,
    is_admin: bool,
    database_name: Option<&str>,
    table_name: &str,
    schema_ddl_state: Option<&SchemaDdlState>,
    schema_drop_target: Option<&SchemaDropTarget>,
) -> bool {
    can_write_table(ability, is_admin, table_name)
        || (resolve_alias(ability) == "tinycloud.sql/schema"
            && (schema_drop_target.is_some_and(|target| {
                target.database_name.as_deref() == database_name && target.object_name == table_name
            }) || (table_name == "sqlite_sequence"
                && schema_drop_target.is_some_and(|target| target.kind == SchemaDropKind::Table)
                && schema_ddl_matches_database(
                    database_name,
                    schema_ddl_state,
                    &[SchemaDdlKind::DropTable],
                ))
                || (is_sqlite_stat_table(table_name)
                    && schema_ddl_matches_database(
                        database_name,
                        schema_ddl_state,
                        &[SchemaDdlKind::DropIndex, SchemaDdlKind::DropTable],
                    ))))
}

pub fn create_authorizer(
    caveats: Option<SqlCaveats>,
    ability: String,
    is_admin: bool,
) -> impl FnMut(AuthContext<'_>) -> Authorization {
    let mut schema_ddl_authorized = false;
    let mut schema_ddl_state: Option<SchemaDdlState> = None;
    let mut schema_drop_target: Option<SchemaDropTarget> = None;
    let mut alter_table_authorized = false;
    move |ctx: AuthContext<'_>| match ctx.action {
        // Always deny attach/detach
        AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,

        // Pragma whitelist
        AuthAction::Pragma { pragma_name, .. } => {
            let readonly_pragmas = [
                "table_info",
                "table_list",
                "table_xinfo",
                "database_list",
                "index_list",
                "index_info",
                "foreign_key_list",
            ];
            if readonly_pragmas.contains(&pragma_name) || is_admin {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }

        // Function whitelist
        AuthAction::Function { function_name } => {
            let allowed_functions = [
                // Standard SQL
                "abs",
                "changes",
                "char",
                "coalesce",
                "glob",
                "hex",
                "ifnull",
                "iif",
                "instr",
                "last_insert_rowid",
                "length",
                "like",
                "likely",
                "lower",
                "ltrim",
                "max",
                "min",
                "nullif",
                "printf",
                "quote",
                "random",
                "randomblob",
                "replace",
                "round",
                "rtrim",
                "sign",
                "soundex",
                "substr",
                "substring",
                "total_changes",
                "trim",
                "typeof",
                "unicode",
                "unlikely",
                "upper",
                "zeroblob",
                // Aggregate
                "avg",
                "count",
                "group_concat",
                "sum",
                "total",
                // Date/time
                "date",
                "time",
                "datetime",
                "julianday",
                "strftime",
                "unixepoch",
                "timediff",
                // JSON
                "json",
                "json_array",
                "json_array_length",
                "json_extract",
                "json_insert",
                "json_object",
                "json_patch",
                "json_remove",
                "json_replace",
                "json_set",
                "json_type",
                "json_valid",
                "json_quote",
                "json_group_array",
                "json_group_object",
                "json_each",
                "json_tree",
                // Math
                "acos",
                "acosh",
                "asin",
                "asinh",
                "atan",
                "atan2",
                "atanh",
                "ceil",
                "ceiling",
                "cos",
                "cosh",
                "degrees",
                "exp",
                "floor",
                "ln",
                "log",
                "log10",
                "log2",
                "mod",
                "pi",
                "pow",
                "power",
                "radians",
                "sin",
                "sinh",
                "sqrt",
                "tan",
                "tanh",
                "trunc",
            ];
            let alter_table_functions = [
                "sqlite_rename_column",
                "sqlite_rename_table",
                "sqlite_rename_test",
                "sqlite_drop_column",
                "sqlite_rename_quotefix",
            ];
            if allowed_functions.contains(&function_name)
                || (alter_table_authorized && alter_table_functions.contains(&function_name))
            {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }

        // Read operations: check table/column caveats
        AuthAction::Read {
            table_name,
            column_name,
        } => {
            if !is_admin
                && resolve_alias(ability.as_str()) == "tinycloud.sql/schema"
                && !schema_ddl_authorized
                && !is_sqlite_schema_table(table_name)
            {
                return Authorization::Deny;
            }
            if let Some(ref caveats) = caveats {
                if !caveats.is_table_allowed(table_name) {
                    return Authorization::Deny;
                }
                if !caveats.is_column_allowed(column_name) {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }

        // Write operations
        AuthAction::Insert { table_name } => {
            if !can_write_table(ability.as_str(), is_admin, table_name) {
                return Authorization::Deny;
            }
            if let Some(ref caveats) = caveats {
                if !caveats.is_write_allowed() {
                    return Authorization::Deny;
                }
                if !caveats.is_table_allowed(table_name) {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }

        AuthAction::Delete { table_name } => {
            if !can_delete_table(
                ability.as_str(),
                is_admin,
                ctx.database_name,
                table_name,
                schema_ddl_state.as_ref(),
                schema_drop_target.as_ref(),
            ) {
                return Authorization::Deny;
            }
            if let Some(ref caveats) = caveats {
                if !caveats.is_write_allowed() {
                    return Authorization::Deny;
                }
                if !caveats.is_table_allowed(table_name) {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }

        AuthAction::Update {
            table_name,
            column_name,
        } => {
            if !can_update_table(
                ability.as_str(),
                is_admin,
                ctx.database_name,
                table_name,
                schema_ddl_state.as_ref(),
            ) {
                return Authorization::Deny;
            }
            if let Some(ref caveats) = caveats {
                if !caveats.is_write_allowed() {
                    return Authorization::Deny;
                }
                if !caveats.is_table_allowed(table_name) {
                    return Authorization::Deny;
                }
                if !caveats.is_column_allowed(column_name) {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }

        // DDL operations
        AuthAction::CreateTable { .. } | AuthAction::CreateTempTable { .. } => {
            // Do not enable application-table reads for CREATE TABLE. SQLite's
            // authorizer does not emit an Insert callback for CTAS result rows,
            // so allowing its source SELECT would let schema authority copy data.
            if is_admin
                || ability_matches(ability.as_str(), "tinycloud.sql/write")
                || ability_matches(ability.as_str(), "tinycloud.sql/schema")
            {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }

        AuthAction::DropTable {
            table_name: object_name,
        }
        | AuthAction::DropTempTable {
            table_name: object_name,
        } => {
            if !(is_admin
                || ability_matches(ability.as_str(), "tinycloud.sql/write")
                || ability_matches(ability.as_str(), "tinycloud.sql/schema"))
            {
                Authorization::Deny
            } else {
                if !is_admin && resolve_alias(ability.as_str()) == "tinycloud.sql/schema" {
                    schema_ddl_authorized = true;
                    schema_ddl_state = Some(SchemaDdlState {
                        database_name: ctx.database_name.map(str::to_owned),
                        kind: SchemaDdlKind::DropTable,
                    });
                    schema_drop_target = Some(SchemaDropTarget {
                        database_name: ctx.database_name.map(str::to_owned),
                        object_name: object_name.to_owned(),
                        kind: SchemaDropKind::Table,
                    });
                }
                Authorization::Allow
            }
        }

        AuthAction::DropView {
            view_name: object_name,
        }
        | AuthAction::DropTempView {
            view_name: object_name,
        } => {
            if !(is_admin
                || ability_matches(ability.as_str(), "tinycloud.sql/write")
                || ability_matches(ability.as_str(), "tinycloud.sql/schema"))
            {
                Authorization::Deny
            } else {
                if !is_admin && resolve_alias(ability.as_str()) == "tinycloud.sql/schema" {
                    schema_ddl_authorized = true;
                    schema_drop_target = Some(SchemaDropTarget {
                        database_name: ctx.database_name.map(str::to_owned),
                        object_name: object_name.to_owned(),
                        kind: SchemaDropKind::View,
                    });
                }
                Authorization::Allow
            }
        }

        AuthAction::AlterTable { database_name, .. } => {
            if !(is_admin
                || ability_matches(ability.as_str(), "tinycloud.sql/write")
                || ability_matches(ability.as_str(), "tinycloud.sql/schema"))
            {
                Authorization::Deny
            } else {
                alter_table_authorized = true;
                if !is_admin && resolve_alias(ability.as_str()) == "tinycloud.sql/schema" {
                    schema_ddl_authorized = true;
                    schema_ddl_state = Some(SchemaDdlState {
                        database_name: Some(database_name.to_owned()),
                        kind: SchemaDdlKind::AlterTable,
                    });
                }
                Authorization::Allow
            }
        }

        AuthAction::DropIndex { .. } | AuthAction::DropTempIndex { .. } => {
            if !(is_admin
                || ability_matches(ability.as_str(), "tinycloud.sql/write")
                || ability_matches(ability.as_str(), "tinycloud.sql/schema"))
            {
                Authorization::Deny
            } else {
                if !is_admin && resolve_alias(ability.as_str()) == "tinycloud.sql/schema" {
                    schema_ddl_authorized = true;
                    schema_ddl_state = Some(SchemaDdlState {
                        database_name: ctx.database_name.map(str::to_owned),
                        kind: SchemaDdlKind::DropIndex,
                    });
                }
                Authorization::Allow
            }
        }

        AuthAction::CreateIndex { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::CreateTempIndex { .. }
        | AuthAction::CreateTempTrigger { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        // SQLite fires SQLITE_REINDEX while building an index; gate it like the
        // CreateIndex it accompanies so an authorized CREATE INDEX can complete.
        | AuthAction::Reindex { .. } => {
            // TC-119: DDL is permitted for abilities that confer write OR
            // schema (`sql/*` implies both). Equivalent to the prior
            // `write | schema | *` set; `admin` is handled by `is_admin`.
            if !(is_admin
                || ability_matches(ability.as_str(), "tinycloud.sql/write")
                || ability_matches(ability.as_str(), "tinycloud.sql/schema"))
            {
                Authorization::Deny
            } else {
                if !is_admin && resolve_alias(ability.as_str()) == "tinycloud.sql/schema" {
                    schema_ddl_authorized = true;
                }
                Authorization::Allow
            }
        }

        // Allow internal operations
        AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } | AuthAction::Select => {
            if !is_admin
                && resolve_alias(ability.as_str()) == "tinycloud.sql/schema"
                && !schema_ddl_authorized
            {
                return Authorization::Deny;
            }
            Authorization::Allow
        }

        // Deny everything else
        _ => Authorization::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorize(ability: &str, is_admin: bool, action: AuthAction<'_>) -> Authorization {
        let mut auth = create_authorizer(None, ability.to_string(), is_admin);
        auth(AuthContext {
            action,
            database_name: Some("main"),
            accessor: None,
        })
    }

    #[test]
    fn create_index_allowed_with_write_ability() {
        // CREATE [UNIQUE] INDEX fires CreateIndex followed by Reindex while the
        // index is built; both must pass for the statement to succeed.
        let create_index = AuthAction::CreateIndex {
            index_name: "uq_interaction_nonce",
            table_name: "interaction",
        };
        let reindex = AuthAction::Reindex {
            index_name: "uq_interaction_nonce",
        };

        assert_eq!(
            authorize("tinycloud.sql/write", false, create_index),
            Authorization::Allow
        );
        assert_eq!(
            authorize("tinycloud.sql/write", false, reindex),
            Authorization::Allow
        );
    }

    #[test]
    fn create_index_allowed_with_schema_ability() {
        let create_index = AuthAction::CreateIndex {
            index_name: "uq_interaction_nonce",
            table_name: "interaction",
        };
        let reindex = AuthAction::Reindex {
            index_name: "uq_interaction_nonce",
        };

        assert_eq!(
            authorize("tinycloud.sql/schema", false, create_index),
            Authorization::Allow
        );
        assert_eq!(
            authorize("tinycloud.sql/schema", false, reindex),
            Authorization::Allow
        );
    }

    #[test]
    fn create_index_allowed_for_admin() {
        let create_index = AuthAction::CreateIndex {
            index_name: "uq_interaction_nonce",
            table_name: "interaction",
        };
        let reindex = AuthAction::Reindex {
            index_name: "uq_interaction_nonce",
        };

        assert_eq!(
            authorize("tinycloud.sql/read", true, create_index),
            Authorization::Allow
        );
        assert_eq!(
            authorize("tinycloud.sql/read", true, reindex),
            Authorization::Allow
        );
    }

    #[test]
    fn create_index_denied_without_write() {
        let create_index = AuthAction::CreateIndex {
            index_name: "uq_interaction_nonce",
            table_name: "interaction",
        };
        let reindex = AuthAction::Reindex {
            index_name: "uq_interaction_nonce",
        };

        assert_eq!(
            authorize("tinycloud.sql/read", false, create_index),
            Authorization::Deny
        );
        // Reindex must be gated identically to CreateIndex: a read-only cap
        // cannot sneak an index build through the companion callback.
        assert_eq!(
            authorize("tinycloud.sql/read", false, reindex),
            Authorization::Deny
        );
    }

    #[test]
    fn schema_ability_denies_dml() {
        assert_eq!(
            authorize(
                "tinycloud.sql/schema",
                false,
                AuthAction::Insert {
                    table_name: "interaction"
                }
            ),
            Authorization::Deny
        );
        assert_eq!(
            authorize(
                "tinycloud.sql/schema",
                false,
                AuthAction::Delete {
                    table_name: "interaction"
                }
            ),
            Authorization::Deny
        );
        assert_eq!(
            authorize(
                "tinycloud.sql/schema",
                false,
                AuthAction::Update {
                    table_name: "interaction",
                    column_name: "nonce",
                }
            ),
            Authorization::Deny
        );
    }

    #[test]
    fn schema_ability_denies_application_table_reads() {
        assert_eq!(
            authorize(
                "tinycloud.sql/schema",
                false,
                AuthAction::Read {
                    table_name: "interaction",
                    column_name: "nonce",
                }
            ),
            Authorization::Deny
        );
        assert_eq!(
            authorize(
                "tinycloud.sql/schema",
                false,
                AuthAction::Read {
                    table_name: "sqlite_schema",
                    column_name: "sql",
                }
            ),
            Authorization::Allow
        );
    }

    /// Install the authorizer on a real rusqlite connection (mirroring the
    /// wiring in database.rs) and run `sql` under the given cap.
    fn execute_under_authorizer(
        conn: &rusqlite::Connection,
        ability: &str,
        is_admin: bool,
        sql: &str,
    ) -> rusqlite::Result<()> {
        let auth = create_authorizer(None, ability.to_string(), is_admin);
        conn.authorizer(Some(auth));
        let result = conn.execute_batch(sql);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        result
    }

    #[test]
    fn create_unique_index_executes_with_write_cap() {
        // End-to-end against real SQLite: the CreateIndex -> Reindex callback
        // sequence fired while building the index must pass under a write cap.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        execute_under_authorizer(
            &conn,
            "tinycloud.sql/write",
            false,
            "CREATE TABLE interaction (reader_did TEXT, nonce TEXT)",
        )
        .unwrap();

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/write",
            false,
            "CREATE UNIQUE INDEX uq_interaction_nonce ON interaction (reader_did, nonce)",
        )
        .expect("CREATE UNIQUE INDEX should succeed with a write cap");
    }

    #[test]
    fn create_unique_index_executes_with_schema_cap() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "CREATE TABLE interaction (reader_did TEXT, nonce TEXT)",
        )
        .unwrap();

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "CREATE UNIQUE INDEX uq_interaction_nonce ON interaction (reader_did, nonce)",
        )
        .expect("CREATE UNIQUE INDEX should succeed with a schema cap");
    }

    #[test]
    fn create_unique_index_blocked_with_read_only_cap() {
        // Set up the table with a write cap, then attempt the index under a
        // read-only cap: SQLite must report "not authorized".
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        execute_under_authorizer(
            &conn,
            "tinycloud.sql/write",
            false,
            "CREATE TABLE interaction (reader_did TEXT, nonce TEXT)",
        )
        .unwrap();

        let err = execute_under_authorizer(
            &conn,
            "tinycloud.sql/read",
            false,
            "CREATE UNIQUE INDEX uq_interaction_nonce ON interaction (reader_did, nonce)",
        )
        .expect_err("CREATE UNIQUE INDEX must be denied for a read-only cap");
        assert!(
            err.to_string().contains("not authorized"),
            "expected an authorization error, got: {err}"
        );
    }

    #[test]
    fn drop_table_obeys_schema_authority() {
        for (ability, is_admin) in [
            ("tinycloud.sql/schema", false),
            ("tinycloud.sql/write", false),
            ("tinycloud.sql/admin", true),
        ] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY)")
                .unwrap();

            execute_under_authorizer(&conn, ability, is_admin, "DROP TABLE items")
                .unwrap_or_else(|error| panic!("{ability} should permit DROP TABLE: {error}"));
        }

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TEMP TABLE temp_items (id INTEGER PRIMARY KEY)")
            .unwrap();
        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP TABLE temp.temp_items",
        )
        .expect("schema authority should permit DROP TEMP TABLE");

        for (setup, sql) in [
            (
                "CREATE TABLE read_items (id INTEGER PRIMARY KEY)",
                "DROP TABLE read_items",
            ),
            (
                "CREATE TEMP TABLE read_items (id INTEGER PRIMARY KEY)",
                "DROP TABLE temp.read_items",
            ),
        ] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch(setup).unwrap();
            let error = execute_under_authorizer(&conn, "tinycloud.sql/read", false, sql)
                .expect_err("read authority must not permit DROP TABLE");
            assert!(
                error.to_string().contains("not authorized"),
                "expected an authorization error, got: {error}"
            );
        }
    }

    #[test]
    fn schema_ability_cannot_populate_create_table_as_select() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE source (id INTEGER); INSERT INTO source VALUES (1)")
            .unwrap();

        let error = execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "CREATE TABLE copied AS SELECT id FROM source",
        )
        .expect_err("schema authority must not insert CTAS result rows");
        assert!(
            error.to_string().contains("not authorized")
                || error.to_string().contains("is prohibited"),
            "expected an authorization error, got: {error}"
        );
        let copied_tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'copied'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(copied_tables, 0, "failed CTAS must roll back its table");
    }

    #[test]
    fn schema_drop_cannot_cascade_into_another_table() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE parents (id INTEGER PRIMARY KEY);
             CREATE TABLE children (
                 id INTEGER PRIMARY KEY,
                 parent_id INTEGER REFERENCES parents(id) ON DELETE CASCADE
             );
             INSERT INTO parents VALUES (1);
             INSERT INTO children VALUES (1, 1);",
        )
        .unwrap();

        let error =
            execute_under_authorizer(&conn, "tinycloud.sql/schema", false, "DROP TABLE parents")
                .expect_err("schema authority must not cascade deletes into another table");
        assert!(
            error.to_string().contains("not authorized"),
            "expected an authorization error, got: {error}"
        );
        let parent_rows: i64 = conn
            .query_row("SELECT count(*) FROM parents", [], |row| row.get(0))
            .unwrap();
        let child_rows: i64 = conn
            .query_row("SELECT count(*) FROM children", [], |row| row.get(0))
            .unwrap();
        assert_eq!(parent_rows, 1, "failed DROP must retain parent rows");
        assert_eq!(child_rows, 1, "failed DROP must retain child rows");
    }

    #[test]
    fn schema_drop_cannot_update_another_table_via_set_null() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE parents (id INTEGER PRIMARY KEY);
             CREATE TABLE children (
                 id INTEGER PRIMARY KEY,
                 parent_id INTEGER REFERENCES parents(id) ON DELETE SET NULL
             );
             INSERT INTO parents VALUES (1);
             INSERT INTO children VALUES (1, 1);",
        )
        .unwrap();

        let error =
            execute_under_authorizer(&conn, "tinycloud.sql/schema", false, "DROP TABLE parents")
                .expect_err("schema authority must not update another table through SET NULL");
        assert!(
            error.to_string().contains("not authorized"),
            "expected an authorization error, got: {error}"
        );
        let parent_rows: i64 = conn
            .query_row("SELECT count(*) FROM parents", [], |row| row.get(0))
            .unwrap();
        let child_parent_id: Option<i64> = conn
            .query_row("SELECT parent_id FROM children WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(parent_rows, 1, "failed DROP must retain parent rows");
        assert_eq!(
            child_parent_id,
            Some(1),
            "failed DROP must retain the child foreign key"
        );
    }

    #[test]
    fn drop_view_obeys_schema_authority_in_main_and_temp() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE VIEW shared_view AS SELECT 1 AS value;
             CREATE TEMP VIEW shared_view AS SELECT 2 AS value;",
        )
        .unwrap();

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP VIEW main.shared_view",
        )
        .expect("schema authority should drop the main view");
        let temp_value: i64 = conn
            .query_row("SELECT value FROM temp.shared_view", [], |row| row.get(0))
            .unwrap();
        assert_eq!(temp_value, 2, "dropping main must retain the temp view");

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP VIEW temp.shared_view",
        )
        .expect("schema authority should drop the temp view");

        for sql in ["DROP VIEW main.read_view", "DROP VIEW temp.read_view"] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch(
                "CREATE VIEW read_view AS SELECT 1 AS value;
                 CREATE TEMP VIEW read_view AS SELECT 2 AS value;",
            )
            .unwrap();
            let error = execute_under_authorizer(&conn, "tinycloud.sql/read", false, sql)
                .expect_err("read authority must not drop a view");
            assert!(
                error.to_string().contains("not authorized"),
                "expected an authorization error, got: {error}"
            );
        }
    }

    #[test]
    fn schema_ability_renames_and_drops_autoincrement_tables_in_main_and_temp() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT);
             CREATE TEMP TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT);
             INSERT INTO main.items DEFAULT VALUES;
             INSERT INTO temp.items DEFAULT VALUES;",
        )
        .unwrap();

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "ALTER TABLE main.items RENAME TO main_items",
        )
        .expect("schema authority should rename a main AUTOINCREMENT table");
        let main_sequence_name: String = conn
            .query_row("SELECT name FROM main.sqlite_sequence", [], |row| {
                row.get(0)
            })
            .unwrap();
        let temp_sequence_name: String = conn
            .query_row("SELECT name FROM temp.sqlite_sequence", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(main_sequence_name, "main_items");
        assert_eq!(temp_sequence_name, "items");

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "ALTER TABLE temp.items RENAME TO temp_items",
        )
        .expect("schema authority should rename a temp AUTOINCREMENT table");

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP TABLE main.main_items",
        )
        .expect("schema authority should drop a main AUTOINCREMENT table");
        let main_sequence_rows: i64 = conn
            .query_row("SELECT count(*) FROM main.sqlite_sequence", [], |row| {
                row.get(0)
            })
            .unwrap();
        let temp_sequence_name: String = conn
            .query_row("SELECT name FROM temp.sqlite_sequence", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(main_sequence_rows, 0);
        assert_eq!(temp_sequence_name, "temp_items");

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP TABLE temp.temp_items",
        )
        .expect("schema authority should drop a temp AUTOINCREMENT table");
        let temp_sequence_rows: i64 = conn
            .query_row("SELECT count(*) FROM temp.sqlite_sequence", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(temp_sequence_rows, 0);
    }

    #[test]
    fn schema_ability_renames_and_drops_columns_in_main_and_temp() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE column_items (id INTEGER, old_value TEXT, removable TEXT);
             CREATE TEMP TABLE column_items (id INTEGER, old_value TEXT, removable TEXT);
             INSERT INTO main.column_items VALUES (1, 'main', 'unused');
             INSERT INTO temp.column_items VALUES (2, 'temp', 'unused');",
        )
        .unwrap();

        for database in ["main", "temp"] {
            execute_under_authorizer(
                &conn,
                "tinycloud.sql/schema",
                false,
                &format!(
                    "ALTER TABLE {database}.column_items RENAME COLUMN old_value TO new_value"
                ),
            )
            .unwrap_or_else(|error| panic!("schema rename column failed in {database}: {error}"));
            execute_under_authorizer(
                &conn,
                "tinycloud.sql/schema",
                false,
                &format!("ALTER TABLE {database}.column_items DROP COLUMN removable"),
            )
            .unwrap_or_else(|error| panic!("schema drop column failed in {database}: {error}"));
        }

        let main_value: String = conn
            .query_row("SELECT new_value FROM main.column_items", [], |row| {
                row.get(0)
            })
            .unwrap();
        let temp_value: String = conn
            .query_row("SELECT new_value FROM temp.column_items", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(main_value, "main");
        assert_eq!(temp_value, "temp");
    }

    #[test]
    fn schema_ability_drops_analyzed_indexes_in_main_and_temp() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE indexed_items (value TEXT);
             CREATE INDEX shared_index ON indexed_items(value);
             INSERT INTO main.indexed_items VALUES ('main');
             ANALYZE main.shared_index;
             CREATE TEMP TABLE indexed_items (value TEXT);
             CREATE INDEX temp.shared_index ON indexed_items(value);
             INSERT INTO temp.indexed_items VALUES ('temp');
             ANALYZE temp.shared_index;",
        )
        .unwrap();

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP INDEX main.shared_index",
        )
        .expect("schema authority should drop an analyzed main index");
        let main_index_rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM main.sqlite_schema WHERE type = 'index' AND name = 'shared_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let temp_index_rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM temp.sqlite_schema WHERE type = 'index' AND name = 'shared_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(main_index_rows, 0);
        assert_eq!(temp_index_rows, 1);

        execute_under_authorizer(
            &conn,
            "tinycloud.sql/schema",
            false,
            "DROP INDEX temp.shared_index",
        )
        .expect("schema authority should drop an analyzed temp index");
    }

    #[test]
    fn schema_auxiliary_access_requires_matching_ddl_state() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT);
             CREATE INDEX items_value ON items(value);
             INSERT INTO items(value) VALUES ('value');
             ANALYZE main.items_value;",
        )
        .unwrap();

        for sql in [
            "DELETE FROM main.sqlite_sequence",
            "UPDATE main.sqlite_sequence SET name = 'other'",
            "DELETE FROM main.sqlite_stat1",
            "DELETE FROM main.sqlite_stat4",
        ] {
            let error = execute_under_authorizer(&conn, "tinycloud.sql/schema", false, sql)
                .expect_err("schema authority must not directly mutate auxiliary tables");
            assert!(
                error.to_string().contains("not authorized"),
                "expected an authorization error for {sql}, got: {error}"
            );
        }

        let mut auth = create_authorizer(None, "tinycloud.sql/schema".to_string(), false);
        for function_name in [
            "sqlite_rename_column",
            "sqlite_rename_table",
            "sqlite_rename_test",
            "sqlite_drop_column",
            "sqlite_rename_quotefix",
        ] {
            assert_eq!(
                auth(AuthContext {
                    action: AuthAction::Function { function_name },
                    database_name: None,
                    accessor: None,
                }),
                Authorization::Deny,
                "internal ALTER function must be denied before an ALTER callback"
            );
        }
        assert_eq!(
            auth(AuthContext {
                action: AuthAction::AlterTable {
                    database_name: "main",
                    table_name: "items",
                },
                database_name: None,
                accessor: None,
            }),
            Authorization::Allow
        );
        for function_name in [
            "sqlite_rename_column",
            "sqlite_rename_table",
            "sqlite_rename_test",
            "sqlite_drop_column",
            "sqlite_rename_quotefix",
        ] {
            assert_eq!(
                auth(AuthContext {
                    action: AuthAction::Function { function_name },
                    database_name: None,
                    accessor: None,
                }),
                Authorization::Allow,
                "internal ALTER function should follow an authorized ALTER callback"
            );
        }
        assert_eq!(
            auth(AuthContext {
                action: AuthAction::Update {
                    table_name: "sqlite_sequence",
                    column_name: "name",
                },
                database_name: Some("temp"),
                accessor: None,
            }),
            Authorization::Deny,
            "main ALTER state must not authorize a temp auxiliary update"
        );

        let caveats = SqlCaveats {
            read_only: Some(true),
            ..SqlCaveats::default()
        };
        let mut caveated_auth =
            create_authorizer(Some(caveats), "tinycloud.sql/schema".to_string(), false);
        assert_eq!(
            caveated_auth(AuthContext {
                action: AuthAction::AlterTable {
                    database_name: "main",
                    table_name: "items",
                },
                database_name: None,
                accessor: None,
            }),
            Authorization::Allow
        );
        assert_eq!(
            caveated_auth(AuthContext {
                action: AuthAction::Update {
                    table_name: "sqlite_sequence",
                    column_name: "name",
                },
                database_name: Some("main"),
                accessor: None,
            }),
            Authorization::Deny,
            "read-only caveats must still reject DDL-internal auxiliary writes"
        );
    }
}
