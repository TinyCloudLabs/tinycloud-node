use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

use super::authority::SqlAuthority;
use super::caveats::SqlCaveats;
use super::parser::ParsedQuery;

/// What the statement being authorized is, as the parser classified it.
///
/// The authorizer is the authoritative defence. It judges every SQLite
/// action against the abilities held, and uses the scope only to decide
/// which restrictions apply to this statement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatementScope {
    pub is_ddl: bool,
    pub is_read_only: bool,
}

impl StatementScope {
    pub fn of(parsed: &ParsedQuery) -> Self {
        Self {
            is_ddl: parsed.is_ddl,
            is_read_only: parsed.is_read_only,
        }
    }
}

/// What the abilities held let this statement do.
#[derive(Clone, Copy, Debug)]
struct Tier {
    is_admin: bool,
    /// `write` (or admin / `*`): may change data.
    can_write_data: bool,
    /// A schema-changing action may run. Under `DdlPolicy::Enforce` this needs
    /// a schema-conferring ability (`schema`, `admin`, `*`); `write` is not
    /// enough (TC-1581).
    can_change_schema: bool,
    /// The statement runs with schema authority and nothing that writes data:
    /// it may not read or write application tables.
    schema_restricted: bool,
    /// The statement may write SQLite's own schema tables: a schema change
    /// writes them internally. A data statement may not (TC-1586): `write`
    /// does not edit `sqlite_master`.
    may_write_schema_tables: bool,
    /// The parser classified the statement as a pure read. Only SQLite's own
    /// schema bookkeeping UPDATE for a `pragma_*` function is allowed to it.
    read_only_scope: bool,
}

impl Tier {
    fn new(authority: &SqlAuthority, scope: StatementScope) -> Self {
        let is_admin = authority.is_admin();
        let can_write_data = authority.confers_data_write();
        let can_change_schema = authority.may_change_schema();
        Self {
            is_admin,
            can_write_data,
            can_change_schema,
            schema_restricted: !is_admin
                && !can_write_data
                && (scope.is_ddl || authority.is_schema_only()),
            may_write_schema_tables: is_admin || (scope.is_ddl && can_change_schema),
            read_only_scope: scope.is_read_only,
        }
    }
}

fn is_sqlite_schema_table(table_name: &str) -> bool {
    matches!(
        table_name,
        "sqlite_master" | "sqlite_schema" | "sqlite_temp_master" | "sqlite_temp_schema"
    )
}

fn can_write_table(tier: &Tier, table_name: &str) -> bool {
    if is_sqlite_schema_table(table_name) {
        // The second clause lets schema-only authority write the sqlite
        // schema tables while it runs DDL.
        return tier.may_write_schema_tables || tier.schema_restricted;
    }
    tier.can_write_data
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
    tier: &Tier,
    database_name: Option<&str>,
    table_name: &str,
    schema_ddl_state: Option<&SchemaDdlState>,
) -> bool {
    can_write_table(tier, table_name)
        // SQLite's first use of a `pragma_*` table-valued function in a
        // connection touches the schema table with an UPDATE, and nothing
        // else: a pure query gets that one action, not INSERT or DELETE.
        || (tier.read_only_scope && is_sqlite_schema_table(table_name))
        || (tier.schema_restricted
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
    tier: &Tier,
    database_name: Option<&str>,
    table_name: &str,
    schema_ddl_state: Option<&SchemaDdlState>,
    schema_drop_target: Option<&SchemaDropTarget>,
) -> bool {
    can_write_table(tier, table_name)
        || (tier.schema_restricted
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

/// Authorize with one ability string (plus the `is_admin` flag), for a
/// statement the caller has not classified. Judges DDL by the abilities
/// alone; use [`create_authorizer_scoped`] when the parser's classification
/// of the statement is known.
pub fn create_authorizer(
    caveats: Option<SqlCaveats>,
    ability: String,
    is_admin: bool,
) -> impl FnMut(AuthContext<'_>) -> Authorization {
    let mut held = vec![ability];
    if is_admin {
        held.push("tinycloud.sql/admin".to_string());
    }
    create_authorizer_scoped(caveats, &SqlAuthority::new(held), StatementScope::default())
}

/// Set once the authorizer has allowed a PRAGMA that is not one of the plain
/// read-only schema reports. The actor resets the connection after any request
/// in which this was set (TC-1586).
pub type PragmaTracker = Arc<AtomicBool>;

/// PRAGMAs anyone may run: reports on the schema that change nothing.
const READ_ONLY_PRAGMAS: [&str; 7] = [
    "table_info",
    "table_list",
    "table_xinfo",
    "database_list",
    "index_list",
    "index_info",
    "foreign_key_list",
];

/// PRAGMAs an admin may also set. They live in the database header, not in
/// connection state.
const ADMIN_SETTABLE_PRAGMAS: [&str; 2] = ["user_version", "application_id"];

/// PRAGMAs an admin may run in their reporting form (no value).
const ADMIN_REPORT_PRAGMAS: [&str; 15] = [
    "user_version",
    "application_id",
    "schema_version",
    "page_count",
    "page_size",
    "freelist_count",
    "data_version",
    "encoding",
    "journal_mode",
    "foreign_keys",
    "writable_schema",
    "query_only",
    "collation_list",
    "compile_options",
    "pragma_list",
];

/// PRAGMAs that check the database; they take an argument and change nothing.
const ADMIN_CHECK_PRAGMAS: [&str; 3] = ["integrity_check", "quick_check", "foreign_key_check"];

fn pragma_in(list: &[&str], name: &str) -> bool {
    list.iter().any(|known| known.eq_ignore_ascii_case(name))
}

/// Whether an admin may run this PRAGMA. Everything that would change
/// connection-level or process-wide SQLite settings is refused: the allow-list
/// is the point, so nothing outside it is reachable by name.
fn admin_pragma_allowed(name: &str, has_value: bool) -> bool {
    pragma_in(&ADMIN_SETTABLE_PRAGMAS, name)
        || pragma_in(&ADMIN_CHECK_PRAGMAS, name)
        || (!has_value && pragma_in(&ADMIN_REPORT_PRAGMAS, name))
}

/// The SQLite authorizer for one statement (TC-1581): every action is judged
/// against all the SQL abilities the invocation holds, and `scope` says what
/// the parser made of the statement.
pub fn create_authorizer_scoped(
    caveats: Option<SqlCaveats>,
    authority: &SqlAuthority,
    scope: StatementScope,
) -> impl FnMut(AuthContext<'_>) -> Authorization {
    create_authorizer_tracked(caveats, authority, scope, PragmaTracker::default())
}

/// As [`create_authorizer_scoped`], and records in `pragmas` that a PRAGMA
/// outside the read-only reports was allowed.
pub fn create_authorizer_tracked(
    caveats: Option<SqlCaveats>,
    authority: &SqlAuthority,
    scope: StatementScope,
    pragmas: PragmaTracker,
) -> impl FnMut(AuthContext<'_>) -> Authorization {
    let tier = Tier::new(authority, scope);
    let is_admin = tier.is_admin;
    let mut schema_ddl_authorized = false;
    let mut schema_ddl_state: Option<SchemaDdlState> = None;
    let mut schema_drop_target: Option<SchemaDropTarget> = None;
    let mut alter_table_authorized = false;
    move |ctx: AuthContext<'_>| match ctx.action {
        // Always deny attach/detach
        AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,

        // PRAGMA: plain schema reports for everyone; for an admin, the
        // allow-list above. Any other PRAGMA is refused.
        AuthAction::Pragma {
            pragma_name,
            pragma_value,
        } => {
            if pragma_in(&READ_ONLY_PRAGMAS, pragma_name) {
                Authorization::Allow
            } else if is_admin && admin_pragma_allowed(pragma_name, pragma_value.is_some()) {
                pragmas.store(true, Ordering::Relaxed);
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
            if tier.schema_restricted
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
            if !can_write_table(&tier, table_name) {
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
                &tier,
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
                &tier,
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

        // DDL operations (TC-1581). Every schema-changing action needs the
        // schema authority that `tier.can_change_schema` encodes, so a
        // statement the parser misclassified as data is still refused here.
        AuthAction::CreateTable { .. } | AuthAction::CreateTempTable { .. } => {
            // Do not enable application-table reads for CREATE TABLE. SQLite's
            // authorizer does not emit an Insert callback for CTAS result rows,
            // so allowing its source SELECT would let schema authority copy data.
            if tier.can_change_schema {
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
            if !tier.can_change_schema {
                Authorization::Deny
            } else {
                if tier.schema_restricted {
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
            if !tier.can_change_schema {
                Authorization::Deny
            } else {
                if tier.schema_restricted {
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
            if !tier.can_change_schema {
                Authorization::Deny
            } else {
                alter_table_authorized = true;
                if tier.schema_restricted {
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
            if !tier.can_change_schema {
                Authorization::Deny
            } else {
                if tier.schema_restricted {
                    schema_ddl_authorized = true;
                    schema_ddl_state = Some(SchemaDdlState {
                        database_name: ctx.database_name.map(str::to_owned),
                        kind: SchemaDdlKind::DropIndex,
                    });
                }
                Authorization::Allow
            }
        }

        // The parser cannot parse CREATE TRIGGER; deny it here as well so the
        // authorizer does not rely on that. A trigger runs later, with the
        // authority of whoever fires it.
        AuthAction::CreateTrigger { .. } | AuthAction::CreateTempTrigger { .. } => {
            Authorization::Deny
        }

        AuthAction::CreateIndex { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::CreateTempIndex { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        // SQLite fires SQLITE_REINDEX while building an index; gate it like the
        // CreateIndex it accompanies so an authorized CREATE INDEX can complete.
        | AuthAction::Reindex { .. } => {
            if !tier.can_change_schema {
                Authorization::Deny
            } else {
                if tier.schema_restricted {
                    schema_ddl_authorized = true;
                }
                Authorization::Allow
            }
        }

        // Caller SQL must never control an actor-owned transaction/savepoint.
        // Internal guard commands run only with this authorizer uninstalled.
        AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } => Authorization::Deny,

        AuthAction::Select => {
            if tier.schema_restricted && !schema_ddl_authorized {
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
    fn create_index_denied_with_write_ability() {
        // TC-1581: `write` no longer runs schema-changing actions. CREATE
        // [UNIQUE] INDEX fires CreateIndex followed by Reindex.
        let create_index = AuthAction::CreateIndex {
            index_name: "uq_interaction_nonce",
            table_name: "interaction",
        };
        let reindex = AuthAction::Reindex {
            index_name: "uq_interaction_nonce",
        };

        assert_eq!(
            authorize("tinycloud.sql/write", false, create_index),
            Authorization::Deny
        );
        assert_eq!(
            authorize("tinycloud.sql/write", false, reindex),
            Authorization::Deny
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
    fn tc626_review_authorizer_denies_caller_transaction_control() {
        for sql in [
            "RELEASE tinycloud_storage_guard",
            "RELEASE SAVEPOINT tinycloud_storage_guard",
            "ROLLBACK",
            "ROLLBACK TO tinycloud_storage_guard",
            "COMMIT",
            "END",
            "SAVEPOINT caller_savepoint",
            "BEGIN",
        ] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch(
                "CREATE TABLE data (value TEXT);
                 SAVEPOINT tinycloud_storage_guard;
                 INSERT INTO data VALUES ('pending');",
            )
            .unwrap();
            let error = execute_under_authorizer(&conn, "tinycloud.sql/admin", true, sql)
                .expect_err("caller transaction control must be denied by SQLite");
            assert!(
                matches!(
                    error,
                    rusqlite::Error::SqliteFailure(code, _)
                        if code.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
                ),
                "transaction control was not rejected by the authorizer: {sql}"
            );
            assert!(!conn.is_autocommit(), "caller closed the guard: {sql}");
            conn.execute_batch(
                "ROLLBACK TO tinycloud_storage_guard; RELEASE tinycloud_storage_guard",
            )
            .unwrap();
            let count: i64 = conn
                .query_row("SELECT count(*) FROM data", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 0, "internal rollback must still work after {sql}");
        }
    }

    #[test]
    fn create_unique_index_blocked_with_write_cap() {
        // End-to-end against real SQLite: `write` alone does not build an index.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE interaction (reader_did TEXT, nonce TEXT)")
            .unwrap();

        let err = execute_under_authorizer(
            &conn,
            "tinycloud.sql/write",
            false,
            "CREATE UNIQUE INDEX uq_interaction_nonce ON interaction (reader_did, nonce)",
        )
        .expect_err("CREATE UNIQUE INDEX must be denied for a write cap");
        assert!(err.to_string().contains("not authorized"), "{err}");
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
        // Set up the table directly, then attempt the index under a
        // read-only cap: SQLite must report "not authorized".
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE interaction (reader_did TEXT, nonce TEXT)")
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

/// TC-1581: schema-changing statements need `schema`; `write` is data only.
#[cfg(test)]
mod ddl_authority_tests {
    use super::*;

    fn authorize(ability: &str, is_admin: bool, action: AuthAction<'_>) -> Authorization {
        let mut auth = create_authorizer_scoped(
            None,
            &authority_for(&[ability], is_admin),
            StatementScope::default(),
        );
        auth(AuthContext {
            action,
            database_name: Some("main"),
            accessor: None,
        })
    }

    fn execute_under_authorizer(
        conn: &rusqlite::Connection,
        ability: &str,
        is_admin: bool,
        sql: &str,
    ) -> rusqlite::Result<()> {
        execute_under_authority(conn, &authority_for(&[ability], is_admin), sql)
    }

    fn authority_for(abilities: &[&str], is_admin: bool) -> SqlAuthority {
        let mut held: Vec<String> = abilities.iter().map(|a| a.to_string()).collect();
        if is_admin {
            held.push("tinycloud.sql/admin".to_string());
        }
        SqlAuthority::new(held)
    }

    fn authorize_held(abilities: &[&str], action: AuthAction<'_>) -> Authorization {
        let mut auth = create_authorizer_scoped(
            None,
            &authority_for(abilities, false),
            StatementScope::default(),
        );
        auth(AuthContext {
            action,
            database_name: Some("main"),
            accessor: None,
        })
    }

    #[test]
    fn create_index_needs_schema_authority_not_write() {
        // CREATE [UNIQUE] INDEX fires CreateIndex followed by Reindex while the
        // index is built; both must pass for the statement to succeed.
        let create_index = || AuthAction::CreateIndex {
            index_name: "uq_interaction_nonce",
            table_name: "interaction",
        };
        let reindex = || AuthAction::Reindex {
            index_name: "uq_interaction_nonce",
        };

        // TC-1581: `write` no longer runs schema-changing actions.
        assert_eq!(
            authorize("tinycloud.sql/write", false, create_index()),
            Authorization::Deny
        );
        assert_eq!(
            authorize("tinycloud.sql/write", false, reindex()),
            Authorization::Deny
        );
        // A holder of both abilities is unaffected.
        let both = ["tinycloud.sql/write", "tinycloud.sql/schema"];
        assert_eq!(authorize_held(&both, create_index()), Authorization::Allow);
        assert_eq!(authorize_held(&both, reindex()), Authorization::Allow);
    }

    /// Install the authorizer on a real rusqlite connection (mirroring the
    /// wiring in database.rs) and run `sql` under the given abilities. The
    /// statement scope comes from the parser, as in `handle_message`.
    fn execute_under_held(
        conn: &rusqlite::Connection,
        abilities: &[&str],
        sql: &str,
    ) -> rusqlite::Result<()> {
        execute_under_authority(conn, &authority_for(abilities, false), sql)
    }

    fn execute_under_authority(
        conn: &rusqlite::Connection,
        authority: &SqlAuthority,
        sql: &str,
    ) -> rusqlite::Result<()> {
        let scope = crate::sql::parser::classify_sql(sql)
            .map(|class| StatementScope {
                is_ddl: class.is_ddl,
                is_read_only: class.is_read_only,
            })
            .unwrap_or_default();
        conn.authorizer(Some(create_authorizer_scoped(None, authority, scope)));
        let result = conn.execute_batch(sql);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        result
    }

    #[test]
    fn create_unique_index_executes_with_write_and_schema() {
        // End-to-end against real SQLite: the CreateIndex -> Reindex callback
        // sequence fired while building the index must pass for a holder of
        // both abilities (the SDK's `[write, schema]` invocation).
        let both = ["tinycloud.sql/write", "tinycloud.sql/schema"];
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        execute_under_held(
            &conn,
            &both,
            "CREATE TABLE interaction (reader_did TEXT, nonce TEXT)",
        )
        .unwrap();

        execute_under_held(
            &conn,
            &both,
            "CREATE UNIQUE INDEX uq_interaction_nonce ON interaction (reader_did, nonce)",
        )
        .expect("CREATE UNIQUE INDEX should succeed with write and schema");
    }

    #[test]
    fn create_unique_index_blocked_without_schema_authority() {
        // Set up the table directly, then attempt the index under a read-only
        // cap and under write alone: SQLite must report "not authorized".
        for ability in ["tinycloud.sql/read", "tinycloud.sql/write"] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE interaction (reader_did TEXT, nonce TEXT)")
                .unwrap();

            let err = execute_under_authorizer(
                &conn,
                ability,
                false,
                "CREATE UNIQUE INDEX uq_interaction_nonce ON interaction (reader_did, nonce)",
            )
            .expect_err("CREATE UNIQUE INDEX must be denied without schema authority");
            assert!(
                err.to_string().contains("not authorized"),
                "expected an authorization error for {ability}, got: {err}"
            );
        }
    }

    const WRITE: &str = "tinycloud.sql/write";
    const SCHEMA: &str = "tinycloud.sql/schema";
    const READ: &str = "tinycloud.sql/read";

    /// One SQLite action per schema-changing callback the authorizer gates.
    fn schema_changing_actions() -> Vec<AuthAction<'static>> {
        vec![
            AuthAction::CreateTable { table_name: "t" },
            AuthAction::CreateTempTable { table_name: "t" },
            AuthAction::CreateIndex {
                index_name: "i",
                table_name: "t",
            },
            AuthAction::CreateTempIndex {
                index_name: "i",
                table_name: "t",
            },
            AuthAction::CreateView { view_name: "v" },
            AuthAction::CreateTempView { view_name: "v" },
            AuthAction::DropTable { table_name: "t" },
            AuthAction::DropTempTable { table_name: "t" },
            AuthAction::DropIndex {
                index_name: "i",
                table_name: "t",
            },
            AuthAction::DropTempIndex {
                index_name: "i",
                table_name: "t",
            },
            AuthAction::DropView { view_name: "v" },
            AuthAction::DropTempView { view_name: "v" },
            AuthAction::AlterTable {
                database_name: "main",
                table_name: "t",
            },
            AuthAction::DropTrigger {
                trigger_name: "g",
                table_name: "t",
            },
            AuthAction::DropTempTrigger {
                trigger_name: "g",
                table_name: "t",
            },
            AuthAction::Reindex { index_name: "i" },
        ]
    }

    #[test]
    fn every_schema_changing_action_needs_a_schema_conferring_ability() {
        for (abilities, expected) in [
            (&[WRITE][..], Authorization::Deny),
            (&[READ][..], Authorization::Deny),
            (&[READ, WRITE][..], Authorization::Deny),
            (&["tinycloud.sql/ddl"][..], Authorization::Deny),
            (&[SCHEMA][..], Authorization::Allow),
            (&[WRITE, SCHEMA][..], Authorization::Allow),
            (&["tinycloud.sql/admin"][..], Authorization::Allow),
            (&["tinycloud.sql/*"][..], Authorization::Allow),
        ] {
            for action in schema_changing_actions() {
                let label = format!("{abilities:?} {action:?}");
                assert_eq!(authorize_held(abilities, action), expected, "{label}");
            }
        }
    }

    #[test]
    fn the_authorizer_denies_create_trigger_for_every_ability() {
        for abilities in [
            &[WRITE][..],
            &[SCHEMA][..],
            &[WRITE, SCHEMA][..],
            &["tinycloud.sql/admin"][..],
            &["tinycloud.sql/*"][..],
        ] {
            for action in [
                AuthAction::CreateTrigger {
                    trigger_name: "g",
                    table_name: "t",
                },
                AuthAction::CreateTempTrigger {
                    trigger_name: "g",
                    table_name: "t",
                },
            ] {
                assert_eq!(
                    authorize_held(abilities, action),
                    Authorization::Deny,
                    "{abilities:?}"
                );
            }
        }

        // End to end: SQLite really calls the authorizer for CREATE TRIGGER,
        // so a statement the parser could one day accept is still refused.
        for abilities in [&[WRITE, SCHEMA][..], &["tinycloud.sql/admin"][..]] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE t (a); CREATE TABLE log (a)")
                .unwrap();
            let error = execute_under_held(
                &conn,
                abilities,
                "CREATE TRIGGER g AFTER INSERT ON t BEGIN INSERT INTO log VALUES (1); END",
            )
            .expect_err("CREATE TRIGGER must be denied");
            assert!(error.to_string().contains("not authorized"), "{error}");
            let triggers: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE type = 'trigger'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(triggers, 0);
        }
    }

    #[test]
    fn a_misclassifying_parser_cannot_give_write_the_schema_actions() {
        // Defence in depth: hand the authorizer a scope in which the parser
        // called every statement plain data (or read-only). Write alone must
        // still be refused by SQLite's own callbacks, and nothing may change.
        let setup = "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT);
                     CREATE VIEW v AS SELECT a FROM t;
                     CREATE INDEX ix ON t (b);
                     INSERT INTO t VALUES (1, 'x')";
        let attacks = [
            "CREATE TABLE made (a)",
            "CREATE TEMP TABLE made (a)",
            "CREATE TABLE made AS SELECT a FROM t",
            "CREATE VIEW w AS SELECT a FROM t",
            "CREATE INDEX iy ON t (a)",
            "ALTER TABLE t ADD COLUMN c",
            "ALTER TABLE t RENAME TO renamed",
            "DROP TABLE t",
            "DROP VIEW v",
            "DROP INDEX ix",
        ];
        for scope in [
            StatementScope::default(),
            StatementScope {
                is_ddl: false,
                is_read_only: true,
            },
        ] {
            for sql in attacks {
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                conn.execute_batch(setup).unwrap();
                let before: String = conn
                    .query_row(
                        "SELECT group_concat(name) FROM sqlite_schema ORDER BY name",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();

                conn.authorizer(Some(create_authorizer_scoped(
                    None,
                    &authority_for(&[WRITE], false),
                    scope,
                )));
                let result = conn.execute_batch(sql);
                conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                let error = result.expect_err(sql);
                assert!(
                    error.to_string().contains("not authorized"),
                    "{sql}: {error}"
                );

                let after: String = conn
                    .query_row(
                        "SELECT group_concat(name) FROM sqlite_schema ORDER BY name",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(before, after, "{sql} changed the schema");
                let rows: i64 = conn
                    .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
                    .unwrap_or(1);
                assert_eq!(rows, 1, "{sql} changed the data");
            }
        }
    }

    #[test]
    fn write_alone_still_runs_data_statements_end_to_end() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a INTEGER PRIMARY KEY AUTOINCREMENT, b TEXT)")
            .unwrap();
        for sql in [
            "INSERT INTO t (b) VALUES ('one')",
            "INSERT OR REPLACE INTO t (a, b) VALUES (1, 'uno')",
            "UPDATE t SET b = 'two' WHERE a = 1",
            "WITH c AS (SELECT 'three' AS b) INSERT INTO t (b) SELECT b FROM c",
            "SELECT a, b FROM t",
            "DELETE FROM t WHERE a = 1",
        ] {
            execute_under_held(&conn, &[WRITE], sql)
                .unwrap_or_else(|error| panic!("write must run {sql}: {error}"));
        }
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn write_and_schema_together_run_schema_changes_with_write_tier_reads() {
        // The SDK's `[write, schema]` invocation: DDL runs under the holder's
        // data authority too, so CREATE TABLE AS SELECT keeps working.
        let both = [WRITE, SCHEMA];
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE source (id INTEGER); INSERT INTO source VALUES (1)")
            .unwrap();
        for sql in [
            "CREATE TABLE copied AS SELECT id FROM source",
            "CREATE INDEX copied_id ON copied (id)",
            "ALTER TABLE copied ADD COLUMN extra TEXT",
            "CREATE VIEW copied_ids AS SELECT id FROM copied",
            "DROP VIEW copied_ids",
            "DROP TABLE copied",
        ] {
            execute_under_held(&conn, &both, sql)
                .unwrap_or_else(|error| panic!("{both:?} must run {sql}: {error}"));
        }
    }

    #[test]
    fn log_and_off_policies_keep_write_able_to_change_the_schema() {
        use crate::sql::authority::DdlPolicy;
        for policy in [DdlPolicy::Log, DdlPolicy::Off] {
            let authority = authority_for(&[WRITE], false).with_ddl_policy(policy);
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            for sql in [
                "CREATE TABLE t (a)",
                "ALTER TABLE t ADD COLUMN b",
                "DROP TABLE t",
            ] {
                execute_under_authority(&conn, &authority, sql)
                    .unwrap_or_else(|error| panic!("{policy:?} must run {sql}: {error}"));
            }
            // Read still cannot.
            let read = authority_for(&[READ], false).with_ddl_policy(policy);
            assert!(execute_under_authority(&conn, &read, "CREATE TABLE u (a)").is_err());
        }
    }

    const SCHEMA_TABLES: [&str; 4] = [
        "sqlite_master",
        "sqlite_schema",
        "sqlite_temp_master",
        "sqlite_temp_schema",
    ];

    fn schema_table_writes(table: &'static str) -> [AuthAction<'static>; 3] {
        [
            AuthAction::Insert { table_name: table },
            AuthAction::Update {
                table_name: table,
                column_name: "sql",
            },
            AuthAction::Delete { table_name: table },
        ]
    }

    fn authorize_scoped(
        abilities: &[&str],
        scope: StatementScope,
        action: AuthAction<'_>,
    ) -> Authorization {
        let mut auth = create_authorizer_scoped(None, &authority_for(abilities, false), scope);
        auth(AuthContext {
            action,
            database_name: Some("main"),
            accessor: None,
        })
    }

    /// TC-1586: `write` is a data ability. It does not write SQLite's own
    /// schema tables, whatever the connection's `writable_schema` says.
    #[test]
    fn write_does_not_write_the_sqlite_schema_tables() {
        let data = StatementScope {
            is_ddl: false,
            is_read_only: false,
        };
        for table in SCHEMA_TABLES {
            for abilities in [&[WRITE][..], &[READ, WRITE][..], &["tinycloud.sql/*"][..]] {
                // `*` is admin-equivalent and keeps its authority.
                let expected = if abilities == ["tinycloud.sql/*"] {
                    Authorization::Allow
                } else {
                    Authorization::Deny
                };
                for action in schema_table_writes(table) {
                    let label = format!("{abilities:?} {action:?}");
                    assert_eq!(
                        authorize_scoped(abilities, data, action),
                        expected,
                        "{label}"
                    );
                }
            }
            // Application tables are unaffected.
            assert_eq!(
                authorize_scoped(
                    &[WRITE],
                    data,
                    AuthAction::Insert {
                        table_name: "notes"
                    }
                ),
                Authorization::Allow
            );
        }
    }

    #[test]
    fn schema_changes_still_write_the_sqlite_schema_tables() {
        let ddl = StatementScope {
            is_ddl: true,
            is_read_only: false,
        };
        for table in SCHEMA_TABLES {
            for abilities in [
                &[SCHEMA][..],
                &[WRITE, SCHEMA][..],
                &["tinycloud.sql/admin"][..],
            ] {
                for action in schema_table_writes(table) {
                    let label = format!("{abilities:?} {action:?}");
                    assert_eq!(
                        authorize_scoped(abilities, ddl, action),
                        Authorization::Allow,
                        "{label}"
                    );
                }
            }
            // Write alone is refused the schema change itself, so it never
            // reaches these callbacks with DDL authority.
            for action in schema_table_writes(table) {
                assert_eq!(authorize_scoped(&[WRITE], ddl, action), Authorization::Deny);
            }
        }
    }

    /// With `writable_schema` ON a connection lets SQL edit `sqlite_master`.
    /// The authorizer still refuses a data statement.
    #[test]
    fn write_cannot_edit_sqlite_master_even_when_the_connection_allows_it() {
        for sql in [
            "UPDATE sqlite_master SET name = 'renamed' WHERE name = 'items'",
            "UPDATE sqlite_master SET sql = 'CREATE TABLE items (id)' WHERE name = 'items'",
            "DELETE FROM sqlite_master WHERE name = 'items'",
            "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', 'fake', 'fake', 0, 'CREATE TABLE fake (id)')",
        ] {
            for abilities in [&[WRITE][..], &[READ, WRITE][..]] {
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                conn.execute_batch(
                    "CREATE TABLE items (id INTEGER); INSERT INTO items VALUES (1); PRAGMA writable_schema = ON;",
                )
                .unwrap();
                let before: String = conn
                    .query_row(
                        "SELECT group_concat(name || ':' || sql) FROM sqlite_schema",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();

                let error = execute_under_held(&conn, abilities, sql)
                    .expect_err("write must not edit sqlite_master");
                assert!(error.to_string().contains("not authorized"), "{sql}: {error}");

                let after: String = conn
                    .query_row(
                        "SELECT group_concat(name || ':' || sql) FROM sqlite_schema",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(before, after, "{sql}");
            }
        }
    }

    /// A table-valued `pragma_*` function reads SQLite's schema through
    /// callbacks on the schema tables the first time a connection uses it.
    /// Closing the schema tables to data statements must not break it.
    #[test]
    fn pragma_table_functions_still_work_for_write() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER, body TEXT)")
            .unwrap();
        for abilities in [&[WRITE][..], &[READ][..], &[READ, WRITE][..]] {
            execute_under_held(
                &conn,
                abilities,
                "SELECT name FROM pragma_table_info('items')",
            )
            .unwrap_or_else(|e| panic!("{abilities:?}: {e}"));
        }
        // Only the whitelisted PRAGMAs are reachable that way.
        let error = execute_under_held(&conn, &[WRITE], "SELECT * FROM pragma_function_list")
            .expect_err("a PRAGMA outside the whitelist stays denied");
        assert!(error.to_string().contains("not authorized"), "{error}");
    }

    /// An unregistered `tinycloud.sql/*` URN confers nothing: beside `schema`
    /// the holder is still schema-only (no data reads or writes, no CTAS copy).
    #[test]
    fn an_unregistered_ability_beside_schema_keeps_the_schema_only_rules() {
        const UNREGISTERED: &str = "tinycloud.sql/not-a-registered-ability";
        for abilities in [&[SCHEMA][..], &[SCHEMA, UNREGISTERED][..]] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE source (id INTEGER); INSERT INTO source VALUES (1)")
                .unwrap();
            for sql in [
                "INSERT INTO source VALUES (2)",
                "UPDATE source SET id = 3",
                "DELETE FROM source",
                "SELECT id FROM source",
                "CREATE TABLE copied AS SELECT id FROM source",
            ] {
                let error = execute_under_held(&conn, abilities, sql)
                    .expect_err("schema authority stays schema-only");
                let message = error.to_string();
                assert!(
                    message.contains("not authorized") || message.contains("is prohibited"),
                    "{abilities:?} {sql}: {error}"
                );
            }
            execute_under_held(&conn, abilities, "CREATE TABLE made (id INTEGER)").unwrap();
        }
    }

    fn pragma_action(abilities: &[&str], name: &str, value: Option<&str>) -> (Authorization, bool) {
        let tracker = PragmaTracker::default();
        let mut auth = create_authorizer_tracked(
            None,
            &authority_for(abilities, false),
            StatementScope::default(),
            tracker.clone(),
        );
        let verdict = auth(AuthContext {
            action: AuthAction::Pragma {
                pragma_name: name,
                pragma_value: value,
            },
            database_name: None,
            accessor: None,
        });
        (verdict, tracker.load(Ordering::Relaxed))
    }

    #[test]
    fn plain_schema_reports_are_open_and_not_tracked() {
        for abilities in [&[WRITE][..], &[READ][..], &["tinycloud.sql/admin"][..]] {
            for name in ["table_info", "TABLE_INFO", "index_list", "foreign_key_list"] {
                assert_eq!(
                    pragma_action(abilities, name, Some("t")),
                    (Authorization::Allow, false),
                    "{abilities:?} {name}"
                );
            }
        }
    }

    #[test]
    fn an_admin_may_run_only_the_allow_listed_pragmas() {
        for abilities in [&["tinycloud.sql/admin"][..], &["tinycloud.sql/*"][..]] {
            // Header values, checks and reports: allowed, and tracked so the
            // connection is reset after the request.
            for (name, value) in [
                ("user_version", Some("3")),
                ("USER_VERSION", None),
                ("application_id", Some("1")),
                ("integrity_check", Some("10")),
                ("quick_check", None),
                ("foreign_key_check", Some("t")),
                ("journal_mode", None),
                ("foreign_keys", None),
            ] {
                assert_eq!(
                    pragma_action(abilities, name, value),
                    (Authorization::Allow, true),
                    "{abilities:?} {name}"
                );
            }
            // Anything that would set connection-level or process-wide
            // state, or run maintenance, is refused.
            for (name, value) in [
                ("writable_schema", Some("ON")),
                ("journal_mode", Some("DELETE")),
                ("foreign_keys", Some("OFF")),
                ("query_only", Some("1")),
                ("max_page_count", Some("1")),
                ("cache_spill", Some("0")),
                ("locking_mode", Some("EXCLUSIVE")),
                ("synchronous", Some("OFF")),
                ("soft_heap_limit", Some("1")),
                ("hard_heap_limit", Some("1")),
                ("temp_store_directory", Some("x")),
                ("wal_checkpoint", Some("TRUNCATE")),
                ("wal_checkpoint", None),
                ("incremental_vacuum", None),
                ("optimize", None),
                ("not_a_pragma", None),
            ] {
                assert_eq!(
                    pragma_action(abilities, name, value),
                    (Authorization::Deny, false),
                    "{abilities:?} {name} {value:?}"
                );
            }
        }
    }

    #[test]
    fn only_an_admin_runs_pragmas_beyond_the_schema_reports() {
        for abilities in [
            &[WRITE][..],
            &[SCHEMA][..],
            &[WRITE, SCHEMA][..],
            &[READ][..],
        ] {
            for (name, value) in [("user_version", Some("3")), ("journal_mode", None)] {
                assert_eq!(
                    pragma_action(abilities, name, value),
                    (Authorization::Deny, false),
                    "{abilities:?} {name}"
                );
            }
        }
    }

    /// A pure query gets only the one schema-table UPDATE SQLite makes for a
    /// `pragma_*` function; it never gets INSERT or DELETE there.
    #[test]
    fn a_read_only_statement_may_only_update_the_schema_tables() {
        let read = StatementScope {
            is_ddl: false,
            is_read_only: true,
        };
        for table in SCHEMA_TABLES {
            for abilities in [&[READ][..], &[WRITE][..], &[READ, WRITE][..]] {
                let [insert, update, delete] = schema_table_writes(table);
                assert_eq!(
                    authorize_scoped(abilities, read, update),
                    Authorization::Allow,
                    "{abilities:?} {table}"
                );
                assert_eq!(
                    authorize_scoped(abilities, read, insert),
                    Authorization::Deny,
                    "{abilities:?} {table}"
                );
                assert_eq!(
                    authorize_scoped(abilities, read, delete),
                    Authorization::Deny,
                    "{abilities:?} {table}"
                );
            }
        }
    }
}
