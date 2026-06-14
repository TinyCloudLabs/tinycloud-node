use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

use super::caveats::SqlCaveats;

pub fn create_authorizer(
    caveats: Option<SqlCaveats>,
    ability: String,
    is_admin: bool,
) -> impl FnMut(AuthContext<'_>) -> Authorization {
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
            if allowed_functions.contains(&function_name) {
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
        AuthAction::Insert { table_name } | AuthAction::Delete { table_name } => {
            if matches!(
                ability.as_str(),
                "tinycloud.sql/read" | "tinycloud.sql/select"
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
            if matches!(
                ability.as_str(),
                "tinycloud.sql/read" | "tinycloud.sql/select"
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
        AuthAction::CreateTable { .. }
        | AuthAction::CreateTempTable { .. }
        | AuthAction::DropTable { .. }
        | AuthAction::DropTempTable { .. }
        | AuthAction::AlterTable { .. }
        | AuthAction::CreateIndex { .. }
        | AuthAction::DropIndex { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::DropView { .. }
        | AuthAction::CreateTempIndex { .. }
        | AuthAction::DropTempIndex { .. }
        | AuthAction::CreateTempTrigger { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        | AuthAction::DropTempView { .. }
        // SQLite fires SQLITE_REINDEX while building an index; gate it like the
        // CreateIndex it accompanies so an authorized CREATE INDEX can complete.
        | AuthAction::Reindex { .. } => {
            if !is_admin && !matches!(ability.as_str(), "tinycloud.sql/write" | "tinycloud.sql/*") {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }

        // Allow internal operations
        AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } | AuthAction::Select => {
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
}
