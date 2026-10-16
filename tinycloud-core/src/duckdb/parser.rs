use std::ops::ControlFlow;

use sqlparser::ast::*;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use super::caveats::DuckDbCaveats;
use super::types::DuckDbError;
use crate::policy_capability::{ability_matches, resolve_alias};
use crate::write_hooks::TouchedTables;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteTargets {
    Supported(Vec<String>),
    Unsupported,
}

pub struct ParsedQuery {
    pub statements: Vec<Statement>,
    pub referenced_tables: Vec<String>,
    pub referenced_columns: Vec<String>,
    pub write_targets: Vec<TouchedTables>,
    pub is_read_only: bool,
    pub is_ddl: bool,
}

fn ascii_prefix(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn node_controlled_setting(name: &str) -> bool {
    [
        "profil",
        "logging_",
        "log_",
        "enable_profil",
        "disable_profil",
        "debug_",
        "verify_",
        "disable_verify_",
    ]
    .iter()
    .any(|prefix| ascii_prefix(name, prefix))
        || [
            "enable_logging",
            "disable_logging",
            "enable_http_logging",
            "http_logging_output",
            "enable_verification",
            "disable_verification",
            "enable_progress_bar",
            "disable_progress_bar",
            "enable_print_progress_bar",
            "disable_print_progress_bar",
            "progress_bar_time",
            "enable_external_access",
            "allow_unsigned_extensions",
            "lock_configuration",
        ]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn diagnostic_function(name: &ObjectName) -> bool {
    name.0.last().is_some_and(|ident| {
        [
            "enable_logging",
            "disable_logging",
            "write_log",
            "truncate_duckdb_logs",
            // Dynamic SQL strings cannot bypass structural statement checks.
            "query",
        ]
        .iter()
        .any(|reserved| ident.value.eq_ignore_ascii_case(reserved))
    })
}

struct DiagnosticPolicy;

impl Visitor for DiagnosticPolicy {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        let prohibited = match statement {
            Statement::SetVariable { variable: name, .. } | Statement::Pragma { name, .. } => name
                .0
                .last()
                .is_some_and(|ident| node_controlled_setting(&ident.value)),
            Statement::Call(function) => diagnostic_function(&function.name),
            _ => false,
        };
        if prohibited {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if matches!(expression, Expr::Function(function) if diagnostic_function(&function.name)) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        let prohibited = match factor {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            }
            | TableFactor::Function { name, .. } => diagnostic_function(name),
            _ => false,
        };
        if prohibited {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

fn check_diagnostic_statements(statements: &[Statement]) -> Result<(), DuckDbError> {
    for statement in statements {
        if statement.visit(&mut DiagnosticPolicy).is_break() {
            return Err(DuckDbError::PermissionDenied(
                "Database diagnostic controls are reserved for the node".into(),
            ));
        }
    }
    Ok(())
}

/// Validates persisted tenant SQL without executing it or granting an ability.
pub(crate) fn validate_diagnostic_sql(sql: &str) -> Result<(), DuckDbError> {
    let statements = Parser::parse_sql(&GenericDialect {}, sql).map_err(|_| {
        DuckDbError::PermissionDenied(
            "Stored SQL does not satisfy the node statement policy".into(),
        )
    })?;
    check_diagnostic_statements(&statements)
}

pub fn validate_sql(
    sql: &str,
    caveats: &Option<DuckDbCaveats>,
    ability: &str,
) -> Result<ParsedQuery, DuckDbError> {
    // TC-119: registry-aware capability tiers. `duckdb/*` implies every duckdb
    // action, so it confers admin and write. `duckdb/admin` does NOT imply
    // write in the registry, so `has_write` keeps admin via the `is_admin`
    // term — reproducing the prior `admin | write | *` set exactly.
    let is_admin = ability_matches(ability, "tinycloud.duckdb/admin");
    let has_write = is_admin || ability_matches(ability, "tinycloud.duckdb/write");

    let dialect = GenericDialect {};
    let statements =
        Parser::parse_sql(&dialect, sql).map_err(|e| DuckDbError::ParseError(e.to_string()))?;

    if statements.is_empty() {
        return Err(DuckDbError::ParseError("Empty SQL statement".to_string()));
    }
    // Invocation-provided templates are data, never authority. Every tier and
    // every nested statement/function follows the same diagnostic boundary.
    check_diagnostic_statements(&statements)?;

    let mut tables = Vec::new();
    let mut columns = Vec::new();
    let mut write_targets = Vec::new();
    let mut is_read_only = true;
    let mut is_ddl = false;

    for stmt in &statements {
        if !is_admin {
            check_statement_allowed(stmt, has_write)?;
        }

        classify_statement(
            stmt,
            &mut tables,
            &mut columns,
            &mut is_read_only,
            &mut is_ddl,
        );
        if let Some(targets) = extract_write_targets_from_statement(stmt) {
            write_targets.push(targets);
        }
    }

    // Function blocklist (defense in depth)
    check_blocked_functions(sql, is_admin)?;

    // DDL requires write ability
    if is_ddl && !has_write {
        return Err(DuckDbError::PermissionDenied(
            "DDL operations require write or admin ability".to_string(),
        ));
    }

    // Exact-tier restriction: read-tier (`read`, or its `select` alias) cannot
    // run a write. Exact by design — `duckdb/*` implies read but must still
    // permit writes, so this must not use `ability_matches`.
    if !is_read_only && resolve_alias(ability) == "tinycloud.duckdb/read" {
        return Err(DuckDbError::ReadOnlyViolation);
    }

    // Validate caveats
    if let Some(caveats) = caveats {
        apply_caveat_checks(caveats, &tables, &columns, is_read_only)?;
    }

    tables.dedup();
    columns.dedup();

    Ok(ParsedQuery {
        statements,
        referenced_tables: tables,
        referenced_columns: columns,
        write_targets,
        is_read_only,
        is_ddl,
    })
}

pub fn extract_write_targets(sql: &str) -> Result<WriteTargets, DuckDbError> {
    let dialect = GenericDialect {};
    let statements =
        Parser::parse_sql(&dialect, sql).map_err(|e| DuckDbError::ParseError(e.to_string()))?;

    if statements.is_empty() {
        return Err(DuckDbError::ParseError("Empty SQL statement".to_string()));
    }

    let mut tables = Vec::new();
    let mut saw_supported_write = false;

    for stmt in &statements {
        match collect_write_targets_from_statement(stmt, &mut tables) {
            CollectWriteTargets::Supported => saw_supported_write = true,
            CollectWriteTargets::Unsupported => return Ok(WriteTargets::Unsupported),
        }
    }

    if !saw_supported_write || tables.is_empty() {
        return Ok(WriteTargets::Unsupported);
    }

    tables.sort();
    tables.dedup();
    Ok(WriteTargets::Supported(tables))
}

enum CollectWriteTargets {
    Supported,
    Unsupported,
}

fn collect_write_targets_from_statement(
    stmt: &Statement,
    tables: &mut Vec<String>,
) -> CollectWriteTargets {
    match stmt {
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => collect_write_targets_from_statement(statement, tables),
        Statement::Insert { table_name, .. } => {
            tables.push(table_name.to_string());
            CollectWriteTargets::Supported
        }
        Statement::Update { table, .. } => {
            if let Some(name) = table_target_name(table) {
                tables.push(name);
                CollectWriteTargets::Supported
            } else {
                CollectWriteTargets::Unsupported
            }
        }
        Statement::Delete { from, .. } => match from {
            FromTable::WithFromKeyword(from_items) | FromTable::WithoutKeyword(from_items) => {
                if from_items.len() != 1 {
                    return CollectWriteTargets::Unsupported;
                }

                if let Some(name) = table_target_name(&from_items[0]) {
                    tables.push(name);
                    CollectWriteTargets::Supported
                } else {
                    CollectWriteTargets::Unsupported
                }
            }
        },
        Statement::CreateTable { name, .. } => {
            tables.push(name.to_string());
            CollectWriteTargets::Supported
        }
        Statement::CreateView { name, .. } => {
            tables.push(name.to_string());
            CollectWriteTargets::Supported
        }
        Statement::AlterTable { name, .. } => {
            tables.push(name.to_string());
            CollectWriteTargets::Supported
        }
        Statement::Drop { names, .. } => {
            for name in names {
                tables.push(name.to_string());
            }
            CollectWriteTargets::Supported
        }
        Statement::CreateIndex { table_name, .. } => {
            tables.push(table_name.to_string());
            CollectWriteTargets::Supported
        }
        _ => CollectWriteTargets::Unsupported,
    }
}

fn table_target_name(table: &TableWithJoins) -> Option<String> {
    match &table.relation {
        TableFactor::Table { name, .. } => Some(name.to_string()),
        _ => None,
    }
}

/// Classify a statement: extract tables/columns, set read_only/ddl flags.
/// Does NOT enforce allowlist — that is done separately.
fn classify_statement(
    stmt: &Statement,
    tables: &mut Vec<String>,
    columns: &mut Vec<String>,
    is_read_only: &mut bool,
    is_ddl: &mut bool,
) {
    match stmt {
        Statement::Explain {
            analyze, statement, ..
        } => {
            let mut inner_read_only = true;
            let mut inner_ddl = false;
            classify_statement(
                statement,
                tables,
                columns,
                &mut inner_read_only,
                &mut inner_ddl,
            );
            if *analyze {
                *is_read_only &= inner_read_only;
                *is_ddl |= inner_ddl;
            }
        }
        Statement::Query(_) => {
            extract_tables_from_statement(stmt, tables);
            extract_columns_from_statement(stmt, columns);
        }
        Statement::Insert { .. } => {
            *is_read_only = false;
            extract_tables_from_statement(stmt, tables);
        }
        Statement::Update { .. } => {
            *is_read_only = false;
            extract_tables_from_statement(stmt, tables);
            extract_columns_from_statement(stmt, columns);
        }
        Statement::Delete { .. } => {
            *is_read_only = false;
            extract_tables_from_statement(stmt, tables);
        }
        Statement::CreateTable { .. }
        | Statement::AlterTable { .. }
        | Statement::Drop { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateView { .. } => {
            *is_read_only = false;
            *is_ddl = true;
            extract_tables_from_statement(stmt, tables);
        }
        Statement::SetVariable { .. } => {
            *is_read_only = false;
        }
        _ => {}
    }
}

fn apply_caveat_checks(
    caveats: &DuckDbCaveats,
    tables: &[String],
    columns: &[String],
    is_read_only: bool,
) -> Result<(), DuckDbError> {
    if caveats.read_only.unwrap_or(false) && !is_read_only {
        return Err(DuckDbError::ReadOnlyViolation);
    }

    for table in tables {
        if !caveats.is_table_allowed(table) {
            return Err(DuckDbError::PermissionDenied(format!(
                "Access to table '{}' is not allowed",
                table
            )));
        }
    }

    for column in columns {
        if !caveats.is_column_allowed(column) {
            return Err(DuckDbError::PermissionDenied(format!(
                "Access to column '{}' is not allowed",
                column
            )));
        }
    }

    Ok(())
}

/// Tier 1 allowlist: check that the statement type is allowed for non-admin users.
fn check_statement_allowed(stmt: &Statement, has_write: bool) -> Result<(), DuckDbError> {
    match stmt {
        // ANALYZE executes its body; plain EXPLAIN only plans it.
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => check_statement_allowed(statement, has_write),
        // Read operations — any ability
        Statement::Query(_) => Ok(()),
        Statement::ExplainTable { .. } | Statement::Explain { .. } => Ok(()),

        // Write operations — require write ability
        Statement::Insert { .. } | Statement::Update { .. } | Statement::Delete { .. } => {
            if has_write {
                Ok(())
            } else {
                Err(DuckDbError::PermissionDenied(
                    "Write ability required".into(),
                ))
            }
        }

        // DDL — require write ability
        Statement::CreateTable { .. }
        | Statement::CreateView { .. }
        | Statement::CreateIndex { .. } => {
            if has_write {
                Ok(())
            } else {
                Err(DuckDbError::PermissionDenied(
                    "Write ability required".into(),
                ))
            }
        }
        Statement::Drop { .. } | Statement::AlterTable { .. } => {
            if has_write {
                Ok(())
            } else {
                Err(DuckDbError::PermissionDenied(
                    "Write ability required".into(),
                ))
            }
        }

        // Transactions
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. } => Ok(()),

        // Everything else is blocked
        other => Err(DuckDbError::PermissionDenied(format!(
            "Statement type not allowed: {}. Request admin access or a specific delegation.",
            statement_type_name(other)
        ))),
    }
}

/// Defense-in-depth: block function calls that could access external resources.
fn check_blocked_functions(sql: &str, is_admin: bool) -> Result<(), DuckDbError> {
    if is_admin {
        return Ok(());
    }
    let sql_upper = sql.to_uppercase();
    const BLOCKED_FUNCTIONS: &[&str] = &[
        "READ_CSV",
        "READ_PARQUET",
        "READ_JSON",
        "READ_CSV_AUTO",
        "READ_JSON_AUTO",
        "HTTPFS",
        "S3://",
        "HTTP://",
        "HTTPS://",
        "PARQUET_SCAN",
        "CSV_SCAN",
        "JSON_SCAN",
        "READ_BLOB",
        "READ_TEXT",
        "GLOB(",
        "PARQUET_METADATA",
        "SCAN_PARQUET_OBJECTS",
        "ICEBERG_SCAN",
        "DELTA_SCAN",
        "QUERY_TABLE",
    ];
    for pattern in BLOCKED_FUNCTIONS {
        if sql_upper.contains(pattern) {
            return Err(DuckDbError::PermissionDenied(format!(
                "External access function '{}' is not allowed",
                pattern
            )));
        }
    }
    Ok(())
}

/// Return a human-readable name for a statement type.
fn statement_type_name(stmt: &Statement) -> String {
    match stmt {
        Statement::Query(_) => "SELECT".to_string(),
        Statement::Insert { .. } => "INSERT".to_string(),
        Statement::Update { .. } => "UPDATE".to_string(),
        Statement::Delete { .. } => "DELETE".to_string(),
        Statement::CreateTable { .. } => "CREATE TABLE".to_string(),
        Statement::CreateView { .. } => "CREATE VIEW".to_string(),
        Statement::CreateIndex { .. } => "CREATE INDEX".to_string(),
        Statement::Drop { .. } => "DROP".to_string(),
        Statement::AlterTable { .. } => "ALTER TABLE".to_string(),
        Statement::Copy { .. } => "COPY".to_string(),
        Statement::Install { .. } => "INSTALL".to_string(),
        Statement::Load { .. } => "LOAD".to_string(),
        Statement::SetVariable { .. } => "SET".to_string(),
        Statement::AttachDatabase { .. } => "ATTACH".to_string(),
        Statement::StartTransaction { .. } => "BEGIN".to_string(),
        Statement::Commit { .. } => "COMMIT".to_string(),
        Statement::Rollback { .. } => "ROLLBACK".to_string(),
        Statement::Explain { .. } => "EXPLAIN".to_string(),
        Statement::ExplainTable { .. } => "EXPLAIN TABLE".to_string(),
        other => format!("{}", other)
            .split_whitespace()
            .next()
            .unwrap_or("UNKNOWN")
            .to_string(),
    }
}

fn extract_tables_from_statement(stmt: &Statement, tables: &mut Vec<String>) {
    match stmt {
        Statement::Query(query) => {
            extract_tables_from_query(query, tables);
        }
        Statement::Insert { table_name, .. } => {
            tables.push(table_name.to_string());
        }
        Statement::Update { table, .. } => {
            extract_tables_from_table_with_joins(table, tables);
        }
        Statement::Delete { from, .. } => match from {
            FromTable::WithFromKeyword(from_items) | FromTable::WithoutKeyword(from_items) => {
                for item in from_items {
                    extract_tables_from_table_with_joins(item, tables);
                }
            }
        },
        Statement::CreateTable { name, .. } => {
            tables.push(name.to_string());
        }
        Statement::AlterTable { name, .. } => {
            tables.push(name.to_string());
        }
        Statement::Drop { names, .. } => {
            for name in names {
                tables.push(name.to_string());
            }
        }
        Statement::CreateIndex { table_name, .. } => {
            tables.push(table_name.to_string());
        }
        Statement::CreateView { name, .. } => {
            tables.push(name.to_string());
        }
        _ => {}
    }
}

fn extract_tables_from_query(query: &Query, tables: &mut Vec<String>) {
    extract_tables_from_set_expr(&query.body, tables);
}

fn extract_tables_from_set_expr(body: &SetExpr, tables: &mut Vec<String>) {
    match body {
        SetExpr::Select(select) => {
            for item in &select.from {
                extract_tables_from_table_with_joins(item, tables);
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            extract_tables_from_set_expr(left, tables);
            extract_tables_from_set_expr(right, tables);
        }
        SetExpr::Query(query) => {
            extract_tables_from_query(query, tables);
        }
        _ => {}
    }
}

fn extract_tables_from_table_with_joins(twj: &TableWithJoins, tables: &mut Vec<String>) {
    extract_tables_from_table_factor(&twj.relation, tables);
    for join in &twj.joins {
        extract_tables_from_table_factor(&join.relation, tables);
    }
}

fn extract_tables_from_table_factor(factor: &TableFactor, tables: &mut Vec<String>) {
    match factor {
        TableFactor::Table { name, .. } => {
            tables.push(name.to_string());
        }
        TableFactor::Derived { subquery, .. } => {
            extract_tables_from_query(subquery, tables);
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            extract_tables_from_table_with_joins(table_with_joins, tables);
        }
        _ => {}
    }
}

fn extract_columns_from_statement(stmt: &Statement, columns: &mut Vec<String>) {
    match stmt {
        Statement::Query(query) => {
            extract_columns_from_query(query, columns);
        }
        Statement::Update { assignments, .. } => {
            for assignment in assignments {
                for id in &assignment.id {
                    columns.push(id.value.clone());
                }
            }
        }
        _ => {}
    }
}

fn extract_columns_from_query(query: &Query, columns: &mut Vec<String>) {
    if let SetExpr::Select(select) = &*query.body {
        for item in &select.projection {
            match item {
                SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                    columns.push(ident.value.clone());
                }
                SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                    if let Some(last) = parts.last() {
                        columns.push(last.value.clone());
                    }
                }
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => {
                    columns.push("*".to_string());
                }
                _ => {}
            }
        }
    }
}

pub fn extract_write_targets_from_statement(stmt: &Statement) -> Option<TouchedTables> {
    match stmt {
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => extract_write_targets_from_statement(statement),
        Statement::Insert { table_name, .. } => {
            Some(TouchedTables::supported(vec![table_name.to_string()]))
        }
        Statement::Update { table, .. } => extract_write_target_from_update(table),
        Statement::Delete { tables, from, .. } => extract_write_target_from_delete(tables, from),
        Statement::CreateTable { name, .. }
        | Statement::AlterTable { name, .. }
        | Statement::CreateView { name, .. } => {
            Some(TouchedTables::supported(vec![name.to_string()]))
        }
        Statement::Drop { names, .. } => Some(TouchedTables::supported(unique_names(
            names.iter().map(ToString::to_string).collect(),
        ))),
        Statement::CreateIndex { table_name, .. } => {
            Some(TouchedTables::supported(vec![table_name.to_string()]))
        }
        _ => None,
    }
}

fn extract_write_target_from_update(table: &TableWithJoins) -> Option<TouchedTables> {
    match &table.relation {
        TableFactor::Table { name, .. } => Some(TouchedTables::supported(vec![name.to_string()])),
        _ => Some(TouchedTables::unsupported()),
    }
}

fn extract_write_target_from_delete(
    tables: &[ObjectName],
    from: &FromTable,
) -> Option<TouchedTables> {
    if !tables.is_empty() {
        return Some(TouchedTables::supported(unique_names(
            tables.iter().map(ToString::to_string).collect(),
        )));
    }

    let relation = match from {
        FromTable::WithFromKeyword(from_items) | FromTable::WithoutKeyword(from_items) => {
            if from_items.len() != 1 {
                return Some(TouchedTables::unsupported());
            }
            &from_items[0].relation
        }
    };

    match relation {
        TableFactor::Table { name, .. } => Some(TouchedTables::supported(vec![name.to_string()])),
        _ => Some(TouchedTables::unsupported()),
    }
}

fn unique_names(names: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::super::caveats::DuckDbCaveats;
    use super::*;
    use crate::write_hooks::TouchedTables;

    #[test]
    fn test_select_allowed() {
        let result = validate_sql("SELECT * FROM users", &None, "tinycloud.duckdb/read");
        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_allowed_with_write() {
        let result = validate_sql(
            "INSERT INTO users (name) VALUES ('test')",
            &None,
            "tinycloud.duckdb/write",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_denied_without_write() {
        let result = validate_sql(
            "INSERT INTO users (name) VALUES ('test')",
            &None,
            "tinycloud.duckdb/read",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_table_requires_write() {
        let result = validate_sql(
            "CREATE TABLE test (id INTEGER)",
            &None,
            "tinycloud.duckdb/read",
        );
        assert!(result.is_err());
        let result = validate_sql(
            "CREATE TABLE test (id INTEGER)",
            &None,
            "tinycloud.duckdb/write",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_copy_blocked_for_non_admin() {
        let result = validate_sql("COPY users TO 'file.csv'", &None, "tinycloud.duckdb/write");
        assert!(result.is_err());
    }

    #[test]
    fn test_install_blocked() {
        let result = validate_sql("INSTALL httpfs", &None, "tinycloud.duckdb/write");
        assert!(result.is_err());
    }

    #[test]
    fn test_attach_blocked() {
        let result = validate_sql(
            "ATTACH 'other.db' AS other",
            &None,
            "tinycloud.duckdb/write",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_set_security_vars_blocked_for_admin() {
        let result = validate_sql(
            "SET enable_external_access = true",
            &None,
            "tinycloud.duckdb/admin",
        );
        assert!(result.is_err());
        let result = validate_sql(
            "SET allow_unsigned_extensions = true",
            &None,
            "tinycloud.duckdb/admin",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_set_non_security_allowed_for_admin() {
        let result = validate_sql("SET threads = 4", &None, "tinycloud.duckdb/admin");
        assert!(result.is_ok());
    }

    #[test]
    fn test_blocked_functions() {
        let result = validate_sql(
            "SELECT * FROM read_csv('file.csv')",
            &None,
            "tinycloud.duckdb/read",
        );
        assert!(result.is_err());
        let result = validate_sql(
            "SELECT * FROM parquet_scan('file.parquet')",
            &None,
            "tinycloud.duckdb/read",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_blocked_functions_allowed_for_admin() {
        let result = validate_sql(
            "SELECT * FROM read_csv('file.csv')",
            &None,
            "tinycloud.duckdb/admin",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_statements() {
        assert!(validate_sql("BEGIN", &None, "tinycloud.duckdb/read").is_ok());
        assert!(validate_sql("COMMIT", &None, "tinycloud.duckdb/read").is_ok());
        assert!(validate_sql("ROLLBACK", &None, "tinycloud.duckdb/read").is_ok());
    }

    #[test]
    fn test_explain_allowed() {
        let result = validate_sql(
            "EXPLAIN SELECT * FROM users",
            &None,
            "tinycloud.duckdb/read",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_wildcard_blocked_with_column_caveats() {
        let caveats = DuckDbCaveats {
            tables: None,
            columns: Some(vec!["name".to_string(), "email".to_string()]),
            statements: None,
            read_only: None,
        };
        let result = validate_sql(
            "SELECT * FROM users",
            &Some(caveats),
            "tinycloud.duckdb/read",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_specific_columns_allowed_with_caveats() {
        let caveats = DuckDbCaveats {
            tables: None,
            columns: Some(vec!["name".to_string(), "email".to_string()]),
            statements: None,
            read_only: None,
        };
        let result = validate_sql(
            "SELECT name, email FROM users",
            &Some(caveats),
            "tinycloud.duckdb/read",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ddl_requires_write() {
        assert!(validate_sql("DROP TABLE users", &None, "tinycloud.duckdb/read").is_err());
        assert!(validate_sql(
            "ALTER TABLE users ADD COLUMN age INTEGER",
            &None,
            "tinycloud.duckdb/read"
        )
        .is_err());
    }

    #[test]
    fn test_read_only_caveat() {
        let caveats = DuckDbCaveats {
            tables: None,
            columns: None,
            statements: None,
            read_only: Some(true),
        };
        let result = validate_sql(
            "INSERT INTO users (name) VALUES ('test')",
            &Some(caveats),
            "tinycloud.duckdb/write",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_table_caveats() {
        let caveats = DuckDbCaveats {
            tables: Some(vec!["users".to_string()]),
            columns: None,
            statements: None,
            read_only: None,
        };
        assert!(validate_sql(
            "SELECT * FROM users",
            &Some(caveats.clone()),
            "tinycloud.duckdb/read"
        )
        .is_ok());
        assert!(validate_sql(
            "SELECT * FROM secrets",
            &Some(caveats),
            "tinycloud.duckdb/read"
        )
        .is_err());
    }

    #[test]
    fn test_update_write_targets_only_include_target_table() {
        let result = validate_sql(
            "UPDATE users SET name = 'test'",
            &None,
            "tinycloud.duckdb/write",
        )
        .unwrap();

        assert_eq!(
            result.write_targets,
            vec![TouchedTables::supported(vec!["users".to_string()])]
        );
    }

    #[test]
    fn test_delete_write_targets_use_target_table_list() {
        let result = validate_sql(
            "DELETE FROM users WHERE id = 1",
            &None,
            "tinycloud.duckdb/write",
        )
        .unwrap();

        assert_eq!(
            result.write_targets,
            vec![TouchedTables::supported(vec!["users".to_string()])]
        );
    }
}
