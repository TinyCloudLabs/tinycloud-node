use sqlparser::ast::*;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use super::caveats::DuckDbCaveats;
use super::types::DuckDbError;

pub struct ParsedQuery {
    pub statements: Vec<Statement>,
    pub referenced_tables: Vec<String>,
    pub referenced_columns: Vec<String>,
    pub is_read_only: bool,
    pub is_ddl: bool,
}

pub fn validate_sql(
    sql: &str,
    caveats: &Option<DuckDbCaveats>,
    ability: &str,
) -> Result<ParsedQuery, DuckDbError> {
    let is_admin = matches!(ability, "tinycloud.duckdb/admin" | "tinycloud.duckdb/*");
    let has_write = matches!(
        ability,
        "tinycloud.duckdb/write" | "tinycloud.duckdb/admin" | "tinycloud.duckdb/*"
    );

    // Tier 3: Check if SQL is in pre-approved statements list
    if let Some(ref c) = caveats {
        if c.find_statement_by_sql(sql).is_some() {
            // Pre-approved by delegation — skip allowlist check
            // Still apply function blocklist (defense in depth)
            check_blocked_functions(sql, is_admin)?;

            // Parse to extract tables/columns for caveat checks
            let dialect = GenericDialect {};
            let statements = Parser::parse_sql(&dialect, sql)
                .map_err(|e| DuckDbError::ParseError(e.to_string()))?;

            let mut tables = Vec::new();
            let mut columns = Vec::new();
            let mut is_read_only = true;
            let mut is_ddl = false;

            for stmt in &statements {
                classify_statement(
                    stmt,
                    &mut tables,
                    &mut columns,
                    &mut is_read_only,
                    &mut is_ddl,
                );
            }

            // Still apply caveat table/column checks
            apply_caveat_checks(c, &tables, &columns, is_read_only)?;

            tables.dedup();
            columns.dedup();

            return Ok(ParsedQuery {
                statements,
                referenced_tables: tables,
                referenced_columns: columns,
                is_read_only,
                is_ddl,
            });
        }
    }

    // Parse normally
    let dialect = GenericDialect {};
    let statements =
        Parser::parse_sql(&dialect, sql).map_err(|e| DuckDbError::ParseError(e.to_string()))?;

    if statements.is_empty() {
        return Err(DuckDbError::ParseError("Empty SQL statement".to_string()));
    }

    let mut tables = Vec::new();
    let mut columns = Vec::new();
    let mut is_read_only = true;
    let mut is_ddl = false;

    for stmt in &statements {
        // Tier 1/2: Check statement allowlist
        if is_admin {
            check_admin_blocked(stmt)?;
        } else {
            check_statement_allowed(stmt, has_write)?;
        }

        classify_statement(
            stmt,
            &mut tables,
            &mut columns,
            &mut is_read_only,
            &mut is_ddl,
        );
    }

    // Function blocklist (defense in depth)
    check_blocked_functions(sql, is_admin)?;

    // DDL requires write ability
    if is_ddl && !has_write {
        return Err(DuckDbError::PermissionDenied(
            "DDL operations require write or admin ability".to_string(),
        ));
    }

    if !is_read_only && matches!(ability, "tinycloud.duckdb/read" | "tinycloud.duckdb/select") {
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
        is_read_only,
        is_ddl,
    })
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

/// Tier 2: Admin bypass — block only security-critical SET variables.
fn check_admin_blocked(stmt: &Statement) -> Result<(), DuckDbError> {
    if let Statement::SetVariable { variable, .. } = stmt {
        let var_name = variable.to_string().to_uppercase();
        const BLOCKED: &[&str] = &[
            "ENABLE_EXTERNAL_ACCESS",
            "ALLOW_UNSIGNED_EXTENSIONS",
            "ENABLE_LOGGING",
            "LOG_QUERY_PATH",
            "LOCK_CONFIGURATION",
        ];
        if BLOCKED.iter().any(|s| var_name.contains(s)) {
            return Err(DuckDbError::PermissionDenied(format!(
                "Cannot modify security setting: {}",
                variable
            )));
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::super::caveats::{DuckDbCaveats, PreparedStatement};
    use super::*;

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
    fn test_pre_approved_statement_bypass() {
        let caveats = DuckDbCaveats {
            tables: None,
            columns: None,
            statements: Some(vec![PreparedStatement {
                name: "special".to_string(),
                sql: "COPY users TO 'file.csv'".to_string(),
            }]),
            read_only: None,
        };
        // This SQL would normally be blocked, but it's pre-approved
        let result = validate_sql(
            "COPY users TO 'file.csv'",
            &Some(caveats),
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
}
