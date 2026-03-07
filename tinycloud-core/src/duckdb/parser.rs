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

    let is_admin = matches!(ability, "tinycloud.duckdb/admin" | "tinycloud.duckdb/*");

    for stmt in &statements {
        match stmt {
            Statement::Query(_) => {
                extract_tables_from_statement(stmt, &mut tables);
                extract_columns_from_statement(stmt, &mut columns);
            }
            Statement::Insert { .. } => {
                is_read_only = false;
                extract_tables_from_statement(stmt, &mut tables);
            }
            Statement::Update { .. } => {
                is_read_only = false;
                extract_tables_from_statement(stmt, &mut tables);
                extract_columns_from_statement(stmt, &mut columns);
            }
            Statement::Delete { .. } => {
                is_read_only = false;
                extract_tables_from_statement(stmt, &mut tables);
            }
            Statement::CreateTable { .. }
            | Statement::AlterTable { .. }
            | Statement::Drop { .. }
            | Statement::CreateIndex { .. }
            | Statement::CreateView { .. } => {
                is_read_only = false;
                is_ddl = true;
                extract_tables_from_statement(stmt, &mut tables);
            }

            // Block COPY TO/FROM
            Statement::Copy { .. } => {
                return Err(DuckDbError::PermissionDenied(
                    "COPY is not allowed".to_string(),
                ));
            }

            // Block INSTALL/LOAD extension
            Statement::Install { .. } | Statement::Load { .. } => {
                return Err(DuckDbError::PermissionDenied(
                    "INSTALL/LOAD extensions are not allowed".to_string(),
                ));
            }

            // Block SET unless admin
            Statement::SetVariable { .. } => {
                if !is_admin {
                    return Err(DuckDbError::PermissionDenied(
                        "SET is not allowed without admin ability".to_string(),
                    ));
                }
            }

            // Block ATTACH/DETACH
            Statement::AttachDatabase { .. } => {
                return Err(DuckDbError::PermissionDenied(
                    "ATTACH is not allowed".to_string(),
                ));
            }

            _ => {
                return Err(DuckDbError::PermissionDenied(format!(
                    "Statement type not allowed: {}",
                    stmt
                )));
            }
        }
    }

    // DDL requires write ability (not admin-only like SQLite)
    if is_ddl
        && !matches!(
            ability,
            "tinycloud.duckdb/admin"
                | "tinycloud.duckdb/write"
                | "tinycloud.duckdb/*"
        )
    {
        return Err(DuckDbError::PermissionDenied(
            "DDL operations require write or admin ability".to_string(),
        ));
    }

    if !is_read_only
        && matches!(
            ability,
            "tinycloud.duckdb/read" | "tinycloud.duckdb/select"
        )
    {
        return Err(DuckDbError::ReadOnlyViolation);
    }

    // Validate caveats
    if let Some(caveats) = caveats {
        if caveats.read_only.unwrap_or(false) && !is_read_only {
            return Err(DuckDbError::ReadOnlyViolation);
        }

        for table in &tables {
            if !caveats.is_table_allowed(table) {
                return Err(DuckDbError::PermissionDenied(format!(
                    "Access to table '{}' is not allowed",
                    table
                )));
            }
        }

        for column in &columns {
            if !caveats.is_column_allowed(column) {
                return Err(DuckDbError::PermissionDenied(format!(
                    "Access to column '{}' is not allowed",
                    column
                )));
            }
        }
    }

    // Defense in depth: block function calls that could access external resources
    let sql_upper = sql.to_uppercase();
    let blocked_patterns = [
        "READ_CSV",
        "READ_PARQUET",
        "READ_JSON",
        "READ_CSV_AUTO",
        "READ_JSON_AUTO",
        "HTTPFS",
        "S3://",
        "HTTP://",
        "HTTPS://",
    ];
    if !is_admin {
        for pattern in &blocked_patterns {
            if sql_upper.contains(pattern) {
                return Err(DuckDbError::PermissionDenied(format!(
                    "External access function '{}' is not allowed",
                    pattern
                )));
            }
        }
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
            if let SelectItem::UnnamedExpr(Expr::Identifier(ident)) = item {
                columns.push(ident.value.clone());
            }
        }
    }
}
