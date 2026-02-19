use sqlparser::ast::*;
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

use super::caveats::SqlCaveats;
use super::types::SqlError;

pub struct ParsedQuery {
    pub statements: Vec<Statement>,
    pub referenced_tables: Vec<String>,
    pub referenced_columns: Vec<String>,
    pub is_read_only: bool,
    pub is_ddl: bool,
}

pub fn validate_sql(
    sql: &str,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<ParsedQuery, SqlError> {
    let dialect = SQLiteDialect {};
    let statements =
        Parser::parse_sql(&dialect, sql).map_err(|e| SqlError::ParseError(e.to_string()))?;

    if statements.is_empty() {
        return Err(SqlError::ParseError("Empty SQL statement".to_string()));
    }

    let mut tables = Vec::new();
    let mut columns = Vec::new();
    let mut is_read_only = true;
    let mut is_ddl = false;

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
            | Statement::CreateIndex { .. } => {
                is_read_only = false;
                is_ddl = true;
                extract_tables_from_statement(stmt, &mut tables);
            }
            Statement::AttachDatabase { .. } => {
                return Err(SqlError::PermissionDenied(
                    "ATTACH is not allowed".to_string(),
                ));
            }
            _ => {
                return Err(SqlError::PermissionDenied(format!(
                    "Statement type not allowed: {}",
                    stmt
                )));
            }
        }
    }

    // Validate ability vs operation type
    if is_ddl
        && !matches!(
            ability,
            "tinycloud.sql/admin" | "tinycloud.sql/write" | "tinycloud.sql/*"
        )
    {
        return Err(SqlError::PermissionDenied(
            "DDL operations require admin or write ability".to_string(),
        ));
    }

    if !is_read_only && matches!(ability, "tinycloud.sql/read" | "tinycloud.sql/select") {
        return Err(SqlError::ReadOnlyViolation);
    }

    // Validate caveats
    if let Some(caveats) = caveats {
        if caveats.read_only.unwrap_or(false) && !is_read_only {
            return Err(SqlError::ReadOnlyViolation);
        }

        for table in &tables {
            if !caveats.is_table_allowed(table) {
                return Err(SqlError::PermissionDenied(format!(
                    "Access to table '{}' is not allowed",
                    table
                )));
            }
        }

        for column in &columns {
            if !caveats.is_column_allowed(column) {
                return Err(SqlError::PermissionDenied(format!(
                    "Access to column '{}' is not allowed",
                    column
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
