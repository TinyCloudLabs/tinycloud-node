use std::ops::ControlFlow;

use sqlparser::ast::*;
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

use super::authority::{DdlKind, DdlPolicy, SqlAuthority};
use super::caveats::SqlCaveats;
use super::types::SqlError;
use crate::write_hooks::TouchedTables;

#[derive(Debug)]
pub struct ParsedQuery {
    pub statements: Vec<Statement>,
    pub referenced_tables: Vec<String>,
    pub referenced_columns: Vec<String>,
    pub write_targets: Vec<TouchedTables>,
    pub is_read_only: bool,
    pub is_ddl: bool,
    /// `DdlPolicy::Log` only: the statement is schema-changing, and it runs
    /// only because `write` still sufficed. The caller counts and logs it.
    pub ddl_without_schema: Option<DdlKind>,
}

/// What a SQL string does, whoever runs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlClass {
    pub is_read_only: bool,
    pub is_ddl: bool,
}

/// The classification of one parsed statement list, before any ability or
/// caveat is applied.
struct Analysis {
    statements: Vec<Statement>,
    tables: Vec<String>,
    columns: Vec<String>,
    write_targets: Vec<TouchedTables>,
    is_read_only: bool,
    is_ddl: bool,
    has_non_ddl: bool,
    ddl_kind: Option<DdlKind>,
}

/// Classify `sql` independently of the caller's abilities.
///
/// A denial must never read as "not a write" (the storage-quota gate asks
/// this question), so the answer cannot depend on `validate_sql`'s ability
/// checks. Statements that do not parse are an `Err`; execution surfaces
/// the real error.
pub fn classify_sql(sql: &str) -> Result<SqlClass, SqlError> {
    if is_pragma_sql(sql) {
        return Ok(SqlClass {
            is_read_only: true,
            is_ddl: false,
        });
    }
    let analysis = analyze_statements(sql)?;
    Ok(SqlClass {
        is_read_only: analysis.is_read_only,
        is_ddl: analysis.is_ddl,
    })
}

pub fn validate_sql(
    sql: &str,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<ParsedQuery, SqlError> {
    validate_sql_authorized(sql, caveats, &SqlAuthority::from(ability))
}

/// As [`validate_sql`], judging the statement against every SQL ability the
/// invocation holds and the node's DDL policy (TC-1581).
pub fn validate_sql_authorized(
    sql: &str,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
) -> Result<ParsedQuery, SqlError> {
    if is_pragma_sql(sql) {
        // TC-119: confers-admin gate. `sql/admin` and `sql/*` (implies admin)
        // pass; identical to the prior `admin | *` match.
        if !authority.is_admin() {
            return Err(SqlError::PermissionDenied(
                "PRAGMA operations require admin ability".to_string(),
            ));
        }

        // SQLite accepts PRAGMA values that the AST parser does not support.
        // Still tokenize the entire input so quoted/comment semicolons cannot
        // hide another statement from the one-statement request contract.
        let tokens = Tokenizer::new(&SQLiteDialect {}, sql)
            .tokenize()
            .map_err(|e| SqlError::ParseError(e.to_string()))?;
        let mut terminated = false;
        for token in tokens {
            match token {
                // sqlparser nests block comments, but SQLite ends at the first
                // */. Fail closed rather than hiding executable SQL in a token.
                Token::Whitespace(Whitespace::MultiLineComment(comment))
                    if comment.contains("*/") =>
                {
                    return Err(SqlError::InvalidStatement(
                        "Nested block comments are not supported by SQLite".into(),
                    ));
                }
                Token::Whitespace(_) | Token::EOF => {}
                Token::SemiColon => terminated = true,
                _ if terminated => {
                    return Err(SqlError::InvalidStatement(
                        "Exactly one SQL statement is required".into(),
                    ));
                }
                _ => {}
            }
        }

        return Ok(ParsedQuery {
            statements: Vec::new(),
            referenced_tables: Vec::new(),
            referenced_columns: Vec::new(),
            write_targets: Vec::new(),
            is_read_only: true,
            is_ddl: false,
            ddl_without_schema: None,
        });
    }

    let Analysis {
        statements,
        mut tables,
        mut columns,
        write_targets,
        is_read_only,
        is_ddl,
        has_non_ddl,
        ddl_kind,
    } = analyze_statements(sql)?;

    // TC-1581: schema-changing statements need a schema-conferring ability
    // (`schema`; `admin` through the registry's `admin ⊃ schema`; `sql/*`).
    // `write` covers data statements only. `DdlPolicy::Log` and `Off` keep
    // the earlier rule, under which `write` also sufficed.
    if is_ddl && !authority.may_change_schema() {
        return Err(SqlError::PermissionDenied(match authority.ddl_policy() {
            DdlPolicy::Enforce => {
                "Schema-changing statements require the tinycloud.sql/schema ability".to_string()
            }
            DdlPolicy::Log | DdlPolicy::Off => {
                "DDL operations require admin, schema, or write ability".to_string()
            }
        }));
    }
    let ddl_without_schema = if is_ddl && authority.schema_change_only_by_legacy_rule() {
        ddl_kind
    } else {
        None
    };

    // Exact-tier restriction: the `schema` ability is DDL-only. A holder of
    // nothing else cannot run a data statement. This is not a confers-check:
    // a broader ability like `admin` is not restricted here.
    if (!is_ddl || has_non_ddl) && !authority.has_non_schema_ability() {
        return Err(SqlError::PermissionDenied(
            "Schema ability only permits DDL operations".to_string(),
        ));
    }

    // Exact-tier restriction: a holder of the read tier only (`read`, or its
    // `select` alias) cannot run a data write. Exact by design: `sql/*`
    // implies read but must still permit writes, so this must not use
    // `ability_matches`.
    if !is_read_only && !is_ddl && authority.is_read_tier_only() {
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
        write_targets,
        is_read_only,
        is_ddl,
        ddl_without_schema,
    })
}

fn analyze_statements(sql: &str) -> Result<Analysis, SqlError> {
    let dialect = SQLiteDialect {};
    let statements =
        Parser::parse_sql(&dialect, sql).map_err(|e| SqlError::ParseError(e.to_string()))?;

    if statements.is_empty() {
        return Err(SqlError::ParseError("Empty SQL statement".to_string()));
    }
    if statements.len() != 1 {
        return Err(SqlError::InvalidStatement(
            "Exactly one SQL statement is required".to_string(),
        ));
    }

    let mut tables = Vec::new();
    let mut columns = Vec::new();
    let mut write_targets = Vec::new();
    let mut is_read_only = true;
    let mut is_ddl = false;
    let mut has_non_ddl = false;
    let mut ddl_kind = None;

    for stmt in &statements {
        match stmt {
            Statement::Query(query) => {
                has_non_ddl = true;
                extract_tables_from_statement(stmt, &mut tables);
                extract_columns_from_statement(stmt, &mut columns);
                // TC-1585: `WITH … INSERT/UPDATE` parses as a Query whose body
                // is a write. A write anywhere in the tree makes the statement
                // a write: it is quota-gated, emits write hooks and is made
                // durable like any other write, and a read tier cannot run it.
                for write in writes_in_query(query) {
                    is_read_only = false;
                    extract_tables_from_statement(&write, &mut tables);
                    extract_columns_from_statement(&write, &mut columns);
                    if let Some(targets) = extract_write_targets_from_statement(&write) {
                        write_targets.push(targets);
                    }
                }
            }
            Statement::Insert { .. } => {
                has_non_ddl = true;
                is_read_only = false;
                extract_tables_from_statement(stmt, &mut tables);
                if let Some(targets) = extract_write_targets_from_statement(stmt) {
                    write_targets.push(targets);
                }
            }
            Statement::Update { .. } => {
                has_non_ddl = true;
                is_read_only = false;
                extract_tables_from_statement(stmt, &mut tables);
                extract_columns_from_statement(stmt, &mut columns);
                if let Some(targets) = extract_write_targets_from_statement(stmt) {
                    write_targets.push(targets);
                }
            }
            Statement::Delete { .. } => {
                has_non_ddl = true;
                is_read_only = false;
                extract_tables_from_statement(stmt, &mut tables);
                if let Some(targets) = extract_write_targets_from_statement(stmt) {
                    write_targets.push(targets);
                }
            }
            Statement::CreateTable { .. }
            | Statement::CreateView { .. }
            | Statement::AlterTable { .. }
            | Statement::Drop { .. }
            | Statement::CreateIndex { .. } => {
                is_read_only = false;
                is_ddl = true;
                ddl_kind = Some(ddl_kind_of(stmt));
                extract_tables_from_statement(stmt, &mut tables);
                if let Some(targets) = extract_write_targets_from_statement(stmt) {
                    write_targets.push(targets);
                }
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

    Ok(Analysis {
        statements,
        tables,
        columns,
        write_targets,
        is_read_only,
        is_ddl,
        has_non_ddl,
        ddl_kind,
    })
}

fn ddl_kind_of(stmt: &Statement) -> DdlKind {
    match stmt {
        Statement::CreateView { .. } => DdlKind::CreateView,
        Statement::CreateIndex { .. } => DdlKind::CreateIndex,
        Statement::AlterTable { .. } => DdlKind::AlterTable,
        Statement::Drop { .. } => DdlKind::Drop,
        _ => DdlKind::CreateTable,
    }
}

/// The INSERT, UPDATE and DELETE statements anywhere inside a query tree
/// (its CTE bodies, sub-queries and set operations).
fn writes_in_query(query: &Query) -> Vec<Statement> {
    let mut writes = Vec::new();
    let _ = visit_statements(query, |statement| {
        if matches!(
            statement,
            Statement::Insert { .. } | Statement::Update { .. } | Statement::Delete { .. }
        ) {
            writes.push(statement.clone());
        }
        ControlFlow::<()>::Continue(())
    });
    writes
}

pub fn is_pragma_sql(sql: &str) -> bool {
    first_sql_token(sql).as_deref() == Some("pragma")
}

fn first_sql_token(sql: &str) -> Option<String> {
    let mut index = 0;

    while index < sql.len() {
        while let Some(ch) = sql[index..].chars().next() {
            if !ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }

        if sql[index..].starts_with("--") {
            let newline = sql[index + 2..].find('\n')?;
            index += 2 + newline + 1;
            continue;
        }

        if sql[index..].starts_with("/*") {
            let end = sql[index + 2..].find("*/")?;
            index += 2 + end + 2;
            continue;
        }

        break;
    }

    let token: String = sql[index..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphabetic() || *ch == '_')
        .collect();
    (!token.is_empty()).then(|| token.to_ascii_lowercase())
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
        Statement::CreateView { name, .. } => {
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

pub fn extract_write_targets_from_statement(stmt: &Statement) -> Option<TouchedTables> {
    match stmt {
        Statement::Insert { table_name, .. } => {
            Some(TouchedTables::supported(vec![table_name.to_string()]))
        }
        Statement::Update { table, .. } => extract_write_target_from_update(table),
        Statement::Delete { tables, from, .. } => extract_write_target_from_delete(tables, from),
        Statement::CreateTable { name, .. } | Statement::AlterTable { name, .. } => {
            Some(TouchedTables::supported(vec![name.to_string()]))
        }
        Statement::CreateView { name, .. } => {
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
    use super::*;
    use crate::write_hooks::TouchedTables;

    #[test]
    fn tc626_review_pragma_rejects_hidden_statements() {
        for sql in [
            "PRAGMA user_version = 1; RELEASE tinycloud_storage_guard",
            "PRAGMA table_info('semi;colon'); -- separator;\nCOMMIT",
            "PRAGMA table_info(\"semi;colon\"); /* separator; */ SELECT 1",
            "PRAGMA user_version = 1; /* outer /* inner */ COMMIT; -- */",
        ] {
            assert!(
                validate_sql(sql, &None, "tinycloud.sql/admin").is_err(),
                "PRAGMA must not bypass single-statement validation: {sql}"
            );
        }
    }

    #[test]
    fn update_write_targets_only_include_target_table() {
        let dialect = SQLiteDialect {};
        let statements = Parser::parse_sql(&dialect, "UPDATE users SET name = 'test'").unwrap();

        let targets = extract_write_targets_from_statement(&statements[0]).unwrap();
        assert_eq!(targets, TouchedTables::supported(vec!["users".to_string()]));
    }

    #[test]
    fn delete_write_targets_use_target_table_list() {
        let dialect = SQLiteDialect {};
        let statements = Parser::parse_sql(&dialect, "DELETE FROM users WHERE id = 1").unwrap();

        let targets = extract_write_targets_from_statement(&statements[0]).unwrap();
        assert_eq!(targets, TouchedTables::supported(vec!["users".to_string()]));
    }

    #[test]
    fn pragma_requires_admin_before_generic_sql_parse() {
        let err = validate_sql(
            "PRAGMA table_info(secret_records)",
            &None,
            "tinycloud.sql/read",
        )
        .expect_err("read ability must not authorize PRAGMA");

        assert!(matches!(err, SqlError::PermissionDenied(message) if message.contains("admin")));
    }

    #[test]
    fn admin_pragma_is_validated_without_sqlparser() {
        let parsed = validate_sql(
            "
              -- migration introspection
              /* SQLite-specific */
              PRAGMA table_info(secret_records)
            ",
            &None,
            "tinycloud.sql/admin",
        )
        .expect("admin PRAGMA should not fail sqlparser parsing");

        assert!(parsed.is_read_only);
        assert!(parsed.write_targets.is_empty());
    }

    #[test]
    fn validate_sql_rejects_ddl_ability_for_schema_changes() {
        let err = validate_sql(
            "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)",
            &None,
            "tinycloud.sql/ddl",
        )
        .expect_err("ddl ability is not a schema permission");

        assert!(matches!(err, SqlError::PermissionDenied(_)));
    }

    #[test]
    fn schema_ability_allows_ddl() {
        let parsed = validate_sql(
            "CREATE TABLE IF NOT EXISTS conversation (id TEXT PRIMARY KEY)",
            &None,
            "tinycloud.sql/schema",
        )
        .expect("schema ability should authorize DDL");

        assert!(parsed.is_ddl);
        assert!(!parsed.is_read_only);
        assert_eq!(
            parsed.write_targets,
            vec![TouchedTables::supported(vec!["conversation".to_string()])]
        );
    }

    #[test]
    fn schema_ability_rejects_dml() {
        for sql in [
            "INSERT INTO conversation (id) VALUES ('1')",
            "UPDATE conversation SET id = '2'",
            "DELETE FROM conversation WHERE id = '1'",
        ] {
            let err = validate_sql(sql, &None, "tinycloud.sql/schema")
                .expect_err("schema ability must not authorize DML");

            assert!(
                matches!(err, SqlError::PermissionDenied(ref message) if message.contains("only permits DDL")),
                "expected DML permission denial for {sql}, got {err:?}"
            );
        }
    }

    #[test]
    fn schema_ability_rejects_select() {
        let err = validate_sql("SELECT id FROM conversation", &None, "tinycloud.sql/schema")
            .expect_err("schema ability must not authorize reads");

        assert!(
            matches!(err, SqlError::PermissionDenied(ref message) if message.contains("only permits DDL")),
            "expected SELECT permission denial, got {err:?}"
        );
    }

    #[test]
    fn schema_ability_rejects_mixed_ddl_and_select() {
        let err = validate_sql(
            "CREATE TABLE conversation (id TEXT); SELECT id FROM private_conversation",
            &None,
            "tinycloud.sql/schema",
        )
        .expect_err("schema ability must not authorize mixed DDL and reads");

        assert!(
            matches!(err, SqlError::InvalidStatement(ref message) if message.contains("Exactly one")),
            "expected multi-statement rejection, got {err:?}"
        );
    }

    #[test]
    fn query_rejects_multiple_statements() {
        let err = validate_sql(
            "SELECT id FROM conversation; SELECT id FROM private_conversation",
            &None,
            "tinycloud.sql/read",
        )
        .expect_err("a query request must contain one statement");

        assert!(matches!(
            err,
            SqlError::InvalidStatement(ref message) if message.contains("Exactly one")
        ));
    }

    #[test]
    fn schema_ability_allows_create_view() {
        let parsed = validate_sql(
            "CREATE VIEW conversation_ids AS SELECT id FROM conversation",
            &None,
            "tinycloud.sql/schema",
        )
        .expect("schema ability should authorize CREATE VIEW");

        assert!(parsed.is_ddl);
        assert_eq!(
            parsed.write_targets,
            vec![TouchedTables::supported(vec![
                "conversation_ids".to_string()
            ])]
        );
    }
}

/// TC-1581: schema-changing statements need `schema`; `write` is data only.
#[cfg(test)]
mod ddl_authority_tests {
    use super::*;
    use crate::sql::authority::DdlPolicy;
    use crate::write_hooks::TouchedTables;

    const READ: &str = "tinycloud.sql/read";
    const WRITE: &str = "tinycloud.sql/write";
    const SCHEMA: &str = "tinycloud.sql/schema";
    const ADMIN: &str = "tinycloud.sql/admin";
    const STAR: &str = "tinycloud.sql/*";

    fn held(abilities: &[&str]) -> SqlAuthority {
        SqlAuthority::new(abilities.iter().copied())
    }

    fn validate(sql: &str, abilities: &[&str]) -> Result<ParsedQuery, SqlError> {
        validate_sql_authorized(sql, &None, &held(abilities))
    }

    /// One statement of every schema-changing kind the parser classifies.
    const DDL: [&str; 10] = [
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)",
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE scratch (id INTEGER)",
        "CREATE TABLE copied AS SELECT id FROM notes",
        "CREATE VIEW note_ids AS SELECT id FROM notes",
        "CREATE INDEX notes_body ON notes (body)",
        "CREATE UNIQUE INDEX notes_id ON notes (id)",
        "ALTER TABLE notes ADD COLUMN extra TEXT",
        "DROP TABLE notes",
        "DROP VIEW note_ids",
    ];

    const DML: [&str; 3] = [
        "INSERT INTO notes (id) VALUES (1)",
        "UPDATE notes SET body = 'x'",
        "DELETE FROM notes WHERE id = 1",
    ];

    #[test]
    fn pragma_stays_admin_only_whatever_else_is_held() {
        for sql in ["PRAGMA user_version = 3", "PRAGMA table_info(notes)"] {
            for abilities in [
                &[WRITE][..],
                &[SCHEMA][..],
                &[WRITE, SCHEMA][..],
                &[READ, WRITE, SCHEMA][..],
            ] {
                for policy in [DdlPolicy::Enforce, DdlPolicy::Log, DdlPolicy::Off] {
                    let authority = held(abilities).with_ddl_policy(policy);
                    assert!(
                        matches!(
                            validate_sql_authorized(sql, &None, &authority),
                            Err(SqlError::PermissionDenied(_))
                        ),
                        "{abilities:?} must not run {sql} under {policy:?}"
                    );
                }
            }
            for admin in [ADMIN, STAR] {
                validate(sql, &[admin]).expect("admin and * may run PRAGMA");
            }
        }
    }

    #[test]
    fn ddl_needs_a_schema_conferring_ability() {
        for sql in DDL {
            for (abilities, allowed) in [
                (&[WRITE][..], false),
                (&[READ][..], false),
                (&[READ, WRITE][..], false),
                (&["tinycloud.sql/select"][..], false),
                (&["tinycloud.sql/ddl"][..], false),
                (&[SCHEMA][..], true),
                (&[WRITE, SCHEMA][..], true),
                (&[READ, SCHEMA][..], true),
                (&[ADMIN][..], true),
                (&[STAR][..], true),
                (&[WRITE, ADMIN][..], true),
            ] {
                let result = validate(sql, abilities);
                if allowed {
                    let parsed =
                        result.unwrap_or_else(|e| panic!("{abilities:?} must run {sql}: {e:?}"));
                    assert!(parsed.is_ddl && !parsed.is_read_only, "{sql}");
                    assert_eq!(parsed.ddl_without_schema, None, "{sql}");
                } else {
                    assert!(
                        matches!(result, Err(SqlError::PermissionDenied(_))),
                        "{abilities:?} must not run {sql}, got {result:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn write_alone_is_refused_with_a_schema_hint() {
        let err = validate("DROP TABLE notes", &[WRITE]).unwrap_err();
        assert!(
            matches!(&err, SqlError::PermissionDenied(message) if message.contains("tinycloud.sql/schema")),
            "{err:?}"
        );
    }

    #[test]
    fn data_statements_keep_their_tiers() {
        for sql in DML {
            for (abilities, expected) in [
                (&[WRITE][..], "ok"),
                (&[READ, WRITE][..], "ok"),
                (&[WRITE, SCHEMA][..], "ok"),
                (&[ADMIN][..], "ok"),
                (&[STAR][..], "ok"),
                (&[READ][..], "read-only"),
                (&["tinycloud.sql/select"][..], "read-only"),
                (&[READ, SCHEMA][..], "read-only"),
                (&[SCHEMA][..], "schema-only"),
            ] {
                let result = validate(sql, abilities);
                match expected {
                    "ok" => {
                        let parsed = result
                            .unwrap_or_else(|e| panic!("{abilities:?} must run {sql}: {e:?}"));
                        assert!(!parsed.is_ddl && !parsed.is_read_only);
                    }
                    "read-only" => assert!(
                        matches!(result, Err(SqlError::ReadOnlyViolation)),
                        "{abilities:?} {sql}: {result:?}"
                    ),
                    _ => assert!(
                        matches!(&result, Err(SqlError::PermissionDenied(m)) if m.contains("only permits DDL")),
                        "{abilities:?} {sql}: {result:?}"
                    ),
                }
            }
        }
    }

    #[test]
    fn select_needs_a_data_ability_not_schema_alone() {
        for abilities in [
            &[READ][..],
            &[WRITE][..],
            &[ADMIN][..],
            &[STAR][..],
            &[READ, SCHEMA][..],
        ] {
            validate("SELECT id FROM notes", abilities)
                .unwrap_or_else(|e| panic!("{abilities:?} must read: {e:?}"));
        }
        let err = validate("SELECT id FROM notes", &[SCHEMA]).unwrap_err();
        assert!(matches!(err, SqlError::PermissionDenied(m) if m.contains("only permits DDL")));
    }

    #[test]
    fn statements_outside_the_allow_list_stay_denied_for_every_ability() {
        for sql in [
            "ATTACH DATABASE 'other.db' AS other",
            "DETACH DATABASE other",
            "VACUUM",
            "VACUUM INTO 'copy.db'",
            "REINDEX",
            "ANALYZE TABLE notes",
            "CREATE VIRTUAL TABLE docs USING fts5(body)",
            "CREATE TRIGGER t AFTER INSERT ON notes BEGIN DELETE FROM notes; END",
            "DROP TRIGGER t",
            "BEGIN",
            "COMMIT",
            "SAVEPOINT s",
            "EXPLAIN SELECT 1",
        ] {
            for abilities in [
                &[WRITE][..],
                &[WRITE, SCHEMA][..],
                &[ADMIN][..],
                &[STAR][..],
            ] {
                assert!(
                    validate(sql, abilities).is_err(),
                    "{abilities:?} must not run {sql}"
                );
            }
        }
    }

    #[test]
    fn mixed_requests_need_both_abilities_per_statement() {
        // A request that runs DDL and DML is validated statement by statement
        // against the same held set.
        let ddl = "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY)";
        let dml = "INSERT INTO notes (id) VALUES (1)";
        for (abilities, ddl_ok, dml_ok) in [
            (&[WRITE][..], false, true),
            (&[SCHEMA][..], true, false),
            (&[WRITE, SCHEMA][..], true, true),
            (&[ADMIN][..], true, true),
            (&[STAR][..], true, true),
            (&[READ][..], false, false),
        ] {
            assert_eq!(
                validate(ddl, abilities).is_ok(),
                ddl_ok,
                "{abilities:?} ddl"
            );
            assert_eq!(
                validate(dml, abilities).is_ok(),
                dml_ok,
                "{abilities:?} dml"
            );
        }
    }

    #[test]
    fn policy_off_and_log_keep_the_earlier_rule_and_log_marks_the_statement() {
        for policy in [DdlPolicy::Off, DdlPolicy::Log] {
            for sql in DDL {
                let write_only = held(&[WRITE]).with_ddl_policy(policy);
                let parsed = validate_sql_authorized(sql, &None, &write_only)
                    .unwrap_or_else(|e| panic!("{policy:?} must run {sql}: {e:?}"));
                assert_eq!(
                    parsed.ddl_without_schema.is_some(),
                    policy == DdlPolicy::Log,
                    "{policy:?} {sql}"
                );

                let both = held(&[WRITE, SCHEMA]).with_ddl_policy(policy);
                assert_eq!(
                    validate_sql_authorized(sql, &None, &both)
                        .unwrap()
                        .ddl_without_schema,
                    None
                );

                let read_only = held(&[READ]).with_ddl_policy(policy);
                assert!(matches!(
                    validate_sql_authorized(sql, &None, &read_only),
                    Err(SqlError::PermissionDenied(_))
                ));
            }
            let data = held(&[WRITE]).with_ddl_policy(policy);
            assert_eq!(
                validate_sql_authorized("INSERT INTO notes (id) VALUES (1)", &None, &data)
                    .unwrap()
                    .ddl_without_schema,
                None
            );
        }
    }

    #[test]
    fn log_marks_each_statement_kind() {
        let write_only = held(&[WRITE]).with_ddl_policy(DdlPolicy::Log);
        for (sql, kind) in [
            ("CREATE TABLE t (a)", DdlKind::CreateTable),
            ("CREATE VIEW v AS SELECT 1", DdlKind::CreateView),
            ("CREATE INDEX i ON t (a)", DdlKind::CreateIndex),
            ("ALTER TABLE t ADD COLUMN b", DdlKind::AlterTable),
            ("DROP TABLE t", DdlKind::Drop),
        ] {
            assert_eq!(
                validate_sql_authorized(sql, &None, &write_only)
                    .unwrap()
                    .ddl_without_schema,
                Some(kind),
                "{sql}"
            );
        }
    }

    /// One CTE-wrapped write per kind the parser can represent, with the
    /// table it touches.
    const CTE_WRITES: [(&str, &str); 3] = [
        (
            "WITH c AS (SELECT 1 AS id) INSERT INTO notes (id) SELECT id FROM c",
            "notes",
        ),
        (
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) INSERT INTO notes (id) SELECT i FROM n",
            "notes",
        ),
        (
            "WITH c AS (SELECT 'x' AS body) UPDATE notes SET body = (SELECT body FROM c)",
            "notes",
        ),
    ];

    #[test]
    fn cte_wrapped_writes_are_writes_with_their_targets() {
        for (sql, table) in CTE_WRITES {
            let class = classify_sql(sql).unwrap();
            assert!(!class.is_read_only && !class.is_ddl, "{sql}");

            for abilities in [
                &[WRITE][..],
                &[WRITE, SCHEMA][..],
                &[ADMIN][..],
                &[STAR][..],
            ] {
                let parsed = validate(sql, abilities).unwrap();
                assert!(!parsed.is_read_only && !parsed.is_ddl, "{sql}");
                assert_eq!(
                    parsed.write_targets,
                    vec![TouchedTables::supported(vec![table.to_string()])],
                    "{sql} must report its target for write hooks and durability"
                );
            }
        }
    }

    #[test]
    fn cte_wrapped_writes_are_refused_to_read_and_schema_only_holders() {
        for (sql, _) in CTE_WRITES {
            for abilities in [
                &[READ][..],
                &["tinycloud.sql/select"][..],
                &[READ, SCHEMA][..],
            ] {
                assert!(
                    matches!(validate(sql, abilities), Err(SqlError::ReadOnlyViolation)),
                    "{abilities:?} {sql}"
                );
            }
            let err = validate(sql, &[SCHEMA]).unwrap_err();
            assert!(matches!(err, SqlError::PermissionDenied(m) if m.contains("only permits DDL")));
        }
    }

    #[test]
    fn cte_wrapped_writes_obey_the_caveats_of_a_write() {
        for (sql, _) in CTE_WRITES {
            let read_only = Some(SqlCaveats {
                read_only: Some(true),
                ..SqlCaveats::default()
            });
            assert!(matches!(
                validate_sql_authorized(sql, &read_only, &held(&[WRITE])),
                Err(SqlError::ReadOnlyViolation)
            ));
            let other_table = Some(SqlCaveats {
                tables: Some(vec!["other".to_string()]),
                ..SqlCaveats::default()
            });
            assert!(matches!(
                validate_sql_authorized(sql, &other_table, &held(&[WRITE])),
                Err(SqlError::PermissionDenied(_))
            ));
            let this_table = Some(SqlCaveats {
                tables: Some(vec!["notes".to_string()]),
                ..SqlCaveats::default()
            });
            validate_sql_authorized(sql, &this_table, &held(&[WRITE])).unwrap();
        }
    }

    #[test]
    fn a_cte_without_a_write_stays_read_only() {
        for sql in [
            "WITH c AS (SELECT id FROM notes) SELECT id FROM c",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) SELECT i FROM n",
            "SELECT id FROM notes WHERE id IN (WITH c AS (SELECT 1) SELECT * FROM c)",
        ] {
            let parsed = validate(sql, &[READ]).unwrap();
            assert!(parsed.is_read_only && parsed.write_targets.is_empty(), "{sql}");
            assert!(classify_sql(sql).unwrap().is_read_only, "{sql}");
        }
    }

    #[test]
    fn a_cte_wrapped_delete_is_not_accepted_for_any_ability() {
        // sqlparser 0.44 cannot represent `WITH … DELETE`, so it is rejected
        // outright rather than classified as a read.
        let sql = "WITH c AS (SELECT 1 AS id) DELETE FROM notes WHERE id IN (SELECT id FROM c)";
        assert!(classify_sql(sql).is_err());
        for abilities in [&[READ][..], &[WRITE][..], &[ADMIN][..], &[STAR][..]] {
            assert!(validate(sql, abilities).is_err(), "{abilities:?}");
        }
    }

    #[test]
    fn classification_does_not_depend_on_abilities() {
        // A denial must never read as "not a write" (quota gate).
        for sql in DDL {
            let class = classify_sql(sql).unwrap();
            assert!(class.is_ddl && !class.is_read_only, "{sql}");
            assert!(validate(sql, &[WRITE]).is_err());
        }
        for sql in DML {
            let class = classify_sql(sql).unwrap();
            assert!(!class.is_ddl && !class.is_read_only, "{sql}");
        }
        let select = classify_sql("SELECT 1").unwrap();
        assert!(select.is_read_only && !select.is_ddl);
        // PRAGMA is classified read-only, as `validate_sql` always did.
        assert!(classify_sql("PRAGMA table_info(t)").unwrap().is_read_only);
        assert!(classify_sql("NOT SQL AT ALL").is_err());
    }

    #[test]
    fn read_only_caveat_still_refuses_ddl_for_a_schema_holder() {
        let caveats = Some(SqlCaveats {
            read_only: Some(true),
            ..SqlCaveats::default()
        });
        let err =
            validate_sql_authorized("CREATE TABLE t (a)", &caveats, &held(&[SCHEMA])).unwrap_err();
        assert!(matches!(err, SqlError::ReadOnlyViolation));
    }
}
