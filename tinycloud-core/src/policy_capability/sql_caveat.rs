// `SqlConstrainedStatementCaveat` — the SQL-side W0 contract.
//
// See `policy-engine/spec/sql-constrained-statement-caveat.md` and the
// vectors in `policy-engine/test-vectors/sql-caveat/`.

use super::RejectionCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParam {
    pub index: i64,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstrainedStatement {
    pub name: String,
    pub sql: String,
    pub fixed_params: Vec<FixedParam>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlConstrainedStatementCaveat {
    pub read_only: bool,
    pub statements: Vec<ConstrainedStatement>,
}

/// Invocation-time rejection codes per
/// `sql-constrained-statement-caveat.md` §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationReject {
    SqlStatementNotAllowed,
    SqlFixedParamOverride,
    SqlFixedParamMismatch,
    SqlRawQueryBlocked,
    SqlRawExecuteBlocked,
    SqlBatchBlocked,
    SqlExportBlocked,
    SqlNonReadBlocked,
    SqlWriteBlocked,
    SqlEscapeBlocked,
    SqlNonPrimitiveBind,
    SqlMultistatementBlocked,
}

impl InvocationReject {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlStatementNotAllowed => "sql-statement-not-allowed",
            Self::SqlFixedParamOverride => "sql-fixed-param-override",
            Self::SqlFixedParamMismatch => "sql-fixed-param-mismatch",
            Self::SqlRawQueryBlocked => "sql-raw-query-blocked",
            Self::SqlRawExecuteBlocked => "sql-raw-execute-blocked",
            Self::SqlBatchBlocked => "sql-batch-blocked",
            Self::SqlExportBlocked => "sql-export-blocked",
            Self::SqlNonReadBlocked => "sql-non-read-blocked",
            Self::SqlWriteBlocked => "sql-write-blocked",
            Self::SqlEscapeBlocked => "sql-escape-blocked",
            Self::SqlNonPrimitiveBind => "sql-non-primitive-bind",
            Self::SqlMultistatementBlocked => "sql-multistatement-blocked",
        }
    }
}

pub fn parse(input: &Value) -> Result<SqlConstrainedStatementCaveat, RejectionCode> {
    let obj = input
        .as_object()
        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
    let mode = obj
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
    if mode != "constrained-statements" {
        return Err(RejectionCode::PolicyCapabilityMalformedCaveats);
    }
    let read_only_value = obj
        .get("readOnly")
        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
    let read_only = read_only_value
        .as_bool()
        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
    let statements_arr = obj
        .get("statements")
        .and_then(Value::as_array)
        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
    let mut statements = Vec::with_capacity(statements_arr.len());
    for s in statements_arr {
        let so = s
            .as_object()
            .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
        let name = so
            .get("name")
            .and_then(Value::as_str)
            .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?
            .to_string();
        let sql = so
            .get("sql")
            .and_then(Value::as_str)
            .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?
            .to_string();
        let fixed = match so.get("fixedParams") {
            None => Vec::new(),
            Some(v) => {
                let arr = v
                    .as_array()
                    .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
                let mut out = Vec::with_capacity(arr.len());
                for fp in arr {
                    let fpo = fp
                        .as_object()
                        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
                    let index = fpo
                        .get("index")
                        .and_then(Value::as_i64)
                        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?;
                    let value = fpo
                        .get("value")
                        .ok_or(RejectionCode::PolicyCapabilityMalformedCaveats)?
                        .clone();
                    out.push(FixedParam { index, value });
                }
                out
            }
        };
        statements.push(ConstrainedStatement {
            name,
            sql,
            fixed_params: fixed,
        });
    }
    Ok(SqlConstrainedStatementCaveat {
        read_only,
        statements,
    })
}

/// Containment per spec §5.
pub fn contains(
    auth: &SqlConstrainedStatementCaveat,
    req: &SqlConstrainedStatementCaveat,
) -> Result<(), RejectionCode> {
    // §1: both must be read-only.
    if !auth.read_only || !req.read_only {
        return Err(RejectionCode::SqlNonReadonlyNotPermitted);
    }
    for req_stmt in &req.statements {
        let auth_stmt = match auth.statements.iter().find(|s| s.name == req_stmt.name) {
            Some(s) => s,
            None => return Err(RejectionCode::ContainmentSqlStatementAdded),
        };
        if auth_stmt.sql != req_stmt.sql {
            return Err(RejectionCode::ContainmentSqlStatementAdded);
        }
        // Every auth fixedParam must be present in req with same value.
        for ap in &auth_stmt.fixed_params {
            match req_stmt.fixed_params.iter().find(|rp| rp.index == ap.index) {
                None => return Err(RejectionCode::ContainmentSqlFixedParamDropped),
                Some(rp) => {
                    if rp.value != ap.value {
                        return Err(RejectionCode::ContainmentSqlFixedParamMismatch);
                    }
                }
            }
        }
    }
    Ok(())
}

/// True if `sql` contains a SQL write keyword. Implemented as a
/// case-insensitive bounded-token scan; we only consider tokens at word
/// boundaries (not substrings). Used as a fail-closed check on the bound SQL
/// shipped inside a constrained-statements caveat.
pub fn contains_write_keyword(sql: &str) -> bool {
    const WRITE_KEYWORDS: &[&str] = &[
        "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "CREATE", "DROP", "ALTER", "TRUNCATE",
        "ATTACH", "DETACH", "PRAGMA", "VACUUM", "ANALYZE",
    ];
    let upper = sql.to_ascii_uppercase();
    for kw in WRITE_KEYWORDS {
        if contains_word(&upper, kw) {
            return true;
        }
    }
    false
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = haystack[start..].find(needle) {
        let pos = start + idx;
        let before = pos == 0
            || !haystack.as_bytes()[pos - 1].is_ascii_alphanumeric()
                && haystack.as_bytes()[pos - 1] != b'_';
        let end = pos + needle.len();
        let after = end == haystack.len()
            || !haystack.as_bytes()[end].is_ascii_alphanumeric()
                && haystack.as_bytes()[end] != b'_';
        if before && after {
            return true;
        }
        start = pos + needle.len();
    }
    false
}

/// True if `value` looks like an identifier/string escape attempt — used to
/// fail-closed on caller-supplied non-fixed bind values.
pub fn looks_like_escape(value: &str) -> bool {
    value.contains('"')
        || value.contains('\'')
        || value.contains(';')
        || value.contains("--")
        || value.to_ascii_uppercase().contains(" OR 1=1")
        || value.contains("/*")
        || value.contains("*/")
}

/// True if the SQL contains a top-level `;` (more than one statement). The
/// v0 spec rejects multi-statement bound SQL; we treat any unescaped
/// non-terminal `;` outside a string as multi-statement.
pub fn is_multistatement(sql: &str) -> bool {
    let trimmed = sql.trim_end_matches(|c: char| c.is_whitespace() || c == ';');
    let mut in_str = false;
    let mut prev = '\0';
    for c in trimmed.chars() {
        if c == '\'' && prev != '\\' {
            in_str = !in_str;
        }
        if c == ';' && !in_str {
            return true;
        }
        prev = c;
    }
    false
}
