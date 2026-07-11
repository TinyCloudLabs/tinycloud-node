use crate::capability::CapabilityRejection;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedParam {
    pub index: i64,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

pub fn parse(input: &Value) -> Result<SqlConstrainedStatementCaveat, CapabilityRejection> {
    let obj = input
        .as_object()
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;
    let mode = obj
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;
    if mode != "constrained-statements" {
        return Err(CapabilityRejection::PolicyCapabilityMalformedCaveats);
    }
    let read_only = obj
        .get("readOnly")
        .and_then(Value::as_bool)
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;
    let statements_value = obj
        .get("statements")
        .and_then(Value::as_array)
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;

    let mut statements = Vec::with_capacity(statements_value.len());
    for statement in statements_value {
        let statement = statement
            .as_object()
            .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;
        let name = statement
            .get("name")
            .and_then(Value::as_str)
            .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?
            .to_string();
        let sql = statement
            .get("sql")
            .and_then(Value::as_str)
            .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?
            .to_string();
        let fixed_params = match statement.get("fixedParams") {
            Some(Value::Array(params)) => {
                let mut out = Vec::with_capacity(params.len());
                for param in params {
                    let param = param
                        .as_object()
                        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;
                    let index = param
                        .get("index")
                        .and_then(Value::as_i64)
                        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?;
                    let value = param
                        .get("value")
                        .ok_or(CapabilityRejection::PolicyCapabilityMalformedCaveats)?
                        .clone();
                    out.push(FixedParam { index, value });
                }
                out
            }
            Some(_) => return Err(CapabilityRejection::PolicyCapabilityMalformedCaveats),
            None => Vec::new(),
        };
        statements.push(ConstrainedStatement {
            name,
            sql,
            fixed_params,
        });
    }

    Ok(SqlConstrainedStatementCaveat {
        read_only,
        statements,
    })
}

pub fn contains(
    auth: &SqlConstrainedStatementCaveat,
    req: &SqlConstrainedStatementCaveat,
) -> Result<(), CapabilityRejection> {
    if !auth.read_only || !req.read_only {
        return Err(CapabilityRejection::SqlNonReadonlyNotPermitted);
    }

    for req_statement in &req.statements {
        let Some(auth_statement) = auth
            .statements
            .iter()
            .find(|statement| statement.name == req_statement.name)
        else {
            return Err(CapabilityRejection::ContainmentSqlStatementAdded);
        };
        if auth_statement.sql != req_statement.sql {
            return Err(CapabilityRejection::ContainmentSqlStatementAdded);
        }
        for auth_param in &auth_statement.fixed_params {
            let Some(req_param) = req_statement
                .fixed_params
                .iter()
                .find(|param| param.index == auth_param.index)
            else {
                return Err(CapabilityRejection::ContainmentSqlFixedParamDropped);
            };
            if req_param.value != auth_param.value {
                return Err(CapabilityRejection::ContainmentSqlFixedParamMismatch);
            }
        }
    }

    Ok(())
}

pub fn contains_write_keyword(sql: &str) -> bool {
    const WRITE_KEYWORDS: &[&str] = &[
        "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "CREATE", "DROP", "ALTER", "TRUNCATE",
        "ATTACH", "DETACH", "PRAGMA", "VACUUM", "ANALYZE",
    ];
    let upper = sql.to_ascii_uppercase();
    WRITE_KEYWORDS
        .iter()
        .any(|keyword| contains_word(&upper, keyword))
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(index) = haystack[start..].find(needle) {
        let pos = start + index;
        let before = pos == 0
            || (!haystack.as_bytes()[pos - 1].is_ascii_alphanumeric()
                && haystack.as_bytes()[pos - 1] != b'_');
        let end = pos + needle.len();
        let after = end == haystack.len()
            || (!haystack.as_bytes()[end].is_ascii_alphanumeric()
                && haystack.as_bytes()[end] != b'_');
        if before && after {
            return true;
        }
        start = end;
    }
    false
}
