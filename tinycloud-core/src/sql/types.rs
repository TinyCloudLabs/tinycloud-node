use serde::{Deserialize, Serialize};

use crate::write_hooks::TouchedTables;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum SqlRequest {
    #[serde(rename = "query")]
    Query {
        sql: String,
        #[serde(default)]
        params: Vec<SqlValue>,
        #[serde(default, rename = "maxRows")]
        max_rows: Option<usize>,
        #[serde(default, rename = "maxBytes")]
        max_bytes: Option<usize>,
    },
    #[serde(rename = "execute")]
    Execute {
        sql: String,
        #[serde(default)]
        params: Vec<SqlValue>,
        #[serde(default)]
        schema: Option<Vec<String>>,
    },
    #[serde(rename = "batch")]
    Batch { statements: Vec<SqlStatement> },
    #[serde(rename = "executeStatement", alias = "execute_statement")]
    ExecuteStatement {
        name: String,
        #[serde(default)]
        params: Vec<SqlValue>,
    },
    #[serde(rename = "export")]
    Export,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlStatement {
    pub sql: String,
    #[serde(default)]
    pub params: Vec<SqlValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Serialize for SqlValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            SqlValue::Null => serializer.serialize_none(),
            SqlValue::Integer(i) => serializer.serialize_i64(*i),
            SqlValue::Real(f) => serializer.serialize_f64(*f),
            SqlValue::Text(s) => serializer.serialize_str(s),
            SqlValue::Blob(b) => serializer.serialize_bytes(b),
        }
    }
}

impl<'de> Deserialize<'de> for SqlValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SqlValueVisitor;

        impl<'de> serde::de::Visitor<'de> for SqlValueVisitor {
            type Value = SqlValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a SQL value (null, integer, real, string, or byte array)")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<SqlValue, E> {
                Ok(SqlValue::Null)
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<SqlValue, E> {
                Ok(SqlValue::Null)
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<SqlValue, D::Error> {
                Deserialize::deserialize(deserializer)
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<SqlValue, E> {
                Ok(SqlValue::Integer(if v { 1 } else { 0 }))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<SqlValue, E> {
                Ok(SqlValue::Integer(v))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<SqlValue, E> {
                i64::try_from(v)
                    .map(SqlValue::Integer)
                    .map_err(|_| E::custom("SQLite integers must fit in signed 64 bits"))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<SqlValue, E> {
                Ok(SqlValue::Real(v))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SqlValue, E> {
                Ok(SqlValue::Text(v.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<SqlValue, E> {
                Ok(SqlValue::Text(v))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<SqlValue, E> {
                Ok(SqlValue::Blob(v.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<SqlValue, E> {
                Ok(SqlValue::Blob(v))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<SqlValue, A::Error> {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(SqlValue::Blob(bytes))
            }
        }

        deserializer.deserialize_any(SqlValueVisitor)
    }
}

impl From<rusqlite::types::Value> for SqlValue {
    fn from(v: rusqlite::types::Value) -> Self {
        match v {
            rusqlite::types::Value::Null => SqlValue::Null,
            rusqlite::types::Value::Integer(i) => SqlValue::Integer(i),
            rusqlite::types::Value::Real(f) => SqlValue::Real(f),
            rusqlite::types::Value::Text(s) => SqlValue::Text(s),
            rusqlite::types::Value::Blob(b) => SqlValue::Blob(b),
        }
    }
}

impl From<&SqlValue> for rusqlite::types::Value {
    fn from(v: &SqlValue) -> Self {
        match v {
            SqlValue::Null => rusqlite::types::Value::Null,
            SqlValue::Integer(i) => rusqlite::types::Value::Integer(*i),
            SqlValue::Real(f) => rusqlite::types::Value::Real(*f),
            SqlValue::Text(s) => rusqlite::types::Value::Text(s.clone()),
            SqlValue::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
        }
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn publication_sdk_execute_statement_spelling_is_supported() {
        let request=serde_json::from_str::<SqlRequest>(r#"{"action":"execute_statement","name":"tinycloud.meetingPublication.v3","params":["{}"]}"#).unwrap();
        assert!(matches!(request, SqlRequest::ExecuteStatement { .. }));
    }

    #[test]
    fn query_deserializes_optional_camel_case_bounds() {
        let request: SqlRequest = serde_json::from_str(
            r#"{"action":"query","sql":"SELECT 1","maxRows":100,"maxBytes":1024}"#,
        )
        .unwrap();

        match request {
            SqlRequest::Query {
                max_rows,
                max_bytes,
                ..
            } => {
                assert_eq!(max_rows, Some(100));
                assert_eq!(max_bytes, Some(1024));
            }
            _ => panic!("expected query request"),
        }
    }

    #[test]
    fn request_rejects_unsigned_integer_overflow() {
        let error = serde_json::from_str::<SqlRequest>(
            r#"{"action":"query","sql":"SELECT ?","params":[18446744073709551615]}"#,
        )
        .expect_err("u64 values above SQLite's signed integer range must fail");

        assert!(error.to_string().contains("signed 64 bits"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SqlResponse {
    Query(QueryResponse),
    Execute(ExecuteResponse),
    Batch(BatchResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlValue>>,
    pub row_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteResponse {
    pub changes: u64,
    pub last_insert_row_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse {
    pub results: Vec<ExecuteResponse>,
}

#[derive(Debug, Clone)]
pub struct SqlExecutionResult {
    pub response: SqlResponse,
    pub write_targets: Vec<TouchedTables>,
}

#[derive(Debug, thiserror::Error)]
pub enum SqlError {
    #[error("SQLite error: {0}")]
    Sqlite(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Database not found")]
    DatabaseNotFound,
    #[error("sql_response_too_large: Response too large: {0} bytes (limit {1} bytes)")]
    ResponseTooLarge(u64, u64),
    #[error("Quota exceeded")]
    QuotaExceeded,
    /// The space is full and the request would have grown the database; it
    /// was undone.
    #[error("Write would grow a full database")]
    StorageWouldGrow,
    #[error("Invalid statement: {0}")]
    InvalidStatement(String),
    #[error("Schema error: {0}")]
    SchemaError(String),
    #[error("Read-only violation")]
    ReadOnlyViolation,
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Internal error: {0}")]
    Internal(String),
    /// The durable store was briefly unreachable or too slow (a lost
    /// connection, an exhausted pool, a statement timeout), and no write of
    /// the request can have taken effect: hydration failed, or the artifact
    /// write was refused or never sent. A fresh request is safe (TC-1054).
    /// A failure after the write was sent is [`SqlError::OutcomeUnknown`].
    #[error("unavailable_retryable: database storage temporarily unavailable; retry the request")]
    Unavailable,
    /// The connection was lost after the request's write was sent: it may
    /// or may not have been applied. The client must read the database back
    /// before deciding to retry (TC-1054).
    #[error(
        "outcome_unknown: the write may have been applied; read the database back before retrying"
    )]
    OutcomeUnknown,
    /// A bounded wait gave up before the request's write began, so nothing
    /// was applied (TC-1274). A retry after `Retry-After` is safe.
    #[error("sql_busy: {0}: the database is busy; retry the request")]
    Busy(SqlBusyStage),
    /// The request deadline was reached before the request's write began, so
    /// nothing was applied (TC-1274).
    #[error("request_timeout: no change was applied; retry the request")]
    RequestTimeout,
}

/// Where a [`SqlError::Busy`] request was waiting when its bound expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlBusyStage {
    /// The per-(space, db) operation lock.
    LockWait,
    /// Joining a hydration of the database's local cache that is still
    /// writing its files.
    Hydration,
    /// Loading or saving the durable database artifact.
    ArtifactTransfer,
}

impl SqlBusyStage {
    pub fn as_str(self) -> &'static str {
        match self {
            SqlBusyStage::LockWait => "lock_wait",
            SqlBusyStage::Hydration => "hydration",
            SqlBusyStage::ArtifactTransfer => "artifact_transfer",
        }
    }
}

impl std::fmt::Display for SqlBusyStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
