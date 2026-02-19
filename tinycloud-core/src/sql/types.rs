use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum SqlRequest {
    #[serde(rename = "query")]
    Query {
        sql: String,
        #[serde(default)]
        params: Vec<SqlValue>,
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
    #[serde(rename = "executeStatement")]
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

#[derive(Debug, Clone)]
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
                Ok(SqlValue::Integer(v as i64))
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
    pub last_insert_row_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse {
    pub results: Vec<ExecuteResponse>,
}

#[derive(Debug, thiserror::Error)]
pub enum SqlError {
    #[error("SQLite error: {0}")]
    Sqlite(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Database not found")]
    DatabaseNotFound,
    #[error("Response too large: {0} bytes")]
    ResponseTooLarge(u64),
    #[error("Quota exceeded")]
    QuotaExceeded,
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
}
