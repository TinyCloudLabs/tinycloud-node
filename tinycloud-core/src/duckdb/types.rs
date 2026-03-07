use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum DuckDbRequest {
    #[serde(rename = "query")]
    Query {
        sql: String,
        #[serde(default)]
        params: Vec<DuckDbValue>,
    },
    #[serde(rename = "execute")]
    Execute {
        sql: String,
        #[serde(default)]
        params: Vec<DuckDbValue>,
        #[serde(default)]
        schema: Option<Vec<String>>,
    },
    #[serde(rename = "batch")]
    Batch {
        statements: Vec<DuckDbStatement>,
        #[serde(default)]
        transactional: bool,
    },
    #[serde(rename = "executeStatement")]
    ExecuteStatement {
        name: String,
        #[serde(default)]
        params: Vec<DuckDbValue>,
    },
    #[serde(rename = "describe")]
    Describe,
    #[serde(rename = "ingest")]
    Ingest { statement: IngestStatement },
    #[serde(rename = "exportToKv")]
    ExportToKv {
        sql: String,
        key: String,
        #[serde(default = "default_export_format")]
        format: String,
    },
    #[serde(rename = "export")]
    Export,
    #[serde(rename = "import")]
    Import { data: Vec<u8> },
}

fn default_export_format() -> String {
    "parquet".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuckDbStatement {
    pub sql: String,
    #[serde(default)]
    pub params: Vec<DuckDbValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestStatement {
    pub source: String,
    #[serde(default = "default_ingest_format")]
    pub format: String,
    pub table: String,
    #[serde(default = "default_ingest_mode")]
    pub mode: String,
}

fn default_ingest_format() -> String {
    "parquet".to_string()
}

fn default_ingest_mode() -> String {
    "create".to_string()
}

#[derive(Debug, Clone)]
pub enum DuckDbValue {
    Null,
    Boolean(bool),
    Integer(i64),
    BigInt(i128),
    Float(f32),
    Double(f64),
    Text(String),
    Blob(Vec<u8>),
    Date(String),
    Timestamp(String),
    List(Vec<DuckDbValue>),
    Struct(HashMap<String, DuckDbValue>),
}

impl Serialize for DuckDbValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            DuckDbValue::Null => serializer.serialize_none(),
            DuckDbValue::Boolean(b) => serializer.serialize_bool(*b),
            DuckDbValue::Integer(i) => serializer.serialize_i64(*i),
            DuckDbValue::BigInt(i) => {
                // Serialize i128 as string to preserve precision
                serializer.serialize_str(&i.to_string())
            }
            DuckDbValue::Float(f) => serializer.serialize_f32(*f),
            DuckDbValue::Double(f) => serializer.serialize_f64(*f),
            DuckDbValue::Text(s) => serializer.serialize_str(s),
            DuckDbValue::Blob(b) => serializer.serialize_bytes(b),
            DuckDbValue::Date(s) => serializer.serialize_str(s),
            DuckDbValue::Timestamp(s) => serializer.serialize_str(s),
            DuckDbValue::List(items) => items.serialize(serializer),
            DuckDbValue::Struct(fields) => fields.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for DuckDbValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DuckDbValueVisitor;

        impl<'de> serde::de::Visitor<'de> for DuckDbValueVisitor {
            type Value = DuckDbValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a DuckDB value (null, boolean, integer, float, string, array, or object)",
                )
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Null)
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Null)
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<DuckDbValue, D::Error> {
                Deserialize::deserialize(deserializer)
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Boolean(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Integer(v))
            }

            fn visit_i128<E: serde::de::Error>(self, v: i128) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::BigInt(v))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Integer(v as i64))
            }

            fn visit_f32<E: serde::de::Error>(self, v: f32) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Float(v))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Double(v))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Text(v.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Text(v))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Blob(v.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<DuckDbValue, E> {
                Ok(DuckDbValue::Blob(v))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<DuckDbValue, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<DuckDbValue>()? {
                    items.push(item);
                }
                Ok(DuckDbValue::List(items))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<DuckDbValue, A::Error> {
                let mut fields = HashMap::new();
                while let Some((key, value)) = map.next_entry::<String, DuckDbValue>()? {
                    fields.insert(key, value);
                }
                Ok(DuckDbValue::Struct(fields))
            }
        }

        deserializer.deserialize_any(DuckDbValueVisitor)
    }
}

impl From<duckdb::types::Value> for DuckDbValue {
    fn from(v: duckdb::types::Value) -> Self {
        match v {
            duckdb::types::Value::Null => DuckDbValue::Null,
            duckdb::types::Value::Boolean(b) => DuckDbValue::Boolean(b),
            duckdb::types::Value::TinyInt(i) => DuckDbValue::Integer(i as i64),
            duckdb::types::Value::SmallInt(i) => DuckDbValue::Integer(i as i64),
            duckdb::types::Value::Int(i) => DuckDbValue::Integer(i as i64),
            duckdb::types::Value::BigInt(i) => DuckDbValue::Integer(i),
            duckdb::types::Value::HugeInt(i) => DuckDbValue::BigInt(i),
            duckdb::types::Value::UTinyInt(i) => DuckDbValue::Integer(i as i64),
            duckdb::types::Value::USmallInt(i) => DuckDbValue::Integer(i as i64),
            duckdb::types::Value::UInt(i) => DuckDbValue::Integer(i as i64),
            duckdb::types::Value::UBigInt(i) => {
                if i <= i64::MAX as u64 {
                    DuckDbValue::Integer(i as i64)
                } else {
                    DuckDbValue::Text(i.to_string())
                }
            }
            duckdb::types::Value::Float(f) => DuckDbValue::Float(f),
            duckdb::types::Value::Double(f) => DuckDbValue::Double(f),
            duckdb::types::Value::Decimal(d) => DuckDbValue::Text(ToString::to_string(&d)),
            duckdb::types::Value::Timestamp(unit, val) => {
                let ts = format_timestamp(unit, val);
                DuckDbValue::Timestamp(ts)
            }
            duckdb::types::Value::Text(s) => DuckDbValue::Text(s),
            duckdb::types::Value::Blob(b) => DuckDbValue::Blob(b),
            duckdb::types::Value::Date32(d) => {
                // Days since Unix epoch
                DuckDbValue::Date(format_date32(d))
            }
            duckdb::types::Value::Time64(unit, val) => {
                let t = format_time64(unit, val);
                DuckDbValue::Text(t)
            }
            duckdb::types::Value::Interval {
                months,
                days,
                nanos,
            } => DuckDbValue::Text(format!(
                "INTERVAL {} months {} days {} nanos",
                months, days, nanos
            )),
            duckdb::types::Value::List(items) => {
                DuckDbValue::List(items.into_iter().map(DuckDbValue::from).collect())
            }
            duckdb::types::Value::Enum(s) => DuckDbValue::Text(s),
            duckdb::types::Value::Struct(ordered_map) => {
                let mut fields = HashMap::new();
                for (k, v) in ordered_map.iter() {
                    fields.insert(k.clone(), DuckDbValue::from(v.clone()));
                }
                DuckDbValue::Struct(fields)
            }
            duckdb::types::Value::Array(items) => {
                DuckDbValue::List(items.into_iter().map(DuckDbValue::from).collect())
            }
            duckdb::types::Value::Map(ordered_map) => {
                let mut fields = HashMap::new();
                for (k, v) in ordered_map.iter() {
                    let key_str = match k {
                        duckdb::types::Value::Text(s) => s.clone(),
                        duckdb::types::Value::Boolean(b) => b.to_string(),
                        duckdb::types::Value::TinyInt(i) => i.to_string(),
                        duckdb::types::Value::SmallInt(i) => i.to_string(),
                        duckdb::types::Value::Int(i) => i.to_string(),
                        duckdb::types::Value::BigInt(i) => i.to_string(),
                        duckdb::types::Value::Float(f) => f.to_string(),
                        duckdb::types::Value::Double(f) => f.to_string(),
                        other => format!("{:?}", other),
                    };
                    fields.insert(key_str, DuckDbValue::from(v.clone()));
                }
                DuckDbValue::Struct(fields)
            }
            duckdb::types::Value::Union(boxed) => DuckDbValue::from(*boxed),
        }
    }
}

impl From<&DuckDbValue> for duckdb::types::Value {
    fn from(v: &DuckDbValue) -> Self {
        match v {
            DuckDbValue::Null => duckdb::types::Value::Null,
            DuckDbValue::Boolean(b) => duckdb::types::Value::Boolean(*b),
            DuckDbValue::Integer(i) => duckdb::types::Value::BigInt(*i),
            DuckDbValue::BigInt(i) => duckdb::types::Value::HugeInt(*i),
            DuckDbValue::Float(f) => duckdb::types::Value::Float(*f),
            DuckDbValue::Double(f) => duckdb::types::Value::Double(*f),
            DuckDbValue::Text(s) => duckdb::types::Value::Text(s.clone()),
            DuckDbValue::Blob(b) => duckdb::types::Value::Blob(b.clone()),
            DuckDbValue::Date(s) => duckdb::types::Value::Text(s.clone()),
            DuckDbValue::Timestamp(s) => duckdb::types::Value::Text(s.clone()),
            DuckDbValue::List(items) => {
                duckdb::types::Value::List(items.iter().map(duckdb::types::Value::from).collect())
            }
            DuckDbValue::Struct(fields) => {
                let pairs: Vec<(String, duckdb::types::Value)> = fields
                    .iter()
                    .map(|(k, v)| (k.clone(), duckdb::types::Value::from(v)))
                    .collect();
                duckdb::types::Value::Struct(duckdb::types::OrderedMap::from(pairs))
            }
        }
    }
}

fn format_timestamp(unit: duckdb::types::TimeUnit, val: i64) -> String {
    let micros = match unit {
        duckdb::types::TimeUnit::Second => val * 1_000_000,
        duckdb::types::TimeUnit::Millisecond => val * 1_000,
        duckdb::types::TimeUnit::Microsecond => val,
        duckdb::types::TimeUnit::Nanosecond => val / 1_000,
    };
    let secs = micros / 1_000_000;
    let remaining_micros = (micros % 1_000_000).unsigned_abs();
    format!("{}.{:06}", secs, remaining_micros)
}

fn format_date32(days: i32) -> String {
    // Days since Unix epoch (1970-01-01)
    let epoch =
        time::Date::from_calendar_date(1970, time::Month::January, 1).expect("valid epoch date");
    match epoch.checked_add(time::Duration::days(days as i64)) {
        Some(date) => {
            let format =
                time::format_description::parse("[year]-[month]-[day]").expect("valid format");
            date.format(&format).unwrap_or_else(|_| days.to_string())
        }
        None => days.to_string(),
    }
}

fn format_time64(unit: duckdb::types::TimeUnit, val: i64) -> String {
    let micros = match unit {
        duckdb::types::TimeUnit::Second => val * 1_000_000,
        duckdb::types::TimeUnit::Millisecond => val * 1_000,
        duckdb::types::TimeUnit::Microsecond => val,
        duckdb::types::TimeUnit::Nanosecond => val / 1_000,
    };
    let total_secs = micros / 1_000_000;
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    let remaining_micros = (micros % 1_000_000).unsigned_abs();
    format!(
        "{:02}:{:02}:{:02}.{:06}",
        hours, mins, secs, remaining_micros
    )
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum DuckDbResponse {
    Query(QueryResponse),
    Execute(ExecuteResponse),
    Batch(BatchResponse),
    Describe(SchemaInfo),
    Ingest(IngestResponse),
    ExportToKv(ExportResponse),
    Arrow(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<DuckDbValue>>,
    pub row_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteResponse {
    pub changes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse {
    pub results: Vec<ExecuteResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaInfo {
    pub tables: Vec<TableInfo>,
    pub views: Vec<ViewInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    #[serde(rename = "nullable")]
    pub is_nullable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewInfo {
    pub name: String,
    pub sql: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestResponse {
    pub rows_inserted: u64,
    pub table: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResponse {
    pub key: String,
    pub size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DuckDbError {
    #[error("DuckDB error: {0}")]
    DuckDb(String),
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
    #[error("Ingest error: {0}")]
    IngestError(String),
    #[error("Export error: {0}")]
    ExportError(String),
    #[error("Import error: {0}")]
    ImportError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubigint_no_truncation() {
        let max_u64 = u64::MAX;
        let val = DuckDbValue::from(duckdb::types::Value::UBigInt(max_u64));
        match val {
            DuckDbValue::Text(s) => assert_eq!(s, max_u64.to_string()),
            _ => panic!("Expected Text for u64::MAX, got {:?}", val),
        }
    }

    #[test]
    fn test_ubigint_small_value() {
        let val = DuckDbValue::from(duckdb::types::Value::UBigInt(42));
        match val {
            DuckDbValue::Integer(i) => assert_eq!(i, 42),
            _ => panic!("Expected Integer for small u64, got {:?}", val),
        }
    }

    #[test]
    fn test_map_key_formatting() {
        let pairs: Vec<(duckdb::types::Value, duckdb::types::Value)> = vec![
            (
                duckdb::types::Value::Text("key1".to_string()),
                duckdb::types::Value::Int(1),
            ),
            (
                duckdb::types::Value::Int(42),
                duckdb::types::Value::Text("val".to_string()),
            ),
        ];
        let map = duckdb::types::Value::Map(duckdb::types::OrderedMap::from(pairs));
        let converted = DuckDbValue::from(map);
        match converted {
            DuckDbValue::Struct(fields) => {
                assert!(
                    fields.contains_key("key1"),
                    "Missing text key, got keys: {:?}",
                    fields.keys().collect::<Vec<_>>()
                );
                assert!(
                    fields.contains_key("42"),
                    "Missing int key, got keys: {:?}",
                    fields.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("Expected Struct, got {:?}", converted),
        }
    }

    #[test]
    fn test_column_info_serialization() {
        let col = ColumnInfo {
            name: "id".to_string(),
            data_type: "INTEGER".to_string(),
            is_nullable: false,
        };
        let json = serde_json::to_value(&col).unwrap();
        assert_eq!(json["name"], "id");
        assert_eq!(json["type"], "INTEGER");
        assert_eq!(json["nullable"], false);
        // Should NOT have "dataType" or "isNullable"
        assert!(json.get("dataType").is_none());
        assert!(json.get("isNullable").is_none());
    }
}
