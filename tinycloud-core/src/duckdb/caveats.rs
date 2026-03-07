use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DuckDbCaveats {
    pub tables: Option<Vec<String>>,
    pub columns: Option<Vec<String>>,
    pub statements: Option<Vec<PreparedStatement>>,
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedStatement {
    pub name: String,
    pub sql: String,
}

impl DuckDbCaveats {
    pub fn from_caveats(caveats: &BTreeMap<String, serde_json::Value>) -> Option<Self> {
        caveats
            .get("duckdbCaveats")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn is_table_allowed(&self, table: &str) -> bool {
        match &self.tables {
            None => true,
            Some(tables) => tables.iter().any(|t| t == table),
        }
    }

    pub fn is_column_allowed(&self, column: &str) -> bool {
        match &self.columns {
            None => true,
            Some(columns) => {
                if column == "*" {
                    return false;
                }
                columns.iter().any(|c| c == column)
            }
        }
    }

    pub fn is_write_allowed(&self) -> bool {
        !self.read_only.unwrap_or(false)
    }

    pub fn find_statement(&self, name: &str) -> Option<&PreparedStatement> {
        self.statements.as_ref()?.iter().find(|s| s.name == name)
    }

    pub fn find_statement_by_sql(&self, sql: &str) -> Option<&PreparedStatement> {
        self.statements.as_ref()?.iter().find(|s| s.sql == sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_table_allowed_none() {
        let c = DuckDbCaveats {
            tables: None,
            columns: None,
            statements: None,
            read_only: None,
        };
        assert!(c.is_table_allowed("anything"));
    }

    #[test]
    fn test_table_allowed_some() {
        let c = DuckDbCaveats {
            tables: Some(vec!["users".to_string(), "orders".to_string()]),
            columns: None,
            statements: None,
            read_only: None,
        };
        assert!(c.is_table_allowed("users"));
        assert!(c.is_table_allowed("orders"));
        assert!(!c.is_table_allowed("secrets"));
    }

    #[test]
    fn test_column_allowed_wildcard() {
        let c = DuckDbCaveats {
            tables: None,
            columns: Some(vec!["name".to_string()]),
            statements: None,
            read_only: None,
        };
        assert!(!c.is_column_allowed("*"));
        assert!(c.is_column_allowed("name"));
        assert!(!c.is_column_allowed("secret"));
    }

    #[test]
    fn test_column_allowed_none() {
        let c = DuckDbCaveats {
            tables: None,
            columns: None,
            statements: None,
            read_only: None,
        };
        assert!(c.is_column_allowed("*"));
        assert!(c.is_column_allowed("anything"));
    }

    #[test]
    fn test_from_caveats_deserialization() {
        let mut map = BTreeMap::new();
        map.insert(
            "duckdbCaveats".to_string(),
            serde_json::json!({
                "tables": ["users"],
                "readOnly": true
            }),
        );
        let result = DuckDbCaveats::from_caveats(&map);
        assert!(result.is_some());
        let c = result.unwrap();
        assert_eq!(c.tables, Some(vec!["users".to_string()]));
        assert_eq!(c.read_only, Some(true));
        assert!(c.columns.is_none());
    }

    #[test]
    fn test_find_statement() {
        let c = DuckDbCaveats {
            tables: None,
            columns: None,
            statements: Some(vec![PreparedStatement {
                name: "get_users".to_string(),
                sql: "SELECT * FROM users".to_string(),
            }]),
            read_only: None,
        };
        assert!(c.find_statement("get_users").is_some());
        assert!(c.find_statement("nonexistent").is_none());
    }

    #[test]
    fn test_find_statement_by_sql() {
        let c = DuckDbCaveats {
            tables: None,
            columns: None,
            statements: Some(vec![PreparedStatement {
                name: "special".to_string(),
                sql: "COPY users TO 'file.csv'".to_string(),
            }]),
            read_only: None,
        };
        assert!(c
            .find_statement_by_sql("COPY users TO 'file.csv'")
            .is_some());
        assert!(c.find_statement_by_sql("DROP TABLE users").is_none());
    }
}
