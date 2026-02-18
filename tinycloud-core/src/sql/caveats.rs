use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SqlCaveats {
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

impl SqlCaveats {
    pub fn from_caveats(caveats: &BTreeMap<String, serde_json::Value>) -> Option<Self> {
        serde_json::to_value(caveats)
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
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
            Some(columns) => columns.iter().any(|c| c == column),
        }
    }

    pub fn is_write_allowed(&self) -> bool {
        !self.read_only.unwrap_or(false)
    }

    pub fn find_statement(&self, name: &str) -> Option<&PreparedStatement> {
        self.statements.as_ref()?.iter().find(|s| s.name == name)
    }
}
