#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchedTables {
    Supported(Vec<String>),
    Unsupported,
}

impl TouchedTables {
    pub fn supported(tables: Vec<String>) -> Self {
        Self::Supported(tables)
    }

    pub fn unsupported() -> Self {
        Self::Unsupported
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }

    pub fn tables(&self) -> Option<&[String]> {
        match self {
            Self::Supported(tables) => Some(tables),
            Self::Unsupported => None,
        }
    }
}

pub fn db_table_path(db_name: &str, table_name: &str) -> String {
    format!("{db_name}/{table_name}")
}
