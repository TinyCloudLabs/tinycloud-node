use serde::Deserialize;
use serde_json::Value as JsonValue;

/// Parameters for SQL reads.
/// Passed via the UCAN invocation facts field under `sqlReadParams`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SqlReadParams {
    #[serde(rename = "canonical")]
    Canonical,
    #[serde(rename = "provisional")]
    Provisional,
}

impl Default for SqlReadParams {
    fn default() -> Self {
        Self::Canonical
    }
}

impl SqlReadParams {
    pub fn from_facts(facts: &[JsonValue]) -> Option<Self> {
        facts.iter().find_map(|fact| {
            fact.as_object()
                .and_then(|obj| obj.get("sqlReadParams"))
                .and_then(|value| serde_json::from_value(value.clone()).ok())
        })
    }

    pub fn uses_provisional(self) -> bool {
        matches!(self, Self::Provisional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sql_read_params_from_facts() {
        let facts = vec![serde_json::json!({
            "sqlReadParams": { "type": "provisional" }
        })];

        assert_eq!(
            SqlReadParams::from_facts(&facts),
            Some(SqlReadParams::Provisional)
        );
    }

    #[test]
    fn defaults_to_canonical_when_absent() {
        assert_eq!(SqlReadParams::default(), SqlReadParams::Canonical);
        assert!(!SqlReadParams::Canonical.uses_provisional());
        assert!(SqlReadParams::Provisional.uses_provisional());
    }
}
