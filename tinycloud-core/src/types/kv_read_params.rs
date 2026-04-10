use serde::Deserialize;
use serde_json::Value as JsonValue;

/// Parameters for KV reads.
/// Passed via the UCAN invocation facts field under `kvReadParams`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum KvReadParams {
    /// Hide keys present in `kv_quarantine`.
    #[serde(rename = "canonical")]
    Canonical,
    /// Preserve the existing visibility behavior, including quarantined keys.
    #[serde(rename = "provisional")]
    Provisional,
}

impl Default for KvReadParams {
    fn default() -> Self {
        Self::Canonical
    }
}

impl KvReadParams {
    pub fn from_facts(facts: &[JsonValue]) -> Option<Self> {
        facts.iter().find_map(|fact| {
            fact.as_object()
                .and_then(|obj| obj.get("kvReadParams"))
                .and_then(|value| serde_json::from_value(value.clone()).ok())
        })
    }

    pub fn hides_quarantined_keys(self) -> bool {
        matches!(self, Self::Canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kv_read_params_from_facts() {
        let facts = vec![serde_json::json!({
            "kvReadParams": { "type": "provisional" }
        })];

        assert_eq!(
            KvReadParams::from_facts(&facts),
            Some(KvReadParams::Provisional)
        );
    }

    #[test]
    fn defaults_to_canonical_when_absent() {
        assert_eq!(KvReadParams::default(), KvReadParams::Canonical);
        assert!(KvReadParams::Canonical.hides_quarantined_keys());
        assert!(!KvReadParams::Provisional.hides_quarantined_keys());
    }
}
