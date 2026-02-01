use serde::Deserialize;

/// Parameters for the capabilities/read invocation.
/// Passed via the UCAN facts field.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum CapabilitiesReadParams {
    /// List delegations with optional filters
    #[serde(rename = "list")]
    List {
        /// Optional filters to apply
        filters: Option<ListFilters>,
    },
    /// Get the delegation chain for a specific delegation
    #[serde(rename = "chain")]
    Chain {
        /// The CID of the delegation to get the chain for
        delegation_cid: String,
    },
}

/// Filters for listing delegations
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListFilters {
    /// Filter by direction relative to the invoker
    /// - "created": delegations where invoker is the delegator
    /// - "received": delegations where invoker is the delegatee
    /// - "all" or None: no direction filter
    pub direction: Option<String>,
    /// Filter by resource path prefix
    pub path: Option<String>,
    /// Filter by ability (must match one of these)
    pub actions: Option<Vec<String>>,
}
