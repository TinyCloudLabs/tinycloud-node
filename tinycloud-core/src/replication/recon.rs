use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconInterest {
    pub service: &'static str,
    pub range: String,
}
