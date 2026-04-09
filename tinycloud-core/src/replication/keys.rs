use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationKeyspace {
    pub service: &'static str,
    pub scope: String,
}
