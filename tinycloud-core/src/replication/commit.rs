use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalCommitRef {
    pub space: String,
    pub commit_seq: i64,
    pub authored_fact: String,
}
