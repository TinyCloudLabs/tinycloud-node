use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDescriptor {
    pub space: String,
    pub base_commit_seq: i64,
    pub format: &'static str,
}
