use super::store::encode_hash;
use crate::types::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationKeyspace {
    pub service: &'static str,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct KvReconKey {
    pub encoded: String,
}

impl KvReconKey {
    pub fn new(path: &Path, invocation_id: crate::hash::Hash) -> Self {
        Self {
            encoded: format!("{}\u{0000}{}", path, encode_hash(invocation_id)),
        }
    }
}
