use crate::types::Metadata;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationSessionOpenRequest {
    pub space_id: String,
    pub service: String,
    pub prefix: Option<String>,
    pub db_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationSessionOpenResponse {
    pub session_token: String,
    pub space_id: String,
    pub service: String,
    pub prefix: Option<String>,
    pub db_name: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationInfoRequest {
    pub include_endpoints: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationExportRequest {
    pub space_id: String,
    pub prefix: Option<String>,
    pub since_seq: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationReconcileRequest {
    pub peer_url: String,
    pub space_id: String,
    pub prefix: Option<String>,
    pub since_seq: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationExportResponse {
    pub space_id: String,
    pub prefix: Option<String>,
    pub requested_since_seq: Option<i64>,
    pub exported_until_seq: Option<i64>,
    pub sequences: Vec<KvReplicationSequence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationApplyResponse {
    pub space_id: String,
    pub requested_since_seq: Option<i64>,
    pub peer_url: Option<String>,
    pub applied_sequences: usize,
    pub applied_events: usize,
    pub applied_until_seq: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlReplicationExportRequest {
    pub space_id: String,
    pub db_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlReplicationReconcileRequest {
    pub peer_url: String,
    pub space_id: String,
    pub db_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlReplicationExportResponse {
    pub space_id: String,
    pub db_name: String,
    pub snapshot: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlReplicationApplyResponse {
    pub space_id: String,
    pub db_name: String,
    pub peer_url: Option<String>,
    pub snapshot_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReplicationSequence {
    pub seq: i64,
    pub epoch: String,
    pub events: Vec<KvReplicationEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReplicationEvent {
    pub invocation_id: String,
    pub invocation: String,
    pub delegations: Vec<String>,
    pub operation: KvReplicationOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum KvReplicationOperation {
    Put {
        key: String,
        value_hash: String,
        metadata: Metadata,
        content: Vec<u8>,
    },
    Delete {
        key: String,
        deleted_invocation_id: String,
        deleted_seq: i64,
        deleted_epoch: String,
        deleted_epoch_seq: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationErrorResponse {
    pub message: String,
}
