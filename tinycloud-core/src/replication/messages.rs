use crate::types::Metadata;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationSessionOpenRequest {
    pub space_id: String,
    pub service: String,
    pub prefix: Option<String>,
    pub db_name: Option<String>,
    pub supporting_delegations: Option<Vec<String>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReconExportRequest {
    pub space_id: String,
    pub prefix: Option<String>,
    pub start_after: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KvReconItem {
    pub key: String,
    pub kind: String,
    pub recon_key: String,
    pub invocation_id: String,
    pub seq: i64,
    pub epoch: String,
    pub epoch_seq: i64,
    pub value_hash: String,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconExportResponse {
    pub space_id: String,
    pub prefix: Option<String>,
    pub start_after: Option<String>,
    pub limit: Option<usize>,
    pub item_count: usize,
    pub has_more: bool,
    pub next_start_after: Option<String>,
    pub fingerprint: String,
    pub items: Vec<KvReconItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitRequest {
    pub space_id: String,
    pub prefix: Option<String>,
    pub child_start_after: Option<String>,
    pub child_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitChild {
    pub prefix: String,
    pub item_count: usize,
    pub fingerprint: String,
    pub leaf: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitResponse {
    pub space_id: String,
    pub prefix: Option<String>,
    pub child_start_after: Option<String>,
    pub child_limit: Option<usize>,
    pub item_count: usize,
    pub fingerprint: String,
    pub has_more: bool,
    pub next_child_start_after: Option<String>,
    pub children: Vec<KvReconSplitChild>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitCompareRequest {
    pub peer_url: String,
    pub space_id: String,
    pub prefix: Option<String>,
    pub child_start_after: Option<String>,
    pub child_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KvReconSplitChildStatus {
    Match,
    LocalMissing,
    PeerMissing,
    Mismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitChildComparison {
    pub prefix: String,
    pub status: String,
    pub local_item_count: usize,
    pub peer_item_count: usize,
    pub local_fingerprint: String,
    pub peer_fingerprint: String,
    pub leaf: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitCompareResponse {
    pub space_id: String,
    pub prefix: Option<String>,
    pub peer_url: String,
    pub child_start_after: Option<String>,
    pub child_limit: Option<usize>,
    pub matches: bool,
    pub has_more: bool,
    pub next_child_start_after: Option<String>,
    pub children: Vec<KvReconSplitChildComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitReconcileRequest {
    pub peer_url: String,
    pub space_id: String,
    pub prefix: Option<String>,
    pub child_start_after: Option<String>,
    pub child_limit: Option<usize>,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitReconcileChildResult {
    pub prefix: String,
    pub before_status: String,
    pub after_status: String,
    pub applied_sequences: usize,
    pub applied_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconSplitReconcileResponse {
    pub space_id: String,
    pub prefix: Option<String>,
    pub peer_url: String,
    pub child_start_after: Option<String>,
    pub child_limit: Option<usize>,
    pub matches: bool,
    pub has_more: bool,
    pub next_child_start_after: Option<String>,
    pub attempted_children: usize,
    pub reconciled_children: usize,
    pub children: Vec<KvReconSplitReconcileChildResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvReconCompareRequest {
    pub peer_url: String,
    pub space_id: String,
    pub prefix: Option<String>,
    pub start_after: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KvReconCompareResponse {
    pub space_id: String,
    pub prefix: Option<String>,
    pub peer_url: String,
    pub start_after: Option<String>,
    pub limit: Option<usize>,
    pub matches: bool,
    pub local_item_count: usize,
    pub peer_item_count: usize,
    pub local_has_more: bool,
    pub peer_has_more: bool,
    pub local_next_start_after: Option<String>,
    pub peer_next_start_after: Option<String>,
    pub local_fingerprint: String,
    pub peer_fingerprint: String,
    pub first_mismatch_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthReplicationExportRequest {
    pub space_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthReplicationReconcileRequest {
    pub peer_url: String,
    pub space_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthReplicationExportResponse {
    pub space_id: String,
    pub delegations: Vec<String>,
    pub revocations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthReplicationApplyResponse {
    pub space_id: String,
    pub peer_url: Option<String>,
    pub imported_delegations: usize,
    pub imported_revocations: usize,
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
