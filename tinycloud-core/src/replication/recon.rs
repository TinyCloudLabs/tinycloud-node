use super::{keys::KvReconKey, messages::KvReconItem, store::encode_hash};
use crate::{
    hash::Blake3Hasher,
    models::kv_write,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconInterest {
    pub service: &'static str,
    pub range: String,
}

pub fn kv_recon_item(write: &kv_write::Model) -> KvReconItem {
    let recon_key = KvReconKey::new(&write.key, write.invocation);
    KvReconItem {
        key: write.key.to_string(),
        kind: "put".to_string(),
        recon_key: recon_key.encoded,
        invocation_id: encode_hash(write.invocation),
        seq: write.seq,
        epoch: encode_hash(write.epoch),
        epoch_seq: write.epoch_seq,
        value_hash: encode_hash(write.value),
        metadata: write.metadata.clone(),
    }
}

pub fn sort_kv_recon_items(items: &mut [KvReconItem]) {
    items.sort_by(|left, right| left.recon_key.cmp(&right.recon_key));
}

pub fn kv_recon_fingerprint(items: &[KvReconItem]) -> String {
    let mut hasher = Blake3Hasher::new();
    for item in items {
        hasher.update(item.recon_key.as_bytes());
        hasher.update(&[0]);
        hasher.update(item.key.as_bytes());
        hasher.update(&[0]);
        hasher.update(item.invocation_id.as_bytes());
        hasher.update(&[0]);
        hasher.update(item.value_hash.as_bytes());
        hasher.update(&[0]);
        for (key, value) in &item.metadata.0 {
            hasher.update(key.as_bytes());
            hasher.update(&[0]);
            hasher.update(value.as_bytes());
            hasher.update(&[0]);
        }
        hasher.update(&[0xff]);
    }
    encode_hash(hasher.finalize())
}
