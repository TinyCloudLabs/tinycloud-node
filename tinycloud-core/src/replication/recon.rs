use super::{
    keys::KvReconKey,
    messages::{
        KvReconItem, KvReconSplitChild, KvReconSplitChildComparison, KvReconSplitChildStatus,
    },
    store::encode_hash,
};
use crate::{hash::Blake3Hasher, models::kv_write};
use serde::Serialize;
use std::collections::BTreeMap;

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

pub fn window_kv_recon_items(
    items: &[KvReconItem],
    start_after: Option<&str>,
    limit: Option<usize>,
) -> (Vec<KvReconItem>, bool, Option<String>) {
    let start_index = start_after.map_or(0, |cursor| {
        match items.binary_search_by(|item| item.recon_key.as_str().cmp(cursor)) {
            Ok(index) => index + 1,
            Err(index) => index,
        }
    });
    let end_index = limit.map_or(items.len(), |limit| {
        start_index.saturating_add(limit).min(items.len())
    });
    let window = items[start_index..end_index].to_vec();
    let has_more = end_index < items.len();
    let next_start_after = window
        .last()
        .map(|item| item.recon_key.clone())
        .filter(|_| has_more);

    (window, has_more, next_start_after)
}

pub fn split_kv_recon_items(items: &[KvReconItem], prefix: Option<&str>) -> Vec<KvReconSplitChild> {
    let normalized_prefix = normalized_split_prefix(prefix);
    let mut groups = BTreeMap::<String, Vec<KvReconItem>>::new();

    for item in items {
        let child_prefix = child_prefix_for_key(normalized_prefix, &item.key);
        groups.entry(child_prefix).or_default().push(item.clone());
    }

    groups
        .into_iter()
        .map(|(prefix, items)| KvReconSplitChild {
            leaf: items.iter().all(|item| item.key == prefix),
            item_count: items.len(),
            fingerprint: kv_recon_fingerprint(&items),
            prefix,
        })
        .collect()
}

pub fn compare_kv_recon_split_children(
    local: &[KvReconSplitChild],
    peer: &[KvReconSplitChild],
) -> Vec<KvReconSplitChildComparison> {
    let mut prefixes =
        BTreeMap::<String, (Option<&KvReconSplitChild>, Option<&KvReconSplitChild>)>::new();

    for child in local {
        prefixes.entry(child.prefix.clone()).or_default().0 = Some(child);
    }
    for child in peer {
        prefixes.entry(child.prefix.clone()).or_default().1 = Some(child);
    }

    prefixes
        .into_iter()
        .map(|(prefix, (local, peer))| {
            let status = match (local, peer) {
                (Some(local), Some(peer))
                    if local.item_count == peer.item_count
                        && local.fingerprint == peer.fingerprint =>
                {
                    KvReconSplitChildStatus::Match
                }
                (Some(_), Some(_)) => KvReconSplitChildStatus::Mismatch,
                (None, Some(_)) => KvReconSplitChildStatus::LocalMissing,
                (Some(_), None) => KvReconSplitChildStatus::PeerMissing,
                (None, None) => KvReconSplitChildStatus::Mismatch,
            };

            KvReconSplitChildComparison {
                prefix,
                status: split_child_status_label(&status).to_string(),
                local_item_count: local.map_or(0, |child| child.item_count),
                peer_item_count: peer.map_or(0, |child| child.item_count),
                local_fingerprint: local
                    .map(|child| child.fingerprint.clone())
                    .unwrap_or_default(),
                peer_fingerprint: peer
                    .map(|child| child.fingerprint.clone())
                    .unwrap_or_default(),
                leaf: local
                    .map(|child| child.leaf)
                    .or_else(|| peer.map(|child| child.leaf))
                    .unwrap_or(false),
            }
        })
        .collect()
}

pub fn first_kv_recon_mismatch(left: &[KvReconItem], right: &[KvReconItem]) -> Option<String> {
    let mismatch_len = left.len().min(right.len());
    for index in 0..mismatch_len {
        if left[index].kind != right[index].kind
            || left[index].recon_key != right[index].recon_key
            || left[index].invocation_id != right[index].invocation_id
            || left[index].value_hash != right[index].value_hash
            || left[index].metadata != right[index].metadata
        {
            return Some(left[index].key.clone());
        }
    }

    if left.len() > mismatch_len {
        return left.get(mismatch_len).map(|item| item.key.clone());
    }
    if right.len() > mismatch_len {
        return right.get(mismatch_len).map(|item| item.key.clone());
    }

    None
}

fn normalized_split_prefix(prefix: Option<&str>) -> Option<&str> {
    prefix.and_then(|value| {
        let trimmed = value.trim_end_matches('/');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn child_prefix_for_key(prefix: Option<&str>, key: &str) -> String {
    let remainder = match prefix {
        Some(prefix) if key == prefix => "",
        Some(prefix) => key
            .strip_prefix(prefix)
            .and_then(|value| value.strip_prefix('/'))
            .unwrap_or(key),
        None => key,
    };

    if remainder.is_empty() {
        return prefix.unwrap_or(key).to_string();
    }

    let segment = remainder.split('/').next().unwrap_or(remainder);
    match prefix {
        Some(prefix) => format!("{prefix}/{segment}"),
        None => segment.to_string(),
    }
}

fn split_child_status_label(status: &KvReconSplitChildStatus) -> &'static str {
    match status {
        KvReconSplitChildStatus::Match => "match",
        KvReconSplitChildStatus::LocalMissing => "local-missing",
        KvReconSplitChildStatus::PeerMissing => "peer-missing",
        KvReconSplitChildStatus::Mismatch => "mismatch",
    }
}
