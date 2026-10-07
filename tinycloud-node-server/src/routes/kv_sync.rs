//! TC-732: the HTTP side of the `tinycloud.kv/sync` change feed.
//!
//! The feed rides on `/invoke`, so admission, the replay cache, read audit
//! and CORS are the ordinary KV read path. This module owns what is specific
//! to the feed's wire format: its request headers, the JSON response and its
//! typed error bodies. The cursor itself is sealed and opened in
//! `tinycloud_core::kv_sync`, after authorization; see
//! `docs/kv-sync.md` for the full contract.

use rocket::http::Status;
use serde::Serialize;
use std::collections::BTreeMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_core::hash::Hash;
use tinycloud_core::kv_sync::{
    kv_sync_cursor_is_well_formed, KvSyncPage, KvSyncRequest, KvSyncResetReason,
    KvSyncRetentionError, KV_SYNC_DEFAULT_LIMIT, KV_SYNC_MAX_LIMIT,
};
use tinycloud_core::types::Metadata;

/// `{"error":{"code":..,"reason":..}}`, the typed body of a feed error.
pub(crate) fn kv_sync_error_body(code: &str, reason: &str) -> String {
    serde_json::json!({ "error": { "code": code, "reason": reason } }).to_string()
}

/// 410 `RESET_REQUIRED`: the client must re-bootstrap from an empty cursor.
pub(crate) fn kv_sync_reset_required(reason: KvSyncResetReason) -> (Status, String) {
    (
        Status::Gone,
        kv_sync_error_body("RESET_REQUIRED", reason.as_str()),
    )
}

/// 403: the presented retention grant is refused. The sync itself is not
/// silently served without retention.
pub(crate) fn kv_sync_retention_refused(error: KvSyncRetentionError) -> (Status, String) {
    (
        Status::Forbidden,
        kv_sync_error_body("RETENTION_GRANT_REFUSED", error.as_str()),
    )
}

fn bad_request(message: &str) -> (Status, String) {
    (Status::BadRequest, message.to_string())
}

/// Parse the feed's request headers: `x-tinycloud-limit` (1..=1000, default
/// 500), `x-tinycloud-cursor`, and `x-tinycloud-retention-grant` (a
/// delegation CID). A cursor is only checked for shape here (400 when it is
/// not one); it is authenticated after the invocation is authorized.
pub(crate) fn kv_sync_request(
    cursor_key: [u8; 32],
    limit: Option<u64>,
    cursor: Option<&str>,
    retention_grant: Option<&str>,
) -> Result<KvSyncRequest, (Status, String)> {
    let limit = match limit {
        None => KV_SYNC_DEFAULT_LIMIT,
        Some(limit) if (1..=KV_SYNC_MAX_LIMIT as u64).contains(&limit) => limit as usize,
        Some(_) => return Err(bad_request("x-tinycloud-limit must be between 1 and 1000")),
    };
    let cursor = cursor
        .map(|cursor| {
            let cursor = cursor.trim();
            kv_sync_cursor_is_well_formed(cursor)
                .then(|| cursor.to_owned())
                .ok_or_else(|| bad_request("Malformed kv/sync cursor"))
        })
        .transpose()?;
    let retention_grant = retention_grant
        .map(|value| {
            value
                .trim()
                .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                .map(Hash::from)
                .map_err(|_| bad_request("x-tinycloud-retention-grant must be a delegation CID"))
        })
        .transpose()?;
    Ok(KvSyncRequest {
        limit,
        cursor,
        cursor_key,
        retention_grant,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KvSyncResponse {
    changes: Vec<KvSyncResponseChange>,
    more: bool,
    cursor: String,
    source: KvSyncResponseSource,
    authority: KvSyncResponseAuthority,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KvSyncResponseChange {
    key: String,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KvSyncResponseSource {
    node_did: String,
    space: String,
    prefix: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KvSyncResponseAuthority {
    not_before: Option<String>,
    expires_at: Option<String>,
    retain_until: Option<String>,
}

fn rfc3339(instant: Option<OffsetDateTime>) -> Result<Option<String>, ()> {
    instant
        .map(|instant| instant.format(&Rfc3339).map_err(|_| ()))
        .transpose()
}

/// Build the response body for `page`. `node_did` is the node identity
/// `/info` advertises as `nodeId`.
pub(crate) fn kv_sync_response(
    page: &KvSyncPage,
    node_did: String,
    filter_metadata: impl Fn(Metadata) -> Metadata,
) -> Result<KvSyncResponse, ()> {
    Ok(KvSyncResponse {
        changes: page
            .changes
            .iter()
            .map(|change| match &change.value {
                Some((hash, metadata)) => KvSyncResponseChange {
                    key: change.key.to_string(),
                    deleted: false,
                    etag: Some(format!("\"blake3-{}\"", hex::encode(hash.as_ref()))),
                    metadata: Some(filter_metadata(metadata.clone()).0),
                },
                None => KvSyncResponseChange {
                    key: change.key.to_string(),
                    deleted: true,
                    etag: None,
                    metadata: None,
                },
            })
            .collect(),
        more: page.more,
        cursor: page.cursor.clone(),
        source: KvSyncResponseSource {
            node_did,
            space: page.space.to_string(),
            prefix: page.prefix.to_string(),
        },
        authority: KvSyncResponseAuthority {
            not_before: rfc3339(page.authority.not_before)?,
            expires_at: rfc3339(page.authority.expires_at)?,
            retain_until: rfc3339(page.authority.retain_until)?,
        },
    })
}
