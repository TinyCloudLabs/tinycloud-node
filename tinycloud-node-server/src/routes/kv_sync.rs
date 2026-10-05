//! TC-732: the HTTP side of the `tinycloud.kv/sync` change feed.
//!
//! The feed rides on `/invoke`, so admission, the replay cache, read audit
//! and CORS are the ordinary KV read path. This module owns what is specific
//! to the feed: its request headers, the encrypted cursor, the JSON response
//! and its typed error bodies.
//!
//! # Cursor
//!
//! `base64url(nonce[24] || XChaCha20-Poly1305(plaintext))` under the node's
//! `tinycloud/kv/sync-cursor/v1` key, with associated data
//! `"tinycloud.kv/sync\0" || space || "\0" || prefix`. The plaintext carries
//! global `event_order` positions, which is why it is encrypted rather than
//! the readable MAC'd envelope list cursors use: a client scoped to one prefix
//! must not learn the space's write rate. The cursor is deliberately not bound
//! to the invoker; authorization is re-checked on every call.

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use rocket::http::Status;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::resource::{Path, SpaceId};
use tinycloud_core::hash::Hash;
use tinycloud_core::kv_sync::{
    KvSyncAnchor, KvSyncPage, KvSyncPosition, KvSyncRequest, KvSyncResetReason,
    KvSyncRetentionError, KvSyncState, KV_SYNC_DEFAULT_LIMIT, KV_SYNC_MAX_LIMIT,
};
use tinycloud_core::types::Metadata;

/// Longest cursor header accepted, in characters.
pub(crate) const KV_SYNC_CURSOR_MAX_LEN: usize = 4096;
const NONCE_LEN: usize = 24;
const CURSOR_AAD_DOMAIN: &[u8] = b"tinycloud.kv/sync\0";

#[derive(Serialize, Deserialize)]
struct WireAnchor {
    seq: i64,
    /// Hex of the epoch's multihash bytes.
    epoch: String,
    epoch_seq: i64,
}

#[derive(Serialize, Deserialize)]
struct WirePosition {
    seq: i64,
    epoch: String,
    epoch_seq: i64,
    key: String,
}

#[derive(Serialize, Deserialize)]
struct WireCursor {
    v: u8,
    pos: Option<WirePosition>,
    floor: Option<WireAnchor>,
}

fn cursor_aad(space: &SpaceId, prefix: &Path) -> Vec<u8> {
    let mut aad = CURSOR_AAD_DOMAIN.to_vec();
    aad.extend_from_slice(space.to_string().as_bytes());
    aad.push(0);
    aad.extend_from_slice(prefix.as_str().as_bytes());
    aad
}

fn epoch_hex(epoch: Hash) -> String {
    hex::encode(Vec::<u8>::from(epoch))
}

fn epoch_from_hex(value: &str) -> Option<Hash> {
    Hash::try_from(hex::decode(value).ok()?).ok()
}

/// Encrypt `state` into an opaque cursor for `space`/`prefix`.
pub(crate) fn encode_kv_sync_cursor(
    key: &[u8; 32],
    space: &SpaceId,
    prefix: &Path,
    state: &KvSyncState,
) -> Result<String, ()> {
    let wire = WireCursor {
        v: 1,
        pos: state.pos.as_ref().map(|pos| WirePosition {
            seq: pos.anchor.seq,
            epoch: epoch_hex(pos.anchor.epoch),
            epoch_seq: pos.anchor.epoch_seq,
            key: pos.key.clone(),
        }),
        floor: state.floor.map(|floor| WireAnchor {
            seq: floor.seq,
            epoch: epoch_hex(floor.epoch),
            epoch_seq: floor.epoch_seq,
        }),
    };
    let plaintext = serde_json::to_vec(&wire).map_err(|_| ())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = cursor_aad(space, prefix);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ())?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&ciphertext);
    let encoded = encode_config(bytes, URL_SAFE_NO_PAD);
    if encoded.len() > KV_SYNC_CURSOR_MAX_LEN {
        return Err(());
    }
    Ok(encoded)
}

/// Why a cursor header was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KvSyncCursorError {
    /// Not a cursor at all: oversized or not base64url. A 400.
    Malformed,
    /// Well-formed but not minted by this node for this space and prefix
    /// (or no longer decodable). A 410 `RESET_REQUIRED`.
    Invalid,
}

/// Decrypt a cursor minted for `space`/`prefix`.
pub(crate) fn decode_kv_sync_cursor(
    key: &[u8; 32],
    value: &str,
    space: &SpaceId,
    prefix: &Path,
) -> Result<KvSyncState, KvSyncCursorError> {
    if value.is_empty() || value.len() > KV_SYNC_CURSOR_MAX_LEN {
        return Err(KvSyncCursorError::Malformed);
    }
    let bytes = decode_config(value, URL_SAFE_NO_PAD).map_err(|_| KvSyncCursorError::Malformed)?;
    if bytes.len() <= NONCE_LEN {
        return Err(KvSyncCursorError::Malformed);
    }
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KvSyncCursorError::Malformed)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| KvSyncCursorError::Invalid)?;
    let aad = cursor_aad(space, prefix);
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| KvSyncCursorError::Invalid)?;
    let wire: WireCursor =
        serde_json::from_slice(&plaintext).map_err(|_| KvSyncCursorError::Invalid)?;
    if wire.v != 1 {
        return Err(KvSyncCursorError::Invalid);
    }
    let pos = wire
        .pos
        .map(|pos| {
            Some(KvSyncPosition {
                anchor: KvSyncAnchor {
                    seq: pos.seq,
                    epoch: epoch_from_hex(&pos.epoch)?,
                    epoch_seq: pos.epoch_seq,
                },
                key: pos.key,
            })
        })
        .map(|pos| pos.ok_or(KvSyncCursorError::Invalid))
        .transpose()?;
    let floor = wire
        .floor
        .map(|floor| {
            Some(KvSyncAnchor {
                seq: floor.seq,
                epoch: epoch_from_hex(&floor.epoch)?,
                epoch_seq: floor.epoch_seq,
            })
        })
        .map(|floor| floor.ok_or(KvSyncCursorError::Invalid))
        .transpose()?;
    Ok(KvSyncState { pos, floor })
}

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

/// Parse the feed's request headers. `limit` is `x-tinycloud-limit`
/// (1..=1000, default 500), `cursor` is `x-tinycloud-cursor`, and
/// `retention_grant` is `x-tinycloud-retention-grant` (a delegation CID).
pub(crate) fn kv_sync_request(
    cursor_key: &[u8; 32],
    space: &SpaceId,
    prefix: &Path,
    limit: Option<u64>,
    cursor: Option<&str>,
    retention_grant: Option<&str>,
) -> Result<KvSyncRequest, (Status, String)> {
    let limit = match limit {
        None => KV_SYNC_DEFAULT_LIMIT,
        Some(limit) if (1..=KV_SYNC_MAX_LIMIT as u64).contains(&limit) => limit as usize,
        Some(_) => return Err(bad_request("x-tinycloud-limit must be between 1 and 1000")),
    };
    let state = cursor
        .map(|cursor| {
            decode_kv_sync_cursor(cursor_key, cursor.trim(), space, prefix).map_err(|error| {
                match error {
                    KvSyncCursorError::Malformed => bad_request("Malformed kv/sync cursor"),
                    KvSyncCursorError::Invalid => {
                        kv_sync_reset_required(KvSyncResetReason::CursorInvalid)
                    }
                }
            })
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
        state,
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

/// Build the response body for `page`. `cursor` is the cursor to return
/// (the request's own, byte for byte, when the page is empty), and
/// `node_did` is the node identity `/info` advertises as `nodeId`.
pub(crate) fn kv_sync_response(
    page: &KvSyncPage,
    cursor: String,
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
        cursor,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tinycloud_auth::resolver::DID_METHODS;
    use tinycloud_auth::ssi::{dids::DIDBuf, jwk::JWK};

    fn space(name: &str) -> SpaceId {
        let did: DIDBuf = DID_METHODS
            .generate(&JWK::generate_ed25519().unwrap(), "key")
            .unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    fn state() -> KvSyncState {
        let epoch = tinycloud_core::hash::hash(b"epoch");
        KvSyncState {
            pos: Some(KvSyncPosition {
                anchor: KvSyncAnchor {
                    seq: 7,
                    epoch,
                    epoch_seq: 1,
                },
                key: "notes/a".to_string(),
            }),
            floor: Some(KvSyncAnchor {
                seq: 3,
                epoch,
                epoch_seq: 0,
            }),
        }
    }

    /// The cursor round-trips only for the space and prefix it was minted
    /// for, under the key that minted it; everything else is a reset (410),
    /// and a header that is not a cursor at all is a 400.
    #[test]
    fn kv_sync_cursor_is_bound_to_space_prefix_and_key() {
        let key = [7u8; 32];
        let space = space("files");
        let prefix: Path = "notes".parse().unwrap();
        let cursor = encode_kv_sync_cursor(&key, &space, &prefix, &state()).unwrap();
        assert_eq!(
            decode_kv_sync_cursor(&key, &cursor, &space, &prefix).unwrap(),
            state()
        );
        assert!(!cursor.contains("notes"), "the cursor must be opaque");

        let other_prefix: Path = "notes-secret".parse().unwrap();
        assert_eq!(
            decode_kv_sync_cursor(&key, &cursor, &space, &other_prefix),
            Err(KvSyncCursorError::Invalid)
        );
        assert_eq!(
            decode_kv_sync_cursor(&key, &cursor, &self::space("files"), &prefix),
            Err(KvSyncCursorError::Invalid)
        );
        assert_eq!(
            decode_kv_sync_cursor(&[8u8; 32], &cursor, &space, &prefix),
            Err(KvSyncCursorError::Invalid)
        );
        assert_eq!(
            decode_kv_sync_cursor(&key, "not base64!", &space, &prefix),
            Err(KvSyncCursorError::Malformed)
        );
        assert_eq!(
            decode_kv_sync_cursor(&key, &"A".repeat(4097), &space, &prefix),
            Err(KvSyncCursorError::Malformed)
        );
    }
}
