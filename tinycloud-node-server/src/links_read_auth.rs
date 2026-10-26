//! The node's signed read of a link (links API contract section 4.11) and the
//! clock skew it can see.
//!
//! The node reads every link from one egress address, so it proves who it is
//! by a signature instead: `TinyCloud-Read-Auth: base64url(JCS({issuedAt,
//! signature, signerDid}))`, a signature by the node identity key (the key that
//! signs the delivery admission) over
//! `SHA-256("xyz.tinycloud.links/read-auth/v1\0" || JCS({audience, issuedAt,
//! method, path, signerDid}))`. The API builds `method`, `path` and `audience`
//! from the request it received and its own configuration; the node builds the
//! same three from the URL it requests and the configured `links_origin`. The
//! API accepts a header within 120 seconds of its own clock, so the node also
//! reads the standard `Date` response header and reports a clock that is off by
//! more than 60 seconds.
//!
//! The header carries no key, no link fragment and no secret: a signature, a
//! time and the node's public DID.

use crate::delivery_link::format_utc_millis;
use base64::{encode_config, URL_SAFE_NO_PAD};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc2822, OffsetDateTime};
use tinycloud_core::{keys::StaticSecret, libp2p::identity::Keypair};

/// The request header (HTTP names are case-insensitive: `TinyCloud-Read-Auth`).
pub const READ_AUTH_HEADER: &str = "tinycloud-read-auth";
pub const READ_AUTH_DOMAIN: &[u8] = b"xyz.tinycloud.links/read-auth/v1\0";
/// The header value is at most this many bytes.
pub const MAX_READ_AUTH_BYTES: usize = 512;
/// The API's window around its own clock.
pub const READ_AUTH_WINDOW_SECS: u64 = 120;
/// A clock further than this from the API's is reported.
const SKEW_THRESHOLD_MS: i64 = 60_000;
/// One skew line at most per this long.
const SKEW_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// The node identity, as the signer of link reads.
#[derive(Clone)]
pub struct ReadSigner {
    secret: StaticSecret,
}

impl ReadSigner {
    pub fn new(secret: StaticSecret) -> Self {
        Self { secret }
    }

    /// The `TinyCloud-Read-Auth` value for a `GET` of `path` at the API whose
    /// origin is `audience`, issued at `now`.
    pub fn header_value(&self, audience: &str, path: &str, now: OffsetDateTime) -> String {
        read_auth_header_value(
            &self.secret.node_keypair(),
            &self.secret.node_did(),
            audience,
            path,
            &format_utc_millis(now),
        )
    }
}

/// The signed object, as the API rebuilds it for `GET {path}`.
pub(crate) fn read_auth_object(
    audience: &str,
    issued_at: &str,
    path: &str,
    signer_did: &str,
) -> Value {
    json!({
        "audience": audience,
        "issuedAt": issued_at,
        "method": "GET",
        "path": path,
        "signerDid": signer_did,
    })
}

/// The 64-byte signature: Ed25519 over `SHA-256(domain || JCS(object))`.
pub(crate) fn read_auth_signature(keypair: &Keypair, object: &Value) -> Vec<u8> {
    let mut signed = READ_AUTH_DOMAIN.to_vec();
    signed.extend_from_slice(&tinycloud_core::policy_capability::jcs::canonicalize(
        object,
    ));
    keypair
        .sign(&Sha256::digest(signed))
        .expect("an Ed25519 key signs")
}

/// `base64url(JCS({issuedAt, signature, signerDid}))`.
pub(crate) fn read_auth_header_value(
    keypair: &Keypair,
    signer_did: &str,
    audience: &str,
    path: &str,
    issued_at: &str,
) -> String {
    let signature = read_auth_signature(
        keypair,
        &read_auth_object(audience, issued_at, path, signer_did),
    );
    let header = json!({
        "issuedAt": issued_at,
        "signature": encode_config(signature, URL_SAFE_NO_PAD),
        "signerDid": signer_did,
    });
    encode_config(
        tinycloud_core::policy_capability::jcs::canonicalize(&header),
        URL_SAFE_NO_PAD,
    )
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Watches the API's `Date` header against the node's clock. A clock off by
/// more than 60 seconds is counted every time and logged at most once a
/// minute; a missing or unreadable `Date` is ignored.
#[derive(Default)]
pub struct ClockSkew {
    last_logged: Mutex<Option<Instant>>,
}

impl ClockSkew {
    /// The node clock minus the API clock in milliseconds (positive when the
    /// node is ahead), when it is over the threshold. `date` is the `Date`
    /// header value, `now` the node's clock when the response arrived and
    /// `at` the monotonic time for the log cap.
    pub fn observe(&self, date: Option<&str>, now: OffsetDateTime, at: Instant) -> Option<i64> {
        let api = OffsetDateTime::parse(date?, &Rfc2822).ok()?;
        let skew_ms = i64::try_from((now - api).whole_milliseconds()).ok()?;
        if skew_ms.abs() <= SKEW_THRESHOLD_MS {
            return None;
        }
        crate::prometheus::observe_links_read_clock_skew();
        let mut last = locked(&self.last_logged);
        if last.is_none_or(|previous| at.saturating_duration_since(previous) >= SKEW_LOG_INTERVAL) {
            *last = Some(at);
            tracing::warn!(
                event = "links_read_clock_skew",
                skew_ms,
                window_s = READ_AUTH_WINDOW_SECS,
                "the links API clock differs from the node clock"
            );
        }
        Some(skew_ms)
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
