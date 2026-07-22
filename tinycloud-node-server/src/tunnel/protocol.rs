//! Wire protocol for the tunnel relay's HTTP-over-WebSocket framing.
//!
//! This is a Rust port of `tinycloud-link/src/tunnel/protocol.ts`, which is
//! the source of truth for this file: every frame shape a node must produce
//! or consume is defined there. See that file's doc comment and the
//! tinycloud-link README's "Remote reachability: the tunnel relay" section
//! for the full contract.
//!
//! A node opens one outbound WebSocket to
//! `wss://api.tinycloud.link/v1/tunnel/<name>` and authenticates with a
//! single [`crate::tunnel::auth::TunnelAuthFrame`] (the first WS text
//! message). After the relay's `{"type":"ack"}`, every subsequent frame on
//! the socket is one of the variants below: the relay sends `request` +
//! `requestBody` frames for each inbound HTTPS request to
//! `<name>.tinycloud.link`, and the node replies with `response` +
//! `responseBody` frames carrying the same `id`. Frames are JSON text
//! messages, one per WebSocket message (no batching, no binary frames).
use serde::{Deserialize, Serialize};

/// Max size in bytes of a single WebSocket message the relay will accept
/// from a node (mirrors the relay's `WebSocketServer` `maxPayload`).
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Chunk size (pre-base64, in bytes) used to split a request/response body
/// across multiple body frames. Base64 expands this by ~4/3, plus JSON
/// envelope overhead, staying comfortably under `MAX_FRAME_PAYLOAD_BYTES`.
pub const BODY_CHUNK_BYTES: usize = 256 * 1024;

/// Default cap (bytes) on a full reassembled request or response body.
pub const DEFAULT_MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

// Close codes the relay uses to reject/terminate a tunnel WebSocket, in the
// RFC 6455 private-use range. Mirrors `tinycloud-link/src/tunnel/upgrade.ts`
// and `registry.ts`.
/// Malformed auth frame, or the frame's `name` doesn't match the connection URL.
pub const CLOSE_BAD_FRAME: u16 = 4400;
/// The auth record's signature does not verify.
pub const CLOSE_INVALID_SIGNATURE: u16 = 4401;
/// The signing subject does not own the claimed name.
pub const CLOSE_NOT_OWNER: u16 = 4403;
/// The name is not claimed at all (no `PUT /v1/names/:name` on record).
pub const CLOSE_NAME_NOT_CLAIMED: u16 = 4404;
/// No auth frame arrived within the relay's auth window (5s).
pub const CLOSE_AUTH_TIMEOUT: u16 = 4408;
/// The auth record's `sequence` was not strictly greater than the name's
/// stored sequence. Recovery: resync the local sequence forward and retry
/// with a fresh auth frame — see `tunnel::reconnect`.
pub const CLOSE_STALE_SEQUENCE: u16 = 4409;
/// A newer connection for the same name has taken over ("newest wins").
/// A node must NOT reconnect-fight after this — see `tunnel::reconnect`.
pub const CLOSE_SUPERSEDED: u16 = 4410;

/// One frame of the post-auth tunnel protocol. Serializes/deserializes as
/// `{"type": "...", ...}` to match `tinycloud-link/src/tunnel/protocol.ts`
/// exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TunnelFrame {
    /// Sent by the relay once auth succeeds. The tunnel is live after this.
    #[serde(rename = "ack")]
    Ack,

    /// Sent by the relay on auth failure (immediately before closing the
    /// socket, in addition to the WS close code), or by either side on a
    /// per-request failure (carries the request `id`, which fails just that
    /// request without closing the socket).
    #[serde(rename = "error")]
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        message: String,
    },

    /// Relay -> node: the head of an inbound HTTP request for
    /// `<name>.tinycloud.link`.
    #[serde(rename = "request")]
    Request {
        id: String,
        method: String,
        /// Path + query string, e.g. "/foo?bar=1". Always starts with "/".
        path: String,
        /// Ordered `[name, value]` pairs, one per header line — an array
        /// (not an object) so duplicate header names (e.g. multiple
        /// `Set-Cookie` lines) survive rather than colliding on one object
        /// key.
        headers: Vec<(String, String)>,
    },

    /// Relay -> node: a chunk of the request body. Always sent at least
    /// once per request, even if empty. A body larger than
    /// `BODY_CHUNK_BYTES` is split across multiple `requestBody` frames;
    /// only the last has `done: true`.
    #[serde(rename = "requestBody")]
    RequestBody {
        id: String,
        /// Base64-encoded body bytes for this chunk (may be an empty string).
        chunk: String,
        done: bool,
    },

    /// Node -> relay: the head of the response to a proxied request.
    #[serde(rename = "response")]
    Response {
        id: String,
        status: u16,
        headers: Vec<(String, String)>,
    },

    /// Node -> relay: a chunk of the response body. Always sent at least
    /// once per request, even if empty. A body larger than
    /// `BODY_CHUNK_BYTES` must be split across multiple `responseBody`
    /// frames; only the last has `done: true`.
    #[serde(rename = "responseBody")]
    ResponseBody {
        id: String,
        chunk: String,
        done: bool,
    },
}

impl TunnelFrame {
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("tunnel frame is always serializable")
    }

    pub fn parse(raw: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(raw)
    }

    /// The request `id` this frame carries, if any (every variant except
    /// `Ack` and an id-less `Error` carries one).
    pub fn request_id(&self) -> Option<&str> {
        match self {
            TunnelFrame::Ack => None,
            TunnelFrame::Error { id, .. } => id.as_deref(),
            TunnelFrame::Request { id, .. } => Some(id),
            TunnelFrame::RequestBody { id, .. } => Some(id),
            TunnelFrame::Response { id, .. } => Some(id),
            TunnelFrame::ResponseBody { id, .. } => Some(id),
        }
    }
}

/// Splits `body` into base64-encoded chunks of at most `BODY_CHUNK_BYTES`
/// pre-base64 bytes each, matching the relay's own chunking behavior. An
/// empty body still yields exactly one (empty) chunk, since the protocol
/// requires at least one body frame per request/response even when empty.
pub fn chunk_body(body: &[u8]) -> Vec<String> {
    if body.is_empty() {
        return vec![String::new()];
    }
    body.chunks(BODY_CHUNK_BYTES)
        .map(|chunk| base64::encode_config(chunk, base64::STANDARD))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn ack_frame_round_trips_with_ts_shape() {
        let frame = TunnelFrame::Ack;
        assert_eq!(frame.encode(), r#"{"type":"ack"}"#);
        assert_eq!(TunnelFrame::parse(r#"{"type":"ack"}"#).unwrap(), frame);
    }

    #[::core::prelude::v1::test]
    fn request_frame_headers_serialize_as_ordered_pair_arrays() {
        let frame = TunnelFrame::Request {
            id: "req-1".into(),
            method: "GET".into(),
            path: "/hello?x=1".into(),
            headers: vec![
                ("x-custom".into(), "hello".into()),
                ("set-cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
            ],
        };
        let json = frame.encode();
        assert_eq!(
            json,
            r#"{"type":"request","id":"req-1","method":"GET","path":"/hello?x=1","headers":[["x-custom","hello"],["set-cookie","a=1"],["set-cookie","b=2"]]}"#
        );
        assert_eq!(TunnelFrame::parse(&json).unwrap(), frame);
    }

    #[::core::prelude::v1::test]
    fn error_frame_omits_id_when_absent() {
        let frame = TunnelFrame::Error {
            id: None,
            message: "boom".into(),
        };
        assert_eq!(frame.encode(), r#"{"type":"error","message":"boom"}"#);
    }

    #[::core::prelude::v1::test]
    fn error_frame_includes_id_when_present() {
        let frame = TunnelFrame::Error {
            id: Some("req-1".into()),
            message: "boom".into(),
        };
        assert_eq!(
            frame.encode(),
            r#"{"type":"error","id":"req-1","message":"boom"}"#
        );
    }

    #[::core::prelude::v1::test]
    fn request_id_accessor_covers_every_variant() {
        assert_eq!(TunnelFrame::Ack.request_id(), None);
        assert_eq!(
            TunnelFrame::Error {
                id: Some("x".into()),
                message: "m".into()
            }
            .request_id(),
            Some("x")
        );
        assert_eq!(
            TunnelFrame::Response {
                id: "y".into(),
                status: 200,
                headers: vec![]
            }
            .request_id(),
            Some("y")
        );
    }

    #[::core::prelude::v1::test]
    fn chunk_body_splits_at_body_chunk_bytes() {
        let body = vec![b'x'; 2 * BODY_CHUNK_BYTES + 10];
        let chunks = chunk_body(&body);
        assert_eq!(chunks.len(), 3);
        let reassembled: Vec<u8> = chunks
            .iter()
            .flat_map(|c| base64::decode_config(c, base64::STANDARD).unwrap())
            .collect();
        assert_eq!(reassembled, body);
    }

    #[::core::prelude::v1::test]
    fn chunk_body_of_empty_body_yields_one_empty_chunk() {
        assert_eq!(chunk_body(&[]), vec![String::new()]);
    }

    #[::core::prelude::v1::test]
    fn parse_rejects_unknown_type() {
        assert!(TunnelFrame::parse(r#"{"type":"bogus"}"#).is_err());
    }
}
