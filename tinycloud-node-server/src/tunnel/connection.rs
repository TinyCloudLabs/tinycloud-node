//! The outbound tunnel WebSocket client: connect, authenticate, then proxy
//! `request`/`requestBody` frames to the loopback public API and stream
//! `response`/`responseBody` frames back.
//!
//! Lifecycle (see the tinycloud-link README's "Remote reachability: the
//! tunnel relay" section, and `tinycloud-link/src/tunnel/protocol.ts` /
//! `upgrade.ts` for the authoritative wire contract this implements):
//!
//!   1. Bump-before-connect: consume the name's next shared sequence value
//!      and persist it to `dataPath/link/state.json` *before* dialing out
//!      (mirrors `link::commands::send_with_sequence` — the relay commits
//!      its own sequence bump as soon as auth succeeds, so a client that
//!      only persists on success can fall behind).
//!   2. Dial `wss://<service>/v1/tunnel/<name>`, send the signed auth frame
//!      as the first message, and wait for `{"type":"ack"}` or a close code.
//!   3. On ack, multiplex proxied HTTP requests: each `request` +
//!      `requestBody...` sequence is reassembled, forwarded to
//!      `127.0.0.1:<public API port>`, and the response is written back as
//!      `response` + `responseBody...` frames.
//!   4. On disconnect, reconnect with backoff — except close code 4410
//!      (superseded by a newer connection for this name), which stops the
//!      task entirely, and 4409 (stale sequence), which resyncs the local
//!      sequence forward and retries immediately. See `tunnel::reconnect`.
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::{net::TcpStream, sync::watch, sync::Mutex};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::CloseFrame, tungstenite::Message, MaybeTlsStream,
    WebSocketStream,
};

use crate::config::Keys;
use crate::link::state::TunnelRuntimeState;
use crate::node_control::key_provider::{self, IdentityPurpose};

use super::auth::{self, TunnelAuthFrame};
use super::commands as tunnel_commands;
use super::protocol::{TunnelFrame, BODY_CHUNK_BYTES, CLOSE_SUPERSEDED, DEFAULT_MAX_BODY_BYTES};
use super::reconnect::{AttemptOutcome, BackoffState, ReconnectAction};

/// How long to wait for the relay's `{"type":"ack"}` (or a rejecting close
/// frame) after sending the auth frame. The relay itself enforces a 5s
/// window for the node to *send* the auth frame; this is a client-side
/// generosity margin for the round trip, not a mirror of that window.
const AUTH_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// If no frame (data, ping, or close) arrives within this long while a
/// tunnel is live, treat the connection as dead and reconnect. The relay
/// pings every 30s; this is a multiple of that so a couple of missed
/// heartbeats are tolerated before we give up on the socket.
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(90);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = futures::stream::SplitSink<WsStream, Message>;
type SharedSink = Arc<Mutex<WsSink>>;

/// Everything the tunnel task needs for the lifetime of `serve`.
#[derive(Clone)]
pub struct TunnelContext {
    pub data_root: PathBuf,
    pub keys: Option<Keys>,
    /// The loopback public API address requests are forwarded to, e.g.
    /// `127.0.0.1:8081`.
    pub upstream_addr: SocketAddr,
}

/// Run the tunnel connection loop until `shutdown` fires or the relay
/// supersedes this connection (4410). Never panics on a bad frame or a dead
/// socket — those are reconnect-worthy events, not task failures.
pub async fn run(ctx: TunnelContext, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BackoffState::new();
    let mut extra_sequence_jump: u64 = 0;

    loop {
        if *shutdown.borrow() {
            break;
        }

        let attempt = match prepare_attempt(&ctx, extra_sequence_jump).await {
            Ok(attempt) => attempt,
            Err(err) => {
                tracing::warn!(%err, "tunnel: failed to prepare connection attempt");
                record_state(
                    &ctx.data_root,
                    TunnelRuntimeState {
                        connected: false,
                        last_error: Some(err.to_string()),
                    },
                );
                extra_sequence_jump = 0;
                if wait_backoff(&mut backoff, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };
        extra_sequence_jump = 0;

        match connect_and_serve(&ctx, &attempt, &mut shutdown).await {
            AttemptResult::Stopped => break,
            AttemptResult::Outcome(outcome) => {
                let jitter = rand::random::<f64>();
                match backoff.next_action(outcome, jitter) {
                    ReconnectAction::Serve => unreachable!("Ack outcome is handled inline"),
                    ReconnectAction::ResyncAndRetry { jump } => {
                        extra_sequence_jump = jump;
                    }
                    ReconnectAction::Stop => break,
                    ReconnectAction::Backoff { delay } => {
                        if wait_for(delay, &mut shutdown).await {
                            break;
                        }
                    }
                }
            }
        }
    }

    record_state(
        &ctx.data_root,
        TunnelRuntimeState {
            connected: false,
            last_error: None,
        },
    );
}

/// Sleeps for `delay`, but wakes early (and returns `true`) if shutdown
/// fires first.
async fn wait_for(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn wait_backoff(backoff: &mut BackoffState, shutdown: &mut watch::Receiver<bool>) -> bool {
    let jitter = rand::random::<f64>();
    match backoff.next_action(AttemptOutcome::TransportError, jitter) {
        ReconnectAction::Backoff { delay } => wait_for(delay, shutdown).await,
        _ => false,
    }
}

struct PreparedAttempt {
    name: String,
    service_url: String,
    auth_frame: TunnelAuthFrame,
}

/// Bump-before-connect: consume the next sequence value and persist it,
/// then resolve the node's signing identity and build the signed auth
/// frame. Both steps touch blocking resources (an flock'd file and,
/// depending on the KeyProvider backend, the OS keychain) so this runs on
/// the blocking pool.
async fn prepare_attempt(ctx: &TunnelContext, extra_sequence_jump: u64) -> Result<PreparedAttempt> {
    let data_root = ctx.data_root.clone();
    let keys = ctx.keys.clone();
    tokio::task::spawn_blocking(move || -> Result<PreparedAttempt> {
        let (name, service_url, sequence) =
            tunnel_commands::bump_sequence_for_tunnel(&data_root, extra_sequence_jump)?;

        let identity_state =
            key_provider::resolve_identity_state(keys.as_ref(), &data_root, IdentityPurpose::Serve)
                .context("failed to resolve node identity for tunnel auth")?;
        let secret = identity_state
            .secret
            .ok_or_else(|| anyhow!("node identity is not ready"))?;
        let node_did = identity_state
            .node_did
            .ok_or_else(|| anyhow!("node identity is not ready"))?;
        let keypair = secret.node_keypair();

        let auth_frame = auth::build_auth_frame(&keypair, &name, &node_did, sequence)
            .map_err(|err| anyhow!(err))?;

        Ok(PreparedAttempt {
            name,
            service_url,
            auth_frame,
        })
    })
    .await
    .context("tunnel attempt preparation task panicked")?
}

enum AttemptResult {
    /// Shutdown fired, or the relay superseded this connection (4410) — the
    /// task must not reconnect.
    Stopped,
    Outcome(AttemptOutcome),
}

async fn connect_and_serve(
    ctx: &TunnelContext,
    attempt: &PreparedAttempt,
    shutdown: &mut watch::Receiver<bool>,
) -> AttemptResult {
    let url = to_ws_url(&attempt.service_url, &attempt.name);
    let (ws_stream, _response) = match connect_async(&url).await {
        Ok(pair) => pair,
        Err(err) => {
            record_state(
                &ctx.data_root,
                TunnelRuntimeState {
                    connected: false,
                    last_error: Some(format!("connect failed: {err}")),
                },
            );
            return AttemptResult::Outcome(AttemptOutcome::TransportError);
        }
    };

    let (sink, mut stream) = ws_stream.split();
    let sink: SharedSink = Arc::new(Mutex::new(sink));

    let auth_json = serde_json::to_string(&attempt.auth_frame)
        .expect("tunnel auth frame is always serializable");
    if let Err(err) = sink.lock().await.send(Message::Text(auth_json)).await {
        record_state(
            &ctx.data_root,
            TunnelRuntimeState {
                connected: false,
                last_error: Some(format!("failed to send auth frame: {err}")),
            },
        );
        return AttemptResult::Outcome(AttemptOutcome::TransportError);
    }

    match wait_for_ack(&mut stream).await {
        AckOutcome::Ack => {}
        AckOutcome::Closed(code, reason) => {
            let message = format!("tunnel auth rejected (close code {code}): {reason}");
            if code == CLOSE_SUPERSEDED {
                tracing::info!(%message, "tunnel: superseded by a newer connection; not reconnecting");
                record_state(
                    &ctx.data_root,
                    TunnelRuntimeState {
                        connected: false,
                        last_error: Some(message),
                    },
                );
                return AttemptResult::Stopped;
            }
            tracing::warn!(%message);
            record_state(
                &ctx.data_root,
                TunnelRuntimeState {
                    connected: false,
                    last_error: Some(message),
                },
            );
            return AttemptResult::Outcome(AttemptOutcome::Closed(code));
        }
        AckOutcome::Failed(err) => {
            record_state(
                &ctx.data_root,
                TunnelRuntimeState {
                    connected: false,
                    last_error: Some(err),
                },
            );
            return AttemptResult::Outcome(AttemptOutcome::TransportError);
        }
    }

    record_state(
        &ctx.data_root,
        TunnelRuntimeState {
            connected: true,
            last_error: None,
        },
    );
    tracing::info!(name = %attempt.name, "tunnel: connected and authenticated");

    let outcome = serve_requests(ctx, sink.clone(), stream, shutdown).await;

    match &outcome {
        AttemptResult::Stopped => {}
        AttemptResult::Outcome(_) => {
            record_state(
                &ctx.data_root,
                TunnelRuntimeState {
                    connected: false,
                    last_error: Some("tunnel connection dropped".to_string()),
                },
            );
        }
    }
    outcome
}

enum AckOutcome {
    Ack,
    Closed(u16, String),
    Failed(String),
}

async fn wait_for_ack(stream: &mut futures::stream::SplitStream<WsStream>) -> AckOutcome {
    let next = tokio::time::timeout(AUTH_ACK_TIMEOUT, stream.next()).await;
    match next {
        Err(_) => AckOutcome::Failed("timed out waiting for auth ack".to_string()),
        Ok(None) => AckOutcome::Failed("connection closed before auth ack".to_string()),
        Ok(Some(Err(err))) => AckOutcome::Failed(err.to_string()),
        Ok(Some(Ok(Message::Text(text)))) => match TunnelFrame::parse(&text) {
            Ok(TunnelFrame::Ack) => AckOutcome::Ack,
            Ok(other) => AckOutcome::Failed(format!("expected ack, got {other:?}")),
            Err(err) => AckOutcome::Failed(format!("malformed ack frame: {err}")),
        },
        Ok(Some(Ok(Message::Close(frame)))) => {
            let (code, reason) = close_code_and_reason(frame);
            AckOutcome::Closed(code, reason)
        }
        Ok(Some(Ok(other))) => AckOutcome::Failed(format!("unexpected message: {other:?}")),
    }
}

fn close_code_and_reason(frame: Option<CloseFrame<'_>>) -> (u16, String) {
    match frame {
        Some(frame) => (u16::from(frame.code), frame.reason.to_string()),
        None => (0, String::new()),
    }
}

/// A request whose head (`request` frame) has arrived but whose body is
/// still being reassembled from `requestBody` frames.
struct PendingRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Multiplex proxied requests over the live socket until it closes, an
/// error occurs, the socket goes idle, or shutdown fires.
async fn serve_requests(
    ctx: &TunnelContext,
    sink: SharedSink,
    mut stream: futures::stream::SplitStream<WsStream>,
    shutdown: &mut watch::Receiver<bool>,
) -> AttemptResult {
    let mut pending: HashMap<String, PendingRequest> = HashMap::new();
    let upstream_addr = ctx.upstream_addr;
    let http_client = reqwest::Client::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = sink.lock().await.close().await;
                    return AttemptResult::Stopped;
                }
            }
            next = tokio::time::timeout(IDLE_READ_TIMEOUT, stream.next()) => {
                let next = match next {
                    Err(_) => {
                        tracing::warn!("tunnel: no frame within idle timeout; treating connection as dead");
                        return AttemptResult::Outcome(AttemptOutcome::TransportError);
                    }
                    Ok(next) => next,
                };
                match next {
                    None => return AttemptResult::Outcome(AttemptOutcome::TransportError),
                    Some(Err(err)) => {
                        tracing::warn!(%err, "tunnel: read error");
                        return AttemptResult::Outcome(AttemptOutcome::TransportError);
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let (code, _reason) = close_code_and_reason(frame);
                        if code == CLOSE_SUPERSEDED {
                            return AttemptResult::Stopped;
                        }
                        return AttemptResult::Outcome(AttemptOutcome::Closed(code));
                    }
                    Some(Ok(Message::Text(text))) => {
                        handle_frame(
                            &text,
                            &mut pending,
                            sink.clone(),
                            upstream_addr,
                            http_client.clone(),
                        );
                    }
                    // Pings are auto-ponged by tungstenite; Pong/Binary/Frame
                    // carry no protocol meaning here. Any of these still
                    // counts as socket activity, resetting the idle timer on
                    // the next loop iteration.
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

fn handle_frame(
    text: &str,
    pending: &mut HashMap<String, PendingRequest>,
    sink: SharedSink,
    upstream_addr: SocketAddr,
    http_client: reqwest::Client,
) {
    let frame = match TunnelFrame::parse(text) {
        Ok(frame) => frame,
        Err(err) => {
            tracing::warn!(%err, "tunnel: dropping malformed frame");
            return;
        }
    };

    match frame {
        TunnelFrame::Request {
            id,
            method,
            path,
            headers,
        } => {
            pending.insert(
                id,
                PendingRequest {
                    method,
                    path,
                    headers,
                    body: Vec::new(),
                },
            );
        }
        TunnelFrame::RequestBody { id, chunk, done } => {
            let Some(req) = pending.get_mut(&id) else {
                // Unrecognized id (e.g. already failed/timed out) — silently
                // ignore, per the protocol's multiplexing rule.
                return;
            };
            if !chunk.is_empty() {
                match base64::decode_config(&chunk, base64::STANDARD) {
                    Ok(bytes) => {
                        if req.body.len() + bytes.len() > DEFAULT_MAX_BODY_BYTES {
                            pending.remove(&id);
                            spawn_send_error(sink, id, "request body exceeds max size".to_string());
                            return;
                        }
                        req.body.extend_from_slice(&bytes);
                    }
                    Err(err) => {
                        pending.remove(&id);
                        spawn_send_error(sink, id, format!("invalid base64 body chunk: {err}"));
                        return;
                    }
                }
            }
            if done {
                let req = pending.remove(&id).expect("just checked present above");
                tokio::spawn(serve_request(id, req, upstream_addr, sink, http_client));
            }
        }
        // These are relay <- node frames or connection-level frames; the
        // relay never sends them to us post-ack. Ignore defensively rather
        // than treating an unexpected frame as a protocol error that tears
        // down the whole socket.
        TunnelFrame::Ack | TunnelFrame::Response { .. } | TunnelFrame::ResponseBody { .. } => {}
        TunnelFrame::Error { id, message } => {
            if let Some(id) = id {
                pending.remove(&id);
            }
            tracing::warn!(%message, "tunnel: relay sent an error frame");
        }
    }
}

fn spawn_send_error(sink: SharedSink, id: String, message: String) {
    tokio::spawn(async move {
        send_frame(
            &sink,
            TunnelFrame::Error {
                id: Some(id),
                message,
            },
        )
        .await;
    });
}

async fn send_frame(sink: &SharedSink, frame: TunnelFrame) {
    let json = frame.encode();
    if let Err(err) = sink.lock().await.send(Message::Text(json)).await {
        tracing::warn!(%err, "tunnel: failed to write frame");
    }
}

/// Forward one fully-reassembled request to the loopback public API and
/// stream the response back as `response` + chunked `responseBody` frames.
/// Failures are surfaced as a per-request `error` frame — per the protocol,
/// this never closes the socket.
async fn serve_request(
    id: String,
    req: PendingRequest,
    upstream_addr: SocketAddr,
    sink: SharedSink,
    http_client: reqwest::Client,
) {
    let method = match reqwest::Method::from_bytes(req.method.as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            send_frame(
                &sink,
                TunnelFrame::Error {
                    id: Some(id),
                    message: format!("invalid HTTP method: {}", req.method),
                },
            )
            .await;
            return;
        }
    };

    let url = format!("http://{upstream_addr}{}", req.path);
    let mut header_map = reqwest::header::HeaderMap::new();
    for (name, value) in &req.headers {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            header_map.append(name, value);
        }
    }

    let response = match http_client
        .request(method, url)
        .headers(header_map)
        .body(req.body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            send_frame(
                &sink,
                TunnelFrame::Error {
                    id: Some(id),
                    message: format!("upstream request failed: {err}"),
                },
            )
            .await;
            return;
        }
    };

    if let Some(len) = response.content_length() {
        if len as usize > DEFAULT_MAX_BODY_BYTES {
            send_frame(
                &sink,
                TunnelFrame::Error {
                    id: Some(id),
                    message: "upstream response body exceeds max size".to_string(),
                },
            )
            .await;
            return;
        }
    }

    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();

    let body = match response.bytes().await {
        Ok(body) => body,
        Err(err) => {
            send_frame(
                &sink,
                TunnelFrame::Error {
                    id: Some(id),
                    message: format!("failed to read upstream response body: {err}"),
                },
            )
            .await;
            return;
        }
    };

    if body.len() > DEFAULT_MAX_BODY_BYTES {
        send_frame(
            &sink,
            TunnelFrame::Error {
                id: Some(id),
                message: "upstream response body exceeds max size".to_string(),
            },
        )
        .await;
        return;
    }

    send_frame(
        &sink,
        TunnelFrame::Response {
            id: id.clone(),
            status,
            headers,
        },
    )
    .await;

    if body.is_empty() {
        send_frame(
            &sink,
            TunnelFrame::ResponseBody {
                id,
                chunk: String::new(),
                done: true,
            },
        )
        .await;
        return;
    }

    let mut offset = 0usize;
    while offset < body.len() {
        let end = (offset + BODY_CHUNK_BYTES).min(body.len());
        let done = end == body.len();
        let chunk = base64::encode_config(&body[offset..end], base64::STANDARD);
        send_frame(
            &sink,
            TunnelFrame::ResponseBody {
                id: id.clone(),
                chunk,
                done,
            },
        )
        .await;
        offset = end;
    }
}

fn record_state(data_root: &std::path::Path, state: TunnelRuntimeState) {
    if let Err(err) = tunnel_commands::record_runtime_state(data_root, &state) {
        tracing::warn!(%err, "tunnel: failed to record runtime state");
    }
}

/// Convert the tunnel relay's HTTP(S) base URL into the WebSocket URL for
/// `name`, e.g. `https://api.tinycloud.link` ->
/// `wss://api.tinycloud.link/v1/tunnel/office`.
fn to_ws_url(service_url: &str, name: &str) -> String {
    let trimmed = service_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        trimmed.to_string()
    };
    format!(
        "{ws_base}/v1/tunnel/{}",
        percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_ws_url_converts_https_to_wss() {
        assert_eq!(
            to_ws_url("https://api.tinycloud.link", "office"),
            "wss://api.tinycloud.link/v1/tunnel/office"
        );
    }

    #[test]
    fn to_ws_url_converts_http_to_ws_for_local_dev() {
        assert_eq!(
            to_ws_url("http://127.0.0.1:4000/", "office"),
            "ws://127.0.0.1:4000/v1/tunnel/office"
        );
    }

    #[test]
    fn to_ws_url_percent_encodes_name() {
        assert_eq!(
            to_ws_url("https://api.tinycloud.link", "weird name"),
            "wss://api.tinycloud.link/v1/tunnel/weird%20name"
        );
    }
}
