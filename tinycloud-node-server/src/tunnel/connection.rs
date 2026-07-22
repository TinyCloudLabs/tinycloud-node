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

/// Default cap on the number of requests concurrently being reassembled
/// (head received, body not yet complete) per tunnel connection. Bounds
/// `pending`'s memory usage against a relay that opens many requests without
/// ever finishing their bodies. Override via
/// `TINYCLOUD_TUNNEL_MAX_PENDING_REQUESTS`.
const DEFAULT_MAX_PENDING_REQUESTS: usize = 64;

/// Resolves the effective in-flight request cap, reading
/// `TINYCLOUD_TUNNEL_MAX_PENDING_REQUESTS` once per connection.
fn max_pending_requests() -> usize {
    effective_max_pending(std::env::var("TINYCLOUD_TUNNEL_MAX_PENDING_REQUESTS").ok())
}

/// Pure helper behind [`max_pending_requests`] so it can be unit-tested
/// without touching the real process environment (env vars are process-wide
/// global state, which would otherwise race other tests running in
/// parallel).
fn effective_max_pending(env_value: Option<String>) -> usize {
    env_value
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_PENDING_REQUESTS)
}

/// Rejects any relay-supplied request path that isn't a plain absolute path
/// on the loopback upstream. `serve_request` builds the forwarded URL as
/// `format!("http://{upstream_addr}{path}")` — a path that doesn't start
/// with `/` (e.g. `@evil.com/x`, which reads as URL userinfo, redirecting
/// the request to host `evil.com`) or that itself embeds a scheme (e.g.
/// `http://evil.com/`) can retarget the request to an arbitrary host
/// reachable from the node, entirely bypassing the intended
/// loopback-only upstream. Whitespace/control characters are rejected too
/// since they have no legitimate place in a path and can be used to smuggle
/// header-like content into the request line on some HTTP stacks.
fn validate_request_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!(
            "rejected request: path must start with '/': {path:?}"
        ));
    }
    if path.contains("://") {
        return Err(format!(
            "rejected request: path must not embed a scheme: {path:?}"
        ));
    }
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "rejected request: path contains whitespace/control characters: {path:?}"
        ));
    }
    Ok(())
}

/// Headers that must never be forwarded verbatim across the tunnel's proxy
/// boundary: RFC 7230 §6.1 hop-by-hop headers (connection-management state
/// meaningful only to one physical leg of the proxy, never the other), plus
/// `content-length`/`transfer-encoding`, which describe framing for a body
/// this proxy has already fully reassembled (request side) or buffered and
/// re-chunked into `responseBody` frames (response side) — forwarding a
/// stale value here can desync the receiving side's framing rather than
/// merely being redundant.
fn should_strip_forwarded_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
            | "content-length"
    ) || lower.starts_with("proxy-")
}

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

/// Run the tunnel connection loop until `shutdown` fires, the relay
/// supersedes this connection (4410), or the tunnel is disabled (`tunnel
/// disable`) while this loop is running. Never panics on a bad frame or a
/// dead socket — those are reconnect-worthy events, not task failures.
pub async fn run(ctx: TunnelContext, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BackoffState::new();
    let mut extra_sequence_jump: u64 = 0;

    loop {
        if *shutdown.borrow() {
            break;
        }

        let attempt = match prepare_attempt(&ctx, extra_sequence_jump).await {
            Ok(attempt) => attempt,
            Err(err) if is_tunnel_disabled_error(&err) => {
                // `tunnel disable` flipped the flag off (concurrently with
                // this loop, e.g. while it was mid-retry). This is terminal,
                // not one more thing to retry past: stop reconnecting and
                // remove the runtime marker so `disable`'s own cleanup isn't
                // resurrected by our next scheduled attempt. This check only
                // runs before dialing a *new* connection — a socket already
                // live from a prior attempt is unaffected and keeps serving
                // until its next reconnect or a `serve` restart.
                tracing::info!("tunnel: disabled; stopping the connection loop");
                clear_state(&ctx.data_root);
                return;
            }
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

        match connect_and_serve(&ctx, &attempt, &mut backoff, &mut shutdown).await {
            AttemptResult::ShutdownRequested => break,
            AttemptResult::Superseded => return,
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
    /// Shutdown fired — the task must not reconnect. `run`'s final cleanup
    /// clears any prior error state, since a deliberate stop isn't an error
    /// worth preserving.
    ShutdownRequested,
    /// Another connection for this name has taken over (WS close code
    /// 4410, "superseded"). The task must not reconnect-fight with the
    /// socket that superseded it. The descriptive "superseded by a newer
    /// connection" message has already been recorded to the on-disk marker
    /// at the site that detected this — `run`'s final cleanup must not
    /// clobber it with a generic reset.
    Superseded,
    Outcome(AttemptOutcome),
}

async fn connect_and_serve(
    ctx: &TunnelContext,
    attempt: &PreparedAttempt,
    backoff: &mut BackoffState,
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
            let message = if code == CLOSE_SUPERSEDED {
                format!("superseded by a newer connection (close code {code}): {reason}")
            } else {
                format!("tunnel auth rejected (close code {code}): {reason}")
            };
            if code == CLOSE_SUPERSEDED {
                tracing::info!(%message, "tunnel: superseded by a newer connection; not reconnecting");
                record_state(
                    &ctx.data_root,
                    TunnelRuntimeState {
                        connected: false,
                        last_error: Some(message),
                    },
                );
                return AttemptResult::Superseded;
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

    // Auth succeeded: reset backoff here (not via `BackoffState::next_action`,
    // which the run loop only calls with the outcome of a *finished*
    // attempt — an `Ack` never reaches it, since this function consumes the
    // ack itself and moves straight into serving). Without this, a
    // long-lived connection's eventual failure resumes escalating from
    // wherever backoff had reached before this success, instead of starting
    // fresh from the base delay.
    backoff.reset();

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
        AttemptResult::ShutdownRequested | AttemptResult::Superseded => {}
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
    let max_pending = max_pending_requests();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = sink.lock().await.close().await;
                    return AttemptResult::ShutdownRequested;
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
                        let (code, reason) = close_code_and_reason(frame);
                        if code == CLOSE_SUPERSEDED {
                            let message = format!(
                                "tunnel closed (close code {code}): superseded by a newer connection: {reason}"
                            );
                            tracing::info!(%message, "tunnel: superseded by a newer connection; not reconnecting");
                            record_state(
                                &ctx.data_root,
                                TunnelRuntimeState {
                                    connected: false,
                                    last_error: Some(message),
                                },
                            );
                            return AttemptResult::Superseded;
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
                            max_pending,
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
    max_pending: usize,
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
            if let Err(reason) = validate_request_path(&path) {
                spawn_send_error(sink, id, reason);
                return;
            }
            if pending.len() >= max_pending {
                spawn_send_error(sink, id, "too many in-flight requests".to_string());
                return;
            }
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
        if should_strip_forwarded_header(name) {
            continue;
        }
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
        .filter(|(name, _)| !should_strip_forwarded_header(name.as_str()))
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

/// Whether `err` is the sentinel `prepare_attempt`/`bump_sequence_for_tunnel`
/// returns when the tunnel has been disabled (see
/// [`tunnel_commands::TUNNEL_DISABLED_ERROR`]) — distinguishes "stop
/// reconnecting, this is permanent until re-enabled" from an ordinary
/// retry-worthy failure (network error, identity not ready, ...).
fn is_tunnel_disabled_error(err: &anyhow::Error) -> bool {
    err.to_string() == tunnel_commands::TUNNEL_DISABLED_ERROR
}

/// Removes the on-disk tunnel-runtime marker, mirroring `tunnel disable`'s
/// own cleanup — used when the run loop detects mid-flight that the tunnel
/// was disabled, so its own next scheduled write doesn't resurrect the
/// marker `disable` already removed.
fn clear_state(data_root: &std::path::Path) {
    if let Err(err) = tunnel_commands::clear_runtime_state(data_root) {
        tracing::warn!(%err, "tunnel: failed to clear runtime state after disable");
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

    #[::core::prelude::v1::test]
    fn to_ws_url_converts_https_to_wss() {
        assert_eq!(
            to_ws_url("https://api.tinycloud.link", "office"),
            "wss://api.tinycloud.link/v1/tunnel/office"
        );
    }

    #[::core::prelude::v1::test]
    fn to_ws_url_converts_http_to_ws_for_local_dev() {
        assert_eq!(
            to_ws_url("http://127.0.0.1:4000/", "office"),
            "ws://127.0.0.1:4000/v1/tunnel/office"
        );
    }

    #[::core::prelude::v1::test]
    fn to_ws_url_percent_encodes_name() {
        assert_eq!(
            to_ws_url("https://api.tinycloud.link", "weird name"),
            "wss://api.tinycloud.link/v1/tunnel/weird%20name"
        );
    }

    #[::core::prelude::v1::test]
    fn validate_request_path_accepts_a_plain_absolute_path() {
        assert!(validate_request_path("/").is_ok());
        assert!(validate_request_path("/foo/bar?x=1").is_ok());
    }

    #[::core::prelude::v1::test]
    fn validate_request_path_rejects_userinfo_host_confusion() {
        // Concatenated onto `http://{upstream_addr}`, this reads as
        // userinfo@host, redirecting the request to `evil.com`.
        assert!(validate_request_path("@evil.com/x").is_err());
    }

    #[::core::prelude::v1::test]
    fn validate_request_path_rejects_an_embedded_scheme() {
        assert!(validate_request_path("http://evil.com/").is_err());
        assert!(validate_request_path("/redirect").is_ok()); // sanity: no false positive
    }

    #[::core::prelude::v1::test]
    fn validate_request_path_rejects_whitespace_and_control_characters() {
        assert!(validate_request_path("/foo bar").is_err());
        assert!(validate_request_path("/foo\r\nX-Injected: 1").is_err());
        assert!(validate_request_path("/foo\0bar").is_err());
    }

    #[::core::prelude::v1::test]
    fn should_strip_forwarded_header_covers_hop_by_hop_and_framing_headers() {
        for name in [
            "Connection",
            "connection",
            "Keep-Alive",
            "Transfer-Encoding",
            "Upgrade",
            "TE",
            "Trailer",
            "Content-Length",
            "Proxy-Authorization",
            "proxy-connection",
        ] {
            assert!(
                should_strip_forwarded_header(name),
                "expected {name} to be stripped"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn should_strip_forwarded_header_leaves_ordinary_headers_alone() {
        for name in ["Content-Type", "X-Custom", "Set-Cookie", "Authorization"] {
            assert!(
                !should_strip_forwarded_header(name),
                "did not expect {name} to be stripped"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn effective_max_pending_uses_the_default_when_unset_or_invalid() {
        assert_eq!(effective_max_pending(None), DEFAULT_MAX_PENDING_REQUESTS);
        assert_eq!(
            effective_max_pending(Some("not-a-number".to_string())),
            DEFAULT_MAX_PENDING_REQUESTS
        );
        assert_eq!(
            effective_max_pending(Some("0".to_string())),
            DEFAULT_MAX_PENDING_REQUESTS
        );
    }

    #[::core::prelude::v1::test]
    fn effective_max_pending_honors_a_valid_override() {
        assert_eq!(effective_max_pending(Some("8".to_string())), 8);
    }
}
