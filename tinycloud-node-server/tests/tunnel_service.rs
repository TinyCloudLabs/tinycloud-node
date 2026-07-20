// Integration tests for the `tunnel` module (TC-252): the outbound Rust
// tunnel client against a mock relay (a small axum WebSocket server
// standing in for tinycloud-link's `src/tunnel/upgrade.ts` +
// `src/tunnel/protocol.ts`) and a mock loopback upstream server (standing in
// for the node's own public API that a real relay request would be
// forwarded to).
//
//   1. Full framing roundtrip: a >256KB request body is chunked across
//      multiple `requestBody` frames, forwarded to the loopback upstream,
//      and a >256KB response is chunked back across `responseBody` frames.
//   2. Duplicate `Set-Cookie` response headers survive the round trip as
//      distinct ordered pairs, not collapsed onto one header.
//   3. A stale-sequence (4409) close on the first connection attempt is
//      recovered by resyncing the local sequence forward and retrying,
//      landing a second, higher-sequence auth attempt that succeeds.
//   4. A superseded (4410) close stops the tunnel task outright — exactly
//      one connection attempt is made, never a second.
//   5. The relay's ping is answered with a pong automatically (tungstenite's
//      documented behavior, which the tinycloud-link README relies on).
//
// None of these tests touch the real tinycloud.link service or the network
// — the mock relay and the mock upstream both run on 127.0.0.1 with
// OS-assigned ports, mirroring `tests/link_service.rs`'s approach.
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::{
        ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade},
        Path,
    },
    http::{StatusCode, Uri},
    response::{AppendHeaders, IntoResponse},
    routing::{any, get},
    Router,
};
use tempfile::tempdir;
use tinycloud::{
    config::Keys,
    link::state::{self as link_state, LinkPaths, LinkState},
    tunnel::{
        commands::{enable as tunnel_enable, TunnelEnableArgs},
        connection::{run as run_tunnel, TunnelContext},
        protocol::{TunnelFrame, BODY_CHUNK_BYTES, CLOSE_STALE_SEQUENCE, CLOSE_SUPERSEDED},
    },
};
use tokio::sync::{oneshot, watch};

/// Serializes tests that mutate the process-wide `TINYCLOUD_KEYS_SECRET` env
/// var — same rationale as `tests/link_service.rs`'s `env_lock`.
async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn install_env_secret(seed: u8) {
    let secret = [seed; 32];
    let encoded = base64::encode_config(secret, base64::URL_SAFE_NO_PAD);
    std::env::set_var("TINYCLOUD_KEYS_SECRET", &encoded);
}

/// Seeds a `link enable`d + `tunnel enable`d `state.json` directly on disk,
/// bypassing the network calls `link::commands::enable` would make — these
/// tests are about the tunnel connection, not the link claim flow (already
/// covered by `tests/link_service.rs`).
fn seed_enabled_tunnel_state(data_root: &std::path::Path, name: &str, relay_base_url: &str) {
    let paths = LinkPaths::from_data_root(data_root);
    let seeded = LinkState::new(name.to_string(), relay_base_url.to_string(), None);
    link_state::write_state(&paths, &seeded).unwrap();
    tunnel_enable(data_root, TunnelEnableArgs::default()).unwrap();
}

/// A minimal loopback "public API" upstream: echoes the request body back,
/// and additionally appends two `Set-Cookie` headers for `/cookies` so
/// duplicate-header preservation can be exercised end-to-end.
async fn spawn_upstream() -> SocketAddr {
    async fn upstream_handler(uri: Uri, body: Bytes) -> impl IntoResponse {
        if uri.path() == "/cookies" {
            return (
                StatusCode::OK,
                AppendHeaders([("set-cookie", "a=1"), ("set-cookie", "b=2")]),
                body,
            )
                .into_response();
        }
        (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
    }

    let app = Router::new().fallback(any(upstream_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Shared observations the mock relay records across connection attempts.
#[derive(Default)]
struct RelayObservations {
    attempts: usize,
    sequences: Vec<u64>,
    names: Vec<String>,
}

/// Reads the auth frame (recording it into `observations`) and returns the
/// next queued [`AuthOutcome`] for this attempt (defaulting to `Ack` once
/// the queue is exhausted).
async fn recv_auth_frame(
    socket: &mut WebSocket,
    observations: &Arc<Mutex<RelayObservations>>,
) -> serde_json::Value {
    let msg = socket
        .recv()
        .await
        .expect("socket closed before auth frame")
        .expect("websocket error before auth frame");
    let WsMessage::Text(text) = msg else {
        panic!("expected a text auth frame, got {msg:?}");
    };
    let auth: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut obs = observations.lock().unwrap();
    obs.attempts += 1;
    obs.sequences.push(auth["sequence"].as_u64().unwrap());
    obs.names.push(auth["name"].as_str().unwrap().to_string());
    auth
}

async fn send_close(socket: &mut WebSocket, code: u16) {
    let _ = socket
        .send(WsMessage::Close(Some(CloseFrame {
            code,
            reason: "test".into(),
        })))
        .await;
}

async fn send_ack(socket: &mut WebSocket) {
    socket
        .send(WsMessage::Text(TunnelFrame::Ack.encode()))
        .await
        .unwrap();
}

/// Spawns the tunnel connection task against `relay_url`, targeting
/// `upstream_addr` as the loopback public API, and returns its shutdown
/// sender plus join handle.
async fn spawn_tunnel_client(
    data_root: &std::path::Path,
    upstream_addr: SocketAddr,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let ctx = TunnelContext {
        data_root: data_root.to_path_buf(),
        keys: Some(Keys::Auto),
        upstream_addr,
    };
    let handle = tokio::spawn(run_tunnel(ctx, shutdown_rx));
    (shutdown_tx, handle)
}

async fn stop_and_join(shutdown_tx: watch::Sender<bool>, handle: tokio::task::JoinHandle<()>) {
    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("tunnel task did not shut down in time")
        .expect("tunnel task panicked");
}

#[tokio::test]
async fn framing_roundtrip_reassembles_chunked_request_and_response_bodies() {
    let _env_lock = env_lock().await;
    install_env_secret(31);

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let (result_tx, result_rx) = oneshot::channel::<(u16, Vec<(String, String)>, Vec<u8>)>();
    let result_tx = Arc::new(Mutex::new(Some(result_tx)));

    let obs_for_ws = observations.clone();
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let result_tx = result_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_ack(&mut socket).await;

                // A body well over BODY_CHUNK_BYTES so the relay side (us,
                // playing relay) must split it across multiple
                // `requestBody` frames, exactly like the real relay does.
                let body = vec![b'x'; BODY_CHUNK_BYTES * 2 + 12345];
                let id = "req-1".to_string();
                socket
                    .send(WsMessage::Text(
                        TunnelFrame::Request {
                            id: id.clone(),
                            method: "POST".to_string(),
                            path: "/echo".to_string(),
                            headers: vec![("x-custom".to_string(), "hello".to_string())],
                        }
                        .encode(),
                    ))
                    .await
                    .unwrap();
                let chunks = tinycloud::tunnel::protocol::chunk_body(&body);
                let last = chunks.len() - 1;
                for (i, chunk) in chunks.into_iter().enumerate() {
                    socket
                        .send(WsMessage::Text(
                            TunnelFrame::RequestBody {
                                id: id.clone(),
                                chunk,
                                done: i == last,
                            }
                            .encode(),
                        ))
                        .await
                        .unwrap();
                }

                // Collect the response + chunked responseBody frames.
                let mut status = 0u16;
                let mut headers = Vec::new();
                let mut body_out = Vec::new();
                let mut response_frame_count = 0usize;
                loop {
                    let Some(Ok(WsMessage::Text(text))) = socket.recv().await else {
                        break;
                    };
                    match TunnelFrame::parse(&text).unwrap() {
                        TunnelFrame::Response {
                            status: s, headers: h, ..
                        } => {
                            status = s;
                            headers = h;
                        }
                        TunnelFrame::ResponseBody { chunk, done, .. } => {
                            response_frame_count += 1;
                            if !chunk.is_empty() {
                                body_out.extend(
                                    base64::decode_config(&chunk, base64::STANDARD).unwrap(),
                                );
                            }
                            if done {
                                break;
                            }
                        }
                        other => panic!("unexpected frame from node: {other:?}"),
                    }
                }
                assert!(
                    response_frame_count > 1,
                    "expected the >256KB response body to be split across multiple responseBody frames, got {response_frame_count}"
                );

                if let Some(tx) = result_tx.lock().unwrap().take() {
                    let _ = tx.send((status, headers, body_out));
                }
            })
        }
    };

    let app = Router::new().route("/v1/tunnel/:name", get(ws_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let data_root = tempdir().unwrap();
    seed_enabled_tunnel_state(
        data_root.path(),
        "echonode",
        &format!("http://{relay_addr}"),
    );

    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let (status, headers, body_out) = tokio::time::timeout(Duration::from_secs(10), result_rx)
        .await
        .expect("relay-side assertions timed out")
        .expect("relay task dropped its result sender");

    assert_eq!(status, 200);
    assert!(headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/plain"));
    assert_eq!(body_out.len(), BODY_CHUNK_BYTES * 2 + 12345);
    assert!(body_out.iter().all(|&b| b == b'x'));

    stop_and_join(shutdown_tx, handle).await;

    let obs = observations.lock().unwrap();
    assert_eq!(obs.attempts, 1);
    assert_eq!(obs.names, vec!["echonode".to_string()]);
}

#[tokio::test]
async fn duplicate_set_cookie_response_headers_survive_the_round_trip() {
    let _env_lock = env_lock().await;
    install_env_secret(32);

    let upstream_addr = spawn_upstream().await;
    let (result_tx, result_rx) = oneshot::channel::<Vec<(String, String)>>();
    let result_tx = Arc::new(Mutex::new(Some(result_tx)));
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let obs_for_ws = observations.clone();

    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let result_tx = result_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_ack(&mut socket).await;

                let id = "req-1".to_string();
                socket
                    .send(WsMessage::Text(
                        TunnelFrame::Request {
                            id: id.clone(),
                            method: "GET".to_string(),
                            path: "/cookies".to_string(),
                            headers: vec![],
                        }
                        .encode(),
                    ))
                    .await
                    .unwrap();
                socket
                    .send(WsMessage::Text(
                        TunnelFrame::RequestBody {
                            id: id.clone(),
                            chunk: String::new(),
                            done: true,
                        }
                        .encode(),
                    ))
                    .await
                    .unwrap();

                let mut headers = Vec::new();
                loop {
                    let Some(Ok(WsMessage::Text(text))) = socket.recv().await else {
                        break;
                    };
                    match TunnelFrame::parse(&text).unwrap() {
                        TunnelFrame::Response { headers: h, .. } => headers = h,
                        TunnelFrame::ResponseBody { done, .. } => {
                            if done {
                                break;
                            }
                        }
                        other => panic!("unexpected frame from node: {other:?}"),
                    }
                }
                if let Some(tx) = result_tx.lock().unwrap().take() {
                    let _ = tx.send(headers);
                }
            })
        }
    };

    let app = Router::new().route("/v1/tunnel/:name", get(ws_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let data_root = tempdir().unwrap();
    seed_enabled_tunnel_state(
        data_root.path(),
        "cookienode",
        &format!("http://{relay_addr}"),
    );
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let headers = tokio::time::timeout(Duration::from_secs(10), result_rx)
        .await
        .expect("relay-side assertions timed out")
        .expect("relay task dropped its result sender");

    let set_cookie_values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        set_cookie_values,
        vec!["a=1", "b=2"],
        "both Set-Cookie headers must survive as distinct ordered entries, not collapse onto one"
    );

    stop_and_join(shutdown_tx, handle).await;
}

#[tokio::test]
async fn stale_sequence_close_resyncs_and_the_retry_succeeds() {
    let _env_lock = env_lock().await;
    install_env_secret(33);

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let (ack_tx, ack_rx) = oneshot::channel::<()>();
    let ack_tx = Arc::new(Mutex::new(Some(ack_tx)));

    let obs_for_ws = observations.clone();
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let ack_tx = ack_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                let attempt_number = obs.lock().unwrap().attempts;
                if attempt_number == 1 {
                    send_close(&mut socket, CLOSE_STALE_SEQUENCE).await;
                    return;
                }
                send_ack(&mut socket).await;
                if let Some(tx) = ack_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                // Keep the socket open (but idle) until the test shuts the
                // client down — dropping it here would itself look like a
                // disconnect and muddy the assertion.
                let _ = socket.recv().await;
            })
        }
    };

    let app = Router::new().route("/v1/tunnel/:name", get(ws_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let data_root = tempdir().unwrap();
    seed_enabled_tunnel_state(
        data_root.path(),
        "staletunnel",
        &format!("http://{relay_addr}"),
    );
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    tokio::time::timeout(Duration::from_secs(10), ack_rx)
        .await
        .expect("second connection attempt did not ack in time")
        .unwrap();

    stop_and_join(shutdown_tx, handle).await;

    let obs = observations.lock().unwrap();
    assert_eq!(obs.attempts, 2, "expected exactly one resync retry");
    assert_eq!(obs.sequences.len(), 2);
    assert!(
        obs.sequences[1] > obs.sequences[0],
        "resync retry must use a strictly higher sequence: {:?}",
        obs.sequences
    );
    // bump_sequence_for_tunnel jumps by SEQUENCE_RESYNC_JUMP (100) on top of
    // the next ordinary sequence value on a stale-sequence retry.
    assert!(
        obs.sequences[1] - obs.sequences[0] >= 100,
        "resync jump must be at least SEQUENCE_RESYNC_JUMP: {:?}",
        obs.sequences
    );
}

#[tokio::test]
async fn superseded_close_stops_the_task_without_reconnecting() {
    let _env_lock = env_lock().await;
    install_env_secret(34);

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let obs_for_ws = observations.clone();

    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_close(&mut socket, CLOSE_SUPERSEDED).await;
            })
        }
    };

    let app = Router::new().route("/v1/tunnel/:name", get(ws_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let data_root = tempdir().unwrap();
    seed_enabled_tunnel_state(
        data_root.path(),
        "supersedednode",
        &format!("http://{relay_addr}"),
    );
    let (_shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    // A superseded connection must make the task exit on its own — no
    // shutdown signal needed, and (critically) no second connection
    // attempt.
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("tunnel task did not stop after a 4410 close")
        .expect("tunnel task panicked");

    let obs = observations.lock().unwrap();
    assert_eq!(
        obs.attempts, 1,
        "a superseded (4410) close must not trigger a reconnect"
    );
}

#[tokio::test]
async fn relay_ping_is_answered_with_a_pong_automatically() {
    let _env_lock = env_lock().await;
    install_env_secret(35);

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let (pong_tx, pong_rx) = oneshot::channel::<bool>();
    let pong_tx = Arc::new(Mutex::new(Some(pong_tx)));
    let obs_for_ws = observations.clone();

    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let pong_tx = pong_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_ack(&mut socket).await;

                socket.send(WsMessage::Ping(vec![7, 8, 9])).await.unwrap();
                let got_pong = matches!(socket.recv().await, Some(Ok(WsMessage::Pong(_))));
                if let Some(tx) = pong_tx.lock().unwrap().take() {
                    let _ = tx.send(got_pong);
                }
            })
        }
    };

    let app = Router::new().route("/v1/tunnel/:name", get(ws_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let data_root = tempdir().unwrap();
    seed_enabled_tunnel_state(
        data_root.path(),
        "pingnode",
        &format!("http://{relay_addr}"),
    );
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let got_pong = tokio::time::timeout(Duration::from_secs(10), pong_rx)
        .await
        .expect("relay did not observe a response to its ping in time")
        .unwrap();
    assert!(
        got_pong,
        "the tunnel client's WebSocket library must answer a Ping with a Pong automatically"
    );

    stop_and_join(shutdown_tx, handle).await;
}
