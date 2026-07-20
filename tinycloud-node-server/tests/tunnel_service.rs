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
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    extract::{
        ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade},
        Path,
    },
    http::{HeaderMap, StatusCode, Uri},
    response::{AppendHeaders, IntoResponse},
    routing::{any, get},
    Router,
};
use tempfile::tempdir;
use tinycloud::{
    config::Keys,
    link::state::{self as link_state, LinkPaths, LinkState},
    tunnel::{
        commands::{disable as tunnel_disable, enable as tunnel_enable, TunnelEnableArgs},
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

/// Regression test for the tunnel SSRF fix: `serve_request` builds the
/// forwarded URL as `format!("http://{upstream_addr}{path}")`. A relay
/// (hostile or buggy) that sends a `request` frame whose `path` doesn't
/// start with `/` — e.g. `@evil.com/x`, which reads as
/// `userinfo@host` when concatenated onto the authority, retargeting the
/// request to `evil.com` — or that embeds its own scheme (`http://evil.com/`)
/// must get an immediate per-request `error` frame and must never cause an
/// outbound HTTP request to be made at all, to any host.
#[tokio::test]
async fn malicious_request_paths_are_rejected_without_reaching_any_upstream() {
    let _env_lock = env_lock().await;
    install_env_secret(36);

    let request_count = Arc::new(AtomicUsize::new(0));
    let counter_for_upstream = request_count.clone();
    let upstream_app = Router::new().fallback(any(move || {
        let counter = counter_for_upstream.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            StatusCode::OK
        }
    }));
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_app).await;
    });

    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let (result_tx, result_rx) = oneshot::channel::<Vec<(Option<String>, String)>>();
    let result_tx = Arc::new(Mutex::new(Some(result_tx)));

    let obs_for_ws = observations.clone();
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let result_tx = result_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_ack(&mut socket).await;

                let malicious_paths = [("req-a", "@evil.com/x"), ("req-b", "http://evil.com/")];
                for (id, path) in malicious_paths {
                    socket
                        .send(WsMessage::Text(
                            TunnelFrame::Request {
                                id: id.to_string(),
                                method: "GET".to_string(),
                                path: path.to_string(),
                                headers: vec![],
                            }
                            .encode(),
                        ))
                        .await
                        .unwrap();
                    socket
                        .send(WsMessage::Text(
                            TunnelFrame::RequestBody {
                                id: id.to_string(),
                                chunk: String::new(),
                                done: true,
                            }
                            .encode(),
                        ))
                        .await
                        .unwrap();
                }

                let mut errors = Vec::new();
                while errors.len() < malicious_paths.len() {
                    let Some(Ok(WsMessage::Text(text))) = socket.recv().await else {
                        break;
                    };
                    if let Ok(TunnelFrame::Error { id, message }) = TunnelFrame::parse(&text) {
                        errors.push((id, message));
                    }
                }
                if let Some(tx) = result_tx.lock().unwrap().take() {
                    let _ = tx.send(errors);
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
        "ssrfnode",
        &format!("http://{relay_addr}"),
    );
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let errors = tokio::time::timeout(Duration::from_secs(10), result_rx)
        .await
        .expect("expected an error frame for each malicious path")
        .expect("relay task dropped its result sender");

    assert_eq!(
        errors.len(),
        2,
        "expected exactly one error frame per rejected request"
    );
    assert_eq!(errors[0].0.as_deref(), Some("req-a"));
    assert_eq!(errors[1].0.as_deref(), Some("req-b"));

    stop_and_join(shutdown_tx, handle).await;

    assert_eq!(
        request_count.load(Ordering::SeqCst),
        0,
        "a malicious path must never reach any upstream, real or otherwise"
    );
}

/// Regression test for the dead `BackoffState::reset` bug: the run loop
/// never routed a successful `Ack` back through `BackoffState::next_action`,
/// so `reset` was never called and backoff kept escalating for the process
/// lifetime even across successful connections. Three consecutive
/// pre-connect failures push the backoff delay up to ~2-4s (2^3 * 500ms,
/// jittered to [0.5, 1.0)); a fourth attempt then acks and briefly serves
/// before being dropped. If backoff correctly reset on that ack, the
/// following (fifth) failure's delay is back near the ~250-500ms base rather
/// than continuing to escalate — the two are separated by roughly an order
/// of magnitude, wide enough margin to not be timing-flaky.
#[tokio::test]
async fn backoff_resets_after_a_successful_ack_so_a_later_failure_is_not_escalated() {
    let _env_lock = env_lock().await;
    install_env_secret(37);

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let attempt_times: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
    const PRE_ACK_FAILURES: usize = 3;

    let obs_for_ws = observations.clone();
    let times_for_ws = attempt_times.clone();
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let times = times_for_ws.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                times.lock().unwrap().push(Instant::now());
                let attempt_number = obs.lock().unwrap().attempts;

                if attempt_number <= PRE_ACK_FAILURES {
                    // Escalate the ordinary backoff delay with repeated
                    // rejections before the connection ever succeeds.
                    send_close(&mut socket, 4400).await;
                    return;
                }
                if attempt_number == PRE_ACK_FAILURES + 1 {
                    // Succeed once — this must reset backoff — then drop the
                    // live connection so the *next* failure's delay can be
                    // observed.
                    send_ack(&mut socket).await;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    send_close(&mut socket, 4400).await;
                    return;
                }
                // Final attempt: ack and hold so the test can shut down
                // cleanly without a further reconnect.
                send_ack(&mut socket).await;
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
        "backoffnode",
        &format!("http://{relay_addr}"),
    );
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let target_attempts = PRE_ACK_FAILURES + 2;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if attempt_times.lock().unwrap().len() >= target_attempts {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expected the reconnect loop to reach the post-reset attempt in time");

    stop_and_join(shutdown_tx, handle).await;

    let times = attempt_times.lock().unwrap().clone();
    assert_eq!(times.len(), target_attempts);

    // Gap before the 4th (ack) attempt, i.e. after 3 consecutive pre-ack
    // failures: backoff's internal `attempt` counter is 2 by then, so the
    // unjittered delay is 500ms * 2^2 = 2000ms — at least 1000ms even at the
    // minimum 0.5x jitter, confirming backoff really did escalate going into
    // the successful attempt.
    let escalated_gap = times[PRE_ACK_FAILURES] - times[PRE_ACK_FAILURES - 1];
    assert!(
        escalated_gap >= Duration::from_millis(900),
        "expected backoff to have escalated before the ack, got {escalated_gap:?}"
    );

    // Gap after the successful ack (between the ack+drop attempt and the
    // next attempt): if `reset` fires, attempt=0 there, so the delay is back
    // near the ~250-500ms base — nowhere close to the escalated gap above.
    let post_reset_gap = times[PRE_ACK_FAILURES + 1] - times[PRE_ACK_FAILURES];
    assert!(
        post_reset_gap < Duration::from_millis(1500),
        "backoff must reset after a successful ack; got {post_reset_gap:?} \
         (an unreset backoff would be several seconds by this point)"
    );
}

/// Regression test for the "tunnel disable while serve runs" bug: the
/// connection loop used to treat the "tunnel: disabled" bump-sequence error
/// as an ordinary retryable failure, so `tunnel disable` (which flips
/// `tunnelEnabled` off and removes the on-disk runtime marker) racing a live
/// retry loop got its cleanup undone on the loop's very next backoff-write,
/// and the loop itself never stopped. Disabling mid-retry must make the loop
/// exit on its own (no shutdown signal needed) and the marker must stay gone
/// afterward.
#[tokio::test]
async fn disable_during_retry_loop_stops_the_task_and_does_not_resurrect_the_marker() {
    let _env_lock = env_lock().await;
    install_env_secret(38);

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let obs_for_ws = observations.clone();

    // Always reject the auth attempt so the client stays in the retry loop
    // until we disable it out from under it.
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_close(&mut socket, 4400).await;
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
        "disablenode",
        &format!("http://{relay_addr}"),
    );

    let (_shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    // Wait for at least one failed attempt so the retry loop is definitely
    // running (and mid-backoff) before we disable underneath it.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if observations.lock().unwrap().attempts >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expected at least one connection attempt before disabling");

    // Simulate `tinycloud node tunnel disable` running concurrently with the
    // live retry loop.
    tunnel_disable(data_root.path()).unwrap();

    // The loop must notice on its next attempt and exit on its own.
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("tunnel task did not stop after tunnel disable")
        .expect("tunnel task panicked");

    let link_paths = LinkPaths::from_data_root(data_root.path());
    assert!(
        link_state::read_tunnel_runtime_state(&link_paths)
            .unwrap()
            .is_none(),
        "the runtime marker must be gone once the loop notices it's disabled"
    );

    // No resurrection: give any stray scheduled write a chance to run, then
    // re-check.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        link_state::read_tunnel_runtime_state(&link_paths)
            .unwrap()
            .is_none(),
        "the marker must not be resurrected after the loop has stopped"
    );
}

/// Regression test for hop-by-hop/framing header leakage: headers that must
/// never cross the proxy boundary verbatim (RFC 7230 §6.1 hop-by-hop headers
/// plus `content-length`/`transfer-encoding`, whose values describe framing
/// for a body this proxy has already reassembled/re-chunked itself) must be
/// stripped both from the frame headers forwarded to the loopback upstream
/// and from the upstream response headers forwarded back as a `response`
/// frame.
#[tokio::test]
async fn hop_by_hop_and_framing_headers_are_stripped_in_both_directions() {
    let _env_lock = env_lock().await;
    install_env_secret(39);

    let received_headers: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
    let headers_for_upstream = received_headers.clone();
    let upstream_app = Router::new().fallback(any(move |headers: HeaderMap| {
        let store = headers_for_upstream.clone();
        async move {
            *store.lock().unwrap() = Some(headers);
            // A single safe extra header ("connection") — deliberately not
            // also setting `transfer-encoding`/`content-length` by hand
            // here, since combining those with axum's own auto-computed
            // framing produces an actually malformed HTTP/1.1 response and
            // would test transport brokenness rather than header stripping.
            // axum still auto-computes an accurate `Content-Length` for this
            // body, which is exactly what we assert gets stripped below.
            (
                StatusCode::OK,
                [("connection", "close"), ("content-type", "text/plain")],
                "ok",
            )
                .into_response()
        }
    }));
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_app).await;
    });

    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let (result_tx, result_rx) = oneshot::channel::<Vec<(String, String)>>();
    let result_tx = Arc::new(Mutex::new(Some(result_tx)));

    let obs_for_ws = observations.clone();
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let result_tx = result_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_ack(&mut socket).await;

                socket
                    .send(WsMessage::Text(
                        TunnelFrame::Request {
                            id: "req-1".to_string(),
                            method: "GET".to_string(),
                            path: "/echo".to_string(),
                            headers: vec![
                                ("connection".to_string(), "keep-alive".to_string()),
                                ("keep-alive".to_string(), "timeout=5".to_string()),
                                ("transfer-encoding".to_string(), "chunked".to_string()),
                                ("content-length".to_string(), "999".to_string()),
                                ("x-custom".to_string(), "hello".to_string()),
                            ],
                        }
                        .encode(),
                    ))
                    .await
                    .unwrap();
                socket
                    .send(WsMessage::Text(
                        TunnelFrame::RequestBody {
                            id: "req-1".to_string(),
                            chunk: String::new(),
                            done: true,
                        }
                        .encode(),
                    ))
                    .await
                    .unwrap();

                let mut response_headers = Vec::new();
                loop {
                    let Some(Ok(WsMessage::Text(text))) = socket.recv().await else {
                        break;
                    };
                    match TunnelFrame::parse(&text).unwrap() {
                        TunnelFrame::Response { headers, .. } => response_headers = headers,
                        TunnelFrame::ResponseBody { done, .. } => {
                            if done {
                                break;
                            }
                        }
                        other => panic!("unexpected frame from node: {other:?}"),
                    }
                }
                if let Some(tx) = result_tx.lock().unwrap().take() {
                    let _ = tx.send(response_headers);
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
        "headernode",
        &format!("http://{relay_addr}"),
    );
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let response_headers = tokio::time::timeout(Duration::from_secs(10), result_rx)
        .await
        .expect("relay-side assertions timed out")
        .expect("relay task dropped its result sender");

    stop_and_join(shutdown_tx, handle).await;

    // Request side: none of the hop-by-hop/framing headers reached upstream,
    // but the ordinary header did.
    let upstream_headers = received_headers
        .lock()
        .unwrap()
        .take()
        .expect("upstream never received the request");
    for stripped in [
        "connection",
        "keep-alive",
        "transfer-encoding",
        "content-length",
    ] {
        assert!(
            !upstream_headers.contains_key(stripped),
            "expected {stripped} to be stripped before reaching upstream, headers: {upstream_headers:?}"
        );
    }
    assert_eq!(
        upstream_headers
            .get("x-custom")
            .map(|v| v.to_str().unwrap()),
        Some("hello")
    );

    // Response side: none of the hop-by-hop/framing headers the upstream
    // sent back made it into the `response` frame, but the ordinary header
    // did. `content-length` here is axum's own accurately-computed value
    // (not an artificial one) — its absence confirms the strip is
    // unconditional, not merely a no-op on an already-missing header.
    for stripped in ["connection", "content-length"] {
        assert!(
            !response_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(stripped)),
            "expected {stripped} to be stripped from the response frame, got {response_headers:?}"
        );
    }
    assert!(response_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/plain"));
}

/// Regression test for the 4410 last_error-clobbering bug: the run loop's
/// generic tail cleanup used to unconditionally overwrite the on-disk
/// `last_error` with `None` after any `Stopped` exit, discarding the
/// descriptive "superseded by a newer connection" message the detecting
/// site had just recorded.
#[tokio::test]
async fn superseded_close_preserves_the_descriptive_last_error() {
    let _env_lock = env_lock().await;
    install_env_secret(40);

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
        "supersedederrornode",
        &format!("http://{relay_addr}"),
    );
    let (_shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("tunnel task did not stop after a 4410 close")
        .expect("tunnel task panicked");

    let link_paths = LinkPaths::from_data_root(data_root.path());
    let runtime = link_state::read_tunnel_runtime_state(&link_paths)
        .unwrap()
        .expect("expected a runtime marker to have been written");
    assert!(!runtime.connected);
    let last_error = runtime
        .last_error
        .expect("expected the superseded message to survive the run loop's final cleanup");
    assert!(
        last_error.contains("superseded"),
        "expected a descriptive superseded message, got {last_error:?}"
    );
}

/// Regression test for the unbounded pending-request map: a relay that opens
/// many requests without ever finishing their bodies must not be able to
/// grow the node's in-flight tracking table without limit. Requests beyond
/// `TINYCLOUD_TUNNEL_MAX_PENDING_REQUESTS` must get an immediate `error`
/// frame instead.
#[tokio::test]
async fn requests_beyond_the_pending_cap_get_an_immediate_error_frame() {
    let _env_lock = env_lock().await;
    install_env_secret(41);
    const CAP: usize = 2;
    let _cap_guard = EnvVarGuard::set("TINYCLOUD_TUNNEL_MAX_PENDING_REQUESTS", &CAP.to_string());

    let upstream_addr = spawn_upstream().await;
    let observations = Arc::new(Mutex::new(RelayObservations::default()));
    let (result_tx, result_rx) = oneshot::channel::<Vec<Option<String>>>();
    let result_tx = Arc::new(Mutex::new(Some(result_tx)));

    let obs_for_ws = observations.clone();
    let ws_handler = move |ws: WebSocketUpgrade, Path(_name): Path<String>| {
        let obs = obs_for_ws.clone();
        let result_tx = result_tx.clone();
        async move {
            ws.on_upgrade(move |mut socket| async move {
                recv_auth_frame(&mut socket, &obs).await;
                send_ack(&mut socket).await;

                // Open CAP + 1 requests, never completing their bodies, so
                // they all remain in the pending/reassembly map.
                for i in 0..(CAP + 1) {
                    socket
                        .send(WsMessage::Text(
                            TunnelFrame::Request {
                                id: format!("req-{i}"),
                                method: "GET".to_string(),
                                path: "/never-finishes".to_string(),
                                headers: vec![],
                            }
                            .encode(),
                        ))
                        .await
                        .unwrap();
                }

                // Exactly one of the CAP+1 requests must be rejected
                // immediately with an error frame (the map only has room for
                // CAP, and none of these ever complete on their own).
                let mut errors = Vec::new();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(remaining, socket.recv()).await {
                        Ok(Some(Ok(WsMessage::Text(text)))) => {
                            if let Ok(TunnelFrame::Error { id, .. }) = TunnelFrame::parse(&text) {
                                errors.push(id);
                            }
                        }
                        _ => break,
                    }
                }
                if let Some(tx) = result_tx.lock().unwrap().take() {
                    let _ = tx.send(errors);
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
    seed_enabled_tunnel_state(data_root.path(), "capnode", &format!("http://{relay_addr}"));
    let (shutdown_tx, handle) = spawn_tunnel_client(data_root.path(), upstream_addr).await;

    let errors = tokio::time::timeout(Duration::from_secs(10), result_rx)
        .await
        .expect("relay-side assertions timed out")
        .expect("relay task dropped its result sender");

    stop_and_join(shutdown_tx, handle).await;

    assert_eq!(
        errors.len(),
        1,
        "expected exactly one rejection once the pending cap is exceeded, got {errors:?}"
    );
    assert_eq!(errors[0].as_deref(), Some(format!("req-{CAP}").as_str()));
}

/// Sets a process env var for the duration of the guard, restoring (or
/// removing) the previous value on drop. Combined with `env_lock`, this
/// serializes tests that mutate process-wide env state so they don't race
/// other tests running in parallel.
struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}
