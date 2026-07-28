use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::io::AsyncRead;
use rocket::{get, routes, State};
use tinycloud::auth_guards::KVResponse;
use tinycloud_core::{hash::hash, storage::Content, types::Metadata};

const BODY_SIZE: usize = 32 * 1024 * 1024;
const CONFIGURED_MAX_CHUNK_SIZE: usize = 256 * 1024;

struct RecordingReader {
    remaining: usize,
    reads: Arc<Mutex<Vec<usize>>>,
}

impl AsyncRead for RecordingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.remaining == 0 {
            return Poll::Ready(Ok(0));
        }

        let size = self.remaining.min(buf.len());
        buf[..size].fill(0);
        self.remaining -= size;
        self.reads.lock().unwrap().push(size);
        Poll::Ready(Ok(size))
    }
}

#[get("/")]
fn measured_stream(reads: &State<Arc<Mutex<Vec<usize>>>>) -> KVResponse<RecordingReader> {
    KVResponse::new(
        Metadata(Default::default()),
        hash(b"wire-stream"),
        Content::new(
            BODY_SIZE as u64,
            RecordingReader {
                remaining: BODY_SIZE,
                reads: reads.inner().clone(),
            },
        ),
    )
}

#[get("/health")]
fn health() -> &'static str {
    "ok"
}

async fn wait_for_server(client: &reqwest::Client, url: &str) -> anyhow::Result<()> {
    for _ in 0..100 {
        match client.get(url).send().await {
            Ok(response) => {
                response.error_for_status_ref()?;
                return Ok(());
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    anyhow::bail!("Rocket test server did not become ready")
}

#[tokio::test]
async fn observed_wire_streaming_has_content_length_and_useful_frames() -> anyhow::Result<()> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let reads: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let rocket = rocket::custom(
        rocket::Config::figment()
            .merge(("address", "127.0.0.1"))
            .merge(("port", port))
            .merge(("log_level", "off")),
    )
    .manage(reads.clone())
    .mount("/", routes![health, measured_stream]);
    let rocket = rocket.ignite().await?;
    let shutdown = rocket.shutdown();
    let server = tokio::spawn(async move { rocket.launch().await });
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{port}");
    wait_for_server(&client, &format!("{base_url}/health")).await?;

    reads.lock().unwrap().clear();
    let response = client.get(format!("{base_url}/")).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .unwrap()
            .to_str()?
            .parse::<usize>()?,
        BODY_SIZE
    );
    assert!(response.headers().get("transfer-encoding").is_none());
    assert_eq!(response.bytes().await?.len(), BODY_SIZE);
    let frames = reads.lock().unwrap().clone();
    assert!(!frames.is_empty());
    assert!(frames.iter().all(|size| *size <= CONFIGURED_MAX_CHUNK_SIZE));
    assert!(frames.iter().any(|size| *size > 4096));
    eprintln!(
        "TC-285 observed real KVResponse wire stream: configured_chunk_size={} bytes, frames={}, max_frame={} bytes",
        CONFIGURED_MAX_CHUNK_SIZE,
        frames.len(),
        frames.iter().copied().max().unwrap_or_default(),
    );

    shutdown.notify();
    server.await??;
    Ok(())
}
