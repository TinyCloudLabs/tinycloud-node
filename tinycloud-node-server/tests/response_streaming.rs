use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use rocket::{
    get,
    http::{Header, Status},
    request::Request,
    response::{Responder, Response},
    routes, State,
};
use tokio::io::{AsyncRead, ReadBuf};

const BODY_SIZE: usize = 32 * 1024 * 1024;

struct RecordingReader {
    remaining: usize,
    reads: Arc<Mutex<Vec<usize>>>,
}

impl AsyncRead for RecordingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let size = self.remaining.min(buf.remaining());
        buf.put_slice(&vec![0; size]);
        self.remaining -= size;
        self.reads.lock().unwrap().push(size);
        Poll::Ready(Ok(()))
    }
}

struct MeasuredResponse(Response<'static>);

impl<'r> Responder<'r, 'static> for MeasuredResponse {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'static> {
        Ok(self.0)
    }
}

#[get("/<chunk_size>")]
fn measured_stream(chunk_size: usize, reads: &State<Arc<Mutex<Vec<usize>>>>) -> MeasuredResponse {
    MeasuredResponse(
        Response::build()
            .status(Status::Ok)
            .header(Header::new("Content-Length", BODY_SIZE.to_string()))
            .streamed_body(RecordingReader {
                remaining: BODY_SIZE,
                reads: reads.inner().clone(),
            })
            .max_chunk_size(chunk_size)
            .finalize(),
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

    let mut measurements = Vec::new();
    for chunk_size in [64 * 1024, 256 * 1024, 1024 * 1024] {
        reads.lock().unwrap().clear();
        let started = Instant::now();
        let response = client
            .get(format!("{base_url}/{chunk_size}"))
            .send()
            .await?;
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
        let elapsed = started.elapsed();
        let frames = reads.lock().unwrap().clone();
        assert!(!frames.is_empty());
        assert!(frames.iter().all(|size| *size <= chunk_size));
        assert!(frames.iter().any(|size| *size > 4096));
        measurements.push((chunk_size, elapsed, frames));
    }

    for (chunk_size, elapsed, frames) in &measurements {
        eprintln!(
            "TC-285 observed wire stream: chunk_size={} bytes, frames={}, max_frame={} bytes, throughput={:.1} MiB/s",
            chunk_size,
            frames.len(),
            frames.iter().copied().max().unwrap_or_default(),
            BODY_SIZE as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        );
    }

    shutdown.notify();
    server.await??;
    Ok(())
}
