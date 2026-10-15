//! TC-963: when the dstack guest agent answers GetQuote with an error, the
//! node's logs at the production level carry its HTTP status and body length,
//! never the body. Production logs leave the host (TC-959, TC-961).
//!
//! This is its own test binary with one test, so the process-wide subscriber
//! sees every event; a thread-scoped subscriber inside the library's parallel
//! unit tests can miss events while other threads register the same callsites.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

/// Log output written at production's default INFO level.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn guest_agent_error_body_stays_out_of_production_logs() {
    let logs = Captured::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish(),
    )
    .unwrap();

    let body = r#"{"error":"agent-detail-7f3a"}"#;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dstack.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let agent = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let err = tinycloud::dstack::get_quote(socket.to_str().unwrap(), &[0x42; 32])
        .await
        .unwrap_err();
    agent.await.unwrap();

    assert!(format!("{err:#}").contains("HTTP 400"), "{err:#}");
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!logged.contains("agent-detail-7f3a"), "{logged}");
    assert!(logged.contains("status=400"), "{logged}");
    assert!(
        logged.contains(&format!("body_len={}", body.len())),
        "{logged}"
    );
}
