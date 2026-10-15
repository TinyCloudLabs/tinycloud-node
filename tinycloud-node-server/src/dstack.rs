//! Minimal dstack TEE client.
//!
//! Communicates with the dstack daemon over a Unix domain socket using raw
//! HTTP/1.1. The default socket path is `/var/run/dstack.sock` but can be
//! overridden via the `DSTACK_SIMULATOR_ENDPOINT` environment variable.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const DEFAULT_SOCKET: &str = "/var/run/dstack.sock";

/// TDX REPORTDATA is 64 bytes; the dstack guest agent rejects anything longer.
pub const MAX_REPORT_DATA_BYTES: usize = 64;

pub fn socket_path() -> String {
    std::env::var("DSTACK_SIMULATOR_ENDPOINT").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GetKeyResponse {
    key: String, // hex-encoded
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteResponse {
    pub quote: String,       // hex-encoded TDX quote
    pub event_log: String,   // JSON event log
    pub report_data: String, // hex-encoded 64-byte REPORTDATA the agent quoted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoResponse {
    pub app_id: String,
    pub compose_hash: String,
    pub instance_id: String,
}

// ---------------------------------------------------------------------------
// Raw HTTP helpers
// ---------------------------------------------------------------------------

/// Return the body of a raw HTTP/1.1 response (everything after `\r\n\r\n`),
/// or an error naming the status if the guest agent did not answer 2xx.
fn parse_response_body(raw: &[u8]) -> Result<&[u8]> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("invalid HTTP response: missing header terminator"))?;
    let status = raw[..header_end]
        .split(|&b| b == b' ')
        .nth(1)
        .and_then(|code| std::str::from_utf8(code).ok()?.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP response: missing status code"))?;
    let body = &raw[header_end + 4..];
    if !(200..300).contains(&status) {
        // The error body stays in the operator log; callers see only the status.
        let excerpt = String::from_utf8_lossy(&body[..body.len().min(512)]);
        tracing::warn!(status, body = %excerpt, "dstack guest agent returned an error");
        anyhow::bail!("guest agent returned HTTP {status}");
    }
    Ok(body)
}

async fn post_json(
    socket: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to dstack socket at {socket}"))?;

    let body_bytes = serde_json::to_vec(body)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body_bytes.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let body = parse_response_body(&response)?;
    serde_json::from_slice(body).context("parsing dstack JSON response")
}

async fn get_json(socket: &str, path: &str) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to dstack socket at {socket}"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let body = parse_response_body(&response)?;
    serde_json::from_slice(body).context("parsing dstack JSON response")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive a deterministic key from the dstack TEE.
///
/// `path` is a hierarchical key derivation path, e.g. `"tinycloud/keys/primary"`.
/// Returns the raw key bytes.
pub async fn get_key(path: &str) -> Result<Vec<u8>> {
    let body = serde_json::json!({ "path": path });
    let resp: GetKeyResponse = serde_json::from_value(
        post_json(&socket_path(), "/GetKey", &body)
            .await
            .context("dstack GetKey request")?,
    )
    .context("parsing GetKey response")?;
    hex::decode(&resp.key).context("decoding hex key bytes from dstack")
}

/// Request a TDX attestation quote from the guest agent at `socket`.
pub async fn get_quote(socket: &str, report_data: &[u8]) -> Result<GetQuoteResponse> {
    anyhow::ensure!(
        report_data.len() <= MAX_REPORT_DATA_BYTES,
        "report_data is {} bytes; a TDX quote holds at most {MAX_REPORT_DATA_BYTES}",
        report_data.len()
    );
    let body = serde_json::json!({ "report_data": hex::encode(report_data) });
    let response: GetQuoteResponse = serde_json::from_value(
        post_json(socket, "/GetQuote", &body)
            .await
            .context("dstack GetQuote request")?,
    )
    .context("parsing GetQuote response")?;

    // dstack zero-pads report_data to 64 bytes; refuse a quote over anything else.
    let mut expected = report_data.to_vec();
    expected.resize(MAX_REPORT_DATA_BYTES, 0);
    let quoted = hex::decode(response.report_data.trim_start_matches("0x"))
        .context("decoding GetQuote report_data")?;
    anyhow::ensure!(
        quoted == expected,
        "GetQuote report_data does not match the requested report_data"
    );
    Ok(response)
}

/// Retrieve TEE instance information.
pub async fn get_info() -> Result<InfoResponse> {
    serde_json::from_value(
        get_json(&socket_path(), "/Info")
            .await
            .context("dstack Info request")?,
    )
    .context("parsing Info response")
}

/// Check whether the dstack socket is reachable.
pub fn is_available() -> bool {
    std::path::Path::new(&socket_path()).exists()
}

/// A one-shot stand-in for the dstack guest agent on a temporary Unix socket.
#[cfg(test)]
pub(crate) mod stub {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::task::JoinHandle;

    pub(crate) struct Agent {
        _dir: tempfile::TempDir,
        pub(crate) socket: String,
        /// Resolves to the raw request the agent received.
        pub(crate) request: JoinHandle<Vec<u8>>,
    }

    /// Accept one connection, capture the request, then reply with
    /// `status_line` (e.g. `"400 Bad Request"`) and the JSON `body`.
    pub(crate) fn serve_once(status_line: &str, body: &str) -> Agent {
        let (status_line, body) = (status_line.to_owned(), body.to_owned());
        serve(move |_| (status_line, body))
    }

    /// Answer one GetQuote like dstack: a quote whose `report_data` is the
    /// requested bytes zero-padded to 64.
    pub(crate) fn serve_quote() -> Agent {
        serve(|request| {
            let mut padded = requested_report_data(request);
            padded.resize(super::MAX_REPORT_DATA_BYTES, 0);
            let body = serde_json::json!({
                "quote": "aa",
                "event_log": "[]",
                "report_data": hex::encode(padded),
            });
            ("200 OK".to_owned(), body.to_string())
        })
    }

    fn serve(reply: impl FnOnce(&[u8]) -> (String, String) + Send + 'static) -> Agent {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("dstack.sock").to_str().unwrap().to_owned();
        let listener = UnixListener::bind(&socket).unwrap();
        let request = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            let (status_line, body) = reply(&request);
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            request
        });
        Agent {
            _dir: dir,
            socket,
            request,
        }
    }

    /// The decoded `report_data` bytes of a captured GetQuote request.
    pub(crate) fn requested_report_data(raw: &[u8]) -> Vec<u8> {
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let body: serde_json::Value = serde_json::from_slice(&raw[split + 4..]).unwrap();
        hex::decode(body["report_data"].as_str().unwrap()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_quote_sends_exactly_64_bytes_of_report_data() {
        let agent = stub::serve_quote();
        let quote = get_quote(&agent.socket, &[0x42; MAX_REPORT_DATA_BYTES])
            .await
            .unwrap();
        assert_eq!(quote.quote, "aa");
        assert_eq!(quote.event_log, "[]");
        let sent = stub::requested_report_data(&agent.request.await.unwrap());
        assert_eq!(sent, vec![0x42; MAX_REPORT_DATA_BYTES]);
    }

    #[tokio::test]
    async fn get_quote_refuses_65_bytes_without_contacting_dstack() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.sock");
        let err = get_quote(absent.to_str().unwrap(), &[0x42; MAX_REPORT_DATA_BYTES + 1])
            .await
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("65 bytes"), "{message}");
        assert!(!message.contains("connecting"), "{message}");
    }

    #[tokio::test]
    async fn get_quote_reports_guest_agent_error_status_not_a_parse_failure() {
        let agent = stub::serve_once(
            "400 Bad Request",
            r#"{"error":"report_data must be at most 64 bytes"}"#,
        );
        let err = get_quote(&agent.socket, &[0x42; 32]).await.unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("HTTP 400"), "{message}");
        assert!(!message.contains("parsing"), "{message}");
        agent.request.await.unwrap();
    }

    #[tokio::test]
    async fn get_quote_rejects_a_quote_over_different_report_data() {
        let other = hex::encode([0x24u8; MAX_REPORT_DATA_BYTES]);
        let agent = stub::serve_once(
            "200 OK",
            &format!(r#"{{"quote":"aa","event_log":"[]","report_data":"{other}"}}"#),
        );
        let err = get_quote(&agent.socket, &[0x42; 32]).await.unwrap_err();
        assert!(format!("{err:#}").contains("report_data"), "{err:#}");
        agent.request.await.unwrap();
    }

    #[tokio::test]
    async fn get_quote_rejects_a_quote_without_report_data() {
        let agent = stub::serve_once("200 OK", r#"{"quote":"aa","event_log":"[]"}"#);
        let err = get_quote(&agent.socket, &[0x42; 32]).await.unwrap_err();
        assert!(format!("{err:#}").contains("report_data"), "{err:#}");
        agent.request.await.unwrap();
    }
}
