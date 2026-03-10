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

fn socket_path() -> String {
    std::env::var("DSTACK_SIMULATOR_ENDPOINT").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GetKeyResponse {
    #[serde(rename = "asBytes")]
    as_bytes: String, // hex-encoded
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteResponse {
    pub quote: String,     // hex-encoded TDX quote
    pub event_log: String, // hex-encoded event log
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

/// Parse the body from a raw HTTP/1.1 response (everything after `\r\n\r\n`).
fn parse_response_body(raw: &[u8]) -> Result<&[u8]> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("invalid HTTP response: missing header terminator"))?;
    Ok(&raw[header_end + 4..])
}

async fn post_json(path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let socket = socket_path();
    let mut stream = UnixStream::connect(&socket)
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

async fn get_json(path: &str) -> Result<serde_json::Value> {
    let socket = socket_path();
    let mut stream = UnixStream::connect(&socket)
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
        post_json("/GetKey", &body)
            .await
            .context("dstack GetKey request")?,
    )
    .context("parsing GetKey response")?;
    hex::decode(&resp.as_bytes).context("decoding hex key bytes from dstack")
}

/// Request a TDX attestation quote from the TEE.
pub async fn get_quote(report_data: &[u8]) -> Result<GetQuoteResponse> {
    let body = serde_json::json!({ "report_data": hex::encode(report_data) });
    serde_json::from_value(
        post_json("/GetQuote", &body)
            .await
            .context("dstack GetQuote request")?,
    )
    .context("parsing GetQuote response")
}

/// Retrieve TEE instance information.
pub async fn get_info() -> Result<InfoResponse> {
    serde_json::from_value(get_json("/Info").await.context("dstack Info request")?)
        .context("parsing Info response")
}

/// Check whether the dstack socket is reachable.
pub fn is_available() -> bool {
    std::path::Path::new(&socket_path()).exists()
}
