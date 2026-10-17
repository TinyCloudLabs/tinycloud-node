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
        // Production logs ship off-host, so they get the status and size only;
        // the agent's body is logged at debug, which is off by default.
        tracing::warn!(
            status,
            body_len = body.len(),
            "dstack guest agent returned an error"
        );
        tracing::debug!(
            status,
            body = %String::from_utf8_lossy(&body[..body.len().min(512)]),
            "dstack guest agent error body"
        );
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

    let mut expected = report_data.to_vec();
    expected.resize(MAX_REPORT_DATA_BYTES, 0);
    // The agent's echo is a cheap sanity check; the binding that matters is
    // the REPORTDATA inside the quote itself.
    let echoed = hex::decode(response.report_data.trim_start_matches("0x"))
        .context("decoding GetQuote report_data")?;
    anyhow::ensure!(
        echoed == expected,
        "GetQuote report_data does not match the requested report_data"
    );
    let quote =
        hex::decode(response.quote.trim_start_matches("0x")).context("decoding GetQuote quote")?;
    anyhow::ensure!(
        quote_report_data(&quote)? == expected.as_slice(),
        "quote REPORTDATA does not match the requested report_data"
    );
    Ok(response)
}

// TDX quote layout, Intel TDX DCAP Quoting Library API, Appendix A
// ("Version 4 Quote Format"): a 48-byte Quote Header (version u16 LE at 0,
// TEE type u32 LE at 4, 0x81 for TDX), the 584-byte TD Quote Body, then a
// u32 LE signature-data length and that many bytes. REPORTDATA is the last
// 64 bytes of the body (body offset 520). dstack emits version 4 quotes.
const QUOTE_HEADER_LEN: usize = 48;
const TD_QUOTE_BODY_LEN: usize = 584;
const TD_REPORT_DATA_OFFSET: usize = QUOTE_HEADER_LEN + 520;
const TEE_TYPE_TDX: u32 = 0x81;

/// The REPORTDATA of a structurally complete TDX v4 quote. This checks
/// layout only; it does not verify the quote's signature or certificates.
fn quote_report_data(quote: &[u8]) -> Result<&[u8]> {
    let sig_len_at = QUOTE_HEADER_LEN + TD_QUOTE_BODY_LEN;
    anyhow::ensure!(
        quote.len() >= sig_len_at + 4,
        "quote is truncated ({} bytes)",
        quote.len()
    );
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);
    anyhow::ensure!(
        version == 4 && tee_type == TEE_TYPE_TDX,
        "unsupported quote: version {version}, TEE type {tee_type:#x}"
    );
    let sig_len = u32::from_le_bytes([
        quote[sig_len_at],
        quote[sig_len_at + 1],
        quote[sig_len_at + 2],
        quote[sig_len_at + 3],
    ]) as usize;
    anyhow::ensure!(
        quote.len() - (sig_len_at + 4) >= sig_len,
        "quote signature data is truncated"
    );
    Ok(&quote[TD_REPORT_DATA_OFFSET..TD_REPORT_DATA_OFFSET + MAX_REPORT_DATA_BYTES])
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

/// The `app-compose.json` this CVM was launched with: `tcb_info.app_compose`
/// from the guest agent's `/Info` (`tcb_info` is a JSON string or object).
/// The caller checks it against `compose_hash`.
pub async fn get_app_compose() -> Result<String> {
    let info = get_json(&socket_path(), "/Info")
        .await
        .context("dstack Info request")?;
    app_compose_from_info(&info)
}

fn app_compose_from_info(info: &serde_json::Value) -> Result<String> {
    let tcb = match info.get("tcb_info") {
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str(s).context("dstack Info tcb_info is not JSON")?
        }
        Some(other) => other.clone(),
        None => return Err(anyhow!("dstack Info has no tcb_info")),
    };
    tcb.get("app_compose")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("dstack Info tcb_info has no app_compose"))
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

    /// A structurally valid TDX v4 quote: 48-byte header (version 4, ECDSA-256
    /// key type 2, TEE type 0x81), 584-byte TD report body carrying
    /// `report_data` at body offset 520, then a length-prefixed signature
    /// section. The signature bytes are filler; nothing here verifies them.
    pub(crate) fn tdx_quote(report_data: &[u8]) -> Vec<u8> {
        let mut quote = vec![0u8; 48 + 584];
        quote[0..2].copy_from_slice(&4u16.to_le_bytes());
        quote[2..4].copy_from_slice(&2u16.to_le_bytes());
        quote[4..8].copy_from_slice(&0x81u32.to_le_bytes());
        quote[48 + 520..48 + 584].copy_from_slice(report_data);
        quote.extend_from_slice(&64u32.to_le_bytes());
        quote.extend_from_slice(&[0x5a; 64]);
        quote
    }

    /// Answer one GetQuote like dstack: a quote over the requested bytes
    /// zero-padded to 64, echoed back as `report_data`.
    pub(crate) fn serve_quote() -> Agent {
        serve_quote_with(|padded| hex::encode(tdx_quote(padded)))
    }

    /// Like [`serve_quote`], echoing the right `report_data` but answering
    /// with the hex quote `make` builds from the padded request.
    pub(crate) fn serve_quote_with(make: impl FnOnce(&[u8]) -> String + Send + 'static) -> Agent {
        serve(|request| {
            let mut padded = requested_report_data(request);
            padded.resize(super::MAX_REPORT_DATA_BYTES, 0);
            let body = serde_json::json!({
                "quote": make(&padded),
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

    #[test]
    fn app_compose_comes_from_tcb_info_as_a_string_or_an_object() {
        let tcb =
            serde_json::json!({"mrtd": "00", "app_compose": "{\"runner\":\"docker-compose\"}"});
        let as_string = serde_json::json!({"app_id": "a", "tcb_info": tcb.to_string()});
        let as_object = serde_json::json!({"app_id": "a", "tcb_info": tcb});
        for info in [as_string, as_object] {
            assert_eq!(
                app_compose_from_info(&info).unwrap(),
                "{\"runner\":\"docker-compose\"}"
            );
        }
        assert!(app_compose_from_info(&serde_json::json!({"app_id": "a"})).is_err());
        assert!(app_compose_from_info(&serde_json::json!({"tcb_info": "{}"})).is_err());
    }

    #[tokio::test]
    async fn get_quote_sends_exactly_64_bytes_of_report_data() {
        let agent = stub::serve_quote();
        let quote = get_quote(&agent.socket, &[0x42; MAX_REPORT_DATA_BYTES])
            .await
            .unwrap();
        assert_eq!(quote.quote, hex::encode(stub::tdx_quote(&[0x42; 64])));
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
        let quote = hex::encode(stub::tdx_quote(&[0x24; 64]));
        let agent = stub::serve_once(
            "200 OK",
            &format!(r#"{{"quote":"{quote}","event_log":"[]","report_data":"{other}"}}"#),
        );
        let err = get_quote(&agent.socket, &[0x42; 32]).await.unwrap_err();
        assert!(format!("{err:#}").contains("report_data"), "{err:#}");
        agent.request.await.unwrap();
    }

    #[tokio::test]
    async fn get_quote_rejects_a_quote_without_report_data() {
        let quote = hex::encode(stub::tdx_quote(&[0x42; 64]));
        let agent = stub::serve_once(
            "200 OK",
            &format!(r#"{{"quote":"{quote}","event_log":"[]"}}"#),
        );
        let err = get_quote(&agent.socket, &[0x42; 32]).await.unwrap_err();
        assert!(format!("{err:#}").contains("report_data"), "{err:#}");
        agent.request.await.unwrap();
    }

    /// get_quote over 32 bytes of 0x42 against an agent that echoes the right
    /// report_data but answers with the quote `make` builds.
    async fn quote_failure(make: impl FnOnce(&[u8]) -> String + Send + 'static) -> String {
        let agent = stub::serve_quote_with(make);
        let err = get_quote(&agent.socket, &[0x42; 32]).await.unwrap_err();
        agent.request.await.unwrap();
        format!("{err:#}")
    }

    #[tokio::test]
    async fn get_quote_rejects_a_quote_whose_reportdata_differs_from_a_matching_echo() {
        let message = quote_failure(|_| hex::encode(stub::tdx_quote(&[0x24; 64]))).await;
        assert!(message.contains("REPORTDATA"), "{message}");
    }

    #[tokio::test]
    async fn get_quote_rejects_truncated_and_malformed_quotes() {
        let makers: [fn(&[u8]) -> String; 5] = [
            // Cut inside REPORTDATA.
            |padded: &[u8]| hex::encode(&stub::tdx_quote(padded)[..600]),
            // Body complete, signature section missing.
            |padded: &[u8]| hex::encode(&stub::tdx_quote(padded)[..632]),
            // Signature length runs past the end.
            |padded: &[u8]| {
                let mut quote = stub::tdx_quote(padded);
                quote.truncate(quote.len() - 1);
                hex::encode(quote)
            },
            // An SGX (TEE type 0) quote.
            |padded: &[u8]| {
                let mut quote = stub::tdx_quote(padded);
                quote[4] = 0;
                hex::encode(quote)
            },
            // Not hex.
            |_: &[u8]| "zz".to_owned(),
        ];
        for make in makers {
            let message = quote_failure(make).await;
            assert!(message.contains("quote"), "{message}");
        }
    }
}
