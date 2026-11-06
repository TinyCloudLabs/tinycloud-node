use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Explicit guest socket only: no environment/default endpoint fallback.
pub struct GuestClient {
    socket: PathBuf,
}

#[derive(Deserialize)]
pub(crate) struct QuoteResponse {
    pub quote: String,
    pub event_log: String,
    report_data: String,
}

impl GuestClient {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_owned(),
        }
    }

    fn post(&self, path: &str, body: &serde_json::Value) -> Result<Zeroizing<Vec<u8>>> {
        let mut stream =
            UnixStream::connect(&self.socket).context("connecting to explicit guest socket")?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let body = serde_json::to_vec(body)?;
        let headers = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(headers.as_bytes())?;
        stream.write_all(&body)?;
        stream.shutdown(Shutdown::Write)?;
        // Read headers without read-ahead into an unzeroized BufReader. Requiring
        // Content-Length lets us allocate the secret-bearing response exactly
        // once, so Vec growth cannot free earlier unwiped copies of root hex.
        let mut header = Zeroizing::new(Vec::with_capacity(8192));
        let mut byte = Zeroizing::new([0u8; 1]);
        while !header.ends_with(b"\r\n\r\n") {
            ensure!(header.len() < 8192, "guest HTTP headers too large");
            stream
                .read_exact(&mut *byte)
                .context("reading guest HTTP headers")?;
            header.push(byte[0]);
        }
        let text = std::str::from_utf8(&header).context("invalid guest HTTP headers")?;
        let mut length = None;
        for line in text.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').context("invalid guest HTTP header")?;
            ensure!(
                !name.eq_ignore_ascii_case("transfer-encoding"),
                "guest transfer encoding unsupported"
            );
            if name.eq_ignore_ascii_case("content-length") {
                ensure!(length.is_none(), "duplicate guest content length");
                length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("invalid guest content length"))?,
                );
            }
        }
        let length = length.context("guest response requires content length")?;
        ensure!(
            length <= MAX_RESPONSE_BYTES as usize - header.len(),
            "guest response too large"
        );
        let mut response = Zeroizing::new(Vec::with_capacity(header.len() + length));
        response.extend_from_slice(&header);
        response.resize(header.len() + length, 0);
        stream
            .read_exact(&mut response[header.len()..])
            .context("reading guest response")?;
        Ok(response)
    }

    pub(crate) fn get_root(&self) -> Result<Zeroizing<Vec<u8>>> {
        #[derive(Deserialize)]
        struct KeyResponse<'a> {
            #[serde(borrow)]
            key: &'a str,
        }
        let response = self.post(
            "/GetKey",
            &serde_json::json!({"path":"tinycloud/keys/primary"}),
        )?;
        // Borrow the hex string from the zeroizing HTTP buffer. No serde Value or
        // owned String can retain a second copy of the root's hex representation.
        let parsed: KeyResponse<'_> = serde_json::from_slice(response_body(&response)?)
            .map_err(|_| anyhow::anyhow!("invalid GetKey response"))?;
        ensure!(
            parsed.key.len().is_multiple_of(2),
            "invalid GetKey key encoding"
        );
        let mut root = Zeroizing::new(vec![0u8; parsed.key.len() / 2]);
        hex::decode_to_slice(parsed.key, &mut root)
            .map_err(|_| anyhow::anyhow!("invalid GetKey key encoding"))?;
        ensure!(root.len() >= 32, "GetKey root is shorter than 32 bytes");
        Ok(root)
    }

    pub(crate) fn get_quote(&self, binding: &[u8; 64]) -> Result<QuoteResponse> {
        let response = self.post(
            "/GetQuote",
            &serde_json::json!({"report_data":hex::encode(binding)}),
        )?;
        let parsed: QuoteResponse = serde_json::from_slice(response_body(&response)?)
            .map_err(|_| anyhow::anyhow!("invalid GetQuote response"))?;
        let echoed = hex::decode(
            parsed
                .report_data
                .strip_prefix("0x")
                .unwrap_or(&parsed.report_data),
        )
        .context("invalid GetQuote report_data hex")?;
        ensure!(echoed == binding, "GetQuote REPORTDATA echo mismatch");
        let quote = hex::decode(parsed.quote.strip_prefix("0x").unwrap_or(&parsed.quote))
            .context("invalid GetQuote quote hex")?;
        // Structural sanity only (TDX v4). DCAP verification is mandatory later.
        ensure!(quote.len() >= 636, "GetQuote quote truncated");
        ensure!(
            quote[..2] == 4u16.to_le_bytes() && quote[4..8] == 0x81u32.to_le_bytes(),
            "unsupported GetQuote quote layout"
        );
        let signature_length = u32::from_le_bytes(quote[632..636].try_into()?) as usize;
        ensure!(
            signature_length == quote.len() - 636,
            "GetQuote signature length mismatch"
        );
        ensure!(
            &quote[568..632] == binding,
            "GetQuote quote REPORTDATA mismatch"
        );
        Ok(parsed)
    }
}

pub(crate) fn response_body(raw: &[u8]) -> Result<&[u8]> {
    let end = raw
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .context("invalid guest HTTP headers")?;
    let headers = std::str::from_utf8(&raw[..end]).context("invalid guest HTTP headers")?;
    let mut lines = headers.split("\r\n");
    let mut status = lines
        .next()
        .context("missing guest HTTP status")?
        .split_whitespace();
    ensure!(
        matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")),
        "invalid guest HTTP version"
    );
    let code: u16 = status
        .next()
        .context("missing guest HTTP status")?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid guest HTTP status"))?;
    ensure!((200..300).contains(&code), "guest returned HTTP {code}");
    let body = &raw[end + 4..];
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').context("invalid guest HTTP header")?;
        ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "guest transfer encoding unsupported"
        );
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(content_length.is_none(), "duplicate guest content length");
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("invalid guest content length"))?,
            );
        }
    }
    if let Some(length) = content_length {
        ensure!(length == body.len(), "guest response length mismatch");
    }
    Ok(body)
}
