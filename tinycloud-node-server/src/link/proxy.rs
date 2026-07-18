//! LAN TLS terminator: proxies raw TCP bytes from a LAN TLS listener to the
//! loopback public API port.
//!
//! `serve` starts this listener only when link is enabled (there is a valid
//! `state.json` and a matching `tls/{key,cert}.pem`). It participates in the
//! same graceful shutdown as the Rocket app via a `CancellationToken` passed
//! in by the caller.
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

/// Build a rustls `ServerConfig` from PEM key + cert-chain material.
pub fn build_rustls_config(key_pem: &str, cert_chain_pem: &str) -> Result<Arc<ServerConfig>> {
    let mut certs_reader = std::io::Cursor::new(cert_chain_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut certs_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("failed to parse cert chain PEM")?;
    if certs.is_empty() {
        anyhow::bail!("cert chain PEM was empty");
    }

    let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse private key PEM")?
        .context("no private key found in PEM")?;

    // ring backend is enabled via the crate features.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to select rustls protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build rustls server config")?;

    Ok(Arc::new(config))
}

/// Run the LAN TLS listener until `shutdown` is triggered.
///
/// `bind_addr` — the LAN bind address (e.g. `0.0.0.0:8443`).
/// `upstream_addr` — the loopback public API socket, e.g. `127.0.0.1:8081`.
pub async fn run(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind link listener at {bind_addr}"))?;
    tracing::info!(%bind_addr, %upstream_addr, "link LAN TLS listener started");

    let acceptor = TlsAcceptor::from(server_config);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("link LAN TLS listener shutting down");
                    break;
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((tcp, remote)) => {
                        let acceptor = acceptor.clone();
                        let mut client_shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            let handle = handle_connection(tcp, acceptor, upstream_addr, &mut client_shutdown);
                            if let Err(err) = handle.await {
                                tracing::warn!(%remote, %err, "link connection error");
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(%err, "link listener accept error");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    upstream_addr: SocketAddr,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let tls = acceptor.accept(tcp).await.context("TLS handshake failed")?;
    let mut upstream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("failed to connect to loopback API at {upstream_addr}"))?;

    let (mut client_read, mut client_write) = tokio::io::split(tls);
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = async { copy_stream(&mut client_read, &mut upstream_write).await };
    let upstream_to_client = async { copy_stream(&mut upstream_read, &mut client_write).await };

    tokio::select! {
        _ = shutdown.changed() => Ok(()),
        result = client_to_upstream => result,
        result = upstream_to_client => result,
    }
}

async fn copy_stream<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .context("read from stream failed")?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer
            .write_all(&buf[..n])
            .await
            .context("write to stream failed")?;
    }
}
