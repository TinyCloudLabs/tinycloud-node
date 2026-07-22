//! LAN TLS terminator: proxies raw TCP bytes from a LAN TLS listener to the
//! loopback public API port.
//!
//! `serve` starts this listener only when link is enabled (there is a valid
//! `state.json` and a matching `tls/{key,cert}.pem`). It participates in the
//! same graceful shutdown as the Rocket app via a `watch::Receiver<bool>`
//! passed in by the caller.
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::{net::SocketAddr, sync::Arc, sync::RwLock};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

/// Holds the LAN TLS listener's active certificate/key and implements
/// [`ResolvesServerCert`] so a renewed cert can be swapped in without
/// restarting the listener or dropping in-flight connections — see
/// `docs/specs/node-control-plane-v1.md` §3.9.
#[derive(Debug)]
pub struct LinkCertResolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl LinkCertResolver {
    fn new(certified_key: CertifiedKey) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(Arc::new(certified_key)),
        })
    }

    /// Swap in a freshly issued cert/key pair. Only handshakes that start
    /// after this call see the new cert; already-established connections are
    /// unaffected.
    pub fn update(&self, key_pem: &str, cert_chain_pem: &str) -> Result<()> {
        let certified_key = parse_certified_key(key_pem, cert_chain_pem)?;
        *self
            .current
            .write()
            .expect("link cert resolver lock poisoned") = Arc::new(certified_key);
        Ok(())
    }
}

impl ResolvesServerCert for LinkCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.current
                .read()
                .expect("link cert resolver lock poisoned")
                .clone(),
        )
    }
}

fn parse_certified_key(key_pem: &str, cert_chain_pem: &str) -> Result<CertifiedKey> {
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
    CertifiedKey::from_der(certs, key, &provider)
        .map_err(|err| anyhow::anyhow!("failed to build certified key: {err}"))
}

/// Build a rustls `ServerConfig` backed by a [`LinkCertResolver`] from PEM
/// key + cert-chain material. The returned resolver lets the caller refresh
/// the served cert in place after a renew.
pub fn build_rustls_config(
    key_pem: &str,
    cert_chain_pem: &str,
) -> Result<(Arc<ServerConfig>, Arc<LinkCertResolver>)> {
    let certified_key = parse_certified_key(key_pem, cert_chain_pem)?;
    let resolver = LinkCertResolver::new(certified_key);

    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to select rustls protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());

    Ok((Arc::new(config), resolver))
}

/// Synchronously bind the LAN TLS listener socket.
///
/// Binding is split out from [`run`] so callers can detect a failure to bind
/// (bad address, port already in use, permission denied, ...) immediately and
/// synchronously, rather than discovering it only after spawning an async
/// task. This lets `serve` report the LAN listener's real health instead of
/// inferring it from OS process state.
pub fn bind(bind_addr: SocketAddr) -> std::io::Result<TcpListener> {
    let std_listener = std::net::TcpListener::bind(bind_addr)?;
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

/// Run the LAN TLS listener until `shutdown` is triggered.
///
/// `listener` — an already-bound LAN listener (see [`bind`]).
/// `upstream_addr` — the loopback public API socket, e.g. `127.0.0.1:8081`.
pub async fn run(
    listener: TcpListener,
    upstream_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let bind_addr = listener
        .local_addr()
        .context("failed to read bind address")?;
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
    let mut tls = acceptor.accept(tcp).await.context("TLS handshake failed")?;
    let mut upstream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("failed to connect to loopback API at {upstream_addr}"))?;

    tokio::select! {
        _ = shutdown.changed() => Ok(()),
        result = tokio::io::copy_bidirectional(&mut tls, &mut upstream) => {
            result.map(|_| ()).context("proxy copy failed")
        }
    }
}
