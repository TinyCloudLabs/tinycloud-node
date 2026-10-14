//! TinyCloud patch (TC-1054); not in upstream sqlx-core 0.8.6. See
//! `PATCH.md` at the crate root.
//!
//! TCP keepalive and `TCP_USER_TIMEOUT` on the sockets of new TCP
//! connections. Without them a connection the network drops silently (no
//! FIN, no RST) hangs a statement until the kernel gives up retransmitting
//! (about 15 min), or forever if nothing is being sent.
//!
//! The settings are process-global, registered per connect target (host and
//! port as passed to [`connect_tcp`](super::connect_tcp)), so no connect
//! option or driver API changes: the application registers a target before
//! its pool connects to it. A target with no registration is unaffected.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

/// The options set on each new socket to a registered target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpKeepalive {
    /// Idle time before the first probe (`TCP_KEEPIDLE`).
    pub idle: Duration,
    /// Time between unanswered probes (`TCP_KEEPINTVL`; Linux only).
    pub interval: Duration,
    /// Unanswered probes before the connection is dropped (`TCP_KEEPCNT`;
    /// Linux only).
    pub retries: u32,
    /// `TCP_USER_TIMEOUT` (Linux only), or `None` for the kernel default.
    pub user_timeout: Option<Duration>,
}

fn targets() -> &'static RwLock<HashMap<(String, u16), TcpKeepalive>> {
    static TARGETS: OnceLock<RwLock<HashMap<(String, u16), TcpKeepalive>>> = OnceLock::new();
    TARGETS.get_or_init(Default::default)
}

static CONFIGURED: AtomicU64 = AtomicU64::new(0);

fn key(host: &str, port: u16) -> (String, u16) {
    // As `connect_tcp` does: IPv6 literals may keep their URL brackets.
    (host.trim_matches(&['[', ']'][..]).to_owned(), port)
}

/// Set `keepalive` on every later TCP connection to `host:port`, or stop
/// with `None`. The last registration for a target wins.
pub fn set_tcp_keepalive(host: &str, port: u16, keepalive: Option<TcpKeepalive>) {
    let mut targets = targets().write().unwrap_or_else(|e| e.into_inner());
    match keepalive {
        Some(keepalive) => targets.insert(key(host, port), keepalive),
        None => targets.remove(&key(host, port)),
    };
}

/// The registration for `host:port`, if any.
pub fn tcp_keepalive(host: &str, port: u16) -> Option<TcpKeepalive> {
    targets()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key(host, port))
        .copied()
}

/// Sockets configured in this process so far.
pub fn sockets_configured() -> u64 {
    CONFIGURED.load(Ordering::Relaxed)
}

/// Configure a newly connected socket to `host:port` if the target is
/// registered. An error fails the connect: a connection is never handed
/// out without the options it was registered for.
pub(crate) fn apply(socket: socket2::SockRef<'_>, host: &str, port: u16) -> io::Result<()> {
    let Some(keepalive) = tcp_keepalive(host, port) else {
        return Ok(());
    };
    configure(&socket, &keepalive).map_err(|error| {
        tracing::warn!(%error, "setting TCP keepalive on a new connection failed; failing the connect");
        error
    })?;
    CONFIGURED.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure(socket: &socket2::SockRef<'_>, keepalive: &TcpKeepalive) -> io::Result<()> {
    socket.set_tcp_user_timeout(keepalive.user_timeout)?;
    socket.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(keepalive.idle)
            .with_interval(keepalive.interval)
            .with_retries(keepalive.retries),
    )
}

#[cfg(not(target_os = "linux"))]
fn configure(socket: &socket2::SockRef<'_>, keepalive: &TcpKeepalive) -> io::Result<()> {
    socket.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(keepalive.idle))
}
