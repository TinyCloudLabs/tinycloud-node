//! TCP keepalive and `TCP_USER_TIMEOUT` on the PostgreSQL pool's sockets
//! (TC-1054).
//!
//! A pooled connection the network drops silently (no FIN, no RST: a
//! failover, a NAT or proxy that forgot the flow, a black hole) otherwise
//! hangs the statement on it until the kernel gives up retransmitting, about
//! 15 minutes at `tcp_retries2 = 15`, or forever if the node has nothing to
//! send. With keepalive the kernel probes an idle connection and drops it
//! after `idle + interval * retries`; `TCP_USER_TIMEOUT` drops it once sent
//! data has gone unacknowledged that long. The statement then fails with a
//! connection-class error, which the routes answer with 503.
//!
//! **Stopgap.** sqlx 0.8 sets neither option and exposes no socket or
//! connector hook (`sqlx-core` `net::socket::connect_tcp`), and `PgConnection`
//! does not expose its descriptor. So the pool's `after_connect` hook calls
//! [`KeepaliveConfigurator::on_connect`], which finds the new connection's
//! socket among the process's descriptors: a TCP socket whose peer is one of
//! the database host's addresses and that has no `SO_KEEPALIVE` yet. Every
//! other socket is left untouched. A scan may reach another pool's new
//! socket to the same database first; every pool of the node is built from
//! the one `[database]` configuration, so the settings are the same. Remove this (TC-1061) once sqlx can set
//! keepalive itself. Linux only; elsewhere it is a logged no-op.

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

/// The keepalive settings applied to each PostgreSQL connection socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpKeepalive {
    /// Idle time before the first probe (`TCP_KEEPIDLE`).
    pub idle: Duration,
    /// Time between unanswered probes (`TCP_KEEPINTVL`).
    pub interval: Duration,
    /// Unanswered probes before the connection is dropped (`TCP_KEEPCNT`).
    pub retries: u32,
    /// `TCP_USER_TIMEOUT`, or `None` for the kernel default.
    pub user_timeout: Option<Duration>,
}

/// The most descriptors one scan reads. The node holds a few hundred; the
/// scan stops (and says so) rather than walk an unbounded table.
pub const MAX_SCANNED_FDS: usize = 65_536;

/// Applies [`TcpKeepalive`] to the sockets of one pool's connections.
#[derive(Debug)]
pub struct KeepaliveConfigurator {
    settings: TcpKeepalive,
    host: String,
    port: u16,
}

/// Sockets configured, and connections opened, by every pool in the
/// process. A scan for one connection may configure another pool's new
/// socket to the same database, so only the process-wide totals compare.
static CONFIGURED: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

impl KeepaliveConfigurator {
    /// For a pool connecting over TCP to `host:port`, or `None` for a Unix
    /// socket path, which has no TCP options.
    pub fn new(settings: TcpKeepalive, host: &str, port: u16) -> Option<Arc<Self>> {
        if host.starts_with('/') {
            return None;
        }
        Some(Arc::new(Self {
            settings,
            // The `url` crate keeps the brackets of an IPv6 literal.
            host: host.trim_matches(&['[', ']'][..]).to_owned(),
            port,
        }))
    }

    pub fn settings(&self) -> TcpKeepalive {
        self.settings
    }

    /// Sockets configured in this process so far.
    pub fn configured() -> u64 {
        CONFIGURED.load(Ordering::Relaxed)
    }

    /// PostgreSQL connections opened in this process so far.
    pub fn connections() -> u64 {
        CONNECTIONS.load(Ordering::Relaxed)
    }

    /// Configure the socket of the connection the pool just opened. Never
    /// fails the connection: a socket it cannot configure is logged and
    /// keeps the kernel defaults.
    pub async fn on_connect(&self) -> usize {
        // Counted before the scan: this connection's socket already exists.
        let connections = CONNECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
        if !cfg!(target_os = "linux") {
            return 0;
        }
        let peers: HashSet<SocketAddr> = match tokio::net::lookup_host((
            self.host.as_str(),
            self.port,
        ))
        .await
        {
            Ok(addrs) => addrs.map(canonical).collect(),
            Err(error) => {
                tracing::warn!(%error, "PostgreSQL TCP keepalive not applied: resolving the database host failed");
                return 0;
            }
        };
        match configure_sockets(&peers, &self.settings) {
            Ok(scan) => {
                let configured = CONFIGURED.fetch_add(scan.configured as u64, Ordering::Relaxed)
                    + scan.configured as u64;
                if scan.truncated {
                    tracing::warn!(
                        max_fds = MAX_SCANNED_FDS,
                        "PostgreSQL TCP keepalive scan stopped at its descriptor limit"
                    );
                }
                // A scan that configures nothing is normal when connections
                // open concurrently (an earlier scan took this one), so
                // only a shortfall in the totals means a socket was missed:
                // its peer did not match the addresses resolved here.
                if configured < connections {
                    tracing::warn!(
                        sockets_configured = configured,
                        connections_opened = connections,
                        "PostgreSQL TCP keepalive missed a connection's socket"
                    );
                } else {
                    tracing::debug!(
                        sockets = scan.configured,
                        "PostgreSQL TCP keepalive scan after a new connection"
                    );
                }
                scan.configured
            }
            Err(error) => {
                tracing::warn!(%error, "PostgreSQL TCP keepalive not applied");
                0
            }
        }
    }
}

/// What one [`configure_sockets`] scan did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Sockets newly configured.
    pub configured: usize,
    /// Whether the scan stopped at [`MAX_SCANNED_FDS`].
    pub truncated: bool,
}

/// Normalize an IPv4-mapped IPv6 address, so a peer matches however the
/// resolver and the kernel spell it.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Apply `settings` to every TCP socket of this process whose peer is in
/// `peers` and whose `SO_KEEPALIVE` is still off. A socket already
/// configured has it on, so each is configured once; any socket that cannot
/// be inspected is skipped.
#[cfg(target_os = "linux")]
pub fn configure_sockets(
    peers: &HashSet<SocketAddr>,
    settings: &TcpKeepalive,
) -> std::io::Result<Scan> {
    use std::os::fd::{BorrowedFd, RawFd};

    let mut scan = Scan::default();
    for (index, entry) in std::fs::read_dir("/proc/self/fd")?.enumerate() {
        if index >= MAX_SCANNED_FDS {
            scan.truncated = true;
            break;
        }
        let Ok(entry) = entry else { continue };
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        else {
            continue;
        };
        // Cheap filter before any socket call: only sockets.
        let is_socket = std::fs::read_link(entry.path())
            .map(|target| target.to_string_lossy().starts_with("socket:"))
            .unwrap_or(false);
        if !is_socket {
            continue;
        }
        // SAFETY: the descriptor is only borrowed for the socket options
        // below and never closed. If it is closed concurrently the calls
        // fail with EBADF and the descriptor is skipped; if its number is
        // reused in between, the peer and SO_KEEPALIVE checks run against
        // the new socket, so only a matching socket is ever configured.
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let socket = socket2::SockRef::from(&fd);
        if !matches!(socket.r#type(), Ok(socket2::Type::STREAM)) {
            continue;
        }
        let Some(peer) = socket.peer_addr().ok().and_then(|addr| addr.as_socket()) else {
            continue;
        };
        if !peers.contains(&canonical(peer)) || socket.keepalive().unwrap_or(true) {
            continue;
        }
        match apply(&socket, settings) {
            Ok(()) => scan.configured += 1,
            Err(error) => {
                tracing::warn!(%error, "PostgreSQL TCP keepalive could not be set on a socket")
            }
        }
    }
    Ok(scan)
}

#[cfg(not(target_os = "linux"))]
pub fn configure_sockets(
    _peers: &HashSet<SocketAddr>,
    _settings: &TcpKeepalive,
) -> std::io::Result<Scan> {
    Ok(Scan::default())
}

#[cfg(target_os = "linux")]
fn apply(socket: &socket2::SockRef<'_>, settings: &TcpKeepalive) -> std::io::Result<()> {
    // `TCP_USER_TIMEOUT` first: SO_KEEPALIVE marks the socket configured.
    socket.set_tcp_user_timeout(settings.user_timeout)?;
    socket.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(settings.idle)
            .with_interval(settings.interval)
            .with_retries(settings.retries),
    )
}

/// Log, once per process, that keepalive is unavailable on this platform.
pub fn log_unsupported_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    if !cfg!(target_os = "linux") {
        ONCE.call_once(|| {
            tracing::warn!(
                "PostgreSQL TCP keepalive and TCP_USER_TIMEOUT are only set on Linux; this platform keeps the kernel defaults"
            )
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn settings() -> TcpKeepalive {
        TcpKeepalive {
            idle: Duration::from_secs(15),
            interval: Duration::from_secs(5),
            retries: 3,
            user_timeout: Some(Duration::from_millis(30_000)),
        }
    }

    /// Every option reads back from the socket with `getsockopt`, only the
    /// socket to the database peer is touched, and a second scan finds it
    /// already configured.
    #[test]
    fn configures_only_sockets_to_the_database_peer() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let to_database = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        let (accepted, _) = database.accept().unwrap();
        let to_other = TcpStream::connect(other.local_addr().unwrap()).unwrap();
        let peers = HashSet::from([database.local_addr().unwrap()]);

        let scan = configure_sockets(&peers, &settings()).unwrap();
        assert_eq!(
            scan,
            Scan {
                configured: 1,
                truncated: false
            }
        );

        let socket = socket2::SockRef::from(&to_database);
        assert!(socket.keepalive().unwrap(), "SO_KEEPALIVE");
        assert_eq!(
            socket.keepalive_time().unwrap(),
            Duration::from_secs(15),
            "TCP_KEEPIDLE"
        );
        assert_eq!(
            socket.keepalive_interval().unwrap(),
            Duration::from_secs(5),
            "TCP_KEEPINTVL"
        );
        assert_eq!(socket.keepalive_retries().unwrap(), 3, "TCP_KEEPCNT");
        assert_eq!(
            socket.tcp_user_timeout().unwrap(),
            Some(Duration::from_millis(30_000)),
            "TCP_USER_TIMEOUT"
        );
        // The listener's side of the same connection and an unrelated
        // connection keep the kernel defaults.
        for untouched in [&accepted, &to_other] {
            let socket = socket2::SockRef::from(untouched);
            assert!(!socket.keepalive().unwrap());
            assert_eq!(socket.tcp_user_timeout().unwrap(), None);
        }

        assert_eq!(
            configure_sockets(&peers, &settings()).unwrap().configured,
            0
        );
    }

    #[test]
    fn ipv4_mapped_peers_match() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5432".parse().unwrap();
        assert_eq!(canonical(mapped), "127.0.0.1:5432".parse().unwrap());
    }

    #[tokio::test]
    async fn on_connect_resolves_the_host_and_counts() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let _client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let configurator = KeepaliveConfigurator::new(settings(), "127.0.0.1", port).unwrap();
        assert_eq!(configurator.on_connect().await, 1);
        assert!(KeepaliveConfigurator::configured() >= 1);
        assert!(KeepaliveConfigurator::connections() >= 1);
        assert!(KeepaliveConfigurator::new(settings(), "/run/postgresql", 5432).is_none());
    }
}
