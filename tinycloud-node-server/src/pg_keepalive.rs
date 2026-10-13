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
//! connection-class error.
//!
//! **Stopgap (TC-1061).** sqlx 0.8 sets neither option, exposes no socket or
//! connector hook (`sqlx-core` `net::socket::connect_tcp`), and does not
//! expose a connection's descriptor. So the pool's `after_connect` hook calls
//! [`KeepaliveConfigurator::on_connect`], which configures every TCP socket
//! of the process whose peer port is the database port and whose
//! `SO_KEEPALIVE` is still off. Remove this once sqlx can set keepalive
//! itself.
//!
//! - **The new connection is never admitted unprotected.** Its socket is
//!   open and connected to the database port, so the scan reaches it; if
//!   any such socket cannot be configured, or the scan cannot complete,
//!   `on_connect` fails and sqlx closes the connection and connects again.
//!   Matching does not depend on DNS: a rotating or failing lookup cannot
//!   leave the connected address out. Lookups only label a configured
//!   socket whose address the host did not resolve to, which is logged.
//! - **Only database sockets are touched.** Nothing else in the node
//!   connects to the database port: webhook deliveries must be HTTPS on port
//!   443, and every other outbound endpoint (S3, billing, link, control) is
//!   operator-configured. Every node pool shares the one `[database]`
//!   configuration, so a scan that reaches another pool's new socket
//!   applies the same settings.
//! - **Every check and change acts on one socket.** Each descriptor is first
//!   duplicated (`F_DUPFD_CLOEXEC`); the type, peer and `SO_KEEPALIVE` checks
//!   and the option changes all go through that owned duplicate. If the
//!   original number is closed and reused meanwhile, the duplicate still
//!   refers to the socket that was checked.
//!
//! Linux only; elsewhere it is a logged no-op.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
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

/// The most descriptors one scan reads. The node holds a few hundred; past
/// this the scan fails rather than walk an unbounded table.
pub const MAX_SCANNED_FDS: usize = 65_536;

/// How long `on_connect` waits for the (diagnostic) host lookup.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Applies [`TcpKeepalive`] to the sockets of one pool's connections.
#[derive(Debug)]
pub struct KeepaliveConfigurator {
    settings: TcpKeepalive,
    host: String,
    port: u16,
    /// Every address the host has resolved to so far.
    resolved: Mutex<HashSet<IpAddr>>,
}

/// Sockets configured, connections admitted, and connections refused
/// because a socket could not be configured, by every pool in the process.
/// After a deploy, `sockets_configured >= connections_opened` and
/// `keepalive_missed == 0` in the startup log show every admitted
/// connection is protected.
static CONFIGURED: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static MISSED: AtomicU64 = AtomicU64::new(0);

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
            resolved: Mutex::new(HashSet::new()),
        }))
    }

    pub fn settings(&self) -> TcpKeepalive {
        self.settings
    }

    /// Sockets configured in this process so far.
    pub fn configured() -> u64 {
        CONFIGURED.load(Ordering::Relaxed)
    }

    /// PostgreSQL connections admitted to a pool in this process so far.
    pub fn connections() -> u64 {
        CONNECTIONS.load(Ordering::Relaxed)
    }

    /// Connections refused because a socket could not be configured.
    pub fn missed() -> u64 {
        MISSED.load(Ordering::Relaxed)
    }

    /// Configure the socket of the connection the pool just opened, with
    /// every other unconfigured socket to the database port. An error means
    /// a socket to the database port may be left unprotected; the caller
    /// must not admit the connection.
    pub async fn on_connect(&self) -> std::io::Result<usize> {
        if !cfg!(target_os = "linux") {
            CONNECTIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(0);
        }
        match self.scan().await {
            Ok(configured) => {
                CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                Ok(configured)
            }
            Err(error) => {
                MISSED.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    %error,
                    "PostgreSQL TCP keepalive missed a connection's socket; refusing the connection"
                );
                Err(error)
            }
        }
    }

    async fn scan(&self) -> std::io::Result<usize> {
        let (port, settings) = (self.port, self.settings);
        // /proc and socket syscalls, off the async workers.
        let scan = tokio::task::spawn_blocking(move || configure_sockets(port, &settings))
            .await
            .map_err(std::io::Error::other)??;
        CONFIGURED.fetch_add(scan.configured() as u64, Ordering::Relaxed);
        // Addresses only label the result, so the host is looked up only
        // when a configured socket's address has not been seen before.
        let unseen: Vec<IpAddr> = {
            let resolved = self.resolved.lock().unwrap_or_else(|e| e.into_inner());
            scan.peers
                .iter()
                .filter(|ip| !resolved.contains(ip))
                .copied()
                .collect()
        };
        if !unseen.is_empty() {
            let lookup = tokio::time::timeout(
                LOOKUP_TIMEOUT,
                tokio::net::lookup_host((self.host.as_str(), self.port)),
            )
            .await;
            let mut resolved = self.resolved.lock().unwrap_or_else(|e| e.into_inner());
            if let Ok(Ok(addrs)) = lookup {
                resolved.extend(addrs.map(|addr| addr.ip().to_canonical()));
            }
            let unresolved = unseen.iter().filter(|ip| !resolved.contains(ip)).count();
            if unresolved > 0 {
                tracing::warn!(
                    sockets = unresolved,
                    "PostgreSQL TCP keepalive set on a socket to the database port at an address the database host did not resolve to"
                );
                // Configured either way; remember it so it is reported once.
                resolved.extend(unseen);
            }
        }
        // Zero is normal when connections open concurrently: an earlier
        // scan already configured this one.
        tracing::debug!(
            sockets = scan.configured(),
            "PostgreSQL TCP keepalive scan after a new connection"
        );
        Ok(scan.configured())
    }
}

/// What one [`configure_sockets`] scan did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// The peer address of each socket newly configured.
    pub peers: Vec<IpAddr>,
}

impl Scan {
    /// Sockets newly configured.
    pub fn configured(&self) -> usize {
        self.peers.len()
    }
}

/// Apply `settings` to every TCP socket of this process whose peer port is
/// `port` and whose `SO_KEEPALIVE` is still off; see the [module docs](self).
/// Fails if the scan cannot complete or any such socket cannot be
/// configured.
#[cfg(target_os = "linux")]
pub fn configure_sockets(port: u16, settings: &TcpKeepalive) -> std::io::Result<Scan> {
    configure_sockets_with(port, settings, |_| {})
}

/// [`configure_sockets`], calling `after_duplicate` with each candidate's
/// original descriptor number once it has been duplicated. Tests use it to
/// close and reuse that number at the worst moment.
#[cfg(target_os = "linux")]
pub fn configure_sockets_with(
    port: u16,
    settings: &TcpKeepalive,
    mut after_duplicate: impl FnMut(std::os::fd::RawFd),
) -> std::io::Result<Scan> {
    use std::os::fd::RawFd;

    let mut scan = Scan::default();
    let mut failure = None;
    for (index, entry) in std::fs::read_dir("/proc/self/fd")?.enumerate() {
        if index >= MAX_SCANNED_FDS {
            return Err(std::io::Error::other(format!(
                "more than {MAX_SCANNED_FDS} descriptors to scan"
            )));
        }
        let Ok(entry) = entry else { continue };
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        else {
            continue;
        };
        // A cheap filter before any socket call; the duplicate below is
        // what the checks trust.
        let is_socket = std::fs::read_link(entry.path())
            .map(|target| target.to_string_lossy().starts_with("socket:"))
            .unwrap_or(false);
        if !is_socket {
            continue;
        }
        let Some(socket) = duplicate(fd) else {
            // Closed since it was listed.
            continue;
        };
        after_duplicate(fd);
        match configure_if_database_socket(&socket, port, settings) {
            Ok(Some(peer)) => scan.peers.push(peer),
            Ok(None) => {}
            Err(error) => failure = Some(error),
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(scan),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn configure_sockets(_port: u16, _settings: &TcpKeepalive) -> std::io::Result<Scan> {
    Ok(Scan::default())
}

/// An owned duplicate of `fd`, or `None` if it is no longer open.
#[cfg(target_os = "linux")]
fn duplicate(fd: std::os::fd::RawFd) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // SAFETY: fcntl with F_DUPFD_CLOEXEC has no memory-safety
    // preconditions; on an fd that is not open it fails with EBADF.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    // SAFETY: on success the new descriptor is ours alone to own and close.
    (duplicate >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) })
}

/// Configure `socket` if it is an unconfigured TCP socket to `port`:
/// `Some(its peer address)` when configured, `None` when it is not a
/// candidate, an error when a candidate could not be configured.
#[cfg(target_os = "linux")]
fn configure_if_database_socket(
    socket: &std::os::fd::OwnedFd,
    port: u16,
    settings: &TcpKeepalive,
) -> std::io::Result<Option<IpAddr>> {
    use std::os::fd::AsRawFd;

    let socket = socket2::SockRef::from(socket);
    if !matches!(socket.r#type(), Ok(socket2::Type::STREAM)) {
        return Ok(None);
    }
    let Some(peer) = socket.peer_addr().ok().and_then(|addr| addr.as_socket()) else {
        // Not an inet socket, or not connected.
        return Ok(None);
    };
    if peer.port() != port || socket.keepalive()? {
        return Ok(None);
    }
    // SO_KEEPALIVE marks the socket configured, so it goes on last: a
    // socket whose configuration failed part-way is still a candidate.
    socket.set_tcp_user_timeout(settings.user_timeout)?;
    let seconds = |duration: Duration| {
        libc::c_int::try_from(duration.as_secs().max(1)).unwrap_or(libc::c_int::MAX)
    };
    set_tcp_option(
        socket.as_raw_fd(),
        libc::TCP_KEEPIDLE,
        seconds(settings.idle),
    )?;
    set_tcp_option(
        socket.as_raw_fd(),
        libc::TCP_KEEPINTVL,
        seconds(settings.interval),
    )?;
    set_tcp_option(
        socket.as_raw_fd(),
        libc::TCP_KEEPCNT,
        libc::c_int::try_from(settings.retries).unwrap_or(libc::c_int::MAX),
    )?;
    socket.set_keepalive(true)?;
    Ok(Some(canonical(peer).ip()))
}

#[cfg(target_os = "linux")]
fn set_tcp_option(
    fd: std::os::fd::RawFd,
    option: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    // SAFETY: `value` outlives the call and its size is passed; `fd` is a
    // descriptor the caller owns (the duplicate).
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Normalize an IPv4-mapped IPv6 address, so a peer matches however the
/// resolver and the kernel spell it.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
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
    use std::os::fd::AsRawFd;

    fn settings() -> TcpKeepalive {
        TcpKeepalive {
            idle: Duration::from_secs(15),
            interval: Duration::from_secs(5),
            retries: 3,
            user_timeout: Some(Duration::from_millis(30_000)),
        }
    }

    fn assert_configured(socket: &impl std::os::fd::AsFd) {
        let socket = socket2::SockRef::from(socket);
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
    }

    fn assert_untouched(socket: &impl std::os::fd::AsFd) {
        let socket = socket2::SockRef::from(socket);
        assert!(!socket.keepalive().unwrap());
        assert_eq!(socket.tcp_user_timeout().unwrap(), None);
    }

    /// Every option reads back from the socket with `getsockopt`, only the
    /// socket to the database port is touched, and a second scan finds it
    /// already configured.
    #[test]
    fn configures_only_sockets_to_the_database_port() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let to_database = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        let (accepted, _) = database.accept().unwrap();
        let to_other = TcpStream::connect(other.local_addr().unwrap()).unwrap();
        let scan = configure_sockets(port, &settings()).unwrap();
        assert_eq!(scan.peers, vec![database.local_addr().unwrap().ip()]);
        assert_configured(&to_database);
        // The listener's side of the same connection and an unrelated
        // connection keep the kernel defaults.
        assert_untouched(&accepted);
        assert_untouched(&to_other);
        assert_eq!(
            configure_sockets(port, &settings()).unwrap().configured(),
            0
        );
    }

    /// Astra's race: the scanned descriptor number is closed and reused by
    /// an unrelated socket between the checks and the option changes. The
    /// checks and changes all act on the duplicate, so the socket that was
    /// checked is configured and the one now holding the number is not.
    #[test]
    fn a_reused_descriptor_number_never_redirects_the_change() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let to_database = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        // A second handle on the database socket, to inspect it after its
        // original number is reused.
        let witness = to_database.try_clone().unwrap();
        let unrelated_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unrelated = TcpStream::connect(unrelated_listener.local_addr().unwrap()).unwrap();
        let target = to_database.as_raw_fd();

        let mut reused = false;
        let scan = configure_sockets_with(port, &settings(), |fd| {
            if fd == target && !reused {
                // SAFETY: atomically replaces descriptor `target` (the
                // original database socket number) with the unrelated socket;
                // `to_database` is forgotten below and never used again.
                assert!(unsafe { libc::dup2(unrelated.as_raw_fd(), target) } >= 0);
                reused = true;
            }
        })
        .unwrap();
        assert!(reused, "the scan reached the database socket");
        assert_eq!(scan.configured(), 1);
        assert_configured(&witness);
        assert_untouched(&unrelated);
        // `target` now refers to the unrelated socket; closing it is the
        // unrelated socket's business, not `to_database`'s.
        std::mem::forget(to_database);
        // SAFETY: `target` is a descriptor this test owns (the dup2 copy).
        unsafe { libc::close(target) };
    }

    /// Rotating DNS: the connection went to an address the host's lookup
    /// does not return (or the lookup fails). The socket is configured all
    /// the same; the address only produces a warning.
    #[tokio::test]
    async fn sockets_at_unresolved_addresses_are_still_configured() {
        // 127.0.0.2 is on loopback but is not what "127.0.0.1" resolves to.
        let database = TcpListener::bind("127.0.0.2:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let client = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        let configurator = KeepaliveConfigurator::new(settings(), "127.0.0.1", port).unwrap();
        assert_eq!(configurator.on_connect().await.unwrap(), 1);
        assert_configured(&client);

        let failing = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = failing.local_addr().unwrap().port();
        let client = TcpStream::connect(failing.local_addr().unwrap()).unwrap();
        let unresolvable = KeepaliveConfigurator::new(settings(), "tc1054.invalid", port).unwrap();
        assert_eq!(
            unresolvable.on_connect().await.unwrap(),
            1,
            "lookup failure"
        );
        assert_configured(&client);
        assert!(KeepaliveConfigurator::new(settings(), "/run/postgresql", 5432).is_none());
    }

    /// A socket to the database port that cannot be configured fails the
    /// scan, so the pool does not admit its connection.
    #[tokio::test]
    async fn an_unconfigurable_socket_fails_the_connection() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let client = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        // Linux caps TCP_KEEPCNT at 127.
        let invalid = TcpKeepalive {
            retries: 1000,
            ..settings()
        };
        let configurator = KeepaliveConfigurator::new(invalid, "127.0.0.1", port).unwrap();
        let missed = KeepaliveConfigurator::missed();
        assert!(configurator.on_connect().await.is_err());
        assert!(KeepaliveConfigurator::missed() > missed);
        assert!(!socket2::SockRef::from(&client).keepalive().unwrap());
    }

    #[test]
    fn ipv4_mapped_peers_match() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5432".parse().unwrap();
        assert_eq!(canonical(mapped), "127.0.0.1:5432".parse().unwrap());
    }
}
