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
//! [`KeepaliveConfigurator::on_connect`], which finds the process's
//! **outbound client sockets to the database** and configures those whose
//! `SO_KEEPALIVE` is still off. Remove this once sqlx can set keepalive
//! itself.
//!
//! - **Identity.** A socket is a database client socket only if it is a
//!   connected TCP stream whose *local* port is in the kernel's ephemeral
//!   range and is not a port this process listens on (so no accepted, i.e.
//!   incoming, socket qualifies), whose *remote* port is the database port,
//!   and whose remote address is one the database host resolved to (the
//!   addresses seen so far, cached). An outbound socket to the database port
//!   at any other address is never touched.
//! - **Fail closed.** An outbound socket to the database port at an address
//!   the host has not resolved to triggers one fresh lookup; if it is still
//!   unknown, the connection is refused rather than guessed about. Any error
//!   other than a descriptor that closed, or a socket that is not connected,
//!   fails the scan (exhausted descriptors included). And a connection is
//!   admitted only by claiming one configured database socket from the
//!   process-wide count of sockets configured but not yet claimed: every new
//!   connection's socket is configured exactly once, by its own scan or a
//!   concurrent one, so each admission is backed by a configured socket and a
//!   scan that finds nothing admits nothing. Refused connections are closed
//!   by sqlx, which connects again until the acquire deadline.
//! - **One socket per check.** Each descriptor is first duplicated
//!   (`F_DUPFD_CLOEXEC`); every check and change goes through that owned
//!   duplicate, so a closed and reused descriptor number cannot redirect
//!   them.
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

/// How long `on_connect` waits for a host lookup.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolved addresses kept per host; a larger answer set restarts the cache.
const MAX_RESOLVED: usize = 256;

/// Applies [`TcpKeepalive`] to the sockets of one pool's connections.
#[derive(Debug)]
pub struct KeepaliveConfigurator {
    settings: TcpKeepalive,
    host: String,
    port: u16,
    /// Every address the host has resolved to so far (bounded).
    resolved: Mutex<HashSet<IpAddr>>,
}

/// Sockets configured, connections admitted, and connections refused, by
/// every pool in the process; and configured sockets no admission has
/// claimed yet. After a deploy, `sockets_configured >= connections_opened`
/// and `keepalive_missed == 0` in the startup log show every admitted
/// connection is protected.
static CONFIGURED: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static MISSED: AtomicU64 = AtomicU64::new(0);
static UNCLAIMED: AtomicU64 = AtomicU64::new(0);

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

    /// Connections refused because their socket could not be confirmed
    /// configured.
    pub fn missed() -> u64 {
        MISSED.load(Ordering::Relaxed)
    }

    /// Configure the socket of the connection the pool just opened, with
    /// every other unconfigured database client socket. An error means the
    /// connection's socket may be unprotected; the caller must not admit it.
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
        if self.known().is_empty() {
            self.resolve().await;
        }
        let mut scan = self.scan_once().await?;
        if !scan.unverified.is_empty() {
            // Perhaps the host now resolves to the address sqlx connected
            // to; one fresh lookup, then refuse rather than guess.
            self.resolve().await;
            let again = self.scan_once().await?;
            scan.configured.extend(again.configured);
            scan.unverified = again.unverified;
        }
        if !scan.unverified.is_empty() {
            return Err(std::io::Error::other(format!(
                "{} outbound socket(s) to the database port at an address the database host does not resolve to",
                scan.unverified.len()
            )));
        }
        // Each admission claims one configured socket: this connection's,
        // configured by this scan or a concurrent one.
        if UNCLAIMED
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_err()
        {
            return Err(std::io::Error::other(
                "no configured database socket backs this connection",
            ));
        }
        // Zero is normal when connections open concurrently: an earlier
        // scan already configured this one.
        tracing::debug!(
            sockets = scan.configured.len(),
            "PostgreSQL TCP keepalive scan after a new connection"
        );
        Ok(scan.configured.len())
    }

    async fn scan_once(&self) -> std::io::Result<Scan> {
        let (port, settings, resolved) = (self.port, self.settings, self.known());
        // /proc and socket syscalls, off the async workers.
        let scan =
            tokio::task::spawn_blocking(move || configure_sockets(port, &resolved, &settings))
                .await
                .map_err(std::io::Error::other)??;
        let configured = scan.configured.len() as u64;
        CONFIGURED.fetch_add(configured, Ordering::Relaxed);
        UNCLAIMED.fetch_add(configured, Ordering::AcqRel);
        Ok(scan)
    }

    fn known(&self) -> HashSet<IpAddr> {
        self.resolved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Add the host's current addresses to the cache. A failed lookup adds
    /// nothing; the scan then refuses any socket it cannot verify.
    async fn resolve(&self) {
        let lookup = tokio::time::timeout(
            LOOKUP_TIMEOUT,
            tokio::net::lookup_host((self.host.as_str(), self.port)),
        )
        .await;
        let Ok(Ok(addrs)) = lookup else {
            tracing::warn!("PostgreSQL TCP keepalive: looking up the database host failed");
            return;
        };
        let mut resolved = self.resolved.lock().unwrap_or_else(|e| e.into_inner());
        if resolved.len() >= MAX_RESOLVED {
            resolved.clear();
        }
        resolved.extend(addrs.map(|addr| addr.ip().to_canonical()));
    }
}

/// What one [`configure_sockets`] scan found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Database client sockets newly configured, by peer address.
    pub configured: Vec<SocketAddr>,
    /// Unconfigured outbound sockets to the database port at an address not
    /// among the resolved ones, left untouched.
    pub unverified: Vec<SocketAddr>,
}

/// Configure every unconfigured database client socket of this process (see
/// the [module docs](self)): `port` is the database port, `resolved` the
/// database host's addresses. Fails if the scan cannot complete or any
/// database client socket cannot be configured.
#[cfg(target_os = "linux")]
pub fn configure_sockets(
    port: u16,
    resolved: &HashSet<IpAddr>,
    settings: &TcpKeepalive,
) -> std::io::Result<Scan> {
    configure_sockets_with(port, resolved, settings, |_| {})
}

/// [`configure_sockets`], calling `after_duplicate` with each socket's
/// original descriptor number once it has been duplicated. Tests use it to
/// close and reuse that number at the worst moment.
#[cfg(target_os = "linux")]
pub fn configure_sockets_with(
    port: u16,
    resolved: &HashSet<IpAddr>,
    settings: &TcpKeepalive,
    mut after_duplicate: impl FnMut(std::os::fd::RawFd),
) -> std::io::Result<Scan> {
    let ephemeral = ephemeral_ports()?;
    let mut listening = HashSet::new();
    for_each_socket(|_, socket| {
        if is_listener(socket)? {
            if let Some(local) = local_addr(socket)? {
                listening.insert(local.port());
            }
        }
        Ok(())
    })?;
    let mut scan = Scan::default();
    for_each_socket(|fd, socket| {
        after_duplicate(fd);
        let socket_ref = socket2::SockRef::from(socket);
        if is_listener(socket)? {
            return Ok(());
        }
        let Some(local) = local_addr(socket)? else {
            return Ok(());
        };
        let Some(peer) = peer_addr(socket)? else {
            return Ok(());
        };
        if !ephemeral.contains(&local.port())
            || listening.contains(&local.port())
            || peer.port() != port
            || socket_ref.keepalive()?
        {
            return Ok(());
        }
        let peer = canonical(peer);
        if !resolved.contains(&peer.ip()) {
            scan.unverified.push(peer);
            return Ok(());
        }
        configure(&socket_ref, settings)?;
        scan.configured.push(peer);
        Ok(())
    })?;
    Ok(scan)
}

#[cfg(not(target_os = "linux"))]
pub fn configure_sockets(
    _port: u16,
    _resolved: &HashSet<IpAddr>,
    _settings: &TcpKeepalive,
) -> std::io::Result<Scan> {
    Ok(Scan::default())
}

/// Call `visit` with an owned duplicate of every TCP stream socket of this
/// process. Only a descriptor that closed meanwhile, or one that is no
/// longer a socket, is skipped; any other failure ends the scan with it.
#[cfg(target_os = "linux")]
fn for_each_socket(
    mut visit: impl FnMut(std::os::fd::RawFd, &std::os::fd::OwnedFd) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::fd::RawFd;

    for (index, entry) in std::fs::read_dir("/proc/self/fd")?.enumerate() {
        if index >= MAX_SCANNED_FDS {
            return Err(std::io::Error::other(format!(
                "more than {MAX_SCANNED_FDS} descriptors to scan"
            )));
        }
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        else {
            continue;
        };
        // A cheap filter before any socket call; the duplicate below is
        // what the checks trust.
        match std::fs::read_link(entry.path()) {
            Ok(target) if target.to_string_lossy().starts_with("socket:") => {}
            Ok(_) => continue,
            // Closed since it was listed.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let Some(socket) = duplicate(fd)? else {
            continue;
        };
        match socket2::SockRef::from(&socket).r#type() {
            Ok(socket2::Type::STREAM) => visit(fd, &socket)?,
            Ok(_) => {}
            // The number was reused by something that is not a socket.
            Err(error) if error.raw_os_error() == Some(libc::ENOTSOCK) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// An owned duplicate of `fd`, `None` if it is no longer open, or the error
/// (exhausted descriptors, for one) that prevented duplicating it.
#[cfg(target_os = "linux")]
fn duplicate(fd: std::os::fd::RawFd) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    use std::os::fd::FromRawFd;

    // SAFETY: fcntl with F_DUPFD_CLOEXEC has no memory-safety
    // preconditions; on an fd that is not open it fails with EBADF.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate >= 0 {
        // SAFETY: the new descriptor is ours alone to own and close.
        return Ok(Some(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(duplicate)
        }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        Ok(None)
    } else {
        Err(error)
    }
}

/// The kernel's ephemeral (client) port range, inclusive.
#[cfg(target_os = "linux")]
fn ephemeral_ports() -> std::io::Result<std::ops::RangeInclusive<u16>> {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")?;
    let mut bounds = range.split_whitespace().map(str::parse::<u16>);
    match (bounds.next(), bounds.next()) {
        (Some(Ok(low)), Some(Ok(high))) => Ok(low..=high),
        _ => Err(std::io::Error::other(format!(
            "unreadable ip_local_port_range {range:?}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn is_listener(socket: &std::os::fd::OwnedFd) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;

    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` outlive the call and describe its buffer.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if result == 0 {
        Ok(value != 0)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The socket's local inet address, or `None` for a non-inet socket.
#[cfg(target_os = "linux")]
fn local_addr(socket: &std::os::fd::OwnedFd) -> std::io::Result<Option<SocketAddr>> {
    Ok(socket2::SockRef::from(socket).local_addr()?.as_socket())
}

/// The socket's inet peer, or `None` when it is not connected or not inet.
#[cfg(target_os = "linux")]
fn peer_addr(socket: &std::os::fd::OwnedFd) -> std::io::Result<Option<SocketAddr>> {
    match socket2::SockRef::from(socket).peer_addr() {
        Ok(addr) => Ok(addr.as_socket()),
        Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Set the options; `SO_KEEPALIVE` last, since it marks the socket
/// configured: a socket whose configuration failed part-way stays a
/// candidate.
#[cfg(target_os = "linux")]
fn configure(socket: &socket2::SockRef<'_>, settings: &TcpKeepalive) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

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
    socket.set_keepalive(true)
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

    fn loopback() -> HashSet<IpAddr> {
        HashSet::from(["127.0.0.1".parse().unwrap()])
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

    /// A socket bound to `local` before it connects to `remote`.
    fn connect_from(local: SocketAddr, remote: SocketAddr) -> TcpStream {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket.bind(&local.into()).unwrap();
        socket.connect(&remote.into()).unwrap();
        socket.into()
    }

    /// Every option reads back from the socket with `getsockopt`; only the
    /// client socket to the database is touched, and a second scan finds it
    /// already configured.
    #[test]
    fn configures_only_database_client_sockets() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let to_database = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        let (accepted, _) = database.accept().unwrap();
        let to_other = TcpStream::connect(other.local_addr().unwrap()).unwrap();

        let scan = configure_sockets(port, &loopback(), &settings()).unwrap();
        assert_eq!(scan.configured, vec![database.local_addr().unwrap()]);
        assert!(scan.unverified.is_empty());
        assert_configured(&to_database);
        // The listener's side of the same connection and an unrelated
        // connection keep the kernel defaults.
        assert_untouched(&accepted);
        assert_untouched(&to_other);
        let again = configure_sockets(port, &loopback(), &settings()).unwrap();
        assert!(again.configured.is_empty());
    }

    /// Astra (re-review): an incoming connection whose *source* port is the
    /// database port is an accepted socket, never a database client socket.
    #[test]
    fn an_incoming_socket_from_the_database_port_is_never_configured() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        // The node's HTTP listener, and a caller connecting to it from the
        // database port (on another loopback address).
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let caller = connect_from(
            SocketAddr::new("127.0.0.2".parse().unwrap(), port),
            http.local_addr().unwrap(),
        );
        let (incoming, from) = http.accept().unwrap();
        assert_eq!(
            from.port(),
            port,
            "the incoming peer port is the database port"
        );

        let scan = configure_sockets(
            port,
            &HashSet::from([from.ip(), "127.0.0.1".parse().unwrap()]),
            &settings(),
        )
        .unwrap();
        assert!(scan.configured.is_empty(), "{scan:?}");
        assert!(scan.unverified.is_empty(), "{scan:?}");
        assert_untouched(&incoming);
        assert_untouched(&caller);
    }

    /// Astra (re-review): an outbound connection to the database port at an
    /// address the database host does not resolve to is never configured; it
    /// is reported, and `on_connect` refuses.
    #[tokio::test]
    async fn an_unrelated_peer_on_the_database_port_is_never_configured() {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let unrelated = TcpListener::bind(("127.0.0.2", port)).unwrap();
        let to_unrelated = TcpStream::connect(unrelated.local_addr().unwrap()).unwrap();

        let scan = configure_sockets(port, &loopback(), &settings()).unwrap();
        assert!(scan.configured.is_empty());
        assert_eq!(scan.unverified, vec![unrelated.local_addr().unwrap()]);
        assert_untouched(&to_unrelated);

        // With the real database connection open as well, the unverified
        // peer still makes the connection be refused, not guessed about.
        let _to_database = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        let configurator = KeepaliveConfigurator::new(settings(), "127.0.0.1", port).unwrap();
        assert!(configurator.on_connect().await.is_err());
        assert_untouched(&to_unrelated);
    }

    /// Rotating DNS: the connection went to an address the host's lookup
    /// does not return, or the lookup fails. The socket is not verified, so
    /// the connection is refused; once the address resolves it is admitted.
    #[tokio::test]
    async fn connections_to_unresolved_addresses_are_refused() {
        // 127.0.0.2 is on loopback but is not what "127.0.0.1" resolves to.
        let database = TcpListener::bind("127.0.0.2:0").unwrap();
        let port = database.local_addr().unwrap().port();
        let client = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        let rotated = KeepaliveConfigurator::new(settings(), "127.0.0.1", port).unwrap();
        assert!(rotated.on_connect().await.is_err());
        let unresolvable = KeepaliveConfigurator::new(settings(), "tc1054.invalid", port).unwrap();
        assert!(unresolvable.on_connect().await.is_err(), "lookup failure");
        assert_untouched(&client);

        let resolves = KeepaliveConfigurator::new(settings(), "127.0.0.2", port).unwrap();
        assert_eq!(resolves.on_connect().await.unwrap(), 1);
        assert_configured(&client);
        assert!(KeepaliveConfigurator::new(settings(), "/run/postgresql", 5432).is_none());
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
        let scan = configure_sockets_with(port, &loopback(), &settings(), |fd| {
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
        assert_eq!(scan.configured.len(), 1);
        assert_configured(&witness);
        assert_untouched(&unrelated);
        // `target` now refers to the unrelated socket's duplicate.
        std::mem::forget(to_database);
        // SAFETY: `target` is a descriptor this test owns (the dup2 copy).
        unsafe { libc::close(target) };
    }

    /// A database client socket that cannot be configured fails the scan,
    /// so the pool does not admit its connection; `SO_KEEPALIVE` stays off,
    /// so the socket is still a candidate for the next scan.
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

    /// Astra (re-review): with descriptors exhausted, duplicating a socket
    /// fails with EMFILE; that is a scan failure, not "nothing found", and a
    /// scan that configures nothing admits nothing. Runs in a child process,
    /// which owns its descriptor limit and the process-wide claim count.
    #[test]
    fn exhausted_descriptors_and_empty_scans_admit_nothing() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pg_keepalive::tests::exhausted_descriptors_child",
                "--ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("TC1054_FD_CHILD", "1")
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{log}");
        assert!(log.contains("1 passed"), "{log}");
    }

    #[test]
    #[ignore = "run by exhausted_descriptors_and_empty_scans_admit_nothing"]
    fn exhausted_descriptors_child() {
        if std::env::var_os("TC1054_FD_CHILD").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = database.local_addr().unwrap().port();

        // A scan that finds no database socket admits nothing.
        let configurator = KeepaliveConfigurator::new(settings(), "127.0.0.1", port).unwrap();
        assert!(
            runtime.block_on(configurator.on_connect()).is_err(),
            "nothing found"
        );

        let client = TcpStream::connect(database.local_addr().unwrap()).unwrap();
        // Lower the soft limit, fill it, and free exactly one slot: the
        // directory listing takes it, so duplicating the socket hits EMFILE.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid rlimit for getrlimit/setrlimit.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            limit.rlim_cur = 128;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
        }
        let mut fillers = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            fillers.push(file);
        }
        fillers.pop();
        let scan = configure_sockets(port, &loopback(), &settings());
        drop(fillers);
        let error = scan.expect_err("EMFILE is a scan failure, not an empty scan");
        assert_eq!(error.raw_os_error(), Some(libc::EMFILE), "{error:?}");
        assert_untouched(&client);
    }

    #[test]
    fn ipv4_mapped_peers_match() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5432".parse().unwrap();
        assert_eq!(canonical(mapped), "127.0.0.1:5432".parse().unwrap());
    }
}
