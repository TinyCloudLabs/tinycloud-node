//! Private-range LAN IP discovery.
//!
//! Filtering is based on `tinycloud-link/src/ip.ts::isPrivateAddress` but is
//! not a byte-for-byte port:
//!   - IPv4 RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//!     plus link-local 169.254.0.0/16.
//!   - IPv6 unique-local `fc00::/7` and link-local `fe80::/10`.
//!   - Unlike the TS implementation, loopback is always excluded here (TS
//!     classifies 127.0.0.0/8 and `::1` as private). This is safe because
//!     `discover_lan_ips` already filters loopback interfaces separately
//!     before this function ever sees a loopback address.
//!   - Unlike the TS implementation, IPv4-mapped (`::ffff:a.b.c.d`), NAT64
//!     (`64:ff9b::/96`), and 6to4 (`2002::/16`) IPv6 addresses are not
//!     unwrapped and classified by their embedded IPv4 — they fall through to
//!     "not private". `if_addrs` does not surface these forms from OS
//!     interface enumeration, so this gap is not currently reachable.
//!
//! `is_private_lan_address` above is the general "is this usable at all"
//! predicate (still matches the TS `isPrivateAddress` shape, including
//! `fe80::/10`). `discover_lan_ips` — the function that actually decides what
//! gets published in a claim — applies a stricter policy on top: it prefers
//! RFC1918/ULA addresses over IPv4 link-local when truncating to
//! `MAX_LAN_IPS`, and excludes IPv6 link-local (`fe80::/10`) entirely, since
//! a scope-less AAAA record for one is unreachable from other hosts.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::LinkError;

/// Maximum number of LAN IPs the service accepts on a claim.
pub const MAX_LAN_IPS: usize = 8;

/// True if `addr` is a link/site-local address we're willing to advertise.
pub fn is_private_lan_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

fn is_private_ipv4(addr: Ipv4Addr) -> bool {
    if addr.is_loopback() || addr.is_broadcast() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }
    // RFC1918 + link-local.
    addr.is_private() || addr.is_link_local()
}

fn is_private_ipv6(addr: Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_multicast() || addr.is_unspecified() {
        return false;
    }
    let segments = addr.segments();
    // fc00::/7 unique local.
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // fe80::/10 link-local.
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    false
}

/// True for `fe80::/10` IPv6 link-local addresses.
fn is_ipv6_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// True for RFC1918 (IPv4) or unique-local (IPv6 ULA `fc00::/7`) addresses —
/// the preferred address classes for published records, since (unlike
/// link-local addresses) they're routable within the LAN and don't need a
/// zone/scope ID to be reachable.
fn is_preferred_lan_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Name prefixes for interfaces that are virtual bridges/tunnels rather than
/// a host's real physical LAN connection: VM hypervisor bridges (Lima,
/// Docker Desktop, VirtualBox, `vmnet`), macOS's private relay / per-app VPN
/// `utun` tunnels, AirDrop/AWDL, and low-latency WLAN (`llw`) on macOS; and
/// Docker/libvirt/veth/bridge devices on Linux. Addresses on these
/// interfaces are technically "private range" but aren't reachable from
/// other devices on the actual LAN, so publishing them alongside (or instead
/// of) the real interface's address produces a claim clients can't connect
/// to — see the `192.168.64.1` (Lima bridge) case in TC-250.
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "bridge", "vmnet", "utun", "awdl", "llw", // macOS
    "docker", "virbr", "veth", "br-", // Linux
];

/// True if `name` looks like a virtual/VM-bridge interface rather than a
/// host's real physical (`en*`/`eth*`/`wlan*`) network interface.
fn is_virtual_bridge_interface(name: &str) -> bool {
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Enumerate this host's non-loopback private LAN IPs to publish in a claim.
///
/// RFC1918/ULA addresses are preferred over IPv4 link-local (`169.254.0.0/16`)
/// when the set has to be truncated to `MAX_LAN_IPS`. IPv6 link-local
/// (`fe80::/10`) addresses are excluded outright: they require a zone/scope
/// ID to be reachable, which a plain AAAA record can't carry, so publishing
/// one would produce an address LAN clients can't actually connect to (see
/// docs/specs/node-control-plane-v1.md §3.9).
pub fn discover_lan_ips() -> Result<Vec<IpAddr>, LinkError> {
    let addrs = if_addrs::get_if_addrs().map_err(|err| LinkError::Interface(err.to_string()))?;
    select_lan_ips(addrs)
}

/// The filtering/selection logic behind [`discover_lan_ips`], split out so
/// tests can drive it with a fabricated interface list instead of this
/// host's real interfaces.
fn select_lan_ips(addrs: Vec<if_addrs::Interface>) -> Result<Vec<IpAddr>, LinkError> {
    // Each entry also records whether it came from a virtual bridge/tunnel
    // interface, so those can be deprioritized below.
    let mut preferred: Vec<(IpAddr, bool)> = Vec::new();
    let mut fallback: Vec<(IpAddr, bool)> = Vec::new();
    for iface in addrs {
        if iface.is_loopback() {
            continue;
        }
        let ip = iface.ip();
        if let IpAddr::V6(v6) = ip {
            if is_ipv6_link_local(v6) {
                continue;
            }
        }
        if !is_private_lan_address(ip) {
            continue;
        }
        let is_virtual = is_virtual_bridge_interface(&iface.name);
        let bucket = if is_preferred_lan_address(ip) {
            &mut preferred
        } else {
            &mut fallback
        };
        if bucket.iter().any(|(existing, _)| *existing == ip) {
            continue;
        }
        bucket.push((ip, is_virtual));
    }
    let mut all = preferred;
    all.extend(fallback);

    // Exclude known VM-bridge/tunnel interfaces (Lima/Docker/VirtualBox
    // bridges, `utun`/`awdl`/`llw` on macOS, `docker`/`virbr`/`veth`/`br-` on
    // Linux) in favor of real physical interfaces — but never publish
    // nothing when something private exists, so fall back to the unfiltered
    // set if that filtering would leave it empty.
    let physical: Vec<IpAddr> = all
        .iter()
        .filter(|(_, is_virtual)| !is_virtual)
        .map(|(ip, _)| *ip)
        .collect();

    let mut ips = if physical.is_empty() {
        all.into_iter().map(|(ip, _)| ip).collect()
    } else {
        physical
    };
    ips.truncate(MAX_LAN_IPS);
    if ips.is_empty() {
        return Err(LinkError::NoLanIps);
    }
    Ok(ips)
}

pub fn format_lan_ips(ips: &[IpAddr]) -> Vec<String> {
    ips.iter().map(|ip| ip.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_private_ranges_are_included() {
        assert!(is_private_lan_address("10.0.0.1".parse().unwrap()));
        assert!(is_private_lan_address("10.255.255.254".parse().unwrap()));
        assert!(is_private_lan_address("172.16.0.5".parse().unwrap()));
        assert!(is_private_lan_address("172.31.255.9".parse().unwrap()));
        assert!(is_private_lan_address("192.168.1.42".parse().unwrap()));
        assert!(is_private_lan_address("169.254.10.20".parse().unwrap()));
    }

    #[test]
    fn ipv4_public_and_loopback_are_excluded() {
        assert!(!is_private_lan_address("8.8.8.8".parse().unwrap()));
        assert!(!is_private_lan_address("1.1.1.1".parse().unwrap()));
        assert!(!is_private_lan_address("127.0.0.1".parse().unwrap()));
        assert!(!is_private_lan_address("172.32.0.1".parse().unwrap())); // just outside 172.16/12
        assert!(!is_private_lan_address("192.169.0.1".parse().unwrap())); // just outside 192.168/16
        assert!(!is_private_lan_address("224.0.0.1".parse().unwrap())); // multicast
        assert!(!is_private_lan_address("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn ipv6_ula_and_link_local_are_included() {
        assert!(is_private_lan_address("fd00::1".parse().unwrap()));
        assert!(is_private_lan_address("fdff::abcd".parse().unwrap()));
        assert!(is_private_lan_address("fc12::1".parse().unwrap()));
        assert!(is_private_lan_address("fe80::1".parse().unwrap()));
        assert!(is_private_lan_address("febf::1234".parse().unwrap()));
    }

    #[test]
    fn ipv6_public_and_loopback_are_excluded() {
        assert!(!is_private_lan_address("2001:db8::1".parse().unwrap()));
        assert!(!is_private_lan_address("2606:4700::1".parse().unwrap()));
        assert!(!is_private_lan_address("::1".parse().unwrap()));
        assert!(!is_private_lan_address("::".parse().unwrap()));
        assert!(!is_private_lan_address("ff02::1".parse().unwrap())); // multicast
        assert!(!is_private_lan_address("fec0::1".parse().unwrap())); // deprecated site-local
    }

    #[test]
    fn ipv6_link_local_is_flagged_for_exclusion_from_published_records() {
        assert!(is_ipv6_link_local("fe80::1".parse().unwrap()));
        assert!(is_ipv6_link_local("febf::1234".parse().unwrap()));
        assert!(!is_ipv6_link_local("fd00::1".parse().unwrap()));
        assert!(!is_ipv6_link_local("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_and_ula_are_preferred_over_link_local() {
        assert!(is_preferred_lan_address("192.168.1.5".parse().unwrap()));
        assert!(is_preferred_lan_address("10.0.0.1".parse().unwrap()));
        assert!(is_preferred_lan_address("fd00::1".parse().unwrap()));
        assert!(!is_preferred_lan_address("169.254.1.1".parse().unwrap()));
        assert!(!is_preferred_lan_address("fe80::1".parse().unwrap()));
    }

    #[test]
    fn format_lan_ips_stringifies_addresses() {
        let ips: Vec<IpAddr> = vec!["192.168.1.10".parse().unwrap(), "fd00::1".parse().unwrap()];
        let rendered = format_lan_ips(&ips);
        assert_eq!(rendered, vec!["192.168.1.10", "fd00::1"]);
    }

    #[test]
    fn virtual_bridge_prefixes_are_recognized() {
        for name in [
            "bridge100",
            "vmnet1",
            "utun0",
            "awdl0",
            "llw0",
            "docker0",
            "virbr0",
            "veth1234",
            "br-abcdef",
        ] {
            assert!(
                is_virtual_bridge_interface(name),
                "{name} should be recognized as virtual"
            );
        }
        for name in ["en0", "en1", "eth0", "wlan0"] {
            assert!(
                !is_virtual_bridge_interface(name),
                "{name} should not be recognized as virtual"
            );
        }
    }

    fn v4_iface(name: &str, ip: Ipv4Addr) -> if_addrs::Interface {
        if_addrs::Interface {
            name: name.to_string(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            index: None,
        }
    }

    #[test]
    fn lan_ip_selection_excludes_vm_bridge_when_a_physical_interface_exists() {
        // Reproduces the live TC-250 case: Lima's `bridge100` publishing
        // 192.168.64.1 alongside the real `en0` LAN address 192.168.1.195.
        let addrs = vec![
            v4_iface("en0", "192.168.1.195".parse().unwrap()),
            v4_iface("bridge100", "192.168.64.1".parse().unwrap()),
        ];
        let ips = select_lan_ips(addrs).unwrap();
        assert_eq!(ips, vec!["192.168.1.195".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn lan_ip_selection_falls_back_to_virtual_interface_when_nothing_physical_exists() {
        // Never publish nothing when a private-range address exists at all —
        // even if every interface we found looks virtual.
        let addrs = vec![v4_iface("bridge100", "192.168.64.1".parse().unwrap())];
        let ips = select_lan_ips(addrs).unwrap();
        assert_eq!(ips, vec!["192.168.64.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn lan_ip_selection_errors_when_no_private_addresses_exist() {
        let addrs = vec![v4_iface("en0", "8.8.8.8".parse().unwrap())];
        assert!(select_lan_ips(addrs).is_err());
    }
}
