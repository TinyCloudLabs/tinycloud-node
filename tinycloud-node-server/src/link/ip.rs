//! Private-range LAN IP discovery.
//!
//! Filtering mirrors `tinycloud-link/src/ip.ts::isPrivateAddress`:
//!   - IPv4 RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//!     plus link-local 169.254.0.0/16.
//!   - IPv6 unique-local `fc00::/7` and link-local `fe80::/10`.
//!   - Loopback and public addresses are excluded so a public IP can never be
//!     handed to the service (which rejects public IPs anyway, but we don't
//!     want to leak one).
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

/// Enumerate this host's non-loopback private LAN IPs. Preserves discovery
/// order but drops duplicates, and caps the returned set at `MAX_LAN_IPS` so
/// callers stay under the service's `lanIps.length <= MAX_LAN_IPS` cap.
pub fn discover_lan_ips() -> Result<Vec<IpAddr>, LinkError> {
    let addrs = if_addrs::get_if_addrs().map_err(|err| LinkError::Interface(err.to_string()))?;
    let mut ips = Vec::new();
    for iface in addrs {
        if iface.is_loopback() {
            continue;
        }
        let ip = iface.ip();
        if !is_private_lan_address(ip) {
            continue;
        }
        if ips.contains(&ip) {
            continue;
        }
        ips.push(ip);
        if ips.len() >= MAX_LAN_IPS {
            break;
        }
    }
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
    fn format_lan_ips_stringifies_addresses() {
        let ips: Vec<IpAddr> = vec!["192.168.1.10".parse().unwrap(), "fd00::1".parse().unwrap()];
        let rendered = format_lan_ips(&ips);
        assert_eq!(rendered, vec!["192.168.1.10", "fd00::1"]);
    }
}
