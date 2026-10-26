//! App ids under the reserved `apps/` key segment.
//!
//! A key path that starts with `apps/` is `apps/<app id>/<name>[/<more>]`. The
//! app id is validated, never transformed, and must match
//! `^[a-z0-9][a-z0-9._-]{0,63}$` as a whole string (ASCII only; a trailing
//! newline fails).
//!
//! An app id is bound to a host when it equals the host's labels reversed and
//! joined with `.`, or starts with that string followed by `.`. The host is
//! compared in its lowercase ASCII (punycode) form and needs at least two
//! labels.

use super::key_id::valid_segment;

/// Whether `id` is a valid app id.
pub fn app_id_valid(id: &str) -> bool {
    valid_segment(id)
}

/// Whether `app_id` is bound to `host`. `host` is a bare host name: no scheme,
/// no port. IP literals, `localhost` names, a trailing dot and single-label
/// hosts are never bound.
pub fn app_id_bound_to_host(host: &str, app_id: &str) -> bool {
    if !app_id_valid(app_id) {
        return false;
    }
    let Some(reversed) = reversed_ascii_host(host) else {
        return false;
    };
    app_id == reversed
        || app_id
            .strip_prefix(reversed.as_str())
            .is_some_and(|rest| rest.starts_with('.'))
}

/// The host in lowercase ASCII form, labels reversed and joined with `.`, or
/// `None` when the host is not an eligible DNS name.
fn reversed_ascii_host(host: &str) -> Option<String> {
    if host.is_empty() || host.ends_with('.') || host.starts_with('[') {
        return None;
    }
    let ascii = idna::domain_to_ascii(host).ok()?;
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|label| dns_label(label)) {
        return None;
    }
    let last = labels.last().copied().unwrap_or_default();
    // An IPv4 form (`1.0.0.127`, `127.1`, `0x7f.1`) is not a DNS name.
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return None;
    }
    if last == "localhost" {
        return None;
    }
    let mut reversed = String::with_capacity(ascii.len());
    for (index, label) in labels.iter().rev().enumerate() {
        if index > 0 {
            reversed.push('.');
        }
        reversed.push_str(label);
    }
    Some(reversed)
}

fn dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/encryption/app-key-vectors.json"
        ))
        .expect("vector file parses")
    }

    /// Host of an `https://<host>` origin with no port, as the shared vectors
    /// phrase it. Any other origin shape is not bound.
    fn origin_host(origin: &str) -> Option<&str> {
        let host = origin.strip_prefix("https://")?;
        if host.contains(['/', ':', '@', '?', '#']) {
            return None;
        }
        Some(host)
    }

    #[test]
    fn shared_app_id_vectors() {
        let vectors = vectors();
        let cases = vectors["appIdValid"].as_array().unwrap();
        assert_eq!(cases.len(), 39);
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let valid = case["valid"].as_bool().unwrap();
            assert_eq!(app_id_valid(id), valid, "app id {id:?}");
        }
    }

    #[test]
    fn shared_host_binding_vectors() {
        let vectors = vectors();
        let cases = vectors["hostBinding"].as_array().unwrap();
        assert_eq!(cases.len(), 23);
        for case in cases {
            let origin = case["origin"].as_str().unwrap();
            let id = case["id"].as_str().unwrap();
            let bound = case["bound"].as_bool().unwrap();
            let actual = origin_host(origin).is_some_and(|host| app_id_bound_to_host(host, id));
            assert_eq!(actual, bound, "origin {origin:?} id {id:?}");
        }
    }

    #[test]
    fn bare_hosts_with_a_port_or_scheme_are_not_bound() {
        assert!(!app_id_bound_to_host(
            "listen.tinycloud.xyz:8443",
            "xyz.tinycloud.listen"
        ));
        assert!(!app_id_bound_to_host(
            "https://listen.tinycloud.xyz",
            "xyz.tinycloud.listen"
        ));
        assert!(!app_id_bound_to_host("", "a"));
        assert!(app_id_bound_to_host(
            "LISTEN.tinycloud.xyz",
            "xyz.tinycloud.listen"
        ));
    }
}
