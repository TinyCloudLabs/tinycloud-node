//! TC-3123: write-only custom headers a webhook subscriber registers, for
//! callbacks that require their own credential (e.g. `Authorization`).
//!
//! Values are secret: they are sealed like the webhook secret, never returned,
//! and never rendered by `Debug`, errors, logs or `last_error`. Names are not
//! secret and are returned on list.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use std::fmt;
use tinycloud_core::encryption::RowBinding;

pub const MAX_HEADERS: usize = 8;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_VALUE_BYTES: usize = 1024;
pub const MAX_TOTAL_BYTES: usize = 4096;

/// Exact names refused case-insensitively: framing, routing, hop-by-hop and
/// proxy-identity headers the node or its egress owns, `Content-Type` which
/// the node sets, and cookies. Kept identical to the js-sdk client list.
const RESERVED: [&str; 20] = [
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "content-md5",
    "content-range",
    "transfer-encoding",
    "accept-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "cookie",
    "cookie2",
    "set-cookie",
    "forwarded",
    "via",
    "x-real-ip",
];
/// Prefixes refused case-insensitively. `x-tinycloud-` covers the signature
/// and the delivery, event and subscription id headers.
const RESERVED_PREFIXES: [&str; 4] = ["proxy-", "sec-", "x-forwarded-", "x-tinycloud-"];

/// The sealed headers are bound to this column of the row whose primary key
/// is `row_key` (`&[subscription_id.as_bytes()]`), like the webhook secret.
pub fn binding<'a>(row_key: &'a [&'a [u8]]) -> RowBinding<'a> {
    RowBinding::new("hook_subscription", "encrypted_headers", row_key)
}

/// Registered name/value pairs in request order. `Debug` shows names only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WebhookHeaders(Vec<(String, String)>);

impl fmt::Debug for WebhookHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(name, _)| (name, "<redacted>")))
            .finish()
    }
}

/// Collects every JSON member, duplicates included, so a duplicate key is
/// refused by [`WebhookHeaders::validate`] instead of silently overwritten.
impl<'de> Deserialize<'de> for WebhookHeaders {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PairsVisitor;
        impl<'de> Visitor<'de> for PairsVisitor {
            type Value = WebhookHeaders;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object of header names to string values")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, String>()? {
                    pairs.push(pair);
                }
                Ok(WebhookHeaders(pairs))
            }
        }
        deserializer.deserialize_map(PairsVisitor)
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_value_byte(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn is_reserved(lower: &str) -> bool {
    RESERVED.contains(&lower) || RESERVED_PREFIXES.iter().any(|p| lower.starts_with(p))
}

impl WebhookHeaders {
    #[cfg(test)]
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Enforce the registration contract. Messages name a header only once
    /// the name is a valid token and never include a value.
    pub fn validate(&self) -> Result<(), String> {
        if self.0.len() > MAX_HEADERS {
            return Err(format!("headers: at most {MAX_HEADERS} headers"));
        }
        let mut seen = Vec::with_capacity(self.0.len());
        let mut total = 0usize;
        for (name, value) in &self.0 {
            if name.is_empty() || name.len() > MAX_NAME_BYTES || !name.bytes().all(is_token_byte) {
                return Err("headers: invalid header name".to_string());
            }
            let lower = name.to_ascii_lowercase();
            if is_reserved(&lower) {
                return Err(format!("headers: header \"{name}\" is reserved"));
            }
            if seen.contains(&lower) {
                return Err(format!("headers: duplicate header \"{name}\""));
            }
            if value.len() > MAX_VALUE_BYTES {
                return Err(format!(
                    "headers: value for header \"{name}\" exceeds {MAX_VALUE_BYTES} bytes"
                ));
            }
            let bytes = value.as_bytes();
            if bytes.is_empty()
                || !bytes.iter().copied().all(is_value_byte)
                || bytes.first() == Some(&b' ')
                || bytes.last() == Some(&b' ')
            {
                return Err(format!("headers: invalid value for header \"{name}\""));
            }
            total += name.len() + value.len();
            seen.push(lower);
        }
        if total > MAX_TOTAL_BYTES {
            return Err(format!(
                "headers: total size exceeds {MAX_TOTAL_BYTES} bytes"
            ));
        }
        Ok(())
    }

    /// Names sorted case-insensitively, as stored in `header_names_json`.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.0.iter().map(|(name, _)| name.clone()).collect();
        names.sort_by_key(|name| name.to_ascii_lowercase());
        names
    }

    /// Plaintext sealed into `encrypted_headers`: `[[name, value], ...]`.
    pub fn sealed_plaintext(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("serializing string pairs cannot fail")
    }
}

/// Opened `encrypted_headers` plaintext as a request header map. Every value
/// is marked sensitive. The plaintext is re-checked against the registration
/// rules so a tampered or legacy row can never smuggle a reserved header.
pub fn delivery_header_map(plaintext: &[u8]) -> Result<HeaderMap, &'static str> {
    let pairs: Vec<(String, String)> =
        serde_json::from_slice(plaintext).map_err(|_| "custom headers unreadable")?;
    let headers = WebhookHeaders(pairs);
    headers
        .validate()
        .map_err(|_| "custom headers failed validation")?;
    let mut map = HeaderMap::with_capacity(headers.0.len());
    for (name, value) in headers.0 {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "custom headers invalid")?;
        let mut value = HeaderValue::from_str(&value).map_err(|_| "custom headers invalid")?;
        value.set_sensitive(true);
        map.insert(name, value);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(pairs: &[(&str, &str)]) -> String {
        WebhookHeaders::from_pairs(pairs).validate().unwrap_err()
    }

    #[test]
    fn accepts_credentials_and_sorts_names() {
        let headers = WebhookHeaders::from_pairs(&[
            ("X-Api-Key", "k1"),
            ("Authorization", "Bearer tok with-space"),
        ]);
        headers.validate().unwrap();
        assert_eq!(headers.names(), ["Authorization", "X-Api-Key"]);
        let map = delivery_header_map(&headers.sealed_plaintext()).unwrap();
        assert_eq!(map["authorization"], "Bearer tok with-space");
        assert!(map["authorization"].is_sensitive());
    }

    #[test]
    fn refuses_injection_and_reserved_names_without_echoing_values() {
        const SECRET: &str = "s3cr3t-marker";
        for value in [
            format!("{SECRET}\r\nX-Evil: 1"),
            format!("{SECRET}\nb"),
            format!("{SECRET}\rb"),
            format!("{SECRET}\0b"),
            format!("{SECRET}\u{7f}"),
            format!("caf\u{e9}{SECRET}"),
            format!(" {SECRET}"),
            format!("{SECRET} "),
            format!("{SECRET}\t"),
            format!("a\t{SECRET}"),
            String::new(),
        ] {
            let message = refused(&[("Authorization", &value)]);
            assert_eq!(
                message,
                "headers: invalid value for header \"Authorization\""
            );
        }
        for name in [
            "Host",
            "content-LENGTH",
            "Content-Type",
            "Transfer-Encoding",
            "Connection",
            "TE",
            "Proxy-Authorization",
            "X-TinyCloud-Signature",
            "x-tinycloud-delivery-id",
            "X-TINYCLOUD-Anything",
            "Cookie",
            "cookie2",
            "set-cookie",
            "Forwarded",
            "Via",
            "X-Real-IP",
            "X-Forwarded-For",
            "x-forwarded-host",
            "Sec-Fetch-Site",
            "Content-MD5",
            "Content-Range",
            "Accept-Encoding",
        ] {
            assert_eq!(
                refused(&[(name, SECRET)]),
                format!("headers: header \"{name}\" is reserved")
            );
        }
        for name in ["", "Bad Name", "Bad:Name", "Bad\r\nName", "Ünicode", "a(b)"] {
            let message = refused(&[(name, SECRET)]);
            assert!(
                message.starts_with("headers: invalid header name"),
                "{message}"
            );
            assert!(!message.contains(SECRET));
            assert!(!message.contains('\r') && !message.contains('\n'));
        }
        assert_eq!(
            refused(&[("X-Key", "a"), ("x-key", "b")]),
            "headers: duplicate header \"x-key\""
        );
    }

    #[test]
    fn enforces_count_and_size_caps() {
        let names: Vec<String> = (0..=MAX_HEADERS).map(|i| format!("X-H{i}")).collect();
        let pairs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
        assert_eq!(refused(&pairs), "headers: at most 8 headers");
        WebhookHeaders::from_pairs(&pairs[..MAX_HEADERS])
            .validate()
            .unwrap();

        let long_name = "X".repeat(MAX_NAME_BYTES + 1);
        assert!(refused(&[(&long_name, "v")]).starts_with("headers: invalid header name"));
        let max_value = "v".repeat(MAX_VALUE_BYTES);
        WebhookHeaders::from_pairs(&[("X-A", &max_value)])
            .validate()
            .unwrap();
        let long_value = "v".repeat(MAX_VALUE_BYTES + 1);
        assert_eq!(
            refused(&[("X-A", &long_value)]),
            "headers: value for header \"X-A\" exceeds 1024 bytes"
        );
        let total: Vec<(&str, &str)> = ["X-A", "X-B", "X-C", "X-D"]
            .iter()
            .map(|n| (*n, max_value.as_str()))
            .collect();
        assert_eq!(refused(&total), "headers: total size exceeds 4096 bytes");
    }

    #[test]
    fn json_duplicate_keys_are_kept_for_refusal_and_debug_redacts() {
        let headers: WebhookHeaders =
            serde_json::from_str(r#"{"X-Key":"one","X-Key":"two"}"#).unwrap();
        assert_eq!(
            headers.validate().unwrap_err(),
            "headers: duplicate header \"X-Key\""
        );
        let debug = format!("{headers:?}");
        assert!(debug.contains("X-Key") && !debug.contains("one") && !debug.contains("two"));
    }

    #[test]
    fn delivery_refuses_reserved_plaintext() {
        let plaintext = serde_json::to_vec(&[("X-TinyCloud-Signature", "forged")]).unwrap();
        assert!(delivery_header_map(&plaintext).is_err());
        assert!(delivery_header_map(b"not json").is_err());
    }
}
