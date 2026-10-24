//! A verifier of `TinyCloud-Read-Auth` as links API contract section 4.11
//! defines it. The links API is the real verifier; the node only signs. This
//! mirror lets the node's signer be checked against every `nodeReadAuth` row,
//! including the rows only a verifier can refuse, with the node's own strict
//! Ed25519 rule. Test code only.

use super::*;
use crate::delivery_link::{did_key_ed25519, is_canonical_prime_order, utc_millis};
use base64::decode_config;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Map;
use std::sync::Arc;

/// What the API received.
pub(crate) struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub audience: &'a str,
}

/// `(label, did)` entries.
pub(crate) type AllowList = Vec<(String, String)>;

/// The group order, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn decode_strict(value: &str) -> Option<Vec<u8>> {
    let bytes = decode_config(value, URL_SAFE_NO_PAD).ok()?;
    (encode_config(&bytes, URL_SAFE_NO_PAD) == value).then_some(bytes)
}

/// The entries of a JSON object in order, duplicates kept.
struct Entries(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Collect;
        impl<'de> Visitor<'de> for Collect {
            type Value = Entries;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                let mut entries = vec![];
                while let Some(entry) = map.next_entry::<String, Value>()? {
                    entries.push(entry);
                }
                Ok(Entries(entries))
            }
        }
        deserializer.deserialize_map(Collect)
    }
}

/// A flat JSON object whose key set is exactly `keys`, no key twice.
pub(crate) fn exact_object(bytes: &[u8], keys: &[&str]) -> Option<Map<String, Value>> {
    let Entries(entries) = serde_json::from_slice(bytes).ok()?;
    let mut object = Map::new();
    for (key, value) in entries {
        if object.insert(key, value).is_some() {
            return None;
        }
    }
    let mut present: Vec<_> = object.keys().map(String::as_str).collect();
    present.sort_unstable();
    let mut wanted = keys.to_vec();
    wanted.sort_unstable();
    (present == wanted).then_some(object)
}

/// The label of the allow-list entry, or the reason the read is an ordinary
/// unauthenticated one.
pub(crate) fn verify(
    header: Option<&str>,
    request: &Request<'_>,
    allow_list: &AllowList,
    now: OffsetDateTime,
) -> Result<String, &'static str> {
    let value = header.ok_or("missing")?;
    if value.len() > MAX_READ_AUTH_BYTES {
        return Err("malformed");
    }
    let bytes = decode_strict(value).ok_or("malformed")?;
    let object =
        exact_object(&bytes, &["issuedAt", "signature", "signerDid"]).ok_or("malformed")?;
    // Contract section 4.11 and section 2.2 rule (d): the decoded text, as
    // bytes, is the JCS of its own parsed value.
    if tinycloud_core::policy_capability::jcs::canonicalize(&Value::Object(object.clone())) != bytes
    {
        return Err("malformed");
    }
    let text = |name: &str| object[name].as_str().ok_or("malformed");
    let (issued_at, signature, signer_did) =
        (text("issuedAt")?, text("signature")?, text("signerDid")?);

    let key = did_key_ed25519(signer_did).ok_or("malformed")?;
    let label = allow_list
        .iter()
        .find(|(_, did)| did == signer_did)
        .map(|(label, _)| label.clone())
        .ok_or("unlisted-signer")?;
    // The verification rule of section 2.5 on the listed key.
    let point = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "malformed")?;
    if point.to_edwards().compress().to_bytes() != key {
        return Err("noncanonical-key");
    }
    if point.is_weak() || !is_canonical_prime_order(&key) {
        return Err("weak-key");
    }

    let issued = utc_millis(issued_at).ok_or("malformed")?;
    let window = time::Duration::seconds(READ_AUTH_WINDOW_SECS as i64);
    if issued < now - window {
        return Err("stale");
    }
    if issued > now + window {
        return Err("future");
    }

    let signature: [u8; 64] = decode_strict(signature)
        .filter(|_| signature.len() == 86)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("malformed")?;
    // S below the group order, compared most significant byte first.
    if !signature[32..].iter().rev().lt(L.iter().rev()) {
        return Err("non-canonical-signature");
    }
    let signed = read_auth_object(request.audience, issued_at, request.path, signer_did);
    let mut message = READ_AUTH_DOMAIN.to_vec();
    message.extend_from_slice(&tinycloud_core::policy_capability::jcs::canonicalize(&{
        let mut signed = signed;
        signed["method"] = json!(request.method);
        signed
    }));
    if crate::delivery_link::verify_strict_prime_order(&key, &Sha256::digest(message), &signature) {
        Ok(label)
    } else {
        Err("bad-signature")
    }
}

/// Everything logged on this thread while a test runs, as JSON lines.
#[derive(Clone, Default)]
pub(crate) struct Captured(pub Arc<parking_lot::Mutex<Vec<u8>>>);

impl Captured {
    /// Install a JSON subscriber that writes here until the guard drops.
    pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .json()
                .with_writer(self.clone())
                .with_max_level(tracing::Level::WARN)
                .finish(),
        )
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().clone()).unwrap()
    }
}

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

pub(crate) fn lines(captured: &Captured) -> Vec<Value> {
    captured
        .text()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
