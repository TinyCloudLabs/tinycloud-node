//! Canonical hashing used by decrypt invocations.
//!
//! `bodyHash` and `encryptedSymmetricKeyHash` are SHA-256 hashes of canonical
//! JSON bytes (objects emitted with lexicographically sorted keys). The output
//! is hex-encoded so it can travel through string-only JSON fields safely.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn hex(bytes: &[u8]) -> String {
    hex_lower(bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 of raw bytes, hex-encoded.
pub fn hash_hex(input: &[u8]) -> String {
    hex_lower(&Sha256::digest(input))
}

/// Canonicalize a JSON value to bytes with sorted object keys.
///
/// Arrays preserve order; numbers/strings/booleans/null serialize directly.
/// Objects are re-emitted with keys sorted lexicographically. This is *not* a
/// general dag-json canonicalizer — it exists only so request bodies hash
/// deterministically regardless of how the client serialized them.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

pub fn canonical_hash(value: &Value) -> String {
    hash_hex(&canonical_json_bytes(value))
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
        }
        Value::Number(n) => {
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => {
            // serde_json escaping suffices; Value::String round-trips.
            let encoded = serde_json::to_string(s).expect("string encoding");
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let encoded = serde_json::to_string(k).expect("key encoding");
                out.extend_from_slice(encoded.as_bytes());
                out.push(b':');
                write_canonical(&map[k], out);
            }
            out.push(b'}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_object_keys() {
        let a = json!({ "b": 1, "a": 2 });
        let b = json!({ "a": 2, "b": 1 });
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn canonical_preserves_array_order() {
        let a = json!([1, 2, 3]);
        let b = json!([3, 2, 1]);
        assert_ne!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn canonical_differs_for_nested_changes() {
        let a = json!({ "outer": { "x": 1 } });
        let b = json!({ "outer": { "x": 2 } });
        assert_ne!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn hash_hex_stable() {
        let h1 = hash_hex(b"hello");
        let h2 = hash_hex(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}
