// JCS (RFC 8785) canonicalizer over `serde_json::Value`.
//
// Implements the subset needed by the W0 PolicyCapability vectors:
//   * Object keys sorted by UTF-16 code unit order (matches RFC 8785).
//   * No whitespace between tokens.
//   * Strings encoded per JSON, escaping the JSON-required control chars.
//   * Numbers serialized by the Ryū algorithm via serde_json (sufficient for
//     the integer indices in our vectors; the policy boundary rejects
//     non-numeric caveats).
//
// The output is the UTF-8 byte representation of the canonical JSON string,
// per RFC 8785 §3.1.

use serde_json::Value;

pub fn canonicalize(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => write_number(n, out),
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Collect & sort keys by UTF-16 code units.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| cmp_utf16(a.0, b.0));
            out.push(b'{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(val, out);
            }
            out.push(b'}');
        }
    }
}

fn write_number(value: &serde_json::Number, out: &mut Vec<u8>) {
    if let Some(value) = value.as_i64() {
        out.extend_from_slice(value.to_string().as_bytes());
        return;
    }
    if let Some(value) = value.as_u64() {
        out.extend_from_slice(value.to_string().as_bytes());
        return;
    }
    let Some(value) = value.as_f64() else {
        return;
    };
    let mut buffer = ryu_js::Buffer::new();
    out.extend_from_slice(buffer.format(value).as_bytes());
}

fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                non_eq => return non_eq,
            },
        }
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let s = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(s.as_bytes());
            }
            c => {
                // Append UTF-8 bytes of the character.
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 1, "a": [3, 2, 1], "c": {"y": 2, "x": 1}});
        let canon = canonicalize(&v);
        assert_eq!(
            std::str::from_utf8(&canon).unwrap(),
            r#"{"a":[3,2,1],"b":1,"c":{"x":1,"y":2}}"#
        );
    }

    #[test]
    fn nfc_path_round_trips_in_string() {
        // The "café" example from the policy capability vector encodes the
        // precomposed é (0xc3 0xa9) — the JCS encoder must emit raw UTF-8.
        let v = json!({"x": "café"});
        let canon = canonicalize(&v);
        let want: Vec<u8> = b"{\"x\":\"caf\xc3\xa9\"}".to_vec();
        assert_eq!(canon, want);
    }

    #[test]
    fn canonicalizes_numbers_at_ecmascript_thresholds() {
        for (raw, expected) in [
            ("-0.0", "0"),
            ("100000000000000000000", "100000000000000000000"),
            ("1000000000000000000000", "1e+21"),
            ("0.000001", "0.000001"),
            ("0.0000001", "1e-7"),
            ("333333333.33333329", "333333333.3333333"),
        ] {
            let value: Value = serde_json::from_str(raw).unwrap();
            assert_eq!(
                std::str::from_utf8(&canonicalize(&value)).unwrap(),
                expected
            );
        }
    }
}
