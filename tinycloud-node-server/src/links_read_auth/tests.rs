use super::{test_support::*, *};
use base64::decode_config;
use time::format_description::well_known::Rfc3339;
use tinycloud_core::libp2p::identity::{ed25519, Keypair};

const VECTORS: &str = include_str!("../../tests/fixtures/short-links-api-vectors.json");

fn group() -> Value {
    serde_json::from_str::<Value>(VECTORS).unwrap()["nodeReadAuth"].clone()
}

fn at(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

fn allow_list(value: &Value) -> AllowList {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["label"].as_str().unwrap().to_owned(),
                entry["did"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// The vectors' TEST ONLY node identity: seed 0x33 repeated.
fn test_node(group: &Value) -> (Keypair, String) {
    let seed: [u8; 32] = hex::decode(group["signer"]["seedHex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let keypair = Keypair::from(ed25519::Keypair::from(
        ed25519::SecretKey::try_from_bytes(seed).unwrap(),
    ));
    let did = tinycloud_core::keys::public_key_to_did_key(keypair.public());
    assert_eq!(did, group["signer"]["did"].as_str().unwrap());
    (keypair, did)
}

#[test]
fn the_constants_are_the_contracts() {
    let group = group();
    assert_eq!(
        READ_AUTH_DOMAIN,
        group["domain"].as_str().unwrap().as_bytes()
    );
    assert_eq!(READ_AUTH_DOMAIN.last(), Some(&0));
    assert!(group["headerName"]
        .as_str()
        .unwrap()
        .eq_ignore_ascii_case(READ_AUTH_HEADER));
    assert_eq!(group["windowSeconds"], READ_AUTH_WINDOW_SECS);
    assert_eq!(group["headerMaxBytes"], MAX_READ_AUTH_BYTES);
}

#[test]
fn every_node_read_auth_row_gets_its_expected_answer_and_the_nodes_signer_reproduces_the_valid_ones(
) {
    let group = group();
    let rows = group["vectors"].as_array().unwrap();
    assert_eq!(rows.len(), 19);
    let (keypair, did) = test_node(&group);
    let now = at(group["serviceNow"].as_str().unwrap());
    let mut signed_rows = 0;
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let request = Request {
            method: row["request"]["method"].as_str().unwrap(),
            path: row["request"]["path"].as_str().unwrap(),
            audience: row["request"]["audience"].as_str().unwrap(),
        };
        let listed = allow_list(row.get("allowList").unwrap_or(&group["allowList"]));
        let header = row["headerValue"].as_str();
        let got = verify(header, &request, &listed, now);
        let expect = &row["expect"];
        if expect["authenticated"] == true {
            assert_eq!(
                got,
                Ok(expect["label"].as_str().unwrap().to_owned()),
                "{name}"
            );
        } else {
            assert_eq!(got, Err(expect["reason"].as_str().unwrap()), "{name}");
        }

        // The signed bytes, wherever the row gives them.
        if let Some(object) = row["signed"]
            .get("object")
            .filter(|object| object.is_object())
        {
            let jcs = tinycloud_core::policy_capability::jcs::canonicalize(object);
            assert_eq!(
                String::from_utf8(jcs).unwrap(),
                row["signed"]["jcs"].as_str().unwrap(),
                "{name}"
            );
        }

        // The valid rows: the node's signer writes the same signature and the
        // same header, byte for byte.
        if expect["authenticated"] == true {
            signed_rows += 1;
            let issued_at = row["header"]["issuedAt"].as_str().unwrap();
            let object = read_auth_object(request.audience, issued_at, request.path, &did);
            assert_eq!(object, row["signed"]["object"], "{name}");
            let mut preimage = READ_AUTH_DOMAIN.to_vec();
            preimage.extend_from_slice(&tinycloud_core::policy_capability::jcs::canonicalize(
                &object,
            ));
            assert_eq!(
                hex::encode(&preimage),
                row["signed"]["preimageHex"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                hex::encode(Sha256::digest(&preimage)),
                row["signed"]["digestHex"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                encode_config(read_auth_signature(&keypair, &object), URL_SAFE_NO_PAD),
                row["header"]["signature"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                read_auth_header_value(&keypair, &did, request.audience, request.path, issued_at),
                header.unwrap(),
                "{name}"
            );
        }
    }
    assert_eq!(signed_rows, 4);
}

#[test]
fn the_nodes_signer_writes_a_bounded_three_field_header_the_api_accepts() {
    let secret = StaticSecret::new(vec![9; 32]).unwrap();
    let did = secret.node_did();
    let signer = ReadSigner::new(secret);
    let now = at("2026-10-24T12:00:00.123Z");
    let audience = "https://api.tinycloud.xyz";
    let path = "/v1/links/lqdw5iopqq2tkkvjj6gbbi5vbv";
    let value = signer.header_value(audience, path, now);
    assert!(value.len() <= MAX_READ_AUTH_BYTES, "{}", value.len());
    let bytes = decode_config(&value, URL_SAFE_NO_PAD).unwrap();
    let object = exact_object(&bytes, &["issuedAt", "signature", "signerDid"]).unwrap();
    assert_eq!(object["issuedAt"], "2026-10-24T12:00:00.123Z");
    assert_eq!(object["signerDid"], did.as_str());
    // The text is its own JCS: no spaces, keys in order.
    assert_eq!(
        bytes,
        tinycloud_core::policy_capability::jcs::canonicalize(&Value::Object(object))
    );

    let listed = vec![("service:node".to_owned(), did)];
    let request = |path| Request {
        method: "GET",
        path,
        audience,
    };
    assert_eq!(
        verify(Some(&value), &request(path), &listed, now),
        Ok("service:node".into())
    );
    // Bound to its path, its audience, its method and its window.
    assert_eq!(
        verify(
            Some(&value),
            &request("/v1/links/22222222222222222222222222"),
            &listed,
            now
        ),
        Err("bad-signature")
    );
    assert_eq!(
        verify(
            Some(&value),
            &Request {
                method: "GET",
                path,
                audience: "https://api.example"
            },
            &listed,
            now
        ),
        Err("bad-signature")
    );
    assert_eq!(
        verify(
            Some(&value),
            &Request {
                method: "POST",
                path,
                audience
            },
            &listed,
            now
        ),
        Err("bad-signature")
    );
    assert_eq!(
        verify(
            Some(&value),
            &request(path),
            &listed,
            now + time::Duration::seconds(121)
        ),
        Err("stale")
    );
    assert_eq!(
        verify(Some(&value), &request(path), &Vec::new(), now),
        Err("unlisted-signer")
    );
    // The value holds a signature, a time and the public DID.
    assert!(!String::from_utf8(bytes).unwrap().contains("seed"));
}

#[test]
fn a_header_with_an_extra_key_a_proto_key_or_a_repeated_key_is_malformed() {
    let group = group();
    let (keypair, did) = test_node(&group);
    let now = at(group["serviceNow"].as_str().unwrap());
    let audience = "https://api.tinycloud.xyz";
    let path = "/v1/links/lqdw5iopqq2tkkvjj6gbbi5vbv";
    let issued_at = "2026-10-24T12:00:00.000Z";
    let signature = encode_config(
        read_auth_signature(&keypair, &read_auth_object(audience, issued_at, path, &did)),
        URL_SAFE_NO_PAD,
    );
    let text = |extra: &str, repeat: &str| {
        format!(
            r#"{{{extra}"issuedAt":"{issued_at}",{repeat}"signature":"{signature}","signerDid":"{did}"}}"#
        )
    };
    let listed = vec![("service:node".to_owned(), did.clone())];
    let request = Request {
        method: "GET",
        path,
        audience,
    };
    let check = |text: String| {
        verify(
            Some(&encode_config(text.as_bytes(), URL_SAFE_NO_PAD)),
            &request,
            &listed,
            now,
        )
    };
    assert_eq!(check(text("", "")), Ok("service:node".into()));
    assert_eq!(check(text(r#""extra":1,"#, "")), Err("malformed"));
    assert_eq!(check(text(r#""__proto__":{"x":1},"#, "")), Err("malformed"));
    assert_eq!(check(text(r#""__proto__":"x","#, "")), Err("malformed"));
    // The same key twice, the last one the signed value: the object is refused.
    assert_eq!(
        check(text("", r#""issuedAt":"2026-10-24T12:00:00.000Z","#)),
        Err("malformed")
    );
    assert_eq!(
        check(text(r#""signerDid":"did:key:z6MkOther","#, "")),
        Err("malformed")
    );
}

#[test]
fn a_header_text_that_is_not_its_own_jcs_or_starts_with_a_byte_order_mark_is_malformed() {
    let group = group();
    let (keypair, did) = test_node(&group);
    let now = at(group["serviceNow"].as_str().unwrap());
    let audience = "https://api.tinycloud.xyz";
    let path = "/v1/links/lqdw5iopqq2tkkvjj6gbbi5vbv";
    let issued_at = "2026-10-24T12:00:00.000Z";
    let signature = encode_config(
        read_auth_signature(&keypair, &read_auth_object(audience, issued_at, path, &did)),
        URL_SAFE_NO_PAD,
    );
    let listed = vec![("service:node".to_owned(), did.clone())];
    let request = Request {
        method: "GET",
        path,
        audience,
    };
    let check = |bytes: &[u8]| {
        verify(
            Some(&encode_config(bytes, URL_SAFE_NO_PAD)),
            &request,
            &listed,
            now,
        )
    };
    let canonical =
        format!(r#"{{"issuedAt":"{issued_at}","signature":"{signature}","signerDid":"{did}"}}"#);
    assert_eq!(check(canonical.as_bytes()), Ok("service:node".into()));
    // The node's own writer produces exactly the canonical text.
    assert_eq!(
        read_auth_header_value(&keypair, &did, audience, path, issued_at),
        encode_config(canonical.as_bytes(), URL_SAFE_NO_PAD)
    );

    let bom = [0xEF, 0xBB, 0xBF];
    assert_eq!(
        check(&[bom.as_slice(), canonical.as_bytes()].concat()),
        Err("malformed")
    );
    assert_eq!(
        check(&[canonical.as_bytes(), bom.as_slice()].concat()),
        Err("malformed")
    );
    let spaced = canonical.replacen(',', ", ", 1);
    let reordered =
        format!(r#"{{"signature":"{signature}","issuedAt":"{issued_at}","signerDid":"{did}"}}"#);
    let escaped_key = canonical.replacen("issuedAt", r"\u0069ssuedAt", 1);
    for text in [
        spaced,
        format!(" {canonical}"),
        format!("{canonical}\n"),
        reordered,
        escaped_key,
    ] {
        assert_eq!(check(text.as_bytes()), Err("malformed"), "{text}");
    }
}

#[test]
fn a_clock_off_by_more_than_a_minute_is_counted_and_logged_once_a_minute() {
    let captured = Captured::default();
    let _subscriber = captured.install();
    let skew = ClockSkew::default();
    let node = at("2026-10-24T12:00:00.000Z");
    let t0 = Instant::now();
    let date = |text: &str| Some(text.to_owned());
    let ahead = date("Sat, 24 Oct 2026 12:03:00 GMT");
    let on_time = date("Sat, 24 Oct 2026 12:00:30 GMT");

    // Inside a minute either way: nothing.
    assert_eq!(skew.observe(on_time.as_deref(), node, t0), None);
    assert_eq!(
        skew.observe(date("Sat, 24 Oct 2026 11:59:00 GMT").as_deref(), node, t0),
        None
    );
    assert_eq!(
        skew.observe(date("Sat, 24 Oct 2026 12:01:00 GMT").as_deref(), node, t0),
        None
    );
    // No `Date`, or one that is not a date: nothing.
    assert_eq!(skew.observe(None, node, t0), None);
    assert_eq!(skew.observe(Some("yesterday"), node, t0), None);
    assert_eq!(skew.observe(Some(""), node, t0), None);
    assert!(lines(&captured).is_empty());

    // The API is three minutes ahead: the node's clock minus the API's.
    assert_eq!(skew.observe(ahead.as_deref(), node, t0), Some(-180_000));
    // And the node can be the one ahead.
    assert_eq!(
        skew.observe(
            date("Sat, 24 Oct 2026 11:58:00 GMT").as_deref(),
            node,
            t0 + Duration::from_secs(10)
        ),
        Some(120_000)
    );
    // Many observations inside the minute: one line, from the first.
    for second in 1..30 {
        skew.observe(ahead.as_deref(), node, t0 + Duration::from_secs(second));
    }
    let first = lines(&captured);
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0]["level"], "WARN");
    assert_eq!(first[0]["fields"]["event"], "links_read_clock_skew");
    assert_eq!(first[0]["fields"]["skew_ms"], -180_000);
    assert_eq!(first[0]["fields"]["window_s"], 120);
    let mut keys: Vec<_> = first[0]["fields"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(keys, ["event", "message", "skew_ms", "window_s"]);

    // A minute later the next one logs.
    skew.observe(ahead.as_deref(), node, t0 + Duration::from_secs(61));
    assert_eq!(lines(&captured).len(), 2);
    // Inside the second minute, none.
    skew.observe(ahead.as_deref(), node, t0 + Duration::from_secs(90));
    assert_eq!(lines(&captured).len(), 2);
}

#[test]
fn the_threshold_is_sixty_seconds_exclusive() {
    let skew = ClockSkew::default();
    let node = at("2026-10-24T12:00:00.000Z");
    let t0 = Instant::now();
    // `Date` has whole-second resolution: exactly 60 s is not over the line.
    assert_eq!(
        skew.observe(Some("Sat, 24 Oct 2026 12:01:00 GMT"), node, t0),
        None
    );
    assert_eq!(
        skew.observe(Some("Sat, 24 Oct 2026 12:01:01 GMT"), node, t0),
        Some(-61_000)
    );
    assert_eq!(
        skew.observe(Some("Sat, 24 Oct 2026 11:59:00 GMT"), node, t0),
        None
    );
    assert_eq!(
        skew.observe(Some("Sat, 24 Oct 2026 11:58:59 GMT"), node, t0),
        Some(61_000)
    );
}
