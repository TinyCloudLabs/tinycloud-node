use super::{test_support::*, *};
use serde_json::json;
use tinycloud_core::libp2p::identity::ed25519;

const VECTORS: &str = include_str!("../../tests/fixtures/short-links-api-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap()
}

fn at(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

#[test]
fn link_grammar_vectors_hold_for_the_share_path() {
    let mut accepted = 0;
    let mut refused = 0;
    for vector in vectors()["links"].as_array().unwrap() {
        let href = text(vector, "href");
        let expect = &vector["expect"];
        let parsed = ShortLink::parse(href, ORIGIN);
        // The node takes the short form on the share path at its own origin,
        // and only the lowercase spelling of the id.
        let node_takes = expect["valid"] == true
            && expect["form"] == "short"
            && expect["pathType"] == "share"
            && href.starts_with(&format!("{ORIGIN}/s/{}#", text(expect, "id")));
        assert_eq!(parsed.is_some(), node_takes, "{}", vector["name"]);
        if let Some(link) = parsed {
            accepted += 1;
            assert_eq!(link.id().as_str(), text(expect, "id"));
            assert_eq!(link.cid(), text(expect, "c"));
            assert_eq!(link.key.to_vec(), decode_strict(text(expect, "k")).unwrap());
            assert_eq!(link.href(), href);
        } else {
            refused += 1;
        }
    }
    assert!(accepted >= 1 && refused >= 25, "{accepted} {refused}");
}

#[test]
fn oc_return_link_vectors_agree_with_the_node_grammar() {
    let vectors = vectors();
    let cases = vectors["deliveryAdmission"]["ocReturnLinks"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let origin = case["allowedOrigins"][0].as_str().unwrap();
        assert_eq!(
            ShortLink::parse(text(case, "returnLink"), origin).is_some(),
            case["expect"]["permits"] == true,
            "{}",
            case["name"]
        );
    }
}

#[test]
fn ed25519_strict_vectors() {
    let vectors = vectors();
    let cases = vectors["ed25519Strict"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for case in cases {
        let key: [u8; 32] = hex::decode(text(case, "publicKeyHex"))
            .unwrap()
            .try_into()
            .unwrap();
        let signature: [u8; 64] = hex::decode(text(case, "signatureHex"))
            .unwrap()
            .try_into()
            .unwrap();
        let message = hex::decode(text(case, "messageHex")).unwrap();
        assert_eq!(
            verify_strict_prime_order(&key, &message, &signature),
            case["expect"]["valid"] == true,
            "{}",
            case["name"]
        );
    }
}

fn fetched_from(record: &Value) -> FetchedLink {
    FetchedLink {
        record_header: record_header(
            &record["header"],
            record
                .get("signature")
                .map(|signature| text(signature, "value")),
        ),
        body: decode_config(text(record, "body"), URL_SAFE_NO_PAD).unwrap(),
    }
}

/// What the node does with a record behind a link: `Err(None)` when the link
/// grammar refuses, `Err(Some(_))` when a record check refuses.
fn node_outcome(link: &str, now: &str, record: &Value) -> Result<(), Option<LinkRefusal>> {
    let link = ShortLink::parse(link, ORIGIN).ok_or(None)?;
    let opened = open_link_record(&link, &fetched_from(record), at(now)).map_err(Some)?;
    let envelope: Value =
        serde_json::from_slice(&opened.plaintext).map_err(|_| Some(LinkRefusal::BodyOpenFailed))?;
    let issuer = opened.issuer.clone();
    opened
        .bind_issuer(
            envelope
                .pointer("/signature/signerDid")
                .and_then(Value::as_str),
            &issuer,
        )
        .map_err(Some)
}

fn check_vector(
    name: &Value,
    expect: &Value,
    record_type: &str,
    outcome: Result<(), Option<LinkRefusal>>,
) {
    let status = expect["status"].as_u64().unwrap();
    match (status, expect["reason"].as_str()) {
        (200, _) if record_type == "share" => assert_eq!(outcome, Ok(()), "{name}"),
        // The node takes `share` records only.
        (200, _) => assert!(outcome.is_err(), "{name}"),
        _ => {
            let refusal = outcome.expect_err(&name.to_string());
            if record_type == "share" {
                let expected = match expect["reason"].as_str().unwrap() {
                    "link_cid_mismatch" => Some(LinkRefusal::LinkCidMismatch),
                    "body_open_failed" => Some(LinkRefusal::BodyOpenFailed),
                    "issuer_binding_mismatch" => Some(LinkRefusal::IssuerBindingMismatch),
                    "body_hash_mismatch" => Some(LinkRefusal::BodyCidMismatch),
                    "bad_signature" => Some(LinkRefusal::BadSignature),
                    "unsigned_not_allowed" => Some(LinkRefusal::Unsigned),
                    // The node answers an expired link with its own 400.
                    "expired" => Some(LinkRefusal::Expired),
                    "size_mismatch" => Some(LinkRefusal::SizeMismatch),
                    "audience_format" => Some(LinkRefusal::RecordShape),
                    _ => None,
                };
                if let Some(expected) = expected {
                    assert_eq!(refusal, Some(expected), "{name}");
                }
            }
        }
    }
}

#[test]
fn resolve_vectors() {
    let vectors = vectors();
    let cases = vectors["resolve"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    let mut run = 0;
    for case in cases {
        let record = &case["serverRecord"];
        if record.is_null() {
            let link = text(case, "link");
            if link.contains("/s/full#") {
                // The full form is not accepted by this route.
                assert!(ShortLink::parse(link, ORIGIN).is_none(), "{}", case["name"]);
            } else {
                // No record: the API answers 404, which the route maps to
                // `delivery-link-unavailable` (route tests).
                assert_eq!(case["expect"]["status"], 404);
            }
            continue;
        }
        let header = &record["header"];
        run += 1;
        let record_type = text(header, "type");
        let outcome = node_outcome(text(case, "link"), text(case, "now"), record);
        check_vector(&case["name"], &case["expect"], record_type, outcome);
    }
    assert_eq!(run, 11);
}

#[test]
fn record_vectors() {
    let vectors = vectors();
    let cases = vectors["records"].as_array().unwrap();
    assert_eq!(cases.len(), 28);
    let mut limit_vectors = 0;
    for case in cases {
        let record = &case["record"];
        let header = &record["header"];
        if let Some(synthesized) = case.get("bodySynthesized") {
            // The body is `length` bytes of `fillByte` with byte 0 set to
            // `firstByte`, and is not opened: only the size, CID, signature
            // and expiry checks are exercised.
            limit_vectors += 1;
            let mut body = vec![
                synthesized["fillByte"].as_u64().unwrap() as u8;
                synthesized["length"].as_u64().unwrap() as usize
            ];
            body[0] = synthesized["firstByte"].as_u64().unwrap() as u8;
            let link = ShortLink::parse(
                &short_link(ORIGIN, LINK_ID, &TEST_KEY, text(header, "bodyCid")),
                ORIGIN,
            )
            .unwrap();
            let fetched = FetchedLink {
                record_header: record_header(header, Some(text(&record["signature"], "value"))),
                body,
            };
            let outcome = open_link_record(&link, &fetched, at(text(case, "now")));
            let expected = match (text(header, "type"), case["expect"]["status"].as_u64()) {
                // The node takes `share` records only.
                (record_type, _) if record_type != "share" => LinkRefusal::NotShare,
                // At the limit every check up to opening passes; the fill
                // bytes are not a sealed envelope.
                (_, Some(200)) => LinkRefusal::BodyOpenFailed,
                (_, Some(413)) => LinkRefusal::SizeMismatch,
                other => panic!("{other:?}"),
            };
            assert_eq!(outcome.unwrap_err(), expected, "{}", case["name"]);
            continue;
        }
        let key = decode_strict(text(case, "contentKeyB64u")).unwrap();
        let link = format!(
            "{ORIGIN}/s/{LINK_ID}#v=4&k={}&c={}",
            b64(&key),
            text(header, "bodyCid")
        );
        let outcome = node_outcome(&link, text(case, "now"), record);
        check_vector(
            &case["name"],
            &case["expect"],
            text(header, "type"),
            outcome,
        );
    }
    assert_eq!(limit_vectors, 6);
}

fn owner() -> ed25519::Keypair {
    ed25519::Keypair::generate()
}

fn open(built: &BuiltLink) -> Result<OpenedLink, LinkRefusal> {
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    open_link_record(&link, &built.fetched, at("2026-10-24T12:00:00.000Z"))
}

const FUTURE: &str = "2026-10-24T12:10:00.000Z";

#[test]
fn a_valid_signed_share_record_opens() {
    let signer = owner();
    let built = build(b"{\"k\":1}", &signer, FUTURE);
    let opened = open(&built).unwrap();
    assert_eq!(opened.plaintext, b"{\"k\":1}");
    assert_eq!(opened.issuer, did_of(&signer));
    assert_eq!(opened.expires_at, at(FUTURE));
}

fn resigned(built: &mut BuiltLink, signer: &ed25519::Keypair, edit: impl FnOnce(&mut Value)) {
    edit(&mut built.header);
    let signature = sign_header(&built.header, signer);
    built.fetched.record_header = record_header(&built.header, Some(&signature));
}

#[test]
fn step_one_refuses_a_record_that_is_not_a_strict_signed_share_header() {
    let signer = owner();
    let base = build(b"{}", &signer, FUTURE);
    let refuse = |built: &BuiltLink, expected: LinkRefusal| {
        assert_eq!(open(built).unwrap_err(), expected);
    };

    let mut unsigned = build(b"{}", &signer, FUTURE);
    unsigned.fetched.record_header = record_header(&unsigned.header, None);
    refuse(&unsigned, LinkRefusal::Unsigned);

    for other in ["courier", "openkey-login"] {
        let mut built = build(b"{}", &signer, FUTURE);
        resigned(&mut built, &signer, |header| header["type"] = json!(other));
        refuse(&built, LinkRefusal::NotShare);
    }

    // Everything below is a shape refusal, each signed so only the shape fails.
    let shape = |edit: &dyn Fn(&mut Value)| {
        let mut built = build(b"{}", &signer, FUTURE);
        resigned(&mut built, &signer, |header| edit(header));
        refuse(&built, LinkRefusal::RecordShape);
    };
    shape(&|header| header["version"] = json!(2));
    shape(&|header| header["type"] = json!("other"));
    shape(&|header| header["extra"] = json!(1));
    shape(&|header| {
        header.as_object_mut().unwrap().remove("nonce");
    });
    shape(&|header| header["size"] = json!(0));
    shape(&|header| header["size"] = json!(245.5));
    shape(&|header| header["size"] = json!("245"));
    shape(&|header| header["audience"] = json!("http://api.tinycloud.xyz"));
    shape(&|header| header["audience"] = json!("https://API.tinycloud.xyz"));
    shape(&|header| header["audience"] = json!("https://api.tinycloud.xyz/"));
    shape(&|header| header["issuedAt"] = json!("2026-10-24T12:00:00Z"));
    shape(&|header| header["expiresAt"] = json!("2026-02-30T12:00:00.000Z"));
    shape(&|header| header["expiresAt"] = json!("2026-10-24T12:10:00.000+00:00"));
    shape(&|header| header["nonce"] = json!("AAAA"));
    // The final character of a canonical 22-character nonce has zero trailing bits.
    shape(&|header| header["nonce"] = json!("BQUFBQUFBQUFBQUFBQUFBR"));
    shape(&|header| header["bodyCid"] = json!(raw_cid(b"x").to_uppercase()));
    shape(&|header| header["bodyCid"] = json!("bafkreiaaaa"));

    // Outside the header: the record object, the signature object, the encoding.
    let signature = sign_header(&base.header, &signer);
    let encode = |value: &Value| b64(value.to_string().as_bytes());
    let record = |edit: &dyn Fn(&mut Value)| {
        let mut value = json!({
            "header": base.header,
            "signature": {"algorithm": "Ed25519", "value": signature},
        });
        edit(&mut value);
        let mut built = build(b"{}", &signer, FUTURE);
        built.fetched.record_header = encode(&value);
        refuse(&built, LinkRefusal::RecordShape);
    };
    record(&|value| value["extra"] = json!(1));
    record(&|value| value["signature"]["extra"] = json!(1));
    record(&|value| value["signature"]["algorithm"] = json!("ES256"));
    record(&|value| value["signature"]["value"] = json!(&signature[..85]));
    record(&|value| value["signature"] = json!("x"));
    record(&|value| value["header"] = json!([]));
    let mut padded = build(b"{}", &signer, FUTURE);
    padded.fetched.record_header.push('=');
    refuse(&padded, LinkRefusal::RecordShape);
    let mut not_json = build(b"{}", &signer, FUTURE);
    not_json.fetched.record_header = b64(b"not json");
    refuse(&not_json, LinkRefusal::RecordShape);
    let mut huge = build(b"{}", &signer, FUTURE);
    huge.fetched.record_header = "A".repeat(MAX_LINK_RECORD_HEADER_BYTES + 1);
    refuse(&huge, LinkRefusal::RecordShape);
}

#[test]
fn step_two_binds_size_and_cid_to_the_header_and_the_link() {
    let signer = owner();
    let mut wrong_size = build(b"{}", &signer, FUTURE);
    resigned(&mut wrong_size, &signer, |header| {
        header["size"] = json!(header["size"].as_u64().unwrap() + 1)
    });
    assert_eq!(open(&wrong_size).unwrap_err(), LinkRefusal::SizeMismatch);

    let mut substituted = build(b"{}", &signer, FUTURE);
    substituted.fetched.body = seal(b"{\"other\":true}", &TEST_KEY, [7; SEALED_NONCE_BYTES]);
    resigned(&mut substituted, &signer, |header| {
        header["size"] = json!(substituted_len())
    });
    assert_eq!(
        open(&substituted).unwrap_err(),
        LinkRefusal::BodyCidMismatch
    );

    // The header and the body agree, the link's `c` does not.
    let built = build(b"{}", &signer, FUTURE);
    let other_cid = raw_cid(b"another body");
    let link =
        ShortLink::parse(&short_link(ORIGIN, LINK_ID, &TEST_KEY, &other_cid), ORIGIN).unwrap();
    assert_eq!(
        open_link_record(&link, &built.fetched, at("2026-10-24T12:00:00.000Z")).unwrap_err(),
        LinkRefusal::LinkCidMismatch
    );

    let mut oversize = build(&vec![b'a'; MAX_LINK_BODY_BYTES], &signer, FUTURE);
    assert!(oversize.sealed.len() > MAX_LINK_BODY_BYTES);
    assert_eq!(open(&oversize).unwrap_err(), LinkRefusal::SizeMismatch);
    oversize.fetched.body.truncate(10);
    assert_eq!(open(&oversize).unwrap_err(), LinkRefusal::SizeMismatch);
}

fn substituted_len() -> usize {
    seal(b"{\"other\":true}", &TEST_KEY, [7; SEALED_NONCE_BYTES]).len()
}

#[test]
fn step_three_verifies_the_header_signature_under_the_links_domain() {
    let signer = owner();
    let base = build(b"{}", &signer, FUTURE);

    let mut by_another_key = build(b"{}", &signer, FUTURE);
    let signature = sign_header(&base.header, &owner());
    by_another_key.fetched.record_header = record_header(&base.header, Some(&signature));
    assert_eq!(
        open(&by_another_key).unwrap_err(),
        LinkRefusal::BadSignature
    );

    // A header edited after signing.
    let mut edited = build(b"{}", &signer, FUTURE);
    let signature = sign_header(&edited.header, &signer);
    edited.header["expiresAt"] = json!("2026-10-24T12:09:00.000Z");
    edited.fetched.record_header = record_header(&edited.header, Some(&signature));
    assert_eq!(open(&edited).unwrap_err(), LinkRefusal::BadSignature);

    // The same bytes signed under another domain never verify here.
    let mut wrong_domain = build(b"{}", &signer, FUTURE);
    let mut other = b"xyz.tinycloud.links/delete/v1\0".to_vec();
    other.extend_from_slice(&tinycloud_core::policy_capability::jcs::canonicalize(
        &base.header,
    ));
    let signature = b64(&signer.sign(&Sha256::digest(other)));
    wrong_domain.fetched.record_header = record_header(&base.header, Some(&signature));
    assert_eq!(open(&wrong_domain).unwrap_err(), LinkRefusal::BadSignature);

    // A key the signature was not made by, a service issuer and a non-Ed25519
    // DID are refused before any signature is tried.
    for issuer in [
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        "service:openkey",
        "did:web:example.com",
        "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22Sx",
    ] {
        let mut built = build(b"{}", &signer, FUTURE);
        built.header["issuer"] = json!(issuer);
        let signature = sign_header(&built.header, &signer);
        built.fetched.record_header = record_header(&built.header, Some(&signature));
        assert_eq!(
            open(&built).unwrap_err(),
            LinkRefusal::BadSignature,
            "{issuer}"
        );
    }
    let identity = {
        use tinycloud_auth::ipld_core::cid::multibase::{self, Base};
        let mut bytes = vec![0xed, 0x01, 0x01];
        bytes.extend_from_slice(&[0; 31]);
        format!("did:key:{}", multibase::encode(Base::Base58Btc, bytes))
    };
    let mut weak = build(b"{}", &signer, FUTURE);
    weak.header["issuer"] = json!(identity);
    let mut forged = vec![0x01];
    forged.extend_from_slice(&[0; 63]);
    weak.fetched.record_header = record_header(&weak.header, Some(&b64(&forged)));
    assert_eq!(open(&weak).unwrap_err(), LinkRefusal::BadSignature);
}

#[test]
fn step_four_refuses_a_link_that_is_not_in_the_future() {
    let signer = owner();
    let built = build(b"{}", &signer, FUTURE);
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    let at_expiry = |now: &str| open_link_record(&link, &built.fetched, at(now));
    assert!(at_expiry("2026-10-24T12:09:59.999Z").is_ok());
    assert_eq!(at_expiry(FUTURE).unwrap_err(), LinkRefusal::Expired);
    assert_eq!(
        at_expiry("2026-10-24T12:10:00.001Z").unwrap_err(),
        LinkRefusal::Expired
    );

    // The link cannot outlive the share.
    let opened = open(&built).unwrap();
    assert!(opened.within_share_expiry(at(FUTURE)).is_ok());
    assert_eq!(
        opened
            .within_share_expiry(at("2026-10-24T12:09:59.999Z"))
            .unwrap_err(),
        LinkRefusal::Expired
    );
}

#[test]
fn step_five_needs_the_key_in_the_link() {
    let signer = owner();
    let built = build(b"{}", &signer, FUTURE);
    let link = ShortLink::parse(
        &short_link(ORIGIN, LINK_ID, &[0x5b; 32], &raw_cid(&built.sealed)),
        ORIGIN,
    )
    .unwrap();
    assert_eq!(
        open_link_record(&link, &built.fetched, at("2026-10-24T12:00:00.000Z")).unwrap_err(),
        LinkRefusal::BodyOpenFailed
    );

    // A body that is not a sealed envelope (wrong version byte, too short).
    for body in [
        {
            let mut sealed = built.sealed.clone();
            sealed[0] = 2;
            sealed
        },
        built.sealed[..29].to_vec(),
    ] {
        let mut broken = build(b"{}", &signer, FUTURE);
        broken.fetched.body = body.clone();
        resigned(&mut broken, &signer, |header| {
            header["size"] = json!(body.len());
            header["bodyCid"] = json!(raw_cid(&body));
        });
        let link = ShortLink::parse(
            &short_link(ORIGIN, LINK_ID, &TEST_KEY, &raw_cid(&body)),
            ORIGIN,
        )
        .unwrap();
        assert_eq!(
            open_link_record(&link, &broken.fetched, at("2026-10-24T12:00:00.000Z")).unwrap_err(),
            LinkRefusal::BodyOpenFailed
        );
    }
}

#[test]
fn checks_run_in_the_contract_order() {
    let signer = owner();
    let now = at("2026-10-24T12:00:00.000Z");
    // Unsigned before everything else, even a body that does not match.
    let mut built = build(b"{}", &signer, FUTURE);
    built.fetched.record_header = record_header(&built.header, None);
    built.fetched.body[3] ^= 1;
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    assert_eq!(
        open_link_record(&link, &built.fetched, now).unwrap_err(),
        LinkRefusal::Unsigned
    );
    // CID before signature.
    let mut built = build(b"{}", &signer, FUTURE);
    built.fetched.body[3] ^= 1;
    built.fetched.record_header = record_header(&built.header, Some(&b64(&[1; 64])));
    assert_eq!(
        open_link_record(&link, &built.fetched, now).unwrap_err(),
        LinkRefusal::BodyCidMismatch
    );
    // Signature before expiry.
    let built = build(b"{}", &signer, "2026-10-24T11:00:00.000Z");
    let fetched = FetchedLink {
        record_header: record_header(&built.header, Some(&b64(&[1; 64]))),
        body: built.fetched.body.clone(),
    };
    assert_eq!(
        open_link_record(&link, &fetched, now).unwrap_err(),
        LinkRefusal::BadSignature
    );
    // Expiry before opening the body.
    let link_wrong_key = ShortLink::parse(
        &short_link(ORIGIN, LINK_ID, &[1; 32], &raw_cid(&built.sealed)),
        ORIGIN,
    )
    .unwrap();
    assert_eq!(
        open_link_record(&link_wrong_key, &built.fetched, now).unwrap_err(),
        LinkRefusal::Expired
    );
}

#[test]
fn the_issuer_must_be_the_envelope_signer_and_the_registration_owner() {
    let signer = owner();
    let opened = open(&build(b"{}", &signer, FUTURE)).unwrap();
    let issuer = opened.issuer.clone();
    assert!(opened.bind_issuer(Some(&issuer), &issuer).is_ok());
    assert!(opened.bind_issuer(Some("did:key:zOther"), &issuer).is_err());
    assert!(opened.bind_issuer(Some(&issuer), "did:key:zOther").is_err());
    assert!(opened.bind_issuer(None, &issuer).is_err());
}

#[test]
fn the_key_never_appears_in_debug_output() {
    let signer = owner();
    let built = build(b"{}", &signer, FUTURE);
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    let opened = open(&built).unwrap();
    for rendered in [
        format!("{link:?}"),
        format!("{opened:?}"),
        format!("{:?}", LinkRefusal::BadSignature),
    ] {
        assert!(!rendered.contains(&b64(&TEST_KEY)), "{rendered}");
        assert!(!rendered.contains("#v=4"), "{rendered}");
    }
}

#[test]
fn only_the_exact_short_share_link_at_the_configured_origin_parses() {
    let cid = raw_cid(b"body");
    let good = short_link(ORIGIN, LINK_ID, &TEST_KEY, &cid);
    assert!(ShortLink::parse(&good, ORIGIN).is_some());
    let refused = [
        good.replace("/s/", "/c/"),
        good.replace("/s/", "/l/"),
        good.replace("#v=4", "#v=3"),
        good.replace("#v=4", "#v=2"),
        good.replace("https://share.tinycloud.xyz", "https://share.example"),
        good.replace("https://", "http://"),
        format!("{good}&x=1"),
        format!("{good} "),
        format!(" {good}"),
        good.replace("#v=4", "?q=1#v=4"),
        good.replace(LINK_ID, &LINK_ID.to_uppercase()),
        good.replace(LINK_ID, "lqdw5iopqq2tkkvjj6gbbi5vb"),
        format!("{ORIGIN}/s/full#v=4&k={}&r=AAAA", b64(&TEST_KEY)),
        format!("{ORIGIN}/s/{cid}#k={}", b64(&TEST_KEY)),
        format!("{ORIGIN}/s/inline#v=2&p=eyJ2IjoyfQ"),
        good.replace("&c=", "&c=B"),
        format!("{ORIGIN}:443/s/{LINK_ID}#v=4&k={}&c={cid}", b64(&TEST_KEY)),
        String::new(),
    ];
    for link in refused {
        assert!(ShortLink::parse(&link, ORIGIN).is_none(), "{link}");
    }
    // A key with a second spelling.
    let mut spelled = b64(&TEST_KEY);
    spelled.replace_range(42.., "p");
    assert!(ShortLink::parse(
        &format!("{ORIGIN}/s/{LINK_ID}#v=4&k={spelled}&c={cid}"),
        ORIGIN
    )
    .is_none());
}

#[test]
fn the_limits_are_the_contracts() {
    let vectors = vectors();
    let fetch = &vectors["sizes"]["nodeFetch"];
    assert_eq!(vectors["constants"]["maxLinkBodyBytes"], 65_536);
    assert_eq!(MAX_LINK_BODY_BYTES as u64, fetch["maxBodyBytes"]);
    assert_eq!(
        MAX_LINK_RECORD_HEADER_BYTES as u64,
        fetch["maxRecordHeaderBytes"]
    );
    assert_eq!(
        crate::links_fetch::LINK_TOTAL_TIMEOUT.as_millis() as u64,
        fetch["totalTimeoutMs"]
    );
    assert_eq!(fetch["redirects"], 0);
    assert_eq!(fetch["retries"], 0);
    assert_eq!(vectors["constants"]["minBodyBytes"], 30);
    assert_eq!(MIN_SEALED_BYTES, 30);
    assert_eq!(vectors["constants"]["ocReturnLinkMaxBytes"], 512);
    assert_eq!(MAX_LINK_BYTES, 512);
}

#[test]
fn a_sealed_body_of_exactly_the_limit_opens_and_one_byte_more_does_not() {
    let signer = owner();
    // The sealed body is the plaintext plus the version byte, nonce and tag.
    let overhead = 1 + SEALED_NONCE_BYTES + SEALED_TAG_BYTES;
    let at_limit = build(&vec![b'a'; MAX_LINK_BODY_BYTES - overhead], &signer, FUTURE);
    assert_eq!(at_limit.sealed.len(), MAX_LINK_BODY_BYTES);
    assert!(open(&at_limit).is_ok());
    let over = build(
        &vec![b'a'; MAX_LINK_BODY_BYTES - overhead + 1],
        &signer,
        FUTURE,
    );
    assert_eq!(over.sealed.len(), MAX_LINK_BODY_BYTES + 1);
    assert_eq!(open(&over).unwrap_err(), LinkRefusal::SizeMismatch);
}
