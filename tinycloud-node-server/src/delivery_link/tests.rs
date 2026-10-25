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

#[test]
fn a_non_canonical_spelling_of_a_low_y_point_is_not_an_accepted_key() {
    use ed25519_dalek::VerifyingKey;
    // `y < 19` has a second spelling `y + p` below 2^255, with p = 2^255 - 19
    // (little-endian: 0xed, 0xff x 30, 0x7f). dalek decompresses both.
    let canonical = |y: u8| {
        let mut bytes = [0_u8; 32];
        bytes[0] = y;
        bytes
    };
    let spelled_with_p = |y: u8| {
        let mut bytes = [0xff_u8; 32];
        bytes[0] = 0xed + y;
        bytes[31] = 0x7f;
        bytes
    };
    let mut on_curve = vec![];
    for y in 3..=18_u8 {
        let Ok(key) = VerifyingKey::from_bytes(&canonical(y)) else {
            continue;
        };
        // Both spellings are the same point, and it is not a small-order one:
        // a weak-key check alone would keep it.
        let other =
            VerifyingKey::from_bytes(&spelled_with_p(y)).expect("the p + y spelling decompresses");
        assert_eq!(key.to_edwards(), other.to_edwards(), "y = {y}");
        assert!(!key.is_weak(), "y = {y}");
        assert!(!is_canonical_prime_order(&spelled_with_p(y)), "p + {y}");
        assert!(!is_canonical_prime_order(&canonical(y)), "{y}");
        on_curve.push(y);
    }
    // y = 3 is one of them, so the loop is not vacuous.
    assert!(on_curve.contains(&3), "{on_curve:?}");
    // None of these low-y points has order exactly the group order, so for
    // them the torsion check and the canonical-spelling check agree; the
    // spelling check is the one that also covers a prime-order point if one
    // is ever spelled this way.
    // A signature under such a key is refused as a whole.
    let signature = [0x42_u8; 64];
    assert!(!verify_strict_prime_order(
        &spelled_with_p(3),
        b"m",
        &signature
    ));
}

#[test]
fn a_key_with_a_torsion_component_is_refused_though_it_is_not_a_weak_key() {
    use ed25519_dalek::VerifyingKey;
    let signer = ed25519::Keypair::generate();
    let key_bytes: [u8; 32] = signer.public().to_bytes();
    let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    assert!(
        is_canonical_prime_order(&key_bytes),
        "an ordinary key is accepted"
    );

    // T2, the point of order two: (0, -1), y = p - 1.
    let mut order_two = [0xff_u8; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    let t2 = VerifyingKey::from_bytes(&order_two).unwrap();
    assert!(t2.is_weak());

    // A + T2 has order 2 * l: it is canonical and not small-order, and only
    // the torsion check refuses it.
    let mixed = VerifyingKey::from(key.to_edwards() + t2.to_edwards());
    assert!(!mixed.is_weak());
    assert_eq!(
        mixed.to_edwards().compress().to_bytes(),
        mixed.to_bytes(),
        "the sum is spelled canonically"
    );
    assert!(!mixed.to_edwards().is_torsion_free());
    assert!(!is_canonical_prime_order(&mixed.to_bytes()));
    assert!(!verify_strict_prime_order(
        &mixed.to_bytes(),
        b"m",
        &[0x42; 64]
    ));
}

#[test]
fn a_non_canonical_cid_spelling_and_impossible_dates_are_refused_without_a_panic() {
    let signer = owner();
    let refuse_header = |edit: &dyn Fn(&mut Value)| {
        let mut built = build(b"{}", &signer, FUTURE);
        resigned(&mut built, &signer, |header| edit(header));
        assert_eq!(open(&built).unwrap_err(), LinkRefusal::RecordShape);
    };
    // The last base32 character of a sha2-256 CID carries two bits that must
    // be zero: the same bytes spelled with the next character are a second
    // spelling of one CID.
    let cid = raw_cid(&build(b"{}", &signer, FUTURE).sealed);
    let (head, last) = cid.split_at(cid.len() - 1);
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let index = alphabet.find(last).unwrap();
    assert_eq!(
        index % 4,
        0,
        "the canonical last character has zero low bits"
    );
    let second_spelling = format!("{head}{}", &alphabet[index + 1..index + 2]);
    refuse_header(&|header| header["bodyCid"] = json!(second_spelling));

    for (field, date) in [
        ("issuedAt", "2026-13-24T12:00:00.000Z"),
        ("expiresAt", "2026-13-24T12:10:00.000Z"),
        ("issuedAt", "2026-02-30T12:00:00.000Z"),
        ("expiresAt", "2026-02-30T12:10:00.000Z"),
        ("expiresAt", "2026-10-24T24:00:00.000Z"),
        ("expiresAt", "2026-10-24T12:60:00.000Z"),
        ("expiresAt", "0000-00-00T00:00:00.000Z"),
        ("expiresAt", "9999-12-31T23:59:59.999Z-"),
    ] {
        refuse_header(&|header| header[field] = json!(date));
    }
}

#[test]
fn a_proto_key_or_any_extra_key_makes_the_header_a_refused_shape() {
    let signer = owner();
    let built = build(b"{}", &signer, FUTURE);
    let signature = sign_header(&built.header, &signer);
    // Raw JSON text, as a JavaScript `JSON.parse` would see it: `__proto__`
    // is an ordinary own key here.
    let canonical = |value: &Value| {
        String::from_utf8(tinycloud_core::policy_capability::jcs::canonicalize(value)).unwrap()
    };
    let header = canonical(&built.header);
    let signature_object = canonical(&json!({"algorithm": "Ed25519", "value": signature}));
    let with = |header_text: &str, signature_text: &str, outer: &str| {
        let text = format!(r#"{{{outer}"header":{header_text},"signature":{signature_text}}}"#);
        FetchedLink {
            record_header: b64(text.as_bytes()),
            body: built.fetched.body.clone(),
        }
    };
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    let now = at("2026-10-24T12:00:00.000Z");
    // The unmodified text opens, so each refusal below is the extra key.
    assert!(open_link_record(&link, &with(&header, &signature_object, ""), now).is_ok());
    let proto_header = header.replacen('{', r#"{"__proto__":{"x":1},"#, 1);
    let proto_signature = signature_object.replacen('{', r#"{"__proto__":{"x":1},"#, 1);
    for fetched in [
        with(&proto_header, &signature_object, ""),
        with(&header, &proto_signature, ""),
        with(&header, &signature_object, r#""__proto__":{"x":1},"#),
        with(
            &header.replacen('{', r#"{"extra":1,"#, 1),
            &signature_object,
            "",
        ),
    ] {
        assert_eq!(
            open_link_record(&link, &fetched, now).unwrap_err(),
            LinkRefusal::RecordShape
        );
    }
}

/// The record text must be the JCS of its own parsed value (contract section
/// 2.2 rule (d)): a duplicate key at any depth, whitespace, another key order
/// or another spelling of a character is a refused shape, though the parsed
/// value (and so the signature check) would be the same.
#[test]
fn a_record_text_that_is_not_the_jcs_of_its_own_parsed_value_is_a_refused_shape() {
    let signer = owner();
    let built = build(b"{}", &signer, FUTURE);
    let signature = sign_header(&built.header, &signer);
    let canonical = |value: &Value| {
        String::from_utf8(tinycloud_core::policy_capability::jcs::canonicalize(value)).unwrap()
    };
    let header = canonical(&built.header);
    let signature_object = canonical(&json!({"algorithm": "Ed25519", "value": signature}));
    let size = built.sealed.len();
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    let now = at("2026-10-24T12:00:00.000Z");
    let outcome = |text: &str| {
        open_link_record(
            &link,
            &FetchedLink {
                record_header: b64(text.as_bytes()),
                body: built.fetched.body.clone(),
            },
            now,
        )
    };
    let assemble =
        |header: &str, signature: &str| format!(r#"{{"header":{header},"signature":{signature}}}"#);

    // The canonical text opens, and it is what the record builder writes.
    assert_eq!(assemble(&header, &signature_object), {
        String::from_utf8(decode_config(&built.fetched.record_header, URL_SAFE_NO_PAD).unwrap())
            .unwrap()
    });
    assert!(outcome(&assemble(&header, &signature_object)).is_ok());

    let wrong_size = size + 1;
    let size_member = format!(r#""size":{size},"#);
    assert!(header.contains(&size_member));
    let in_header = |replacement: String| header.replacen(&size_member, &replacement, 1);
    let wrong_value = "A".repeat(86);
    let algorithm = r#""algorithm":"Ed25519","#;
    let value_member = format!(r#""value":"{signature}""#);
    assert!(signature_object.contains(&value_member));
    let in_signature =
        |replacement: String| signature_object.replacen(&value_member, &replacement, 1);

    // `version` is the last key of the header's JCS: write it first.
    let version_first = {
        let rest = header.strip_suffix(r#","version":1}"#).unwrap();
        format!(r#"{{"version":1,{}}}"#, rest.strip_prefix('{').unwrap())
    };
    let texts = [
        // A duplicate `size`: the last one is the signed value, or the first.
        assemble(
            &in_header(format!(r#""size":{wrong_size},{size_member}"#)),
            &signature_object,
        ),
        assemble(
            &in_header(format!(r#"{size_member}"size":{wrong_size},"#)),
            &signature_object,
        ),
        // The same value twice, and a duplicate of any other header field.
        assemble(
            &in_header(format!("{size_member}{size_member}")),
            &signature_object,
        ),
        assemble(
            &header.replacen(r#""type":"share","#, r#""type":"share","type":"share","#, 1),
            &signature_object,
        ),
        // A duplicate inside the signature object: the value, and the algorithm.
        assemble(
            &header,
            &in_signature(format!(r#""value":"{wrong_value}",{value_member}"#)),
        ),
        assemble(
            &header,
            &in_signature(format!(r#"{value_member},"value":"{wrong_value}""#)),
        ),
        assemble(
            &header,
            &signature_object.replacen(algorithm, &format!("{algorithm}{algorithm}"), 1),
        ),
        // A duplicate at the top of the record.
        format!(r#"{{"header":{header},"header":{header},"signature":{signature_object}}}"#),
        format!(r#"{{"header":{header},"signature":{signature_object},"header":{header}}}"#),
        format!(
            r#"{{"header":{header},"signature":{signature_object},"signature":{signature_object}}}"#
        ),
        // Whitespace anywhere, including around the text.
        format!(r#"{{"header": {header},"signature":{signature_object}}}"#),
        format!(r#"{{"header":{header}, "signature":{signature_object}}}"#),
        format!(" {}", assemble(&header, &signature_object)),
        format!("{}\n", assemble(&header, &signature_object)),
        assemble(
            &header.replacen(r#""size""#, r#""size" "#, 1),
            &signature_object,
        ),
        // Another key order: the record, the header, the signature object.
        format!(r#"{{"signature":{signature_object},"header":{header}}}"#),
        assemble(&version_first, &signature_object),
        assemble(
            &header,
            &format!(r#"{{{value_member},"algorithm":"Ed25519"}}"#),
        ),
        // Another spelling of a character the parser reads the same way.
        assemble(
            &header.replacen(r#""type":"share""#, r#""type":"shar\u0065""#, 1),
            &signature_object,
        ),
        assemble(
            &header.replacen(r#""type""#, r#""t\u0079pe""#, 1),
            &signature_object,
        ),
        assemble(
            &header.replacen("https://", r"https:\/\/", 1),
            &signature_object,
        ),
    ];
    for (index, text) in texts.iter().enumerate() {
        // Every one of these parses to a header whose signature verifies
        // except where the parsed value itself changed; the refusal is the
        // shape in every case.
        assert_eq!(
            outcome(text).unwrap_err(),
            LinkRefusal::RecordShape,
            "case {index}: {text}"
        );
    }
}

/// The JCS identity compares bytes: a text decoder may drop a leading byte
/// order mark, the comparison must not.
#[test]
fn a_byte_order_mark_before_the_record_is_a_refused_shape_and_one_inside_a_string_is_a_character() {
    let signer = owner();
    let built = build(b"{}", &signer, FUTURE);
    let link = ShortLink::parse(&built.href, ORIGIN).unwrap();
    let now = at("2026-10-24T12:00:00.000Z");
    let canonical = decode_config(&built.fetched.record_header, URL_SAFE_NO_PAD).unwrap();
    let outcome = |bytes: &[u8]| {
        open_link_record(
            &link,
            &FetchedLink {
                record_header: b64(bytes),
                body: built.fetched.body.clone(),
            },
            now,
        )
    };
    assert!(outcome(&canonical).is_ok());
    let bom = [0xEF, 0xBB, 0xBF];
    let with_bom = [bom.as_slice(), canonical.as_slice()].concat();
    assert_eq!(outcome(&with_bom).unwrap_err(), LinkRefusal::RecordShape);
    // The bytes of the BOM alone, and after the text.
    assert_eq!(outcome(&bom).unwrap_err(), LinkRefusal::RecordShape);
    let trailing = [canonical.as_slice(), bom.as_slice()].concat();
    assert_eq!(outcome(&trailing).unwrap_err(), LinkRefusal::RecordShape);

    // U+FEFF inside a string value is a character. JCS writes it as the raw
    // bytes EF BB BF, so that spelling is the canonical one and passes the
    // identity check (the issuer is then not a key: a later refusal); the
    // `\ufeff` spelling of the same string is not the JCS and is a shape.
    let mut header = built.header.clone();
    header["issuer"] = json!(format!("{}\u{feff}", did_of(&signer)));
    let signature = sign_header(&header, &signer);
    let text = |header: &Value| {
        let value =
            json!({"header": header, "signature": {"algorithm": "Ed25519", "value": signature}});
        String::from_utf8(tinycloud_core::policy_capability::jcs::canonicalize(&value)).unwrap()
    };
    let raw = text(&header);
    assert!(raw.as_bytes().windows(3).any(|window| window == bom));
    assert_eq!(
        outcome(raw.as_bytes()).unwrap_err(),
        LinkRefusal::BadSignature
    );
    let escaped = raw.replace('\u{feff}', r"\ufeff");
    assert!(!escaped.contains('\u{feff}'));
    assert_eq!(
        outcome(escaped.as_bytes()).unwrap_err(),
        LinkRefusal::RecordShape
    );
}
