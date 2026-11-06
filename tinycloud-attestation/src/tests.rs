use super::*;
use dcap_qvl::quote::TDReport10;
use serde_json::Value;

fn fixture() -> (AttestationBundle, u64) {
    let mut value: Value =
        serde_json::from_str(include_str!("../tests/fixtures/dstack-tdx-quote.json")).unwrap();
    // The registry's JS wire format uses integer arrays; Rust DCAP JSON uses hex.
    for field in [
        "root_ca_crl",
        "pck_crl",
        "tcb_info_signature",
        "qe_identity_signature",
    ] {
        let bytes: Vec<u8> = serde_json::from_value(value["collateral"][field].take()).unwrap();
        value["collateral"][field] = Value::String(hex::encode(bytes));
    }
    let bundle = AttestationBundle {
        quote: value["getQuote"]["quote"].as_str().unwrap().into(),
        event_log: serde_json::from_str(value["getQuote"]["event_log"].as_str().unwrap()).unwrap(),
        collateral: serde_json::from_value(value["collateral"].clone()).unwrap(),
    };
    (bundle, value["verificationTime"].as_u64().unwrap())
}

fn event(name: &str, payload: &[u8], version: u32) -> Event {
    let payload_hex = hex::encode(payload);
    let preimage = (version == 2).then(|| {
        hex::encode(format!(
            "{{\"name\":{},\"payload\":\"{}\",\"type\":134217729}}",
            serde_json::to_string(name).unwrap(),
            payload_hex
        ))
    });
    Event {
        imr: 3,
        event_type: 0x08000001,
        digest: String::new(),
        event: name.into(),
        event_payload: payload_hex,
        version: Some(version),
        preimage,
    }
}

// Synthetic policy-only vectors: these report bodies have no valid quote signature.
// They exercise the private policy seam, never the public verification entry point.
fn synthetic(version: u32) -> (TDReport10, Vec<Event>, AttestationPolicy) {
    let events = vec![
        event("system-preparing", &[], version),
        event("app-id", &[0x11; 20], version),
        event("compose-hash", &[0x22; 32], version),
        event("boot-mr-done", &[], version),
        event("key-provider", br#"{"name":"kms","id":"302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"}"#, version),
        event("system-ready", &[], version),
    ];
    let report = TDReport10 {
        tee_tcb_svn: [0; 16],
        mr_seam: [0; 48],
        mr_signer_seam: [0; 48],
        seam_attributes: [0; 8],
        td_attributes: [0; 8],
        xfam: [0; 8],
        mr_td: [0x33; 48],
        mr_config_id: [0; 48],
        mr_owner: [0; 48],
        mr_owner_config: [0; 48],
        rt_mr0: [0x44; 48],
        rt_mr1: [0x55; 48],
        rt_mr2: [0x66; 48],
        rt_mr3: replay_event_log(&events).unwrap(),
        report_data: [0x77; 64],
    };
    let policy = AttestationPolicy {
        app_id: hex::encode([0x11; 20]), compose_hashes: vec![hex::encode([0x22; 32])],
        kms_id: "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111".into(),
        mrtd: hex::encode(report.mr_td), rtmr0: hex::encode(report.rt_mr0),
        rtmr1: hex::encode(report.rt_mr1), rtmr2: hex::encode(report.rt_mr2),
    };
    (report, events, policy)
}

fn check(report: &TDReport10, events: &[Event], policy: &AttestationPolicy) -> anyhow::Result<()> {
    verify_policy("UpToDate", report, events, policy, &[0x77; 64])
}

fn resign_synthetic_replay(report: &mut TDReport10, events: &[Event]) {
    report.rt_mr3 = replay_event_log(events).unwrap();
}

#[test]
fn real_quote_chain_and_rtmr3_known_answer() {
    let (bundle, now) = fixture();
    let verified = authenticate(&bundle, now).unwrap();
    assert_eq!(verified.status, "UpToDate");
    let report = verified.report.as_td10().unwrap();
    assert_eq!(report.report_data, [0x42; 64]);
    assert_eq!(replay_event_log(&bundle.event_log).unwrap(), report.rt_mr3);
    assert_eq!(hex::encode(report.rt_mr3), "b49119652a84beeee90c614992c1f67461b17edac4a4f6034c72b147c51fae66920eb2d23e8d40287fcebf5ac2a263e8");
}

#[test]
fn real_corrupted_quote_and_collateral_are_rejected() {
    let (mut bundle, now) = fixture();
    let mut quote = hex::decode(&bundle.quote).unwrap();
    quote[100] ^= 1;
    bundle.quote = hex::encode(quote);
    assert!(authenticate(&bundle, now).is_err());
    let (mut bundle, now) = fixture();
    bundle.collateral.tcb_info_signature[0] ^= 1;
    assert!(authenticate(&bundle, now).is_err());
    let (mut bundle, now) = fixture();
    bundle.collateral.tcb_info_issuer_chain = bundle
        .collateral
        .tcb_info_issuer_chain
        .replacen('M', "N", 1);
    assert!(authenticate(&bundle, now).is_err());
}

#[test]
fn real_collateral_cannot_be_backdated_or_used_after_expiration() {
    let (bundle, _) = fixture();
    assert!(authenticate(&bundle, 0).is_err());
    assert!(authenticate(&bundle, 1_799_136_000).is_err());
}

#[test]
fn real_none_provider_is_not_an_authenticated_kms_identity() {
    let (bundle, now) = fixture();
    let verified = authenticate(&bundle, now).unwrap();
    let report = verified.report.as_td10().unwrap();
    let (_, _, mut policy) = synthetic(1);
    policy.app_id = "60618cd0c23d15d921b788b8fc3a0d024ac72295".into();
    policy.compose_hashes =
        vec!["60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833".into()];
    policy.mrtd = hex::encode(report.mr_td);
    policy.rtmr0 = hex::encode(report.rt_mr0);
    policy.rtmr1 = hex::encode(report.rt_mr1);
    policy.rtmr2 = hex::encode(report.rt_mr2);
    let err = verify(&bundle, &policy, &[0x42; 64], now).unwrap_err();
    assert!(err.to_string().contains("KMS"), "{err}");
    assert!(verify(&bundle, &policy, &[0; 64], now).is_err());
    policy.app_id = hex::encode([0x99; 20]);
    assert!(verify(&bundle, &policy, &[0x42; 64], now).is_err());
}

#[test]
fn reconstructed_empty_digests_match_real_quote_but_not_modified_payloads() {
    let (mut bundle, now) = fixture();
    let verified = authenticate(&bundle, now).unwrap();
    let expected = verified.report.as_td10().unwrap().rt_mr3;
    for event in &mut bundle.event_log {
        if event.imr == 3 {
            event.digest.clear();
        }
    }
    assert_eq!(replay_event_log(&bundle.event_log).unwrap(), expected);
    bundle
        .event_log
        .iter_mut()
        .find(|e| e.event == "app-id")
        .unwrap()
        .event_payload = hex::encode([0x99; 20]);
    assert_ne!(replay_event_log(&bundle.event_log).unwrap(), expected);
    bundle
        .event_log
        .iter_mut()
        .find(|e| e.event == "app-id")
        .unwrap()
        .digest = "00".repeat(48);
    assert!(replay_event_log(&bundle.event_log).is_err());
}

#[test]
fn synthetic_both_runtime_versions_and_compose_allowlist_work() {
    for version in [1, 2] {
        let (report, events, mut policy) = synthetic(version);
        policy.compose_hashes.insert(0, hex::encode([0x99; 32]));
        check(&report, &events, &policy).unwrap();
    }
}

#[test]
fn synthetic_wrong_app_compose_and_actual_kms_id_fail() {
    let (report, events, policy) = synthetic(1);
    let mut wrong = policy.clone();
    wrong.app_id = hex::encode([0x99; 20]);
    assert!(check(&report, &events, &wrong).is_err());
    let mut wrong = policy.clone();
    wrong.compose_hashes = vec![hex::encode([0x99; 32])];
    assert!(check(&report, &events, &wrong).is_err());
    let mut wrong = policy.clone();
    wrong.kms_id = hex::encode([0x99; 44]);
    assert!(check(&report, &events, &wrong).is_err());
    let mut wrong = policy.clone();
    wrong.kms_id = "kms".into();
    assert!(check(&report, &events, &wrong).is_err());
    let mut wrong = policy;
    wrong.kms_id.clear();
    assert!(check(&report, &events, &wrong).is_err());
}

#[test]
fn synthetic_provider_name_never_substitutes_for_identity() {
    for payload in [
        br#"{"name":"kms","id":""}"#.as_slice(),
        br#"{"name":"none","id":"302a"}"#.as_slice(),
        br#"{"name":"kms"}"#.as_slice(),
        br#"{"name":"kms","id":"30","id":"31"}"#.as_slice(),
    ] {
        let (mut report, mut events, policy) = synthetic(1);
        events[4] = event("key-provider", payload, 1);
        resign_synthetic_replay(&mut report, &events);
        assert!(check(&report, &events, &policy).is_err());
    }
}

#[test]
fn synthetic_requires_unique_ordered_binding_and_boot_events() {
    for name in [
        "app-id",
        "compose-hash",
        "key-provider",
        "boot-mr-done",
        "system-ready",
    ] {
        let (mut report, mut events, policy) = synthetic(1);
        let index = events.iter().position(|e| e.event == name).unwrap();
        events.push(events[index].clone());
        resign_synthetic_replay(&mut report, &events);
        assert!(
            check(&report, &events, &policy).is_err(),
            "duplicate {name}"
        );
        events.retain(|e| e.event != name);
        resign_synthetic_replay(&mut report, &events);
        assert!(check(&report, &events, &policy).is_err(), "missing {name}");
    }
    for (a, b) in [(1, 3), (2, 3), (3, 4), (4, 5)] {
        let (mut report, mut events, policy) = synthetic(1);
        events.swap(a, b);
        resign_synthetic_replay(&mut report, &events);
        assert!(
            check(&report, &events, &policy).is_err(),
            "ordering {a}/{b}"
        );
    }
}

#[test]
fn synthetic_debug_stale_tcb_reportdata_and_pinned_measurements_fail() {
    let (report, events, policy) = synthetic(1);
    for status in [
        "OutOfDate",
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "Revoked",
    ] {
        assert!(verify_policy(status, &report, &events, &policy, &[0x77; 64]).is_err());
    }
    let mut debug = report;
    debug.td_attributes[0] |= 1;
    assert!(check(&debug, &events, &policy).is_err());
    assert!(verify_policy("UpToDate", &report, &events, &policy, &[0; 64]).is_err());
    for index in 0..4 {
        let mut changed = report;
        match index {
            0 => changed.mr_td[0] ^= 1,
            1 => changed.rt_mr0[0] ^= 1,
            2 => changed.rt_mr1[0] ^= 1,
            _ => changed.rt_mr2[0] ^= 1,
        }
        assert!(check(&changed, &events, &policy).is_err());
    }
}

#[test]
fn synthetic_authenticates_every_rtmr3_event_including_unknown_names() {
    let (report, mut events, policy) = synthetic(1);
    events.push(event("unrecognized-event", b"measured bytes", 1));
    assert!(check(&report, &events, &policy).is_err());
    let mut changed = report;
    resign_synthetic_replay(&mut changed, &events);
    check(&changed, &events, &policy).unwrap();
    events.last_mut().unwrap().event_payload = hex::encode(b"changed bytes");
    assert!(check(&changed, &events, &policy).is_err());
}

#[test]
fn malformed_runtime_inputs_and_noncanonical_v2_preimage_fail() {
    for version in [1, 2] {
        let (_, events, _) = synthetic(version);
        let mut changed = events.clone();
        changed[0].event_payload = "a".into();
        assert!(replay_event_log(&changed).is_err());
        let mut changed = events.clone();
        changed[0].digest = "00".repeat(32);
        assert!(replay_event_log(&changed).is_err());
        let mut changed = events.clone();
        changed[0].imr = 4;
        assert!(replay_event_log(&changed).is_err());
        let mut changed = events.clone();
        changed[0].event_type = 0;
        assert!(replay_event_log(&changed).is_err());
        let mut changed = events.clone();
        changed[0].version = Some(3);
        assert!(replay_event_log(&changed).is_err());
        if version == 2 {
            let mut changed = events.clone();
            changed[0].preimage = Some(hex::encode(b"{}"));
            assert!(replay_event_log(&changed).is_err());
            let mut changed = events;
            changed[0].preimage = None;
            assert!(replay_event_log(&changed).is_err());
        }
    }
    assert!(replay_event_log(&[]).is_err());
}

#[test]
fn serde_rejects_malformed_unicode_and_missing_payload() {
    assert!(serde_json::from_str::<Event>(
        r#"{"imr":3,"event_type":134217729,"digest":"","event":"\ud800","event_payload":""}"#
    )
    .is_err());
    assert!(serde_json::from_str::<Event>(
        r#"{"imr":3,"event_type":134217729,"digest":"","event":"name"}"#
    )
    .is_err());
}

#[test]
fn canonical_runtime_digest_known_answers() {
    // v1 is independently recorded in the genuine fixture. v2 uses the exact
    // canonical JSON preimage and an independently derived SHA384 answer.
    let v1 = event("system-preparing", &[], 1);
    assert_eq!(hex::encode(runtime_digest(&v1).unwrap()), "f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624");
    let mut v2 = event("system-preparing", &[], 2);
    v2.preimage = Some("7b226e616d65223a2273797374656d2d707265706172696e67222c227061796c6f6164223a22222c2274797065223a3133343231373732397d".into());
    assert_eq!(hex::encode(runtime_digest(&v2).unwrap()), "918e390aef67de4520d37d7e046dd222038e0a8385825072383ab194543ffa3046a9a48fdabbc16e6ba9ff24249ba88f");
    let mut default_v1 = v1;
    default_v1.version = None;
    assert_eq!(hex::encode(runtime_digest(&default_v1).unwrap()), "f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624");
}
