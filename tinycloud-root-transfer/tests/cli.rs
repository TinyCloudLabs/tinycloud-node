//! Offline binary smoke tests; generated quotes below are synthetic, not DCAP-valid.
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
    process::Command,
    thread,
};

fn fixture() -> Value {
    let mut fixture: Value = serde_json::from_str(include_str!(
        "../../tinycloud-attestation/tests/fixtures/dstack-tdx-quote.json"
    ))
    .unwrap();
    for name in [
        "root_ca_crl",
        "pck_crl",
        "tcb_info_signature",
        "qe_identity_signature",
    ] {
        let bytes: Vec<u8> = serde_json::from_value(fixture["collateral"][name].clone()).unwrap();
        fixture["collateral"][name] = Value::String(hex::encode(bytes));
    }
    fixture
}
fn policy() -> Value {
    json!({"app_id":"11223344", "compose_hashes":["11".repeat(32)], "kms_id":"aabb",
        "mrtd":"00".repeat(48), "rtmr0":"00".repeat(48), "rtmr1":"00".repeat(48), "rtmr2":"00".repeat(48)})
}
fn agent(listener: UnixListener, quote: bool) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for index in 0..if quote { 2 } else { 1 } {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            let body: Value =
                serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
            let response = if index == 0 {
                assert!(request.starts_with("POST /GetKey "));
                assert_eq!(body, json!({"path":"tinycloud/keys/primary"}));
                json!({"key":"54432d313434322064737461636b204765744b65792066697874757265212121"})
            } else {
                assert!(request.starts_with("POST /GetQuote "));
                let report = hex::decode(body["report_data"].as_str().unwrap()).unwrap();
                assert_eq!(report.len(), 64);
                let mut synthetic = vec![0u8; 636];
                synthetic[0..2].copy_from_slice(&4u16.to_le_bytes());
                synthetic[4..8].copy_from_slice(&0x81u32.to_le_bytes());
                synthetic[568..632].copy_from_slice(&report);
                json!({"quote":hex::encode(synthetic),"event_log":"[]","report_data":hex::encode(report)})
            }.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        }
    })
}

#[test]
fn prepare_binary_publishes_bound_public_document_without_root() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("guest.sock");
    let server = agent(UnixListener::bind(&socket).unwrap(), true);
    let policy_file = dir.path().join("policy.json");
    let collateral_file = dir.path().join("collateral.json");
    fs::write(&policy_file, policy().to_string()).unwrap();
    fs::write(&collateral_file, fixture()["collateral"].to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tinycloud-root-import"))
        .arg("prepare")
        .arg("--socket")
        .arg(&socket)
        .arg("--policy")
        .arg(&policy_file)
        .arg("--collateral")
        .arg(&collateral_file)
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: tinycloud_root_transfer::TargetDocument =
        serde_json::from_slice(&output.stdout).unwrap();
    let public: [u8; 32] = hex::decode(&document.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let policy = serde_json::from_value(policy()).unwrap();
    let expected = tinycloud_root_transfer::report_binding(&public, &policy).unwrap();
    let quote = hex::decode(&document.attestation.quote).unwrap();
    assert_eq!(&quote[568..632], &expected);
    assert!(!String::from_utf8_lossy(&output.stdout)
        .contains("54432d313434322064737461636b204765744b65792066697874757265212121"));
}

#[test]
fn export_binary_refuses_wrong_did_and_unbound_quote_with_empty_stdout() {
    for expected_did in [
        "did:key:wrong",
        "did:key:z6MkmRVxeLv23jCfiR5XQMt5yZsyP5rxoS8GD8RkWoo7BnBA",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("guest.sock");
        let server = agent(UnixListener::bind(&socket).unwrap(), false);
        let config = dir.path().join("config.json");
        let target = dir.path().join("target.json");
        fs::write(
            &config,
            json!({"policy":policy(),"expected_old_did":expected_did}).to_string(),
        )
        .unwrap();
        let recorded = fixture();
        fs::write(&target, json!({"public_key":"07".repeat(32),"attestation":{
            "quote":recorded["getQuote"]["quote"], "event_log":serde_json::from_str::<Value>(recorded["getQuote"]["event_log"].as_str().unwrap()).unwrap(),
            "collateral":recorded["collateral"]}}).to_string()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_tinycloud-root-export"))
            .arg("--socket")
            .arg(&socket)
            .arg("--config")
            .arg(config)
            .arg("--target")
            .arg(target)
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("54432d313434322064737461636b204765744b65792066697874757265212121")
        );
    }
}
