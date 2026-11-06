use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn invoke(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tinycloud-attestation"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn recorded_request() -> Value {
    let mut fixture: Value =
        serde_json::from_str(include_str!("fixtures/dstack-tdx-quote.json")).unwrap();
    for field in [
        "root_ca_crl",
        "pck_crl",
        "tcb_info_signature",
        "qe_identity_signature",
    ] {
        let bytes: Vec<u8> = serde_json::from_value(fixture["collateral"][field].take()).unwrap();
        fixture["collateral"][field] = Value::String(hex::encode(bytes));
    }
    json!({
        "bundle": {"quote": fixture["getQuote"]["quote"], "event_log": serde_json::from_str::<Value>(fixture["getQuote"]["event_log"].as_str().unwrap()).unwrap(), "collateral": fixture["collateral"]},
        "policy": {"app_id": "60618cd0c23d15d921b788b8fc3a0d024ac72295", "compose_hashes": ["60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833"], "kms_id": "302a", "mrtd": "00".repeat(48), "rtmr0": "00".repeat(48), "rtmr1": "00".repeat(48), "rtmr2": "00".repeat(48)},
        "expected_report_data": "42".repeat(64)
    })
}

#[test]
fn malformed_input_is_machine_readable_and_not_echoed() {
    let output = invoke(&[], b"not json: DO_NOT_ECHO_INPUT");
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert!(result["error"].is_string());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DO_NOT_ECHO_INPUT"));
    assert!(output.stderr.is_empty());
}

#[test]
fn no_cli_flag_or_json_field_can_override_wall_clock() {
    let output = invoke(&["--now", "1789432200"], b"");
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["ok"],
        false
    );
    let mut request = recorded_request();
    request["now"] = json!(1789432200_u64);
    let output = invoke(&[], &serde_json::to_vec(&request).unwrap());
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"],
        "invalid attestation request"
    );
}

#[test]
fn recorded_non_kms_fixture_is_never_cli_success() {
    // Genuine signed quote, but no KMS identity, no import binding, and expired collateral.
    let output = invoke(&[], &serde_json::to_vec(&recorded_request()).unwrap());
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"], "attestation verification failed");
}

#[test]
fn report_data_must_be_exactly_64_bytes_of_hex() {
    for value in ["42".repeat(63), "42".repeat(65), "not hex".into()] {
        let mut request = recorded_request();
        request["expected_report_data"] = json!(value);
        let output = invoke(&[], &serde_json::to_vec(&request).unwrap());
        assert!(!output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"],
            "invalid attestation request"
        );
    }
}
