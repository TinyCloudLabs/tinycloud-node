use std::{fs, path::Path, process::Command};

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use m1_realdata_e2e::live_gate_verifier::{self, Mode};
use serde_json::{json, Value};
use tempfile::TempDir;

#[test]
fn verifier_rejects_critical_field_removed_from_accepted_bundle_copy() -> Result<()> {
    let bundle = TempDir::new()?;
    accepted_bundle(bundle.path())?;
    let report = live_gate_verifier::run(
        bundle.path(),
        Mode::VerifyAndMutationSelfTest,
        "expected-node-sha",
    )?;
    let rendered = serde_json::to_value(report)?;
    assert_eq!(rendered["verdict"], "pass");
    assert_eq!(rendered["mutationSelfTest"], "passed");
    Ok(())
}

#[test]
fn verifier_requires_matching_expected_node_sha() -> Result<()> {
    let bundle = TempDir::new()?;
    accepted_bundle(bundle.path())?;

    assert!(live_gate_verifier::run(bundle.path(), Mode::Verify, "").is_err());
    assert!(live_gate_verifier::run(bundle.path(), Mode::Verify, "wrong-node-sha").is_err());
    Ok(())
}

#[test]
fn verifier_requires_ability_linked_to_imported_delegation() -> Result<()> {
    let bundle = TempDir::new()?;
    accepted_bundle(bundle.path())?;
    let path = bundle.path().join("node-db/post-import.json");
    let mut snapshot: Value = serde_json::from_slice(&fs::read(&path)?)?;
    snapshot["abilities"][0]["delegation"] = delegation_id("unrelated-delegation");
    write(path, snapshot)?;

    let error = live_gate_verifier::run(bundle.path(), Mode::Verify, "expected-node-sha")
        .expect_err("unlinked ability row must fail closed");
    assert!(error.to_string().contains("ability rows are not linked"));
    Ok(())
}

#[test]
fn verifier_requires_refusal_after_issued_expiry() -> Result<()> {
    let bundle = TempDir::new()?;
    accepted_bundle(bundle.path())?;
    let path = bundle.path().join("requester/post-expiry-read.json");
    let mut exchange: Value = serde_json::from_slice(&fs::read(&path)?)?;
    exchange["observedAt"] = json!("2026-07-11T12:01:01Z");
    write(path, exchange)?;

    let error = live_gate_verifier::run(bundle.path(), Mode::Verify, "expected-node-sha")
        .expect_err("pre-expiry refusal must fail closed");
    assert!(error
        .to_string()
        .contains("before the issued delegation expired"));
    Ok(())
}

#[test]
fn runner_timestamp_helper_has_millisecond_precision() -> Result<()> {
    let source = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/m1-gate-demo.sh"
    ))?;
    let definition = source
        .lines()
        .find(|line| line.starts_with("now()"))
        .expect("runner must define now()");
    let output = Command::new("bash")
        .arg("-c")
        .arg(format!("{definition}\nnow"))
        .output()?;
    assert!(output.status.success());
    let timestamp = String::from_utf8(output.stdout)?.trim().to_string();
    DateTime::parse_from_rfc3339(&timestamp)?;
    let fractional = timestamp
        .split_once('.')
        .and_then(|(_, suffix)| suffix.strip_suffix('Z'));
    assert_eq!(fractional.map(str::len), Some(3));
    Ok(())
}

#[test]
fn snapshot_reads_native_singular_ability_table() -> Result<()> {
    let bundle = TempDir::new()?;
    let database = bundle.path().join("caps.db");
    let output = bundle.path().join("snapshot.json");
    let created = Command::new("python3")
        .arg("-c")
        .arg(
            r#"import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.executescript('''
CREATE TABLE delegation (id BLOB, serialization TEXT);
CREATE TABLE ability (resource TEXT, ability TEXT, delegation BLOB, caveats TEXT);
CREATE TABLE parent_delegation (parent BLOB, child BLOB);
INSERT INTO ability VALUES ('tinycloud:sql:test', 'tinycloud.sql/read', X'01', '{}');
''')
connection.commit()
"#,
        )
        .arg(&database)
        .status()?;
    assert!(created.success());

    let captured = Command::new("bash")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/snapshot-node-db.sh"
        ))
        .arg(&database)
        .arg("snapshot-contract-test")
        .arg(&output)
        .status()?;
    assert!(captured.success());

    let snapshot: Value = serde_json::from_slice(&fs::read(output)?)?;
    assert_eq!(snapshot["abilities"].as_array().map(Vec::len), Some(1));
    assert_eq!(snapshot["abilities"][0]["ability"], "tinycloud.sql/read");
    Ok(())
}

#[test]
fn snapshot_fails_closed_when_required_authority_table_is_missing() -> Result<()> {
    let bundle = TempDir::new()?;
    let database = bundle.path().join("caps.db");
    let output = bundle.path().join("snapshot.json");
    let created = Command::new("python3")
        .arg("-c")
        .arg(
            r#"import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.executescript('''
CREATE TABLE delegation (id BLOB, serialization TEXT);
CREATE TABLE ability (resource TEXT, ability TEXT, delegation BLOB, caveats TEXT);
''')
connection.commit()
"#,
        )
        .arg(&database)
        .status()?;
    assert!(created.success());

    let captured = Command::new("bash")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/snapshot-node-db.sh"
        ))
        .arg(&database)
        .arg("snapshot-contract-test")
        .arg(&output)
        .output()?;
    assert!(!captured.status.success());
    assert!(!output.exists());
    assert!(String::from_utf8(captured.stderr)?.contains("parent_delegation"));
    Ok(())
}

fn accepted_bundle(root: &Path) -> Result<()> {
    for directory in ["driver", "requester", "node-db", "sidecar", "node", "meta"] {
        fs::create_dir_all(root.join(directory))?;
    }
    for (file, content) in [
        ("meta/artifacts.sha256", "aa artifact\n"),
        ("meta/tinycloud-node.sha", "expected-node-sha\n"),
        ("meta/runner.pid", "39\n"),
        ("meta/runner.actual-command", "m1-gate-demo.sh\n"),
        ("node/process.pid", "40\n"),
        ("node/process.actual-command", "tinycloud-node-server\n"),
        ("node/port", "41001\n"),
        ("sidecar/initial-process.pid", "41\n"),
        (
            "sidecar/initial-process.actual-command",
            "policy-engine-http\n",
        ),
        ("sidecar/redeployed-process.pid", "43\n"),
        (
            "sidecar/redeployed-process.actual-command",
            "policy-engine-http\n",
        ),
        ("sidecar/initial-port", "41002\n"),
        ("sidecar/redeployed-port", "41003\n"),
    ] {
        fs::write(root.join(file), content)?;
    }
    write(
        root.join("manifest.json"),
        json!({
            "schema": "xyz.tinycloud.m1/live-gate-raw-bundle/v1", "runId": "verifier-contract-test",
            "createdAt": "2026-07-11T12:00:00Z",
            "inputs": {"nonceSha256":"11".repeat(32),"renewalNonceSha256":"22".repeat(32),"revokedNonceSha256":"33".repeat(32),"sqlSeedSha256":"44".repeat(32)},
            "candidates": {"tinycloudNode":"expected-node-sha","policyEngine":"d9a8d37","jsSdk":"d53c83e","listen":"c9cf086","openCredentials":"d2cf81e"}
        }),
    )?;
    exchange(
        root,
        "driver/publish.json",
        "publish",
        "2026-07-11T12:00:01Z",
        json!({"published":true}),
    )?;
    exchange(
        root,
        "requester/initial.json",
        "initial",
        "2026-07-11T12:00:02Z",
        json!({
            "delegation":"real-wire-delegation", "import":{"delegation":"real-wire-delegation"},
            "issuedAt":"2026-07-11T12:00:02Z", "expiresAt":"2026-07-11T12:01:02Z",
            "reads":{"sql":{"sha256":"44".repeat(32)}},
            "ssrfScope":{"coverage":"unit-conformance-only","liveObserved":false}
        }),
    )?;
    exchange(
        root,
        "requester/renewal.json",
        "renewal",
        "2026-07-11T12:00:03Z",
        json!({"renewed":true}),
    )?;
    exchange(
        root,
        "driver/revoke.json",
        "revoke",
        "2026-07-11T12:00:04Z",
        json!({"disposition":"revoked"}),
    )?;
    fs::write(
        root.join("sidecar/redeployed-ready.timestamp"),
        "2026-07-11T12:00:05Z\n",
    )?;
    write(
        root.join("meta/teardown.json"),
        json!({"runId":"verifier-contract-test","observedAt":"2026-07-11T12:01:04Z","runnerExit":0,"allOwnedProcessesDead":true,"allDynamicPortsClosed":true}),
    )?;
    exchange(
        root,
        "requester/renewal-denied.json",
        "denied",
        "2026-07-11T12:00:06Z",
        json!({"error":{"code":"policy-inactive"},"accessEnded":false,"execution":"direct-live-challenge"}),
    )?;
    exchange(
        root,
        "requester/post-expiry-read.json",
        "expired",
        "2026-07-11T12:01:03Z",
        json!({"layer":"native-node","refused":true}),
    )?;
    write(
        root.join("node-db/pre-import.json"),
        json!({"runId":"verifier-contract-test","observedAt":"2026-07-11T12:00:01Z","database":"caps.db","delegations":[],"abilities":[],"parentDelegations":[]}),
    )?;
    write(
        root.join("node-db/post-import.json"),
        json!({"runId":"verifier-contract-test","observedAt":"2026-07-11T12:00:03Z","database":"caps.db","delegations":[{"id":delegation_id("real-wire-delegation"),"serialization":{"base64":"ZW5jcnlwdGVkLWF0LXJlc3Q"}}],"abilities":[{"delegation":delegation_id("real-wire-delegation")}],"parentDelegations":[]}),
    )?;
    Ok(())
}

fn delegation_id(serialization: &str) -> Value {
    let hash: Vec<u8> = tinycloud_core::hash::hash(serialization.as_bytes()).into();
    json!({"base64": URL_SAFE_NO_PAD.encode(hash)})
}

fn exchange(
    root: &Path,
    file: &str,
    request_id: &str,
    observed_at: &str,
    response: Value,
) -> Result<()> {
    write(
        root.join(file),
        json!({"runId":"verifier-contract-test","requestId":request_id,"producerPid":42,"request":{"method":"production-operation"},"response":response,"observedAt":observed_at}),
    )
}

fn write(path: impl AsRef<Path>, value: Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}
