use std::{fs, path::Path};

use anyhow::Result;
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
            "candidates": {"tinycloudNode":"expected-node-sha","policyEngine":"d72812a","jsSdk":"2949408","listen":"7bbd99a","openCredentials":"a1633710"}
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
        json!({"error":{"code":"policy-inactive"},"accessEnded":false,"execution":"direct-live-challenge-resolve"}),
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
        json!({"runId":"verifier-contract-test","observedAt":"2026-07-11T12:00:03Z","database":"caps.db","delegations":[{"id":"cid","serialization":"real-wire-delegation"}],"abilities":[{"delegation":"cid"}],"parentDelegations":[]}),
    )?;
    Ok(())
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
