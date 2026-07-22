//! The node lane runs the immutable cross-language contract program from the
//! checked-in fixture rather than depending on a sibling worktree.

mod common;

use serde_json::Value;

use common::email_claim_fixture_root;

#[test]
fn pinned_email_claim_manifest_runs_all_negative_rows() {
    let vector_root = email_claim_fixture_root();
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(vector_root.join("manifest.json"))
            .expect("pinned email-claim manifest must be present"),
    )
    .expect("pinned email-claim manifest must be JSON");
    assert_eq!(manifest["manifestVersion"], 1);
    assert_eq!(
        manifest["contractVersion"],
        "tinycloud.share-email-claim/v1"
    );
    assert_eq!(
        manifest["manifestDigest"],
        "pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs"
    );

    let negative: Value = serde_json::from_slice(
        &std::fs::read(vector_root.join("negative.json"))
            .expect("frozen negative rows must be present"),
    )
    .expect("frozen negative rows must be JSON");
    let negative_rows = negative["cases"]
        .as_array()
        .expect("frozen negative cases")
        .len();
    assert_eq!(negative_rows, 118);

    let provenance: Value = serde_json::from_slice(
        &std::fs::read(vector_root.join("PROVENANCE.json"))
            .expect("frozen fixture provenance must be present"),
    )
    .expect("frozen fixture provenance must be JSON");
    assert_eq!(
        provenance["sourceCommit"],
        "3fa222a4e797af6a8192957e59ac41e2a7d805fd"
    );
    assert_eq!(provenance["manifestDigest"], manifest["manifestDigest"]);

    let output = std::process::Command::new("node")
        .arg(vector_root.join("validate.mjs"))
        .current_dir(&vector_root)
        .output()
        .expect("node must be available for the frozen contract runner");
    assert!(
        output.status.success(),
        "frozen email-claim runner failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("{negative_rows} negative rows dispatched")));
    assert!(stdout.contains(&format!(
        "manifestDigest: {}",
        manifest["manifestDigest"].as_str().unwrap()
    )));

    let states: Value = serde_json::from_slice(
        &std::fs::read(vector_root.join("states.json")).expect("frozen lifecycle states present"),
    )
    .expect("frozen lifecycle states must be JSON");
    let operations = states["operations"]
        .as_array()
        .expect("frozen lifecycle operations");
    for operation in [
        "create_persist_outbox",
        "provider_accept",
        "resend_persist_v2",
        "crash_after_provider_accept",
        "retry_same_provider_idempotency",
        "same_redemption_idempotent",
        "different_redemption_rejected",
        "scanner_get_no_state_change",
    ] {
        assert!(
            operations
                .iter()
                .any(|value| value.as_str() == Some(operation)),
            "frozen lifecycle must cover {operation}"
        );
    }
    let delivery = states["delivery"].as_array().expect("delivery state model");
    for scenario in [
        "resend-accepted",
        "resend-provider-failure",
        "crash-after-provider-accept",
    ] {
        assert!(
            delivery.iter().any(|value| value["name"] == scenario),
            "frozen delivery lifecycle must cover {scenario}"
        );
    }
}
