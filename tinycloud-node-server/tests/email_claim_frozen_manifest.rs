//! The node lane runs the immutable cross-language contract program rather
//! using the small checked-in contract fixture rather than a sibling worktree.

use serde_json::Value;
use std::path::PathBuf;

#[test]
fn pinned_email_claim_manifest_runs_all_negative_rows() {
    let vector_root = std::env::var_os("TINYCLOUD_EMAIL_CLAIM_VECTOR_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/email-claim-v1")
        });
    let manifest = std::fs::read_to_string(vector_root.join("manifest.json"))
        .expect("pinned email-claim manifest must be present");
    assert!(manifest.contains("pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs"));
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
    assert!(stdout.contains("118 negative rows dispatched"));
    assert!(stdout.contains("manifestDigest: pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs"));

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
