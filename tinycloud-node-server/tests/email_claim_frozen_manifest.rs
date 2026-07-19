//! The node lane runs the immutable cross-language contract program rather
//! than copying its 115 MB generated vectors into this repository.

use std::path::PathBuf;

#[test]
fn pinned_email_claim_manifest_runs_all_negative_rows() {
    let vector_root = std::env::var_os("TINYCLOUD_EMAIL_CLAIM_VECTOR_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../share/feat/email-claim-e1-e2e/test/vectors/email-claim-v1")
        });
    let manifest = std::fs::read_to_string(vector_root.join("manifest.json"))
        .expect("pinned email-claim manifest must be present");
    assert!(manifest.contains("0KhpZQqEm2N01I3fNOSN0LclCbR3uw_EK8CoBtqua2g"));
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
    assert!(stdout.contains("manifestDigest: 0KhpZQqEm2N01I3fNOSN0LclCbR3uw_EK8CoBtqua2g"));
}
