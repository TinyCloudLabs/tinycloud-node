use std::path::PathBuf;

pub fn email_claim_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/email-claim-v1")
}
