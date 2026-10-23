#![allow(dead_code)]

use std::path::PathBuf;

pub fn email_claim_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/email-claim-v1")
}

/// The PostgreSQL URL for the `postgres_*` integration tests, or `None` when
/// they skip. Identical to `tinycloud_node_server::test_support::postgres_test_url`,
/// which an integration-test crate cannot reach (`pub(crate)`). Keep the two in step.
pub fn postgres_test_url(test: &str) -> Option<String> {
    postgres_gate(
        std::env::var("TINYCLOUD_TEST_POSTGRES_URL").ok(),
        std::env::var_os("GITHUB_ACTIONS").map(|value| value.to_string_lossy().into_owned()),
        std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").ok(),
        test,
    )
}

/// The rule behind [`postgres_test_url`]: connect only when the URL is set and
/// non-empty AND either `github_actions` is `"true"` or `allow_local` is `"1"`.
/// Panics when `github_actions` is `"true"` and the URL is not (TC-381).
pub fn postgres_gate(
    url: Option<String>,
    github_actions: Option<String>,
    allow_local: Option<String>,
    test: &str,
) -> Option<String> {
    let Some(url) = url.filter(|url| !url.trim().is_empty()) else {
        if github_actions.as_deref() == Some("true") {
            panic!(
                "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset (or empty) on GitHub Actions. \
                 This test must not be allowed to skip on GitHub Actions — see TC-381. Check the \
                 `postgres` service container and the `env:` block in .github/workflows/rust.yml."
            );
        }
        skip_postgres_test(test);
        return None;
    };
    if github_actions.as_deref() == Some("true") || allow_local.as_deref() == Some("1") {
        return Some(url);
    }
    skip_postgres_test(test);
    None
}

fn skip_postgres_test(test: &str) {
    use std::io::Write;
    // Written to the process stderr directly: libtest captures `eprintln!` output of passing tests.
    let _ = writeln!(
        std::io::stderr(),
        "skipping {test}: PostgreSQL-backed tests run only on GitHub Actions (or with TINYCLOUD_ALLOW_LOCAL_PG=1 for an isolated server you started yourself); not connecting"
    );
}
