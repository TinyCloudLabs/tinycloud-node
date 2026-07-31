//! Shared helpers for tinycloud-core's own tests.

/// Resolve the PostgreSQL URL that the `postgres_*` regressions run against.
///
/// TC-381: these tests used to `return` silently whenever
/// `TINYCLOUD_TEST_POSTGRES_URL` was unset. Combined with a CI command that
/// filtered on the name `postgres_` — and libtest exiting 0 when a filter
/// matches nothing — the whole PostgreSQL job could report green having
/// asserted nothing at all, twice over. A test that no-ops in silence is worse
/// than no test, because it manufactures confidence.
///
/// So: skipping stays available locally, where not everyone wants to run a
/// PostgreSQL server just to `cargo test`, but in CI (`CI` is always set by
/// GitHub Actions) a missing URL is a hard failure rather than a shrug.
pub(crate) fn postgres_test_url(test: &str) -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            if std::env::var_os("CI").is_some() {
                panic!(
                    "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset (or empty) in CI. \
                     This test must not be allowed to skip on CI — see TC-381. Check the \
                     `postgres` service container and the `env:` block in .github/workflows/rust.yml."
                );
            }
            eprintln!(
                "skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset (set it to run this \
                 locally; it is mandatory in CI)"
            );
            None
        }
    }
}
