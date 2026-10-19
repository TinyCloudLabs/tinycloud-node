//! Argument routing of the released `tinycloud` binary (TC-1442).
//!
//! Only two invocations may reach the server start: no arguments (container
//! entrypoint) and exactly `--validate-config` (deploy preflight). Everything
//! else is the clap CLI, which must never boot a server. These tests run the
//! built binary with default features.
//!
//! Every run uses a scrubbed environment and an empty HOME, so a binary that
//! falls through to the server start fails fast on the missing key source
//! rather than binding a socket. The timeout turns an accidental server start
//! into a test failure instead of a hang.

use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Throwaway 32-byte secret for config validation; never used as a real key.
const TEST_SECRET: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_tinycloud(args: &[&str], env: &[(&str, &str)]) -> Run {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_tinycloud"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("xdg-config"))
        .env("XDG_DATA_HOME", home.path().join("xdg-data"))
        .env("XDG_STATE_HOME", home.path().join("xdg-state"))
        .env(
            "TINYCLOUD_NODE_CONFIG_ROOT",
            home.path().join("node-config"),
        )
        .envs(env.iter().copied())
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        status.is_some(),
        "tinycloud {args:?} did not exit within 20s (server started?)\nstdout: {stdout}\nstderr: {stderr}"
    );
    Run {
        code: status.and_then(|status| status.code()),
        stdout,
        stderr,
    }
}

/// The run was answered by the CLI, not by the server start path.
fn assert_cli_handled(args: &[&str], run: &Run) {
    assert!(
        !run.stderr.contains("Failed to start tinycloud-node")
            && !run.stderr.contains("runtime configuration is"),
        "tinycloud {args:?} fell through to the server start\nstderr: {}",
        run.stderr
    );
}

#[test]
fn node_help_lists_subcommands_without_starting_the_server() {
    let args = ["node", "--help"];
    let run = run_tinycloud(&args, &[]);
    assert_cli_handled(&args, &run);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    for subcommand in [
        "service", "status", "logs", "doctor", "key", "link", "tunnel",
    ] {
        assert!(
            run.stdout
                .lines()
                .any(|line| line.trim_start().starts_with(subcommand)),
            "`tinycloud node --help` does not list `{subcommand}`:\n{}",
            run.stdout
        );
    }
}

#[test]
fn top_level_help_lists_serve_and_node() {
    let args = ["--help"];
    let run = run_tinycloud(&args, &[]);
    assert_cli_handled(&args, &run);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    for subcommand in ["serve", "node"] {
        assert!(
            run.stdout
                .lines()
                .any(|line| line.trim_start().starts_with(subcommand)),
            "`tinycloud --help` does not list `{subcommand}`:\n{}",
            run.stdout
        );
    }
}

#[test]
fn version_prints_the_package_version() {
    let args = ["--version"];
    let run = run_tinycloud(&args, &[]);
    assert_cli_handled(&args, &run);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        format!("tinycloud {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn node_status_json_on_an_empty_home_reports_that_no_service_is_installed() {
    // The empty HOME has no service manifest. The CLI reports that on stderr
    // and exits 1 with nothing on stdout, so a caller parsing stdout as JSON
    // sees an empty document, never a half-started node.
    let args = ["node", "status", "--json"];
    let run = run_tinycloud(&args, &[]);
    assert_cli_handled(&args, &run);
    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    assert!(run.stdout.is_empty(), "stdout: {}", run.stdout);
    assert!(
        run.stderr.contains("service is not installed"),
        "stderr: {}",
        run.stderr
    );
}

#[test]
fn unrecognised_arguments_are_a_usage_error_and_never_start_a_server() {
    for args in [
        &["help"][..],
        &["-v"],
        &["-x", "-h"],
        &["--config", "x"],
        &["servee"],
        &["--validate-config", "--help"],
        &["--bogus"],
    ] {
        let run = run_tinycloud(args, &[]);
        assert_cli_handled(args, &run);
        assert_eq!(run.code, Some(2), "{args:?} stderr: {}", run.stderr);
        assert!(
            run.stderr.contains("Usage:"),
            "{args:?} stderr: {}",
            run.stderr
        );
        assert!(run.stdout.is_empty(), "{args:?} stdout: {}", run.stdout);
    }
}

#[test]
fn validate_config_still_checks_the_configuration_without_the_cli() {
    let args = ["--validate-config"];
    let valid = run_tinycloud(
        &args,
        &[
            ("TINYCLOUD_KEYS__TYPE", "static"),
            ("TINYCLOUD_KEYS__SECRET", TEST_SECRET),
        ],
    );
    assert_eq!(valid.code, Some(0), "stderr: {}", valid.stderr);
    assert!(
        valid.stderr.contains("runtime configuration is valid"),
        "stderr: {}",
        valid.stderr
    );

    // Share email enabled without a trust bundle is rejected before any
    // socket or key is opened.
    let invalid = run_tinycloud(
        &args,
        &[
            ("TINYCLOUD_KEYS__TYPE", "static"),
            ("TINYCLOUD_KEYS__SECRET", TEST_SECRET),
            ("TINYCLOUD_SHARE_EMAIL__ENABLED", "true"),
        ],
    );
    assert_eq!(invalid.code, Some(1), "stderr: {}", invalid.stderr);
    assert!(
        invalid.stderr.contains("runtime configuration is invalid"),
        "stderr: {}",
        invalid.stderr
    );
}

#[test]
fn no_arguments_keep_the_server_start_path() {
    // No key source is configured, so the server start path reports that and
    // exits before binding anything. The CLI would answer with a usage error.
    let run = run_tinycloud(&[], &[]);
    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("Failed to start tinycloud-node"),
        "stderr: {}",
        run.stderr
    );
    assert!(!run.stderr.contains("Usage:"), "stderr: {}", run.stderr);
}
