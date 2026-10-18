//! The released `tinycloud` binary must route `node ...`, `serve`, `--help`
//! and `--version` to the clap CLI instead of booting the server (TC-1442).
//!
//! Every invocation runs with a scrubbed environment and an empty HOME, so a
//! binary that falls through to the server start fails fast on the missing key
//! source rather than binding a socket. The timeout turns any accidental
//! server start into a test failure instead of a hang.

use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_tinycloud(args: &[&str]) -> Run {
    let home = tempfile::tempdir().unwrap();
    let config_root = home.path().join("node-config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tinycloud"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("xdg-config"))
        .env("XDG_DATA_HOME", home.path().join("xdg-data"))
        .env("XDG_STATE_HOME", home.path().join("xdg-state"))
        .env("TINYCLOUD_NODE_CONFIG_ROOT", &config_root)
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
    let run = Run {
        code: status.and_then(|status| status.code()),
        stdout,
        stderr,
    };
    assert!(
        status.is_some(),
        "tinycloud {args:?} did not exit within 20s (server started?)\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        !run.stderr.contains("Failed to start tinycloud-node"),
        "tinycloud {args:?} fell through to the server start\nstderr: {}",
        run.stderr
    );
    run
}

#[test]
fn node_help_lists_subcommands_without_starting_the_server() {
    let run = run_tinycloud(&["node", "--help"]);
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
    let run = run_tinycloud(&["--help"]);
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
fn version_prints_the_package_version_without_starting_the_server() {
    let run = run_tinycloud(&["--version"]);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        format!("tinycloud {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn node_status_json_on_an_empty_home_fails_fast_without_starting_the_server() {
    // No service is installed under the empty HOME: the command reports that
    // through the CLI error path (exit 1, nothing on stdout) and returns.
    let run = run_tinycloud(&["node", "status", "--json"]);
    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    assert!(run.stdout.is_empty(), "stdout: {}", run.stdout);
}
