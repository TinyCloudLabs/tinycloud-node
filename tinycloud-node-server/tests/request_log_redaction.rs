//! TC-961: production logs are publicly readable, so the node must never write
//! a signed-KV ticket id, a space id (which embeds a wallet address) or any
//! other raw request path to them.
//!
//! This runs the real `tinycloud` binary with the production log setting
//! (`TINYCLOUD_LOG_LEVEL=normal`, telemetry on), drives requests carrying
//! unique markers through it over HTTP, and checks everything the process
//! wrote to stdout and stderr.

use std::{
    fs::File,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const STATIC_SECRET: &str =
    "VEMtOTYxIHJlcXVlc3QgbG9nIHJlZGFjdGlvbiB0ZXN0IHNlY3JldCBrZXkgbWF0ZXJpYWw";

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn marker(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
}

/// Drop ANSI escape sequences so a colored field name can't split a match.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn read_logs(dir: &Path) -> String {
    let stdout = std::fs::read_to_string(dir.join("stdout.log")).unwrap();
    let stderr = std::fs::read_to_string(dir.join("stderr.log")).unwrap();
    strip_ansi(&format!("{stdout}{stderr}"))
}

fn wait_until_healthy(client: &reqwest::blocking::Client, base: &str, server: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(status) = server.try_wait().unwrap() {
            panic!("tinycloud exited before becoming healthy: {status}");
        }
        if let Ok(response) = client.get(format!("{base}/healthz")).send() {
            if response.status().is_success() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("tinycloud did not become healthy within 60s");
}

#[test]
fn production_logs_carry_neither_signed_kv_tickets_nor_space_ids() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");

    let ticket = marker("tc961ticket");
    let wallet = uuid::Uuid::new_v4().simple().to_string() + "00000000";
    let space = format!("tinycloud:pkh:eip155:1:0x{wallet}:default");
    let key = marker("tc961key");

    let server = Command::new(env!("CARGO_BIN_EXE_tinycloud"))
        .current_dir(dir.path())
        .env_remove("RUST_LOG")
        .env_remove("ROCKET_LOG_LEVEL")
        .env("TINYCLOUD_CONFIG_FILE", dir.path().join("absent.toml"))
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", port.to_string())
        .env("TINYCLOUD_LOG_LEVEL", "normal")
        .env("TINYCLOUD_TELEMETRY__ENABLED", "true")
        .env("TINYCLOUD_PROMETHEUS__PORT", free_port().to_string())
        .env("TINYCLOUD_STORAGE__DATADIR", dir.path().join("data"))
        .env("TINYCLOUD_KEYS__TYPE", "static")
        .env("TINYCLOUD_KEYS__SECRET", STATIC_SECRET)
        .stdin(Stdio::null())
        .stdout(File::create(dir.path().join("stdout.log")).unwrap())
        .stderr(File::create(dir.path().join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let mut server = KillOnDrop(server);

    let client = reqwest::blocking::Client::new();
    wait_until_healthy(&client, &base, &mut server.0);

    // Matched routes, a query string, and paths no route matches (Rocket logs
    // those separately, at ERROR).
    let requests = [
        (reqwest::Method::GET, format!("/signed/kv/{ticket}")),
        (reqwest::Method::HEAD, format!("/signed/kv/{ticket}")),
        (reqwest::Method::GET, format!("/signed/kv/{ticket}/unmatched")),
        (reqwest::Method::GET, format!("/public/{space}/kv/{key}")),
        (reqwest::Method::HEAD, format!("/public/{space}/kv/{key}")),
        (reqwest::Method::GET, format!("/public/{space}/kv?prefix={key}")),
        (reqwest::Method::GET, format!("/public/{space}/unmatched/{key}")),
    ];
    for (method, path) in &requests {
        let response = client
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .unwrap();
        assert!(
            !response.status().is_success(),
            "{method} {path} unexpectedly succeeded"
        );
    }

    // Rocket and the request-logging fairing both write before the response
    // is sent; a short pause covers any stdout buffering.
    std::thread::sleep(Duration::from_millis(200));
    drop(server);
    let logs = read_logs(dir.path());

    for (what, needle) in [
        ("signed-KV ticket id", ticket.as_str()),
        ("space id", space.as_str()),
        ("wallet address", wallet.as_str()),
        ("KV key", key.as_str()),
    ] {
        let leaked: Vec<&str> = logs.lines().filter(|line| line.contains(needle)).collect();
        assert!(
            leaked.is_empty(),
            "the {what} reached the log:\n{}",
            leaked.join("\n")
        );
    }

    // Requests are still logged, by route template rather than raw path.
    for template in [
        "/signed/kv/<ticket_id>",
        "/public/<space_id>/kv/<key..>",
        "/public/<space_id>/kv?<prefix>",
    ] {
        assert!(
            logs.lines()
                .any(|line| line.contains("tinycloud::request") && line.contains(template)),
            "no request line for {template}; logs:\n{logs}"
        );
    }
}
