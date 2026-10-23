//! TC-1482 / TC-961: production logs are publicly readable, so neither the
//! stats token, the admin secret, nor a wallet address returned by
//! `GET /admin/stats` may reach them.
//!
//! Runs the real `tinycloud` binary (as `tests/request_log_redaction.rs` does)
//! over a SQLite file seeded with a space whose owner carries a unique
//! address, drives the route with the right token, the wrong token, the admin
//! secret and no credential, and searches everything the process wrote to
//! stdout and stderr.

use std::{
    fs::File,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use tinycloud_core::sea_orm::{ConnectionTrait, Database, DbBackend, Statement, Value};

const STATIC_SECRET: &str = "VEMtMTQ4MiByZXF1ZXN0IGxvZyBsZWFrIHRlc3Qgc2VjcmV0IGtleSBtYXRlcmlhbA";

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

/// One space with a live key, owned by `owner`.
async fn seed(database: &str, space: &str) {
    let conn = Database::connect(database).await.unwrap();
    let blob = |tag: &str| Value::Bytes(Some(Box::new(tag.as_bytes().to_vec())));
    for (sql, values) in [
        ("INSERT INTO space (id) VALUES (?)", vec![space.into()]),
        (
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, \
             metadata, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                space.into(),
                "k".into(),
                blob("invocation"),
                1i64.into(),
                blob("epoch"),
                1i64.into(),
                blob("value"),
                Value::Json(Some(Box::new(serde_json::json!({})))),
                false.into(),
            ],
        ),
    ] {
        conn.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            sql,
            values,
        ))
        .await
        .unwrap();
    }
    conn.close().await.unwrap();
}

#[test]
fn production_logs_carry_no_stats_token_or_address() {
    assert_stats_data_stays_out_of_logs(&[]);
}

#[test]
fn debug_logs_carry_no_stats_token_or_address() {
    assert_stats_data_stays_out_of_logs(&[("TINYCLOUD_LOG_LEVEL", "debug")]);
}

#[test]
fn trace_logs_carry_no_stats_token_or_address() {
    assert_stats_data_stays_out_of_logs(&[("RUST_LOG", "trace")]);
}

fn assert_stats_data_stays_out_of_logs(extra_env: &[(&str, &str)]) {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let database = format!("sqlite:{}?mode=rwc", dir.path().join("node.db").display());

    let token = marker("tc1482token");
    let admin_secret = marker("tc1482admin");
    let wrong_token = marker("tc1482wrong");
    let wallet = uuid::Uuid::new_v4().simple().to_string() + "0000000a";
    let space = format!("tinycloud:pkh:eip155:1:0x{wallet}:default");

    let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
    // No inherited node configuration: only the settings below apply.
    for (name, _) in std::env::vars_os() {
        let name_str = name.to_string_lossy();
        if name_str.starts_with("TINYCLOUD_")
            || name_str.starts_with("ROCKET_")
            || name_str == "RUST_LOG"
            || name_str == "NODE_STATS_READ_TOKEN"
        {
            command.env_remove(&name);
        }
    }
    let server = command
        .current_dir(dir.path())
        .env("TINYCLOUD_CONFIG_FILE", dir.path().join("absent.toml"))
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", port.to_string())
        .env("TINYCLOUD_LOG_LEVEL", "normal")
        .env("TINYCLOUD_LOG__FORMAT", "Json")
        .envs(extra_env.iter().copied())
        .env("TINYCLOUD_TELEMETRY__ENABLED", "true")
        .env("TINYCLOUD_PROMETHEUS__PORT", free_port().to_string())
        .env("TINYCLOUD_STORAGE__DATADIR", dir.path().join("data"))
        .env("TINYCLOUD_STORAGE__DATABASE", &database)
        .env("TINYCLOUD_KEYS__TYPE", "static")
        .env("TINYCLOUD_KEYS__SECRET", STATIC_SECRET)
        .env("NODE_STATS_READ_TOKEN", &token)
        .env("TINYCLOUD_ADMIN_SECRET", &admin_secret)
        .stdin(Stdio::null())
        .stdout(File::create(dir.path().join("stdout.log")).unwrap())
        .stderr(File::create(dir.path().join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let mut server = KillOnDrop(server);

    let client = reqwest::blocking::Client::new();
    wait_until_healthy(&client, &base, &mut server.0);

    // The node has migrated the file by now; add the data the route will list.
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(seed(&database, &space));

    let stats = |authorization: Option<&str>| {
        let mut request = client.get(format!("{base}/admin/stats"));
        if let Some(authorization) = authorization {
            request = request.header("Authorization", authorization);
        }
        request.send().unwrap()
    };
    let ok = stats(Some(&format!("Bearer {token}")));
    assert_eq!(ok.status(), 200);
    let body = ok.text().unwrap();
    assert!(
        body.contains(&format!("0x{wallet}")),
        "the route must return the seeded owner, or this test proves nothing: {body}"
    );
    assert_eq!(stats(Some(&format!("Bearer {wrong_token}"))).status(), 401);
    assert_eq!(stats(Some(&format!("Bearer {admin_secret}"))).status(), 401);
    assert_eq!(stats(None).status(), 401);

    // Rocket and the request-logging fairing both write before the response
    // is sent; a short pause covers any stdout buffering.
    std::thread::sleep(Duration::from_millis(200));
    drop(server);
    let logs = read_logs(dir.path());

    for (what, needle) in [
        ("stats token", token.as_str()),
        ("admin secret", admin_secret.as_str()),
        ("presented wrong token", wrong_token.as_str()),
        ("owner address", wallet.as_str()),
        ("space id", space.as_str()),
    ] {
        let leaked: Vec<&str> = logs.lines().filter(|line| line.contains(needle)).collect();
        assert!(
            leaked.is_empty(),
            "the {what} reached the log:\n{}",
            leaked.join("\n")
        );
    }

    // Each request is still logged once, by method and route template.
    let stats_events = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| {
            event["target"] == "tinycloud::request" && event["fields"]["route"] == "/admin/stats"
        })
        .count();
    assert_eq!(stats_events, 4, "one request event per call:\n{logs}");
}
