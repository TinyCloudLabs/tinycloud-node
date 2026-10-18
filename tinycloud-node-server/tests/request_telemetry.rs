//! TC-959 N2: exercise the real node, not a mocked logging subscriber.
use std::{
    fs::File,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::Value;
use uuid::Uuid;

// Synthetic fixture material; never an operator credential.
const SECRET: &str = "VEMtOTU5IHJlcXVlc3QgdGVsZW1ldHJ5IHN5bnRoZXRpYyB0ZXN0IHNlY3JldA";

struct Node {
    child: Child,
    root: tempfile::TempDir,
    base: String,
    client: reqwest::blocking::Client,
}

impl Node {
    fn start(level: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let port = free_port();
        let base = format!("http://127.0.0.1:{port}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
        // An inherited configuration must never redirect a test to a real DB.
        for (name, _) in std::env::vars_os() {
            let text = name.to_string_lossy();
            if text.starts_with("TINYCLOUD_") || text.starts_with("ROCKET_") || text == "RUST_LOG" {
                command.env_remove(name);
            }
        }
        let child = command
            .current_dir(root.path())
            .env("TINYCLOUD_CONFIG_FILE", root.path().join("absent.toml"))
            .env("TINYCLOUD_ADDRESS", "127.0.0.1")
            .env("TINYCLOUD_PORT", port.to_string())
            .env("TINYCLOUD_LOG_LEVEL", "normal")
            .env("RUST_LOG", level)
            .env("TINYCLOUD_LOG__FORMAT", "Json")
            .env("TINYCLOUD_TELEMETRY__ENABLED", "false")
            .env("TINYCLOUD_PROMETHEUS__PORT", free_port().to_string())
            .env("TINYCLOUD_STORAGE__DATADIR", root.path().join("data"))
            .env("TINYCLOUD_KEYS__TYPE", "static")
            .env("TINYCLOUD_KEYS__SECRET", SECRET)
            .stdin(Stdio::null())
            .stdout(File::create(root.path().join("stdout.log")).unwrap())
            .stderr(File::create(root.path().join("stderr.log")).unwrap())
            .spawn()
            .unwrap();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let mut node = Self {
            child,
            root,
            base,
            client,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            assert!(
                node.child.try_wait().unwrap().is_none(),
                "node exited: {}",
                node.logs()
            );
            if node
                .client
                .get(format!("{}/healthz", node.base))
                .send()
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "node did not start: {}",
                node.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        node
    }

    fn get(&self, path: &str, ids: &[&str]) -> reqwest::blocking::Response {
        let mut request = self.client.get(format!("{}{path}", self.base));
        for id in ids {
            request = request.header("x-request-id", *id);
        }
        request.send().unwrap()
    }

    fn logs(&self) -> String {
        ["stdout.log", "stderr.log"]
            .map(|name| std::fs::read_to_string(self.root.path().join(name)).unwrap())
            .join("\n")
    }

    fn events(&self) -> Vec<Value> {
        self.logs()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|value| value["target"] == "tinycloud::request")
            .map(|value| value["fields"].clone())
            .collect()
    }

    fn event(&self, id: &str) -> Value {
        let events = self.events();
        let matching: Vec<_> = events
            .iter()
            .filter(|event| event["request_id"] == id)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "one event per request; events={events:?}"
        );
        matching[0].clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn echoed(response: &reqwest::blocking::Response) -> String {
    let value = response
        .headers()
        .get("x-request-id")
        .expect("node must echo x-request-id")
        .to_str()
        .unwrap();
    let id = Uuid::parse_str(value).expect("echo must be a UUID");
    assert_eq!(
        value,
        id.hyphenated().to_string(),
        "wire UUID is canonical lowercase"
    );
    assert!(!id.is_nil());
    value.to_string()
}

fn check_event(event: &Value, route: &str, status: u16) {
    assert_eq!(event["event"], "node_request");
    assert_eq!(event["svc"], "api");
    assert_eq!(event["method"], "GET");
    assert_eq!(event["route"], route);
    assert_eq!(event["status"], status);
    assert!(event["latency_us"].as_u64().is_some());
    for field in ["pool_wait_ms", "query_time_ms"] {
        let number = event[field]
            .as_f64()
            .unwrap_or_else(|| panic!("missing numeric {field}: {event}"));
        assert!(number.is_finite() && number >= 0.0);
    }
    assert!(event["query_count"].as_u64().is_some());
    assert!(event["request_id_replaced"].as_bool().is_some());
    let allowed = [
        "message",
        "event",
        "svc",
        "method",
        "route",
        "status",
        "latency_us",
        "request_id",
        "request_id_replaced",
        "pool_wait_ms",
        "query_time_ms",
        "query_count",
        "account_hash",
        "space_hash",
    ];
    for key in event.as_object().unwrap().keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "non-allowlisted field {key}"
        );
    }
    assert!(
        serde_json::to_vec(event).unwrap().len() < 2048,
        "bounded request event"
    );
}

#[test]
fn valid_uuid_is_accepted_normalized_echoed_and_propagated_to_one_event() {
    let node = Node::start("info");
    let id = Uuid::new_v4().hyphenated().to_string();
    let response = node.get("/version", &[&id.to_uppercase()]);
    assert_eq!(response.status(), 200);
    assert_eq!(echoed(&response), id);
    let event = node.event(&id);
    assert_eq!(event["request_id_replaced"], false);
    check_event(&event, "/version", 200);
    assert_eq!(event["pool_wait_ms"], 0.0);
    assert_eq!(event["query_time_ms"], 0.0);
    assert_eq!(event["query_count"], 0);
    assert!(event.get("account_hash").is_none());
    assert!(event.get("space_hash").is_none());
}

#[test]
fn rfc_variant_uuid_versions_one_through_eight_are_accepted_and_other_forms_mint_v4() {
    let node = Node::start("info");
    for version in 1..=8 {
        let mut bytes = [0x12; 16];
        bytes[6] = version << 4 | 0x02;
        bytes[8] = 0x92;
        let id = Uuid::from_bytes(bytes).to_string();
        let response = node.get("/version", &[&id.to_uppercase()]);
        assert_eq!(node.event(&id)["request_id_replaced"], false);
        assert_eq!(echoed(&response), id);
        check_event(&node.event(&id), "/version", 200);
    }
    for invalid in [
        "12121212-1212-0212-9212-121212121212",
        "12121212-1212-9212-9212-121212121212",
        "12121212-1212-4212-1212-121212121212",
        "12121212-1212-4212-c212-121212121212",
        "12121212-1212-4212-e212-121212121212",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "12121212121242129212121212121212",
        "12121212-1212-4212-9212-12121212121x",
    ] {
        let response = node.get("/version", &[invalid]);
        let id = echoed(&response);
        assert_ne!(id, invalid);
        assert_eq!(Uuid::parse_str(&id).unwrap().get_version_num(), 4);
        assert_eq!(node.event(&id)["request_id_replaced"], true);
        check_event(&node.event(&id), "/version", 200);
    }
}

#[test]
fn health_probe_counts_its_real_database_transaction() {
    let node = Node::start("info");
    let id = Uuid::new_v4().to_string();
    let response = node.get("/healthz", &[&id]);
    assert_eq!(response.status(), 200);
    let event = node.event(&id);
    check_event(&event, "/healthz", 200);
    assert!(event["query_count"].as_u64().unwrap() > 0);
    assert!(event["query_time_ms"].as_f64().unwrap() > 0.0);
    assert!(event["pool_wait_ms"].as_f64().unwrap() > 0.0);
}

#[test]
fn malformed_ambiguous_or_untrusted_request_ids_are_replaced_without_logging_input() {
    let node = Node::start("trace");
    let canary = "tc959header-secret-bearer-not-a-uuid";
    let valid = Uuid::new_v4().to_string();
    for headers in [
        vec![],
        vec![canary],
        vec!["00000000-0000-0000-0000-000000000000"],
        vec![&valid, &valid],
        vec!["urn:uuid:9cfbd2ac-052c-40e5-a64c-abf6b49ebccc"],
    ] {
        let response = node.get("/tc959-unmatched-private-path", &headers);
        assert_eq!(response.status(), 404);
        let id = echoed(&response);
        assert_eq!(Uuid::parse_str(&id).unwrap().get_version_num(), 4);
        assert_eq!(node.event(&id)["request_id_replaced"], !headers.is_empty());
        assert!(!headers.contains(&id.as_str()));
        check_event(&node.event(&id), "<unmatched>", 404);
    }
    let logs = node.logs();
    assert!(!logs.contains(canary));
    assert!(!logs.contains("tc959-unmatched-private-path"));
}

#[test]
fn real_database_requests_have_keyed_pseudonyms_and_no_sql_or_identity_leaks() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tinycloud_core::keys::StaticSecret;
    let node = Node::start("trace");
    let wallet = "0x1234567890abcdef1234567890abcdef12345678";
    let parsed: tinycloud_auth::resource::SpaceId =
        format!("tinycloud:pkh:eip155:1:{wallet}:public")
            .parse()
            .unwrap();
    let account = parsed.did().to_string();
    let space = parsed.to_string();
    let path = format!("/public/{space}/kv/tc959-private-key");
    let id = Uuid::new_v4().to_string();
    let response = node.get(&path, &[&id]);
    assert_eq!(response.status(), 404);
    let event = node.event(&id);
    check_event(&event, "/public/<space_id>/kv/<key..>", 404);
    assert!(event["query_count"].as_u64().unwrap() > 0);
    assert!(event["query_time_ms"].as_f64().unwrap() > 0.0);
    assert!(event["pool_wait_ms"].as_f64().unwrap() > 0.0);
    let key = StaticSecret::new(base64::decode_config(SECRET, base64::URL_SAFE_NO_PAD).unwrap())
        .unwrap()
        .derive_key(b"tinycloud/telemetry/pseudonyms/v1");
    for (field, domain, identity) in [
        ("account_hash", b"account\0".as_slice(), account.as_str()),
        ("space_hash", b"space\0".as_slice(), space.as_str()),
    ] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(domain);
        mac.update(identity.as_bytes());
        assert_eq!(event[field], hex::encode(mac.finalize().into_bytes()));
    }
    let again = Uuid::new_v4().to_string();
    node.get(&path, &[&again]);
    let second = node.event(&again);
    assert_eq!(event["space_hash"], second["space_hash"]);
    assert_eq!(event["account_hash"], second["account_hash"]);
    let logs = node.logs();
    for forbidden in [
        SECRET,
        wallet,
        account.as_str(),
        space.as_str(),
        "tc959-private-key",
        "SELECT",
        "FROM \"kv\"",
    ] {
        assert!(
            !logs.contains(forbidden),
            "forbidden value reached stdout/stderr: {forbidden}"
        );
    }
}

#[test]
fn sql_statement_text_stays_out_of_real_process_debug_and_trace_logs() {
    for level in ["debug", "trace"] {
        let node = Node::start(level);
        let space = "tinycloud:pkh:eip155:1:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd:public";
        let response = node.get(&format!("/public/{space}/kv/tc959-sql-canary"), &[]);
        assert_eq!(response.status(), 404);
        let logs = node.logs();
        for forbidden in [
            "SELECT ",
            "INSERT INTO ",
            "CREATE TABLE ",
            "db.statement",
            space,
            "tc959-sql-canary",
        ] {
            assert!(
                !logs.contains(forbidden),
                "{level} stdout/stderr leaked {forbidden}"
            );
        }
    }
}

#[test]
fn canonical_shared_vectors_cross_the_real_binary_http_boundary() {
    // Exact corpus from tinycloud-dev 76bd10752a52f179ac2a49214f488236d02f8192.
    // SHA-256 d995cd9065a9e1c51bc4d3ed041c3bf2a0363e9a04a90f1d07914437d8dd9a80.
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/request-id-vectors.json")).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    let node = Node::start("trace");
    for case in cases {
        let before = node.events().len();
        let mut connection = TcpStream::connect(node.base.trim_start_matches("http://")).unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            connection,
            "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        )
        .unwrap();
        if let Some(values) = case["incoming"].as_array() {
            for value in values {
                write!(connection, "X-ReQuEsT-ID: {}\r\n", value.as_str().unwrap()).unwrap();
            }
        }
        write!(connection, "\r\n").unwrap();
        let mut response = String::new();
        connection.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 "),
            "HTTP case {}: {response}",
            case["name"]
        );
        let id = response
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
            .map(|(_, value)| value.trim())
            .expect("real node echoes canonical UUID");

        // HTTP OWS and line delimiters are removed by Hyper before Rocket sees
        // field values. The identical application-visible padding/LF corpus is
        // checked, without normalization, in tracing's middleware-boundary test.
        let visible = case["incoming"]
            .as_array()
            .map(|values| {
                Value::Array(
                    values
                        .iter()
                        .map(|value| {
                            Value::String(
                                value
                                    .as_str()
                                    .unwrap()
                                    .split('\n')
                                    .next()
                                    .unwrap()
                                    .trim_matches([' ', '\t', '\r'])
                                    .to_string(),
                            )
                        })
                        .collect(),
                )
            })
            .unwrap_or(Value::Null);
        let expected = cases
            .iter()
            .find(|candidate| candidate["incoming"] == visible)
            .expect("transport-normalized fields also have a canonical corpus oracle");
        let events = node.events();
        assert_eq!(
            events.len(),
            before + 1,
            "one event for HTTP case {}",
            case["name"]
        );
        let event = &events[before];
        check_event(event, "/version", 200);
        assert_eq!(event["request_id"], id);
        assert_eq!(
            event["request_id_replaced"],
            expected["request_id_replaced"]
        );
        if let Some(normalized) = expected["normalized"].as_str() {
            assert_eq!(id, normalized, "HTTP case {}", case["name"]);
        } else {
            assert_eq!(
                Uuid::parse_str(id).unwrap().get_version_num(),
                4,
                "HTTP case {}",
                case["name"]
            );
        }
    }
}

#[test]
fn burst_request_stream_keeps_every_bounded_typed_completion() {
    use std::collections::BTreeSet;
    let node = Node::start("info");
    let mut responses = BTreeSet::new();
    for _ in 0..2_100 {
        let id = Uuid::new_v4().to_string();
        let response = node.get("/version", &[&id]);
        assert_eq!(response.status(), 200);
        assert_eq!(echoed(&response), id);
        assert!(responses.insert(id));
    }
    let mut completions = BTreeSet::new();
    for event in node
        .events()
        .iter()
        .filter(|event| event["route"] == "/version")
    {
        check_event(event, "/version", 200);
        assert_eq!(event["request_id_replaced"], false);
        assert_eq!(event["query_count"], 0);
        assert_eq!(event["pool_wait_ms"], 0.0);
        assert_eq!(event["query_time_ms"], 0.0);
        assert!(
            completions.insert(event["request_id"].as_str().unwrap().to_string()),
            "duplicate completion"
        );
    }
    assert_eq!(
        completions, responses,
        "every real response has exactly one bounded source event"
    );
}
