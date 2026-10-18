//! The node identity each key source resolves at startup, observed through
//! the real `tinycloud` binary's `/.well-known/tinycloud/node-keys` (TC-1442).
//!
//! - `node service install` writes `[global.keys] type = "provider"`, and the
//!   installed unit runs `serve --config <that file>`. That, and the same file
//!   without a key section (`type = "Auto"`, the default), must boot with the
//!   provider identity, keep it across restarts, and report it to the
//!   control plane.
//! - The production key sources must keep resolving the DID they resolve
//!   today. The DIDs below are pinned from fixed fixture keys; none of them is
//!   a real node key.

use std::{
    fs::{self, File},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tinycloud_core::keys::StaticSecret;

/// The repository's `tinycloud.toml`, which the Docker image copies next to
/// the `/tinycloud` entrypoint.
const SHIPPED_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tinycloud.toml");

/// base64url of the 32 bytes `TC-1442 static-env fixture key!!`.
const STATIC_SECRET: &str = "VEMtMTQ0MiBzdGF0aWMtZW52IGZpeHR1cmUga2V5ISE";
/// What the node published for `STATIC_SECRET` before TC-1442's provider fix.
const STATIC_DID: &str = "did:key:z6Mkocaf9dnjBPLMQpu5jo4mLRMnqTEugbMCMS1zvb6ahrvH";

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

/// A `tinycloud` command that inherits no node configuration from the test
/// process, so only the environment each test sets applies.
fn tinycloud(cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tinycloud"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(cwd)
        .stdin(Stdio::null());
    command
}

/// Start the node and wait until it serves. Returns the running node and the
/// DID it publishes.
fn start_node(mut command: Command, logs: &Path) -> (KillOnDrop, String) {
    let port = free_port();
    let stderr_path = logs.join(format!("stderr-{port}.log"));
    let child = command
        .env("TINYCLOUD_ADDRESS", "127.0.0.1")
        .env("TINYCLOUD_PORT", port.to_string())
        .stdout(File::create(logs.join(format!("stdout-{port}.log"))).unwrap())
        .stderr(File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let mut server = KillOnDrop(child);

    let url = format!("http://127.0.0.1:{port}/.well-known/tinycloud/node-keys");
    let client = reqwest::blocking::Client::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!(
                "tinycloud exited before serving ({status}):\n{}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            );
        }
        if let Ok(response) = client.get(&url).send() {
            if response.status().is_success() {
                let body: serde_json::Value = response.json().unwrap();
                let did = body["nodeDid"].as_str().unwrap().to_owned();
                return (server, did);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("tinycloud did not serve within 60s");
}

/// The container layout: `tinycloud.toml` in the working directory.
fn shipped_layout() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::copy(SHIPPED_CONFIG, dir.path().join("tinycloud.toml")).unwrap();
    dir
}

#[test]
fn shipped_config_with_a_static_secret_keeps_its_did() {
    let dir = shipped_layout();
    let secret = base64::decode_config(STATIC_SECRET, base64::URL_SAFE_NO_PAD).unwrap();
    assert_eq!(StaticSecret::new(secret).unwrap().node_did(), STATIC_DID);

    // The container entrypoint: `/tinycloud` with no arguments.
    let mut legacy = tinycloud(dir.path());
    legacy.env("TINYCLOUD_KEYS__SECRET", STATIC_SECRET);
    assert_eq!(start_node(legacy, dir.path()).1, STATIC_DID);

    let mut serve = tinycloud(dir.path());
    serve
        .args(["serve", "--config", "tinycloud.toml"])
        .env("TINYCLOUD_KEYS__SECRET", STATIC_SECRET);
    assert_eq!(start_node(serve, dir.path()).1, STATIC_DID);
}

#[cfg(feature = "dstack")]
mod dstack {
    use super::*;
    use parking_lot::Mutex;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        path::PathBuf,
        sync::Arc,
    };

    /// The bytes the stand-in guest agent derives for the node's key path:
    /// `TC-1442 dstack GetKey fixture!!!`.
    const KEY_HEX: &str = "54432d313434322064737461636b204765744b65792066697874757265212121";
    /// What the node published for `KEY_HEX` before TC-1442's provider fix.
    const DSTACK_DID: &str = "did:key:z6MkmRVxeLv23jCfiR5XQMt5yZsyP5rxoS8GD8RkWoo7BnBA";
    /// The derivation path production's KMS key (and so its DID) comes from.
    const PRIMARY_KEY_PATH: &str = "tinycloud/keys/primary";

    /// A dstack guest agent on a Unix socket: answers `GetKey` for the
    /// node's key path with `KEY_HEX` and `Info` with fixed values, and
    /// records every `GetKey` path it is asked for.
    fn guest_agent(socket: PathBuf) -> Arc<Mutex<Vec<String>>> {
        let listener = UnixListener::bind(socket).unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&paths);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                let request = String::from_utf8(request).unwrap();
                let (head, body) = request.split_once("\r\n\r\n").unwrap();
                let (status, reply) = if head.starts_with("POST /GetKey ") {
                    let body: serde_json::Value = serde_json::from_str(body).unwrap();
                    let path = body["path"].as_str().unwrap().to_owned();
                    recorded.lock().push(path.clone());
                    if path == PRIMARY_KEY_PATH {
                        ("200 OK", format!("{{\"key\":\"{KEY_HEX}\"}}"))
                    } else {
                        ("404 Not Found", "{}".to_owned())
                    }
                } else if head.starts_with("GET /Info ") {
                    (
                        "200 OK",
                        r#"{"app_id":"tc1442","compose_hash":"tc1442","instance_id":"tc1442"}"#
                            .to_owned(),
                    )
                } else {
                    ("404 Not Found", "{}".to_owned())
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
            }
        });
        paths
    }

    /// Production runs the image's `tinycloud.toml` (`type = "Static"`) with
    /// `TINYCLOUD_KEYS_TYPE=Dstack` and the guest agent's socket.
    #[test]
    fn production_dstack_config_keeps_its_did() {
        let dir = shipped_layout();
        let key = hex::decode(KEY_HEX).unwrap();
        assert_eq!(StaticSecret::new(key).unwrap().node_did(), DSTACK_DID);
        let socket = dir.path().join("dstack.sock");
        let requested = guest_agent(socket.clone());

        let mut legacy = tinycloud(dir.path());
        legacy
            .env("TINYCLOUD_KEYS_TYPE", "Dstack")
            .env("DSTACK_SIMULATOR_ENDPOINT", &socket);
        assert_eq!(start_node(legacy, dir.path()).1, DSTACK_DID);

        let requested = requested.lock();
        assert!(
            !requested.is_empty(),
            "the node never asked dstack for a key"
        );
        assert!(
            requested.iter().all(|path| path == PRIMARY_KEY_PATH),
            "the node asked dstack for {requested:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn installed_provider_config_serves_a_stable_identity() {
    installed_node_serves_a_stable_identity(|config| config);
}

#[cfg(target_os = "linux")]
#[test]
fn installed_config_without_a_key_section_serves_a_stable_identity() {
    installed_node_serves_a_stable_identity(|config| {
        let auto = config.replace("\n[global.keys]\ntype = \"provider\"\n", "");
        assert_ne!(auto, config);
        auto
    });
}

/// `node service install` on a fresh Linux user account, `edit` applied to the
/// config it writes, then the command its systemd unit runs. Linux only:
/// macOS stores the provider key in the keychain.
#[cfg(target_os = "linux")]
fn installed_node_serves_a_stable_identity(edit: fn(String) -> String) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bin).unwrap();
    // `install` enables the unit through `systemctl --user`.
    let systemctl = bin.join("systemctl");
    fs::write(&systemctl, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    let user_command = || {
        let mut command = tinycloud(dir.path());
        command
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("xdg-config"))
            .env("XDG_DATA_HOME", home.join("xdg-data"))
            .env("XDG_STATE_HOME", home.join("xdg-state"));
        command
    };

    let installed = user_command()
        .args(["node", "service", "install"])
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let config = home.join("xdg-config/tinycloud-node/tinycloud.toml");
    let written = fs::read_to_string(&config).unwrap();
    assert!(written.contains("\n[global.keys]\ntype = \"provider\"\n"));
    fs::write(&config, edit(written)).unwrap();

    let serve = || {
        let mut command = user_command();
        command.arg("serve").arg("--config").arg(&config);
        command
    };

    // First boot generates the identity; the control plane must report it.
    let (server, did) = start_node(serve(), dir.path());
    assert!(did.starts_with("did:key:"), "{did}");
    let status = user_command()
        .args(["node", "status", "--json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "node status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["identityReady"], true, "{status}");
    assert_eq!(status["nodeDid"].as_str(), Some(did.as_str()), "{status}");
    drop(server);

    // A restart loads the stored identity instead of making a new one.
    assert_eq!(start_node(serve(), dir.path()).1, did);
}
