//! TC-887 S1 through the real app: provisioning, the ceremony test-unlock,
//! the encrypt gate at boot, and recovery of a node booted under a new root.
//! SQLite file and filesystem blocks in a temp dir, so restarts keep state.

use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;

use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use tinycloud_at_rest_escrow::{
    binding_digest, recovery_binding, wrap_share, EscrowBundle, RecoveryInfo,
};

const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

struct Holders(Vec<age::x25519::Identity>);

impl Holders {
    fn new() -> Self {
        Self((0..3).map(|_| age::x25519::Identity::generate()).collect())
    }

    fn recipients(&self) -> Value {
        json!(["sam", "hunter", "safe"]
            .iter()
            .zip(&self.0)
            .map(|(h, id)| json!({"holder": h, "recipient": id.to_public().to_string()}))
            .collect::<Vec<_>>())
    }

    /// Holder `i`: `age -d` their share, then seal it to the node's recovery key.
    fn wrapped(&self, bundle: &EscrowBundle, info: &RecoveryInfo, i: usize) -> String {
        let armored = &bundle.shares[i].ciphertext;
        let decryptor =
            age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armored.as_bytes()))
                .unwrap();
        let mut plain = Vec::new();
        decryptor
            .decrypt(std::iter::once(&self.0[i] as &dyn age::Identity))
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        let share = bundle.open_share(&plain).unwrap();
        wrap_share(&info.recovery_recipient, &share).unwrap()
    }
}

async fn app(dir: &Path, root: u8, at_rest: Value) -> anyhow::Result<Client> {
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.into();
    config.storage.database = Some(format!("sqlite:{}?mode=rwc", dir.join("caps.db").display()));
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([root; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    config.at_rest = serde_json::from_value(at_rest)?;
    let figment = Figment::from(rocket::Config {
        address: "127.0.0.1".parse()?,
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app(&figment).await?;
    Ok(Client::untracked(rocket).await?)
}

/// The boot must fail; returns the full error chain.
async fn refused(dir: &Path, root: u8, at_rest: Value) -> String {
    match app(dir, root, at_rest).await {
        Ok(_) => panic!("the node started, but this configuration must be refused"),
        Err(e) => format!("{e:#}"),
    }
}

fn remote() -> SocketAddr {
    "127.0.0.1:40000".parse().unwrap()
}

async fn get_json(client: &Client, uri: &str) -> (Status, Value) {
    let res = client
        .get(uri.to_string())
        .remote(remote())
        .dispatch()
        .await;
    let status = res.status();
    let body = res.into_string().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    )
}

async fn post_share(client: &Client, body: impl Into<Vec<u8>>) -> (Status, Value) {
    let res = client
        .post("/at-rest/recovery/shares")
        .remote(remote())
        .header(ContentType::Plain)
        .body(body.into())
        .dispatch()
        .await;
    let status = res.status();
    let body = res.into_string().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    )
}

async fn recovery(client: &Client) -> RecoveryInfo {
    let (status, body) = get_json(client, &format!("/at-rest/recovery?nonce={NONCE}")).await;
    assert_eq!(status, Status::Ok, "{body}");
    let info: RecoveryInfo = serde_json::from_value(body).unwrap();
    // No TEE here: no quote, and the holder tool would refuse to release.
    assert_eq!(info.mode, "classic");
    assert!(info.quote.is_none());
    assert_eq!(
        info.binding,
        recovery_binding(&info.recovery_recipient, &info.efp, NONCE)
    );
    assert_eq!(info.binding_sha256, binding_digest(&info.binding));
    info
}

#[tokio::test]
async fn ceremony_gate_and_recovery_through_the_app() {
    let dir = tempfile::tempdir().unwrap();
    let h = Holders::new();
    let escrow = |fp: Option<&str>| json!({"recipients": h.recipients(), "allow_software": true, "verified_fp": fp});

    // Default config: nothing at rest, and /info says nothing about it.
    let client = app(dir.path(), 1, json!({})).await.unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert!(info.get("at_rest").is_none(), "{info}");
    let (_, status) = get_json(&client, "/at-rest/status").await;
    assert_eq!(status["state"], "disabled");
    assert_eq!(
        get_json(&client, "/at-rest/escrow").await.0,
        Status::NotFound
    );
    drop(client);
    assert!(!dir.path().join("at-rest").exists());

    // Release A: recipients pinned, mode off. The ARK and escrow are made.
    let client = app(dir.path(), 1, json!({"escrow": escrow(None)}))
        .await
        .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"off","state":"unlocked","encrypting":false})
    );
    let (_, bundle) = get_json(&client, "/at-rest/escrow").await;
    let bundle: EscrowBundle = serde_json::from_value(bundle).unwrap();
    let efp = bundle.fingerprint().to_string();
    assert!(std::fs::read_dir(dir.path().join("at-rest/_tc/at-rest"))
        .unwrap()
        .any(|e| e.unwrap().file_name().to_string_lossy().starts_with("ark-")));

    // Ceremony test-unlock: junk and oversize are refused, two shares are
    // held, the third verifies.
    assert_eq!(post_share(&client, "junk").await.0, Status::BadRequest);
    assert_eq!(
        post_share(&client, vec![b'a'; 8192]).await.0,
        Status::PayloadTooLarge
    );
    let info = recovery(&client).await;
    assert_eq!(info.state, "unlocked");
    let (s, a) = post_share(&client, h.wrapped(&bundle, &info, 0)).await;
    assert_eq!(
        (s, &a["outcome"], &a["shares_held"]),
        (Status::Ok, &json!("held"), &json!([1]))
    );
    let (_, a) = post_share(&client, h.wrapped(&bundle, &info, 2)).await;
    assert_eq!(a["shares_held"], json!([1, 3]));
    assert_eq!(recovery(&client).await.shares_held, vec![1, 3]);
    let (_, a) = post_share(&client, h.wrapped(&bundle, &info, 1)).await;
    assert_eq!(a["outcome"], "verified");
    assert_eq!(a["efp"], json!(efp));
    let (status, record) = get_json(&client, "/at-rest/escrow/record").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(record["efp"], json!(efp));
    let (_, st) = get_json(&client, "/at-rest/status").await;
    assert_eq!(
        (st["verified"].clone(), st["encrypting"].clone()),
        (json!(true), json!(false))
    );
    drop(client);

    // No seal path in this build: encrypt and strict are refused at boot,
    // even with the escrow pinned and verified, so nothing ever claims to
    // encrypt while storage writes plaintext.
    for mode in ["encrypt", "strict"] {
        let err = refused(
            dir.path(),
            1,
            json!({"mode": mode, "escrow": escrow(Some(&efp))}),
        )
        .await;
        assert!(err.contains("no at-rest seal path"), "{err}");
    }

    // Pinned and verified, mode off: the gate passes, nothing is encrypted.
    let client = app(dir.path(), 1, json!({"escrow": escrow(Some(&efp))}))
        .await
        .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"off","state":"unlocked","encrypting":false})
    );
    drop(client);

    // New root (new app id / KMS): boots LOCKED, not refused.
    let client = app(dir.path(), 2, json!({"escrow": escrow(Some(&efp))}))
        .await
        .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"off","state":"locked","encrypting":false})
    );
    let (status, _) = get_json(&client, "/at-rest/escrow/record").await;
    assert_eq!(status, Status::NotFound);
    let info = recovery(&client).await;
    assert_eq!(info.state, "locked");
    // One share, even twice, does nothing.
    let one = h.wrapped(&bundle, &info, 1);
    assert_eq!(
        post_share(&client, one.clone()).await.1["shares_held"],
        json!([2])
    );
    assert_eq!(post_share(&client, one).await.1["shares_held"], json!([2]));
    let (_, st) = get_json(&client, "/at-rest/status").await;
    assert_eq!(st["state"], "locked");
    // A second holder unlocks it and the escrow gate passes again.
    let (_, a) = post_share(&client, h.wrapped(&bundle, &info, 2)).await;
    assert_eq!(
        (a["outcome"].clone(), a["gate"].clone()),
        (json!("unlocked"), json!("open"))
    );
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"off","state":"unlocked","encrypting":false})
    );
    drop(client);

    // Resealed under the new root: it now boots unlocked.
    let client = app(dir.path(), 2, json!({"escrow": escrow(Some(&efp))}))
        .await
        .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(info["at_rest"]["state"], json!("unlocked"));
}

async fn post_share_from(client: &Client, ip: &str, body: impl Into<Vec<u8>>) -> (Status, Value) {
    let res = client
        .post("/at-rest/recovery/shares")
        .remote(format!("{ip}:4000").parse().unwrap())
        .header(ContentType::Plain)
        .body(body.into())
        .dispatch()
        .await;
    let status = res.status();
    let body = res.into_string().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    )
}

/// The review's starvation probe, inverted: junk from one client, at about
/// ten requests a minute, never keeps a genuine holder from recovering a
/// locked node.
#[tokio::test]
async fn junk_from_one_client_does_not_block_a_genuine_share() {
    let dir = tempfile::tempdir().unwrap();
    let h = Holders::new();
    let escrow = |fp: Option<&str>| json!({"recipients": h.recipients(), "allow_software": true, "verified_fp": fp});
    let client = app(dir.path(), 1, json!({"escrow": escrow(None)}))
        .await
        .unwrap();
    let (_, bundle) = get_json(&client, "/at-rest/escrow").await;
    let bundle: EscrowBundle = serde_json::from_value(bundle).unwrap();
    let efp = bundle.fingerprint().to_string();
    drop(client);

    let client = app(dir.path(), 2, json!({"escrow": escrow(Some(&efp))}))
        .await
        .unwrap();
    let info = recovery(&client).await;
    assert_eq!(info.state, "locked");
    // Ten junk bodies from one address: rejected, then that client is
    // throttled; the node's share budget is untouched.
    let mut statuses = Vec::new();
    for _ in 0..10 {
        statuses.push(post_share_from(&client, "203.0.113.7", "junk").await.0);
    }
    assert!(statuses.contains(&Status::BadRequest), "{statuses:?}");
    assert_eq!(statuses.last(), Some(&Status::TooManyRequests));
    // Two genuine holders from other addresses recover the node.
    let (s, a) = post_share_from(&client, "198.51.100.1", h.wrapped(&bundle, &info, 0)).await;
    assert_eq!((s, &a["shares_held"]), (Status::Ok, &json!([1])), "{a}");
    let (s, a) = post_share_from(&client, "198.51.100.2", h.wrapped(&bundle, &info, 2)).await;
    assert_eq!((s, &a["outcome"]), (Status::Ok, &json!("unlocked")), "{a}");
}

/// The round-3 security probe, inverted: one planted file whose name or
/// type the mirror refuses used to stop the node booting.
#[tokio::test]
async fn planted_mirror_files_never_stop_a_node_from_booting() {
    let dir = tempfile::tempdir().unwrap();
    let h = Holders::new();
    let escrow = json!({"escrow": {"recipients": h.recipients(), "allow_software": true}});
    drop(app(dir.path(), 1, escrow.clone()).await.unwrap());
    let mirror = dir.path().join("at-rest/_tc/at-rest");
    for name in [
        "ark-0000000002-x y.json",
        "ark-..json",
        "ark-0000000002-x+y.json",
        "record-x y.json",
    ] {
        std::fs::write(mirror.join(name), b"junk").unwrap();
    }
    std::fs::create_dir(mirror.join("ark-0000000002-d.json")).unwrap();
    std::os::unix::fs::symlink("/dev/zero", mirror.join("ark-0000000002-z.json")).unwrap();

    let client = app(dir.path(), 1, escrow).await.unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"off","state":"unlocked","encrypting":false})
    );
}

#[tokio::test]
async fn misconfigurations_are_refused_at_boot() {
    let dir = tempfile::tempdir().unwrap();
    let h = Holders::new();
    // Software holders without the opt-in.
    let err = refused(
        dir.path(),
        1,
        json!({"escrow": {"recipients": h.recipients()}}),
    )
    .await;
    assert!(err.contains("software keys"), "{err}");
    // Both escrow and escrow_none.
    let err = refused(
        dir.path(),
        1,
        json!({"escrow_none": true, "escrow": {"recipients": h.recipients(), "allow_software": true}}),
    )
    .await;
    assert!(err.contains("not both"), "{err}");
    // No seal path: encrypt is refused even on a self-hosted Static root
    // that acknowledges having no escrow.
    let err = refused(
        dir.path(),
        1,
        json!({"mode": "encrypt", "escrow_none": true}),
    )
    .await;
    assert!(err.contains("no at-rest seal path"), "{err}");
    // Unknown keys in the section are refused, not ignored.
    refused(dir.path(), 1, json!({"escrow_nonee": true})).await;
}
