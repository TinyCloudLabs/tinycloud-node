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

    // encrypt without the pinned fingerprint: the node refuses to start.
    let err = refused(
        dir.path(),
        1,
        json!({"mode": "encrypt", "escrow": escrow(None)}),
    )
    .await;
    assert!(err.contains("verified_fp is unset"), "{err}");
    let err = refused(
        dir.path(),
        1,
        json!({"mode": "encrypt", "escrow": escrow(Some(&"0".repeat(64)))}),
    )
    .await;
    assert!(err.contains("is not the active escrow"), "{err}");

    // Pinned and verified: encryption is enabled.
    let client = app(
        dir.path(),
        1,
        json!({"mode": "encrypt", "escrow": escrow(Some(&efp))}),
    )
    .await
    .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"encrypt","state":"unlocked","encrypting":true})
    );
    drop(client);

    // New root (new app id / KMS): boots LOCKED, not refused.
    let client = app(
        dir.path(),
        2,
        json!({"mode": "encrypt", "escrow": escrow(Some(&efp))}),
    )
    .await
    .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"encrypt","state":"locked","encrypting":false})
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
    // A second holder unlocks it and the gate reopens.
    let (_, a) = post_share(&client, h.wrapped(&bundle, &info, 2)).await;
    assert_eq!(
        (a["outcome"].clone(), a["gate"].clone()),
        (json!("unlocked"), json!("open"))
    );
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(
        info["at_rest"],
        json!({"mode":"encrypt","state":"unlocked","encrypting":true})
    );
    drop(client);

    // Resealed under the new root: it now boots unlocked with encryption on.
    let client = app(
        dir.path(),
        2,
        json!({"mode": "encrypt", "escrow": escrow(Some(&efp))}),
    )
    .await
    .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(info["at_rest"]["encrypting"], json!(true));
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
    // encrypt with no escrow at all on a Static root needs the acknowledgement.
    let err = refused(dir.path(), 1, json!({"mode": "encrypt"})).await;
    assert!(err.contains("escrow_none"), "{err}");
    let client = app(
        dir.path(),
        1,
        json!({"mode": "encrypt", "escrow_none": true}),
    )
    .await
    .unwrap();
    let (_, info) = get_json(&client, "/info").await;
    assert_eq!(info["at_rest"]["encrypting"], json!(true));
    // Unknown keys in the section are refused, not ignored.
    refused(
        dir.path(),
        1,
        json!({"mode": "encrypt", "escrow_nonee": true}),
    )
    .await;
}
