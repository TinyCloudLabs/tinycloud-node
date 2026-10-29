//! TC-1777: with `[global.encryption_network] named_keys_v1` off (the
//! default), the production app does not mount the named-key routes and
//! `/delegate` refuses delegations on keys and key prefixes, for UCAN and
//! SIWE (CACAO) delegations alike. Booted through `app_with_control`, so the
//! route set is the one a node serves.

use super::test_harness::*;
use super::*;
use rocket::http::{ContentType, Header};
use serde_json::json;
use tinycloud_core::encryption_network::{CreateNetworkRequest, EncryptionService, Threshold};

const NAMED_KEYS_UNAVAILABLE: &str =
    "named_keys_unavailable: named keys are not enabled on this node";
const KEY_DECRYPT: &str = "tinycloud.encryption/decrypt";
const KEY_CREATE: &str = "tinycloud.encryption/key.create";

/// Status, body and content type of a response.
async fn answer(
    request: rocket::local::asynchronous::LocalRequest<'_>,
) -> (Status, String, String) {
    let response = request.dispatch().await;
    let status = response.status();
    let content_type = response
        .content_type()
        .map(|content_type| content_type.to_string())
        .unwrap_or_default();
    (
        status,
        response.into_string().await.unwrap_or_default(),
        content_type,
    )
}

/// The four named-key routes answer exactly as an unmounted path does, and the
/// network routes still answer.
async fn named_key_routes_are_unmounted_and_network_routes_are_not(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "named_key_routes_are_unmounted_and_network_routes_are_not",
    )
    .await?
    else {
        return Ok(());
    };
    let network = h
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed")
        .create_one_of_one_network(CreateNetworkRequest {
            name: "net".to_string(),
            owner_did: h.space_owner.did().to_string(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .network_id
        .to_string();
    let json = || ContentType::JSON;
    let authorization = || Header::new("Authorization", "not-a-token");
    let remote = || "127.0.0.1:0".parse().expect("socket address");

    let unmounted_post = answer(
        h.client
            .post(format!("/encryption/networks/{network}/no-such-route"))
            .header(json())
            .body("{}"),
    )
    .await;
    let unmounted_get = answer(
        h.client
            .get(format!(
                "/encryption/networks/{network}/no-such-route/docs/a"
            ))
            .remote(remote()),
    )
    .await;
    assert_eq!(unmounted_post.0, Status::NotFound);
    assert_eq!(unmounted_get.0, Status::NotFound);

    let key_routes = [
        (
            "create",
            answer(
                h.client
                    .post(format!("/encryption/networks/{network}/keys"))
                    .header(json())
                    .header(authorization())
                    .body("{}"),
            )
            .await,
            &unmounted_post,
        ),
        (
            "public key",
            answer(
                h.client
                    .get(format!("/encryption/networks/{network}/keys/docs/a"))
                    .remote(remote()),
            )
            .await,
            &unmounted_get,
        ),
        (
            "describe",
            answer(
                h.client
                    .get(format!("/encryption/networks/{network}/keys/docs/a"))
                    .header(authorization())
                    .remote(remote()),
            )
            .await,
            &unmounted_get,
        ),
        (
            "block",
            answer(
                h.client
                    .post(format!("/encryption/networks/{network}/key-actions/block"))
                    .header(json())
                    .header(authorization())
                    .body("{}"),
            )
            .await,
            &unmounted_post,
        ),
        (
            "unblock",
            answer(
                h.client
                    .post(format!(
                        "/encryption/networks/{network}/key-actions/unblock"
                    ))
                    .header(json())
                    .header(authorization())
                    .body("{}"),
            )
            .await,
            &unmounted_post,
        ),
        (
            "delete",
            answer(
                h.client
                    .post(format!("/encryption/networks/{network}/key-actions/delete"))
                    .header(json())
                    .header(authorization())
                    .body("{}"),
            )
            .await,
            &unmounted_post,
        ),
    ];
    for (label, got, unmounted) in key_routes {
        assert_eq!(got.0, Status::NotFound, "{label}: {got:?}");
        assert_eq!(&got, unmounted, "{label} differs from an unmounted path");
    }

    // The network routes keep their own answers.
    let (status, body, _) = answer(h.client.get(format!("/encryption/networks/{network}"))).await;
    assert_eq!(status, Status::Ok, "{body}");
    let (status, body, _) = answer(h.client.get("/encryption/networks/not-a-network")).await;
    assert_eq!(status, Status::BadRequest, "{body}");
    for path in ["decrypt", "revoke"] {
        let (status, body, _) = answer(
            h.client
                .post(format!("/encryption/networks/{network}/{path}"))
                .header(json())
                .header(authorization())
                .body("{}"),
        )
        .await;
        assert_ne!(status, Status::NotFound, "{path}: {body}");
    }
    Ok(())
}
on_both_backends!(named_key_routes_are_unmounted_and_network_routes_are_not);

/// An owner-signed delegation on a key or a key prefix is refused with the
/// code and nothing is stored, for a did:key owner (UCAN) and a did:pkh
/// owner (SIWE CACAO); the owner's grant on the bare network is admitted.
async fn delegations_on_named_keys_are_refused(backend: Backend) -> anyhow::Result<()> {
    for (shape, label) in [
        (
            Shape::KeySession,
            "delegations_on_named_keys_are_refused_ucan",
        ),
        (
            Shape::PkhSession,
            "delegations_on_named_keys_are_refused_cacao",
        ),
    ] {
        let Some(h) = Harness::new(backend, shape, label).await? else {
            return Ok(());
        };
        let window = || Window::until(now() + Duration::hours(1));
        let key = format!("{}/docs/a", h.network);
        let prefix = format!("{}/docs/", h.network);
        for (what, grants) in [
            ("key", vec![(key.clone(), KEY_DECRYPT)]),
            ("prefix", vec![(prefix.clone(), KEY_DECRYPT)]),
            ("key create", vec![(key.clone(), KEY_CREATE)]),
            (
                "network and prefix",
                vec![
                    (h.network.clone(), KEY_DECRYPT),
                    (prefix.clone(), KEY_DECRYPT),
                ],
            ),
        ] {
            let authorization = h
                .space_owner
                .delegate(h.owner.did(), &grants, window(), &[])?;
            let (status, body) = h.delegate(authorization).await;
            assert_eq!(status, Status::Unauthorized, "{label} {what}: {body}");
            assert_eq!(body, NAMED_KEYS_UNAVAILABLE, "{label} {what}");
        }
        let authorization = h.space_owner.delegate(
            h.owner.did(),
            &[(h.network.clone(), KEY_DECRYPT)],
            window(),
            &[],
        )?;
        let (status, body) = h.delegate(authorization).await;
        assert_eq!(status, Status::Ok, "{label} bare network: {body}");
    }
    Ok(())
}
on_both_backends!(delegations_on_named_keys_are_refused);

const KEY_BLOCK: &str = "tinycloud.encryption/key.block";
const APP_ID_NOT_BOUND: &str = "app_id_not_bound";

/// With named keys on, a SIWE (CACAO) root grants an ability other than
/// `key.block` under `apps/<app id>` only when the app id is bound to the
/// SIWE domain (`tc1423.test` here, so `test.tc1423` and `test.tc1423.<more>`);
/// a UCAN root is not checked.
async fn siwe_app_grants_need_an_app_id_bound_to_the_domain(
    backend: Backend,
) -> anyhow::Result<()> {
    // Named keys on needs a deletion ledger path.
    let ledger_dir = tempfile::tempdir()?;
    let ledger_path = ledger_dir.path().join("deletion-ledger.jsonl");
    let on = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(ledger_path.clone());
    };
    // The second harness below runs while the first is alive: its own file.
    let on_ucan = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path =
            Some(ledger_dir.path().join("deletion-ledger-ucan.jsonl"));
    };
    let window = || Window::until(now() + Duration::hours(1));

    let Some(h) = Harness::new_with(
        backend,
        Shape::PkhSession,
        "siwe_app_grants_need_an_app_id_bound_to_the_domain_cacao",
        on,
    )
    .await?
    else {
        return Ok(());
    };
    let key = |tail: &str| format!("{}/{tail}", h.network);
    for (what, grants) in [
        ("bound key", vec![(key("apps/test.tc1423/x"), KEY_DECRYPT)]),
        (
            "bound prefix",
            vec![(key("apps/test.tc1423.notes/"), KEY_CREATE)],
        ),
        ("foreign block", vec![(key("apps/other.app/"), KEY_BLOCK)]),
        ("ordinary key", vec![(key("docs/a"), KEY_DECRYPT)]),
        ("reserved lookalike", vec![(key("appsx/y"), KEY_DECRYPT)]),
    ] {
        let authorization = h
            .space_owner
            .delegate(h.owner.did(), &grants, window(), &[])?;
        let (status, body) = h.delegate(authorization).await;
        assert_eq!(status, Status::Ok, "{what}: {body}");
    }
    for (what, grants) in [
        ("foreign key", vec![(key("apps/other.app/x"), KEY_DECRYPT)]),
        ("foreign prefix", vec![(key("apps/other.app/"), KEY_CREATE)]),
        (
            "prefix of the domain only",
            vec![(key("apps/test.tc1423x/"), KEY_CREATE)],
        ),
        (
            "bound block, foreign decrypt",
            vec![
                (key("apps/test.tc1423/"), KEY_BLOCK),
                (key("apps/other.app/x"), KEY_DECRYPT),
            ],
        ),
    ] {
        let authorization = h
            .space_owner
            .delegate(h.owner.did(), &grants, window(), &[])?;
        let (status, body) = h.delegate(authorization).await;
        assert_ne!(status, Status::Ok, "{what}: {body}");
        assert!(body.starts_with(APP_ID_NOT_BOUND), "{what}: {body}");
    }

    let Some(h) = Harness::new_with(
        backend,
        Shape::KeySession,
        "siwe_app_grants_need_an_app_id_bound_to_the_domain_ucan",
        on_ucan,
    )
    .await?
    else {
        return Ok(());
    };
    let grants = vec![(format!("{}/apps/other.app/x", h.network), KEY_DECRYPT)];
    let authorization = h
        .space_owner
        .delegate(h.owner.did(), &grants, window(), &[])?;
    let (status, body) = h.delegate(authorization).await;
    assert_eq!(status, Status::Ok, "UCAN root: {body}");
    Ok(())
}
on_both_backends!(siwe_app_grants_need_an_app_id_bound_to_the_domain);

/// The app refuses to start while a key row under `apps/` is not a deletable
/// key, and starts once the row is gone.
async fn startup_refuses_a_non_deletable_key_row_under_apps(
    backend: Backend,
) -> anyhow::Result<()> {
    use tinycloud_core::models::encryption_network_key;
    use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, ModelTrait};

    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "startup_refuses_a_non_deletable_key_row_under_apps",
    )
    .await?
    else {
        return Ok(());
    };
    h.boot_again(|_| {}).await.expect("boots with no stray row");

    let db = Database::connect(h.database_url()).await?;
    let stray = |path: &str, kind: &str| encryption_network_key::ActiveModel {
        network_id: Set(h.network.clone()),
        key_path: Set(path.to_string()),
        kind: Set(kind.to_string()),
        state: Set("active".to_string()),
        public_key: Set(vec![7u8; 32]),
        sealed_seed: Set(None),
        key_version: Set(1),
        created_at: Set("2026-01-01T00:00:00Z".to_string()),
        updated_at: Set("2026-01-01T00:00:00Z".to_string()),
    };
    // Rows outside the rule do not stop the start.
    stray("docs/a", "deterministic").insert(&db).await?;
    stray("appsx/y", "deterministic").insert(&db).await?;
    h.boot_again(|_| {})
        .await
        .expect("boots with ordinary rows");

    let row = stray("apps/foo/old", "deterministic").insert(&db).await?;
    let Err(error) = h.boot_again(|_| {}).await else {
        panic!("a stray row under apps/ stops the start");
    };
    assert!(
        error
            .to_string()
            .contains("1 key rows under apps/ are not deletable keys"),
        "{error}"
    );
    // The same with the named-keys setting on (and a ledger path, which that
    // setting requires).
    let ledger_dir = tempfile::tempdir()?;
    let ledger_path = ledger_dir.path().join("deletion-ledger.jsonl");
    let named_keys = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(ledger_path.clone());
    };
    assert!(h.boot_again(named_keys).await.is_err());
    let Err(error) = h.boot_again(named_keys).await else {
        panic!("a stray row under apps/ stops the start with named keys on");
    };
    assert!(
        error
            .to_string()
            .contains("1 key rows under apps/ are not deletable keys"),
        "{error}"
    );

    row.delete(&db).await?;
    h.boot_again(|_| {})
        .await
        .expect("boots once the row is gone");
    Ok(())
}
on_both_backends!(startup_refuses_a_non_deletable_key_row_under_apps);

// ---------------------------------------------------------------------------
// Deletion ledger replay at start

/// One delete operation as the ledger holds it.
fn ledger_op(op: &str, network: &str, paths: &[&str]) -> String {
    serde_json::json!({
        "op": op,
        "networkId": network,
        "keys": paths
            .iter()
            .map(|path| serde_json::json!({ "keyPath": path, "keyVersion": 1 }))
            .collect::<Vec<_>>(),
        "deletedAt": "2026-10-23T12:00:00Z",
    })
    .to_string()
}

fn append_to_ledger(path: &std::path::Path, lines: &[String]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn delete_route(network: &str) -> String {
    format!("/encryption/networks/{network}/key-actions/delete")
}

/// A network owned by the harness's space owner, with `paths` created as
/// deletable keys. Returns the network id.
async fn network_with_keys(
    h: &Harness,
    paths: &[&str],
) -> anyhow::Result<tinycloud_core::encryption_network::NetworkId> {
    use tinycloud_core::encryption_network::key_id::KeyLocation;
    let service = h
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed");
    service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "mainnet".to_string(),
            owner_did: h.space_owner.did().to_string(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let network: tinycloud_core::encryption_network::NetworkId = h.network.parse()?;
    for path in paths {
        service
            .create_key(&KeyLocation::new(&network, path)?, true)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    Ok(network)
}

async fn key_state(
    client: &rocket::local::asynchronous::Client,
    network: &tinycloud_core::encryption_network::NetworkId,
    path: &str,
) -> anyhow::Result<String> {
    use tinycloud_core::encryption_network::key_id::KeyLocation;
    let service = client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed");
    let key = service
        .describe_key(&KeyLocation::new(network, path)?)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(key.state.as_str().to_string())
}

/// A database a restore brought back, with every key still active, and a
/// ledger that knows better: when the node starts, the committed operation
/// and the still-open one are applied and the aborted one is not; only then
/// are the key routes served.
async fn a_restored_database_has_the_ledger_applied_before_the_key_routes_serve(
    backend: Backend,
) -> anyhow::Result<()> {
    let ledger_dir = tempfile::tempdir()?;
    let ledger_path = ledger_dir.path().join("deletion-ledger.jsonl");
    let on = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(ledger_path.clone());
    };
    // The first boot has its own ledger file; the restart reads the restored
    // one, which only one process opens at a time.
    let first_boot = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path =
            Some(ledger_dir.path().join("deletion-ledger-first.jsonl"));
    };
    let Some(h) = Harness::new_with(
        backend,
        Shape::KeySession,
        "a_restored_database_has_the_ledger_applied_before_the_key_routes_serve",
        first_boot,
    )
    .await?
    else {
        return Ok(());
    };
    let network = network_with_keys(
        &h,
        &[
            "apps/a/committed",
            "apps/a/open",
            "apps/a/aborted",
            "apps/a/untouched",
        ],
    )
    .await?;
    append_to_ledger(
        &ledger_path,
        &[
            ledger_op("c", &h.network, &["apps/a/committed"]),
            r#"{"committed":"c"}"#.to_string(),
            ledger_op("o", &h.network, &["apps/a/open"]),
            ledger_op("x", &h.network, &["apps/a/aborted"]),
            r#"{"aborted":"x"}"#.to_string(),
        ],
    )?;

    let restarted = h.boot_again(on).await?;
    for (path, state) in [
        ("apps/a/committed", "deleted"),
        ("apps/a/open", "deleted"),
        ("apps/a/aborted", "active"),
        ("apps/a/untouched", "active"),
    ] {
        assert_eq!(
            key_state(&restarted, &network, path).await?,
            state,
            "{path}"
        );
    }
    // The open operation was closed, so the next start does not repeat it.
    let text = std::fs::read_to_string(&ledger_path)?;
    assert!(text.contains(r#"{"committed":"o"}"#), "{text}");
    // The key routes serve: the delete route is mounted and asks for a credential.
    let (status, _, _) = answer(
        restarted
            .post(delete_route(&h.network))
            .header(ContentType::JSON)
            .body("{}"),
    )
    .await;
    assert_eq!(status, Status::Unauthorized);
    Ok(())
}
on_both_backends!(a_restored_database_has_the_ledger_applied_before_the_key_routes_serve);

/// A start with a clean database and a ledger that holds nothing changes
/// nothing and serves the key routes.
async fn a_start_with_an_empty_ledger_changes_nothing(backend: Backend) -> anyhow::Result<()> {
    let ledger_dir = tempfile::tempdir()?;
    let ledger_path = ledger_dir.path().join("deletion-ledger.jsonl");
    let on = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(ledger_path.clone());
    };
    let first_boot = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path =
            Some(ledger_dir.path().join("deletion-ledger-first.jsonl"));
    };
    let Some(h) = Harness::new_with(
        backend,
        Shape::KeySession,
        "a_start_with_an_empty_ledger_changes_nothing",
        first_boot,
    )
    .await?
    else {
        return Ok(());
    };
    let network = network_with_keys(&h, &["apps/a/x", "apps/a/y"]).await?;

    let restarted = h.boot_again(on).await?;
    for path in ["apps/a/x", "apps/a/y"] {
        assert_eq!(key_state(&restarted, &network, path).await?, "active");
    }
    assert_eq!(std::fs::metadata(&ledger_path)?.len(), 0);
    let (status, _, _) = answer(
        restarted
            .post(delete_route(&h.network))
            .header(ContentType::JSON)
            .body("{}"),
    )
    .await;
    assert_eq!(status, Status::Unauthorized);
    Ok(())
}
on_both_backends!(a_start_with_an_empty_ledger_changes_nothing);

/// The events a test run logged, with their fields.
#[derive(Clone, Default)]
struct EventLog(std::sync::Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>);

impl ::tracing::Subscriber for EventLog {
    fn enabled(&self, _metadata: &::tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &::tracing::span::Attributes<'_>) -> ::tracing::span::Id {
        ::tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &::tracing::span::Id, _values: &::tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &::tracing::span::Id, _follows: &::tracing::span::Id) {}

    fn enter(&self, _span: &::tracing::span::Id) {}

    fn exit(&self, _span: &::tracing::span::Id) {}

    fn event(&self, event: &::tracing::Event<'_>) {
        #[derive(Default)]
        struct Fields(std::collections::BTreeMap<String, String>);
        impl ::tracing::field::Visit for Fields {
            fn record_debug(
                &mut self,
                field: &::tracing::field::Field,
                value: &dyn std::fmt::Debug,
            ) {
                self.0
                    .insert(field.name().to_string(), format!("{value:?}"));
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.0.lock().expect("event log").push(fields.0);
    }
}

/// A ledger the node cannot replay (or cannot open) turns the key routes off
/// as if `named_keys_v1` were off, logs one alert event with a fixed name and
/// a fixed error kind, and the rest of the node serves. Runs on one thread so
/// the thread-scoped subscriber sees every event of the start.
async fn a_failing_ledger_turns_the_key_routes_off_and_the_rest_of_the_node_serves(
    ledger: impl FnOnce(&std::path::Path) -> (std::path::PathBuf, &'static str, &'static str),
) -> anyhow::Result<()> {
    let events = EventLog::default();
    let _subscriber = ::tracing::subscriber::set_default(events.clone());
    let ledger_dir = tempfile::tempdir()?;
    let (ledger_path, event, error_kind) = ledger(ledger_dir.path());
    let on = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(ledger_path.clone());
    };
    let Some(h) = Harness::new_with(
        Backend::Sqlite,
        Shape::KeySession,
        "a_failing_ledger_turns_the_key_routes_off",
        on,
    )
    .await?
    else {
        return Ok(());
    };

    let unmounted = answer(
        h.client
            .post(format!("/encryption/networks/{}/no-such-route", h.network))
            .header(ContentType::JSON)
            .body("{}"),
    )
    .await;
    let delete = answer(
        h.client
            .post(delete_route(&h.network))
            .header(ContentType::JSON)
            .body("{}"),
    )
    .await;
    assert_eq!(unmounted.0, Status::NotFound);
    assert_eq!(
        delete, unmounted,
        "the delete route answers as an unmounted path"
    );
    let (status, body, _) = answer(h.client.get("/version")).await;
    assert_eq!(status, Status::Ok, "{body}");

    // The configuration the routes read says named keys are off.
    let config = h
        .client
        .rocket()
        .state::<crate::config::Config>()
        .expect("Config is managed");
    assert!(!config.encryption_network.named_keys_v1);
    let (status, body, _) = answer(h.client.get("/info")).await;
    assert_eq!(status, Status::Ok, "{body}");
    let info: serde_json::Value = serde_json::from_str(&body)?;
    assert!(
        !info["features"]
            .as_array()
            .expect("features")
            .iter()
            .any(|feature| feature == "encryption-named-keys-v1"),
        "{body}"
    );
    // A delegation on a key is refused as it is with named keys off.
    let authorization = h.space_owner.delegate(
        h.owner.did(),
        &[(format!("{}/docs/a", h.network), KEY_DECRYPT)],
        Window::until(now() + Duration::hours(1)),
        &[],
    )?;
    let (status, body) = h.delegate(authorization).await;
    assert_eq!(status, Status::Unauthorized, "{body}");
    assert_eq!(body, NAMED_KEYS_UNAVAILABLE);
    // Every key route answers as an unmounted path does.
    let network = &h.network;
    let remote = || "127.0.0.1:0".parse().expect("socket address");
    let unmounted_get = answer(
        h.client
            .get(format!(
                "/encryption/networks/{network}/no-such-route/docs/a"
            ))
            .remote(remote()),
    )
    .await;
    let authorization = || Header::new("Authorization", "not-a-token");
    for action in ["block", "unblock", "delete"] {
        let got = answer(
            h.client
                .post(format!(
                    "/encryption/networks/{network}/key-actions/{action}"
                ))
                .header(ContentType::JSON)
                .header(authorization())
                .body("{}"),
        )
        .await;
        assert_eq!(got, unmounted, "{action}");
    }
    let create = answer(
        h.client
            .post(format!("/encryption/networks/{network}/keys"))
            .header(ContentType::JSON)
            .header(authorization())
            .body("{}"),
    )
    .await;
    assert_eq!(create, unmounted, "create");
    let public_key = answer(
        h.client
            .get(format!("/encryption/networks/{network}/keys/docs/a"))
            .remote(remote()),
    )
    .await;
    assert_eq!(public_key, unmounted_get, "public key");
    let describe = answer(
        h.client
            .get(format!("/encryption/networks/{network}/keys/docs/a"))
            .header(authorization())
            .remote(remote()),
    )
    .await;
    assert_eq!(describe, unmounted_get, "describe");

    let logged = events.0.lock().expect("event log").clone();
    let alerts: Vec<_> = logged
        .iter()
        .filter(|fields| fields.get("event").map(String::as_str) == Some(&format!("{event:?}")))
        .collect();
    assert_eq!(alerts.len(), 1, "{logged:?}");
    assert_eq!(
        alerts[0].get("error_kind").map(String::as_str),
        Some(format!("{error_kind:?}").as_str())
    );
    // The alert carries the event name and a kind, and nothing else but the message.
    assert!(
        alerts[0]
            .keys()
            .all(|name| ["event", "error_kind", "message"].contains(&name.as_str())),
        "{:?}",
        alerts[0]
    );
    Ok(())
}

#[tokio::test]
async fn a_ledger_with_a_malformed_line_turns_the_key_routes_off() -> anyhow::Result<()> {
    a_failing_ledger_turns_the_key_routes_off_and_the_rest_of_the_node_serves(|dir| {
        let path = dir.join("deletion-ledger.jsonl");
        let op = ledger_op("o", "urn:tinycloud:encryption:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:mainnet", &["apps/a/x"]);
        std::fs::write(&path, format!("{op}\nnot a ledger line\n{op}\n")).expect("write ledger");
        (path, "deletion_ledger_replay_failed", "malformed")
    })
    .await
}

#[tokio::test]
async fn a_ledger_that_cannot_be_opened_turns_the_key_routes_off() -> anyhow::Result<()> {
    a_failing_ledger_turns_the_key_routes_off_and_the_rest_of_the_node_serves(|dir| {
        // The directory does not exist, so the file cannot be created.
        (
            dir.join("missing").join("deletion-ledger.jsonl"),
            "deletion_ledger_open_failed",
            "io",
        )
    })
    .await
}

/// With named keys on, `/delegate` refuses an `apps/` grant from a SIWE whose
/// scheme is not `https` even when its domain is bound to the app id, and
/// admits it when the scheme is `https` (any case) or absent.
async fn siwe_app_grants_need_an_https_or_absent_scheme(backend: Backend) -> anyhow::Result<()> {
    let ledger_dir = tempfile::tempdir()?;
    let Some(h) = Harness::new_with(
        backend,
        Shape::PkhSession,
        "siwe_app_grants_need_an_https_or_absent_scheme",
        |config| {
            config.encryption_network.named_keys_v1 = true;
            config.encryption_network.deletion_ledger_path =
                Some(ledger_dir.path().join("deletion-ledger.jsonl"));
        },
    )
    .await?
    else {
        return Ok(());
    };
    let window = || Window::until(now() + Duration::hours(1));
    // `tc1423.test` is the harness SIWE domain, so `test.tc1423` is bound to it.
    let grants = vec![(format!("{}/apps/test.tc1423/x", h.network), KEY_CREATE)];
    for scheme in ["http", "wss", "ws"] {
        let authorization = h.space_owner.delegate_with_scheme(
            Some(scheme),
            h.owner.did(),
            &grants,
            window(),
            &[],
        )?;
        let (status, body) = h.delegate(authorization).await;
        assert_ne!(status, Status::Ok, "scheme {scheme}: {body}");
        assert!(
            body.starts_with(APP_ID_NOT_BOUND),
            "scheme {scheme}: {body}"
        );
    }
    for scheme in [Some("https"), Some("HTTPS"), None] {
        let authorization =
            h.space_owner
                .delegate_with_scheme(scheme, h.owner.did(), &grants, window(), &[])?;
        let (status, body) = h.delegate(authorization).await;
        assert_eq!(status, Status::Ok, "scheme {scheme:?}: {body}");
    }
    Ok(())
}
on_both_backends!(siwe_app_grants_need_an_https_or_absent_scheme);

const TC2192_KEY_PATH: &str = "share/tc-2192";

#[derive(Clone, Copy)]
enum SourceDigest {
    RawWrappedBytes,
    LegacyWire,
    Missing,
}

struct ShareDecrypt {
    h: Harness,
    session: String,
    public_key: Vec<u8>,
    wrapped: Vec<u8>,
    receiver: x25519_dalek::StaticSecret,
    key_path: Option<&'static str>,
    _ledger: tempfile::TempDir,
}

impl ShareDecrypt {
    async fn new() -> anyhow::Result<Self> {
        Self::with_source(Some(TC2192_KEY_PATH), "immutable").await
    }

    async fn with_source(key_path: Option<&'static str>, mode: &str) -> anyhow::Result<Self> {
        let digest_format = if key_path.is_some() {
            SourceDigest::RawWrappedBytes
        } else {
            SourceDigest::LegacyWire
        };
        Self::with_source_digest(key_path, mode, digest_format).await
    }

    async fn with_source_digest(
        key_path: Option<&'static str>,
        mode: &str,
        digest_format: SourceDigest,
    ) -> anyhow::Result<Self> {
        use tinycloud_core::encryption_network::{
            backend::wrap_to_public_key, canonical::canonical_hash, key_id::KeyLocation,
        };
        let ledger = tempfile::tempdir()?;
        let mut h = Harness::new_with(Backend::Sqlite, Shape::KeySession, "tc2192", |config| {
            config.encryption_network.named_keys_v1 = true;
            config.encryption_network.deletion_ledger_path =
                Some(ledger.path().join("deletion-ledger.jsonl"));
        })
        .await?
        .expect("SQLite harness");
        h.network = format!("urn:tinycloud:encryption:{}:default", h.space_owner.did());
        let service = h.client.rocket().state::<EncryptionService>().unwrap();
        let network = service
            .create_one_of_one_network(CreateNetworkRequest {
                name: "default".into(),
                owner_did: h.space_owner.did().into(),
                threshold: Threshold::one_of_one(),
            })
            .await?;
        let public_key = if let Some(path) = key_path {
            service
                .create_key(&KeyLocation::new(&network.network_id, path)?, false)
                .await?
                .public_encryption_key
        } else {
            network.public_encryption_key
        };
        let wrapped = wrap_to_public_key(&public_key, &[0xCD; 32])?;
        let leaf = match key_path {
            Some(path) => format!("{}/{path}", h.network),
            None => h.network.clone(),
        };
        let mut grants = h.owner_grants();
        grants[2].0 = leaf.clone();
        h.grant_owner_with(&grants, Window::until(now() + Duration::days(2)))
            .await?;
        let (status, body, registered) = h
            .register_with(policy_window(), |policy| {
                policy["contentSource"]["shareId"] = json!("tc-2192");
                policy["contentSource"]["mode"] = json!(mode);
                if let Some(path) = key_path {
                    policy["contentSource"]["encryptionKeyPath"] = json!(path);
                }
                let digest = match digest_format {
                    SourceDigest::RawWrappedBytes => Some(hex::encode(Sha256::digest(&wrapped))),
                    SourceDigest::LegacyWire => {
                        Some(canonical_hash(&json!(base64::encode(&wrapped))))
                    }
                    SourceDigest::Missing => None,
                };
                match digest {
                    Some(digest) => {
                        policy["contentSource"]["encryptedSymmetricKeyDigestHex"] = json!(digest);
                    }
                    None => {
                        policy["contentSource"]
                            .as_object_mut()
                            .unwrap()
                            .remove("encryptedSymmetricKeyDigestHex");
                    }
                }
                policy["capabilityCeiling"][1]["resource"] = json!(leaf);
            })
            .await?;
        anyhow::ensure!(status == Status::Ok, "register Share: {status} {body}");
        let session = h.mint_ok(&registered).await?;
        Ok(Self {
            h,
            session,
            public_key,
            wrapped,
            receiver: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
            key_path,
            _ledger: ledger,
        })
    }

    fn body(&self) -> Value {
        use tinycloud_core::encryption_network::{canonical::canonical_hash, DECRYPT_REQUEST_TYPE};
        let wrapped = json!(base64::encode(&self.wrapped));
        let receiver = json!(base64::encode(
            x25519_dalek::PublicKey::from(&self.receiver).as_bytes()
        ));
        let mut body = json!({
            "type": DECRYPT_REQUEST_TYPE,
            "targetNode": self.h.node_did(),
            "networkId": self.h.network,
            "alg": tinycloud_core::encryption_network::types::ALG_X25519_AES256GCM,
            "keyVersion": 1,
            "encryptedSymmetricKeyHash": canonical_hash(&wrapped),
            "encryptedSymmetricKey": wrapped,
            "receiverPublicKeyHash": canonical_hash(&receiver),
            "receiverPublicKey": receiver,
        });
        if let Some(path) = self.key_path {
            body["keyPath"] = json!(path);
        }
        body
    }

    async fn invoke(
        &self,
        resource: &str,
        body: &Value,
        extra_attenuation: Option<Value>,
        metadata: Value,
    ) -> anyhow::Result<(Status, String)> {
        self.invoke_at("/invoke", resource, body, extra_attenuation, metadata)
            .await
    }

    async fn invoke_at(
        &self,
        route: &str,
        resource: &str,
        body: &Value,
        extra_attenuation: Option<Value>,
        metadata: Value,
    ) -> anyhow::Result<(Status, String)> {
        use tinycloud_auth::{
            siwe_recap::Ability,
            ssi::{claims::jwt::NumericDate, ucan::Payload},
            ucan_capabilities_object::Capabilities,
        };
        use tinycloud_core::encryption_network::canonical::canonical_hash;
        let mut attenuation: Capabilities<Value> =
            serde_json::from_value(extra_attenuation.unwrap_or_else(|| json!({})))?;
        attenuation.with_action(
            resource.parse()?,
            KEY_DECRYPT.parse::<Ability>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        let mut facts = body.clone();
        facts
            .as_object_mut()
            .unwrap()
            .remove("encryptedSymmetricKey");
        facts.as_object_mut().unwrap().remove("receiverPublicKey");
        facts["bodyHash"] = json!(canonical_hash(body));
        let Signer::Key { jwk, vm, .. } = &self.h.holder else {
            unreachable!()
        };
        let at = now();
        let authorization = Payload {
            issuer: vm.parse()?,
            audience: self.h.node_did().parse()?,
            not_before: Some(NumericDate::try_from_seconds(at.unix_timestamp() as f64)?),
            expiration: NumericDate::try_from_seconds(
                (at + Duration::seconds(30)).unix_timestamp() as f64,
            )?,
            nonce: Some(unique("tc2192decrypt")),
            facts: Some(vec![facts, metadata]),
            proof: vec![session_cid(&self.session)?],
            attenuation,
        }
        .sign(Algorithm::EdDSA, jwk)?
        .encode()?;
        let (status, body, _) = answer(
            self.h
                .client
                .post(route)
                .header(ContentType::JSON)
                .header(Header::new("Authorization", authorization))
                .body(body.to_string()),
        )
        .await;
        Ok((status, body))
    }

    fn leaf(&self) -> String {
        match self.key_path {
            Some(path) => format!("{}/{path}", self.h.network),
            None => self.h.network.clone(),
        }
    }
}

#[tokio::test]
async fn tc2192_legacy_immutable_share_decrypt_uses_signed_wire_digest() -> anyhow::Result<()> {
    use tinycloud_core::encryption_network::{
        backend::wrap_to_public_key, canonical::canonical_hash,
    };
    let share = ShareDecrypt::with_source(None, "immutable").await?;
    let original = share.body();
    let (status, response) = share
        .invoke(&share.leaf(), &original, None, Value::Null)
        .await?;
    assert_eq!(status, Status::Ok, "{response}");
    let response: Value = serde_json::from_str(&response)?;
    let wrapped = base64::decode(response["wrappedKey"].as_str().unwrap())?;
    let (ephemeral, sealed) = wrapped.split_at(32);
    let peer = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ephemeral)?);
    let shared = share.receiver.diffie_hellman(&peer);
    assert_eq!(
        tinycloud_core::encryption::ColumnEncryption::new(*shared.as_bytes())
            .decrypt_strict(sealed)?,
        vec![0xCD; 32],
    );

    let other = wrap_to_public_key(&share.public_key, &[0xEF; 32])?;
    let mut changed = original;
    changed["encryptedSymmetricKey"] = json!(base64::encode(&other));
    changed["encryptedSymmetricKeyHash"] = json!(canonical_hash(&changed["encryptedSymmetricKey"]));
    let (status, response) = share
        .invoke(&share.leaf(), &changed, None, Value::Null)
        .await?;
    assert_eq!(status, Status::Forbidden, "{response}");
    assert_eq!(response, "policy-decrypt-content-source-mismatch");
    Ok(())
}

#[tokio::test]
async fn tc2192_legacy_immutable_source_without_digest_remains_compatible() -> anyhow::Result<()> {
    let share = ShareDecrypt::with_source_digest(None, "immutable", SourceDigest::Missing).await?;
    let (status, response) = share
        .invoke(&share.leaf(), &share.body(), None, Value::Null)
        .await?;
    assert_eq!(status, Status::Ok, "{response}");
    Ok(())
}

#[tokio::test]
async fn tc2192_immutable_share_decrypt_binds_registered_source() -> anyhow::Result<()> {
    assert_registered_source_binding(ShareDecrypt::new().await?, "/invoke").await
}

#[tokio::test]
async fn tc2192_mutable_share_decrypt_binds_registered_source() -> anyhow::Result<()> {
    assert_registered_source_binding(
        ShareDecrypt::with_source(Some(TC2192_KEY_PATH), "mutable").await?,
        "/invoke",
    )
    .await
}

#[tokio::test]
async fn tc2192_direct_decrypt_binds_registered_source_before_release() -> anyhow::Result<()> {
    let share = ShareDecrypt::with_source(None, "immutable").await?;
    let route = format!("/encryption/networks/{}/decrypt", share.h.network);
    assert_registered_source_binding(share, &route).await
}

async fn assert_registered_source_binding(share: ShareDecrypt, route: &str) -> anyhow::Result<()> {
    use tinycloud_core::encryption_network::{
        backend::wrap_to_public_key, canonical::canonical_hash,
    };
    let original = share.body();
    let mut different_key = original.clone();
    let other = wrap_to_public_key(&share.public_key, &[0xEF; 32])?;
    different_key["encryptedSymmetricKey"] = json!(base64::encode(&other));
    different_key["encryptedSymmetricKeyHash"] =
        json!(canonical_hash(&different_key["encryptedSymmetricKey"]));
    let mut different_version = original.clone();
    different_version["keyVersion"] = json!(2);
    for (label, body, metadata) in [
        ("digest", different_key.clone(), Value::Null),
        ("version", different_version, Value::Null),
        (
            "caller source override",
            different_key,
            json!({
                "contentSource": {
                    "mode": "mutable",
                    "encryptedSymmetricKeyDigestHex": hex::encode(Sha256::digest(&other)),
                    "keyVersion": 1,
                },
            }),
        ),
    ] {
        let (status, response) = share
            .invoke_at(route, &share.leaf(), &body, None, metadata)
            .await?;
        assert_eq!(status, Status::Forbidden, "{label}: {response}");
        assert_eq!(
            response, "policy-decrypt-content-source-mismatch",
            "{label}"
        );
    }
    let (status, response) = share
        .invoke_at(route, &share.leaf(), &original, None, Value::Null)
        .await?;
    assert_eq!(status, Status::Ok, "{response}");
    let response: Value = serde_json::from_str(&response)?;
    let wrapped = base64::decode(response["wrappedKey"].as_str().unwrap())?;
    let (ephemeral, sealed) = wrapped.split_at(32);
    let peer = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ephemeral)?);
    let shared = share.receiver.diffie_hellman(&peer);
    assert_eq!(
        tinycloud_core::encryption::ColumnEncryption::new(*shared.as_bytes())
            .decrypt_strict(sealed)?,
        vec![0xCD; 32],
    );
    Ok(())
}

#[tokio::test]
async fn tc2192_share_owner_path_and_exact_resources_are_checked_before_decrypt(
) -> anyhow::Result<()> {
    let share = ShareDecrypt::new().await?;
    let original = share.body();
    for (field, value) in [
        (
            "networkId",
            format!("urn:tinycloud:encryption:{}:default", share.h.owner.did()),
        ),
        (
            "networkId",
            format!(
                "urn:tinycloud:encryption:{}:other",
                share.h.space_owner.did()
            ),
        ),
        ("keyPath", "share/other".into()),
        ("keyPath", format!("{TC2192_KEY_PATH}/child")),
    ] {
        let mut body = original.clone();
        body[field] = json!(value);
        let (status, response) = share
            .invoke(&share.leaf(), &body, None, Value::Null)
            .await?;
        assert_eq!(status, Status::Forbidden, "{field}: {response}");
        assert_eq!(
            response, "policy-decrypt-content-source-mismatch",
            "{field}"
        );
    }
    for resource in [
        share.h.network.clone(),
        format!("{}/share/other", share.h.network),
        format!("{}/child", share.leaf()),
        format!(
            "urn:tinycloud:encryption:{}:default/{TC2192_KEY_PATH}",
            share.h.owner.did()
        ),
    ] {
        let (status, response) = share
            .invoke(&resource, &original, None, Value::Null)
            .await?;
        assert_eq!(status, Status::Forbidden, "{resource}: {response}");
        assert_eq!(response, "policy-invocation-capability-widening");
    }
    // A copied exact caveat must not authorize a different KV resource, even
    // when bundled with a valid decrypt that would otherwise return a key.
    for suffix in ["/child", "-sibling"] {
        let kv = json!({
            "kind": "kv",
            "resource": share.h.content_resource.to_string(),
            "selector": "exact",
            "actions": ["tinycloud.kv/get"],
        });
        let attenuation = attenuation_for_policy_capabilities(&[kv])
            .map_err(|(_, error)| anyhow::anyhow!(error))?;
        let exact = share.h.content_resource.to_string();
        let mut changed = attenuation.as_object().unwrap().clone();
        let caveats = changed.remove(&exact).unwrap();
        changed.insert(format!("{exact}{suffix}"), caveats);
        // Keep the original selector value, not a newly attenuated selector.
        let (status, response) = share
            .invoke(
                &share.leaf(),
                &original,
                Some(Value::Object(changed)),
                Value::Null,
            )
            .await?;
        assert_eq!(status, Status::Forbidden, "{suffix}: {response}");
        assert_eq!(response, "policy-invocation-capability-widening");
    }
    Ok(())
}

#[tokio::test]
async fn tc2192_share_cannot_redelegate_but_unrelated_policy_still_can() -> anyhow::Result<()> {
    let share = ShareDecrypt::new().await?;
    let session = decode_delegation(&share.session).map_err(|(_, error)| anyhow::anyhow!(error))?;
    assert_eq!(profile_depth(&session.0.delegation), Some(0));
    let (status, body, _, child) = share.h.reshare(&share.session).await?;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert_eq!(body, "policy-session-descendant-invalid");
    assert!(child.is_none());
    let h = Harness::new(Backend::Sqlite, Shape::KeySession, "tc2192-unrelated")
        .await?
        .unwrap();
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let registered = h.register_ok(policy_window()).await?;
    let session = h.mint_ok(&registered).await?;
    let event = decode_delegation(&session).map_err(|(_, error)| anyhow::anyhow!(error))?;
    assert_eq!(profile_depth(&event.0.delegation), Some(8));
    let (status, body, reader, child) = h.reshare(&session).await?;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(
        h.read_as(&reader, child.unwrap()).await?,
        (Status::Ok, "tc-1423-content".into()),
    );
    Ok(())
}

#[test]
fn tc2192_path_scoped_sources_require_a_digest_in_both_modes() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../test-fixtures/tc-405-compact-authorization.json"
    ))
    .unwrap();
    for mode in ["immutable", "mutable"] {
        let mut policy = vector["policy"]["value"].clone();
        policy["contentSource"]["mode"] = json!(mode);
        policy["contentSource"]
            .as_object_mut()
            .unwrap()
            .remove("encryptedSymmetricKeyDigestHex");
        assert!(registration_projections(&policy).is_ok(), "legacy {mode}");
        let owner = policy["ownerDid"].as_str().unwrap();
        let network = format!("urn:tinycloud:encryption:{owner}:default");
        let path = format!(
            "share/{}",
            policy["contentSource"]["shareId"].as_str().unwrap()
        );
        policy["contentSource"]["encryptionNetwork"] = json!(network);
        policy["contentSource"]["encryptionKeyPath"] = json!(path);
        policy["capabilityCeiling"][1]["resource"] = json!(format!("{network}/{path}"));
        assert_eq!(
            registration_projections(&policy).err(),
            Some((Status::BadRequest, "content-source-invalid".into())),
            "{mode} accepted a path-scoped source without a digest",
        );
        policy["contentSource"]["encryptedSymmetricKeyDigestHex"] = json!("aa".repeat(32));
        assert!(
            registration_projections(&policy).is_ok(),
            "{mode} with digest"
        );
    }
}

#[tokio::test]
async fn tc2192_legacy_mutable_source_preserves_wrapped_key_rotation() -> anyhow::Result<()> {
    use tinycloud_core::encryption_network::{
        backend::wrap_to_public_key, canonical::canonical_hash,
    };
    let share = ShareDecrypt::with_source(None, "mutable").await?;
    let mut body = share.body();
    body["encryptedSymmetricKey"] = json!(base64::encode(wrap_to_public_key(
        &share.public_key,
        &[0xCD; 32]
    )?));
    body["encryptedSymmetricKeyHash"] = json!(canonical_hash(&body["encryptedSymmetricKey"]));
    // This fresh wrap has a different digest from the registration but is
    // still permitted for a mutable source without encryptionKeyPath.
    assert_ne!(
        body["encryptedSymmetricKey"],
        share.body()["encryptedSymmetricKey"],
    );
    let (status, response) = share
        .invoke(&share.leaf(), &body, None, Value::Null)
        .await?;
    assert_eq!(status, Status::Ok, "{response}");
    let response: Value = serde_json::from_str(&response)?;
    let wrapped = base64::decode(response["wrappedKey"].as_str().unwrap())?;
    let (ephemeral, sealed) = wrapped.split_at(32);
    let peer = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ephemeral)?);
    let shared = share.receiver.diffie_hellman(&peer);
    assert_eq!(
        tinycloud_core::encryption::ColumnEncryption::new(*shared.as_bytes())
            .decrypt_strict(sealed)?,
        vec![0xCD; 32],
    );
    Ok(())
}

#[tokio::test]
async fn tc2192_refused_direct_mixed_decrypt_delete_leaves_kv_unchanged() -> anyhow::Result<()> {
    use tinycloud_auth::{
        siwe_recap::Ability,
        ssi::{claims::jwt::NumericDate, ucan::Payload},
        ucan_capabilities_object::Capabilities,
    };
    use tinycloud_core::encryption_network::canonical::canonical_hash;

    let share = ShareDecrypt::with_source(None, "immutable").await?;
    let before = share.h.read(&share.session).await?;
    assert_eq!(before, (Status::Ok, b"tc-1423-content".to_vec()));
    // Delete is independently authorized, but is not part of this policy
    // session or the direct decrypt endpoint's contract.
    let delete_grant = share
        .h
        .import(share.h.space_owner.delegate(
            share.h.holder.did(),
            &[(share.h.content_resource.to_string(), "tinycloud.kv/del")],
            Window::until(now() + Duration::hours(1)),
            &[],
        )?)
        .await?;
    let mut attenuation = Capabilities::<Value>::new();
    for (resource, ability) in [
        (share.leaf(), KEY_DECRYPT),
        (share.h.content_resource.to_string(), "tinycloud.kv/del"),
    ] {
        attenuation.with_action(
            resource.parse()?,
            ability.parse::<Ability>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
    }
    let body = share.body();
    let mut facts = body.clone();
    facts
        .as_object_mut()
        .unwrap()
        .remove("encryptedSymmetricKey");
    facts.as_object_mut().unwrap().remove("receiverPublicKey");
    facts["bodyHash"] = json!(canonical_hash(&body));
    let Signer::Key { jwk, vm, .. } = &share.h.holder else {
        unreachable!()
    };
    let at = now();
    let authorization = Payload {
        issuer: vm.parse()?,
        audience: share.h.node_did().parse()?,
        not_before: Some(NumericDate::try_from_seconds(at.unix_timestamp() as f64)?),
        expiration: NumericDate::try_from_seconds(
            (at + Duration::seconds(30)).unix_timestamp() as f64
        )?,
        nonce: Some(unique("tc2192mixeddecrypt")),
        facts: Some(vec![facts]),
        proof: vec![session_cid(&share.session)?, delete_grant.parse()?],
        attenuation,
    }
    .sign(Algorithm::EdDSA, jwk)?
    .encode()?;
    let (status, response, _) = answer(
        share
            .h
            .client
            .post(format!("/encryption/networks/{}/decrypt", share.h.network))
            .header(ContentType::JSON)
            .header(Header::new("Authorization", authorization))
            .body(body.to_string()),
    )
    .await;
    assert_eq!(status, Status::Forbidden, "{response}");
    assert_eq!(
        share.h.read(&share.session).await?,
        before,
        "a refused direct decrypt must not execute its bundled KV delete",
    );
    Ok(())
}
