//! TC-1777: with `[global.encryption_network] named_keys_v1` off (the
//! default), the production app does not mount the named-key routes and
//! `/delegate` refuses delegations on keys and key prefixes, for UCAN and
//! SIWE (CACAO) delegations alike. Booted through `app_with_control`, so the
//! route set is the one a node serves.

use super::test_harness::*;
use super::*;
use rocket::http::{ContentType, Header};
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
