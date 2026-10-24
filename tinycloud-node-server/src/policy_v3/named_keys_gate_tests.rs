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
    let on = |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
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
        on,
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
    // The same with the named-keys setting on.
    assert!(h
        .boot_again(|config| config.encryption_network.named_keys_v1 = true)
        .await
        .is_err());

    row.delete(&db).await?;
    h.boot_again(|_| {})
        .await
        .expect("boots once the row is gone");
    Ok(())
}
on_both_backends!(startup_refuses_a_non_deletable_key_row_under_apps);

/// With named keys on, `/delegate` refuses an `apps/` grant from a SIWE whose
/// scheme is not `https` even when its domain is bound to the app id, and
/// admits it when the scheme is `https` (any case) or absent.
async fn siwe_app_grants_need_an_https_or_absent_scheme(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with(
        backend,
        Shape::PkhSession,
        "siwe_app_grants_need_an_https_or_absent_scheme",
        |config| config.encryption_network.named_keys_v1 = true,
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
