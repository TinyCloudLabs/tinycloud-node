//! TC-780 (N1/N2) regression, run against the REAL node authorization and
//! `/invoke` path — not a unit test of `db_name_from_path`.
//!
//! Two defects are pinned by asserting the required behavior. Both tests fail
//! on the pre-N2 code and pass with full-path identity and exact-path grants:
//!
//! 1. **Cross-app database sharing.** `SqlService::db_name_from_path`
//!    (`tinycloud-core/src/sql/service.rs`) and
//!    `DuckDbService::db_name_from_path` (`tinycloud-core/src/duckdb/service.rs`)
//!    previously keyed databases by `(space, last_path_segment)`. Within one
//!    space, `appA/connectors` and `appB/connectors` therefore opened the SAME database:
//!    rows the owner writes under `appB/connectors` are returned to a holder
//!    whose grant only covers `appA/connectors`.
//!
//! 2. **Descendant authorization.** `ResourceId::extends`
//!    (`tinycloud-auth/src/resource.rs`) previously treated a SQL or DuckDB
//!    capability path without a trailing slash as a prefix:
//!    a grant for the exact path `appA/connectors` (no trailing slash) also
//!    authorizes an invocation on `appA/connectors/private`, which opens a
//!    completely different database (`private`) that the grant never named.
//!
//! The third invocation in each test (`appB/connectors` read) is a control that
//! passes today: a grant on one path must NOT authorize a sibling path — this
//! stays true before and after N2.
//!
//! Space bootstrap mirrors `tc119_registry_wire_paths.rs`: the owner's
//! delegation is persisted directly as a node row, the holder signs UCAN
//! invocations citing it as `prf`, and every call goes through the real
//! `/invoke` route — signature verification, chain containment (`extends`),
//! ability matching, `select_database_scope`, `db_name_from_path`, and the
//! per-service database layer are all exercised on the wire.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use tempfile::TempDir;
use tinycloud_auth::{
    authorization::Cid as AuthCid,
    resolver::DID_METHODS,
    resource::{Path as AuthPath, ResourceId, Service, SpaceId},
    siwe_recap::Ability as UcanAbility,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    database_artifacts::SeaOrmDatabaseArtifactRepository,
    database_migration,
    duckdb::{DuckDbRequest, DuckDbValue},
    hash::Hash,
    models::{abilities, actor, database_artifact, database_legacy_artifact, space},
    relationships::parent_delegations,
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection,
        EntityTrait,
    },
    sql::{SqlRequest, SqlService, SqlValue},
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

const FAR_FUTURE_SECONDS: f64 = 4_102_444_800.0; // 2100-01-01
/// Value written under `appA/connectors`. The holder's exact-path grant must
/// return it — a read that is rejected or empty is an over-narrowed grant,
/// not correct isolation.
const APP_A_ROW: &str = "appa-owned-row";
/// Value only ever written under `appB/connectors`. Any read path that returns
/// it proves cross-app data sharing.
const APP_B_SECRET: &str = "appb-only-row";

/// A fresh space plus the owner's signing key so the owner can self-invoke
/// (root authority: no delegation proof needed for their own space).
fn space_identity(name: &str) -> Result<(JWK, String, String, SpaceId)> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?;
    let did_string = did.to_string();
    let fragment = did_string
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let vm = format!("{did_string}#{fragment}");
    Ok((jwk, did_string, vm, SpaceId::new(did, name.parse()?)))
}

/// Restart with the existing metadata database and cache. Unlike `boot_node`,
/// this must not insert another space/actor row.
async fn restart_node(tempdir: &TempDir, fenced: bool) -> Result<Client> {
    let datadir = tempdir.path().join("data");
    let secret = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let overlay = format!(
        r#"
[storage]
datadir = "{}"
[keys]
type = "Static"
secret = "{}"
[database]
write_fence = {}
"#,
        datadir.display(),
        secret,
        fenced
    );
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&overlay));
    let cfg = figment.extract::<tinycloud::config::Config>()?;
    Ok(Client::tracked(tinycloud::app_with_control(&figment, &cfg, None).await?).await?)
}

#[tokio::test]
async fn legacy_web_artifacts_load_via_invoke_after_alias_cutover_and_restart() -> Result<()> {
    use std::sync::Arc;
    use tinycloud_core::duckdb::DuckDbService;

    let tempdir = TempDir::new()?;
    let (owner_jwk, owner_did, owner_vm, space_id) = space_identity("tc780-n3-web")?;
    let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
    let (client, conn) = boot_node(
        &tempdir,
        &space_id,
        &[owner_did.clone(), holder_did.clone()],
    )
    .await?;
    let datadir = tempdir.path().join("data");
    let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone()));

    // These writes use the exact pre-N2 physical selectors. The active node
    // sees only N2 logical names until the alias transaction is applied.
    let sql = SqlService::new(datadir.join("sql").display().to_string(), 0, repo.clone());
    for (physical, row) in [
        ("threads", "exo-thread-row"),
        ("canvas", "exo-canvas-row"),
        ("connectors", "shared-old-row"),
        ("orphan", "unattributed-row"),
    ] {
        sql.execute(
            &space_id,
            physical,
            serde_json::from_value(sql_write_body(row))?,
            None,
            "tinycloud.sql/write".into(),
        )
        .await?;
    }
    let duck = DuckDbService::new(
        datadir.join("duckdb").display().to_string(),
        0,
        60,
        "1GB".into(),
        repo,
    );
    duck.execute(
        &space_id,
        "default",
        serde_json::from_value(duckdb_write_body("exo-duck-default"))?,
        None,
        "tinycloud.duckdb/write".into(),
        false,
    )
    .await?;

    let sql_path = "xyz.tinycloud.tinychat/threads";
    let canvas_path = "xyz.tinycloud.tinychat/canvas";
    let sql_resource = db_resource(&space_id, "sql", sql_path)?;
    let canvas_resource = db_resource(&space_id, "sql", canvas_path)?;
    let duck_resource = db_resource(&space_id, "duckdb", "appA/")?;
    let connectors_a = db_resource(&space_id, "sql", "xyz.tinycloud.tinychat/connectors")?;
    let connectors_b = db_resource(&space_id, "sql", "another.app/connectors")?;
    for (index, resource) in [
        &sql_resource,
        &canvas_resource,
        &duck_resource,
        &connectors_a,
        &connectors_b,
    ]
    .into_iter()
    .enumerate()
    {
        let ability = if resource.service().as_str() == "sql" {
            "tinycloud.sql/read"
        } else {
            "tinycloud.duckdb/read"
        };
        persist_grant(
            &conn,
            tinycloud_core::hash::hash(format!("n3-grant-{index}").as_bytes()),
            &owner_did,
            &holder_did,
            resource,
            ability,
        )
        .await?;
    }

    let items = database_migration::inventory(&conn, &datadir).await?;
    let find = |service: &str, physical: &str| {
        items
            .iter()
            .find(|item| item.service == service && item.physical_name == physical)
            .unwrap()
    };
    assert_eq!(find("sql", "threads").classification, "unique");
    assert_eq!(find("sql", "connectors").classification, "ambiguous");
    assert_eq!(find("sql", "orphan").classification, "unattributed");
    assert_eq!(
        find("duckdb", "default").paths,
        vec![Some("appA/".to_owned())]
    );
    let key = ("sql".to_owned(), space_id.to_string(), "threads".to_owned());
    let checkpoint_before = database_artifact::Entity::find_by_id(key.clone())
        .one(&conn)
        .await?;
    database_migration::set_fence(&conn, true).await?;
    database_migration::apply_inventory(&conn, &items).await?;
    database_migration::apply_inventory(&conn, &items).await?;
    database_migration::set_fence(&conn, false).await?;
    assert_eq!(
        database_artifact::Entity::find_by_id(key)
            .one(&conn)
            .await?,
        checkpoint_before
    );

    let sql_read = serde_json::to_value(SqlRequest::Query {
        sql: "SELECT v FROM t".into(),
        params: vec![],
        max_rows: None,
        max_bytes: None,
    })?;
    let duck_read = serde_json::to_value(DuckDbRequest::Query {
        sql: "SELECT v FROM t".into(),
        params: vec![],
    })?;
    for (resource, ability, body, value, suffix) in [
        (
            &sql_resource,
            "tinycloud.sql/read",
            &sql_read,
            "exo-thread-row",
            "11",
        ),
        (
            &canvas_resource,
            "tinycloud.sql/read",
            &sql_read,
            "exo-canvas-row",
            "12",
        ),
        (
            &duck_resource,
            "tinycloud.duckdb/read",
            &duck_read,
            "exo-duck-default",
            "13",
        ),
    ] {
        let grant = tinycloud_core::hash::hash(
            format!(
                "n3-grant-{}",
                if suffix == "11" {
                    0
                } else if suffix == "12" {
                    1
                } else {
                    2
                }
            )
            .as_bytes(),
        );
        let header = invocation(
            &holder_jwk,
            &holder_did,
            &holder_vm,
            vec![grant.to_cid(0x55)],
            resource,
            ability,
            &format!("urn:uuid:00000000-0000-4000-8000-0000000000{suffix}"),
        )?;
        let (status, response) = invoke_json(&client, header, body).await;
        assert_eq!(status, Status::Ok, "{response}");
        assert!(response.contains(value), "{response}");
    }

    let fresh_path = "new.app/notes";
    let fresh_resource = db_resource(&space_id, "sql", fresh_path)?;
    let fresh_write = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &fresh_resource,
        "tinycloud.sql/write",
        "urn:uuid:00000000-0000-4000-8000-000000000024",
    )?;
    let (status, response) = invoke_json(&client, fresh_write, &sql_write_body("new-row")).await;
    assert_eq!(status, Status::Ok, "{response}");
    let digest = tinycloud_core::database_identity::logical_name(Some(fresh_path));
    let quarantined_before = database_migration::quarantined(&conn).await?.len();
    database_migration::set_fence(&conn, true).await?;
    database_migration::apply(&conn, &datadir).await?;
    database_migration::set_fence(&conn, false).await?;
    assert_eq!(
        database_migration::quarantined(&conn).await?.len(),
        quarantined_before
    );
    assert!(!database_migration::inventory(&conn, &datadir)
        .await?
        .iter()
        .any(|item| item.physical_name == digest));

    // A short-name holder has a valid grant but can never reach a reserved
    // legacy artifact, whether another path aliases it or nobody does.
    for (path, suffix) in [("threads", "14"), ("orphan", "15"), ("connectors", "16")] {
        let resource = db_resource(&space_id, "sql", path)?;
        let (status, response) = invoke_json(
            &client,
            invocation(
                &owner_jwk,
                &owner_did,
                &owner_vm,
                vec![],
                &resource,
                "tinycloud.sql/read",
                &format!("urn:uuid:00000000-0000-4000-8000-0000000000{suffix}"),
            )?,
            &sql_read,
        )
        .await;
        assert_eq!(status, Status::Conflict, "{path}: {response}");
    }
    for (resource, suffix) in [
        (db_resource(&space_id, "duckdb", "default")?, "21"),
        (
            space_id
                .clone()
                .to_resource("duckdb".parse()?, None, None, None),
            "22",
        ),
    ] {
        let (status, response) = invoke_json(
            &client,
            invocation(
                &owner_jwk,
                &owner_did,
                &owner_vm,
                vec![],
                &resource,
                "tinycloud.duckdb/read",
                &format!("urn:uuid:00000000-0000-4000-8000-0000000000{suffix}"),
            )?,
            &duck_read,
        )
        .await;
        assert_eq!(status, Status::Conflict, "{resource}: {response}");
    }
    // A candidate of the ambiguous legacy artifact is reserved even though
    // its N2 digest does not exist. Rejected invocations add no history.
    let rejected = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &connectors_a,
        "tinycloud.sql/read",
        "urn:uuid:00000000-0000-4000-8000-000000000023",
    )?;
    let (status, response) = invoke_json(&client, rejected, &sql_read).await;
    assert_eq!(status, Status::Conflict, "{response}");
    let rejected_write = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &connectors_a,
        "tinycloud.sql/write",
        "urn:uuid:00000000-0000-4000-8000-000000000027",
    )?;
    let (status, response) =
        invoke_json(&client, rejected_write, &sql_write_body("must-not-create")).await;
    assert_eq!(status, Status::Conflict, "{response}");
    let orphan_candidate = db_resource(&space_id, "sql", "some.app/orphan")?;
    let rejected_orphan = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &orphan_candidate,
        "tinycloud.sql/read",
        "urn:uuid:00000000-0000-4000-8000-000000000028",
    )?;
    let (status, response) = invoke_json(&client, rejected_orphan, &sql_read).await;
    assert_eq!(status, Status::Conflict, "{response}");
    assert_eq!(
        database_migration::inventory(&conn, &datadir)
            .await?
            .iter()
            .find(|item| item.physical_name == "connectors")
            .unwrap()
            .paths
            .len(),
        2
    );
    database_migration::set_fence(&conn, true).await?;
    database_migration::set_alias(
        &conn,
        "sql",
        &space_id.to_string(),
        Some("xyz.tinycloud.tinychat/connectors"),
        "connectors",
    )
    .await?;
    database_migration::set_fence(&conn, false).await?;
    let header = invocation(
        &holder_jwk,
        &holder_did,
        &holder_vm,
        vec![tinycloud_core::hash::hash(b"n3-grant-3").to_cid(0x55)],
        &connectors_a,
        "tinycloud.sql/read",
        "urn:uuid:00000000-0000-4000-8000-000000000019",
    )?;
    let (status, response) = invoke_json(&client, header, &sql_read).await;
    assert_eq!(status, Status::Ok, "{response}");
    assert!(response.contains("shared-old-row"));
    database_migration::set_fence(&conn, true).await?;
    database_migration::clear_alias(
        &conn,
        "sql",
        &space_id.to_string(),
        Some("xyz.tinycloud.tinychat/connectors"),
    )
    .await?;
    database_migration::set_fence(&conn, false).await?;
    assert_eq!(
        database_migration::resolve(&conn, "sql", &space_id.to_string(), Some("connectors"))
            .await
            .unwrap_err()
            .to_string(),
        "quarantined legacy artifact is unreachable without an explicit alias"
    );
    drop(client);
    let restarted = restart_node(&tempdir, false).await?;
    let header = invocation(
        &holder_jwk,
        &holder_did,
        &holder_vm,
        vec![tinycloud_core::hash::hash(b"n3-grant-0").to_cid(0x55)],
        &sql_resource,
        "tinycloud.sql/read",
        "urn:uuid:00000000-0000-4000-8000-000000000017",
    )?;
    let (status, response) = invoke_json(&restarted, header, &sql_read).await;
    assert_eq!(status, Status::Ok, "{response}");
    assert!(response.contains("exo-thread-row"));
    drop(restarted);
    let fenced = restart_node(&tempdir, true).await?;
    let write = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &sql_resource,
        "tinycloud.sql/write",
        "urn:uuid:00000000-0000-4000-8000-000000000018",
    )?;
    let (status, response) = invoke_json(&fenced, write, &sql_write_body("blocked")).await;
    assert_eq!(status, Status::ServiceUnavailable, "{response}");
    let duck_write = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &duck_resource,
        "tinycloud.duckdb/write",
        "urn:uuid:00000000-0000-4000-8000-000000000020",
    )?;
    let (status, response) = invoke_json(&fenced, duck_write, &duckdb_write_body("blocked")).await;
    assert_eq!(status, Status::ServiceUnavailable, "{response}");
    Ok(())
}

#[tokio::test]
async fn legacy_alias_collision_refuses_the_whole_transaction() -> Result<()> {
    use std::sync::Arc;
    let tempdir = TempDir::new()?;
    let (_, owner_did, _, space_id) = space_identity("tc780-n3-collision")?;
    let (client, conn) = boot_node(&tempdir, &space_id, std::slice::from_ref(&owner_did)).await?;
    let datadir = tempdir.path().join("data");
    let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone()));
    let sql = SqlService::new(datadir.join("sql").display().to_string(), 0, repo);
    let path = "exo/threads";
    let digest = tinycloud_core::database_identity::logical_name(Some(path));
    for name in ["threads", digest.as_str()] {
        sql.execute(
            &space_id,
            name,
            serde_json::from_value(sql_write_body("row"))?,
            None,
            "tinycloud.sql/write".into(),
        )
        .await?;
    }
    let resource = db_resource(&space_id, "sql", path)?;
    persist_grant(
        &conn,
        tinycloud_core::hash::hash(b"n3-collision"),
        &owner_did,
        &owner_did,
        &resource,
        "tinycloud.sql/read",
    )
    .await?;
    let items = database_migration::inventory(&conn, &datadir).await?;
    assert!(items
        .iter()
        .any(|item| item.physical_name == "threads" && item.collision));
    assert!(database_migration::apply_inventory(&conn, &items)
        .await
        .is_err());
    assert!(database_migration::aliases(&conn).await?.is_empty());
    assert!(database_legacy_artifact::Entity::find()
        .all(&conn)
        .await?
        .is_empty());
    let resolved =
        database_migration::resolve(&conn, "sql", &space_id.to_string(), Some(path)).await?;
    assert_eq!(resolved, digest);
    drop(client);
    Ok(())
}

#[tokio::test]
async fn legacy_inventory_attributes_from_invoked_abilities_without_a_grant() -> Result<()> {
    use std::sync::Arc;
    let tempdir = TempDir::new()?;
    let (owner_jwk, owner_did, owner_vm, space_id) = space_identity("tc780-n3-invoked")?;
    let (client, conn) = boot_node(&tempdir, &space_id, std::slice::from_ref(&owner_did)).await?;
    let path = "web/only";
    let resource = db_resource(&space_id, "sql", path)?;
    let header = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &resource,
        "tinycloud.sql/write",
        "urn:uuid:00000000-0000-4000-8000-000000000025",
    )?;
    let (status, response) = invoke_json(&client, header, &sql_write_body("digest-row")).await;
    assert_eq!(status, Status::Ok, "{response}");
    let datadir = tempdir.path().join("data");
    let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone()));
    let sql = SqlService::new(datadir.join("sql").display().to_string(), 0, repo);
    sql.execute(
        &space_id,
        "only",
        serde_json::from_value(sql_write_body("legacy-row"))?,
        None,
        "tinycloud.sql/write".into(),
    )
    .await?;
    let items = database_migration::inventory(&conn, &datadir).await?;
    assert_eq!(items.len(), 1, "digest artifacts must be excluded");
    assert_eq!(items[0].classification, "unique");
    assert_eq!(items[0].paths, vec![Some(path.to_owned())]);
    assert!(
        items[0].collision,
        "the existing digest must block auto alias"
    );
    let unfenced_write = invocation(
        &owner_jwk,
        &owner_did,
        &owner_vm,
        vec![],
        &resource,
        "tinycloud.sql/write",
        "urn:uuid:00000000-0000-4000-8000-000000000026",
    )?;
    let (status, response) = invoke_json(&client, unfenced_write, &sql_write_body("blocked")).await;
    assert_eq!(status, Status::ServiceUnavailable, "{response}");
    Ok(())
}

fn holder_identity() -> Result<(JWK, String, String)> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    Ok((jwk, did.clone(), format!("{did}#{fragment}")))
}

/// Boot a real node against a temp datadir and return (client, node metadata
/// connection, space id). Kept per-test: the process-global logger can only be
/// initialized once per process *target*, and separate #[tokio::test]s in one
/// binary each need their own app instance anyway.
async fn boot_node(
    tempdir: &TempDir,
    space_id: &SpaceId,
    extra_actor_dids: &[String],
) -> Result<(Client, DatabaseConnection)> {
    let datadir = tempdir.path().join("data");
    std::fs::create_dir_all(&datadir)?;
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let config_overlay = format!(
        r#"
[storage]
datadir = "{}"

[keys]
type = "Static"
secret = "{}"
"#,
        datadir.display(),
        secret
    );
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&config_overlay));
    let tinycloud_config = figment.extract::<tinycloud::config::Config>()?;
    let rocket = tinycloud::app_with_control(&figment, &tinycloud_config, None).await?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;

    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(&conn)
    .await?;
    for did in extra_actor_dids {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&conn)
        .await?;
    }

    Ok((Client::tracked(rocket).await?, conn))
}

/// Persist a root-authority delegation row + one ability row, the way
/// `delegation::process` would have. The delegator is the space owner, so the
/// grant is self-authorizing. Same construction as the tc119 wire test.
async fn persist_grant(
    conn: &DatabaseConnection,
    delegation_hash: Hash,
    owner_did: &str,
    holder_did: &str,
    resource: &ResourceId,
    ability: &str,
) -> Result<()> {
    tinycloud_core::models::delegation::ActiveModel {
        id: Set(delegation_hash),
        delegator: Set(owner_did.to_string()),
        delegatee: Set(holder_did.to_string()),
        expiry: Set(Some(time::OffsetDateTime::from_unix_timestamp(
            FAR_FUTURE_SECONDS as i64,
        )?)),
        issued_at: Set(Some(time::OffsetDateTime::UNIX_EPOCH)),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(format!("tc780-n1-test-row:{ability}").into_bytes()),
    }
    .insert(conn)
    .await?;

    abilities::ActiveModel {
        delegation: Set(delegation_hash),
        resource: Set(Resource::TinyCloud(resource.clone())),
        ability: Set(Ability::try_from(ability.to_string()).unwrap()),
        caveats: Set(Caveats(BTreeMap::new())),
    }
    .insert(conn)
    .await?;
    Ok(())
}

/// Build a UCAN invocation Authorization header. `proofs` empty = root
/// authority (owner) self-invocation; otherwise cite the persisted grant.
fn invocation(
    invoker_jwk: &JWK,
    invoker_did: &str,
    invoker_vm: &str,
    proofs: Vec<AuthCid>,
    resource: &ResourceId,
    ability: &str,
    nonce: &str,
) -> Result<String> {
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        ability.parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let payload = Payload {
        issuer: invoker_vm.parse::<DIDURLBuf>()?,
        audience: invoker_did.parse::<DIDBuf>()?,
        not_before: None,
        // Must stay under the node's default 300 s invocation lifetime cap
        // (`config.invocation.max_lifetime_secs`), else /invoke rejects the
        // token before the authorization checks this test exists to exercise.
        expiration: NumericDate::try_from_seconds(
            time::OffsetDateTime::now_utc().unix_timestamp() as f64 + 250.0,
        )?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: proofs,
        attenuation: caps,
    }
    .sign(invoker_jwk.get_algorithm().unwrap_or_default(), invoker_jwk)?;
    Ok(payload.encode()?)
}

fn db_resource(space_id: &SpaceId, service: &str, path: &str) -> Result<ResourceId> {
    Ok(space_id.clone().to_resource(
        service.parse::<Service>()?,
        Some(path.parse::<AuthPath>()?),
        None,
        None,
    ))
}

/// Dispatch a JSON-bodied `/invoke` and return (status, body).
async fn invoke_json(
    client: &Client,
    header: String,
    body: &serde_json::Value,
) -> (Status, String) {
    let resp = client
        .post("/invoke")
        .header(Header::new("Authorization", header))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    (status, body)
}

/// Bundled invoker identity for readability.
struct Invoker {
    jwk: JWK,
    did: String,
    vm: String,
}

/// Append a failure description when `ok` is false. Collecting rather than
/// panicking means one red run reports EVERY broken guarantee, not just the
/// first — both defects surface in the same failure output.
fn check(failures: &mut Vec<String>, ok: bool, detail: impl std::fmt::Display) {
    if !ok {
        failures.push(detail.to_string());
    }
}

fn sql_write_body(row: &str) -> serde_json::Value {
    serde_json::to_value(SqlRequest::Execute {
        schema: Some(vec!["CREATE TABLE IF NOT EXISTS t (v TEXT)".to_string()]),
        sql: "INSERT INTO t (v) VALUES (?)".to_string(),
        params: vec![SqlValue::Text(row.to_string())],
    })
    .expect("SqlRequest serializes")
}

fn duckdb_write_body(row: &str) -> serde_json::Value {
    serde_json::to_value(DuckDbRequest::Execute {
        sql: "INSERT INTO t (v) VALUES (?)".to_string(),
        params: vec![DuckDbValue::Text(row.to_string())],
        schema: Some(vec!["CREATE TABLE IF NOT EXISTS t (v TEXT)".to_string()]),
    })
    .expect("DuckDbRequest serializes")
}

/// Per-engine parameters for the shared scenario driver.
struct Engine {
    service: &'static str,
    write_ability: &'static str,
    read_ability: &'static str,
    grant_seed: &'static [u8],
    nonce_prefix: &'static str,
    /// Builds the Execute body writing `row` into `t`. The DDL is `IF NOT
    /// EXISTS` because on main BOTH owner writes land in the same `connectors`
    /// database — the second write must still succeed so the two rows coexist.
    write_body: fn(&str) -> serde_json::Value,
    read_body: serde_json::Value,
}

/// Run the full repro for one engine and return every violated guarantee.
/// An empty Vec is the correct (post-N2) outcome.
async fn run_scenario(engine: &Engine, space_name: &str, tempdir: &TempDir) -> Result<Vec<String>> {
    let (owner_jwk, owner_did, owner_vm, space_id) = space_identity(space_name)?;
    let owner = Invoker {
        jwk: owner_jwk,
        did: owner_did,
        vm: owner_vm,
    };
    let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
    let holder = Invoker {
        jwk: holder_jwk,
        did: holder_did,
        vm: holder_vm,
    };
    let (client, conn) =
        boot_node(tempdir, &space_id, &[owner.did.clone(), holder.did.clone()]).await?;

    let mut failures: Vec<String> = Vec::new();

    // The OWNER writes under BOTH paths through the real invoke path — root
    // authority means no grant row is needed. On main these land in the same
    // `connectors` database; after N2 they are separate databases.
    let appa = db_resource(&space_id, engine.service, "appA/connectors")?;
    let appb = db_resource(&space_id, engine.service, "appB/connectors")?;
    for (resource, row, nonce_suffix) in [(&appa, APP_A_ROW, "05"), (&appb, APP_B_SECRET, "01")] {
        let (status, body) = invoke_json(
            &client,
            invocation(
                &owner.jwk,
                &owner.did,
                &owner.vm,
                vec![],
                resource,
                engine.write_ability,
                &format!(
                    "urn:uuid:00000000-0000-4000-8000-{}{nonce_suffix}",
                    engine.nonce_prefix
                ),
            )?,
            &(engine.write_body)(row),
        )
        .await;
        if status != Status::Ok {
            // Seed failed — the rest of the scenario is meaningless. This is a
            // harness bug, not the defect, so bail loudly.
            return Err(anyhow::anyhow!(
                "owner write of {row:?} under {} must succeed (got {status}): {body}",
                resource.path().map(|p| p.as_str()).unwrap_or("<none>"),
            ));
        }
    }

    // The holder is granted `<engine>/read` on the EXACT path
    // `appA/connectors` — no trailing slash.
    let holder_grant = tinycloud_core::hash::hash(engine.grant_seed);
    persist_grant(
        &conn,
        holder_grant,
        &owner.did,
        &holder.did,
        &appa,
        engine.read_ability,
    )
    .await?;

    // (1) Cross-app isolation, in both directions of correctness: the exact-
    // path grant must SUCCEED and return appA's own row (an over-narrowed fix
    // that rejects or empties this read is also wrong), AND it must not leak
    // appB's row. On main both paths resolve to the `connectors` database, so
    // the response contains BOTH rows.
    let (status, body) = invoke_json(
        &client,
        invocation(
            &holder.jwk,
            &holder.did,
            &holder.vm,
            vec![holder_grant.to_cid(0x55)],
            &appa,
            engine.read_ability,
            &format!("urn:uuid:00000000-0000-4000-8000-{}02", engine.nonce_prefix),
        )?,
        &engine.read_body,
    )
    .await;
    check(
        &mut failures,
        status == Status::Ok && body.contains(APP_A_ROW),
        format!(
            "the exact-path grant on appA/connectors must authorize a read \
             returning its own row (expected 200 with {APP_A_ROW:?}, got \
             {status}): {body}"
        ),
    );
    check(
        &mut failures,
        !body.contains(APP_B_SECRET),
        format!(
            "appA/connectors must NOT read data written under appB/connectors \
             (status {status}); the two paths share the `connectors` database: {body}"
        ),
    );

    // (2) Exact-path authorization: a grant for `appA/connectors` (no trailing
    // slash) must NOT authorize `appA/connectors/private`. On main `extends`
    // accepts descendants, authorization passes, and the request reaches the
    // `private` database — so the status is not 401.
    let appa_private = db_resource(&space_id, engine.service, "appA/connectors/private")?;
    let (status, body) = invoke_json(
        &client,
        invocation(
            &holder.jwk,
            &holder.did,
            &holder.vm,
            vec![holder_grant.to_cid(0x55)],
            &appa_private,
            engine.read_ability,
            &format!("urn:uuid:00000000-0000-4000-8000-{}03", engine.nonce_prefix),
        )?,
        &engine.read_body,
    )
    .await;
    check(
        &mut failures,
        status == Status::Unauthorized,
        format!(
            "an exact-path grant for appA/connectors must NOT authorize \
             appA/connectors/private (expected 401, got {status}): {body}"
        ),
    );

    // Control (passes today): the same grant must NOT authorize the sibling
    // path `appB/connectors` — resource matching rejects it outright. This
    // guards the N2 fix from over-narrowing grants.
    let (status, body) = invoke_json(
        &client,
        invocation(
            &holder.jwk,
            &holder.did,
            &holder.vm,
            vec![holder_grant.to_cid(0x55)],
            &appb,
            engine.read_ability,
            &format!("urn:uuid:00000000-0000-4000-8000-{}04", engine.nonce_prefix),
        )?,
        &engine.read_body,
    )
    .await;
    check(
        &mut failures,
        status == Status::Unauthorized,
        format!(
            "a grant for appA/connectors must NOT authorize appB/connectors \
             (expected 401, got {status}): {body}"
        ),
    );

    Ok(failures)
}

/// SQL path-isolation repro (TC-780 N1, engine = sql). On main the returned
/// failure list names both defects: `sql/service.rs` `db_name_from_path`
/// collapses `appA/connectors` and `appB/connectors` to the same `connectors`
/// database, and `ResourceId::extends` (`models/invocation.rs`) authorizes
/// descendants of an exact-path grant.
#[tokio::test]
async fn sql_paths_do_not_share_databases_and_grants_are_exact() -> Result<()> {
    let tempdir = TempDir::new()?;
    let engine = Engine {
        service: "sql",
        write_ability: "tinycloud.sql/write",
        read_ability: "tinycloud.sql/read",
        grant_seed: b"tc780-n1-sql-read-appA-connectors",
        nonce_prefix: "000000000a",
        write_body: sql_write_body,
        read_body: serde_json::to_value(SqlRequest::Query {
            sql: "SELECT v FROM t".to_string(),
            params: vec![],
            max_rows: None,
            max_bytes: None,
        })?,
    };
    let failures = run_scenario(&engine, "tc780-n1-sql", &tempdir).await?;
    assert!(
        failures.is_empty(),
        "SQL path isolation violated:\n  - {}",
        failures.join("\n  - ")
    );
    Ok(())
}

/// DuckDB path-isolation repro — same defects through `duckdb/service.rs`
/// `db_name_from_path` (last segment, or `default`) plus the same
/// `ResourceId::extends` descendant acceptance.
#[tokio::test]
async fn duckdb_paths_do_not_share_databases_and_grants_are_exact() -> Result<()> {
    let tempdir = TempDir::new()?;
    let engine = Engine {
        service: "duckdb",
        write_ability: "tinycloud.duckdb/write",
        read_ability: "tinycloud.duckdb/read",
        grant_seed: b"tc780-n1-duckdb-read-appA-connectors",
        nonce_prefix: "000000000b",
        write_body: duckdb_write_body,
        read_body: serde_json::to_value(DuckDbRequest::Query {
            sql: "SELECT v FROM t".to_string(),
            params: vec![],
        })?,
    };
    let failures = run_scenario(&engine, "tc780-n1-duckdb", &tempdir).await?;
    assert!(
        failures.is_empty(),
        "DuckDB path isolation violated:\n  - {}",
        failures.join("\n  - ")
    );
    Ok(())
}

fn regression_engine(service: &'static str) -> Result<Engine> {
    Ok(match service {
        "sql" => Engine {
            service,
            write_ability: "tinycloud.sql/write",
            read_ability: "tinycloud.sql/read",
            grant_seed: b"tc780-n2-ancestor-sql",
            nonce_prefix: "000000000c",
            write_body: sql_write_body,
            read_body: serde_json::to_value(SqlRequest::Query {
                sql: "SELECT v FROM t".to_string(),
                params: vec![],
                max_rows: None,
                max_bytes: None,
            })?,
        },
        "duckdb" => Engine {
            service,
            write_ability: "tinycloud.duckdb/write",
            read_ability: "tinycloud.duckdb/read",
            grant_seed: b"tc780-n2-ancestor-duckdb",
            nonce_prefix: "000000000d",
            write_body: duckdb_write_body,
            read_body: serde_json::to_value(DuckDbRequest::Query {
                sql: "SELECT v FROM t".to_string(),
                params: vec![],
            })?,
        },
        _ => unreachable!(),
    })
}

/// Simulate a child delegation persisted under the pre-N2 descendant rule.
/// Its slash path covers the invocation by itself, but its exact ancestor does
/// not. The full /invoke authorization path must reject it for both engines.
#[tokio::test]
async fn pre_n2_descendant_delegation_cannot_outgrow_exact_ancestor() -> Result<()> {
    for service in ["sql", "duckdb"] {
        let engine = regression_engine(service)?;
        let tempdir = TempDir::new()?;
        let (_owner_jwk, owner_did, _owner_vm, space_id) = space_identity(service)?;
        let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
        let (client, conn) = boot_node(
            &tempdir,
            &space_id,
            &[owner_did.clone(), holder_did.clone()],
        )
        .await?;

        let exact = db_resource(&space_id, service, "appA/connectors")?;
        let slash_child = db_resource(&space_id, service, "appA/connectors/")?;
        let private = db_resource(&space_id, service, "appA/connectors/private")?;
        let parent_id = tinycloud_core::hash::hash(format!("{service}-exact").as_bytes());
        let child_id = tinycloud_core::hash::hash(format!("{service}-slash-child").as_bytes());
        persist_grant(
            &conn,
            parent_id,
            &owner_did,
            &holder_did,
            &exact,
            engine.read_ability,
        )
        .await?;
        persist_grant(
            &conn,
            child_id,
            &holder_did,
            &holder_did,
            &slash_child,
            engine.read_ability,
        )
        .await?;
        parent_delegations::ActiveModel {
            parent: Set(parent_id),
            child: Set(child_id),
        }
        .insert(&conn)
        .await?;

        let (status, body) = invoke_json(
            &client,
            invocation(
                &holder_jwk,
                &holder_did,
                &holder_vm,
                vec![child_id.to_cid(0x55)],
                &private,
                engine.read_ability,
                &format!("urn:uuid:00000000-0000-4000-8000-{}13", engine.nonce_prefix),
            )?,
            &engine.read_body,
        )
        .await;
        assert_eq!(status, Status::Unauthorized, "{service}: {body}");
    }
    Ok(())
}

/// A leaf with capabilities for two databases can cite one grant for each.
/// Invoking either capability needs one covering path through its own grant,
/// even though the other cited parent does not cover that database.
#[tokio::test]
async fn mixed_parent_delegation_keeps_each_database_capability() -> Result<()> {
    for service in ["sql", "duckdb"] {
        let engine = regression_engine(service)?;
        let tempdir = TempDir::new()?;
        let (owner_jwk, owner_did, owner_vm, space_id) = space_identity(service)?;
        let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
        let (client, conn) = boot_node(
            &tempdir,
            &space_id,
            &[owner_did.clone(), holder_did.clone()],
        )
        .await?;
        let resources = [
            db_resource(&space_id, service, "appA/a")?,
            db_resource(&space_id, service, "appA/b")?,
        ];
        let root_ids = [
            tinycloud_core::hash::hash(format!("{service}-mixed-a").as_bytes()),
            tinycloud_core::hash::hash(format!("{service}-mixed-b").as_bytes()),
        ];
        let leaf_id = tinycloud_core::hash::hash(format!("{service}-mixed-leaf").as_bytes());

        for (index, resource) in resources.iter().enumerate() {
            let (status, body) = invoke_json(
                &client,
                invocation(
                    &owner_jwk,
                    &owner_did,
                    &owner_vm,
                    vec![],
                    resource,
                    engine.write_ability,
                    &format!(
                        "urn:uuid:00000000-0000-4000-8000-{}2{index}",
                        engine.nonce_prefix
                    ),
                )?,
                &(engine.write_body)(&format!("mixed-row-{index}")),
            )
            .await;
            assert_eq!(status, Status::Ok, "{service}: {body}");

            persist_grant(
                &conn,
                root_ids[index],
                &owner_did,
                &holder_did,
                resource,
                engine.read_ability,
            )
            .await?;
        }
        persist_grant(
            &conn,
            leaf_id,
            &holder_did,
            &holder_did,
            &resources[0],
            engine.read_ability,
        )
        .await?;
        abilities::ActiveModel {
            delegation: Set(leaf_id),
            resource: Set(Resource::TinyCloud(resources[1].clone())),
            ability: Set(Ability::try_from(engine.read_ability.to_string()).unwrap()),
            caveats: Set(Caveats(BTreeMap::new())),
        }
        .insert(&conn)
        .await?;
        for root_id in root_ids {
            parent_delegations::ActiveModel {
                parent: Set(root_id),
                child: Set(leaf_id),
            }
            .insert(&conn)
            .await?;
        }

        for (index, resource) in resources.iter().enumerate() {
            let (status, body) = invoke_json(
                &client,
                invocation(
                    &holder_jwk,
                    &holder_did,
                    &holder_vm,
                    vec![leaf_id.to_cid(0x55)],
                    resource,
                    engine.read_ability,
                    &format!(
                        "urn:uuid:00000000-0000-4000-8000-{}3{index}",
                        engine.nonce_prefix
                    ),
                )?,
                &engine.read_body,
            )
            .await;
            assert_eq!(status, Status::Ok, "{service}: {body}");
            assert!(
                body.contains(&format!("mixed-row-{index}")),
                "{service}: {body}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn long_database_paths_work_through_invoke_for_both_engines() -> Result<()> {
    for service in ["sql", "duckdb"] {
        let engine = regression_engine(service)?;
        let tempdir = TempDir::new()?;
        let (owner_jwk, owner_did, owner_vm, space_id) = space_identity(service)?;
        let (client, _conn) =
            boot_node(&tempdir, &space_id, std::slice::from_ref(&owner_did)).await?;
        let path = format!("appA/{}", "x".repeat(1024));
        let resource = db_resource(&space_id, service, &path)?;
        for (ability, nonce_suffix, body) in [
            (
                engine.write_ability,
                "11",
                (engine.write_body)("long-path-row"),
            ),
            (engine.read_ability, "12", engine.read_body.clone()),
        ] {
            let (status, response) = invoke_json(
                &client,
                invocation(
                    &owner_jwk,
                    &owner_did,
                    &owner_vm,
                    vec![],
                    &resource,
                    ability,
                    &format!(
                        "urn:uuid:00000000-0000-4000-8000-{}{nonce_suffix}",
                        engine.nonce_prefix
                    ),
                )?,
                &body,
            )
            .await;
            assert_eq!(status, Status::Ok, "{service}: {response}");
            if ability == engine.read_ability {
                assert!(response.contains("long-path-row"), "{service}: {response}");
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn an_unrelated_parallel_proof_does_not_narrow_a_valid_database_chain() -> Result<()> {
    for service in ["sql", "duckdb"] {
        let engine = regression_engine(service)?;
        let tempdir = TempDir::new()?;
        let (owner_jwk, owner_did, owner_vm, space_id) = space_identity(service)?;
        let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
        let (client, conn) = boot_node(
            &tempdir,
            &space_id,
            &[owner_did.clone(), holder_did.clone()],
        )
        .await?;
        let database = db_resource(&space_id, service, "appA/connectors")?;
        let kv = db_resource(&space_id, "kv", "appA/notes")?;

        let (status, body) = invoke_json(
            &client,
            invocation(
                &owner_jwk,
                &owner_did,
                &owner_vm,
                vec![],
                &database,
                engine.write_ability,
                &format!("urn:uuid:00000000-0000-4000-8000-{}14", engine.nonce_prefix),
            )?,
            &(engine.write_body)("valid-chain-row"),
        )
        .await;
        assert_eq!(status, Status::Ok, "{service}: {body}");

        let db_grant = tinycloud_core::hash::hash(format!("{service}-valid-db").as_bytes());
        let kv_grant = tinycloud_core::hash::hash(format!("{service}-unrelated-kv").as_bytes());
        persist_grant(
            &conn,
            db_grant,
            &owner_did,
            &holder_did,
            &database,
            engine.read_ability,
        )
        .await?;
        persist_grant(
            &conn,
            kv_grant,
            &owner_did,
            &holder_did,
            &kv,
            "tinycloud.kv/get",
        )
        .await?;

        let (status, body) = invoke_json(
            &client,
            invocation(
                &holder_jwk,
                &holder_did,
                &holder_vm,
                vec![db_grant.to_cid(0x55), kv_grant.to_cid(0x55)],
                &database,
                engine.read_ability,
                &format!("urn:uuid:00000000-0000-4000-8000-{}15", engine.nonce_prefix),
            )?,
            &engine.read_body,
        )
        .await;
        assert_eq!(status, Status::Ok, "{service}: {body}");
        assert!(body.contains("valid-chain-row"), "{service}: {body}");
    }
    Ok(())
}
