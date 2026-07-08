//! TC-119 live-wire proof: the capability registry's alias and implication
//! semantics are enforced by the REAL `/invoke` path (not just the unit-level
//! `policy_capability::ability_matches`).
//!
//! A single node boot (the process-global logger can only be initialized once)
//! drives several holder-signed UCAN invocations that cite a root-authority
//! delegation persisted directly as a node row. Each invocation exercises the
//! exact chain-containment code changed in TC-119 (`models/invocation.rs`)
//! plus, for KV, the dispatch alias resolution in `db.rs`.
//!
//! Positive cases prove a registry-declared alias / implication authorizes an
//! invocation whose ability differs from the grant; negative controls prove
//! the change is a strict, registry-BOUNDED widening (undeclared pairs are
//! still rejected). We assert on the error body because the KV `/invoke` error
//! mapping collapses to 401 for both "authorized but no such key" and
//! "unauthorized" — the body ("No Such Key" vs "Unauthorized Action") is the
//! chain-authorization boundary, and neither `kv/del`/`kv/get`/`kv/delete`
//! reaches block-store I/O before the chain check runs.

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
    hash::Hash,
    models::{abilities, actor, space},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection},
    sql::{SqlRequest, SqlService, SqlValue},
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

const FAR_FUTURE_SECONDS: f64 = 4_102_444_800.0; // 2100-01-01

fn test_space_id(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
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
    let verification_method = format!("{did}#{fragment}");
    Ok((jwk, did, verification_method))
}

/// Persist a root-authority delegation row + one ability row directly, the way
/// the node would have after `delegation::process`. The delegator is the space
/// owner (root authority for the resource), so the grant is self-authorizing.
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
        serialization: Set(format!("tc119-test-row:{ability}").into_bytes()),
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

/// Build a holder-signed UCAN invocation Authorization header citing
/// `delegation_hash` as its proof and requesting `ability` on `resource`.
fn holder_invocation(
    holder_jwk: &JWK,
    holder_did: &str,
    holder_vm: &str,
    delegation_hash: Hash,
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
    let parent_cid: AuthCid = delegation_hash.to_cid(0x55);
    let invocation = Payload {
        issuer: holder_vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(FAR_FUTURE_SECONDS)?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent_cid],
        attenuation: caps,
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), holder_jwk)?;
    Ok(invocation.encode()?)
}

#[tokio::test]
async fn registry_alias_and_implication_are_enforced_on_the_wire() -> Result<()> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
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
    let rocket = tinycloud::app(&figment).await?;
    let sql_service = rocket
        .state::<SqlService>()
        .context("node app must manage SqlService")?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;

    let space_id = test_space_id("tc119-wire");
    let owner_did = space_id.did().to_string();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(&conn)
    .await?;

    let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
    for did in [&owner_did, &holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&conn)
        .await?;
    }

    // Materialize the SQL db so the holder's DDL has a database to run in.
    sql_service
        .execute(
            &space_id,
            "records",
            SqlRequest::Execute {
                schema: Some(vec!["CREATE TABLE seed (id INTEGER)".to_string()]),
                sql: "INSERT INTO seed (id) VALUES (?)".to_string(),
                params: vec![SqlValue::Integer(1)],
            },
            None,
            "tinycloud.sql/write".to_string(),
        )
        .await?;

    let kv_resource: ResourceId = space_id.clone().to_resource(
        "kv".parse::<Service>()?,
        Some("docs/note".parse::<AuthPath>()?),
        None,
        None,
    );
    let sql_resource: ResourceId = space_id.clone().to_resource(
        "sql".parse::<Service>()?,
        Some("records".parse::<AuthPath>()?),
        None,
        None,
    );

    // The holder is granted the DEPRECATED ALIAS `kv/delete` and only
    // `sql/admin`.
    let kv_del_grant = tinycloud_core::hash::hash(b"tc119-kv-delete-alias-grant");
    persist_grant(
        &conn,
        kv_del_grant,
        &owner_did,
        &holder_did,
        &kv_resource,
        "tinycloud.kv/delete",
    )
    .await?;
    let sql_admin_grant = tinycloud_core::hash::hash(b"tc119-sql-admin-grant");
    persist_grant(
        &conn,
        sql_admin_grant,
        &owner_did,
        &holder_did,
        &sql_resource,
        "tinycloud.sql/admin",
    )
    .await?;

    let client = Client::tracked(rocket).await?;

    // Helper: dispatch a bodiless KV invocation and return (status, body).
    async fn kv_invoke(client: &Client, header: String) -> (Status, String) {
        let resp = client
            .post("/invoke")
            .header(Header::new("Authorization", header))
            .dispatch()
            .await;
        let status = resp.status();
        let body = resp.into_string().await.unwrap_or_default();
        (status, body)
    }

    // --- KV: chain-level alias (grant `kv/delete` ⊇ request `kv/del`) ---
    // A `kv/del` request authorized by the `kv/delete` grant clears the chain
    // check and fails only at the (empty-store) delete lookup — proving the
    // alias is honored on the chain. Pre-TC-119 this returned "Unauthorized
    // Action".
    let (_status, body) = kv_invoke(
        &client,
        holder_invocation(
            &holder_jwk,
            &holder_did,
            &holder_vm,
            kv_del_grant,
            &kv_resource,
            "tinycloud.kv/del",
            "urn:uuid:00000000-0000-4000-8000-00000000c101",
        )?,
    )
    .await;
    assert!(
        body.contains("No Such Key"),
        "kv/delete grant must authorize a kv/del request on the chain \
         (expected the empty-store 'No Such Key', got: {body})"
    );
    assert!(
        !body.contains("Unauthorized Action"),
        "kv/del must NOT be rejected by the chain check: {body}"
    );

    // --- KV: dispatch-level alias (request `kv/delete` dispatches as `del`) ---
    // An invocation whose OWN ability is the alias `kv/delete` must dispatch to
    // the delete handler (db.rs resolve_alias). It therefore reaches the delete
    // lookup and yields "No Such Key". Pre-TC-119 the alias fell through the
    // dispatch match (`_ => {}`) and the invocation was a silent no-op success.
    let (_status, body) = kv_invoke(
        &client,
        holder_invocation(
            &holder_jwk,
            &holder_did,
            &holder_vm,
            kv_del_grant,
            &kv_resource,
            "tinycloud.kv/delete",
            "urn:uuid:00000000-0000-4000-8000-00000000c102",
        )?,
    )
    .await;
    assert!(
        body.contains("No Such Key"),
        "kv/delete request must dispatch as del (reach the delete lookup): {body}"
    );

    // --- KV NEGATIVE: `kv/delete` grant must NOT authorize `kv/get` ---
    let (status, body) = kv_invoke(
        &client,
        holder_invocation(
            &holder_jwk,
            &holder_did,
            &holder_vm,
            kv_del_grant,
            &kv_resource,
            "tinycloud.kv/get",
            "urn:uuid:00000000-0000-4000-8000-00000000c103",
        )?,
    )
    .await;
    assert_eq!(status, Status::Unauthorized);
    assert!(
        body.contains("Unauthorized Action"),
        "kv/delete grant must NOT authorize kv/get (undeclared): {body}"
    );

    // --- SQL: implication (grant `sql/admin` ⊃ request `sql/schema`) ---
    let resp = client
        .post("/invoke")
        .header(Header::new(
            "Authorization",
            holder_invocation(
                &holder_jwk,
                &holder_did,
                &holder_vm,
                sql_admin_grant,
                &sql_resource,
                "tinycloud.sql/schema",
                "urn:uuid:00000000-0000-4000-8000-00000000c201",
            )?,
        ))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&SqlRequest::Execute {
            schema: None,
            sql: "CREATE TABLE holder_created (x INTEGER)".to_string(),
            params: vec![],
        })?)
        .dispatch()
        .await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Ok,
        "sql/admin grant must authorize an sql/schema DDL invocation live: {body}"
    );

    // --- SQL NEGATIVE: `sql/admin` grant must NOT authorize `sql/write` ---
    // The registry declares `admin ⊃ schema` only, NOT `admin ⊃ write`.
    let resp = client
        .post("/invoke")
        .header(Header::new(
            "Authorization",
            holder_invocation(
                &holder_jwk,
                &holder_did,
                &holder_vm,
                sql_admin_grant,
                &sql_resource,
                "tinycloud.sql/write",
                "urn:uuid:00000000-0000-4000-8000-00000000c202",
            )?,
        ))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&SqlRequest::Execute {
            schema: None,
            sql: "INSERT INTO seed (id) VALUES (2)".to_string(),
            params: vec![],
        })?)
        .dispatch()
        .await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Unauthorized,
        "sql/admin grant must NOT authorize sql/write (undeclared): {body}"
    );

    Ok(())
}
