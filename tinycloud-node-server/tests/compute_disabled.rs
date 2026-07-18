//! P0 named feature-off gate (C5, compute-service-implementation-plan.md):
//! with the `compute` cargo feature OFF, a `tinycloud.compute/*` invocation
//! must return `501 Not Implemented` with "Compute support is not enabled on
//! this node" -- byte-for-byte the same pattern as the duckdb-less branch
//! (compute-service.md §11.3).
//!
//! This file only makes sense with the feature OFF: with it on, the service
//! actually dispatches (see `compute_skeleton.rs`) and this assertion would
//! be false. `#![cfg(not(feature = "compute"))]` makes the whole test binary
//! compile away (0 tests, not a failure) when compiled with `--features
//! compute`, so the plan's "full suite stays green both ways" gate holds:
//! this test only ever runs -- and only ever needs to pass -- in the
//! default (compute-off) build.
#![cfg(not(feature = "compute"))]

use anyhow::Context;
use anyhow::Result;
use base64::{encode_config, URL_SAFE_NO_PAD};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use tempfile::TempDir;
use tinycloud_auth::{
    resolver::DID_METHODS,
    resource::{ResourceId, Service, SpaceId},
    siwe_recap::Ability as UcanAbility,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

fn test_space_id(name: &str) -> Result<SpaceId> {
    let jwk = JWK::generate_ed25519()?;
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key")?;
    Ok(SpaceId::new(
        did,
        name.parse().map_err(|e| anyhow::anyhow!("{e:?}"))?,
    ))
}

/// The disabled-service check in `invoke_impl` runs purely against the
/// invocation's self-declared attenuation, BEFORE any delegation-chain walk
/// -- so this request is deliberately unbacked by any real grant (no DB rows
/// inserted, `proof: vec![]`). If the 501 ever regressed to running the real
/// chain walk first, this test would start failing with 401/403 instead of
/// 501, which is exactly the drift we want caught.
#[tokio::test]
async fn compute_invocation_returns_501_when_feature_is_off() -> Result<()> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let secret = encode_config([13u8; 32], URL_SAFE_NO_PAD);
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
    let mut tinycloud_config = figment.extract::<tinycloud::config::Config>()?;
    tinycloud_config.storage.resolve();
    let rocket = tinycloud::app(&figment, &tinycloud_config, None).await?;

    let space = test_space_id("compute-disabled")?;

    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let verification_method = format!("{did}#{fragment}");

    let compute_resource: ResourceId = space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some("hello".parse().map_err(|e| anyhow::anyhow!("{e:?}"))?),
        None,
        None,
    );

    let mut capabilities = Capabilities::new();
    capabilities.with_action(
        compute_resource.as_uri(),
        "tinycloud.compute/execute".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );

    let invocation = Payload {
        issuer: verification_method.parse::<DIDURLBuf>()?,
        audience: did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some("urn:uuid:00000000-0000-4000-8000-0000000000c1".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(jwk.get_algorithm().unwrap_or_default(), &jwk)?;
    let auth_header = invocation.encode()?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"execute","function":"hello"}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::NotImplemented,
        "unexpected /invoke response: {body}"
    );
    assert_eq!(body, "Compute support is not enabled on this node");

    // `/version` must NOT advertise compute when the feature is off.
    let version = client.get("/version").dispatch().await;
    let version_body: serde_json::Value =
        serde_json::from_str(&version.into_string().await.unwrap())?;
    let features = version_body["features"]
        .as_array()
        .context("features must be an array")?;
    assert!(
        !features.iter().any(|f| f == "compute"),
        "compute must not be advertised in /version when the feature is off: {features:?}"
    );

    Ok(())
}
