// P0 walking-skeleton gate (specs/compute-service-implementation-plan.md,
// §11.3 "501 behavior"): with the `compute` feature NOT compiled in, a
// request carrying a `tinycloud.compute/*` capability must return
// `501 Not Implemented` with "Compute support is not enabled on this node",
// byte-for-byte mirroring the pre-existing duckdb-less branch.
//
// This is the named feature-off gate the implementation plan requires as its
// own `--test` target (a name filter like `cargo test compute::disabled`
// would silently pass with zero tests run if the file were missing — banned
// per the plan's Smithers node template). It is compiled out entirely when
// `compute` IS enabled (`#![cfg(not(feature = "compute"))]` below) so the
// full suite stays green in both feature states: under `--features compute`
// the same wire request reaches the real (if still not-implemented) P0
// handler instead, which `compute_skeleton.rs` covers.
//
// The check here happens purely against the invocation's OWN claimed
// attenuation (`InvocationInfo::capabilities`, `routes/mod.rs`'s
// `#[cfg(not(feature = "compute"))]` branch) BEFORE any delegation-chain
// verification, so a self-signed, unpersisted did:key invocation is
// sufficient — no space, delegation, or ability rows need to exist in the
// database.

#![cfg(not(feature = "compute"))]

use anyhow::{Context, Result};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::collections::BTreeMap;
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

fn test_space_id(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

#[tokio::test]
async fn compute_capability_returns_501_when_feature_is_off() -> Result<()> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let secret = base64::encode_config([13u8; 32], base64::URL_SAFE_NO_PAD);
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

    // Self-signed, unpersisted invocation: the disabled-path check inspects
    // only the invocation's own claimed attenuation and never reaches
    // delegation-chain verification, so no space/delegation/ability rows are
    // needed.
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let verification_method = format!("{did}#{fragment}");

    let space = test_space_id("p0-compute-disabled");
    let resource: ResourceId = space.to_resource("compute".parse::<Service>()?, None, None, None);

    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        "tinycloud.compute/execute".parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let invocation = Payload {
        issuer: verification_method.parse::<DIDURLBuf>()?,
        audience: did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some("urn:uuid:00000000-0000-4000-8000-0000000000d1".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![],
        attenuation: caps,
    }
    .sign(jwk.get_algorithm().unwrap_or_default(), &jwk)?;
    let auth_header = invocation.encode()?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&serde_json::json!({
            "action": "execute",
            "function": "irrelevant-while-disabled"
        }))?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::NotImplemented,
        "compute capability with the feature off must 501: {body}"
    );
    assert_eq!(
        body, "Compute support is not enabled on this node",
        "expected the exact duckdb-mirroring disabled message, got: {body}"
    );

    // `/info` must NOT advertise compute when the feature is off.
    let info = client.get("/info").dispatch().await;
    let info_body: serde_json::Value = serde_json::from_str(&info.into_string().await.unwrap())?;
    let features = info_body["features"]
        .as_array()
        .context("features must be an array")?;
    assert!(
        !features.iter().any(|f| f == "compute"),
        "compute must not be advertised in /info when the feature is off: {features:?}"
    );

    Ok(())
}
