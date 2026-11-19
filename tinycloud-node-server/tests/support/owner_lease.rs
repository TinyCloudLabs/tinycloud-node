//! Signed original/lease graph fixtures for public registration tests.
use rocket::{
    figment::{providers::Serialized, Figment},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::hash,
    sea_orm::{sea_query::Value as Sql, ConnectionTrait, Statement},
};

pub fn key() -> (JWK, String, String) {
    key_for_seed(0x11)
}
pub fn key_for_seed(byte: u8) -> (JWK, String, String) {
    let seed = [byte; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let key: JWK = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
        "x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),
        "d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}))
    .unwrap();
    let did = DID_METHODS.generate(&key, "key").unwrap().to_string();
    let method = format!("{}#{}", did, did.rsplit(':').next().unwrap());
    (key, did, method)
}
pub fn token(
    audience: &str,
    resource: &str,
    action: &str,
    generation: Option<u64>,
    nonce: &str,
    end: i64,
) -> String {
    let (key, _, method) = key();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut caps = Capabilities::<Value>::new();
    let mut caveat = BTreeMap::new();
    if let Some(generation) = generation {
        caveat.insert("expectedGeneration".into(), json!(generation));
    }
    caps.with_action(resource.parse().unwrap(), action.parse().unwrap(), [caveat]);
    Payload::<Value> {
        issuer: method.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 1) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(end as f64).unwrap(),
        nonce: Some(nonce.into()),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &key)
    .unwrap()
    .encode()
    .unwrap()
}

pub fn resign(token: &str, seed: u8, mutate: impl FnOnce(&mut Value)) -> String {
    let ucan = tinycloud_auth::authorization::TinyCloudInvocation::decode(token).unwrap();
    let mut claims = serde_json::to_value(ucan.payload()).unwrap();
    let (key, _, method) = key_for_seed(seed);
    claims["iss"] = json!(method);
    mutate(&mut claims);
    serde_json::from_value::<Payload<Value>>(claims)
        .unwrap()
        .sign(Algorithm::EdDSA, &key)
        .unwrap()
        .encode()
        .unwrap()
}
pub async fn node(url: Option<&str>) -> (Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some(url.unwrap_or("sqlite::memory:").into());
    config.keys = serde_json::from_value(
        json!({"type":"static","secret":base64::encode_config([0x42;32],base64::URL_SAFE_NO_PAD)}),
    )
    .unwrap();
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..Default::default()
    })
    .merge(Serialized::defaults(&config));
    let client = Client::tracked(tinycloud::app(&figment).await.unwrap())
        .await
        .unwrap();
    (client, dir)
}
pub struct Fixture {
    pub client: Client,
    pub _dir: tempfile::TempDir,
    pub original_cid: String,
    pub lease_id: tinycloud_core::hash::Hash,
}
pub async fn fixture(url: Option<&str>, lease_owner: u8) -> Fixture {
    let (client, dir) = node(url).await;
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    let identity = db.renewal_identity().unwrap();
    let (_, owner, _) = key();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let original = token(
        &identity.stable_node_did,
        "urn:test:original",
        "tinycloud.kv/get",
        None,
        &format!("original-{}", dir.path().display()),
        now + 3600,
    );
    let original = resign(&original, 0x11, |c| c["nbf"] = json!(now - 1));
    let original_id = hash(original.as_bytes());
    let original_cid = original_id.to_cid(0x55).to_string();
    let lease = token(
        &identity.renewer_did,
        &format!("urn:cid:{original_cid}"),
        "tinycloud.delegation/renew",
        None,
        "lease",
        now + 7200,
    );
    let lease = resign(&lease, lease_owner, |c| c["nbf"] = json!(now - 1));
    let lease_id = hash(lease.as_bytes());
    let conn = db.connection();
    let backend = conn.get_database_backend();
    let lease_grantor = key_for_seed(lease_owner).1;
    for actor in [
        &owner,
        &lease_grantor,
        &identity.stable_node_did,
        &identity.renewer_did,
    ] {
        conn.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO actor (id) VALUES ($1) ON CONFLICT DO NOTHING",
            [Sql::String(Some(Box::new(actor.clone())))],
        ))
        .await
        .unwrap();
    }
    for (id, serialized, delegatee, expiry) in [
        (original_id, original, &identity.stable_node_did, now + 3600),
        (lease_id, lease, &identity.renewer_did, now + 7200),
    ] {
        conn.execute(Statement::from_sql_and_values(backend,
            "INSERT INTO delegation (id, delegator, delegatee, expiry, issued_at, not_before, facts, serialization, serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
            [Sql::Bytes(Some(Box::new(Vec::<u8>::from(id)))),Sql::String(Some(Box::new(if id == lease_id { key_for_seed(lease_owner).1 } else { owner.clone() }))),Sql::String(Some(Box::new(delegatee.clone()))),
             Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(time::OffsetDateTime::from_unix_timestamp(expiry).unwrap().date(),time::OffsetDateTime::from_unix_timestamp(expiry).unwrap().time())))),Sql::Bytes(Some(Box::new(serialized.into_bytes())))])).await.unwrap();
        conn.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
            [Sql::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
        ))
        .await
        .unwrap();
    }
    conn.execute(Statement::from_sql_and_values(backend,
        "INSERT INTO ability (delegation, resource, ability, caveats) VALUES ($1,$2,'tinycloud.delegation/renew',$3)",
        [Sql::Bytes(Some(Box::new(Vec::<u8>::from(lease_id)))), Sql::String(Some(Box::new(format!("urn:cid:{original_cid}")))), Sql::Json(Some(Box::new(json!({}))))])).await.unwrap();
    Fixture {
        client,
        _dir: dir,
        original_cid,
        lease_id,
    }
}
impl Fixture {
    pub fn db(&self) -> &tinycloud::TinyCloud {
        self.client.rocket().state().unwrap()
    }
    pub async fn snapshot(&self) -> Value {
        let conn = self.db().connection();
        let row=conn.query_one(Statement::from_string(conn.get_database_backend(),
            "SELECT state,generation,(SELECT count(*) FROM renewal_stamp) AS stamps,(SELECT count(*) FROM invocation_replay) AS nonces FROM renewal_lease LIMIT 1")).await.unwrap().unwrap();
        json!({"state":row.try_get::<String>("","state").unwrap(),"generation":row.try_get::<i64>("","generation").unwrap(),
            "stamps":row.try_get::<i64>("","stamps").unwrap(),"nonces":row.try_get::<i64>("","nonces").unwrap()})
    }
}
