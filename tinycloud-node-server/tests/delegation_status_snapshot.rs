//! Status history has the same binding for raw and non-raw codec CID aliases.
#[allow(dead_code)]
#[path = "support/owner_lease.rs"]
mod support;

use rocket::http::{ContentType, Header, Status};
use serde_json::{json, Value};

#[tokio::test]
async fn status_cid_codec_alias_preserves_exact_history_binding() {
    let fixture = support::fixture(None, 0x11).await;
    let (_, owner, _) = support::key();
    use tinycloud_auth::authorization::{
        make_invocation_from_uris, InvocationOptions, TinyCloudInvocation,
    };
    use tinycloud_core::sea_orm::{ConnectionTrait, Statement};
    let conn = fixture.db().connection();
    let row = conn
        .query_one(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT serialization FROM delegation WHERE id=$1",
            [Vec::<u8>::from(fixture.lease_id).into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let lease = String::from_utf8(row.try_get::<Vec<u8>>("", "serialization").unwrap()).unwrap();
    assert_eq!(
        fixture
            .client
            .post("/delegate")
            .header(Header::new("Authorization", lease))
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
    let secret = tinycloud_core::keys::StaticSecret::new(vec![0x42; 32]).unwrap();
    let seed = secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let key: tinycloud_auth::ssi::jwk::JWK = serde_json::from_value(json!({
        "kty":"OKP", "crv":"Ed25519", "alg":"EdDSA",
        "x":base64::encode_config(signing.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD),
        "d":base64::encode_config(seed, base64::URL_SAFE_NO_PAD),
    }))
    .unwrap();
    let did = secret.renewal_did();
    let method = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let end = time::OffsetDateTime::now_utc().unix_timestamp() + 300;
    let signed = make_invocation_from_uris(
        [(
            format!("urn:cid:{}", fixture.original_cid).parse().unwrap(),
            ["tinycloud.delegation/renew".parse().unwrap()],
        )],
        &fixture.lease_id.to_cid(0x55),
        &key,
        &method,
        end as f64,
        InvocationOptions::default(),
    )
    .unwrap();
    let invocation = tinycloud_core::events::Invocation::from_header_ser::<TinyCloudInvocation>(
        &signed.encode().unwrap(),
    )
    .unwrap();
    let replay_hash = invocation.content_hash();
    fixture
        .db()
        .issue_renewal_stamp(tinycloud_core::renewal::StampIssue {
            invocation: invocation.0,
            original_cid: fixture.original_cid.clone(),
            lease_cid: fixture.lease_id.to_cid(0x55).to_string(),
            replay_hash,
            replay_expires_at: end,
        })
        .await
        .unwrap();

    let original = tinycloud_core::hash::Hash::from(
        fixture
            .original_cid
            .parse::<tinycloud_auth::authorization::Cid>()
            .unwrap(),
    );
    for (target, history_len) in [(original, 1), (fixture.lease_id, 0)] {
        let mut responses = Vec::new();
        for codec in [0x55, 0x71] {
            let cid = target.to_cid(codec).to_string();
            let auth = support::token(
                &owner,
                &format!("urn:cid:{cid}"),
                "tinycloud.delegation/status",
                None,
                &format!("status-alias-{cid}"),
                time::OffsetDateTime::now_utc().unix_timestamp() + 300,
            );
            let response = fixture
                .client
                .post("/delegation/status")
                .header(Header::new("Authorization", auth))
                .header(ContentType::JSON)
                .body(json!({"cid": cid}).to_string())
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            let body: Value = response.into_json().await.unwrap();
            assert_eq!(body["cid"], cid);
            assert_eq!(body["status"], "active");
            assert_eq!(
                body["renewal_history"].as_array().unwrap().len(),
                history_len
            );
            for row in body["renewal_history"].as_array().unwrap() {
                assert_eq!(row["lease_cid"], fixture.lease_id.to_cid(0x55).to_string());
            }
            responses.push(body);
        }
        assert_eq!(responses[0]["status"], responses[1]["status"]);
        assert_eq!(
            responses[0]["effective_expiry"],
            responses[1]["effective_expiry"]
        );
        assert_eq!(
            responses[0]["renewal_history"],
            responses[1]["renewal_history"]
        );
    }
}
