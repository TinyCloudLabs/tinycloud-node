//! HTTP conformance deltas requested by the exact-head security review.
#[path = "support/renewal_state.rs"]
mod support;
use rocket::http::{ContentType, Header, Status};
use serde_json::{json, Value};
use support::*;
use tinycloud_core::sea_orm::{ConnectionTrait, Statement};

#[tokio::test]
async fn exact_targets_and_owner_read_hide_foreign_and_missing_leases() {
    let f = fixture(None, 0x11).await;
    let auth = f.auth("stop-renewal", Some(1), "target-vector");
    let action = "tinycloud.delegation/stop-renewal";
    let owner = key().1;
    let space = format!("tinycloud:{}:review", owner.strip_prefix("did:").unwrap());
    let network = format!("urn:tinycloud:encryption:{owner}:review");
    let before = f.snapshot().await;
    for target in [
        format!("urn:cid:{}", f.original_cid),
        "urn:cid:*".into(),
        space,
        network,
    ] {
        let signed = resign(&auth, 0x11, |c| {
            c["att"] = json!({target:{action:[{"expectedGeneration":1}]}});
        });
        let result = f.request(Some(signed), &f.body(Some(1))).await;
        assert_eq!(result.0, Status::Forbidden, "{result:?}");
        assert_eq!(result.1["code"], "unauthorized_control");
        assert_eq!(f.snapshot().await, before);
    }
    let multiple = resign(&auth, 0x11, |c| {
        c["att"][format!("urn:cid:{}", f.original_cid)] =
            json!({action:[{"expectedGeneration":1}]});
    });
    let result = f.request(Some(multiple), &f.body(Some(1))).await;
    assert_eq!(result.0, Status::BadRequest);
    assert_eq!(result.1["code"], "invalid_request");
    assert_eq!(f.snapshot().await, before);

    let unknown = tinycloud_core::hash::hash(b"unknown owner read lease")
        .to_cid(0x55)
        .to_string();
    let read = f.auth("status", None, "foreign-read");
    let foreign = resign(&read, 0x22, |_| {});
    let absent = resign(&read, 0x22, |c| {
        c["att"] = json!({format!("urn:cid:{unknown}"):{"tinycloud.delegation/status":[{}]}});
    });
    // Compare actual response bytes, including the static message, not just codes.
    let mut responses = Vec::new();
    for (auth, body) in [
        (foreign, f.body(None)),
        (absent, json!({"version":1,"leaseCid":unknown})),
    ] {
        let response = f
            .client
            .post("/delegation/renewal/state")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", auth))
            .json(&body)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        responses.push(response.into_bytes().await.unwrap());
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(f.snapshot().await, before);
}

async fn stamps(f: &Fixture) -> Vec<Value> {
    let conn = f.db().connection();
    conn.query_all(Statement::from_string(
        conn.get_database_backend(),
        "SELECT * FROM renewal_stamp ORDER BY cid",
    ))
    .await
    .unwrap()
    .into_iter()
    .map(|row| {
        let mut value = json!({});
        for col in [
            "cid",
            "original_canonical",
            "lease_cid",
            "previous_stamp_cid",
            "signed_bytes",
            "signature",
            "replay_hash",
        ] {
            value[col] = json!(row.try_get::<Vec<u8>>("", col).unwrap());
        }
        for col in ["generation", "renewer_epoch"] {
            value[col] = json!(row.try_get::<i64>("", col).unwrap());
        }
        value["new_end"] = json!(row
            .try_get::<time::PrimitiveDateTime>("", "new_end")
            .unwrap()
            .to_string());
        value
    })
    .collect()
}

#[tokio::test]
async fn restart_preserves_state_nonce_receipts_and_every_stamp_field() {
    let storage = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite:{}?mode=rwc",
        storage.path().join("node.db").display()
    );
    let f = fixture(Some(&url), 0x11).await;
    let original_stamps = stamps(&f).await;
    assert!(!original_stamps.is_empty());
    let lease_end = time::OffsetDateTime::from_unix_timestamp(f.now + 7200)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let receipt = |state: &str, generation| {
        json!({"version":1,"originalCid":f.original_cid,
        "leaseCid":f.lease_cid,"state":state,"generation":generation,"leaseEnd":lease_end})
    };
    let stop = f.auth("stop-renewal", Some(1), "durable-stop");
    let result = f.request(Some(stop.clone()), &f.body(Some(1))).await;
    assert_eq!(result, (Status::Ok, receipt("stopped", 2)));
    assert_eq!(stamps(&f).await, original_stamps);
    let before_restart = f.snapshot().await;
    let Fixture {
        client,
        _dir,
        original_cid,
        lease_cid,
        original_id,
        lease_id,
        now,
    } = f;
    drop(client);
    let (client, restart_dir) = node(Some(&url)).await;
    let f = Fixture {
        client,
        _dir: restart_dir,
        original_cid,
        lease_cid,
        original_id,
        lease_id,
        now,
    };
    assert_eq!(f.snapshot().await, before_restart);
    assert_eq!(stamps(&f).await, original_stamps);
    let replay = f.request(Some(stop.clone()), &f.body(Some(1))).await;
    assert_eq!(replay.0, Status::Conflict);
    assert_eq!(replay.1["code"], "invocation_replay");
    assert_eq!(f.snapshot().await, before_restart);
    // A different expiration and new signature still cannot reuse the durable nonce.
    let changed_exp = resign(&stop, 0x11, |c| c["exp"] = json!(now + 45));
    let replay = f.request(Some(changed_exp), &f.body(Some(1))).await;
    assert_eq!(replay.0, Status::Conflict);
    assert_eq!(replay.1["code"], "invocation_replay");
    assert_eq!(f.snapshot().await, before_restart);
    let expected = |state: &str, generation| {
        json!({"version":1,"originalCid":f.original_cid,
        "leaseCid":f.lease_cid,"state":state,"generation":generation,"leaseEnd":lease_end})
    };
    assert_eq!(
        f.request(Some(f.auth("status", None, "restart-read")), &f.body(None))
            .await,
        (Status::Ok, expected("stopped", 2))
    );
    assert_eq!(
        f.request(
            Some(f.auth("enable-renewal", Some(2), "restart-enable")),
            &f.body(Some(2))
        )
        .await,
        (Status::Ok, expected("active", 3))
    );
    assert_eq!(stamps(&f).await, original_stamps);
    drop(_dir);
}
