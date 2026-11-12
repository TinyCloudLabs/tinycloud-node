//! Public registration of the frozen proofless owner-signed lease profile.
mod common;
#[path = "support/owner_lease.rs"]
mod support;
use rocket::http::{Header, Status};
use serde_json::json;
use support::*;
use tinycloud_core::sea_orm::{ConnectionTrait, Statement};

async fn register(f: &Fixture, auth: String) -> (Status, String) {
    let response = f
        .client
        .post("/delegate")
        .header(Header::new("Authorization", auth))
        .dispatch()
        .await;
    (
        response.status(),
        response.into_string().await.unwrap_or_default(),
    )
}
async fn exercise(url: Option<&str>) {
    let f = fixture(url, 0x11).await;
    let conn = f.db().connection();
    let row = conn
        .query_one(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT serialization FROM delegation WHERE id=$1",
            [Vec::<u8>::from(f.lease_id).into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let lease = String::from_utf8(row.try_get::<Vec<u8>>("", "serialization").unwrap()).unwrap();
    conn.execute_unprepared("DELETE FROM renewal_stamp")
        .await
        .unwrap();
    conn.execute_unprepared("DELETE FROM renewal_lease")
        .await
        .unwrap();
    // The first HTTP registration must create the lease graph as well as its registry row.
    for table in ["ability", "delegation_cid_alias", "delegation"] {
        let column = if table == "ability" {
            "delegation"
        } else {
            "id"
        };
        conn.execute(Statement::from_sql_and_values(
            conn.get_database_backend(),
            format!("DELETE FROM {table} WHERE {column}=$1"),
            [Vec::<u8>::from(f.lease_id).into()],
        ))
        .await
        .unwrap();
    }
    let original = serde_json::to_value(
        tinycloud_auth::authorization::TinyCloudInvocation::decode(&lease)
            .unwrap()
            .payload(),
    )
    .unwrap();
    assert_eq!(original["prf"], json!([]));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    // These signatures are valid; each refusal must come from authority/profile/time.
    for invalid in [
        resign(&lease, 0x22, |_| {}),
        resign(
            &lease,
            0x11,
            |c| {
                c["att"] = json!({format!("urn:cid:{}",f.original_cid):{"tinycloud.delegation/status":[{}]}})
            },
        ),
        resign(
            &lease,
            0x11,
            |c| c["att"] = json!({format!("urn:cid:{}",tinycloud_core::hash::hash(b"unknown original").to_cid(0x55)):{"tinycloud.delegation/renew":[{}]}}),
        ),
        resign(&lease, 0x11, |c| {
            c["exp"] = json!(now - 1);
            c["nbf"] = json!(now - 100);
        }),
        resign(&lease, 0x11, |c| c["nbf"] = json!(now + 100)),
        resign(&lease, 0x11, |c| c["prf"] = json!([f.original_cid])),
    ] {
        let result = register(&f, invalid).await;
        assert_eq!(result.0, Status::Unauthorized, "{result:?}");
        let rows = conn
            .query_one(Statement::from_string(
                conn.get_database_backend(),
                "SELECT count(*) AS n FROM renewal_lease",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rows.try_get::<i64>("", "n").unwrap(), 0);
        let graph = conn
            .query_one(Statement::from_string(
                conn.get_database_backend(),
                "SELECT count(*) AS n FROM delegation",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            graph.try_get::<i64>("", "n").unwrap(),
            1,
            "refused lease graph rolled back"
        );
    }
    let accepted = register(&f, lease.clone()).await;
    assert_eq!(accepted.0, Status::Ok, "{accepted:?}");
    assert_eq!(f.snapshot().await["state"], "active");
    assert_eq!(f.snapshot().await["generation"], 1);
    assert_eq!(register(&f, lease.clone()).await.0, Status::Ok);
    assert_eq!(f.snapshot().await["generation"], 1);
    let second = resign(&lease, 0x11, |c| c["nnc"] = json!("second-live-lease"));
    assert_eq!(register(&f, second).await.0, Status::Unauthorized);
    assert_eq!(f.snapshot().await["generation"], 1);
    if url.is_some() {
        conn.sea_orm_connection()
            .get_postgres_connection_pool()
            .close()
            .await;
    }
}

#[tokio::test]
async fn owner_signed_proofless_lease_registration_and_refusals() {
    exercise(None).await;
}

#[tokio::test]
async fn postgres_owner_signed_proofless_lease_registration_and_refusals() {
    use tinycloud_core::sea_orm::{Database, DatabaseBackend};
    let Some(url) = common::postgres_test_url(
        "postgres_owner_signed_proofless_lease_registration_and_refusals",
    ) else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "owner_lease_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DatabaseBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .unwrap();
    let mut shared = reqwest::Url::parse(&url).unwrap();
    shared
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    exercise(Some(shared.as_str())).await;
    admin
        .execute(Statement::from_string(
            DatabaseBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}
