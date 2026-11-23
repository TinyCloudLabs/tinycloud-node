//! TC-4092 over the real Rocket app: `POST /delegate` answers 401
//! `delegation_revoked` for signed bytes whose `revocation` row a purge deleted
//! and replaced with a `revocation_tombstone`, and registers them again once the
//! tombstone is gone (so the refusal is the tombstone's, not the fixture's).
//!
//! The purge itself is not run here: `remove_records` and the sweep need the
//! lifecycle ledger and, for the sweep, PostgreSQL. `tinycloud-core`'s
//! `tc4092_*` tests run the real purge and the real `delegate`; this test pins
//! the HTTP status and body for a tombstoned delegation.
mod common;
#[path = "support/owner_lease.rs"]
#[allow(dead_code)]
mod support;
use rocket::http::{Header, Status};
use support::*;
use tinycloud_core::models::revocation_tombstone;
use tinycloud_core::sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Set, Statement};

async fn count(f: &Fixture, table: &str) -> i64 {
    let conn = f.db().connection();
    conn.query_one(Statement::from_string(
        conn.get_database_backend(),
        format!("SELECT count(*) AS n FROM {table}"),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get::<i64>("", "n")
    .unwrap()
}

#[tokio::test]
async fn delegate_repost_of_a_tombstoned_delegation_is_401_delegation_revoked() {
    let f = fixture(None, 0x11).await;
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
    // The state after a purge: the lease's records are gone.
    conn.execute_unprepared("DELETE FROM renewal_stamp")
        .await
        .unwrap();
    conn.execute_unprepared("DELETE FROM renewal_lease")
        .await
        .unwrap();
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
    let now = time::OffsetDateTime::now_utc();
    revocation_tombstone::ActiveModel {
        delegation_canonical: Set(f.lease_id),
        delegation_expiry: Set(Some(now + time::Duration::hours(2))),
        revoked_at: Set(Some(now)),
        recorded_at: Set(now),
    }
    .insert(conn)
    .await
    .unwrap();

    let post = || async {
        let response = f
            .client
            .post("/delegate")
            .header(Header::new("Authorization", lease.clone()))
            .dispatch()
            .await;
        (
            response.status(),
            response.into_string().await.unwrap_or_default(),
        )
    };
    let (status, body) = post().await;
    assert_eq!(status, Status::Unauthorized, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["code"], "delegation_revoked", "{body}");
    assert_eq!(count(&f, "renewal_lease").await, 0, "no lease row");
    assert_eq!(count(&f, "renewal_stamp").await, 0, "no stamp");
    assert_eq!(count(&f, "delegation").await, 1, "only the original");

    // Control: without the tombstone the same bytes register.
    revocation_tombstone::Entity::delete_by_id(f.lease_id)
        .exec(conn)
        .await
        .unwrap();
    let (status, body) = post().await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(count(&f, "renewal_lease").await, 1);
}
