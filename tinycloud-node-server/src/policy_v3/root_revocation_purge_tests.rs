//! TC-4092: a Policy/v3 root revoked over the JSON `RootRevocation/v1` route
//! (`POST /revoke`) lives only in `policy_v3_root.revoked_at`; no `revocation`
//! row exists. A space purge deletes that row with the root, so purge must
//! leave a `revocation_tombstone`, or the same signed bytes register again
//! through `POST /policy/v3/policies` (the only route that creates a root) and
//! `POST /delegate`.
//!
//! The registration, the revocation and the re-posts go through the real routes
//! on SQLite and PostgreSQL. The purge is the real `remove_records` (the seam
//! `remove_records_for_test`), which `complete_space` and the sweep call after
//! they have chosen the records.

use super::test_harness::*;
use super::*;
use std::collections::HashSet;
use tinycloud_core::sea_orm::{
    ConnectionTrait, EntityTrait, QueryFilter, Statement, TransactionTrait,
};

async fn count<C: ConnectionTrait>(conn: &C, table: &str) -> i64 {
    conn.query_one(Statement::from_string(
        conn.get_database_backend(),
        format!("SELECT COUNT(*) AS n FROM {table}"),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get::<i64>("", "n")
    .unwrap()
}

fn hash_of(cid: &str) -> tinycloud_core::hash::Hash {
    tinycloud_core::hash::Hash::from(cid.parse::<tinycloud_auth::ipld_core::cid::Cid>().unwrap())
}

/// Post a registration body again: through the route when the policy binds an
/// encryption key path, else through the harness's route-equivalent writes
/// (the route refuses unbound sources before it reaches any delegation write).
async fn repost(h: &Harness, body: Value) -> (bool, String) {
    if body["policy"]["contentSource"]
        .get("encryptionKeyPath")
        .is_none()
    {
        match Harness::store_registration_on(&h.client, body).await {
            Ok(_) => (true, String::new()),
            Err(error) => (false, error.to_string()),
        }
    } else {
        let (status, body) = h.post_registration(body).await;
        (status == Status::Ok, format!("{status} {body}"))
    }
}

async fn revoked_root_stays_refused_after_purge(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::PkhSession,
        "revoked_root_stays_refused_after_purge",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let revoked = h.register_ok(policy_window()).await?;
    let kept = h.register_ok(policy_window()).await?;

    // The real RootRevocation/v1 route: the root row only, no `revocation` row.
    let (status, body) = h
        .revoke_root_json(&h.owner, &revoked.policy_root_cid, "policy-authority")
        .await?;
    assert_eq!(status, Status::Ok, "{body}");
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    let conn = &runtime.conn;
    assert_eq!(count(conn, "revocation").await, 0, "no revocation row");
    assert_eq!(count(conn, "revocation_tombstone").await, 0);
    assert_eq!(count(conn, "policy_v3_root").await, 4);
    let revoked_roots = policy_v3_root::Entity::find()
        .filter(policy_v3_root::Column::RevokedAt.is_not_null())
        .all(conn)
        .await?;
    assert_eq!(revoked_roots.len(), 1, "only the revoked policy root");
    assert_eq!(revoked_roots[0].root_cid, revoked.policy_root_cid);

    // What `complete_space` / the sweep do: delete both policies' records.
    let deleted: HashSet<_> = [
        &revoked.policy_root_cid,
        &revoked.enforcement_root_cid,
        &revoked.policy_cid,
        &kept.policy_root_cid,
        &kept.enforcement_root_cid,
        &kept.policy_cid,
    ]
    .into_iter()
    .map(|cid| hash_of(cid))
    .collect();
    let tx = conn.begin().await?;
    tinycloud_core::space_purge_records::remove_records_for_test(&tx, &deleted).await?;
    tx.commit().await?;
    assert_eq!(count(conn, "policy_v3_root").await, 0, "roots are gone");
    assert_eq!(count(conn, "policy_v3_registration").await, 0);

    // One tombstone, for the revoked root only, with its times and nothing else.
    let tombstones = tinycloud_core::models::revocation_tombstone::Entity::find()
        .all(conn)
        .await?;
    assert_eq!(tombstones.len(), 1, "{tombstones:?}");
    assert_eq!(
        tombstones[0].delegation_canonical,
        hash_of(&revoked.policy_root_cid)
    );
    assert!(tombstones[0].revoked_at.is_some(), "{tombstones:?}");
    assert!(tombstones[0].delegation_expiry.is_some(), "{tombstones:?}");

    // POST /policy/v3/policies with the same signed roots is refused whole.
    let (admitted, message) = repost(&h, revoked.registration.clone()).await;
    assert!(
        !admitted && message.contains("delegation-revoked"),
        "re-registration of a revoked root: {admitted} {message}"
    );
    assert_eq!(
        count(conn, "policy_v3_root").await,
        0,
        "nothing was written"
    );
    assert_eq!(count(conn, "policy_v3_registration").await, 0);

    // POST /delegate with the root's bytes: `ordinary_admission_allowed`
    // (policy_v3.rs:374) refuses any policy root there, tombstone or not, so
    // this route never admitted a re-posted root.
    let (status, body) = h
        .delegate(
            revoked.registration["policyRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .await;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert!(body.contains("policy-root-requires-registration"), "{body}");

    // Control: a root that was never revoked registers again.
    let (admitted, message) = repost(&h, kept.registration.clone()).await;
    assert!(admitted, "never-revoked policy after the purge: {message}");
    assert_eq!(count(conn, "policy_v3_root").await, 2);
    Ok(())
}
on_both_backends!(revoked_root_stays_refused_after_purge);
