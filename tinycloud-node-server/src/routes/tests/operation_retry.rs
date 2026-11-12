//! TC-2346: `/delegate` and the `/invoke` authorization step run their whole
//! operation once more after a connection lost before any write, and never
//! otherwise.
//!
//! The route tests go through the Rocket client. SQLite has no connection to
//! lose, so a `fault::Plan` fails the pool wrapper's next two retryable
//! statements of the operation (the statement and its own retry), which is
//! what a burst does; the loss then travels through the real wrapper, write
//! tracker, route and error mapping. The operation tests call
//! `track_writes_retrying` with the real operation and an injected failure.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    db_pool::fault::Plan,
    events::Delegation,
    models::delegation as delegation_model,
    sea_orm::{
        error::{RuntimeErr, SqlxError},
        PaginatorTrait,
    },
};

type Failure = TxError<BlockStores, tinycloud_core::keys::StaticSecret>;

/// A connection lost before the statement was sent, as the pool reports it.
fn lost() -> DbErr {
    DbErr::Query(RuntimeErr::SqlxError(SqlxError::WorkerCrashed))
}

/// A reset socket, as the pool reports it.
fn reset() -> DbErr {
    DbErr::Query(RuntimeErr::SqlxError(SqlxError::Io(std::io::Error::from(
        std::io::ErrorKind::ConnectionReset,
    ))))
}

async fn fixture() -> Result<KvSyncFixture> {
    KvSyncFixture::new_with(|rocket| rocket).await
}

fn tinycloud(fixture: &KvSyncFixture) -> &TinyCloud {
    fixture
        .client
        .rocket()
        .state::<TinyCloud>()
        .expect("TinyCloud is managed")
}

/// An owner-signed delegation of `kv/get` to the fixture's device, as the
/// `Authorization` header carries it.
fn owner_delegation_header(fixture: &KvSyncFixture, nonce: &str) -> Result<String> {
    let mut caps = Capabilities::new();
    caps.with_action(
        fixture.kv_resource("notes/")?.as_uri(),
        "tinycloud.kv/get".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let ucan = Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: fixture.device_did().parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![],
        attenuation: caps,
    }
    .sign(
        fixture.owner.get_algorithm().unwrap_or_default(),
        &fixture.owner,
    )?;
    Ok(TinyCloudDelegation::Ucan(Box::new(ucan)).encode()?)
}

fn owner_delegation(fixture: &KvSyncFixture, nonce: &str) -> Result<Delegation> {
    Ok(Delegation::from_header_ser::<TinyCloudDelegation>(
        &owner_delegation_header(fixture, nonce)?,
    )?)
}

async fn stored_delegations(fixture: &KvSyncFixture) -> u64 {
    delegation_model::Entity::find()
        .count(&fixture.conn)
        .await
        .unwrap()
}

// ---- Through the route -------------------------------------------------

#[tokio::test]
async fn delegate_route_retries_a_connection_lost_before_any_write_and_stores_once() -> Result<()> {
    use rocket::http::Header;
    let fixture = fixture().await?;
    let header = owner_delegation_header(&fixture, "tc2346-route-delegate")?;
    let plan = Plan::new(2, lost);

    let response = plan
        .scope(
            fixture
                .client
                .post("/delegate")
                .header(Header::new("Authorization", header))
                .dispatch(),
        )
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(plan.injected(), 2, "the loss reached the operation");
    assert_eq!(stored_delegations(&fixture).await, 1);
    Ok(())
}

#[tokio::test]
async fn delegate_route_retries_a_reset_socket_before_any_write() -> Result<()> {
    use rocket::http::Header;
    let fixture = fixture().await?;
    let header = owner_delegation_header(&fixture, "tc2346-route-delegate-io")?;
    let plan = Plan::new(2, reset);

    let response = plan
        .scope(
            fixture
                .client
                .post("/delegate")
                .header(Header::new("Authorization", header))
                .dispatch(),
        )
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(plan.injected(), 2);
    assert_eq!(stored_delegations(&fixture).await, 1);
    Ok(())
}

#[tokio::test]
async fn delegate_route_answers_the_safe_503_when_the_retry_is_lost_too() -> Result<()> {
    use rocket::http::Header;
    let fixture = fixture().await?;
    let header = owner_delegation_header(&fixture, "tc2346-route-delegate-twice")?;
    // The first run's statement and its retry, then the second run's too.
    let plan = Plan::new(4, lost);

    let response = plan
        .scope(
            fixture
                .client
                .post("/delegate")
                .header(Header::new("Authorization", header))
                .dispatch(),
        )
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::ServiceUnavailable, "{body}");
    assert!(body.starts_with(UNAVAILABLE_RETRYABLE), "{body}");
    assert_eq!(plan.injected(), 4, "two runs, no third");
    assert_eq!(stored_delegations(&fixture).await, 0);
    Ok(())
}

#[tokio::test]
async fn sql_invoke_route_retries_the_authorization_after_a_lost_connection() -> Result<()> {
    let fixture = fixture().await?;
    let plan = Plan::new(2, lost);

    let reply = plan
        .scope(fixture.owner_sql("db", tc1791_query("SELECT 1")))
        .await?;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(plan.injected(), 2, "the loss reached the authorization");
    Ok(())
}

#[tokio::test]
async fn sql_invoke_route_answers_the_safe_503_when_the_retry_is_lost_too() -> Result<()> {
    let fixture = fixture().await?;
    let plan = Plan::new(4, lost);

    let reply = plan
        .scope(fixture.owner_sql("db", tc1791_query("SELECT 1")))
        .await?;

    assert_eq!(reply.status, Status::ServiceUnavailable, "{}", reply.body);
    assert!(
        reply.body.starts_with(UNAVAILABLE_RETRYABLE),
        "{}",
        reply.body
    );
    assert_eq!(plan.injected(), 4);
    Ok(())
}

/// A database loss while loading a valid session's immediate delegation is
/// not an authorization refusal, for either a read or a write.
#[tokio::test]
async fn tc2514_delegation_lookup_failure_is_retryable() -> Result<()> {
    let fixture = fixture().await?;
    fixture.owner_write("notes/x", Some(b"value")).await?;
    let mut get_grant = None;

    for (path, action) in [
        ("notes/", "tinycloud.kv/list"),
        ("notes/x", "tinycloud.kv/get"),
        ("notes/x", "tinycloud.kv/metadata"),
        ("notes/x", "tinycloud.kv/put"),
        ("notes/x", "tinycloud.kv/del"),
    ] {
        let grant = fixture
            .signed_root_grant(action, action, whole_seconds_from_now(3600), false)
            .await?;
        if action == "tinycloud.kv/get" {
            get_grant = Some(grant);
        }
        let plan = Plan::new(4, lost);
        // Preflight runs before the route's write-tracking boundary. Scope
        // the existing fault injector around that lookup as well.
        let (reply, applied) = plan
            .scope(track_writes(fixture.dispatch(
                fixture.device_invocation(&[(path, action)], grant)?,
                &[],
            )))
            .await;
        assert_eq!(
            reply.status,
            Status::ServiceUnavailable,
            "{action}: {}",
            reply.body
        );
        assert!(
            reply.body.starts_with(UNAVAILABLE_RETRYABLE),
            "{action}: {}",
            reply.body
        );
        assert_eq!(plan.injected(), 2, "{action}: stop at the failed lookup");
        assert!(!applied, "{action}: preflight must not write");
    }

    // The session remains usable after the connection recovers.
    let grant = get_grant.expect("the get session was exercised");
    let reply = fixture
        .dispatch(
            fixture.device_invocation(&[("notes/x", "tinycloud.kv/get")], grant)?,
            &[],
        )
        .await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.body, "value");

    fixture.revoke("tc2514-revoked-session", grant).await?;
    let denied = fixture
        .dispatch(
            fixture.device_invocation(&[("notes/x", "tinycloud.kv/get")], grant)?,
            &[],
        )
        .await;
    assert_eq!(denied.status, Status::Unauthorized, "{}", denied.body);
    Ok(())
}

#[tokio::test]
async fn tc2514_account_query_authorization_lookup_failure_is_retryable() -> Result<()> {
    use rocket::http::{ContentType, Header};
    use tinycloud_core::sea_orm::{ActiveModelTrait, Set};
    let fixture =
        KvSyncFixture::new_with(|rocket| rocket.mount("/", rocket::routes![delegation_query]))
            .await?;
    let account = SpaceId::new(
        "did:pkh:eip155:1:0x1111111111111111111111111111111111111111".parse()?,
        "account".parse()?,
    )?;
    tinycloud_core::models::actor::ActiveModel {
        id: Set(account.did().to_string()),
    }
    .insert(&fixture.conn)
    .await?;
    let grant = fixture
        .grant_in(
            "tc2514-account",
            account.did().as_str(),
            &fixture.device_did(),
            &[(&account, "", "tinycloud.delegation/list")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;
    let header =
        fixture.device_invocation_in(&[(&account, "", "tinycloud.delegation/list")], &[grant])?;
    let request = || {
        fixture
            .client
            .post("/delegation/query")
            .header(Header::new("Authorization", header.clone()))
            .header(ContentType::JSON)
            .body(r#"{"direction":"received"}"#)
            .dispatch()
    };
    let healthy = request().await;
    let status = healthy.status();
    let body = healthy.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "{body}");

    // Close the pool so the authorization graph's first query fails, before
    // account discovery or page loading can run.
    fixture.conn.clone().close().await?;
    let response = request().await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::ServiceUnavailable, "{body}");
    assert!(body.starts_with(UNAVAILABLE_RETRYABLE), "{body}");
    Ok(())
}

/// The retry re-runs authorization against the current state: a parent
/// revoked while the first run was failing and the delay was running is
/// refused, not served from the first run's view.
#[tokio::test]
async fn a_parent_revoked_during_the_retry_wait_refuses_the_retried_invocation() -> Result<()> {
    let fixture = fixture().await?;
    let owner = fixture.space.did().to_string();
    let parent = fixture
        .grant(
            "tc2346-parent",
            &owner,
            &fixture.device_did(),
            &[("db", "tinycloud.sql/read")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;
    let invoke = || -> Result<String> {
        fixture.device_invocation_in(&[(&fixture.space, "db", "tinycloud.sql/read")], &[parent])
    };

    // Control: the chain authorizes the read.
    let control = fixture
        .invoke_json(invoke()?, &tc1791_query("SELECT 1"))
        .await?;
    assert_eq!(control.status, Status::Ok, "{}", control.body);

    let plan = Plan::new(2, lost);
    let query = tc1791_query("SELECT 1");
    let revoker = async {
        // Revoke as soon as the first failure is in: the two failures and the
        // delay before the retry (at least 100 ms) all still lie ahead.
        while plan.injected() < 1 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        fixture.revoke("tc2346-revoke-parent", parent).await
    };
    let (reply, revoked) =
        tokio::join!(plan.scope(fixture.invoke_json(invoke()?, &query)), revoker);
    revoked?;
    let reply = reply?;

    assert_eq!(plan.injected(), 2);
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    Ok(())
}

// ---- The operation and its error mapping ------------------------------

#[tokio::test]
async fn a_loss_after_the_delegation_transaction_began_is_not_retried_and_stays_outcome_unknown(
) -> Result<()> {
    let fixture = fixture().await?;
    let tinycloud = tinycloud(&fixture);
    let delegation = owner_delegation(&fixture, "tc2346-b")?;
    let attempts = AtomicUsize::new(0);

    let (result, applied) = track_writes_retrying(
        "delegate",
        None,
        || {
            attempts.fetch_add(1, Ordering::SeqCst);
            let delegation = delegation.clone();
            async move {
                // The transaction committed, then the connection was lost
                // before the reply: the delegation is stored.
                tinycloud.delegate(delegation).await?;
                Err::<TransactResult, Failure>(TxError::Db(lost()))
            }
        },
        tx_database_error,
    )
    .await;

    let error = result.unwrap_err();
    assert!(applied, "a read-write transaction began");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(stored_delegations(&fixture).await, 1);
    let (status, body) = delegation_failure(&error, applied);
    assert_eq!(status, Status::InternalServerError);
    assert!(body.starts_with(OUTCOME_UNKNOWN), "{body}");
    Ok(())
}

#[tokio::test]
async fn other_database_failures_are_not_retried() -> Result<()> {
    let failures: [fn() -> DbErr; 3] = [
        || DbErr::Conn(RuntimeErr::SqlxError(SqlxError::PoolTimedOut)),
        || DbErr::Custom("constraint".into()),
        || DbErr::Query(RuntimeErr::SqlxError(SqlxError::RowNotFound)),
    ];
    for failure in failures {
        let attempts = AtomicUsize::new(0);
        let (result, applied) = track_writes_retrying(
            "delegate",
            None,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async move { Err::<TransactResult, Failure>(TxError::Db(failure())) }
            },
            tx_database_error,
        )
        .await;
        assert!(result.is_err());
        assert!(!applied);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
    // A refusal that is not a database error is never retried either.
    let attempts = AtomicUsize::new(0);
    let (result, _) = track_writes_retrying(
        "delegate",
        None,
        || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err::<TransactResult, Failure>(TxError::SpaceNotFound) }
        },
        tx_database_error,
    )
    .await;
    assert!(matches!(result, Err(TxError::SpaceNotFound)));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    Ok(())
}

/// A mutating invocation that began its transaction and then lost its
/// connection may have been applied: `outcome_unknown`, not a safe `503`.
/// An authorization that wrote nothing stays a safe `503`.
#[tokio::test]
async fn an_authorization_failure_reports_the_trackers_verdict() {
    let error = TxStoreError::Tx(TxError::Db(lost()));

    let (status, body) = authorization_failure("server.sql.auth", &error, true);
    assert_eq!(status, Status::InternalServerError);
    assert!(body.starts_with(OUTCOME_UNKNOWN), "{body}");

    let (status, body) = authorization_failure("server.sql.auth", &error, false);
    assert_eq!(status, Status::ServiceUnavailable);
    assert!(body.starts_with(UNAVAILABLE_RETRYABLE), "{body}");
}

/// A mutating invocation (a `kv/del` beside the SQL read) reaches the same
/// authorization step. Its read-write transaction began and the connection
/// was then lost, so the delete may have applied: `outcome_unknown`, not a
/// retry and not a safe `503`. The mutating path retries a lost `BEGIN`
/// itself once, so the loss is injected twice.
#[tokio::test]
async fn a_mutating_invocation_that_lost_its_connection_after_begin_is_outcome_unknown(
) -> Result<()> {
    let fixture = fixture().await?;
    // The key the delete targets exists, so authorization reaches the
    // transaction instead of refusing a missing key.
    fixture.owner_write("notes/x", Some(b"value")).await?;
    let sql = fixture
        .resource_in(&fixture.space, "sql", "db")?
        .to_string();
    let kv = fixture.kv_resource("notes/x")?.to_string();
    let header =
        fixture.owner_invocation(&[(sql, "tinycloud.sql/read"), (kv, "tinycloud.kv/del")])?;
    let plan = Plan::new(0, lost).after_begin(2);

    let reply = plan
        .scope(fixture.invoke_json(header, &tc1791_query("SELECT 1")))
        .await?;

    assert_eq!(plan.injected(), 2, "the loss reached the transaction");
    assert_eq!(reply.status, Status::InternalServerError, "{}", reply.body);
    assert!(reply.body.starts_with(OUTCOME_UNKNOWN), "{}", reply.body);
    Ok(())
}
