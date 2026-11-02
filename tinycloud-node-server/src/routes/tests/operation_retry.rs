//! TC-2346: `/delegate` and the `/invoke` authorization step run their whole
//! operation once more after a connection lost before any write, and never
//! otherwise. The operations are the real ones (`SpaceDatabase::delegate`,
//! `invoke_admitted`) on SQLite; the lost connection is injected as the
//! failure of an attempt, since SQLite has no connection to lose.

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
    events::{Delegation, TinyCloudInvocation},
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

/// An owner-signed delegation of `kv/get` to the fixture's device.
fn owner_delegation(fixture: &KvSyncFixture, nonce: &str) -> Result<Delegation> {
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
    let header = TinyCloudDelegation::Ucan(Box::new(ucan)).encode()?;
    Ok(Delegation::from_header_ser::<TinyCloudDelegation>(&header)?)
}

async fn stored_delegations(fixture: &KvSyncFixture) -> u64 {
    delegation_model::Entity::find()
        .count(&fixture.conn)
        .await
        .unwrap()
}

/// The route's own mapping of a failed delegation.
fn answered(error: &Failure, write_may_have_applied: bool) -> (Status, String) {
    match error {
        TxError::Db(db) | TxError::EpochInsert(db) => database_failure(
            tinycloud_core::failure_diagnostic::Service::Other,
            db,
            write_may_have_applied,
            error.to_string(),
        ),
        _ => panic!("not a database failure: {error}"),
    }
}

#[tokio::test]
async fn a_delegation_that_lost_its_connection_before_any_write_is_stored_once_by_the_retry(
) -> Result<()> {
    let fixture = fixture().await?;
    let tinycloud = tinycloud(&fixture);
    let delegation = owner_delegation(&fixture, "tc2346-a")?;
    let attempts = AtomicUsize::new(0);

    let (result, _) = track_writes_retrying(
        "delegate",
        || {
            let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let delegation = delegation.clone();
            async move {
                if first {
                    // The lookup before the transaction found its connection dead.
                    return Err(TxError::Db(lost()));
                }
                tinycloud.delegate(delegation).await
            }
        },
        tx_database_error,
    )
    .await;

    let result = result.map_err(|error| anyhow::anyhow!("{error}"))?;
    assert!(!result.delegation_cids.is_empty());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(stored_delegations(&fixture).await, 1);
    Ok(())
}

#[tokio::test]
async fn a_loss_after_the_delegation_transaction_began_is_not_retried_and_stays_outcome_unknown(
) -> Result<()> {
    let fixture = fixture().await?;
    let tinycloud = tinycloud(&fixture);
    let delegation = owner_delegation(&fixture, "tc2346-b")?;
    let attempts = AtomicUsize::new(0);

    let (result, applied) = track_writes_retrying(
        "delegate",
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
    let (status, body) = answered(&error, applied);
    assert_eq!(status, Status::InternalServerError);
    assert!(body.starts_with(OUTCOME_UNKNOWN), "{body}");
    Ok(())
}

#[tokio::test]
async fn a_loss_on_the_retry_too_answers_the_safe_503_without_a_third_attempt() -> Result<()> {
    let fixture = fixture().await?;
    let attempts = AtomicUsize::new(0);

    let (result, applied) = track_writes_retrying(
        "delegate",
        || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err::<TransactResult, Failure>(TxError::Db(lost())) }
        },
        tx_database_error,
    )
    .await;

    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(!applied);
    let (status, body) = answered(&result.unwrap_err(), applied);
    assert_eq!(status, Status::ServiceUnavailable);
    assert!(body.starts_with(UNAVAILABLE_RETRYABLE), "{body}");
    assert_eq!(stored_delegations(&fixture).await, 0);
    Ok(())
}

#[tokio::test]
async fn io_and_other_database_failures_are_not_retried() -> Result<()> {
    use std::io;
    let failures: [fn() -> DbErr; 3] = [
        || {
            DbErr::Query(RuntimeErr::SqlxError(SqlxError::Io(io::Error::from(
                io::ErrorKind::ConnectionReset,
            ))))
        },
        || DbErr::Conn(RuntimeErr::SqlxError(SqlxError::PoolTimedOut)),
        || DbErr::Custom("constraint".into()),
    ];
    for failure in failures {
        let attempts = AtomicUsize::new(0);
        let (result, applied) = track_writes_retrying(
            "delegate",
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

#[tokio::test]
async fn an_authorization_that_lost_its_connection_before_any_write_runs_again_once() -> Result<()>
{
    use tinycloud_core::models::invocation as invocation_model;

    let fixture = fixture().await?;
    let tinycloud = tinycloud(&fixture);
    let (header, _) = tc409_root_invocation(
        &fixture.owner,
        &fixture.owner_vm,
        "kv",
        "tinycloud.kv/get",
        Some("probe"),
        "urn:uuid:tc2346-invoke",
    )?;
    let admitted = AdmittedInvocation::admit(
        Invocation::from_header_ser::<TinyCloudInvocation>(&header)?,
        3_600,
    )
    .await?;
    let attempts = AtomicUsize::new(0);

    let (result, _) = track_writes_retrying(
        "authorize_invocation",
        || {
            let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let admitted = admitted.clone();
            async move {
                if first {
                    return Err(TxStoreError::Tx(TxError::Db(lost())));
                }
                tinycloud
                    .invoke_admitted::<BlockStage>(admitted, HashMap::new())
                    .await
            }
        },
        |error| match error {
            TxStoreError::Tx(error) => tx_database_error(error),
            _ => None,
        },
    )
    .await;

    assert!(
        result.is_ok(),
        "{:?}",
        result.err().map(|error| error.to_string())
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let recorded = invocation_model::Entity::find()
        .count(&fixture.conn)
        .await
        .unwrap();
    assert_eq!(recorded, 1, "the invocation was recorded once");
    Ok(())
}
