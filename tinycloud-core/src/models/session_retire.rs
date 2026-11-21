//! TC-3443: session keys their holders signed out ("retired").
//!
//! A row names a `did:key` session key (bare DID, no fragment) and when it
//! was retired. While the row is live (`expires_at > now`) the key invokes
//! nothing, and a delegation it issues is refused unless it was stored
//! before the retire. Expired rows are ignored by every lookup and pruned.
use crate::did_resolution::verify_ucan_signature;
use crate::encryption_network::delete_auth::CLOCK_SKEW_SECS;
use sea_orm::{
    entity::prelude::*,
    sea_query::{Alias, Expr, OnConflict, Query, UpdateStatement},
    ActiveValue::Set,
    ConnectionTrait, QuerySelect,
};
use time::{Duration, OffsetDateTime};
use tinycloud_auth::{authorization::TinyCloudInvocation, identity::principal_did};

/// The only resource a retire request names: the signing session itself.
pub const RETIRE_RESOURCE: &str = "urn:tinycloud:session:self";
/// The only ability a retire request carries.
pub const RETIRE_ABILITY: &str = "tinycloud.session/retire";
/// A retire request expires at most this many seconds after `now`.
pub const MAX_RETIRE_LIFETIME_SECS: i64 = 120;

/// A `POST /session/retire` credential the node refuses.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("session_retire_invalid: {0}")]
pub struct RetireRequestError(&'static str);

/// Verify a retire request's `Authorization` header (a UCAN JWT, with or
/// without `Bearer `) and return the bare `did:key` it retires. The UCAN is
/// self-issued by the session key to this node: `aud` is `node_did`, `att` is
/// exactly [`RETIRE_ABILITY`] on [`RETIRE_RESOURCE`], `prf` is empty, a nonce
/// is present, it has not expired, it expires within
/// [`MAX_RETIRE_LIFETIME_SECS`], and `nbf` is not later than `now` plus the
/// owner-delete clock skew. The nonce is not tracked: a replay retires the
/// same key again, which changes nothing. `now` is unix seconds.
pub async fn verify_retire_request(
    authorization: &str,
    node_did: &str,
    now: i64,
) -> Result<String, RetireRequestError> {
    let token = authorization
        .strip_prefix("Bearer ")
        .unwrap_or(authorization)
        .trim();
    let ucan = TinyCloudInvocation::decode(token)
        .map_err(|_| RetireRequestError("authorization is not a UCAN"))?;
    let payload = ucan.payload();
    let did = principal_did(payload.issuer.as_str())
        .map_err(|_| RetireRequestError("the issuer is not a DID"))?;
    if !is_retirable(&did) {
        return Err(RetireRequestError(
            "the issuer is not a did:key session key",
        ));
    }
    verify_ucan_signature(&ucan)
        .await
        .map_err(|_| RetireRequestError("the signature is invalid"))?;
    if payload.audience.as_str() != node_did {
        return Err(RetireRequestError("the audience is not this node"));
    }
    if !payload.proof.is_empty() {
        return Err(RetireRequestError("the request cites proofs"));
    }
    let expected = serde_json::json!({ RETIRE_RESOURCE: { RETIRE_ABILITY: [{}] } });
    if serde_json::to_value(&payload.attenuation).ok() != Some(expected) {
        return Err(RetireRequestError(
            "the capability is not exactly tinycloud.session/retire on urn:tinycloud:session:self",
        ));
    }
    if payload.nonce.as_deref().is_none_or(str::is_empty) {
        return Err(RetireRequestError("the nonce is missing"));
    }
    let now = now as f64;
    let exp = payload.expiration.as_seconds();
    if exp <= now {
        return Err(RetireRequestError("the request has expired"));
    }
    if exp > now + MAX_RETIRE_LIFETIME_SECS as f64 {
        return Err(RetireRequestError(
            "the request expires more than 120 seconds from now",
        ));
    }
    if payload
        .not_before
        .is_some_and(|nbf| nbf.as_seconds() > now + CLOCK_SKEW_SECS as f64)
    {
        return Err(RetireRequestError("the request is not yet valid"));
    }
    Ok(did)
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_retire")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub did: String,
    pub retired_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Only a `did:key` can be retired.
pub fn is_retirable(did: &str) -> bool {
    did.starts_with("did:key:")
}

/// The node's clock at the microsecond precision both database backends
/// store, so a stored time reads back exactly as written. Used for retire
/// times and for `delegation.first_seen_at`, which are compared.
pub fn stored_now() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(now.nanosecond() / 1_000 * 1_000)
        .unwrap_or(now)
}

/// What a retire row's `expires_at` must reach to outlast a delegation the
/// key holds: its expiry, rounded up to the stored microsecond, or
/// [`never_expires`] when it has none.
pub fn covering(expiry: Option<OffsetDateTime>) -> OffsetDateTime {
    let Some(expiry) = expiry else {
        return never_expires();
    };
    let expiry = expiry.to_offset(time::UtcOffset::UTC);
    let truncated = expiry
        .replace_nanosecond(expiry.nanosecond() / 1_000 * 1_000)
        .unwrap_or(expiry);
    if truncated < expiry {
        truncated + Duration::microseconds(1)
    } else {
        truncated
    }
}

/// The far-future `expires_at` of a retire covering a delegation without an
/// expiry: 9999-12-31T23:59:59Z, which both database backends store exactly.
pub fn never_expires() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(253_402_300_799).expect("in range")
}

/// The latest time anything stored can still grant `did` authority: the
/// latest expiry of a delegation it holds (a NULL expiry never ends), or of
/// a renewal stamp extending one. `None` when it holds nothing.
async fn latest_authority_end<C: ConnectionTrait>(
    db: &C,
    did: &str,
) -> Result<Option<OffsetDateTime>, DbErr> {
    let expiries: Vec<Option<OffsetDateTime>> = delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Expiry)
        .filter(delegation::Column::Delegatee.eq(did))
        .into_tuple()
        .all(db)
        .await?;
    let mut latest = expiries.into_iter().map(covering).max();
    let stamp = Alias::new("renewal_stamp");
    let stamped = Query::select()
        .column((stamp.clone(), Alias::new("new_end")))
        .from(stamp.clone())
        .inner_join(
            delegation_cid_alias::Entity,
            Expr::col((
                delegation_cid_alias::Entity,
                delegation_cid_alias::Column::Canonical,
            ))
            .equals((stamp, Alias::new("original_canonical"))),
        )
        .inner_join(
            delegation::Entity,
            Expr::col((delegation::Entity, delegation::Column::Id)).equals((
                delegation_cid_alias::Entity,
                delegation_cid_alias::Column::Id,
            )),
        )
        .and_where(Expr::col((delegation::Entity, delegation::Column::Delegatee)).eq(did))
        .to_owned();
    for row in db
        .query_all(db.get_database_backend().build(&stamped))
        .await?
    {
        let end: OffsetDateTime = row.try_get("", "new_end")?;
        latest = latest.max(Some(covering(Some(end))));
    }
    Ok(latest)
}

/// Raise a live retire row for `did` to `until`; never lowers it. A single
/// statement, so `delegation::save` can run it inside its own insert.
pub fn raise_expiry_statement(
    did: &str,
    until: OffsetDateTime,
    now: OffsetDateTime,
) -> UpdateStatement {
    Query::update()
        .table(Entity)
        .value(Column::ExpiresAt, until)
        .and_where(Column::Did.eq(did))
        .and_where(Column::ExpiresAt.gt(now))
        .and_where(Column::ExpiresAt.lt(until))
        .to_owned()
}

/// Run [`raise_expiry_statement`].
pub async fn raise_expiry<C: ConnectionTrait>(
    db: &C,
    did: &str,
    until: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), DbErr> {
    db.execute(
        db.get_database_backend()
            .build(&raise_expiry_statement(did, until, now)),
    )
    .await
    .map(drop)
}

/// Retire `did` at `now` and return its retire time. The row lasts at least
/// `ttl`, and until the latest-expiring delegation (or renewal stamp) that
/// grants `did` authority ends, so no stored grant outlives it. A key already
/// retired keeps, and returns, its first retire time; its expiry is raised
/// to cover what it holds now, never lowered. Expired rows are deleted first.
pub async fn retire<C: ConnectionTrait>(
    db: &C,
    did: &str,
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<OffsetDateTime, DbErr> {
    prune_expired(db, now).await?;
    let base = now.saturating_add(ttl);
    let expires_at = latest_authority_end(db, did)
        .await?
        .map_or(base, |end| end.max(base));
    Entity::insert(ActiveModel {
        did: Set(did.to_owned()),
        retired_at: Set(now),
        expires_at: Set(expires_at),
    })
    .on_conflict(OnConflict::column(Column::Did).do_nothing().to_owned())
    .exec_without_returning(db)
    .await?;
    raise_expiry(db, did, expires_at, now).await?;
    Entity::find_by_id(did.to_owned())
        .one(db)
        .await?
        .map(|row| row.retired_at)
        .ok_or_else(|| DbErr::RecordNotFound(format!("session_retire row for {did}")))
}

/// Delete every row that expired at or before `now`.
pub async fn prune_expired<C: ConnectionTrait>(db: &C, now: OffsetDateTime) -> Result<u64, DbErr> {
    Entity::delete_many()
        .filter(Column::ExpiresAt.lte(now))
        .exec(db)
        .await
        .map(|result| result.rows_affected)
}

/// When `did` was retired, if a row for it is live at `now`. A DID that is
/// not a `did:key` is never retired and costs no query.
pub async fn live_retired_at<C: ConnectionTrait>(
    db: &C,
    did: &str,
    now: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, DbErr> {
    if !is_retirable(did) {
        return Ok(None);
    }
    Ok(Entity::find_by_id(did.to_owned())
        .one(db)
        .await?
        .filter(|row| row.expires_at > now)
        .map(|row| row.retired_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn repeat_retire_keeps_the_first_time_and_expired_rows_are_ignored_and_pruned() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let did = "did:key:z6MkretireRepeat";
        let first = stored_now();
        let ttl = Duration::days(30);
        assert_eq!(retire(&db, did, first, ttl).await.unwrap(), first);
        let later = first + Duration::minutes(5);
        assert_eq!(retire(&db, did, later, ttl).await.unwrap(), first);
        assert_eq!(live_retired_at(&db, did, later).await.unwrap(), Some(first));

        // A repeat keeps the retire time but raises the expiry to its own
        // `now + ttl`. At and after expiry the row no longer counts, and the
        // next retire call prunes it before recording a new one.
        let expiry = later + ttl;
        assert_eq!(
            live_retired_at(&db, did, expiry - Duration::SECOND)
                .await
                .unwrap(),
            Some(first)
        );
        assert_eq!(live_retired_at(&db, did, expiry).await.unwrap(), None);
        let other = "did:key:z6MkretireOther";
        retire(&db, other, expiry, ttl).await.unwrap();
        assert!(Entity::find_by_id(did.to_owned())
            .one(&db)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            live_retired_at(&db, other, expiry).await.unwrap(),
            Some(expiry)
        );
        // Only a did:key is looked up.
        assert_eq!(
            live_retired_at(&db, "did:pkh:eip155:1:0xabc", expiry)
                .await
                .unwrap(),
            None
        );
    }

    mod request {
        use super::super::*;
        use tinycloud_auth::{
            resolver::DID_METHODS,
            ssi::{
                claims::jwt::NumericDate,
                jwk::{Algorithm, JWK},
                ucan::Payload,
            },
            ucan_capabilities_object::Capabilities,
        };

        const NODE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        const NOW: i64 = 1_800_000_000;

        fn retire_payload(key: &JWK) -> Payload<serde_json::Value> {
            let did = DID_METHODS.generate(key, "key").unwrap().to_string();
            let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
            let mut caps = Capabilities::<serde_json::Value>::new();
            caps.with_action(
                RETIRE_RESOURCE.parse().unwrap(),
                RETIRE_ABILITY.parse().unwrap(),
                [std::collections::BTreeMap::new()],
            );
            Payload {
                issuer: vm.parse().unwrap(),
                audience: NODE.parse().unwrap(),
                not_before: Some(NumericDate::try_from_seconds((NOW - 1) as f64).unwrap()),
                expiration: NumericDate::try_from_seconds((NOW + 60) as f64).unwrap(),
                nonce: Some("retire-nonce".into()),
                facts: None,
                proof: vec![],
                attenuation: caps,
            }
        }

        fn sign(payload: Payload<serde_json::Value>, key: &JWK) -> String {
            payload
                .sign(Algorithm::EdDSA, key)
                .unwrap()
                .encode()
                .unwrap()
        }

        async fn reason(token: &str) -> String {
            verify_retire_request(token, NODE, NOW)
                .await
                .unwrap_err()
                .to_string()
        }

        #[tokio::test]
        async fn a_self_issued_retire_ucan_names_its_bare_did_key() {
            let key = JWK::generate_ed25519().unwrap();
            let did = DID_METHODS.generate(&key, "key").unwrap().to_string();
            let token = sign(retire_payload(&key), &key);
            assert_eq!(verify_retire_request(&token, NODE, NOW).await.unwrap(), did);
            assert_eq!(
                verify_retire_request(&format!("Bearer {token}"), NODE, NOW)
                    .await
                    .unwrap(),
                did
            );
        }

        #[tokio::test]
        async fn malformed_retire_ucans_are_refused_with_their_reason() {
            let key = JWK::generate_ed25519().unwrap();
            let other = JWK::generate_ed25519().unwrap();

            let mut wrong_audience = retire_payload(&key);
            wrong_audience.audience = "did:key:z6MkwrongAudience".parse().unwrap();
            let mut too_long = retire_payload(&key);
            too_long.expiration =
                NumericDate::try_from_seconds((NOW + MAX_RETIRE_LIFETIME_SECS + 1) as f64).unwrap();
            let mut expired = retire_payload(&key);
            expired.expiration = NumericDate::try_from_seconds((NOW - 1) as f64).unwrap();
            let mut early = retire_payload(&key);
            early.not_before =
                Some(NumericDate::try_from_seconds((NOW + CLOCK_SKEW_SECS + 5) as f64).unwrap());
            let mut wrong_att = retire_payload(&key);
            wrong_att.attenuation = Capabilities::new();
            wrong_att.attenuation.with_action(
                RETIRE_RESOURCE.parse().unwrap(),
                "tinycloud.kv/get".parse().unwrap(),
                [std::collections::BTreeMap::new()],
            );
            let mut extra_att = retire_payload(&key);
            extra_att.attenuation.with_action(
                "urn:tinycloud:session:other".parse().unwrap(),
                RETIRE_ABILITY.parse().unwrap(),
                [std::collections::BTreeMap::new()],
            );
            let mut proofs = retire_payload(&key);
            proofs.proof = vec![crate::hash::hash(b"proof").to_cid(0x55)];
            let mut no_nonce = retire_payload(&key);
            no_nonce.nonce = None;
            let mut not_did_key = retire_payload(&key);
            not_did_key.issuer = "did:web:example.com#key-1".parse().unwrap();

            for (token, expected) in [
                ("not a jwt".to_owned(), "authorization is not a UCAN"),
                (
                    sign(retire_payload(&key), &other),
                    "the signature is invalid",
                ),
                (sign(wrong_audience, &key), "the audience is not this node"),
                (sign(too_long, &key), "more than 120 seconds"),
                (sign(expired, &key), "the request has expired"),
                (sign(early, &key), "the request is not yet valid"),
                (sign(wrong_att, &key), "the capability is not exactly"),
                (sign(extra_att, &key), "the capability is not exactly"),
                (sign(proofs, &key), "the request cites proofs"),
                (sign(no_nonce, &key), "the nonce is missing"),
                (sign(not_did_key, &key), "not a did:key session key"),
            ] {
                let reason = reason(&token).await;
                assert!(
                    reason.starts_with("session_retire_invalid: ") && reason.contains(expected),
                    "{expected}: {reason}"
                );
            }
        }
    }
}
