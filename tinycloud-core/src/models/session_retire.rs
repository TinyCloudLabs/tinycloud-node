//! TC-3443: session keys their holders signed out ("retired").
//!
//! A row names a `did:key` session key (bare DID, no fragment) and when it
//! was retired. While the row is live (`expires_at > now`) the key invokes
//! nothing, and a delegation it issues is refused unless it was stored
//! before the retire. Expired rows are ignored by every lookup and pruned.
use crate::did_resolution::verify_ucan_signature;
use crate::encryption_network::delete_auth::CLOCK_SKEW_SECS;
use sea_orm::{entity::prelude::*, sea_query::OnConflict, ActiveValue::Set, ConnectionTrait};
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

/// Retire `did` at `now` until `now + ttl`, and return its retire time. A
/// key already retired keeps, and returns, its first retire time. Expired
/// rows are deleted first.
pub async fn retire<C: ConnectionTrait>(
    db: &C,
    did: &str,
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<OffsetDateTime, DbErr> {
    prune_expired(db, now).await?;
    Entity::insert(ActiveModel {
        did: Set(did.to_owned()),
        retired_at: Set(now),
        expires_at: Set(now.saturating_add(ttl)),
    })
    .on_conflict(OnConflict::column(Column::Did).do_nothing().to_owned())
    .exec_without_returning(db)
    .await?;
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

        // At and after expiry the row no longer counts, and the next retire
        // call prunes it before recording a new one.
        let expiry = first + ttl;
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
