//! Durable, privacy-safe protocol state for the N1 authority seam.
//!
//! The tables in this leaf are replay controls and opaque handles only.  The
//! `authority_session_cid` is an immutable reference to the #117 authority
//! record; this repository never treats it as an authorization decision.

use super::{
    invitation::{InvitationAuthorizationReceipt, InvitationError},
    types::Sha256Digest,
};
use crate::models::{
    share_anonymous_challenge, share_email_audit, share_email_quota, share_holder_read_jti,
    share_invitation_authorization_jti, share_policy_presentation_jti, share_session_handle,
};
use sea_orm::{
    sea_query::{Expr, OnConflict},
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait, QueryFilter,
    TransactionTrait,
};
use serde_json::Value;
use std::fmt;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

pub const MAX_REQUEST_BODY_BYTES: usize = 65_536;
pub const CHALLENGE_TTL: Duration = Duration::seconds(120);
pub const SESSION_TTL: Duration = Duration::seconds(300);
pub const READ_JTI_TTL: Duration = Duration::seconds(60);
pub const QUOTA_WINDOW: Duration = Duration::hours(24);
pub const ORIGIN_QUOTA: i64 = 120;
pub const IP_QUOTA: i64 = 240;
pub const SHARE_QUOTA: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    #[error("share-email state unavailable")]
    Storage,
    #[error("share-email request denied")]
    Invalid,
    #[error("share-email request body exceeds limit")]
    BodyTooLarge,
    #[error("share-email request quota exceeded")]
    QuotaExceeded,
    #[error("share-email state already used")]
    Replay,
    #[error("share-email state expired")]
    Expired,
}

impl From<DbErr> for StateError {
    fn from(_: DbErr) -> Self {
        Self::Storage
    }
}

impl From<InvitationError> for StateError {
    fn from(error: InvitationError) -> Self {
        match error {
            InvitationError::Expired => Self::Expired,
            InvitationError::BodyTooLarge => Self::BodyTooLarge,
            InvitationError::Invalid | InvitationError::Signature => Self::Invalid,
        }
    }
}

#[derive(Clone)]
pub struct ProtocolStateRepository {
    conn: DatabaseConnection,
}

impl ProtocolStateRepository {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { conn }
    }

    pub async fn reserve_invitation_authorization(
        &self,
        receipt: &InvitationAuthorizationReceipt,
        binding_json: Value,
        authorization_digest: &Sha256Digest,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        let issued_at = receipt.authorization.issued_at.clone();
        let expires_at = receipt.authorization.expires_at.clone();
        let jti = receipt.authorization.jti.as_str().to_owned();
        let model = share_invitation_authorization_jti::ActiveModel {
            jti: Set(jti.clone()),
            authorization_digest: Set(authorization_digest.as_str().to_owned()),
            binding_json: Set(binding_json.clone()),
            issued_at: Set(issued_at),
            expires_at: Set(expires_at),
            consumed_at: Set(None),
        };
        let tx = self.conn.begin().await?;
        let existed = share_invitation_authorization_jti::Entity::find_by_id(&jti)
            .one(&tx)
            .await?
            .is_some();
        share_invitation_authorization_jti::Entity::insert(model)
            .on_conflict(
                OnConflict::column(share_invitation_authorization_jti::Column::Jti)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&tx)
            .await?;
        if existed {
            let existing = share_invitation_authorization_jti::Entity::find_by_id(&jti)
                .one(&tx)
                .await?
                .ok_or(StateError::Storage)?;
            if existing.authorization_digest != authorization_digest.as_str()
                || existing.binding_json != binding_json
            {
                return Err(StateError::Replay);
            }
            if existing.consumed_at.is_some() {
                return Err(StateError::Replay);
            }
            if parse_timestamp(&existing.expires_at)? <= now {
                return Err(StateError::Expired);
            }
            tx.commit().await?;
            return Ok(());
        }
        let existing = share_invitation_authorization_jti::Entity::find_by_id(&jti)
            .one(&tx)
            .await?
            .ok_or(StateError::Storage)?;
        if existing.authorization_digest != authorization_digest.as_str()
            || existing.binding_json != binding_json
        {
            return Err(StateError::Replay);
        }
        if parse_timestamp(&receipt.authorization.expires_at)? <= now {
            return Err(StateError::Expired);
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn create_anonymous_challenge(
        &self,
        request: AnonymousChallengeRequest,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        if request.body_bytes > MAX_REQUEST_BODY_BYTES {
            return Err(StateError::BodyTooLarge);
        }
        if request.expires_at <= now || request.expires_at > now + CHALLENGE_TTL {
            return Err(StateError::Invalid);
        }
        let tx = self.conn.begin().await?;
        let challenge_id = request.challenge_id.clone();
        let existed = share_anonymous_challenge::Entity::find_by_id(&challenge_id)
            .one(&tx)
            .await?
            .is_some();
        share_anonymous_challenge::Entity::insert(share_anonymous_challenge::ActiveModel {
            challenge_id: Set(challenge_id.clone()),
            request_digest: Set(request.request_digest.clone()),
            binding_json: Set(request.binding_json.clone()),
            origin_digest: Set(request.origin_digest.clone()),
            ip_digest: Set(request.ip_digest.clone()),
            share_digest: Set(request.share_digest.clone()),
            nonce_hash: Set(request.nonce_hash.clone()),
            issued_at: Set(timestamp(request.issued_at)?),
            expires_at: Set(timestamp(request.expires_at)?),
            consumed_at: Set(None),
        })
        .on_conflict(
            OnConflict::column(share_anonymous_challenge::Column::ChallengeId)
                .do_nothing()
                .to_owned(),
        )
        .exec(&tx)
        .await?;
        if existed {
            let existing = share_anonymous_challenge::Entity::find_by_id(&challenge_id)
                .one(&tx)
                .await?
                .ok_or(StateError::Storage)?;
            if existing.request_digest != request.request_digest
                || existing.binding_json != request.binding_json
            {
                return Err(StateError::Replay);
            }
            tx.commit().await?;
            return Ok(());
        }
        let existing = share_anonymous_challenge::Entity::find_by_id(&challenge_id)
            .one(&tx)
            .await?
            .ok_or(StateError::Storage)?;
        if existing.request_digest != request.request_digest
            || existing.binding_json != request.binding_json
        {
            return Err(StateError::Replay);
        }
        for quota in request.quotas() {
            increment_quota(&tx, quota, now).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn consume_anonymous_challenge(
        &self,
        challenge_id: &str,
        request_digest: &str,
        binding_json: &Value,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        self.consume_anonymous_challenge_checked(
            challenge_id,
            request_digest,
            binding_json,
            None,
            now,
        )
        .await
    }

    /// Consume a challenge while also binding the one-time nonce returned in
    /// its response.  The legacy method above remains available to existing
    /// callers that do not carry the nonce at this boundary.
    pub async fn consume_anonymous_challenge_checked(
        &self,
        challenge_id: &str,
        request_digest: &str,
        binding_json: &Value,
        nonce_hash: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        let tx = self.conn.begin().await?;
        let row = share_anonymous_challenge::Entity::find_by_id(challenge_id)
            .one(&tx)
            .await?
            .ok_or(StateError::Replay)?;
        if row.request_digest != request_digest
            || row.binding_json != *binding_json
            || nonce_hash.is_some_and(|expected| row.nonce_hash != expected)
            || row.consumed_at.is_some()
            || parse_timestamp(&row.expires_at)? <= now
        {
            return Err(StateError::Replay);
        }
        let changed = share_anonymous_challenge::Entity::update_many()
            .col_expr(
                share_anonymous_challenge::Column::ConsumedAt,
                Expr::value(timestamp(now)?),
            )
            .filter(share_anonymous_challenge::Column::ChallengeId.eq(challenge_id))
            .filter(share_anonymous_challenge::Column::ConsumedAt.is_null())
            .exec(&tx)
            .await?;
        if changed.rows_affected != 1 {
            return Err(StateError::Replay);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Persists the opaque handle and the privacy-safe audit event in one
    /// transaction.  The authority CID is a reference to #117, never a
    /// grant, and callers must revalidate #117 before invoking this method.
    pub async fn commit_session(
        &self,
        session: SessionHandleMapping,
        audit: AuditEvent,
        now: OffsetDateTime,
    ) -> Result<SessionHandleMapping, StateError> {
        let tx = self.conn.begin().await?;
        let result = Self::commit_session_body(&tx, session, audit, now).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Transaction-scoped variant of [`Self::commit_session`] for callers
    /// (the #117 bridge) that must revalidate authority and persist this
    /// session's replay/audit effects in one shared transaction.
    pub(crate) async fn commit_session_in_transaction(
        tx: &DatabaseTransaction,
        session: SessionHandleMapping,
        audit: AuditEvent,
        now: OffsetDateTime,
    ) -> Result<SessionHandleMapping, StateError> {
        Self::commit_session_body(tx, session, audit, now).await
    }

    pub(crate) async fn consume_anonymous_challenge_in_transaction(
        tx: &DatabaseTransaction,
        challenge_id: &str,
        request_digest: &str,
        binding_json: &Value,
        nonce_hash: &str,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        let row = share_anonymous_challenge::Entity::find_by_id(challenge_id)
            .one(tx)
            .await?
            .ok_or(StateError::Replay)?;
        if row.request_digest != request_digest
            || row.binding_json != *binding_json
            || row.nonce_hash != nonce_hash
            || row.consumed_at.is_some()
            || parse_timestamp(&row.expires_at)? <= now
        {
            return Err(StateError::Replay);
        }
        let changed = share_anonymous_challenge::Entity::update_many()
            .col_expr(
                share_anonymous_challenge::Column::ConsumedAt,
                Expr::value(timestamp(now)?),
            )
            .filter(share_anonymous_challenge::Column::ChallengeId.eq(challenge_id))
            .filter(share_anonymous_challenge::Column::ConsumedAt.is_null())
            .exec(tx)
            .await?;
        if changed.rows_affected != 1 {
            return Err(StateError::Replay);
        }
        Ok(())
    }

    /// Consume a holder-binding JTI durably. The existing policy-session
    /// replay table is deliberately reused so admission replay is committed
    /// atomically with the authority root and opaque session.
    pub(crate) async fn consume_holder_binding_jti_in_transaction(
        tx: &DatabaseTransaction,
        jti: &str,
        policy_cid: &str,
        session_handle: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StateError> {
        if jti.is_empty() || expires_at <= issued_at {
            return Err(StateError::Invalid);
        }
        let replay_key = format!("holder-binding:{jti}");
        if share_policy_presentation_jti::Entity::find_by_id(&replay_key)
            .one(tx)
            .await?
            .is_some()
        {
            return Err(StateError::Replay);
        }
        share_policy_presentation_jti::ActiveModel {
            presentation_jti: Set(replay_key),
            nonce: Set(format!("holder-binding-nonce:{jti}")),
            policy_cid: Set(policy_cid.to_owned()),
            session_handle: Set(session_handle.to_owned()),
            issued_at: Set(timestamp(issued_at)?),
            expires_at: Set(timestamp(expires_at)?),
        }
        .insert(tx)
        .await
        .map_err(|_| StateError::Replay)?;
        Ok(())
    }

    async fn commit_session_body(
        tx: &DatabaseTransaction,
        session: SessionHandleMapping,
        audit: AuditEvent,
        now: OffsetDateTime,
    ) -> Result<SessionHandleMapping, StateError> {
        if session.expires_at <= now || session.expires_at > now + SESSION_TTL {
            return Err(StateError::Invalid);
        }
        if session.authority_session_cid.is_empty() {
            return Err(StateError::Invalid);
        }
        let existed = share_session_handle::Entity::find_by_id(&session.handle)
            .one(tx)
            .await?
            .is_some();
        share_session_handle::Entity::insert(share_session_handle::ActiveModel {
            session_handle: Set(session.handle.clone()),
            authority_session_cid: Set(session.authority_session_cid.clone()),
            binding_json: Set(session.binding_json.clone()),
            holder_digest: Set(session.holder_digest.clone()),
            issued_at: Set(timestamp(session.issued_at)?),
            expires_at: Set(timestamp(session.expires_at)?),
            revoked_at: Set(None),
        })
        .on_conflict(
            OnConflict::column(share_session_handle::Column::SessionHandle)
                .do_nothing()
                .to_owned(),
        )
        .exec(tx)
        .await?;
        if existed {
            let existing = share_session_handle::Entity::find_by_id(&session.handle)
                .one(tx)
                .await?
                .ok_or(StateError::Storage)?;
            if existing.authority_session_cid != session.authority_session_cid
                || existing.binding_json != session.binding_json
            {
                return Err(StateError::Replay);
            }
            return Ok(session);
        }
        let existing = share_session_handle::Entity::find_by_id(&session.handle)
            .one(tx)
            .await?
            .ok_or(StateError::Storage)?;
        if existing.authority_session_cid != session.authority_session_cid
            || existing.binding_json != session.binding_json
        {
            return Err(StateError::Replay);
        }
        share_email_audit::Entity::insert(share_email_audit::ActiveModel {
            audit_id: Set(audit.audit_id),
            event_kind: Set(audit.event_kind),
            outcome: Set(audit.outcome),
            share_digest: Set(audit.share_digest),
            origin_digest: Set(audit.origin_digest),
            holder_digest: Set(audit.holder_digest),
            request_digest: Set(audit.request_digest),
            created_at: Set(timestamp(now)?),
        })
        .on_conflict(
            OnConflict::column(share_email_audit::Column::AuditId)
                .do_nothing()
                .to_owned(),
        )
        .exec(tx)
        .await?;
        Ok(session)
    }

    /// Inserts and consumes a read JTI while rechecking the mapped session.
    /// A session handle alone is never sufficient for this operation.
    pub async fn consume_holder_read_jti(
        &self,
        read: HolderReadJti,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        let tx = self.conn.begin().await?;
        Self::consume_holder_read_jti_body(&tx, read, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Transaction-scoped variant of [`Self::consume_holder_read_jti`] for
    /// callers (the #117 bridge) that must revalidate authority and consume
    /// this read's JTI in one shared transaction.
    pub(crate) async fn consume_holder_read_jti_in_transaction(
        tx: &DatabaseTransaction,
        read: HolderReadJti,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        Self::consume_holder_read_jti_body(tx, read, now).await
    }

    async fn consume_holder_read_jti_body(
        tx: &DatabaseTransaction,
        read: HolderReadJti,
        now: OffsetDateTime,
    ) -> Result<(), StateError> {
        if read.expires_at <= now || read.expires_at > now + READ_JTI_TTL {
            return Err(StateError::Invalid);
        }
        let session = share_session_handle::Entity::find_by_id(&read.session_handle)
            .one(tx)
            .await?
            .ok_or(StateError::Replay)?;
        if session.revoked_at.is_some() || parse_timestamp(&session.expires_at)? <= now {
            return Err(StateError::Replay);
        }
        if share_holder_read_jti::Entity::find_by_id(&read.jti)
            .one(tx)
            .await?
            .is_some()
        {
            return Err(StateError::Replay);
        }
        share_holder_read_jti::ActiveModel {
            jti: Set(read.jti),
            session_handle: Set(read.session_handle),
            invocation_digest: Set(read.invocation_digest),
            binding_json: Set(read.binding_json),
            issued_at: Set(timestamp(read.issued_at)?),
            expires_at: Set(timestamp(read.expires_at)?),
            consumed_at: Set(Some(timestamp(now)?)),
        }
        .insert(tx)
        .await
        .map_err(|_| StateError::Replay)?;
        Ok(())
    }

    pub async fn cleanup(&self, now: OffsetDateTime) -> Result<(), StateError> {
        let tx = self.conn.begin().await?;
        let now = timestamp(now)?;
        share_invitation_authorization_jti::Entity::delete_many()
            .filter(share_invitation_authorization_jti::Column::ExpiresAt.lt(&now))
            .exec(&tx)
            .await?;
        share_anonymous_challenge::Entity::delete_many()
            .filter(share_anonymous_challenge::Column::ExpiresAt.lt(&now))
            .exec(&tx)
            .await?;
        share_holder_read_jti::Entity::delete_many()
            .filter(share_holder_read_jti::Column::ExpiresAt.lt(&now))
            .exec(&tx)
            .await?;
        share_session_handle::Entity::delete_many()
            .filter(share_session_handle::Column::ExpiresAt.lt(&now))
            .exec(&tx)
            .await?;
        share_email_quota::Entity::delete_many()
            .filter(share_email_quota::Column::ExpiresAt.lt(&now))
            .exec(&tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AnonymousChallengeRequest {
    pub challenge_id: String,
    pub request_digest: String,
    pub binding_json: Value,
    pub origin_digest: String,
    pub ip_digest: String,
    pub share_digest: String,
    pub nonce_hash: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub body_bytes: usize,
    pub origin_limit: i64,
    pub ip_limit: i64,
    pub share_limit: i64,
}

impl AnonymousChallengeRequest {
    fn quotas(&self) -> [QuotaUse; 3] {
        [
            QuotaUse::new("origin", &self.origin_digest, self.origin_limit),
            QuotaUse::new("ip", &self.ip_digest, self.ip_limit),
            QuotaUse::new("share", &self.share_digest, self.share_limit),
        ]
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionHandleMapping {
    pub handle: String,
    pub authority_session_cid: String,
    pub binding_json: Value,
    pub holder_digest: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HolderReadJti {
    pub jti: String,
    pub session_handle: String,
    pub invocation_digest: String,
    pub binding_json: Value,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub audit_id: String,
    pub event_kind: String,
    pub outcome: String,
    pub share_digest: String,
    pub origin_digest: String,
    pub holder_digest: Option<String>,
    pub request_digest: String,
}

impl fmt::Debug for AnonymousChallengeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AnonymousChallengeRequest { [REDACTED] }")
    }
}

impl fmt::Debug for SessionHandleMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHandleMapping { [REDACTED] }")
    }
}

impl fmt::Debug for HolderReadJti {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HolderReadJti { [REDACTED] }")
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditEvent { [REDACTED] }")
    }
}

#[derive(Clone)]
struct QuotaUse {
    kind: &'static str,
    scope_digest: String,
    limit: i64,
}

impl QuotaUse {
    fn new(kind: &'static str, scope_digest: &str, limit: i64) -> Self {
        Self {
            kind,
            scope_digest: scope_digest.to_owned(),
            limit,
        }
    }
}

async fn increment_quota(
    tx: &DatabaseTransaction,
    quota: QuotaUse,
    now: OffsetDateTime,
) -> Result<(), StateError> {
    if quota.scope_digest.is_empty() || quota.limit <= 0 {
        return Err(StateError::Invalid);
    }
    let bucket_seconds = QUOTA_WINDOW.whole_seconds();
    let bucket_start = OffsetDateTime::from_unix_timestamp(
        now.unix_timestamp().div_euclid(bucket_seconds) * bucket_seconds,
    )
    .map_err(|_| StateError::Invalid)?;
    let bucket_start = timestamp(bucket_start)?;
    let expires_at = timestamp(
        OffsetDateTime::parse(&bucket_start, &Rfc3339).map_err(|_| StateError::Invalid)?
            + QUOTA_WINDOW,
    )?;
    let model = share_email_quota::ActiveModel {
        bucket_kind: Set(quota.kind.to_owned()),
        bucket_start: Set(bucket_start.clone()),
        scope_digest: Set(quota.scope_digest.clone()),
        uses: Set(1),
        expires_at: Set(expires_at),
    };
    share_email_quota::Entity::insert(model)
        .on_conflict(
            OnConflict::columns([
                share_email_quota::Column::BucketKind,
                share_email_quota::Column::BucketStart,
                share_email_quota::Column::ScopeDigest,
            ])
            .value(
                share_email_quota::Column::Uses,
                Expr::col(share_email_quota::Column::Uses).add(1),
            )
            .to_owned(),
        )
        .exec(tx)
        .await?;
    let row = share_email_quota::Entity::find_by_id((
        quota.kind.to_owned(),
        bucket_start,
        quota.scope_digest,
    ))
    .one(tx)
    .await?
    .ok_or(StateError::Storage)?;
    if row.uses > quota.limit {
        return Err(StateError::QuotaExceeded);
    }
    Ok(())
}

pub(crate) fn timestamp(value: OffsetDateTime) -> Result<String, StateError> {
    value.format(&Rfc3339).map_err(|_| StateError::Invalid)
}

pub(crate) fn parse_timestamp(value: &str) -> Result<OffsetDateTime, StateError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| StateError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    #[test]
    fn public_state_debug_does_not_contain_bindings() {
        let binding = SessionHandleMapping {
            handle: "opaque-handle".to_owned(),
            authority_session_cid: "authority-cid".to_owned(),
            binding_json: serde_json::json!({"email":"alice@example.com","ip":"198.51.100.4"}),
            holder_digest: "holder-digest".to_owned(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + SESSION_TTL,
        };
        let debug = format!("{binding:?}");
        assert!(!debug.contains("alice@example.com"));
        assert!(!debug.contains("198.51.100.4"));
    }

    #[test]
    fn limits_are_five_minute_session_and_bounded_body() {
        assert_eq!(SESSION_TTL, Duration::seconds(300));
        assert_eq!(MAX_REQUEST_BODY_BYTES, 65_536);
    }

    #[tokio::test]
    async fn holder_binding_jti_is_durable_and_single_use() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::minutes(5);

        let tx = db.begin().await.unwrap();
        ProtocolStateRepository::consume_holder_binding_jti_in_transaction(
            &tx,
            "holder-jti",
            "policy-cid",
            "session-one",
            now,
            expires_at,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let tx = db.begin().await.unwrap();
        assert_eq!(
            ProtocolStateRepository::consume_holder_binding_jti_in_transaction(
                &tx,
                "holder-jti",
                "policy-cid",
                "session-two",
                now,
                expires_at,
            )
            .await,
            Err(StateError::Replay)
        );
        tx.rollback().await.unwrap();
    }
}
