#[cfg(test)]
#[path = "renewal/registration_tests.rs"]
mod registration_tests;

use crate::hash::Hash;
use crate::keys::StaticSecret;
use sea_orm::sea_query::Value;
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement, TransactionTrait};
use std::str::FromStr;
use time::OffsetDateTime;
use tinycloud_auth::ipld_core::cid::Cid;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

pub const STAMP_DOMAIN: &str = "tinycloud/node/renewal-stamp/v1";
pub const RENEWER_KEY_CONTEXT: &[u8] = b"tinycloud/node/renewer/v1";
const MAX_LEASE_SECONDS: i64 = 365 * 24 * 60 * 60;
const MAX_PERIOD_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalFormat {
    Ucan,
    Cacao,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RenewalError {
    #[error("renewal period has no valid signed anchor")]
    MissingAnchor,
    #[error("renewal period is not a positive finite duration within ten years")]
    InvalidPeriod,
    #[error("renewal end timestamp overflowed")]
    TimestampOverflow,
    #[error("renewal stamp end exceeds a signed validity bound")]
    StampEndOutOfBounds,
    #[error("renewal stamp signature is invalid for the lease audience")]
    InvalidSignature,
}

#[derive(Debug, thiserror::Error)]
pub enum RenewalStoreError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error(transparent)]
    Invalid(#[from] RenewalError),
    #[error("renewal lease not found or inactive")]
    LeaseUnavailable,
    #[error("renewal request replayed")]
    Replay,
    #[error("renewal lease is revoked")]
    Revoked,
    #[error("renewal identity epoch changed")]
    IdentityEpoch,
    #[error("renewal operation is not authorized")]
    Unauthorized,
    #[error("renewal input is invalid")]
    InvalidInput,
}

/// Stamp issue request identity; signed content and bounds are computed in core.
#[derive(Clone, Debug)]
pub struct StampIssue {
    pub invocation: crate::util::InvocationInfo,
    pub original_cid: String,
    pub lease_cid: String,
    pub replay_hash: Hash,
    pub replay_expires_at: i64,
}

/// The node identity persisted during startup and held constant for this
/// process lifetime. Request paths reuse this snapshot instead of querying
/// the identity row on every authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewalNodeIdentity {
    pub stable_node_did: String,
    pub renewer_did: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRecord {
    pub original_cid: String,
    pub lease_cid: String,
    pub grantor: String,
    pub renewer_did: String,
    pub renewer_epoch: u64,
    pub lease_expiry: i64,
    pub period_seconds: u64,
    pub state: String,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StampRecord {
    pub cid: String,
    pub lease_cid: String,
    pub new_end: i64,
    pub previous_stamp_cid: String,
    pub generation: u64,
    pub signed_bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn period_seconds(
    expiry: i64,
    not_before: Option<i64>,
    issued_at: Option<i64>,
    format: OriginalFormat,
) -> Result<i64, RenewalError> {
    let anchor = match (not_before, format, issued_at) {
        (Some(not_before), _, _) => not_before,
        (None, OriginalFormat::Cacao, Some(issued_at)) => issued_at,
        _ => return Err(RenewalError::MissingAnchor),
    };
    expiry
        .checked_sub(anchor)
        .filter(|period| *period > 0 && *period <= MAX_PERIOD_SECONDS)
        .ok_or(RenewalError::InvalidPeriod)
}

pub fn new_end(
    now: i64,
    period: i64,
    lease_expiry: i64,
    ancestor_ends: &[i64],
) -> Result<i64, RenewalError> {
    if period <= 0 {
        return Err(RenewalError::InvalidPeriod);
    }
    let period_end = now
        .checked_add(period)
        .ok_or(RenewalError::TimestampOverflow)?;
    Ok(ancestor_ends
        .iter()
        .copied()
        .fold(period_end.min(lease_expiry), i64::min))
}

pub fn validate_stamp_end(
    stamp_end: i64,
    verifier_now: i64,
    period: i64,
    lease_expiry: i64,
    ancestor_ends: &[i64],
) -> Result<(), RenewalError> {
    let latest = verifier_now
        .checked_add(period)
        .ok_or(RenewalError::TimestampOverflow)?;
    if stamp_end <= 0
        || period <= 0
        || stamp_end > lease_expiry
        || stamp_end > latest
        || ancestor_ends.iter().any(|end| stamp_end > *end)
    {
        return Err(RenewalError::StampEndOutOfBounds);
    }
    Ok(())
}

pub fn verify_stamp_signature(
    signed_bytes: &[u8],
    signature_bytes: &[u8],
    lease_audience_public_key: &[u8; 32],
) -> Result<(), RenewalError> {
    let key = VerifyingKey::from_bytes(lease_audience_public_key)
        .map_err(|_| RenewalError::InvalidSignature)?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| RenewalError::InvalidSignature)?;
    key.verify(signed_bytes, &signature)
        .map_err(|_| RenewalError::InvalidSignature)
}
pub(crate) struct SnapshotStampVerification<'a> {
    pub(crate) signed_bytes: &'a [u8],
    pub(crate) signature_bytes: &'a [u8],
    pub(crate) expected_stamp_cid: &'a str,
    pub(crate) expected_original_cid: &'a str,
    pub(crate) expected_lease_cid: &'a str,
    pub(crate) generation: u64,
    pub(crate) previous_stamp_cid: &'a str,
    pub(crate) new_end: i64,
    pub(crate) node_did: &'a str,
    pub(crate) renewer_epoch: u64,
    pub(crate) audience_public_key: &'a [u8; 32],
    pub(crate) verifier_now: i64,
    pub(crate) period: i64,
    pub(crate) lease_expiry: i64,
    pub(crate) ancestor_ends: &'a [i64],
}

/// Verify the frozen signed stamp representation against its registered chain.
pub(crate) fn verify_snapshot_stamp(
    input: SnapshotStampVerification<'_>,
) -> Result<(), RenewalStoreError> {
    let SnapshotStampVerification {
        signed_bytes,
        signature_bytes,
        expected_stamp_cid,
        expected_original_cid,
        expected_lease_cid,
        generation,
        previous_stamp_cid,
        new_end,
        node_did,
        renewer_epoch,
        audience_public_key,
        verifier_now,
        period,
        lease_expiry,
        ancestor_ends,
    } = input;
    verify_stamp_signature(signed_bytes, signature_bytes, audience_public_key)?;
    let signed: CanonicalRenewalStamp<'_> = serde_ipld_dagcbor::from_slice(signed_bytes)
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    if serde_ipld_dagcbor::to_vec(&signed).map_err(|_| RenewalStoreError::InvalidInput)?
        != signed_bytes
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    let unsigned = &signed.unsigned;
    let (expected_stamp_cid, _) = canonical_cid(expected_stamp_cid)?;
    let (expected_original_cid, _) = canonical_cid(expected_original_cid)?;
    let (expected_lease_cid, _) = canonical_cid(expected_lease_cid)?;
    let (previous_stamp_cid, _) = canonical_cid(previous_stamp_cid)?;
    let end_string = unix_time(new_end)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    if signed.domain != STAMP_DOMAIN
        || unsigned.stamp_type != "TinyCloudRenewalStamp"
        || unsigned.version != 1
        || unsigned.original_cid != expected_original_cid
        || unsigned.lease_cid != expected_lease_cid
        || unsigned.lease_generation != generation
        || unsigned.previous_stamp_cid != previous_stamp_cid
        || unsigned.node_did != node_did
        || unsigned.renewer_epoch != renewer_epoch
        || unsigned.new_end != end_string
        || crate::hash::hash(signed_bytes).to_cid(0x55).to_string() != expected_stamp_cid
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    validate_stamp_end(new_end, verifier_now, period, lease_expiry, ancestor_ends)?;
    Ok(())
}

// This declaration order is the frozen canonical DAG-CBOR key order.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRenewalStamp<'a> {
    #[serde(borrow)]
    domain: &'a str,
    unsigned: CanonicalRenewalStampUnsigned<'a>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalRenewalStampUnsigned<'a> {
    #[serde(rename = "type", borrow)]
    stamp_type: &'a str,
    #[serde(borrow)]
    new_end: &'a str,
    #[serde(borrow)]
    node_did: &'a str,
    version: u64,
    #[serde(borrow)]
    lease_cid: &'a str,
    #[serde(borrow)]
    original_cid: &'a str,
    renewer_epoch: u64,
    lease_generation: u64,
    #[serde(borrow)]
    previous_stamp_cid: &'a str,
}

pub struct RenewalSigner {
    key: SigningKey,
    pub node_did: String,
    pub renewer_epoch: u64,
}

impl RenewalSigner {
    pub fn from_seed(seed: [u8; 32], node_did: String, renewer_epoch: u64) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            node_did,
            renewer_epoch,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Serialize the frozen v1 map and sign exactly those canonical bytes.
    pub fn sign_stamp(
        &self,
        original_cid: &str,
        lease_cid: &str,
        lease_generation: u64,
        previous_stamp_cid: &str,
        new_end: &str,
    ) -> Result<
        (Vec<u8>, Vec<u8>, String),
        serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>,
    > {
        let signed = CanonicalRenewalStamp {
            domain: STAMP_DOMAIN,
            unsigned: CanonicalRenewalStampUnsigned {
                stamp_type: "TinyCloudRenewalStamp",
                new_end,
                node_did: &self.node_did,
                version: 1,
                lease_cid,
                original_cid,
                renewer_epoch: self.renewer_epoch,
                lease_generation,
                previous_stamp_cid,
            },
        };
        let bytes = serde_ipld_dagcbor::to_vec(&signed)?;
        let signature = self.key.sign(&bytes).to_bytes().to_vec();
        let cid = crate::hash::hash(&bytes).to_cid(0x55).to_string();
        Ok((bytes, signature, cid))
    }
}

/// Return the dedicated node renewer DID, initial epoch, and raw public key.
pub fn renewal_identity(secret: &StaticSecret) -> (String, u64, [u8; 32]) {
    renewal_identity_at_epoch(secret, 1)
}

pub fn renewal_identity_at_epoch(secret: &StaticSecret, epoch: u64) -> (String, u64, [u8; 32]) {
    renewal_identity_from_seed_at_epoch(secret.derive_key(RENEWER_KEY_CONTEXT), epoch)
}

pub fn renewal_identity_from_seed(seed: [u8; 32]) -> (String, u64, [u8; 32]) {
    renewal_identity_from_seed_at_epoch(seed, 1)
}

pub fn renewal_identity_from_seed_at_epoch(seed: [u8; 32], epoch: u64) -> (String, u64, [u8; 32]) {
    let signer = SigningKey::from_bytes(&seed);
    let bytes = signer.verifying_key().to_bytes();
    let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(&bytes)
        .expect("32-byte Ed25519 public key");
    let did = crate::keys::public_key_to_did_key(public.into());
    (did, epoch, bytes)
}

pub fn is_renewer_did(secret: &StaticSecret, did: &str) -> bool {
    renewal_identity(secret).0 == did
}

pub fn is_renewal_capability(ability: &str, resource: &str, original_cid: &str) -> bool {
    ability == "tinycloud.delegation/renew"
        && resource == format!("urn:cid:{original_cid}")
        && canonical_cid(original_cid).is_ok()
}
/// Persist and return the current renewer identity during node startup.
pub async fn initialize_renewal_identity<C: TransactionTrait + ConnectionTrait>(
    conn: &C,
    seed: [u8; 32],
) -> Result<(String, u64, [u8; 32]), RenewalStoreError> {
    let (current_did, _, public_key) = renewal_identity_from_seed(seed);
    let tx = crate::db::begin_write_transaction(conn, None).await?;
    let backend = tx.get_database_backend();
    tx.execute_unprepared(
        "INSERT INTO renewal_identity (id, renewer_did, epoch) VALUES (1, NULL, 0) ON CONFLICT (id) DO NOTHING",
    )
    .await?;
    let query = match backend {
        DatabaseBackend::Postgres => {
            "SELECT renewer_did, epoch FROM renewal_identity WHERE id = 1 FOR UPDATE"
        }
        DatabaseBackend::Sqlite => "SELECT renewer_did, epoch FROM renewal_identity WHERE id = 1",
        DatabaseBackend::MySql => return Err(RenewalStoreError::InvalidInput),
    };
    let row = tx
        .query_one(Statement::from_string(backend, query))
        .await?
        .ok_or(RenewalStoreError::InvalidInput)?;
    let previous_did: Option<String> = row.try_get("", "renewer_did")?;
    let previous_epoch: i64 = row.try_get("", "epoch")?;
    let epoch = match previous_did.as_deref() {
        None if previous_epoch == 0 => 1,
        Some(previous) if previous == current_did && previous_epoch > 0 => previous_epoch as u64,
        Some(_) if previous_epoch > 0 && previous_epoch < i64::MAX => previous_epoch as u64 + 1,
        _ => return Err(RenewalStoreError::InvalidInput),
    };
    if previous_did.as_deref() != Some(current_did.as_str()) {
        tx.execute(Statement::from_sql_and_values(
            backend,
            "UPDATE renewal_identity SET renewer_did = $1, epoch = $2 WHERE id = 1",
            [
                Value::String(Some(Box::new(current_did.clone()))),
                Value::BigInt(Some(epoch as i64)),
            ],
        ))
        .await?;
    }
    tx.commit().await?;
    Ok((current_did, epoch, public_key))
}

pub async fn current_renewal_identity<C: ConnectionTrait>(
    db: &C,
    secret: &StaticSecret,
) -> Result<(String, u64, [u8; 32]), RenewalStoreError> {
    current_renewal_identity_from_seed(db, secret.derive_key(RENEWER_KEY_CONTEXT)).await
}

pub async fn current_renewal_identity_from_seed<C: ConnectionTrait>(
    db: &C,
    seed: [u8; 32],
) -> Result<(String, u64, [u8; 32]), RenewalStoreError> {
    let backend = db.get_database_backend();
    let query = match backend {
        DatabaseBackend::Postgres => {
            "SELECT renewer_did, epoch FROM renewal_identity WHERE id = 1 FOR SHARE"
        }
        DatabaseBackend::Sqlite => "SELECT renewer_did, epoch FROM renewal_identity WHERE id = 1",
        DatabaseBackend::MySql => return Err(RenewalStoreError::InvalidInput),
    };
    let row = db
        .query_one(Statement::from_string(backend, query))
        .await?
        .ok_or(RenewalStoreError::IdentityEpoch)?;
    let stored_did: Option<String> = row.try_get("", "renewer_did")?;
    let epoch: i64 = row.try_get("", "epoch")?;
    let (derived_did, _, public_key) = renewal_identity_from_seed(seed);
    if stored_did.as_deref() != Some(derived_did.as_str()) || epoch <= 0 {
        return Err(RenewalStoreError::IdentityEpoch);
    }
    Ok((derived_did, epoch as u64, public_key))
}

pub async fn lease_for_original<C: ConnectionTrait>(
    db: &C,
    original_cid: &str,
    identity: &RenewalNodeIdentity,
) -> Result<Option<LeaseRecord>, RenewalStoreError> {
    lease_for_original_at(
        db,
        original_cid,
        OffsetDateTime::now_utc().unix_timestamp(),
        identity,
    )
    .await
}

async fn lease_for_original_at<C: ConnectionTrait>(
    db: &C,
    original_cid: &str,
    verifier_now: i64,
    identity: &RenewalNodeIdentity,
) -> Result<Option<LeaseRecord>, RenewalStoreError> {
    let (original_cid, original) = canonical_cid(original_cid)?;
    if is_revoked_chain(db, &original).await? {
        return Ok(None);
    }
    let now = db_datetime(verifier_now)?;
    let epoch = i64::try_from(identity.epoch).map_err(|_| RenewalStoreError::InvalidInput)?;
    let rows = db
        .query_all(Statement::from_sql_and_values(
            db.get_database_backend(),
            "SELECT lease_cid, grantor, renewer_did, renewer_epoch, lease_expiry, period_seconds, state, generation FROM renewal_lease WHERE original_canonical = $1 AND state = 'active' AND lease_expiry > $2 AND renewer_did = $3 AND renewer_epoch = $4 ORDER BY lease_cid",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                Value::TimeDateTime(Some(Box::new(now))),
                Value::String(Some(Box::new(identity.renewer_did.clone()))),
                Value::BigInt(Some(epoch)),
            ],
        ))
        .await?;
    let mut selected = None;
    for row in rows {
        let lease_bytes: Vec<u8> = row.try_get("", "lease_cid")?;
        let lease = Hash::try_from(lease_bytes).map_err(DbErr::from)?;
        if is_revoked_chain(db, &lease).await? {
            continue;
        }
        if selected.is_some() {
            return Err(RenewalStoreError::InvalidInput);
        }
        let expiry: OffsetDateTime = row.try_get("", "lease_expiry")?;
        selected = Some(LeaseRecord {
            original_cid: original_cid.clone(),
            lease_cid: lease.to_cid(0x55).to_string(),
            grantor: row.try_get("", "grantor")?,
            renewer_did: row.try_get("", "renewer_did")?,
            renewer_epoch: row.try_get::<i64>("", "renewer_epoch")? as u64,
            lease_expiry: expiry.unix_timestamp(),
            period_seconds: row.try_get::<i64>("", "period_seconds")? as u64,
            state: row.try_get("", "state")?,
            generation: row.try_get::<i64>("", "generation")? as u64,
        });
    }
    Ok(selected)
}
/// Lists active leases for the identity captured during node startup.
pub async fn active_leases_for_current_epoch<C: ConnectionTrait>(
    db: &C,
    identity: &RenewalNodeIdentity,
) -> Result<Vec<LeaseRecord>, RenewalStoreError> {
    let backend = db.get_database_backend();
    let verifier_now = OffsetDateTime::now_utc().unix_timestamp();
    let now = db_datetime(verifier_now)?;
    let epoch = i64::try_from(identity.epoch).map_err(|_| RenewalStoreError::InvalidInput)?;
    let rows = db
        .query_all(Statement::from_sql_and_values(
            backend,
            "SELECT DISTINCT original_canonical FROM renewal_lease WHERE state = 'active' AND lease_expiry > $1 AND renewer_did = $2 AND renewer_epoch = $3 ORDER BY original_canonical",
            [
                Value::TimeDateTime(Some(Box::new(now))),
                Value::String(Some(Box::new(identity.renewer_did.clone()))),
                Value::BigInt(Some(epoch)),
            ],
        ))
        .await?;
    let mut leases = Vec::with_capacity(rows.len());
    for row in rows {
        let bytes: Vec<u8> = row.try_get("", "original_canonical")?;
        let original = Hash::try_from(bytes).map_err(DbErr::from)?;
        let original_cid = original.to_cid(0x55).to_string();
        if let Some(lease) =
            lease_for_original_at(db, &original_cid, verifier_now, identity).await?
        {
            leases.push(lease);
        }
    }
    Ok(leases)
}

pub async fn authorize_renewal_invocation<C: ConnectionTrait>(
    db: &C,
    invocation: &crate::util::InvocationInfo,
    original_cid: &str,
    identity: &RenewalNodeIdentity,
) -> Result<(), RenewalStoreError> {
    authorize_renewal_invocation_at(
        db,
        invocation,
        original_cid,
        identity,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
}

async fn authorize_renewal_invocation_at<C: ConnectionTrait>(
    db: &C,
    invocation: &crate::util::InvocationInfo,
    original_cid: &str,
    identity: &RenewalNodeIdentity,
    verifier_now: i64,
) -> Result<(), RenewalStoreError> {
    use crate::models::revocation::{ControlAction, ControlProofDecision};
    if invocation.capabilities.len() != 1
        || !invocation.capabilities[0].caveats.0.is_empty()
        || !is_renewal_capability(
            invocation.capabilities[0].ability.as_ref().as_ref(),
            &invocation.capabilities[0].resource.to_string(),
            original_cid,
        )
    {
        return Err(RenewalStoreError::Unauthorized);
    }
    let lease = lease_for_original_at(db, original_cid, verifier_now, identity)
        .await?
        .ok_or(RenewalStoreError::LeaseUnavailable)?;
    if invocation.invoker != lease.renewer_did {
        return Err(RenewalStoreError::Unauthorized);
    }
    let lease_parent =
        Cid::from_str(&lease.lease_cid).map_err(|_| RenewalStoreError::InvalidInput)?;
    if invocation.parents.as_slice() != [lease_parent] {
        return Err(RenewalStoreError::Unauthorized);
    }
    let (_, target) = canonical_cid(original_cid)?;
    if is_revoked_chain(db, &target).await? {
        return Err(RenewalStoreError::Revoked);
    }
    let original = crate::models::revocation::target_for_cid(db, target)
        .await?
        .ok_or(RenewalStoreError::Unauthorized)?;

    match crate::models::revocation::control_proof_decision_at(
        db,
        &invocation.invoker,
        &invocation.parents,
        ControlAction::Renew,
        &target,
        unix_time(verifier_now)?,
    )
    .await?
    {
        ControlProofDecision::Scoped(control)
            if control.directly_authorizes_cid(&target, &original) =>
        {
            Ok(())
        }
        _ => Err(RenewalStoreError::Unauthorized),
    }
}

fn canonical_cid(value: &str) -> Result<(String, Hash), RenewalStoreError> {
    let cid = Cid::from_str(value).map_err(|_| RenewalStoreError::InvalidInput)?;
    let canonical = cid.to_string();
    if canonical != value {
        return Err(RenewalStoreError::InvalidInput);
    }
    Ok((canonical, Hash::from(cid)))
}

fn cid_hash_bytes(value: &str) -> Result<Vec<u8>, RenewalStoreError> {
    Ok(Vec::<u8>::from(canonical_cid(value)?.1))
}

fn unix_time(value: i64) -> Result<OffsetDateTime, RenewalStoreError> {
    OffsetDateTime::from_unix_timestamp(value).map_err(|_| RenewalStoreError::InvalidInput)
}

fn db_datetime(value: i64) -> Result<time::PrimitiveDateTime, RenewalStoreError> {
    let timestamp = unix_time(value)?.to_offset(time::UtcOffset::UTC);
    Ok(timestamp.date().with_time(timestamp.time()))
}

pub(crate) fn lease_original_from_signed(
    lease: &crate::events::Delegation,
) -> Result<Option<String>, RenewalStoreError> {
    let info = signed_delegation_info(lease.serialized_bytes())?;
    let renew_capabilities = info
        .capabilities
        .iter()
        .filter(|capability| capability.ability.as_ref().as_ref() == "tinycloud.delegation/renew")
        .collect::<Vec<_>>();
    if renew_capabilities.is_empty() {
        return Ok(None);
    }
    if info.capabilities.len() != 1
        || renew_capabilities.len() != 1
        || !renew_capabilities[0].caveats.0.is_empty()
    {
        return Err(RenewalStoreError::Unauthorized);
    }
    let resource = renew_capabilities[0].resource.to_string();
    let original_cid = resource
        .strip_prefix("urn:cid:")
        .ok_or(RenewalStoreError::Unauthorized)?;
    if !is_renewal_capability(
        renew_capabilities[0].ability.as_ref().as_ref(),
        &resource,
        original_cid,
    ) {
        return Err(RenewalStoreError::Unauthorized);
    }
    Ok(Some(original_cid.to_owned()))
}

fn signed_delegation_info(bytes: &[u8]) -> Result<crate::util::DelegationInfo, RenewalStoreError> {
    let signed = tinycloud_auth::authorization::TinyCloudDelegation::from_bytes(bytes)
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    crate::util::DelegationInfo::try_from(signed).map_err(|_| RenewalStoreError::InvalidInput)
}

async fn verify_signed_signature(
    info: &crate::util::DelegationInfo,
) -> Result<(), RenewalStoreError> {
    match &info.delegation {
        tinycloud_auth::authorization::TinyCloudDelegation::Ucan(ucan) => {
            crate::did_resolution::verify_ucan_signature(ucan)
                .await
                .map_err(|_| RenewalStoreError::InvalidInput)?;
        }
        tinycloud_auth::authorization::TinyCloudDelegation::Cacao(cacao) => {
            cacao
                .verify()
                .await
                .map_err(|_| RenewalStoreError::InvalidInput)?;
        }
    }
    Ok(())
}

async fn load_renewal_snapshot<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
    stable_node_did: &str,
    renewer_did: &str,
    renewer_epoch: u64,
    verifier_now: i64,
) -> Result<crate::auth_graph::AuthGraphSnapshot, RenewalStoreError> {
    crate::auth_graph::AuthGraphSnapshot::load_with_renewal_identity(
        db,
        roots,
        stable_node_did,
        renewer_did,
        renewer_epoch,
        verifier_now,
    )
    .await
    .map_err(|error| match error {
        crate::auth_graph::ChainTraversalError::Db(error) => RenewalStoreError::Db(error),
        crate::auth_graph::ChainTraversalError::LimitExceeded => {
            RenewalStoreError::LeaseUnavailable
        }
    })
}

fn live_chain_effective_ends(
    snapshot: &crate::auth_graph::AuthGraphSnapshot,
    root: &Hash,
    now: i64,
) -> Result<Vec<(Hash, i64)>, RenewalStoreError> {
    if snapshot.is_revoked(root) || snapshot.first_revoked_ancestor(root).is_some() {
        return Err(RenewalStoreError::Revoked);
    }
    let chain = snapshot.chain_ids_from(root);
    if chain.is_empty() {
        return Err(RenewalStoreError::LeaseUnavailable);
    }
    let mut ends = Vec::with_capacity(chain.len());
    for id in chain {
        let delegation = snapshot
            .delegation(&id)
            .ok_or(RenewalStoreError::LeaseUnavailable)?;
        if delegation
            .not_before
            .is_some_and(|start| start.unix_timestamp() > now)
        {
            return Err(RenewalStoreError::LeaseUnavailable);
        }
        let end = snapshot
            .effective_expiry(&id)
            .ok_or(RenewalStoreError::LeaseUnavailable)?;
        if end <= now {
            return Err(RenewalStoreError::LeaseUnavailable);
        }
        ends.push((id, end));
    }
    Ok(ends)
}

pub(crate) async fn register_lease<C: ConnectionTrait>(
    tx: &C,
    lease_event: &crate::events::Delegation,
    renewal_seed: [u8; 32],
    renewer_epoch: u64,
    stable_node_did: &str,
    encryption: Option<&crate::encryption::ColumnEncryption>,
) -> Result<(), RenewalStoreError> {
    register_lease_at(
        tx,
        lease_event,
        renewal_seed,
        renewer_epoch,
        stable_node_did,
        encryption,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
}

async fn register_lease_at<C: ConnectionTrait>(
    tx: &C,
    lease_event: &crate::events::Delegation,
    renewal_seed: [u8; 32],
    renewer_epoch: u64,
    stable_node_did: &str,
    encryption: Option<&crate::encryption::ColumnEncryption>,
    now: i64,
) -> Result<(), RenewalStoreError> {
    let lease_bytes = lease_event.serialized_bytes();
    let lease = signed_delegation_info(lease_bytes)?;
    verify_signed_signature(&lease).await?;
    let original_cid =
        lease_original_from_signed(lease_event)?.ok_or(RenewalStoreError::Unauthorized)?;
    let (original_cid, original) = canonical_cid(&original_cid)?;
    let lease_hash = crate::hash::hash(lease_bytes);

    let lease = &lease;

    let original_row = tx.query_one(Statement::from_sql_and_values(
        tx.get_database_backend(),
        "SELECT serialization, serialization_format, delegator, delegatee, expiry FROM delegation WHERE id = $1",
        [Value::Bytes(Some(Box::new(Vec::<u8>::from(original))))],
    )).await?.ok_or(RenewalStoreError::InvalidInput)?;
    let stored_bytes: Vec<u8> = original_row.try_get("", "serialization")?;
    let stored_format: i16 = original_row.try_get("", "serialization_format")?;
    let original_id_bytes = Vec::<u8>::from(original);
    let original_bytes = crate::encryption::maybe_decrypt(
        encryption,
        &stored_bytes,
        crate::encryption::RowBinding::new("delegation", "serialization", &[&original_id_bytes]),
        stored_format,
    )
    .map_err(|_| RenewalStoreError::InvalidInput)?;
    if crate::hash::hash(&original_bytes) != original {
        return Err(RenewalStoreError::InvalidInput);
    }
    let original_info = signed_delegation_info(&original_bytes)?;
    verify_signed_signature(&original_info).await?;
    let graph_delegator: String = original_row.try_get("", "delegator")?;
    let graph_delegatee: String = original_row.try_get("", "delegatee")?;
    let graph_expiry: Option<OffsetDateTime> = original_row.try_get("", "expiry")?;
    if graph_delegator != original_info.delegator
        || graph_delegatee != original_info.delegate
        || graph_expiry != original_info.expiry
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    let original_expiry = original_info
        .expiry
        .ok_or(RenewalStoreError::InvalidInput)?;
    let period = period_seconds(
        original_expiry.unix_timestamp(),
        original_info.not_before.map(|value| value.unix_timestamp()),
        original_info.issued_at.map(|value| value.unix_timestamp()),
        match original_info.delegation {
            tinycloud_auth::authorization::TinyCloudDelegation::Ucan(_) => OriginalFormat::Ucan,
            tinycloud_auth::authorization::TinyCloudDelegation::Cacao(_) => OriginalFormat::Cacao,
        },
    )?;
    let lease_expiry = lease.expiry.ok_or(RenewalStoreError::InvalidInput)?;
    let lease_format = match &lease.delegation {
        tinycloud_auth::authorization::TinyCloudDelegation::Ucan(_) => OriginalFormat::Ucan,
        tinycloud_auth::authorization::TinyCloudDelegation::Cacao(_) => OriginalFormat::Cacao,
    };
    let lease_not_before = match (lease.not_before, lease_format, lease.issued_at) {
        (Some(not_before), _, _) => not_before,
        (None, OriginalFormat::Cacao, Some(issued_at)) => issued_at,
        _ => return Err(RenewalStoreError::InvalidInput),
    };
    let lease_duration = lease_expiry
        .unix_timestamp()
        .checked_sub(lease_not_before.unix_timestamp())
        .ok_or(RenewalStoreError::InvalidInput)?;
    if period <= 0
        || period > MAX_PERIOD_SECONDS
        || lease_not_before.unix_timestamp() <= 0
        || lease_duration <= 0
        || lease_duration > MAX_LEASE_SECONDS
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    let (renewer_did, _, audience_public_key) =
        renewal_identity_from_seed_at_epoch(renewal_seed, renewer_epoch);
    if lease.delegator != original_info.delegator || lease.delegate != renewer_did {
        return Err(RenewalStoreError::Unauthorized);
    }
    lock_original(tx, &original).await?;

    let lease_horizon = now
        .checked_add(MAX_LEASE_SECONDS)
        .ok_or(RenewalStoreError::InvalidInput)?;
    if lease_expiry.unix_timestamp() > lease_horizon
        || lease_not_before.unix_timestamp() > now
        || lease_expiry.unix_timestamp() <= now
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    let backend = tx.get_database_backend();
    let graph_rows = tx
        .query_one(Statement::from_sql_and_values(
            backend,
            "SELECT delegator, delegatee, expiry FROM delegation WHERE id = $1",
            [Value::Bytes(Some(Box::new(Vec::<u8>::from(lease_hash))))],
        ))
        .await?
        .ok_or(RenewalStoreError::InvalidInput)?;
    let graph_delegator: String = graph_rows.try_get("", "delegator")?;
    let graph_delegatee: String = graph_rows.try_get("", "delegatee")?;
    let graph_expiry: Option<OffsetDateTime> = graph_rows.try_get("", "expiry")?;
    if graph_delegator != lease.delegator
        || graph_delegatee != lease.delegate
        || graph_expiry != lease.expiry
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    let lease_abilities = tx
        .query_all(Statement::from_sql_and_values(
            backend,
            "SELECT ability, resource, caveats FROM ability WHERE delegation = $1",
            [Value::Bytes(Some(Box::new(Vec::<u8>::from(lease_hash))))],
        ))
        .await?;
    if lease_abilities.len() != 1
        || !is_renewal_capability(
            lease_abilities[0]
                .try_get::<String>("", "ability")?
                .as_str(),
            lease_abilities[0]
                .try_get::<String>("", "resource")?
                .as_str(),
            &original_cid,
        )
        || !lease_abilities[0]
            .try_get::<crate::types::Caveats>("", "caveats")?
            .0
            .is_empty()
    {
        return Err(RenewalStoreError::Unauthorized);
    }
    let existing = tx.query_one(Statement::from_sql_and_values(
        backend,
        "SELECT grantor, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key FROM renewal_lease WHERE original_canonical = $1 AND lease_cid = $2",
        [
            Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(lease_hash)))),
        ],
    )).await?;
    if let Some(row) = existing {
        // Renewal metadata is stored at whole-second precision.
        let same = row.try_get::<String>("", "grantor")? == lease.delegator
            && row.try_get::<String>("", "renewer_did")? == renewer_did
            && row.try_get::<i64>("", "renewer_epoch")? == renewer_epoch as i64
            && row
                .try_get::<OffsetDateTime>("", "lease_expiry")?
                .unix_timestamp()
                == lease_expiry.unix_timestamp()
            && row
                .try_get::<OffsetDateTime>("", "original_expiry")?
                .unix_timestamp()
                == original_expiry.unix_timestamp()
            && row.try_get::<i64>("", "period_seconds")? == period
            && row.try_get::<Vec<u8>>("", "audience_public_key")? == audience_public_key;
        return if same {
            Ok(())
        } else {
            Err(RenewalStoreError::InvalidInput)
        };
    }

    let snapshot = load_renewal_snapshot(
        tx,
        &[original, lease_hash],
        stable_node_did,
        &renewer_did,
        renewer_epoch,
        now,
    )
    .await?;
    live_chain_effective_ends(&snapshot, &original, now)?;
    live_chain_effective_ends(&snapshot, &lease_hash, now)?;
    let old_leases = tx
        .query_all(Statement::from_sql_and_values(
            backend,
            "SELECT lease_cid, lease_expiry, state FROM renewal_lease WHERE original_canonical = $1 AND renewer_epoch = $2",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                Value::BigInt(Some(renewer_epoch as i64)),
            ],
        ))
        .await?;
    for old in old_leases {
        let old_bytes: Vec<u8> = old.try_get("", "lease_cid")?;
        let old_id = Hash::try_from(old_bytes).map_err(DbErr::from)?;
        let old_state: String = old.try_get("", "state")?;
        if old_state == "revoked" || is_revoked_chain(tx, &old_id).await? {
            continue;
        }
        let old_expiry: OffsetDateTime = old.try_get("", "lease_expiry")?;
        if old_expiry.unix_timestamp() <= now {
            if old_state == "active" {
                tx.execute(Statement::from_sql_and_values(
                    backend,
                    "UPDATE renewal_lease SET state = 'expired' WHERE original_canonical = $1 AND lease_cid = $2",
                    [
                        Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                        Value::Bytes(Some(Box::new(Vec::<u8>::from(old_id)))),
                    ],
                )).await?;
            }
        } else if old_state == "active" {
            return Err(RenewalStoreError::LeaseUnavailable);
        } else if old_state != "expired" {
            return Err(RenewalStoreError::InvalidInput);
        }
    }
    tx.execute(Statement::from_sql_and_values(
        backend,
        "INSERT INTO renewal_lease (original_canonical, lease_cid, state, generation, grantor, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key) VALUES ($1, $2, 'active', 1, $3, $4, $5, $6, $7, $8, $9)",
        [
            Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(lease_hash)))),
            Value::String(Some(Box::new(lease.delegator.clone()))),
            Value::String(Some(Box::new(renewer_did))),
            Value::BigInt(Some(renewer_epoch as i64)),
            Value::TimeDateTime(Some(Box::new(db_datetime(lease_expiry.unix_timestamp())?))),
            Value::TimeDateTime(Some(Box::new(db_datetime(original_expiry.unix_timestamp())?))),
            Value::BigInt(Some(period)),
            Value::Bytes(Some(Box::new(audience_public_key.to_vec()))),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn issue_stamp<C: TransactionTrait + ConnectionTrait>(
    conn: &C,
    request: StampIssue,
    secret: &StaticSecret,
    identity: &RenewalNodeIdentity,
) -> Result<StampRecord, RenewalStoreError> {
    issue_stamp_at(
        conn,
        request,
        secret,
        identity,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
}

async fn issue_stamp_at<C: TransactionTrait + ConnectionTrait>(
    conn: &C,
    request: StampIssue,
    secret: &StaticSecret,
    identity: &RenewalNodeIdentity,
    now: i64,
) -> Result<StampRecord, RenewalStoreError> {
    let (_, original) = canonical_cid(&request.original_cid)?;
    let tx = crate::db::begin_write_transaction(conn, None).await?;
    let result = async {
        lock_original(&tx, &original).await?;
        if request.replay_expires_at <= now {
            return Err(RenewalStoreError::InvalidInput);
        }
        if let Err(error) = tx
            .execute(Statement::from_sql_and_values(
                tx.get_database_backend(),
                "INSERT INTO invocation_replay (content_hash, expires_at) VALUES ($1, $2)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(request.replay_hash)))),
                    Value::TimeDateTime(Some(Box::new(db_datetime(request.replay_expires_at)?))),
                ],
            ))
            .await
        {
            if is_unique_violation(&error) {
                return Err(RenewalStoreError::Replay);
            }
            return Err(error.into());
        }
        authorize_renewal_invocation_at(
            &tx,
            &request.invocation,
            &request.original_cid,
            identity,
            now,
        )
        .await?;
        issue_stamp_in_transaction(&tx, request, secret, identity, now).await
    }
    .await;
    match result {
        Ok(record) => {
            tx.commit().await?;
            Ok(record)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

async fn issue_stamp_in_transaction<C: ConnectionTrait>(
    tx: &C,
    request: StampIssue,
    secret: &StaticSecret,
    identity: &RenewalNodeIdentity,
    now: i64,
) -> Result<StampRecord, RenewalStoreError> {
    let (original_cid, original) = canonical_cid(&request.original_cid)?;
    let (lease_cid, lease) = canonical_cid(&request.lease_cid)?;
    let (stored_renewer_did, stored_epoch, _) =
        current_renewal_identity_from_seed(tx, secret.derive_key(RENEWER_KEY_CONTEXT)).await?;
    if stored_renewer_did != identity.renewer_did || stored_epoch != identity.epoch {
        return Err(RenewalStoreError::IdentityEpoch);
    }
    let backend = tx.get_database_backend();
    let lease_row = tx.query_one(Statement::from_sql_and_values(
        backend,
        "SELECT state, generation, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key FROM renewal_lease WHERE original_canonical = $1 AND lease_cid = $2",
        [
            Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
        ],
    )).await?.ok_or(RenewalStoreError::LeaseUnavailable)?;
    let state: String = lease_row.try_get("", "state")?;
    let generation: i64 = lease_row.try_get("", "generation")?;
    if generation <= 0 {
        return Err(RenewalStoreError::InvalidInput);
    }
    let renewer_did: String = lease_row.try_get("", "renewer_did")?;
    let renewer_epoch: i64 = lease_row.try_get("", "renewer_epoch")?;
    let lease_expiry: OffsetDateTime = lease_row.try_get("", "lease_expiry")?;
    let original_expiry: OffsetDateTime = lease_row.try_get("", "original_expiry")?;
    let period: i64 = lease_row.try_get("", "period_seconds")?;
    let audience: Vec<u8> = lease_row.try_get("", "audience_public_key")?;
    let current_epoch = identity.epoch;
    let current_epoch_i64 =
        i64::try_from(current_epoch).map_err(|_| RenewalStoreError::InvalidInput)?;
    if state != "active" || now >= lease_expiry.unix_timestamp() {
        return Err(RenewalStoreError::LeaseUnavailable);
    }
    if renewer_did != identity.renewer_did || renewer_epoch != current_epoch_i64 {
        return Err(RenewalStoreError::IdentityEpoch);
    }
    let snapshot = load_renewal_snapshot(
        tx,
        &[original, lease],
        &identity.stable_node_did,
        &identity.renewer_did,
        current_epoch,
        now,
    )
    .await?;
    // Compare with the precision stored by register_lease_at; caps remain floored.
    if snapshot
        .delegation(&original)
        .and_then(|row| row.expiry)
        .map(|expiry| expiry.unix_timestamp())
        != Some(original_expiry.unix_timestamp())
        || snapshot
            .delegation(&lease)
            .and_then(|row| row.expiry)
            .map(|expiry| expiry.unix_timestamp())
            != Some(lease_expiry.unix_timestamp())
    {
        return Err(RenewalStoreError::InvalidInput);
    }
    let original_chain = live_chain_effective_ends(&snapshot, &original, now)?;
    live_chain_effective_ends(&snapshot, &lease, now)?;
    let current_original_end = original_chain
        .iter()
        .find_map(|(id, end)| (*id == original).then_some(*end))
        .ok_or(RenewalStoreError::LeaseUnavailable)?;
    let ancestor_ends = original_chain
        .iter()
        .filter_map(|(id, end)| (*id != original).then_some(*end))
        .collect::<Vec<_>>();
    let previous = latest_stamp_cid(tx, &original, &lease)
        .await?
        .unwrap_or_else(|| lease_cid.clone());
    if now >= current_original_end {
        return Err(RenewalStoreError::LeaseUnavailable);
    }
    let new_end = new_end(now, period, lease_expiry.unix_timestamp(), &ancestor_ends)?;
    if new_end <= current_original_end {
        return Err(RenewalStoreError::LeaseUnavailable);
    }
    let signer = RenewalSigner::from_seed(
        secret.derive_key(RENEWER_KEY_CONTEXT),
        identity.stable_node_did.clone(),
        current_epoch,
    );
    let new_end_string = unix_time(new_end)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    let (signed_bytes, signature, cid) = signer
        .sign_stamp(
            &original_cid,
            &lease_cid,
            generation as u64,
            &previous,
            &new_end_string,
        )
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    let audience_key: [u8; 32] = audience
        .as_slice()
        .try_into()
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    verify_stamp_signature(&signed_bytes, &signature, &audience_key)?;
    validate_stamp_end(
        new_end,
        now,
        period,
        lease_expiry.unix_timestamp(),
        &ancestor_ends,
    )?;

    let stamp_hash = canonical_cid(&cid)?.1;
    tx.execute(Statement::from_sql_and_values(
        backend,
        "INSERT INTO renewal_stamp (cid, original_canonical, lease_cid, generation, previous_stamp_cid, renewer_epoch, new_end, signed_bytes, signature, replay_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        [
            Value::Bytes(Some(Box::new(Vec::<u8>::from(stamp_hash)))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
            Value::BigInt(Some(generation)),
            Value::Bytes(Some(Box::new(cid_hash_bytes(&previous)?))),
            Value::BigInt(Some(current_epoch as i64)),
            Value::TimeDateTime(Some(Box::new(db_datetime(new_end)?))),
            Value::Bytes(Some(Box::new(signed_bytes.clone()))),
            Value::Bytes(Some(Box::new(signature.clone()))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(request.replay_hash)))),
        ],
    )).await?;
    Ok(StampRecord {
        cid,
        lease_cid,
        new_end,
        previous_stamp_cid: previous,
        generation: generation as u64,
        signed_bytes,
        signature,
    })
}

async fn lock_original<C: ConnectionTrait>(
    tx: &C,
    original: &Hash,
) -> Result<(), RenewalStoreError> {
    match tx.get_database_backend() {
        DatabaseBackend::Postgres => {
            let bytes = crate::hash::hash(original.as_ref());
            let key = i64::from_be_bytes(bytes.as_ref()[..8].try_into().unwrap());
            tx.query_one(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT pg_advisory_xact_lock($1)",
                [Value::BigInt(Some(key))],
            ))
            .await?;
        }
        DatabaseBackend::Sqlite => {
            tx.execute_unprepared("UPDATE epoch SET seq = seq WHERE 0")
                .await?;
        }
        DatabaseBackend::MySql => return Err(RenewalStoreError::InvalidInput),
    }
    Ok(())
}

async fn is_revoked_chain<C: ConnectionTrait>(
    db: &C,
    id: &Hash,
) -> Result<bool, RenewalStoreError> {
    let row = db.query_one(Statement::from_sql_and_values(
        db.get_database_backend(),
        "WITH RECURSIVE chain(id) AS (SELECT $1 UNION SELECT p.parent FROM parent_delegation p JOIN chain c ON p.child = c.id) SELECT 1 AS revoked FROM chain c JOIN revocation r ON r.revoked = c.id LIMIT 1",
        [Value::Bytes(Some(Box::new(Vec::<u8>::from(*id))))],
    )).await?;
    Ok(row.is_some())
}

fn is_unique_violation(error: &DbErr) -> bool {
    matches!(error, DbErr::Exec(sea_orm::RuntimeErr::SqlxError(err)) if err.to_string().contains("unique"))
        || error.to_string().contains("UNIQUE constraint failed")
}

async fn latest_stamp_cid<C: ConnectionTrait>(
    db: &C,
    original: &Hash,
    lease: &Hash,
) -> Result<Option<String>, RenewalStoreError> {
    let row = db.query_one(Statement::from_sql_and_values(
        db.get_database_backend(),
        "SELECT cid FROM renewal_stamp s WHERE s.original_canonical = $1 AND s.lease_cid = $2 AND NOT EXISTS (SELECT 1 FROM renewal_stamp n WHERE n.original_canonical = s.original_canonical AND n.lease_cid = s.lease_cid AND n.previous_stamp_cid = s.cid)",
        [
            Value::Bytes(Some(Box::new(Vec::<u8>::from(*original)))),
            Value::Bytes(Some(Box::new(Vec::<u8>::from(*lease)))),
        ],
    )).await?;
    row.map(|r| {
        let bytes: Vec<u8> = r.try_get("", "cid")?;
        let hash = Hash::try_from(bytes).map_err(DbErr::from)?;
        Ok::<String, DbErr>(hash.to_cid(0x55).to_string())
    })
    .transpose()
    .map_err(Into::into)
}

pub async fn effective_end<C: ConnectionTrait>(
    db: &C,
    original_cid: &str,
    lease_cid: &str,
    verifier_now: i64,
    identity: &RenewalNodeIdentity,
) -> Result<Option<i64>, RenewalStoreError> {
    let (_, original) = canonical_cid(original_cid)?;
    let (_, lease) = canonical_cid(lease_cid)?;
    let snapshot = load_renewal_snapshot(
        db,
        &[original, lease],
        &identity.stable_node_did,
        &identity.renewer_did,
        identity.epoch,
        verifier_now,
    )
    .await?;
    let original_chain = match live_chain_effective_ends(&snapshot, &original, verifier_now) {
        Ok(chain) => chain,
        Err(RenewalStoreError::LeaseUnavailable) => return Ok(None),
        Err(error) => return Err(error),
    };
    live_chain_effective_ends(&snapshot, &lease, verifier_now)?;
    Ok(original_chain
        .iter()
        .find_map(|(id, end)| (*id == original).then_some(*end)))
}

async fn status_authorized<C: ConnectionTrait>(
    db: &C,
    invoker: &str,
    proofs: &[Cid],
    target_id: Hash,
) -> Result<bool, RenewalStoreError> {
    use crate::models::revocation::{ControlAction, ControlProofDecision};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let Some(target) = crate::models::revocation::target_for_cid(db, target_id).await? else {
        return Ok(false);
    };
    let abilities = crate::models::abilities::Entity::find()
        .filter(crate::models::abilities::Column::Delegation.eq(target.id))
        .all(db)
        .await?;
    Ok(
        match crate::models::revocation::control_proof_decision(
            db,
            invoker,
            proofs,
            ControlAction::Status,
            &target_id,
        )
        .await?
        {
            ControlProofDecision::DirectSigner(principal) => {
                ControlAction::Status.party_may_act(&target, &principal)
                    || abilities.iter().any(|ability| {
                        ability.resource.space().is_some_and(|space| {
                            tinycloud_auth::identity::did_principal_matches(
                                space.did().as_str(),
                                &principal,
                            )
                        })
                    })
            }
            ControlProofDecision::Scoped(control) => {
                control.authorizes_target(&target_id, &target, &abilities)
            }
            ControlProofDecision::Ungranted | ControlProofDecision::Denied => false,
        },
    )
}

/// Read-only, non-authoritative history guarded by original status rights.
/// Call only inside the status snapshot after evaluating the original's status
/// decision, including its revocation state, on the same connection.
pub(crate) async fn renewal_history<C: ConnectionTrait>(
    db: &C,
    original_cid: &str,
    invoker: &str,
    proofs: &[Cid],
) -> Result<Vec<StampRecord>, RenewalStoreError> {
    let original_id = Cid::from_str(original_cid)
        .map(Hash::from)
        .map_err(|_| RenewalStoreError::InvalidInput)?;
    if !status_authorized(db, invoker, proofs, original_id).await? {
        return Err(RenewalStoreError::Unauthorized);
    }
    let canonical_original_cid = original_id.to_cid(0x55).to_string();
    let rows = db.query_all(Statement::from_sql_and_values(
        db.get_database_backend(),
        "SELECT s.cid, s.lease_cid, s.generation, s.previous_stamp_cid, s.new_end, s.signed_bytes, s.signature FROM renewal_stamp s WHERE s.original_canonical = $1 ORDER BY s.lease_cid, s.generation",
        [Value::Bytes(Some(Box::new(Vec::<u8>::from(original_id))))],
    )).await?;
    let mut history = Vec::with_capacity(rows.len());
    for row in rows {
        let cid = Hash::try_from(row.try_get::<Vec<u8>>("", "cid")?).map_err(DbErr::from)?;
        let lease =
            Hash::try_from(row.try_get::<Vec<u8>>("", "lease_cid")?).map_err(DbErr::from)?;
        // The enclosing status snapshot authorizes the original, including
        // its revocation state. Lease-party rights do not gate its stamps.
        let signed_bytes: Vec<u8> = row.try_get("", "signed_bytes")?;
        let Ok(signed) = serde_ipld_dagcbor::from_slice::<CanonicalRenewalStamp<'_>>(&signed_bytes)
        else {
            continue;
        };
        if signed.unsigned.original_cid != canonical_original_cid {
            continue;
        }
        let previous = Hash::try_from(row.try_get::<Vec<u8>>("", "previous_stamp_cid")?)
            .map_err(DbErr::from)?;
        let new_end: OffsetDateTime = row.try_get("", "new_end")?;
        history.push(StampRecord {
            cid: cid.to_cid(0x55).to_string(),
            lease_cid: lease.to_cid(0x55).to_string(),
            new_end: new_end.unix_timestamp(),
            previous_stamp_cid: previous.to_cid(0x55).to_string(),
            generation: row.try_get::<i64>("", "generation")? as u64,
            signed_bytes,
            signature: row.try_get("", "signature")?,
        });
    }
    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sea_orm::sea_query::Value;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, Statement};
    use sea_orm_migration::MigratorTrait;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use tinycloud_auth::{
        authorization::TinyCloudDelegation,
        resolver::DID_METHODS,
        siwe_recap::Ability,
        ssi::{
            claims::jwt::NumericDate,
            jwk::{Algorithm, JWK},
            ucan::Payload,
        },
        ucan_capabilities_object::Capabilities,
    };

    fn fixed_test_ed25519_jwk(seed: [u8; 32]) -> JWK {
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        let x = URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes());
        let d = URL_SAFE_NO_PAD.encode(seed);

        serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": x,
            "d": d,
        }))
        .unwrap()
    }

    fn signed_test_renewal_lease(
        audience: &str,
        original_cid: &str,
        not_before: i64,
        expiration: i64,
    ) -> String {
        let owner_jwk = fixed_test_ed25519_jwk([0x11; 32]);
        let owner_did = DID_METHODS.generate(&owner_jwk, "key").unwrap().to_string();
        let owner_method = format!("{owner_did}#{}", owner_did.trim_start_matches("did:key:"));
        let mut capabilities = Capabilities::<serde_json::Value>::new();
        capabilities.with_action(
            format!("urn:cid:{original_cid}").parse().unwrap(),
            "tinycloud.delegation/renew".parse::<Ability>().unwrap(),
            [BTreeMap::<String, serde_json::Value>::new()],
        );
        Payload::<serde_json::Value> {
            issuer: owner_method.parse().unwrap(),
            audience: audience.parse().unwrap(),
            not_before: Some(NumericDate::try_from_seconds(not_before as f64).unwrap()),
            expiration: NumericDate::try_from_seconds(expiration as f64).unwrap(),
            nonce: Some("epoch-rotation-renewal-lease".to_owned()),
            facts: None,
            proof: Vec::new(),
            attenuation: capabilities,
        }
        .sign(Algorithm::EdDSA, &owner_jwk)
        .unwrap()
        .encode()
        .unwrap()
    }

    #[test]
    fn signed_period_and_ancestor_bounds_are_enforced() {
        assert_eq!(
            period_seconds(100, Some(0), None, OriginalFormat::Ucan),
            Ok(100)
        );
        assert_eq!(
            period_seconds(100, None, Some(0), OriginalFormat::Ucan),
            Err(RenewalError::MissingAnchor)
        );
        assert_eq!(new_end(100, 1000, 2000, &[500]), Ok(500));
        assert_eq!(validate_stamp_end(500, 600, 1000, 2000, &[700]), Ok(()));
        assert_eq!(validate_stamp_end(601, 600, 1000, 2000, &[700]), Ok(()));
    }

    #[test]
    fn stamp_signature_is_verified_with_lease_audience_key() {
        let stable_node_did = renewal_identity_from_seed([8; 32]).0;
        let signer = RenewalSigner::from_seed([7; 32], stable_node_did.clone(), 1);
        assert_ne!(renewal_identity_from_seed([7; 32]).0, stable_node_did);
        let (bytes, signature, _) = signer
            .sign_stamp(
                "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4",
                "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq",
                0,
                "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq",
                "2026-11-11T00:00:00Z",
            )
            .unwrap();
        assert_eq!(
            verify_stamp_signature(&bytes, &signature, &signer.public_key()),
            Ok(())
        );
        let node_identity_key = RenewalSigner::from_seed([8; 32], stable_node_did.clone(), 1);
        assert_eq!(renewal_identity_from_seed([8; 32]).0, stable_node_did);
        assert_eq!(
            verify_stamp_signature(&bytes, &signature, &node_identity_key.public_key()),
            Err(RenewalError::InvalidSignature)
        );
    }

    #[test]
    fn snapshot_stamp_binds_registered_chain_and_bounds() {
        let original = "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4";
        let lease = "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq";
        let signer = RenewalSigner::from_seed([7; 32], "did:key:stable-node".to_owned(), 1);
        let (bytes, signature, stamp) = signer
            .sign_stamp(original, lease, 0, lease, "1970-01-01T00:33:20Z")
            .unwrap();
        verify_snapshot_stamp(SnapshotStampVerification {
            signed_bytes: &bytes,
            signature_bytes: &signature,
            expected_stamp_cid: &stamp,
            expected_original_cid: original,
            expected_lease_cid: lease,
            generation: 0,
            previous_stamp_cid: lease,
            new_end: 2000,
            node_did: &signer.node_did,
            renewer_epoch: signer.renewer_epoch,
            audience_public_key: &signer.public_key(),
            verifier_now: 1000,
            period: 2000,
            lease_expiry: 4000,
            ancestor_ends: &[3000],
        })
        .unwrap();
        assert!(matches!(
            verify_snapshot_stamp(SnapshotStampVerification {
                signed_bytes: &bytes,
                signature_bytes: &signature,
                expected_stamp_cid: &stamp,
                expected_original_cid: original,
                expected_lease_cid: lease,
                generation: 0,
                previous_stamp_cid: lease,
                new_end: 2000,
                node_did: "did:key:wrong-node",
                renewer_epoch: signer.renewer_epoch,
                audience_public_key: &signer.public_key(),
                verifier_now: 1000,
                period: 2000,
                lease_expiry: 4000,
                ancestor_ends: &[3000],
            }),
            Err(RenewalStoreError::InvalidInput)
        ));
    }

    #[test]
    fn snapshot_chain_allows_expired_predecessor_with_active_tip() {
        let original = "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4";
        let lease = "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq";
        let signer = RenewalSigner::from_seed([7; 32], "did:key:stable-node".to_owned(), 1);
        let (old_bytes, old_signature, old_cid) = signer
            .sign_stamp(original, lease, 0, lease, "1970-01-01T00:16:40Z")
            .unwrap();
        let verify = |bytes: &[u8], signature: &[u8], cid: &str, previous: &str, end| {
            verify_snapshot_stamp(SnapshotStampVerification {
                signed_bytes: bytes,
                signature_bytes: signature,
                expected_stamp_cid: cid,
                expected_original_cid: original,
                expected_lease_cid: lease,
                generation: 0,
                previous_stamp_cid: previous,
                new_end: end,
                node_did: &signer.node_did,
                renewer_epoch: signer.renewer_epoch,
                audience_public_key: &signer.public_key(),
                verifier_now: 2_000,
                period: 5_000,
                lease_expiry: 9_000,
                ancestor_ends: &[8_000],
            })
        };
        verify(&old_bytes, &old_signature, &old_cid, lease, 1_000).unwrap();

        let (tip_bytes, tip_signature, tip_cid) = signer
            .sign_stamp(original, lease, 0, &old_cid, "1970-01-01T00:50:00Z")
            .unwrap();
        verify(&tip_bytes, &tip_signature, &tip_cid, &old_cid, 3_000).unwrap();
        // The tip ends after the verifier time.
    }

    #[test]
    fn renewer_identity_is_deterministic_and_epoch_is_supplied_by_state() {
        let first = StaticSecret::new(vec![1; 32]).unwrap();
        let same = StaticSecret::new(vec![1; 32]).unwrap();
        let rotated = StaticSecret::new(vec![2; 32]).unwrap();
        assert_eq!(renewal_identity(&first), renewal_identity(&same));
        assert_ne!(renewal_identity(&first).0, renewal_identity(&rotated).0);
        assert_eq!(renewal_identity(&first).1, 1);
        assert_eq!(renewal_identity_at_epoch(&rotated, 7).1, 7);
        assert!(is_renewer_did(&first, &renewal_identity(&same).0));
    }

    #[tokio::test]
    async fn persisted_renewer_epoch_increments_only_when_identity_changes() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("CREATE TABLE epoch (seq BIGINT NOT NULL)")
            .await
            .unwrap();
        db.execute_unprepared(
            "CREATE TABLE renewal_identity (id INTEGER PRIMARY KEY, renewer_did TEXT, epoch BIGINT NOT NULL)",
        )
        .await
        .unwrap();
        let first_seed = [1; 32];
        let second_seed = [2; 32];

        let (first_did, first_epoch, _) =
            initialize_renewal_identity(&db, first_seed).await.unwrap();
        assert_eq!(first_epoch, 1);
        assert_eq!(
            initialize_renewal_identity(&db, first_seed)
                .await
                .unwrap()
                .1,
            1
        );
        let (second_did, second_epoch, _) =
            initialize_renewal_identity(&db, second_seed).await.unwrap();
        assert_ne!(first_did, second_did);
        assert_eq!(second_epoch, 2);
        assert!(matches!(
            current_renewal_identity_from_seed(&db, first_seed).await,
            Err(RenewalStoreError::IdentityEpoch)
        ));
        assert_eq!(
            initialize_renewal_identity(&db, first_seed)
                .await
                .unwrap()
                .1,
            3
        );
    }

    #[test]
    fn renew_capability_classifier_requires_exact_canonical_resource() {
        let original = "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4";
        assert!(is_renewal_capability(
            "tinycloud.delegation/renew",
            &format!("urn:cid:{original}"),
            original
        ));
        assert!(!is_renewal_capability(
            "tinycloud.delegation/revoke",
            &format!("urn:cid:{original}"),
            original
        ));
        assert!(!is_renewal_capability(
            "tinycloud.delegation/renew",
            &format!("urn:cid:{original}/child"),
            original
        ));
    }

    #[test]
    fn renewal_registration_target_comes_from_signed_lease() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tinycloud-node-server/tests/fixtures/renewal-lease-v1.json"
        ))
        .unwrap();
        let lease = crate::events::Delegation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudDelegation,
        >(fixture["leaseToken"].as_str().unwrap())
        .unwrap();
        assert_eq!(
            lease_original_from_signed(&lease).unwrap().as_deref(),
            Some("bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4")
        );
    }

    #[tokio::test]
    async fn sqlite_issue_caps_to_ancestor_and_replay_is_atomic() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_owned()))
            .await
            .unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tinycloud-node-server/tests/fixtures/renewal-lease-v1.json"
        ))
        .unwrap();
        let original_serialization = fixture["originalToken"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        let lease_serialization = fixture["leaseToken"].as_str().unwrap().as_bytes().to_vec();
        let original_info = signed_delegation_info(&original_serialization).unwrap();
        let lease_info = signed_delegation_info(&lease_serialization).unwrap();
        let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
        let (renewer_did, renewer_epoch, audience) =
            initialize_renewal_identity(&db, secret.derive_key(RENEWER_KEY_CONTEXT))
                .await
                .unwrap();
        let identity = RenewalNodeIdentity {
            stable_node_did: secret.node_did(),
            renewer_did: renewer_did.clone(),
            epoch: renewer_epoch,
        };
        let original_cid = "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4";
        let lease_cid = "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq";
        let original = canonical_cid(original_cid).unwrap().1;
        let lease = canonical_cid(lease_cid).unwrap().1;
        let ancestor = hash(b"renewal ancestor");
        let original_expiry = original_info.expiry.unwrap().unix_timestamp();
        let lease_expiry = lease_info.expiry.unwrap().unix_timestamp();
        let period = period_seconds(
            original_expiry,
            original_info.not_before.map(|value| value.unix_timestamp()),
            original_info.issued_at.map(|value| value.unix_timestamp()),
            OriginalFormat::Ucan,
        )
        .unwrap();
        let now = original_expiry - 4_000;
        let end = now + 8_000;
        let grantor = original_info.delegator.clone();
        let tx = crate::db::begin_write_transaction(&db, None).await.unwrap();
        for actor in [
            grantor.clone(),
            renewer_did.clone(),
            "did:key:child".to_owned(),
            original_info.delegate.clone(),
        ] {
            tx.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO actor (id) VALUES ($1)",
                [Value::String(Some(Box::new(actor)))],
            ))
            .await
            .unwrap();
        }
        let insert_delegation = |id: Hash,
                                 delegator: String,
                                 delegatee: String,
                                 expiry: i64,
                                 serialization: Vec<u8>| {
            Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO delegation (id, delegator, delegatee, expiry, issued_at, not_before, facts, serialization, serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(id)))),
                    Value::String(Some(Box::new(delegator))),
                    Value::String(Some(Box::new(delegatee))),
                    Value::TimeDateTime(Some(Box::new(db_datetime(expiry).unwrap()))),
                    Value::Bytes(Some(Box::new(serialization))),
                ],
            )
        };
        tx.execute(insert_delegation(
            ancestor,
            grantor.clone(),
            "did:key:child".to_owned(),
            end,
            vec![1],
        ))
        .await
        .unwrap();
        tx.execute(insert_delegation(
            original,
            grantor.clone(),
            original_info.delegate.clone(),
            original_expiry,
            original_serialization.clone(),
        ))
        .await
        .unwrap();
        tx.execute(insert_delegation(
            lease,
            grantor.clone(),
            lease_info.delegate.clone(),
            lease_expiry,
            lease_serialization.clone(),
        ))
        .await
        .unwrap();
        for id in [ancestor, original, lease] {
            tx.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
                [Value::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
            ))
            .await
            .unwrap();
        }
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO parent_delegation (parent, child) VALUES ($1, $2)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(ancestor)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
            ],
        ))
        .await
        .unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO ability (delegation, resource, ability, caveats) VALUES ($1,$2,$3,$4)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                Value::String(Some(Box::new(format!("urn:cid:{original_cid}")))),
                Value::String(Some(Box::new("tinycloud.delegation/renew".to_owned()))),
                Value::Json(Some(Box::new(serde_json::json!({})))),
            ],
        ))
        .await
        .unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO renewal_lease (original_canonical, lease_cid, state, generation, grantor, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key) VALUES ($1,$2,'active',1,$3,$4,$5,$6,$7,$8,$9)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                Value::String(Some(Box::new(grantor.to_owned()))),
                Value::String(Some(Box::new(renewer_did.clone()))),
                Value::BigInt(Some(renewer_epoch as i64)),
                Value::TimeDateTime(Some(Box::new(db_datetime(lease_expiry).unwrap()))),
                Value::TimeDateTime(Some(Box::new(db_datetime(original_expiry).unwrap()))),
                Value::BigInt(Some(period)),
                Value::Bytes(Some(Box::new(audience.to_vec()))),
            ],
        )).await.unwrap();
        let stored_audience = tx
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT audience_public_key FROM renewal_lease WHERE original_canonical = $1",
                [Value::Bytes(Some(Box::new(Vec::<u8>::from(original))))],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<Vec<u8>>("", "audience_public_key")
            .unwrap();
        assert_eq!(stored_audience, audience);
        assert_eq!(
            RenewalSigner::from_seed(
                secret.derive_key(RENEWER_KEY_CONTEXT),
                secret.node_did(),
                renewer_epoch,
            )
            .public_key(),
            audience
        );
        tx.commit().await.unwrap();

        let invocation_token = tinycloud_auth::authorization::TinyCloudInvocation::decode(
            fixture["originalToken"].as_str().unwrap(),
        )
        .unwrap();
        let mut request = StampIssue {
            invocation: crate::util::InvocationInfo::try_from(invocation_token).unwrap(),
            original_cid: original_cid.to_owned(),
            lease_cid: lease_cid.to_owned(),
            replay_hash: hash(b"request replay"),
            replay_expires_at: now + 60,
        };
        request.invocation.invoker = renewer_did.clone();
        request.invocation.parents = vec![lease_cid.parse().unwrap()];
        request.invocation.capabilities = vec![crate::util::Capability {
            resource: format!("urn:cid:{original_cid}").parse().unwrap(),
            ability: "tinycloud.delegation/renew".to_owned().try_into().unwrap(),
            caveats: Default::default(),
        }];

        let mut wrong_caller = request.invocation.clone();
        wrong_caller.invoker = "did:key:attacker".to_owned();
        assert!(matches!(
            authorize_renewal_invocation_at(&db, &wrong_caller, original_cid, &identity, now).await,
            Err(RenewalStoreError::Unauthorized)
        ));
        let mut extra_parent = request.invocation.clone();
        extra_parent.parents.push(original_cid.parse().unwrap());
        assert!(matches!(
            authorize_renewal_invocation_at(&db, &extra_parent, original_cid, &identity, now).await,
            Err(RenewalStoreError::Unauthorized)
        ));
        authorize_renewal_invocation_at(&db, &request.invocation, original_cid, &identity, now)
            .await
            .unwrap();
        let issued = issue_stamp_at(&db, request.clone(), &secret, &identity, now)
            .await
            .unwrap();
        assert!(issued.new_end <= end);
        assert!(issued.new_end > original_expiry);
        assert!(matches!(
            issue_stamp_at(&db, request.clone(), &secret, &identity, now).await,
            Err(RenewalStoreError::Replay)
        ));

        assert_eq!(
            effective_end(&db, original_cid, lease_cid, now, &identity)
                .await
                .unwrap(),
            Some(issued.new_end)
        );
        let next_seed = [8; 32];
        let (next_did, next_epoch, _) = initialize_renewal_identity(&db, next_seed).await.unwrap();
        assert_eq!(next_epoch, renewer_epoch + 1);
        let next_identity = RenewalNodeIdentity {
            stable_node_did: secret.node_did(),
            renewer_did: next_did.clone(),
            epoch: next_epoch,
        };
        let mut stale_process_request = request.clone();
        stale_process_request.replay_hash = hash(b"stale process identity");
        stale_process_request.replay_expires_at = now + 120;
        assert!(matches!(
            issue_stamp_at(&db, stale_process_request, &secret, &identity, now + 60,).await,
            Err(RenewalStoreError::IdentityEpoch)
        ));
        let next_snapshot = load_renewal_snapshot(
            &db,
            &[original, lease],
            &secret.node_did(),
            &next_did,
            next_epoch,
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            next_snapshot.effective_expiry(&original),
            Some(original_expiry)
        );
        assert_eq!(
            effective_end(&db, original_cid, lease_cid, now, &next_identity)
                .await
                .unwrap(),
            Some(original_expiry)
        );
        assert!(
            lease_for_original_at(&db, original_cid, now, &next_identity)
                .await
                .unwrap()
                .is_none()
        );
        assert!(issue_stamp_at(&db, request, &secret, &next_identity, now)
            .await
            .is_err());

        let next_not_before = now - 100;
        let next_expiry = next_not_before + MAX_LEASE_SECONDS;
        let next_token =
            signed_test_renewal_lease(&next_did, original_cid, next_not_before, next_expiry);
        let next_event =
            crate::events::Delegation::from_header_ser::<TinyCloudDelegation>(&next_token).unwrap();
        let next_lease = crate::hash::hash(next_event.serialized_bytes());
        let next_info = signed_delegation_info(next_event.serialized_bytes()).unwrap();
        assert_eq!(next_info.delegator, grantor);
        assert_eq!(next_info.delegate, next_did);
        assert_eq!(next_info.expiry.unwrap().unix_timestamp(), next_expiry);
        let tx = crate::db::begin_write_transaction(&db, None).await.unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO actor (id) VALUES ($1)",
            [Value::String(Some(Box::new(next_did.clone())))],
        ))
        .await
        .unwrap();
        tx.execute(insert_delegation(
            next_lease,
            grantor.clone(),
            next_did.clone(),
            next_expiry,
            next_token.as_bytes().to_vec(),
        ))
        .await
        .unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
            [Value::Bytes(Some(Box::new(Vec::<u8>::from(next_lease))))],
        ))
        .await
        .unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO ability (delegation, resource, ability, caveats) VALUES ($1,$2,$3,$4)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(next_lease)))),
                Value::String(Some(Box::new(format!("urn:cid:{original_cid}")))),
                Value::String(Some(Box::new("tinycloud.delegation/renew".to_owned()))),
                Value::Json(Some(Box::new(serde_json::json!({})))),
            ],
        ))
        .await
        .unwrap();
        register_lease_at(
            &tx,
            &next_event,
            next_seed,
            next_epoch,
            &secret.node_did(),
            None,
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let expected_next_lease_cid = next_lease.to_cid(0x55).to_string();
        assert_eq!(
            lease_for_original_at(&db, original_cid, now, &next_identity)
                .await
                .unwrap()
                .unwrap()
                .lease_cid,
            expected_next_lease_cid
        );
        let lease_count: i64 = db
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM renewal_lease WHERE original_canonical = $1",
                [Value::Bytes(Some(Box::new(Vec::<u8>::from(original))))],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "count")
            .unwrap();
        assert_eq!(lease_count, 2);
        for epoch in [1_i64, next_epoch as i64] {
            let rows: i64 = db
                .query_one(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT COUNT(*) AS count FROM renewal_lease WHERE original_canonical = $1 AND renewer_epoch = $2",
                    [
                        Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                        Value::BigInt(Some(epoch)),
                    ],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get("", "count")
                .unwrap();
            assert_eq!(rows, 1);
        }
        let replay_count: i64 = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM invocation_replay",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "count")
            .unwrap();
        let stamp_count: i64 = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM renewal_stamp",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "count")
            .unwrap();
        assert_eq!((replay_count, stamp_count), (1, 1));
    }

    #[tokio::test]
    async fn lease_registration_requires_a_live_original_or_valid_renewal() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_owned()))
            .await
            .unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        let secret = StaticSecret::new(vec![13; 32]).unwrap();
        let renewal_seed = secret.derive_key(b"tinycloud/node/renewer/v1");
        let (renewer_did, renewer_epoch, audience) = renewal_identity_from_seed(renewal_seed);
        let original_cid = "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4";
        let lease_cid = "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq";
        let original = canonical_cid(original_cid).unwrap().1;
        let lease = canonical_cid(lease_cid).unwrap().1;
        let grantor = "did:key:renewal-owner";
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let original_expiry = now - 100;
        let lease_expiry = now + 1_000;
        let tx = crate::db::begin_write_transaction(&db, None).await.unwrap();
        for actor in [
            grantor.to_owned(),
            renewer_did.clone(),
            "did:key:holder".to_owned(),
        ] {
            tx.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO actor (id) VALUES ($1)",
                [Value::String(Some(Box::new(actor)))],
            ))
            .await
            .unwrap();
        }
        for (id, delegatee, expiry) in [
            (original, "did:key:holder", original_expiry),
            (lease, renewer_did.as_str(), lease_expiry),
        ] {
            tx.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO delegation (id, delegator, delegatee, expiry, issued_at, not_before, facts, serialization, serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(id)))),
                    Value::String(Some(Box::new(grantor.to_owned()))),
                    Value::String(Some(Box::new(delegatee.to_owned()))),
                    Value::TimeDateTime(Some(Box::new(db_datetime(expiry).unwrap()))),
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(id)))),
                ],
            ))
            .await
            .unwrap();
            tx.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
                [Value::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
            ))
            .await
            .unwrap();
        }
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO renewal_lease (original_canonical, lease_cid, state, generation, grantor, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key) VALUES ($1,$2,'active',1,$3,$4,$5,$6,$7,10000,$8)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                Value::String(Some(Box::new(grantor.to_owned()))),
                Value::String(Some(Box::new(renewer_did.clone()))),
                Value::BigInt(Some(renewer_epoch as i64)),
                Value::TimeDateTime(Some(Box::new(db_datetime(lease_expiry).unwrap()))),
                Value::TimeDateTime(Some(Box::new(db_datetime(original_expiry).unwrap()))),
                Value::Bytes(Some(Box::new(audience.to_vec()))),
            ],
        ))
        .await
        .unwrap();

        let roots = [original, lease];
        let snapshot = load_renewal_snapshot(
            &tx,
            &roots,
            &secret.node_did(),
            &renewer_did,
            renewer_epoch,
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            live_chain_effective_ends(&snapshot, &original, now),
            Err(RenewalStoreError::LeaseUnavailable)
        ));

        let renewed_end = now + 500;
        let renewed_end_text = OffsetDateTime::from_unix_timestamp(renewed_end)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let signer = RenewalSigner::from_seed(renewal_seed, secret.node_did(), renewer_epoch);
        let (signed_bytes, signature, _) = signer
            .sign_stamp(original_cid, lease_cid, 1, lease_cid, &renewed_end_text)
            .unwrap();
        let forged_signature =
            RenewalSigner::from_seed([0xa5; 32], secret.node_did(), renewer_epoch)
                .sign_stamp(original_cid, lease_cid, 1, lease_cid, &renewed_end_text)
                .unwrap()
                .1;
        let stamp_hash = hash(&signed_bytes);
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO renewal_stamp (cid, original_canonical, lease_cid, generation, previous_stamp_cid, renewer_epoch, new_end, signed_bytes, signature, replay_hash) VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(stamp_hash)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                Value::BigInt(Some(renewer_epoch as i64)),
                Value::TimeDateTime(Some(Box::new(db_datetime(renewed_end).unwrap()))),
                Value::Bytes(Some(Box::new(signed_bytes.clone()))),
                Value::Bytes(Some(Box::new(forged_signature))),
                Value::Bytes(Some(Box::new(hash(&signed_bytes).as_ref().to_vec()))),
            ],
        ))
        .await
        .unwrap();
        let forged_snapshot = load_renewal_snapshot(
            &tx,
            &roots,
            &secret.node_did(),
            &renewer_did,
            renewer_epoch,
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            live_chain_effective_ends(&forged_snapshot, &original, now),
            Err(RenewalStoreError::LeaseUnavailable)
        ));
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE renewal_stamp SET signature = $1 WHERE cid = $2",
            [
                Value::Bytes(Some(Box::new(signature))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(stamp_hash)))),
            ],
        ))
        .await
        .unwrap();
        let snapshot = load_renewal_snapshot(
            &tx,
            &roots,
            &secret.node_did(),
            &renewer_did,
            renewer_epoch,
            now,
        )
        .await
        .unwrap();
        let original_ends = live_chain_effective_ends(&snapshot, &original, now).unwrap();
        assert_eq!(
            original_ends.first().copied(),
            Some((original, renewed_end))
        );
        tx.rollback().await.unwrap();
    }
}
