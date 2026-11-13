//! Strict signed request binding for owner renewal controls.
use base64::Engine as _;
use sea_orm::ConnectionTrait;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use tinycloud_auth::ipld_core::cid::Cid;

const MAX_GENERATION: u64 = (1 << 53) - 1;

/// The operation comes exclusively from the signed capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Read,
    Stop,
    Enable,
}

/// Body selection must exactly match the signed resource and generation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateRequest {
    pub version: u8,
    pub lease_cid: String,
    pub expected_generation: Option<u64>,
}

/// Checks the unnormalized signed attenuation; signature verification is separate.
/// Returns the signed CAS operand, never an unsigned body operand.
pub fn bind_request(
    attenuation: &Value,
    body: &Value,
) -> Result<(StateRequest, Operation, Option<u64>), super::RenewalStoreError> {
    use super::RenewalStoreError::InvalidInput;
    let request: StateRequest = serde_json::from_value(body.clone()).map_err(|_| InvalidInput)?;
    let cid: Cid = request.lease_cid.parse().map_err(|_| InvalidInput)?;
    if request.version != 1
        || cid.to_string() != request.lease_cid
        || cid.codec() != 0x55
        || cid.hash().code() != u64::from(tinycloud_auth::multihash_codetable::Code::Blake3_256)
        || cid.hash().size() != 32
    {
        return Err(InvalidInput);
    }
    let resources = attenuation.as_object().ok_or(InvalidInput)?;
    if resources.len() != 1 {
        return Err(InvalidInput);
    }
    let abilities = resources
        .get(&format!("urn:cid:{}", request.lease_cid))
        .ok_or(super::RenewalStoreError::Unauthorized)?
        .as_object()
        .ok_or(InvalidInput)?;
    if abilities.len() != 1 {
        return Err(InvalidInput);
    }
    let (ability, caveats) = abilities.iter().next().ok_or(InvalidInput)?;
    let operation = match ability.as_str() {
        "tinycloud.delegation/status" => Operation::Read,
        "tinycloud.delegation/stop-renewal" => Operation::Stop,
        "tinycloud.delegation/enable-renewal" => Operation::Enable,
        _ => return Err(super::RenewalStoreError::Unauthorized),
    };
    let caveats = caveats.as_array().ok_or(InvalidInput)?;
    let [caveat] = caveats.as_slice() else {
        return Err(InvalidInput);
    };
    let caveat = caveat.as_object().ok_or(InvalidInput)?;
    let generation = if operation == Operation::Read {
        if !caveat.is_empty() || body.get("expectedGeneration").is_some() {
            return Err(InvalidInput);
        }
        None
    } else {
        if caveat.len() != 1 {
            return Err(InvalidInput);
        }
        let generation = caveat
            .get("expectedGeneration")
            .and_then(Value::as_u64)
            .filter(|generation| *generation <= MAX_GENERATION)
            .ok_or(InvalidInput)?;
        if request.expected_generation != Some(generation) {
            return Err(super::RenewalStoreError::Unauthorized);
        }
        Some(generation)
    };
    Ok((request, operation, generation))
}

// Typed UCAN capability maps normalize duplicate keys. Inspect the signed
// wire object first, preserving uniqueness at each resource/action/caveat level.
#[derive(serde::Serialize)]
#[serde(transparent)]
struct UniqueObject<T>(BTreeMap<String, T>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for UniqueObject<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
            type Value = UniqueObject<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object with unique keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate signed control key"));
                    }
                }
                Ok(UniqueObject(values))
            }
        }
        deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}
#[derive(Deserialize)]
struct RawControlClaims {
    att: UniqueObject<UniqueObject<Vec<UniqueObject<Value>>>>,
}
fn bind_signed_request(
    serialized: &[u8],
    body: &Value,
) -> Result<(StateRequest, Operation, Option<u64>), super::RenewalStoreError> {
    use super::RenewalStoreError::InvalidInput;
    let token = std::str::from_utf8(serialized).map_err(|_| InvalidInput)?;
    let parts = token.split('.').collect::<Vec<_>>();
    let [_, claims, _] = parts.as_slice() else {
        return Err(InvalidInput);
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims)
        .map_err(|_| InvalidInput)?;
    let claims: RawControlClaims = serde_json::from_slice(&bytes).map_err(|_| InvalidInput)?;
    let attenuation = serde_json::to_value(claims.att).map_err(|_| InvalidInput)?;
    bind_request(&attenuation, body)
}

/// A static refusal code, safe to return without exposing signed artifacts.
#[derive(Debug)]
pub struct ControlError(pub &'static str);

impl From<super::RenewalStoreError> for ControlError {
    fn from(_: super::RenewalStoreError) -> Self {
        Self("renewal_state_unavailable")
    }
}
impl From<sea_orm::DbErr> for ControlError {
    fn from(_: sea_orm::DbErr) -> Self {
        Self("renewal_state_unavailable")
    }
}

/// Confirmed state, returned only after its transaction commits.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateReceipt {
    pub version: u8,
    pub original_cid: String,
    pub lease_cid: String,
    pub state: String,
    pub generation: u64,
    pub lease_end: String,
}

async fn signed_artifact<C: sea_orm::ConnectionTrait>(
    tx: &C,
    id: super::Hash,
    encryption: Option<&crate::encryption::ColumnEncryption>,
) -> Result<crate::util::DelegationInfo, ControlError> {
    use sea_orm::{sea_query::Value, Statement};
    let row = tx
        .query_one(Statement::from_sql_and_values(
            tx.get_database_backend(),
            "SELECT serialization, serialization_format, delegator, delegatee, expiry FROM delegation WHERE id = $1",
            [Value::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
        ))
        .await?
        .ok_or(ControlError("unauthorized_control"))?;
    let stored: Vec<u8> = row.try_get("", "serialization")?;
    let format: i16 = row.try_get("", "serialization_format")?;
    let id_bytes = Vec::<u8>::from(id);
    let bytes = crate::encryption::maybe_decrypt(
        encryption,
        &stored,
        crate::encryption::RowBinding::new("delegation", "serialization", &[&id_bytes]),
        format,
    )
    .map_err(|_| ControlError("renewal_state_unavailable"))?;
    if crate::hash::hash(&bytes) != id {
        return Err(ControlError("renewal_state_unavailable"));
    }
    let info = super::signed_delegation_info(&bytes)?;
    super::verify_signed_signature(&info).await?;
    if row.try_get::<String>("", "delegator")? != info.delegator
        || row.try_get::<String>("", "delegatee")? != info.delegate
        || row.try_get::<Option<time::OffsetDateTime>>("", "expiry")? != info.expiry
    {
        return Err(ControlError("renewal_state_unavailable"));
    }
    Ok(info)
}

/// Execute an owner control and spend its nonce in one original-locked transaction.
/// The caller supplies an admitted signature and the standard invoker/nonce reservation.
pub async fn execute<C: sea_orm::ConnectionTrait + sea_orm::TransactionTrait>(
    conn: &C,
    admitted: &crate::AdmittedInvocation,
    body: &Value,
    replay: crate::models::invocation_replay::Model,
    identity: &super::RenewalNodeIdentity,
    encryption: Option<&crate::encryption::ColumnEncryption>,
) -> Result<StateReceipt, ControlError> {
    use super::{canonical_cid, lock_original};
    use sea_orm::{sea_query::Value as SqlValue, Statement};
    let info = &admitted.invocation().0;
    let payload = info.invocation.payload();
    if payload.audience.as_str() != identity.stable_node_did {
        return Err(ControlError("auth_required"));
    }
    if !info.parents.is_empty() || info.invoker == identity.renewer_did {
        return Err(ControlError("unauthorized_control"));
    }
    let nbf = payload
        .not_before
        .ok_or(ControlError("auth_required"))?
        .as_seconds();
    let exp = payload.expiration.as_seconds();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
    if nbf > now || exp <= now || exp - nbf > 60.0 {
        return Err(ControlError("auth_required"));
    }
    let nonce = payload.nonce.as_deref().unwrap_or_default();
    if nonce.is_empty() || nonce.len() > 256 {
        return Err(ControlError("invalid_request"));
    }
    let (request, operation, generation) =
        bind_signed_request(admitted.invocation().serialized_bytes(), body).map_err(|error| {
            match error {
                super::RenewalStoreError::Unauthorized => ControlError("unauthorized_control"),
                _ => ControlError("invalid_request"),
            }
        })?;
    let (_, lease) = canonical_cid(&request.lease_cid)?;
    let tx = crate::db::begin_write_transaction(conn, None).await?;
    let result = async {
        let backend = tx.get_database_backend();
        let lease_bytes = Vec::<u8>::from(lease);
        let row = tx.query_one(Statement::from_sql_and_values(backend,
            "SELECT original_canonical FROM renewal_lease WHERE lease_cid = $1",
            [SqlValue::Bytes(Some(Box::new(lease_bytes.clone())))])).await?
            .ok_or(ControlError("unauthorized_control"))?;
        let original_bytes: Vec<u8> = row.try_get("", "original_canonical")?;
        let original = super::Hash::try_from(original_bytes.clone())
            .map_err(|_| ControlError("renewal_state_unavailable"))?;
        lock_original(&tx, &original).await?;
        let row = tx.query_one(Statement::from_sql_and_values(backend,
            "SELECT state, generation, grantor, renewer_did, renewer_epoch, lease_expiry FROM renewal_lease WHERE original_canonical = $1 AND lease_cid = $2",
            [SqlValue::Bytes(Some(Box::new(original_bytes.clone()))), SqlValue::Bytes(Some(Box::new(lease_bytes.clone())))])).await?
            .ok_or(ControlError("unauthorized_control"))?;
        let original_info = signed_artifact(&tx, original, encryption).await?;
        let lease_info = signed_artifact(&tx, lease, encryption).await?;
        if !tinycloud_auth::identity::did_principal_matches(&original_info.delegator, &info.invoker)
            || !tinycloud_auth::identity::did_principal_matches(&lease_info.delegator, &info.invoker) {
            return Err(ControlError("unauthorized_control"));
        }
        let original_cid = original.to_cid(0x55).to_string();
        let [capability] = lease_info.capabilities.as_slice() else {
            return Err(ControlError("unauthorized_control"));
        };
        if !super::is_renewal_capability(&capability.ability.to_string(),
            &capability.resource.to_string(), &original_cid) {
            return Err(ControlError("unauthorized_control"));
        }
        let mut state: String = row.try_get("", "state")?;
        let mut current: i64 = row.try_get("", "generation")?;
        let end: time::OffsetDateTime = row.try_get("", "lease_expiry")?;
        if current < 1 || lease_info.expiry != Some(end) {
            return Err(ControlError("renewal_state_unavailable"));
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if payload.expiration.as_seconds() <= now as f64
            || payload.not_before.is_some_and(|nbf| nbf.as_seconds() > now as f64) {
            return Err(ControlError("auth_required"));
        }
        if let Err(error) = tx.execute(Statement::from_sql_and_values(backend,
            "INSERT INTO invocation_replay (content_hash, expires_at) VALUES ($1, $2)",
            [SqlValue::Bytes(Some(Box::new(Vec::<u8>::from(replay.content_hash)))),
             SqlValue::TimeDateTimeWithTimeZone(Some(Box::new(replay.expires_at)))])).await {
            return Err(if super::is_unique_violation(&error) { ControlError("invocation_replay") } else { error.into() });
        }
        if operation != Operation::Read {
            if end.unix_timestamp() <= now { return Err(ControlError("lease_expired")); }
            if super::is_revoked_chain(&tx, &lease).await? { return Err(ControlError("lease_revoked")); }
            if super::is_revoked_chain(&tx, &original).await? { return Err(ControlError("grant_revoked")); }
            let did: String = row.try_get("", "renewer_did")?;
            let epoch: i64 = row.try_get("", "renewer_epoch")?;
            let identity_query = match backend {
                sea_orm::DatabaseBackend::Postgres => "SELECT renewer_did, epoch FROM renewal_identity WHERE id = 1 FOR SHARE",
                _ => "SELECT renewer_did, epoch FROM renewal_identity WHERE id = 1",
            };
            let persisted = tx.query_one(Statement::from_string(backend, identity_query)).await?
                .ok_or(ControlError("renewal_state_unavailable"))?;
            if persisted.try_get::<String>("", "renewer_did")? != did
                || persisted.try_get::<i64>("", "epoch")? != epoch {
                return Err(ControlError("renewer_identity_changed"));
            }
            if did != identity.renewer_did || epoch != identity.epoch as i64 {
                return Err(ControlError("renewer_identity_changed"));
            }
            let snapshot = super::load_renewal_snapshot(&tx, &[original, lease],
                &identity.stable_node_did, &identity.renewer_did, identity.epoch, now).await?;
            super::live_chain_effective_ends(&snapshot, &original, now)
                .map_err(|error| match error {
                    super::RenewalStoreError::Db(_) => ControlError("renewal_state_unavailable"),
                    super::RenewalStoreError::Revoked => ControlError("grant_revoked"),
                    _ => ControlError("grant_expired"),
                })?;
            super::live_chain_effective_ends(&snapshot, &lease, now)
                .map_err(|error| match error {
                    super::RenewalStoreError::Db(_) => ControlError("renewal_state_unavailable"),
                    super::RenewalStoreError::Revoked => ControlError("lease_revoked"),
                    _ => ControlError("lease_expired"),
                })?;
            let others = tx.query_all(Statement::from_sql_and_values(backend,
                "SELECT lease_cid FROM renewal_lease WHERE original_canonical = $1 AND renewer_epoch = $2 AND lease_expiry > $3 AND state IN ('active', 'stopped')",
                [SqlValue::Bytes(Some(Box::new(original_bytes.clone()))), SqlValue::BigInt(Some(epoch)),
                 SqlValue::TimeDateTime(Some(Box::new(super::db_datetime(now)?)))])).await?;
            let mut live = 0;
            for other in others {
                let bytes: Vec<u8> = other.try_get("", "lease_cid")?;
                let id = super::Hash::try_from(bytes).map_err(|_| ControlError("renewal_state_unavailable"))?;
                if !super::is_revoked_chain(&tx, &id).await? { live += 1; }
            }
            if live > 1 { return Err(ControlError("ambiguous_renewal_lease")); }
            let (before, after) = match operation {
                Operation::Stop => ("active", "stopped"),
                Operation::Enable => ("stopped", "active"),
                Operation::Read => unreachable!(),
            };
            if state != before || generation != Some(current as u64) || current as u64 >= MAX_GENERATION {
                return Err(ControlError("renewal_state_conflict"));
            }
            let updated = tx.execute(Statement::from_sql_and_values(backend,
                "UPDATE renewal_lease SET state = $1, generation = generation + 1 WHERE original_canonical = $2 AND lease_cid = $3 AND state = $4 AND generation = $5",
                [SqlValue::String(Some(Box::new(after.to_string()))), SqlValue::Bytes(Some(Box::new(original_bytes))),
                 SqlValue::Bytes(Some(Box::new(lease_bytes))), SqlValue::String(Some(Box::new(before.to_string()))), SqlValue::BigInt(Some(current))])).await?;
            if updated.rows_affected() != 1 { return Err(ControlError("renewal_state_conflict")); }
            state = after.to_string();
            current += 1;
        }
        Ok(StateReceipt { version: 1, original_cid: original.to_cid(0x55).to_string(),
            lease_cid: request.lease_cid, state, generation: current as u64,
            lease_end: end.format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| ControlError("renewal_state_unavailable"))? })
    }.await;
    match result {
        Ok(receipt) => {
            tx.commit().await?;
            Ok(receipt)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}
