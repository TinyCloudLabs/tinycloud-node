use super::super::{
    events::{Invocation, VersionedOperation},
    models::*,
    relationships::*,
    util,
};
use crate::encryption::ColumnEncryption;
use crate::hash::Blake3Hasher;
use crate::types::{Facts, Resource, SpaceIdWrap};
use crate::{hash::Hash, types::Ability};
use sea_orm::{
    entity::prelude::*, sea_query::OnConflict, Condition, ConnectionTrait, QueryFilter, QueryOrder,
};
use serde::Serialize;
use std::collections::HashMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{authorization::TinyCloudInvocation, resource::Path, ssi::dids::AnyDidMethod};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "invocation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Hash,

    pub invoker: String,
    pub issued_at: OffsetDateTime,
    pub facts: Option<Facts>,
    pub serialization: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    // inverse relation, invocations belong to invokers
    #[sea_orm(
        belongs_to = "actor::Entity",
        from = "Column::Invoker",
        to = "actor::Column::Id"
    )]
    Invoker,
    #[sea_orm(has_many = "invoked_abilities::Entity")]
    InvokedAbilities,
}

impl Related<actor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Invoker.def()
    }
}

impl Related<invoked_abilities::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::InvokedAbilities.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error(transparent)]
    InvalidInvocation(#[from] InvocationError),
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error("Invocation expired or not yet valid")]
    InvalidTime,
    #[error("Failed to verify signature")]
    InvalidSignature,
    #[error("Unauthorized Invoker")]
    UnauthorizedInvoker(String),
    #[error("Unauthorized Action: {0} / {1}")]
    UnauthorizedAction(Resource, Ability),
    #[error("Cannot find parent delegation")]
    MissingParents,
    #[error("No Such Key: {0}")]
    MissingKvWrite(Path),
}

pub(crate) async fn process<C: ConnectionTrait>(
    db: &C,
    invocation: Invocation,
    ops: Vec<VersionedOperation>,
    encryption: Option<&ColumnEncryption>,
) -> Result<Hash, Error> {
    let (i, serialized) = (invocation.0, invocation.1);
    verify(&i.invocation).await?;

    let now = OffsetDateTime::now_utc();
    validate(db, &i, Some(now)).await?;

    save(db, i, Some(now), serialized, ops, encryption).await
}

async fn verify(invocation: &TinyCloudInvocation) -> Result<(), Error> {
    invocation
        // TODO go back to static DID_METHODS
        .verify_signature(&AnyDidMethod::default())
        .await
        .map_err(|_| InvocationError::InvalidSignature)?;
    invocation
        .payload()
        .validate_time(None)
        .map_err(|_| InvocationError::InvalidTime)?;
    Ok(())
}

// verify parenthood and authorization
async fn validate<C: ConnectionTrait>(
    db: &C,
    invocation: &util::InvocationInfo,
    time: Option<OffsetDateTime>,
) -> Result<(), Error> {
    // get caps which rely on delegated caps
    let dependant_caps: Vec<_> = invocation
        .capabilities
        .iter()
        .filter(|c| {
            // remove caps for which the invoker is the root authority
            c.resource
                .space()
                .map(|o| **o.did() != *invocation.invoker)
                .unwrap_or(true)
        })
        .collect();

    match (dependant_caps.is_empty(), invocation.parents.is_empty()) {
        // no dependant caps, no parents needed, must be valid
        (true, _) => Ok(()),
        // dependant caps, no parents, invalid
        (false, true) => Err(InvocationError::MissingParents.into()),
        // dependant caps, parents, check parents
        (false, false) => {
            // get parents which have
            let parents = delegation::Entity::find()
                // the correct id
                .filter(
                    delegation::Column::Id.is_in(invocation.parents.iter().map(|c| Hash::from(*c))),
                )
                // and also get their abilities
                .find_with_related(abilities::Entity)
                .all(db)
                .await?;

            // check parent identifies correct invoker
            parents
                .iter()
                .map(|(p, _)| {
                    if p.delegatee != invocation.invoker
                        && !invocation.invoker.starts_with(&p.delegatee)
                    {
                        Err(InvocationError::UnauthorizedInvoker(
                            invocation.invoker.clone(),
                        ))
                    } else {
                        Ok(())
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;

            let now = time.unwrap_or_else(OffsetDateTime::now_utc);

            // only use parents which are valid at the time of invocation
            let parents: Vec<_> = parents
                .into_iter()
                .filter(|(p, _)| {
                    p.expiry.map(|pexp| now < pexp).unwrap_or(true)
                        && p.not_before.map(|pnbf| now >= pnbf).unwrap_or(true)
                })
                .collect();

            // check each dependant cap is supported by at least one parent cap
            match dependant_caps.iter().find(|c| {
                !parents
                    .iter()
                    .flat_map(|(_, a)| a)
                    .any(|pc| c.resource.extends(&pc.resource) && c.ability == pc.ability)
            }) {
                Some(c) => Err(InvocationError::UnauthorizedAction(
                    c.resource.clone(),
                    c.ability.clone(),
                )
                .into()),
                None => Ok(()),
            }
        }
    }
}

async fn save<C: ConnectionTrait>(
    db: &C,
    invocation: util::InvocationInfo,
    time: Option<OffsetDateTime>,
    serialization: Vec<u8>,
    parameters: Vec<VersionedOperation>,
    encryption: Option<&ColumnEncryption>,
) -> Result<Hash, Error> {
    // Hash is always computed on plaintext (before encryption)
    let hash = crate::hash::hash(&serialization);
    let issued_at = time.unwrap_or_else(OffsetDateTime::now_utc);
    let invoker = invocation.invoker.clone();

    // Encrypt for storage if encryption is configured
    let stored_serialization = crate::encryption::maybe_encrypt(encryption, &serialization);

    // Ensure the invoker actor exists before inserting the invocation
    match actor::Entity::insert(actor::ActiveModel::from(actor::Model {
        id: invocation.invoker.clone(),
    }))
    .on_conflict(
        OnConflict::column(actor::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .exec(db)
    .await
    {
        Err(DbErr::RecordNotInserted) => (),
        r => {
            r?;
        }
    };

    match Entity::insert(ActiveModel::from(Model {
        id: hash,
        issued_at,
        serialization: stored_serialization,
        facts: None,
        invoker,
    }))
    .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned())
    .exec(db)
    .await
    {
        Err(DbErr::RecordNotInserted) => return Ok(hash),
        r => {
            r?;
        }
    };

    // save invoked abilities
    if !invocation.capabilities.is_empty() {
        invoked_abilities::Entity::insert_many(invocation.capabilities.into_iter().map(|c| {
            invoked_abilities::ActiveModel::from(invoked_abilities::Model {
                invocation: hash,
                resource: c.resource,
                ability: c.ability,
            })
        }))
        .exec(db)
        .await?;
    }
    // save parent relationships
    if !invocation.parents.is_empty() {
        parent_delegations::Entity::insert_many(invocation.parents.into_iter().map(|p| {
            parent_delegations::ActiveModel::from(parent_delegations::Model {
                child: hash,
                parent: p.into(),
            })
        }))
        .exec(db)
        .await?;
    }

    for param in &parameters {
        match param {
            VersionedOperation::KvWrite {
                key,
                value,
                metadata,
                space,
                seq,
                epoch,
                epoch_seq,
            } => {
                kv_write::Entity::insert(kv_write::ActiveModel::from(kv_write::Model {
                    invocation: hash,
                    key: key.clone().into(),
                    value: *value,
                    space: space.clone().into(),
                    metadata: metadata.clone(),
                    seq: *seq,
                    epoch: *epoch,
                    epoch_seq: *epoch_seq,
                }))
                .exec(db)
                .await?;
            }
            VersionedOperation::KvDelete {
                key,
                version,
                space,
                seq: _,
                epoch: _,
                epoch_seq: _,
            } => {
                let deleted_invocation_id = if let Some((s, e, es)) = version {
                    kv_write::Entity::find().filter(
                        Condition::all()
                            .add(kv_write::Column::Key.eq(key.as_str()))
                            .add(kv_write::Column::Space.eq(SpaceIdWrap(space.clone())))
                            .add(kv_write::Column::Seq.eq(*s))
                            .add(kv_write::Column::Epoch.eq(*e))
                            .add(kv_write::Column::EpochSeq.eq(*es)),
                    )
                } else {
                    kv_write::Entity::find()
                        .filter(kv_write::Column::Key.eq(key.as_str()))
                        .filter(kv_write::Column::Space.eq(SpaceIdWrap(space.clone())))
                        .order_by_desc(kv_write::Column::Seq)
                        .order_by_desc(kv_write::Column::Epoch)
                        .order_by_desc(kv_write::Column::EpochSeq)
                }
                .one(db)
                .await?
                .ok_or_else(|| InvocationError::MissingKvWrite(key.clone()))?
                .invocation;
                kv_delete::Entity::insert(kv_delete::ActiveModel::from(kv_delete::Model {
                    key: key.clone().into(),
                    invocation_id: hash,
                    space: space.clone().into(),
                    deleted_invocation_id,
                }))
                .exec(db)
                .await?;
            }
        }
    }

    enqueue_kv_webhook_deliveries(db, hash, &invocation.invoker, issued_at, &parameters).await?;

    Ok(hash)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct KvWebhookPayload {
    id: String,
    space: String,
    service: String,
    ability: String,
    path: Option<String>,
    actor: String,
    epoch: String,
    event_index: u32,
    timestamp: String,
}

async fn enqueue_kv_webhook_deliveries<C: ConnectionTrait>(
    db: &C,
    invocation_hash: Hash,
    actor: &str,
    issued_at: OffsetDateTime,
    parameters: &[VersionedOperation],
) -> Result<(), DbErr> {
    let timestamp = issued_at
        .format(&Rfc3339)
        .expect("valid invocation timestamps should format as RFC3339");
    let mut cached_subscriptions = HashMap::<String, Vec<hook_subscription::Model>>::new();
    let mut event_indexes = HashMap::<String, u32>::new();

    for parameter in parameters {
        let (space, key, ability, epoch) = match parameter {
            VersionedOperation::KvWrite {
                space, key, epoch, ..
            } => (space, key, "tinycloud.kv/put", epoch),
            VersionedOperation::KvDelete {
                space, key, epoch, ..
            } => (space, key, "tinycloud.kv/del", epoch),
        };

        let space_id = space.to_string();
        let subscriptions = match cached_subscriptions.get(&space_id) {
            Some(subscriptions) => subscriptions,
            None => {
                let rows = hook_subscription::Entity::find()
                    .filter(
                        Condition::all()
                            .add(hook_subscription::Column::Active.eq(true))
                            .add(hook_subscription::Column::SpaceId.eq(space_id.clone()))
                            .add(hook_subscription::Column::TargetService.eq("kv")),
                    )
                    .all(db)
                    .await?;
                cached_subscriptions.insert(space_id.clone(), rows);
                cached_subscriptions
                    .get(&space_id)
                    .expect("inserted subscription cache entry should exist")
            }
        };

        if subscriptions.is_empty() {
            *event_indexes.entry(space_id).or_insert(0) += 1;
            continue;
        }

        let event_index = event_indexes.entry(space.to_string()).or_insert(0);
        let current_index = *event_index;
        let epoch_cid = epoch.to_cid(0x55).to_string();
        let event_id = format!("{epoch_cid}:{current_index}");
        let payload_json = serde_json::to_string(&KvWebhookPayload {
            id: event_id.clone(),
            space: space.to_string(),
            service: "kv".to_string(),
            ability: ability.to_string(),
            path: Some(key.to_string()),
            actor: actor.to_string(),
            epoch: epoch_cid,
            event_index: current_index,
            timestamp: timestamp.clone(),
        })
        .expect("KV webhook payload serialization should succeed");

        let pending = subscriptions
            .iter()
            .filter(|subscription| subscription_matches_kv(subscription, key.as_str(), ability))
            .map(|subscription| {
                hook_delivery::ActiveModel::from(hook_delivery::Model {
                    id: hook_delivery_id(&subscription.id, &event_id),
                    subscription_id: subscription.id.clone(),
                    event_id: event_id.clone(),
                    payload_json: payload_json.clone(),
                    status: crate::db::HOOK_DELIVERY_STATUS_PENDING.to_string(),
                    attempts: 0,
                    next_attempt_at: None,
                    last_error: None,
                    created_at: timestamp.clone(),
                    delivered_at: None,
                })
            })
            .collect::<Vec<_>>();

        if !pending.is_empty() {
            hook_delivery::Entity::insert_many(pending)
                .on_conflict(
                    OnConflict::column(hook_delivery::Column::Id)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(db)
                .await?;
        }

        *event_index += 1;
    }

    let _ = invocation_hash;
    Ok(())
}

fn subscription_matches_kv(
    subscription: &hook_subscription::Model,
    key: &str,
    ability: &str,
) -> bool {
    if !matches_prefix(subscription.path_prefix.as_deref(), key) {
        return false;
    }

    match subscription.abilities() {
        Ok(abilities) => {
            abilities.is_empty() || abilities.iter().any(|candidate| candidate == ability)
        }
        Err(_) => false,
    }
}

fn matches_prefix(prefix: Option<&str>, key: &str) -> bool {
    match prefix.and_then(normalize_prefix) {
        None => true,
        Some(prefix) => key == prefix || key.starts_with(&format!("{prefix}/")),
    }
}

fn normalize_prefix(prefix: &str) -> Option<&str> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn hook_delivery_id(subscription_id: &str, event_id: &str) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(subscription_id.as_bytes());
    hasher.update(b":");
    hasher.update(event_id.as_bytes());
    hasher.finalize().to_cid(0x55).to_string()
}
