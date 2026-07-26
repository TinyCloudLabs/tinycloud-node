use super::super::{
    encryption_network::NetworkId,
    events::{Invocation, VersionedOperation},
    models::*,
    relationships::*,
    util,
};
use crate::encryption::ColumnEncryption;
use crate::models::did_resolution::did_resolution_timeout;
use crate::policy_capability::sql_caveat;
use crate::types::{Caveats, Facts, Resource, SpaceIdWrap};
use crate::write_hooks::{hook_delivery_id, subscription_matches_event};
use crate::{hash::Hash, types::Ability};
use sea_orm::{
    entity::prelude::*,
    sea_query::{Alias, Expr, OnConflict},
    Condition, ConnectionTrait, DatabaseBackend, QueryFilter, QueryOrder,
};
use serde::Serialize;
use std::collections::HashMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{
    authorization::TinyCloudInvocation, identity::did_principal_matches, resource::Path,
    ssi::dids::AnyDidMethod,
};

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
    /// W1 (C): the directly-cited delegation has been revoked.
    /// Code: `delegation-revoked`.
    #[error("delegation-revoked: {0}")]
    DelegationRevoked(String),
    /// W1 (C): an attenuable ancestor of the cited delegation has been
    /// revoked. Code: `delegation-ancestor-revoked`.
    #[error("delegation-ancestor-revoked: ancestor={ancestor_cid} invoked={invoked_cid}")]
    DelegationAncestorRevoked {
        ancestor_cid: String,
        invoked_cid: String,
    },
    #[error("delegation-chain-traversal-limit-exceeded")]
    ChainTraversalLimitExceeded,
    /// W1: invocation caveats are not a subset of the chain's caveats — the
    /// invoker tried to widen or replace a constrained-statements caveat
    /// the delegation chain carried (audit P0 finding 1, applied at the
    /// invocation boundary).
    #[error("invocation-caveats-not-subset-of-chain: {0}")]
    CaveatsNotContained(String),
}

pub(crate) async fn process<C: ConnectionTrait>(
    db: &C,
    invocation: Invocation,
    ops: Vec<VersionedOperation>,
    encryption: Option<&ColumnEncryption>,
    auth_graph: Option<&crate::auth_graph::AuthGraphSnapshot>,
) -> Result<Hash, Error> {
    let (i, serialized) = (invocation.0, invocation.1);
    verify_invocation(&i.invocation).await?;

    let now = OffsetDateTime::now_utc();
    validate(db, &i, Some(now), auth_graph).await?;

    save(db, i, Some(now), serialized, ops, encryption).await
}

/// Persist a mutation whose authorization was completed by a trusted
/// application protocol before it entered the database transaction. The
/// caller must use the private `Event::InternalInvocation` path; public
/// invocations must continue to use `process`.
pub(crate) async fn process_internal<C: ConnectionTrait>(
    db: &C,
    invocation: Invocation,
    ops: Vec<VersionedOperation>,
    encryption: Option<&ColumnEncryption>,
) -> Result<Hash, Error> {
    let (i, serialized) = (invocation.0, invocation.1);
    save(
        db,
        i,
        Some(OffsetDateTime::now_utc()),
        serialized,
        ops,
        encryption,
    )
    .await
}

pub async fn verify_invocation(invocation: &TinyCloudInvocation) -> Result<(), Error> {
    tokio::time::timeout(
        did_resolution_timeout(),
        invocation
            // TODO go back to static DID_METHODS
            .verify_signature(&AnyDidMethod::default()),
    )
    .await
    .map_err(|_| InvocationError::InvalidSignature)?
    .map_err(|_| InvocationError::InvalidSignature)?;
    invocation
        .payload()
        .validate_time(None)
        .map_err(|_| InvocationError::InvalidTime)?;
    Ok(())
}

/// Verify an invocation and authorize its capabilities against the persisted
/// delegation chain without recording an invocation event.
pub async fn verify_and_authorize<C: ConnectionTrait>(
    db: &C,
    invocation: &util::InvocationInfo,
    now: OffsetDateTime,
) -> Result<(), Error> {
    verify_invocation(&invocation.invocation).await?;
    validate(db, invocation, Some(now), None).await
}

// verify parenthood and authorization
async fn validate<C: ConnectionTrait>(
    db: &C,
    invocation: &util::InvocationInfo,
    time: Option<OffsetDateTime>,
    auth_graph: Option<&crate::auth_graph::AuthGraphSnapshot>,
) -> Result<(), Error> {
    // get caps which rely on delegated caps
    let dependant_caps: Vec<_> = invocation
        .capabilities
        .iter()
        .filter(|c| {
            // remove caps for which the invoker is the root authority
            !is_root_authority(c, &invocation.invoker)
        })
        .collect();

    match (dependant_caps.is_empty(), invocation.parents.is_empty()) {
        // no dependant caps, no parents needed, must be valid
        (true, _) => Ok(()),
        // dependant caps, no parents, invalid
        (false, true) => Err(InvocationError::MissingParents.into()),
        // dependant caps, parents, check parents
        (false, false) => {
            // TC-269: batch-load the whole authorization graph once inside
            // the invocation transaction (parent edges, delegation rows,
            // cited abilities/caveats, revocations) and run every chain
            // check against that single consistent snapshot instead of
            // re-walking the database per parent and per ancestor.
            let root_ids: Vec<Hash> = invocation.parents.iter().map(|c| Hash::from(*c)).collect();
            let loaded_graph;
            let graph = match auth_graph {
                Some(graph) => graph,
                None => {
                    loaded_graph = crate::auth_graph::AuthGraphSnapshot::load(db, &root_ids)
                        .await
                        .map_err(|error| match error {
                            crate::auth_graph::ChainTraversalError::Db(error) => Error::Db(error),
                            crate::auth_graph::ChainTraversalError::LimitExceeded => {
                                Error::InvalidInvocation(
                                    InvocationError::ChainTraversalLimitExceeded,
                                )
                            }
                        })?;
                    &loaded_graph
                }
            };

            // every cited parent must resolve to a distinct persisted row
            let mut cited = std::collections::HashSet::new();
            let mut parents = Vec::with_capacity(root_ids.len());
            for id in &root_ids {
                match graph.delegation(id) {
                    Some(row) if cited.insert(*id) => parents.push((row, graph.abilities(id))),
                    _ => return Err(InvocationError::MissingParents.into()),
                }
            }

            // check parent identifies correct invoker
            for (p, _) in &parents {
                if !did_principal_matches(&p.delegatee, &invocation.invoker) {
                    return Err(
                        InvocationError::UnauthorizedInvoker(invocation.invoker.clone()).into(),
                    );
                }
            }

            // W1 (C): fail-closed on revocation. A revoked leaf rejects the
            // invocation outright; a revoked ANCESTOR in the cited chain
            // rejects descendants. Loaded on every invocation — we must
            // NOT cache "chain ok" across the revocation event
            // (revocation.md §2.3).
            for (p, _) in &parents {
                if graph.is_revoked(&p.id) {
                    return Err(
                        InvocationError::DelegationRevoked(p.id.to_cid(0x55).to_string()).into(),
                    );
                }
                if let Some(ancestor_cid) = graph.first_revoked_ancestor(&p.id) {
                    return Err(InvocationError::DelegationAncestorRevoked {
                        ancestor_cid,
                        invoked_cid: p.id.to_cid(0x55).to_string(),
                    }
                    .into());
                }

                // A child capability cannot outlive or predate any delegation
                // in the chain that authorizes it. Validate the effective
                // chain window, not only the directly cited leaf. A chain
                // node without a persisted delegation row (malformed graph)
                // fails closed as a missing parent.
                let chain_now = time.unwrap_or_else(OffsetDateTime::now_utc);
                for chain_id in graph.chain_ids_from(&p.id) {
                    let Some(ancestor) = graph.delegation(&chain_id) else {
                        return Err(InvocationError::MissingParents.into());
                    };
                    if ancestor
                        .expiry
                        .map(|expiry| chain_now >= expiry)
                        .unwrap_or(false)
                        || ancestor
                            .not_before
                            .map(|not_before| chain_now < not_before)
                            .unwrap_or(false)
                    {
                        return match dependant_caps.first() {
                            Some(capability) => Err(InvocationError::UnauthorizedAction(
                                capability.resource.clone(),
                                capability.ability.clone(),
                            )
                            .into()),
                            None => Err(InvocationError::MissingParents.into()),
                        };
                    }
                }
            }

            let now = time.unwrap_or_else(OffsetDateTime::now_utc);

            // only use parents which are valid at the time of invocation
            let parents: Vec<_> = parents
                .into_iter()
                .filter(|(p, _)| {
                    p.expiry.map(|pexp| now < pexp).unwrap_or(true)
                        && p.not_before.map(|pnbf| now >= pnbf).unwrap_or(true)
                })
                .collect();

            // W1 caveat-aware containment at the invocation boundary
            // (audit P0 finding 1): each invocation capability must be
            // supported by a parent ability AND any chain-level caveat must
            // contain the invocation's caveat. Invocation-supplied caveats
            // are NOT trusted on their own — they are only authorized when
            // the persisted chain ability row already has a matching or
            // stricter caveat.
            for c in &dependant_caps {
                // TC-119: ability containment is registry-aware. A parent
                // ability supports the invoked ability when it is equal OR a
                // registry-declared alias (`kv/delete`↔`kv/del`) OR implies it
                // (`sql/admin` ⊃ `sql/schema`; `sql/*` ⊃ every sql action).
                // This is a strict widening of the previous `c.ability ==
                // pc.ability`: exact matches still match, only registry
                // alias/implication pairs are added.
                let mut candidates = parents
                    .iter()
                    .flat_map(|(_, a)| a.iter())
                    .filter(|pc| {
                        c.resource.extends(&pc.resource)
                            && crate::policy_capability::ability_matches(
                                pc.ability.as_ref().as_ref(),
                                c.ability.as_ref().as_ref(),
                            )
                    })
                    .peekable();

                if candidates.peek().is_none() {
                    return Err(InvocationError::UnauthorizedAction(
                        c.resource.clone(),
                        c.ability.clone(),
                    )
                    .into());
                }

                let mut last_reason: Option<String> = None;
                let mut authorized = false;
                for pc in candidates {
                    match caveats_contain_child(&pc.caveats, &c.caveats) {
                        Ok(()) => {
                            authorized = true;
                            break;
                        }
                        Err(reason) => last_reason = Some(reason),
                    }
                }
                if !authorized {
                    let reason = last_reason
                        .unwrap_or_else(|| "invocation-caveats-not-subset-of-chain".to_string());
                    return Err(InvocationError::CaveatsNotContained(reason).into());
                }
            }
            Ok(())
        }
    }
}

/// W1 (audit P0 finding 1): same containment helper as the delegation path,
/// applied at invocation. Duplicated rather than shared because the error
/// surface differs and the helper is small.
fn caveats_contain_child(parent: &Caveats, child: &Caveats) -> Result<(), String> {
    let parent_sql = extract_sql_caveat(parent);
    let child_sql = extract_sql_caveat(child);

    match (parent_sql, child_sql) {
        (Some(p), Some(c)) => sql_caveat::contains(&p, &c).map_err(|e| e.as_str().to_string()),
        (Some(_), None) => Err("containment-caveat-required".to_string()),
        (None, _) => {
            if parent.0 == child.0
                || (parent.0.is_empty() && child.0.is_empty())
                || parent.0.is_empty()
            {
                Ok(())
            } else {
                Err("invocation-caveats-not-subset-of-chain".to_string())
            }
        }
    }
}

fn extract_sql_caveat(
    caveats: &Caveats,
) -> Option<crate::policy_capability::SqlConstrainedStatementCaveat> {
    for v in caveats.0.values() {
        if let Ok(c) = sql_caveat::parse(v) {
            return Some(c);
        }
        if let Some(inner) = v.as_object().and_then(|o| o.get("constrained-statements")) {
            if let Ok(c) = sql_caveat::parse(inner) {
                return Some(c);
            }
        }
    }
    None
}

fn is_root_authority(cap: &util::Capability, invoker: &str) -> bool {
    if cap
        .resource
        .space()
        .map(|o| did_principal_matches(o.did().as_str(), invoker))
        .unwrap_or(false)
    {
        return true;
    }

    match &cap.resource {
        Resource::Other(uri) => uri
            .as_str()
            .parse::<NetworkId>()
            .map(|network_id| did_principal_matches(network_id.owner_did(), invoker))
            .unwrap_or(false),
        Resource::TinyCloud(_) => false,
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
                let write = kv_write::Model {
                    invocation: hash,
                    key: key.clone().into(),
                    value: *value,
                    space: space.clone().into(),
                    metadata: metadata.clone(),
                    seq: *seq,
                    epoch: *epoch,
                    epoch_seq: *epoch_seq,
                };
                kv_write::Entity::insert(kv_write::ActiveModel::from(write.clone()))
                    .exec(db)
                    .await?;
                upsert_current_kv(db, write).await?;
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
                delete_current_kv_if_invocation(
                    db,
                    &SpaceIdWrap(space.clone()),
                    key.as_str(),
                    deleted_invocation_id,
                )
                .await?;
            }
        }
    }

    enqueue_kv_webhook_deliveries(db, hash, &invocation.invoker, issued_at, &parameters).await?;

    Ok(hash)
}

fn incoming_is_newer(existing: current_kv::Entity, incoming: Alias) -> Condition {
    Condition::any()
        .add(
            Expr::col((incoming.clone(), current_kv::Column::Seq))
                .gt(Expr::col((existing, current_kv::Column::Seq))),
        )
        .add(
            Condition::all()
                .add(
                    Expr::col((incoming.clone(), current_kv::Column::Seq))
                        .equals((existing, current_kv::Column::Seq)),
                )
                .add(
                    Expr::col((incoming.clone(), current_kv::Column::Epoch))
                        .gt(Expr::col((existing, current_kv::Column::Epoch))),
                ),
        )
        .add(
            Condition::all()
                .add(
                    Expr::col((incoming.clone(), current_kv::Column::Seq))
                        .equals((existing, current_kv::Column::Seq)),
                )
                .add(
                    Expr::col((incoming.clone(), current_kv::Column::Epoch))
                        .equals((existing, current_kv::Column::Epoch)),
                )
                .add(
                    Expr::col((incoming, current_kv::Column::EpochSeq))
                        .gt(Expr::col((existing, current_kv::Column::EpochSeq))),
                ),
        )
}

pub(crate) async fn upsert_current_kv<C: ConnectionTrait>(
    db: &C,
    write: kv_write::Model,
) -> Result<(), DbErr> {
    let current = current_kv::Model {
        space: write.space,
        key: write.key,
        invocation: write.invocation,
        seq: write.seq,
        epoch: write.epoch,
        epoch_seq: write.epoch_seq,
        value: write.value,
        metadata: write.metadata,
        deleted: false,
    };
    let mut conflict = OnConflict::columns([current_kv::Column::Space, current_kv::Column::Key]);
    if db.get_database_backend() == DatabaseBackend::MySql {
        // MySQL ignores ON CONFLICT's action WHERE. Keep the ordering fields
        // until last because ON DUPLICATE KEY assignments are evaluated left
        // to right.
        const NEWER: &str = "VALUES(`seq`) > `seq` OR (VALUES(`seq`) = `seq` AND VALUES(`epoch`) > `epoch`) OR (VALUES(`seq`) = `seq` AND VALUES(`epoch`) = `epoch` AND VALUES(`epoch_seq`) > `epoch_seq`)";
        for (column, incoming) in [
            (current_kv::Column::Invocation, "invocation"),
            (current_kv::Column::Value, "value"),
            (current_kv::Column::Metadata, "metadata"),
            (current_kv::Column::Deleted, "deleted"),
            (current_kv::Column::EpochSeq, "epoch_seq"),
            (current_kv::Column::Epoch, "epoch"),
            (current_kv::Column::Seq, "seq"),
        ] {
            conflict.value(
                column,
                Expr::cust(format!(
                    "CASE WHEN {NEWER} THEN VALUES(`{incoming}`) ELSE `{incoming}` END"
                )),
            );
        }
    } else {
        conflict
            .update_columns([
                current_kv::Column::Invocation,
                current_kv::Column::Seq,
                current_kv::Column::Epoch,
                current_kv::Column::EpochSeq,
                current_kv::Column::Value,
                current_kv::Column::Metadata,
                current_kv::Column::Deleted,
            ])
            .action_cond_where(incoming_is_newer(
                current_kv::Entity,
                Alias::new("excluded"),
            ));
    }
    match current_kv::Entity::insert(current_kv::ActiveModel::from(current))
        .on_conflict(conflict.to_owned())
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn delete_current_kv_if_invocation<C: ConnectionTrait>(
    db: &C,
    space: &SpaceIdWrap,
    key: &str,
    invocation: Hash,
) -> Result<(), DbErr> {
    current_kv::Entity::update_many()
        .col_expr(current_kv::Column::Deleted, Expr::value(true))
        .filter(current_kv::Column::Space.eq(space.clone()))
        .filter(current_kv::Column::Key.eq(key))
        .filter(current_kv::Column::Invocation.eq(invocation))
        .exec(db)
        .await
        .map(|_| ())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct KvWebhookPayload {
    #[serde(rename = "type")]
    event_type: String,
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
            event_type: "write".to_string(),
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
            .filter(|subscription| subscription_matches_event(subscription, key.as_str(), ability))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, Statement, TransactionTrait,
    };
    use sea_orm_migration::MigratorTrait;
    use std::collections::BTreeMap;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        resource::SpaceId,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    fn test_space(name: &str) -> SpaceId {
        let did: DIDBuf = DID_METHODS
            .generate(&JWK::generate_ed25519().unwrap(), "key")
            .unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    fn test_write(space: &SpaceId, key: &str, label: &str, seq: i64) -> kv_write::Model {
        kv_write::Model {
            space: SpaceIdWrap(space.clone()),
            key: key.parse::<Path>().unwrap().into(),
            invocation: crate::hash::hash(format!("invocation-{label}").as_bytes()),
            seq,
            epoch: crate::hash::hash(format!("epoch-{label}").as_bytes()),
            epoch_seq: 0,
            value: crate::hash::hash(format!("value-{label}").as_bytes()),
            metadata: crate::types::Metadata(BTreeMap::from([(
                "label".to_string(),
                label.to_string(),
            )])),
        }
    }

    #[tokio::test]
    async fn projection_updates_are_atomic_ordered_and_version_safe() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys = OFF".to_string(),
        ))
        .await
        .unwrap();
        let space = test_space("projection-atomic");
        let newer = test_write(&space, "ordered", "newer", 2);
        let older = test_write(&space, "ordered", "older", 1);

        for write in [newer.clone(), older.clone()] {
            let tx = db.begin().await.unwrap();
            kv_write::ActiveModel::from(write.clone())
                .insert(&tx)
                .await
                .unwrap();
            upsert_current_kv(&tx, write).await.unwrap();
            tx.commit().await.unwrap();
        }

        let current = current_kv::Entity::find_by_id((
            SpaceIdWrap(space.clone()),
            "ordered".parse::<Path>().unwrap().into(),
        ))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
        assert_eq!(current.invocation, newer.invocation);
        assert_eq!(kv_write::Entity::find().count(&db).await.unwrap(), 2);

        for (label, deleted) in [("delete-older", &older), ("delete-newer", &newer)] {
            let delete_invocation = crate::hash::hash(label.as_bytes());
            let tx = db.begin().await.unwrap();
            kv_delete::ActiveModel {
                invocation_id: Set(delete_invocation),
                space: Set(SpaceIdWrap(space.clone())),
                key: Set("ordered".parse::<Path>().unwrap().into()),
                deleted_invocation_id: Set(deleted.invocation),
            }
            .insert(&tx)
            .await
            .unwrap();
            delete_current_kv_if_invocation(
                &tx,
                &SpaceIdWrap(space.clone()),
                "ordered",
                deleted.invocation,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();

            let current = current_kv::Entity::find_by_id((
                SpaceIdWrap(space.clone()),
                "ordered".parse::<Path>().unwrap().into(),
            ))
            .one(&db)
            .await
            .unwrap();
            if label == "delete-older" {
                assert_eq!(current.unwrap().invocation, newer.invocation);
            } else {
                let watermark = current.unwrap();
                assert!(watermark.deleted);
                assert_eq!(watermark.invocation, newer.invocation);
            }
        }
        assert_eq!(kv_write::Entity::find().count(&db).await.unwrap(), 2);
        assert_eq!(kv_delete::Entity::find().count(&db).await.unwrap(), 2);

        let rolled_back = test_write(&space, "ordered", "rolled-back", 3);
        let tx = db.begin().await.unwrap();
        kv_write::ActiveModel::from(rolled_back.clone())
            .insert(&tx)
            .await
            .unwrap();
        upsert_current_kv(&tx, rolled_back).await.unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(kv_write::Entity::find().count(&db).await.unwrap(), 2);
        let watermark = current_kv::Entity::find_by_id((
            SpaceIdWrap(space),
            "ordered".parse::<Path>().unwrap().into(),
        ))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
        assert!(watermark.deleted);
        assert_eq!(watermark.invocation, newer.invocation);
    }

    #[tokio::test]
    async fn older_write_cannot_resurrect_a_deleted_newer_version() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys = OFF".to_string(),
        ))
        .await
        .unwrap();
        let space = test_space("projection-deleted-watermark");
        let newer = test_write(&space, "ordered", "newer-deleted", 2);
        let older = test_write(&space, "ordered", "older-late", 1);

        kv_write::ActiveModel::from(newer.clone())
            .insert(&db)
            .await
            .unwrap();
        upsert_current_kv(&db, newer.clone()).await.unwrap();
        kv_delete::ActiveModel {
            invocation_id: Set(crate::hash::hash(b"delete-newer")),
            space: Set(SpaceIdWrap(space.clone())),
            key: Set("ordered".parse::<Path>().unwrap().into()),
            deleted_invocation_id: Set(newer.invocation),
        }
        .insert(&db)
        .await
        .unwrap();
        delete_current_kv_if_invocation(
            &db,
            &SpaceIdWrap(space.clone()),
            "ordered",
            newer.invocation,
        )
        .await
        .unwrap();

        kv_write::ActiveModel::from(older.clone())
            .insert(&db)
            .await
            .unwrap();
        upsert_current_kv(&db, older).await.unwrap();

        let watermark = current_kv::Entity::find_by_id((
            SpaceIdWrap(space),
            "ordered".parse::<Path>().unwrap().into(),
        ))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
        assert!(watermark.deleted);
        assert_eq!(watermark.invocation, newer.invocation);
    }

    #[tokio::test]
    async fn conditional_upsert_uses_full_lexicographic_order() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        let space = test_space("projection-order");

        let seq_newer = test_write(&space, "by-seq", "seq-newer", 2);
        let seq_older = test_write(&space, "by-seq", "seq-older", 1);
        for write in [seq_newer.clone(), seq_older] {
            upsert_current_kv(&db, write).await.unwrap();
        }

        let mut epoch_a = test_write(&space, "by-epoch", "epoch-a", 3);
        let mut epoch_b = test_write(&space, "by-epoch", "epoch-b", 3);
        let (epoch_newer, epoch_older) = if epoch_a.epoch > epoch_b.epoch {
            (epoch_a.clone(), epoch_b.clone())
        } else {
            (epoch_b.clone(), epoch_a.clone())
        };
        upsert_current_kv(&db, epoch_newer.clone()).await.unwrap();
        upsert_current_kv(&db, epoch_older).await.unwrap();

        epoch_a.key = "by-epoch-seq".parse::<Path>().unwrap().into();
        epoch_b.key = epoch_a.key.clone();
        epoch_a.epoch = crate::hash::hash(b"same-epoch");
        epoch_b.epoch = epoch_a.epoch;
        epoch_a.epoch_seq = 2;
        epoch_b.epoch_seq = 1;
        upsert_current_kv(&db, epoch_a.clone()).await.unwrap();
        upsert_current_kv(&db, epoch_b).await.unwrap();

        for (key, invocation) in [
            ("by-seq", seq_newer.invocation),
            ("by-epoch", epoch_newer.invocation),
            ("by-epoch-seq", epoch_a.invocation),
        ] {
            let current = current_kv::Entity::find_by_id((
                SpaceIdWrap(space.clone()),
                key.parse::<Path>().unwrap().into(),
            ))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
            assert_eq!(current.invocation, invocation);
        }
    }

    #[tokio::test]
    async fn existing_child_chain_is_rejected_after_parent_revocation() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();

        for actor_id in ["did:key:owner", "did:key:parent", "did:key:child"] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        let parent_id = crate::hash::hash(b"parent");
        let child_id = crate::hash::hash(b"existing-child");
        for (id, delegator, delegatee) in [
            (parent_id, "did:key:owner", "did:key:parent"),
            (child_id, "did:key:parent", "did:key:child"),
        ] {
            delegation::ActiveModel {
                id: Set(id),
                delegator: Set(delegator.to_string()),
                delegatee: Set(delegatee.to_string()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        parent_delegations::ActiveModel {
            parent: Set(parent_id),
            child: Set(child_id),
        }
        .insert(&db)
        .await
        .unwrap();
        revocation::ActiveModel {
            id: Set(crate::hash::hash(b"revocation")),
            revoker: Set("did:key:owner".to_string()),
            revoked: Set(parent_id),
            serialization: Set(b"revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db)
        .await
        .unwrap();

        assert_eq!(
            revocation::first_revoked_ancestor(&db, &child_id)
                .await
                .unwrap(),
            Some(parent_id.to_cid(0x55).to_string())
        );
    }

    #[test]
    fn kv_webhook_payload_serializes_with_type_field() {
        let payload = KvWebhookPayload {
            event_type: "write".to_string(),
            id: "epoch:0".to_string(),
            space: "tinycloud:space".to_string(),
            service: "kv".to_string(),
            ability: "tinycloud.kv/put".to_string(),
            path: Some("docs/1".to_string()),
            actor: "did:key:test".to_string(),
            epoch: "epoch".to_string(),
            event_index: 0,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("write"));
    }

    // W1 (audit P0 finding 1) — caveats helper unit tests. We test the
    // pure-function `caveats_contain_child` and `extract_sql_caveat`
    // helpers here since they encode the spec rule that an invocation
    // cannot widen, drop, or replace the chain caveat. DB-backed tests
    // live next to the delegation::process integration tests so the
    // chain's persisted caveats actually round-trip through the abilities
    // row.
    fn make_sql_constrained_caveat(name: &str, sql: &str) -> Caveats {
        use serde_json::json;
        let mut map = BTreeMap::new();
        map.insert(
            "0".to_string(),
            json!({
                "mode": "constrained-statements",
                "readOnly": true,
                "statements": [{
                    "name": name,
                    "sql": sql,
                    "fixedParams": []
                }]
            }),
        );
        Caveats(map)
    }

    fn make_pinned_caveat(name: &str, sql: &str, index: i64, value: serde_json::Value) -> Caveats {
        use serde_json::json;
        let mut map = BTreeMap::new();
        map.insert(
            "0".to_string(),
            json!({
                "mode": "constrained-statements",
                "readOnly": true,
                "statements": [{
                    "name": name,
                    "sql": sql,
                    "fixedParams": [{"index": index, "value": value}]
                }]
            }),
        );
        Caveats(map)
    }

    #[test]
    fn invocation_caveats_must_match_parent_caveats_subset() {
        let parent = make_sql_constrained_caveat("get", "SELECT 1");
        let child_same = make_sql_constrained_caveat("get", "SELECT 1");
        let child_different_sql = make_sql_constrained_caveat("get", "SELECT 2");
        let child_added_stmt = {
            use serde_json::json;
            let mut map = BTreeMap::new();
            map.insert(
                "0".to_string(),
                json!({
                    "mode": "constrained-statements",
                    "readOnly": true,
                    "statements": [
                        {"name":"get","sql":"SELECT 1","fixedParams":[]},
                        {"name":"extra","sql":"SELECT 99","fixedParams":[]}
                    ]
                }),
            );
            Caveats(map)
        };

        caveats_contain_child(&parent, &child_same).expect("identical caveat must be contained");
        let err = caveats_contain_child(&parent, &child_different_sql)
            .expect_err("changing bound SQL must be rejected");
        assert!(
            err == "containment-sql-statement-added" || err == "child-caveats-not-subset-of-parent",
            "unexpected reason: {err}",
        );
        caveats_contain_child(&parent, &child_added_stmt)
            .expect_err("child must not add statements the parent never granted");
    }

    #[test]
    fn invocation_dropping_chain_caveat_is_rejected() {
        let parent = make_sql_constrained_caveat("get", "SELECT 1");
        let child_empty = Caveats::default();
        let err = caveats_contain_child(&parent, &child_empty)
            .expect_err("child cannot drop the parent's caveat");
        assert_eq!(err, "containment-caveat-required");
    }

    #[test]
    fn invocation_widening_pinned_fixed_param_is_rejected() {
        let parent =
            make_pinned_caveat("get", "SELECT * FROM t WHERE id=?", 0, serde_json::json!(7));
        let child = make_sql_constrained_caveat("get", "SELECT * FROM t WHERE id=?");
        let err = caveats_contain_child(&parent, &child)
            .expect_err("child dropping pinned fixedParam must be rejected");
        assert_eq!(err, "containment-sql-fixed-param-dropped");
    }

    #[test]
    fn invocation_with_no_chain_caveat_can_be_any() {
        let parent = Caveats::default();
        let child_with_constraints = make_sql_constrained_caveat("get", "SELECT 1");
        caveats_contain_child(&parent, &child_with_constraints)
            .expect("narrowing on an unconstrained parent must be allowed");
    }
}
