//! Immutable, versioned evidence of every owner authority that could have
//! supported a registered policy at its original admission time. Expiry is
//! deliberately not a revocation signal: TC-1213 owns owner-self expiry.
use crate::{
    encryption::ColumnEncryption,
    events::SerializedEvent,
    hash::{hash, Hash},
    models::{
        abilities, delegation, delegation_cid_alias, policy_v3_registration, policy_v3_root,
        revocation,
    },
    policy_capability::{self, sql_caveat},
    relationships::parent_delegations,
    types::{Caveats, Resource},
    util::{Capability, DelegationInfo},
};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use sea_orm::{
    entity::prelude::*, ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::TinyCloudDelegation,
    identity::{did_principal_matches, principal_did},
};

const VERSION: i32 = 1;
const MAX_NODES: usize = revocation::MAX_CHAIN_TRAVERSAL_NODES;
const MAX_CANDIDATES: usize = 64;
const CANDIDATE_PAGE_SIZE: u64 = 128;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_witness")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub policy_cid: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub root_cid: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub capability_index: i32,
    pub version: i32,
    pub registered_at: String,
    pub witness_bytes: Vec<u8>,
    pub witness_digest_hex: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("policy-witness-unavailable")]
    Database(#[from] DbErr),
    #[error("policy-witness-missing")]
    Missing,
    #[error("policy-witness-ambiguous")]
    Ambiguous,
    #[error("policy-witness-traversal-overflow")]
    Overflow,
    #[error("policy-witness-revoked")]
    Revoked,
    #[error("policy-witness-invalid")]
    Invalid,
}

/// Counter-only surface: neither serialization nor Debug includes identifiers.
#[derive(Clone, Copy, Default, Debug, Serialize, PartialEq, Eq)]
pub struct BackfillCounts {
    pub policies: u64,
    pub witnesses: u64,
    pub missing: u64,
    pub ambiguous: u64,
    pub overflow: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Contributor {
    pub cid: String,
    pub canonical_cid: String,
    pub signer: String,
    pub audience: String,
    pub proof_cids: Vec<String>,
    /// Exact verified capability/caveat projections from the signed grant.
    pub signed_capabilities: Vec<Capability>,
    /// UCAN facts as signed (CACAO/SIWE has no UCAN facts).
    pub signed_facts: Vec<serde_json::Value>,
    /// Exact signed bytes, kept independent of the mutable delegation graph.
    pub signed_bytes: Vec<u8>,
    pub not_before: Option<String>,
    pub expiry: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CandidateClosure {
    pub tip_cid: String,
    pub contributors: Vec<Contributor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyWitness {
    pub version: i32,
    pub policy_cid: String,
    pub root_cid: String,
    pub capability_index: i32,
    pub owner_principal: String,
    pub capability: Capability,
    pub registered_at: String,
    /// Unknown/legacy by design. An owner-self natural expiry is NOT a
    /// revocation and must not change policy liveness in this phase.
    pub owner_self_classification: String,
    pub root: Contributor,
    pub candidates: Vec<CandidateClosure>,
}

fn principal(value: &str) -> Result<String, WitnessError> {
    principal_did(value).map_err(|_| WitnessError::Invalid)
}

fn signed_event(bytes: &[u8]) -> Result<crate::events::Delegation, WitnessError> {
    let token = match std::str::from_utf8(bytes) {
        Ok(text)
            if text.split('.').count() == 3
                && text.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'=')
                }) =>
        {
            text.to_owned()
        }
        _ => URL_SAFE.encode(bytes),
    };
    SerializedEvent::<DelegationInfo>::from_header_ser::<TinyCloudDelegation>(&token)
        .map_err(|_| WitnessError::Invalid)
}

async fn signed_contributor(
    bytes: &[u8],
    cid: &str,
    event: &crate::events::Delegation,
) -> Result<Contributor, WitnessError> {
    if event.content_hash().to_cid(0x55).to_string() != cid || event.serialized_bytes() != bytes {
        return Err(WitnessError::Invalid);
    }
    match &event.0.delegation {
        TinyCloudDelegation::Ucan(ucan) => {
            crate::did_resolution::verify_ucan_signature(ucan)
                .await
                .map_err(|_| WitnessError::Invalid)?;
        }
        TinyCloudDelegation::Cacao(cacao) => {
            cacao.verify().await.map_err(|_| WitnessError::Invalid)?;
        }
    }
    Ok(Contributor {
        cid: cid.to_owned(),
        canonical_cid: cid.to_owned(),
        signer: principal(&event.0.delegator)?,
        audience: principal(&event.0.delegate)?,
        proof_cids: event.0.parents.iter().map(ToString::to_string).collect(),
        signed_capabilities: event.0.capabilities.clone(),
        signed_facts: match &event.0.delegation {
            TinyCloudDelegation::Ucan(ucan) => ucan.payload().facts.clone().unwrap_or_default(),
            TinyCloudDelegation::Cacao(_) => Vec::new(),
        },
        signed_bytes: bytes.to_vec(),
        not_before: event.0.not_before.map(format_time).transpose()?,
        expiry: event.0.expiry.map(format_time).transpose()?,
    })
}

fn format_time(at: OffsetDateTime) -> Result<String, WitnessError> {
    at.format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| WitnessError::Invalid)
}

fn active_at(row: &Contributor, at: OffsetDateTime) -> Result<bool, WitnessError> {
    let parse = |value: &str| {
        OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .map_err(|_| WitnessError::Invalid)
    };
    Ok(row
        .not_before
        .as_deref()
        .map(parse)
        .transpose()?
        .is_none_or(|start| at >= start)
        && row
            .expiry
            .as_deref()
            .map(parse)
            .transpose()?
            .is_none_or(|end| at < end))
}

fn signed_policy_artifact(delegation: &TinyCloudDelegation) -> bool {
    match delegation {
        TinyCloudDelegation::Ucan(ucan) => ucan.payload().facts.as_ref().is_some_and(|facts| {
            facts.iter().any(|fact| {
                fact.as_object().is_some_and(|object| {
                    object.contains_key("xyz.tinycloud.policy/session-fact")
                        || object.contains_key("xyz.tinycloud.policy/root-profile")
                })
            })
        }),
        TinyCloudDelegation::Cacao(_) => false,
    }
}

fn sql_caveat(caveats: &Caveats) -> Option<policy_capability::SqlConstrainedStatementCaveat> {
    caveats.0.values().find_map(|value| {
        sql_caveat::parse(value).ok().or_else(|| {
            value
                .as_object()
                .and_then(|object| object.get("constrained-statements"))
                .and_then(|inner| sql_caveat::parse(inner).ok())
        })
    })
}

fn covers(held: &Capability, requested: &Capability) -> bool {
    if !requested.resource.extends(&held.resource)
        || !policy_capability::ability_matches(
            held.ability.as_ref().as_ref(),
            requested.ability.as_ref().as_ref(),
        )
    {
        return false;
    }
    // A signed ReCap `[{}]` (or no caveat) is unconstrained. A valid
    // policy selector that stays inside the requested native resource only
    // narrows it; do not treat the absent parent selector as a conflict.
    let unconstrained = held.caveats.0.is_empty()
        || (held.caveats.0.len() == 1
            && held
                .caveats
                .0
                .values()
                .all(|value| value.as_object().is_some_and(serde_json::Map::is_empty)));
    if unconstrained
        && policy_capability::selector_caveats_contain(&requested.caveats.0, &requested.caveats.0)
            == Some(true)
    {
        return requested
            .caveats
            .0
            .values()
            .next()
            .and_then(|value| value.get("value"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<Resource>().ok())
            .is_some_and(|selector| selector.extends(&requested.resource));
    }
    if let Some(contained) =
        policy_capability::selector_caveats_contain(&held.caveats.0, &requested.caveats.0)
    {
        return contained;
    }
    match (sql_caveat(&held.caveats), sql_caveat(&requested.caveats)) {
        (Some(parent), Some(child)) => sql_caveat::contains(&parent, &child).is_ok(),
        (Some(_), None) => false,
        (None, _) => held.caveats.0.is_empty() || held.caveats == requested.caveats,
    }
}

fn root_authority(capability: &Capability, owner: &str) -> bool {
    capability
        .resource
        .space()
        .is_some_and(|space| did_principal_matches(space.did().as_str(), owner))
        || matches!(&capability.resource, Resource::Other(uri)
            if uri.as_str().parse::<crate::encryption_network::NetworkId>()
                .is_ok_and(|network| did_principal_matches(network.owner_did(), owner)))
}

async fn closure<C: ConnectionTrait>(
    db: &C,
    tip: Hash,
    owner: &str,
    capability: &Capability,
    at: OffsetDateTime,
    encryption: Option<&ColumnEncryption>,
) -> Result<Option<CandidateClosure>, WitnessError> {
    let mut pending = vec![tip];
    let mut visited = BTreeSet::new();
    let mut nodes = BTreeMap::new();
    let mut covering = HashMap::<Hash, bool>::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        if visited.len() > MAX_NODES {
            return Err(WitnessError::Overflow);
        }
        let row = delegation::Entity::find_by_id(id)
            .one(db)
            .await?
            .ok_or(WitnessError::Missing)?;
        let alias = delegation_cid_alias::Entity::find_by_id(id)
            .one(db)
            .await?
            .ok_or(WitnessError::Missing)?;
        let bytes = if alias.encrypted {
            encryption
                .ok_or(WitnessError::Missing)?
                .decrypt(&row.serialization)
                .map_err(|_| WitnessError::Invalid)?
        } else {
            row.serialization.clone()
        };
        if hash(&bytes) != id
            || delegation_cid_alias::canonical_hash(&bytes).map_err(|_| WitnessError::Invalid)?
                != alias.canonical
        {
            return Err(WitnessError::Ambiguous);
        }
        let event = signed_event(&bytes)?;
        let mut contributor =
            signed_contributor(&bytes, &id.to_cid(0x55).to_string(), &event).await?;
        contributor.canonical_cid = alias.canonical.to_cid(0x55).to_string();
        if row.delegator != event.0.delegator || row.delegatee != event.0.delegate {
            return Err(WitnessError::Ambiguous);
        }
        let links = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(id))
            .order_by_asc(parent_delegations::Column::Parent)
            .all(db)
            .await?;
        let signed_parents: BTreeSet<_> = contributor
            .proof_cids
            .iter()
            .map(|cid| {
                tinycloud_auth::ipld_core::cid::Cid::try_from(cid.as_str())
                    .map(Hash::from)
                    .map_err(|_| WitnessError::Invalid)
            })
            .collect::<Result<_, _>>()?;
        let graph_parents: BTreeSet<_> = links.iter().map(|link| link.parent).collect();
        if signed_parents.len() != contributor.proof_cids.len() || signed_parents != graph_parents {
            return Err(WitnessError::Ambiguous);
        }
        // Do not classify expiry of a signed owner sign-in as loss of policy
        // authority. TC-1213 supplies the missing signed self-session fact;
        // this witness retains proof dependencies without changing expiry.
        // A grant revoked before admission was not an authority candidate.
        // A later revocation must not erase its historical dependency.
        if revocation::effective_rows(db, &[id])
            .await?
            .iter()
            .any(|(_, revoked)| revoked.revoked_at.is_some_and(|time| time <= at))
        {
            return Ok(None);
        }
        let abilities = abilities::Entity::find()
            .filter(abilities::Column::Delegation.eq(id))
            .all(db)
            .await?;
        let signed_caps = &event.0.capabilities;
        if abilities.len() != signed_caps.len()
            || abilities.iter().any(|ability| {
                !signed_caps.iter().any(|cap| {
                    ability.resource == cap.resource
                        && ability.ability == cap.ability
                        && ability.caveats == cap.caveats
                })
            })
        {
            return Err(WitnessError::Ambiguous);
        }
        if signed_policy_artifact(&event.0.delegation) {
            return Ok(None);
        }
        let has_capability = signed_caps.iter().any(|held| covers(held, capability));
        if id == tip && !has_capability {
            return Ok(None);
        }
        covering.insert(id, has_capability);
        for parent in graph_parents {
            pending.push(parent);
        }
        nodes.insert(id, contributor);
    }
    let tip_row = nodes.get(&tip).ok_or(WitnessError::Missing)?;
    if tip_row.audience != owner || !covering.get(&tip).copied().unwrap_or(false) {
        return Ok(None);
    }
    // The recorded closure always contains *all* signed proof dependencies.
    // A proof path must reach the true space owner and cover the capability
    // throughout; unrelated signed branches remain captured for revocation.
    fn reaches_root(
        id: Hash,
        nodes: &BTreeMap<Hash, Contributor>,
        covering: &HashMap<Hash, bool>,
        capability: &Capability,
        visiting: &mut BTreeSet<Hash>,
    ) -> Result<bool, WitnessError> {
        if !visiting.insert(id) {
            return Err(WitnessError::Ambiguous);
        }
        let row = nodes.get(&id).ok_or(WitnessError::Missing)?;
        let valid = if !covering.get(&id).copied().unwrap_or(false) {
            false
        } else if root_authority(capability, &row.signer) {
            // An owner-signed grant has direct authority even when it cites
            // an earlier sign-in as a dependency. Capture that signed proof
            // for revocation without treating its audience as the signer.
            true
        } else if row.proof_cids.is_empty() {
            false
        } else {
            let mut found = false;
            for cid in &row.proof_cids {
                let hash = Hash::from(
                    tinycloud_auth::ipld_core::cid::Cid::try_from(cid.as_str())
                        .map_err(|_| WitnessError::Invalid)?,
                );
                let parent = nodes.get(&hash).ok_or(WitnessError::Missing)?;
                if parent.audience != row.signer {
                    return Err(WitnessError::Ambiguous);
                }
                found |= reaches_root(hash, nodes, covering, capability, visiting)?;
            }
            found
        };
        visiting.remove(&id);
        Ok(valid)
    }
    if !reaches_root(tip, &nodes, &covering, capability, &mut BTreeSet::new())? {
        return Ok(None);
    }
    Ok(Some(CandidateClosure {
        tip_cid: tip_row.cid.clone(),
        contributors: nodes.into_values().collect(),
    }))
}

/// Call after both signed roots and graph rows have been inserted on the same
/// transaction. `at` is the original registered_at for historical backfill.
/// Revoked *now* but valid *at admission* candidates remain in the witness.
pub async fn capture_in_transaction<C: ConnectionTrait>(
    db: &C,
    policy_cid: &str,
    owner_did: &str,
    root_cids: &[String],
    at: OffsetDateTime,
    encryption: Option<&ColumnEncryption>,
) -> Result<Vec<PolicyWitness>, WitnessError> {
    if root_cids.len() != 2 || root_cids[0] == root_cids[1] {
        return Err(WitnessError::Ambiguous);
    }
    let owner = principal(owner_did)?;
    let mut result = Vec::new();
    let mut roots = Vec::new();
    for (index, root_cid) in root_cids.iter().enumerate() {
        let root = policy_v3_root::Entity::find_by_id(root_cid.clone())
            .one(db)
            .await?
            .ok_or(WitnessError::Missing)?;
        if root.policy_cid != policy_cid
            || root.role
                != if index == 0 {
                    "policy-authority"
                } else {
                    "policy-enforcement"
                }
        {
            return Err(WitnessError::Ambiguous);
        }
        let event = signed_event(&root.authorization_bytes)?;
        let mut signed = signed_contributor(&root.authorization_bytes, root_cid, &event).await?;
        let cid = tinycloud_auth::ipld_core::cid::Cid::try_from(root_cid.as_str())
            .map_err(|_| WitnessError::Invalid)?;
        let alias = delegation_cid_alias::Entity::find_by_id(Hash::from(cid))
            .one(db)
            .await?
            .ok_or(WitnessError::Missing)?;
        signed.canonical_cid = alias.canonical.to_cid(0x55).to_string();
        if signed.signer != owner || !signed.proof_cids.is_empty() || !active_at(&signed, at)? {
            return Err(WitnessError::Ambiguous);
        }
        roots.push((root, signed, event));
    }
    let delegatee_prefix = format!("{owner_did}#%");
    for (root, signed, event) in roots {
        for (index, capability) in event.0.capabilities.into_iter().enumerate() {
            if index > i32::MAX as usize {
                return Err(WitnessError::Overflow);
            }
            let mut closures = Vec::new();
            let mut cursor = None;
            loop {
                let mut query = delegation::Entity::find()
                    .filter(
                        sea_orm::Condition::any()
                            .add(delegation::Column::Delegatee.eq(owner_did))
                            .add(delegation::Column::Delegatee.like(delegatee_prefix.as_str())),
                    )
                    .order_by_asc(delegation::Column::Id)
                    .limit(CANDIDATE_PAGE_SIZE);
                if let Some(last) = cursor {
                    query = query.filter(delegation::Column::Id.gt(last));
                }
                let candidates = query.all(db).await?;
                if candidates.is_empty() {
                    break;
                }
                cursor = candidates.last().map(|row| row.id);
                for candidate in &candidates {
                    if !did_principal_matches(&candidate.delegatee, &owner) {
                        continue;
                    }
                    if let Some(found) =
                        closure(db, candidate.id, &owner, &capability, at, encryption).await?
                    {
                        closures.push(found);
                        if closures.len() > MAX_CANDIDATES {
                            return Err(WitnessError::Overflow);
                        }
                    }
                }
                if candidates.len() < CANDIDATE_PAGE_SIZE as usize {
                    break;
                }
            }
            closures.sort_by(|a, b| a.tip_cid.cmp(&b.tip_cid));
            if closures.is_empty() && !root_authority(&capability, &owner) {
                return Err(WitnessError::Missing);
            }
            result.push(PolicyWitness {
                version: VERSION,
                policy_cid: policy_cid.to_owned(),
                root_cid: root.root_cid.clone(),
                capability_index: index as i32,
                owner_principal: owner.clone(),
                capability,
                registered_at: format_time(at)?,
                owner_self_classification: "unknown/legacy".to_owned(),
                root: signed.clone(),
                candidates: closures,
            });
        }
    }
    if result.is_empty() {
        return Err(WitnessError::Missing);
    }
    Ok(result)
}

/// Idempotent only for byte-identical witness rows. Caller owns commit.
pub async fn persist_in_transaction<C: ConnectionTrait>(
    db: &C,
    witnesses: &[PolicyWitness],
) -> Result<(), WitnessError> {
    if witnesses.is_empty() {
        return Err(WitnessError::Missing);
    }
    for witness in witnesses {
        let bytes = serde_json::to_vec(witness).map_err(|_| WitnessError::Invalid)?;
        let digest = hex::encode(hash(&bytes).as_ref());
        if let Some(existing) = Entity::find_by_id((
            witness.policy_cid.clone(),
            witness.root_cid.clone(),
            witness.capability_index,
        ))
        .one(db)
        .await?
        {
            if existing.version != VERSION
                || existing.witness_bytes != bytes
                || existing.witness_digest_hex != digest
            {
                return Err(WitnessError::Ambiguous);
            }
            continue;
        }
        ActiveModel {
            policy_cid: Set(witness.policy_cid.clone()),
            root_cid: Set(witness.root_cid.clone()),
            capability_index: Set(witness.capability_index),
            version: Set(VERSION),
            registered_at: Set(witness.registered_at.clone()),
            witness_bytes: Set(bytes),
            witness_digest_hex: Set(digest),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}
/// Read bounded indexed witness dependencies without traversing signed graphs
/// or re-resolving historical candidates. Callers may lock `principals` on
/// their transaction before checking and committing an authorized effect.
#[derive(Clone, Debug)]
pub struct WitnessDependencies {
    pub principals: Vec<String>,
    pub spaces: Vec<String>,
    pub signed_cids: Vec<Hash>,
}

pub async fn revocation_dependencies<C: ConnectionTrait>(
    db: &C,
    policy_cid: &str,
) -> Result<WitnessDependencies, WitnessError> {
    load_dependencies(db, policy_cid, true).await
}

// Startup validates the entire immutable witness even when a root was later
// revoked. Live consumers still deny that already-loaded root immediately,
// without reading the other root or aliases on the denied request path.
async fn load_dependencies<C: ConnectionTrait>(
    db: &C,
    policy_cid: &str,
    require_live_root: bool,
) -> Result<WitnessDependencies, WitnessError> {
    let registration = policy_v3_registration::Entity::find_by_id(policy_cid)
        .one(db)
        .await?
        .ok_or(WitnessError::Missing)?;
    let owner = principal(&registration.owner_did)?;
    let rows = Entity::find()
        .filter(Column::PolicyCid.eq(policy_cid))
        .all(db)
        .await?;
    if rows.is_empty() || rows.len() > MAX_NODES * 2 {
        return Err(WitnessError::Missing);
    }
    let mut principals = BTreeSet::from([owner.clone()]);
    let mut spaces = BTreeSet::new();
    let mut signed_cids = BTreeSet::new();
    let mut expected_aliases = BTreeMap::new();
    let by_root: BTreeMap<_, _> = rows
        .iter()
        .map(|row| ((row.root_cid.as_str(), row.capability_index), row))
        .collect();
    if by_root.len() != rows.len() {
        return Err(WitnessError::Ambiguous);
    }
    let mut indexed = BTreeSet::new();
    for (root_cid, role) in [
        (&registration.policy_root_cid, "policy-authority"),
        (&registration.enforcement_root_cid, "policy-enforcement"),
    ] {
        let root = policy_v3_root::Entity::find_by_id(root_cid.clone())
            .one(db)
            .await?
            .ok_or(WitnessError::Missing)?;
        // Signed root status is an explicit CID cutoff. Startup continues
        // validating both historical roots and all witness dependencies;
        // a live request fails closed here with no additional SQL.
        if require_live_root && (root.revoked_at.is_some() || root.revocation_bytes.is_some()) {
            return Err(WitnessError::Revoked);
        }
        if root.policy_cid != policy_cid || root.role != role {
            return Err(WitnessError::Ambiguous);
        }
        let event = signed_event(&root.authorization_bytes)?;
        if event.content_hash().to_cid(0x55).to_string() != *root_cid {
            return Err(WitnessError::Ambiguous);
        }
        let root_audience = principal(&event.0.delegate)?;
        if principal(&event.0.delegator)? != owner {
            return Err(WitnessError::Ambiguous);
        }
        let root_facts = match &event.0.delegation {
            TinyCloudDelegation::Ucan(ucan) => ucan.payload().facts.clone().unwrap_or_default(),
            TinyCloudDelegation::Cacao(_) => Vec::new(),
        };
        for (index, capability) in event.0.capabilities.iter().enumerate() {
            let key = (root_cid.as_str(), index as i32);
            let row = by_root.get(&key).ok_or(WitnessError::Missing)?;
            if !indexed.insert(key)
                || row.version != VERSION
                || row.registered_at != registration.registered_at
                || row.witness_digest_hex != hex::encode(hash(&row.witness_bytes).as_ref())
            {
                return Err(WitnessError::Ambiguous);
            }
            let witness: PolicyWitness =
                serde_json::from_slice(&row.witness_bytes).map_err(|_| WitnessError::Invalid)?;
            if witness.version != VERSION
                || witness.policy_cid != policy_cid
                || witness.root_cid != *root_cid
                || witness.capability_index != index as i32
                || witness.registered_at != row.registered_at
                || witness.owner_principal != owner
                || witness.owner_self_classification != "unknown/legacy"
                || witness.capability != *capability
                || witness.root.cid != *root_cid
                || witness.root.signed_bytes != root.authorization_bytes
                || witness.root.signer != owner
                || witness.root.audience != root_audience
                || witness.root.signed_capabilities != event.0.capabilities
                || witness.root.signed_facts != root_facts
                || !witness.root.proof_cids.is_empty()
            {
                return Err(WitnessError::Ambiguous);
            }
            if let Some(space) = capability.resource.space() {
                spaces.insert(space.to_string());
            }
            let mut tips = BTreeSet::new();
            for closure in &witness.candidates {
                if !tips.insert(&closure.tip_cid)
                    || closure.contributors.is_empty()
                    || !closure
                        .contributors
                        .iter()
                        .any(|node| node.cid == closure.tip_cid)
                {
                    return Err(WitnessError::Ambiguous);
                }
            }
            for contributor in std::iter::once(&witness.root).chain(
                witness
                    .candidates
                    .iter()
                    .flat_map(|closure| closure.contributors.iter()),
            ) {
                if principal(&contributor.signer)? != contributor.signer
                    || principal(&contributor.audience)? != contributor.audience
                {
                    return Err(WitnessError::Invalid);
                }
                principals.insert(contributor.signer.clone());
                principals.insert(contributor.audience.clone());
                let cid = tinycloud_auth::ipld_core::cid::Cid::try_from(contributor.cid.as_str())
                    .map_err(|_| WitnessError::Invalid)?;
                let canonical = tinycloud_auth::ipld_core::cid::Cid::try_from(
                    contributor.canonical_cid.as_str(),
                )
                .map_err(|_| WitnessError::Invalid)?;
                let id = Hash::from(cid);
                if id.to_cid(0x55).to_string() != contributor.cid
                    || Hash::from(canonical).to_cid(0x55).to_string() != contributor.canonical_cid
                {
                    return Err(WitnessError::Ambiguous);
                }
                if expected_aliases
                    .insert(id, Hash::from(canonical))
                    .is_some_and(|old| old != Hash::from(canonical))
                {
                    return Err(WitnessError::Ambiguous);
                }
                signed_cids.insert(id);
                if signed_cids.len() > MAX_NODES * MAX_CANDIDATES * 2 {
                    return Err(WitnessError::Overflow);
                }
            }
        }
    }
    if rows.len() != indexed.len() {
        return Err(WitnessError::Ambiguous);
    }
    let ids: Vec<_> = signed_cids.iter().copied().collect();
    for chunk in ids.chunks(200) {
        let aliases = delegation_cid_alias::Entity::find()
            .filter(delegation_cid_alias::Column::Id.is_in(chunk.iter().copied()))
            .all(db)
            .await?;
        if aliases.len() != chunk.len() {
            return Err(WitnessError::Missing);
        }
        for alias in aliases {
            if expected_aliases.get(&alias.id) != Some(&alias.canonical) {
                return Err(WitnessError::Ambiguous);
            }
        }
    }
    Ok(WitnessDependencies {
        principals: principals.into_iter().collect(),
        spaces: spaces.into_iter().collect(),
        signed_cids: ids,
    })
}

/// Never treat natural expiry or unknown/legacy owner-self classification as
/// explicit revocation. Run on the invocation/mint transaction after acquiring
/// shared `key_authority::lock_targets` for `revocation_dependencies.principals`.
pub async fn check_revocations<C: ConnectionTrait>(
    db: &C,
    policy_cid: &str,
    _encryption: Option<&ColumnEncryption>,
) -> Result<(), WitnessError> {
    let dependencies = revocation_dependencies(db, policy_cid).await?;
    check_dependencies(db, &dependencies, &dependencies.spaces).await
}

pub async fn check_revocations_for_spaces<C: ConnectionTrait>(
    db: &C,
    policy_cid: &str,
    spaces: &[String],
) -> Result<(), WitnessError> {
    let dependencies = revocation_dependencies(db, policy_cid).await?;
    let spaces = if spaces.is_empty() {
        &dependencies.spaces
    } else {
        spaces
    };
    check_dependencies(db, &dependencies, spaces).await
}

/// The caller must supply every space touched by this authorization. Signed
/// CID dependencies are checked regardless of scope; only principal
/// tombstones can be limited to the requested spaces.
pub async fn check_dependencies<C: ConnectionTrait>(
    db: &C,
    dependencies: &WitnessDependencies,
    spaces: &[String],
) -> Result<(), WitnessError> {
    crate::key_authority::check_principals(db, &dependencies.principals, spaces)
        .await
        .map_err(|_| WitnessError::Revoked)?;
    check_signed_cids(db, dependencies).await
}

/// Call after checking all dependency principals (including witness signers)
/// in the same guarded authorization window or write transaction. CID
/// revocation has no space scope and must always be checked.
pub async fn check_signed_cids<C: ConnectionTrait>(
    db: &C,
    dependencies: &WitnessDependencies,
) -> Result<(), WitnessError> {
    for chunk in dependencies.signed_cids.chunks(200) {
        if !revocation::effective_rows(db, chunk).await?.is_empty() {
            return Err(WitnessError::Revoked);
        }
    }
    Ok(())
}

async fn plan_backfill<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
    collect: bool,
) -> Result<(BackfillCounts, Vec<PolicyWitness>), WitnessError> {
    let mut counts = BackfillCounts::default();
    let mut planned = Vec::new();
    let registrations = policy_v3_registration::Entity::find().all(db).await?;
    for registration in registrations {
        counts.policies += 1;
        // Existing immutable witnesses are never reconstructed from a graph
        // that may have gained other grants since the original admission.
        // Dry-run must also work on a pre-migration read replica without
        // reading the not-yet-created witness table.
        if collect {
            let existing = Entity::find()
                .filter(Column::PolicyCid.eq(registration.policy_cid.clone()))
                .all(db)
                .await?;
            if !existing.is_empty() {
                match load_dependencies(db, &registration.policy_cid, false).await {
                    Ok(_) => counts.witnesses += existing.len() as u64,
                    Err(WitnessError::Missing) => counts.missing += 1,
                    Err(
                        WitnessError::Ambiguous | WitnessError::Invalid | WitnessError::Revoked,
                    ) => counts.ambiguous += 1,
                    Err(WitnessError::Overflow) => counts.overflow += 1,
                    Err(error) => return Err(error),
                }
                continue;
            }
        }
        let at = match OffsetDateTime::parse(
            &registration.registered_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(at) => at,
            Err(_) => {
                counts.ambiguous += 1;
                continue;
            }
        };
        match capture_in_transaction(
            db,
            &registration.policy_cid,
            &registration.owner_did,
            &[
                registration.policy_root_cid,
                registration.enforcement_root_cid,
            ],
            at,
            encryption,
        )
        .await
        {
            Ok(witnesses) => {
                counts.witnesses += witnesses.len() as u64;
                if collect {
                    planned.extend(witnesses);
                }
            }
            Err(WitnessError::Missing) => counts.missing += 1,
            Err(WitnessError::Ambiguous | WitnessError::Invalid) => counts.ambiguous += 1,
            Err(WitnessError::Overflow) => counts.overflow += 1,
            Err(error) => return Err(error),
        }
    }
    Ok((counts, planned))
}

/// Read only: callers must print/serialize counts, never witness payloads.
pub async fn dry_run_backfill<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
) -> Result<BackfillCounts, WitnessError> {
    plan_backfill(db, encryption, false)
        .await
        .map(|(counts, _)| counts)
}

/// Must be called only after the operator's Amos production snapshot gate.
/// Supply the caller's transaction; any unresolved policy aborts the whole run.
pub async fn backfill_in_transaction(
    db: &DatabaseTransaction,
    encryption: Option<&ColumnEncryption>,
) -> Result<BackfillCounts, WitnessError> {
    let (counts, witnesses) = plan_backfill(db, encryption, true).await?;
    if counts.missing != 0 {
        return Err(WitnessError::Missing);
    }
    if counts.ambiguous != 0 {
        return Err(WitnessError::Ambiguous);
    }
    if counts.overflow != 0 {
        return Err(WitnessError::Overflow);
    }
    if !witnesses.is_empty() {
        persist_in_transaction(db, &witnesses).await?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_counts_never_serialize_identifiers() {
        let value = BackfillCounts {
            policies: 2,
            witnesses: 4,
            missing: 1,
            ambiguous: 0,
            overflow: 0,
        };
        let text = serde_json::to_string(&value).unwrap();
        assert_eq!(
            text,
            r#"{"policies":2,"witnesses":4,"missing":1,"ambiguous":0,"overflow":0}"#
        );
    }

    #[test]
    fn expiry_is_not_a_revocation_signal() {
        let expired = Contributor {
            cid: String::new(),
            canonical_cid: String::new(),
            signer: String::new(),
            audience: String::new(),
            proof_cids: vec![],
            signed_capabilities: vec![],
            signed_facts: vec![],
            signed_bytes: vec![],
            not_before: None,
            expiry: Some(format_time(OffsetDateTime::UNIX_EPOCH).unwrap()),
        };
        assert!(!active_at(&expired, OffsetDateTime::now_utc()).unwrap());
        // Revocation checks deliberately use signed IDs, not active_at.
    }
}
