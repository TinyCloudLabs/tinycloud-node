//! Signed, live recovery enrollment checks for explicit key revocation.

use std::collections::{HashMap, HashSet};

use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, EntityTrait, QueryFilter,
    QuerySelect,
};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::TinyCloudDelegation,
    identity::{canonicalize_did, principal_did},
    ipld_core::cid::Cid,
    resource::SpaceId,
    ssi::jwk::Algorithm,
};

use crate::{
    auth_graph,
    encryption::{maybe_decrypt, ColumnEncryption},
    hash::{hash, Hash},
    key_authority,
    models::{
        abilities, delegation, delegation_cid_alias, invocation, key_revocation::VerifiedKeyRevoke,
        revocation,
    },
    types::Resource,
    util::DelegationInfo,
};

/// A failed or ambiguous proof is a denial, not information about the target.
/// The caller must use the same transaction for this check and the tombstone.
/// Signatures are checked before shared SQL locks, so DID resolution cannot
/// hold a row lock while awaiting external work.
pub async fn is_authorized(
    db: &DatabaseTransaction,
    request: &VerifiedKeyRevoke,
    now: OffsetDateTime,
    encryption: Option<&ColumnEncryption>,
    proof_expires_at: &mut Option<OffsetDateTime>,
) -> Result<bool, DbErr> {
    if request.proof_cids.is_empty()
        || request.proof_cids.len() > revocation::MAX_CHAIN_TRAVERSAL_NODES
    {
        return Ok(false);
    }
    let resource = format!("urn:tinycloud:key:{}", request.target_did);
    let caveat = serde_json::json!({
        "version": 1,
        "targetDid": &request.target_did,
        "scope": &request.scope,
    });
    let root_issuer = match &request.scope {
        crate::models::key_revocation::KeyRevokeScope::Global => {
            std::borrow::Cow::Borrowed(request.target_did.as_str())
        }
        crate::models::key_revocation::KeyRevokeScope::Space { space_id } => {
            let Ok(space) = space_id.parse::<SpaceId>() else {
                return Ok(false);
            };
            if space.to_string() != *space_id {
                return Ok(false);
            }
            std::borrow::Cow::Owned(space.did().to_string())
        }
    };
    if canonicalize_did(&root_issuer).ok().as_deref() != Some(root_issuer.as_ref()) {
        return Ok(false);
    }
    let mut roots = Vec::with_capacity(request.proof_cids.len());
    for proof in &request.proof_cids {
        let Ok(cid) = proof.parse::<Cid>() else {
            return Ok(false);
        };
        if cid.codec() != 0x55 || cid.to_string() != *proof {
            return Ok(false);
        }
        let Some(id) = resolve_proof(db, cid).await? else {
            return Ok(false);
        };
        if roots.contains(&id) {
            return Ok(false);
        }
        roots.push(id);
    }
    let (nodes, edges) = match auth_graph::load_closure_edges(db, &roots).await {
        Ok(closure) => closure,
        Err(auth_graph::ChainTraversalError::LimitExceeded) => return Ok(false),
        Err(auth_graph::ChainTraversalError::Db(error)) => return Err(error),
    };
    if nodes.is_empty() {
        return Ok(false);
    }
    let rows = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(nodes.iter().copied()))
        .all(db)
        .await?;
    if rows.len() != nodes.len() {
        return Ok(false);
    }
    let ability_rows = abilities::Entity::find()
        .filter(abilities::Column::Delegation.is_in(nodes.iter().copied()))
        .all(db)
        .await?;
    let mut stored_abilities: HashMap<Hash, Vec<abilities::Model>> = HashMap::new();
    for ability in ability_rows {
        stored_abilities
            .entry(ability.delegation)
            .or_default()
            .push(ability);
    }
    let mut signed = HashMap::with_capacity(rows.len());
    for row in &rows {
        let Ok(serialization) = maybe_decrypt(encryption, &row.serialization) else {
            return Ok(false);
        };
        if hash(&serialization) != row.id {
            return Ok(false);
        }
        let Ok(canonical) = delegation_cid_alias::canonical_hash(&serialization) else {
            return Ok(false);
        };
        let alias = delegation_cid_alias::Entity::find_by_id(row.id)
            .one(db)
            .await?;
        if alias.as_ref().is_some_and(|alias| {
            alias.canonical != canonical
                || alias.encrypted != (row.serialization.first() == Some(&0x01))
        }) || (alias.is_none() && canonical != row.id)
        {
            return Ok(false);
        }
        let Ok(token) = TinyCloudDelegation::from_bytes(&serialization) else {
            return Ok(false);
        };
        // A recovery chain has only offline cryptographic methods. Never
        // follow a did:web (or other network) issuer under a SQL row lock.
        let valid_signature = match &token {
            TinyCloudDelegation::Ucan(ucan) => {
                ucan.header().algorithm == Algorithm::EdDSA
                    && ucan.payload().issuer.as_str().starts_with("did:key:")
                    && crate::did_resolution::verify_ucan_signature(ucan)
                        .await
                        .is_ok()
            }
            TinyCloudDelegation::Cacao(cacao) => {
                cacao
                    .payload()
                    .iss
                    .to_string()
                    .starts_with("did:pkh:eip155:")
                    && cacao.verify().await.is_ok()
            }
        };
        if !valid_signature {
            return Ok(false);
        }
        let Ok(info) = DelegationInfo::try_from(token) else {
            return Ok(false);
        };
        let expected_terminal =
            matches!(info.delegation_mode, crate::util::DelegationMode::Terminal);
        let facts_match = if expected_terminal {
            row.facts.as_ref().is_some_and(|facts| {
                facts.0.len() == 1
                    && facts.0.get(crate::util::DelegationMode::FACT_KEY)
                        == Some(&serde_json::json!("terminal"))
            })
        } else {
            row.facts.is_none()
        };
        if row.delegator != info.delegator
            || row.delegatee != info.delegate
            || row.expiry != info.expiry
            || row.not_before != info.not_before
            || row.issued_at != info.issued_at
            || !facts_match
            || row.issued_at.is_some_and(|issued| now < issued)
            || row.expiry.is_some_and(|expiry| now >= expiry)
            || row.not_before.is_some_and(|start| now < start)
            || info.capabilities.len() != 1
            || !exact_capability(&info.capabilities[0], &resource, &caveat)
        {
            return Ok(false);
        }
        let Some(ability) = stored_abilities.get(&row.id) else {
            return Ok(false);
        };
        if ability.len() != 1
            || ability[0].resource != info.capabilities[0].resource
            || ability[0].ability != info.capabilities[0].ability
            || ability[0].caveats != info.capabilities[0].caveats
        {
            return Ok(false);
        }
        let mut signed_parents = Vec::with_capacity(info.parents.len());
        for parent in &info.parents {
            let Some(id) = resolve_proof(db, *parent).await? else {
                return Ok(false);
            };
            signed_parents.push(id);
        }
        let mut persisted_parents = edges.get(&row.id).cloned().unwrap_or_default();
        signed_parents.sort_unstable();
        persisted_parents.sort_unstable();
        if signed_parents.windows(2).any(|pair| pair[0] == pair[1])
            || signed_parents != persisted_parents
        {
            return Ok(false);
        }
        signed.insert(row.id, info);
    }
    // The writer's /revoke transaction takes an exclusive lock on its target
    // delegation row. Lock every dependency in deterministic order, then read
    // revocation state under these locks before declaring authority live.
    if db.get_database_backend() != DbBackend::Sqlite {
        let mut ordered = nodes;
        ordered.sort_unstable();
        for id in ordered {
            let Some(locked) = delegation::Entity::find_by_id(id)
                .lock_shared()
                .one(db)
                .await?
            else {
                return Ok(false);
            };
            if rows.iter().find(|row| row.id == id) != Some(&locked) {
                return Ok(false);
            }
        }
    }
    let mut principals = Vec::with_capacity(rows.len() * 2);
    for row in &rows {
        let (Ok(signer), Ok(audience)) =
            (principal_did(&row.delegator), principal_did(&row.delegatee))
        else {
            return Ok(false);
        };
        principals.push(signer);
        principals.push(audience);
    }
    // The issuer and target receive exclusive locks at the cutoff. Other
    // recovery dependencies remain shared through that commit.
    let shared = principals
        .iter()
        .filter(|did| *did != &request.target_did && *did != &request.issuer_did)
        .cloned()
        .collect::<Vec<_>>();
    key_authority::lock_targets(db, &shared, false).await?;
    // The graph and principal locks may have waited past a signed proof's
    // window. Recheck every bound under those locks rather than trusting the
    // entry timestamp passed by the caller.
    let locked_now = OffsetDateTime::now_utc();
    if rows.iter().any(|row| {
        row.issued_at.is_some_and(|issued| locked_now < issued)
            || row.not_before.is_some_and(|start| locked_now < start)
            || row.expiry.is_some_and(|expiry| locked_now >= expiry)
    }) {
        return Ok(false);
    }
    let spaces = match &request.scope {
        crate::models::key_revocation::KeyRevokeScope::Global => Vec::new(),
        crate::models::key_revocation::KeyRevokeScope::Space { space_id } => vec![space_id.clone()],
    };
    match key_authority::check_principals(db, &principals, &spaces).await {
        Ok(()) => {}
        Err(error) if key_authority::is_revoked_error(&error) => return Ok(false),
        Err(error) => return Err(error),
    }
    let row_lookup = rows
        .iter()
        .map(|row| (row.id, row))
        .collect::<HashMap<_, _>>();
    for (child_id, parents) in &edges {
        let Some(child) = row_lookup.get(child_id) else {
            return Ok(false);
        };
        for parent_id in parents {
            let Some(parent) = row_lookup.get(parent_id) else {
                return Ok(false);
            };
            let linked = matches!(
                (principal_did(&parent.delegatee), principal_did(&child.delegator)),
                (Ok(parent_did), Ok(child_did)) if parent_did == child_did
            );
            if !linked
                || matches!(
                    signed[parent_id].delegation_mode,
                    crate::util::DelegationMode::Terminal
                )
            {
                return Ok(false);
            }
        }
    }
    let mut memo = HashMap::new();
    for id in row_lookup.keys() {
        if !is_rooted(*id, &edges, &mut memo, &mut HashSet::new()) {
            return Ok(false);
        }
    }
    for row in &rows {
        if revocation::is_revoked(db, &row.id).await? {
            return Ok(false);
        }
        let info = &signed[&row.id];
        if info.parents.is_empty() {
            if principal_did(&row.delegator).ok().as_deref() != Some(root_issuer.as_ref()) {
                return Ok(false);
            }
        } else if edges.get(&row.id).is_none_or(Vec::is_empty) {
            return Ok(false);
        }
    }
    for root in &roots {
        if principal_did(&signed[root].delegate).ok().as_deref()
            != Some(request.issuer_did.as_str())
        {
            return Ok(false);
        }
    }
    // The existing holder verifier checks live chain windows, direct signer
    // links and caveat containment; root authority is checked separately above
    // because generic invocations do not treat key URNs as space roots.
    let proofs = roots.iter().map(|id| id.to_cid(0x55)).collect::<Vec<_>>();
    let caps = &signed[&roots[0]].capabilities;
    match invocation::authorize_holder(db, &request.issuer_did, caps, &proofs, locked_now).await {
        Ok(()) => {
            *proof_expires_at = rows.iter().filter_map(|row| row.expiry).min();
            Ok(true)
        }
        Err(invocation::Error::Db(error)) => Err(error),
        Err(_) => Ok(false),
    }
}

fn is_rooted(
    id: Hash,
    edges: &HashMap<Hash, Vec<Hash>>,
    memo: &mut HashMap<Hash, bool>,
    path: &mut HashSet<Hash>,
) -> bool {
    if let Some(&rooted) = memo.get(&id) {
        return rooted;
    }
    if !path.insert(id) {
        return false;
    }
    let rooted = edges.get(&id).is_none_or(|parents| {
        parents.is_empty()
            || parents
                .iter()
                .all(|parent| is_rooted(*parent, edges, memo, path))
    });
    path.remove(&id);
    memo.insert(id, rooted);
    rooted
}

fn exact_capability(
    cap: &crate::util::Capability,
    resource: &str,
    caveat: &serde_json::Value,
) -> bool {
    matches!(&cap.resource, Resource::Other(uri) if uri.as_str() == resource)
        && cap.ability.to_string() == "tinycloud.key/revoke"
        && cap.caveats.0.len() == 1
        && cap.caveats.0.get("0") == Some(caveat)
}

/// Resolve a CID only as a CID: its alias is never a DID principal. Multiple
/// historical encodings for one canonical hash are deliberately ambiguous.
async fn resolve_proof<C: ConnectionTrait>(db: &C, cid: Cid) -> Result<Option<Hash>, DbErr> {
    if cid.codec() != 0x55 {
        return Ok(None);
    }
    let id = Hash::from(cid);
    let aliases = delegation_cid_alias::Entity::find()
        .filter(delegation_cid_alias::Column::Canonical.eq(id))
        .all(db)
        .await?;
    if aliases.len() > 1 {
        return Ok(None);
    }
    let direct = delegation::Entity::find_by_id(id).one(db).await?.is_some();
    if let Some(alias) = aliases.first() {
        if direct && alias.id != id {
            return Ok(None);
        }
        Ok(Some(alias.id))
    } else if direct {
        Ok(Some(id))
    } else {
        Ok(None)
    }
}
