use super::*;
use crate::models::policy_v3_root;
use crate::{
    auth_graph::AuthGraphSnapshot,
    encryption::{maybe_decrypt, ColumnEncryption, RowBinding},
    encryption_network::{key_id, protocol::DECRYPT_ACTION},
    models::{
        abilities, delegation, encryption_network_member, invocation, policy_delegation,
        policy_v3_session,
    },
    policy_authority::{AuthorityArtifactVerifier, AuthorityError, DelegationRole},
    renewal::RenewalNodeIdentity,
    types::Resource,
    util::DelegationInfo,
};
use sea_orm::{ColumnTrait, DatabaseTransaction, DbErr, EntityTrait, QueryFilter};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{authorization::TinyCloudDelegation, identity::did_principal_matches};

fn unavailable() -> DbErr {
    DbErr::Custom("resource dependency authority unavailable".into())
}
fn time(raw: &str) -> Result<OffsetDateTime, DbErr> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| unavailable())
}

/// Does destroying this exact target affect a granted encryption resource?
/// Network destruction includes all key/prefix grants in that network. Exact
/// key destruction includes applicable network authority and matching prefixes.
fn relevant(target: &ResourceTarget, resource: &Resource) -> Result<bool, DbErr> {
    let raw = resource.to_string();
    let prefix = "urn:tinycloud:encryption:";
    if !raw
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        return Ok(false);
    }
    let grant = key_id::parse(&raw).map_err(|_| unavailable())?;
    let requested = key_id::parse(target.as_str()).map_err(|_| unavailable())?;
    match (&grant, &requested) {
        (key_id::EncryptionResource::Network(network), _) => {
            Ok(network.to_string() == target.network_id())
        }
        (_, key_id::EncryptionResource::Network(_)) => {
            let network = match &grant {
                key_id::EncryptionResource::Key(key)
                | key_id::EncryptionResource::KeyPrefix(key) => {
                    crate::encryption_network::NetworkId::new(key.owner_did(), key.network())
                        .map_err(|_| unavailable())?
                }
                _ => return Err(unavailable()),
            };
            Ok(network.to_string() == target.network_id())
        }
        _ => Ok(grant.extends(&requested)),
    }
}
fn decrypt(ability: &crate::types::Ability) -> bool {
    crate::policy_capability::ability_matches(ability.as_ref().as_ref(), DECRYPT_ACTION)
}

pub(crate) async fn load_graph(
    tx: &DatabaseTransaction,
    roots: &[Hash],
    identity: Option<&RenewalNodeIdentity>,
    now: OffsetDateTime,
) -> Result<AuthGraphSnapshot, DbErr> {
    let result = match identity {
        Some(identity) => {
            AuthGraphSnapshot::load_with_renewal_identity(
                tx,
                roots,
                &identity.stable_node_did,
                &identity.renewer_did,
                identity.epoch,
                now.unix_timestamp(),
            )
            .await
        }
        None => AuthGraphSnapshot::load(tx, roots).await,
    };
    result.map_err(|_| unavailable())
}

pub(crate) fn decode(
    row: &delegation::Model,
    encryption: Option<&ColumnEncryption>,
) -> Result<(Vec<u8>, DelegationInfo), DbErr> {
    let id: Vec<u8> = row.id.into();
    let bytes = maybe_decrypt(
        encryption,
        &row.serialization,
        RowBinding::new("delegation", "serialization", &[&id]),
        row.serialization_format,
    )
    .map_err(|_| unavailable())?;
    if crate::hash::hash(&bytes) != row.id {
        return Err(unavailable());
    }
    let signed = TinyCloudDelegation::from_bytes(&bytes).map_err(|_| unavailable())?;
    let info = DelegationInfo::try_from(signed).map_err(|_| unavailable())?;
    if !did_principal_matches(&info.delegator, &row.delegator)
        || !did_principal_matches(&info.delegate, &row.delegatee)
    {
        return Err(unavailable());
    }
    Ok((bytes, info))
}

/// Only a currently authorized, exact signed native recipient projection is
/// positive provenance. Generic account-to-key sessions remain ambiguous.
pub(crate) async fn native_outside(
    tx: &DatabaseTransaction,
    target: &ResourceTarget,
    row: &delegation::Model,
    bytes: &[u8],
    info: &DelegationInfo,
) -> Result<bool, DbErr> {
    if !delegation::is_policy_session(&info.delegation) {
        return Ok(false);
    }
    let cid = row.id.to_cid(0x55).to_string();
    let projection = policy_v3_session::Entity::find_by_id(cid)
        .one(tx)
        .await?
        .ok_or_else(unavailable)?;
    let TinyCloudDelegation::Ucan(ucan) = &info.delegation else {
        return Err(unavailable());
    };
    let facts = ucan
        .payload()
        .facts
        .as_ref()
        .and_then(|facts| facts.first())
        .and_then(serde_json::Value::as_object)
        .ok_or_else(unavailable)?;
    let fact = |name: &str| {
        facts
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(unavailable)
    };
    if projection.authorization_bytes != bytes
        || projection.state != "admitted"
        || projection.policy_cid != fact("policyCid")?
        || !did_principal_matches(&projection.recipient_did, &info.delegate)
        || !did_principal_matches(fact("recipientDid")?, &info.delegate)
        || !did_principal_matches(fact("ownerDid")?, target.owner_did())
        || info.parents.len() != 2
        || !info
            .parents
            .iter()
            .any(|cid| cid.to_string() == fact("policyDelegationCid").unwrap_or(""))
        || !info
            .parents
            .iter()
            .any(|cid| cid.to_string() == fact("enforcementDelegationCid").unwrap_or(""))
        || info.expiry != Some(time(&projection.expires_at)?)
        || info.not_before != Some(time(&projection.not_before)?)
    {
        return Err(unavailable());
    }
    Ok(!did_principal_matches(&info.delegate, target.owner_did()))
}

/// Read one complete exact-target dependency set under the signed-graph lock.
/// Caller holds owner admission exclusion; this function never unwraps key material.
pub async fn collect_target_dependencies(
    tx: &DatabaseTransaction,
    target: &ResourceTarget,
    operated_nodes: &BTreeSet<String>,
    now: OffsetDateTime,
    encryption: Option<&ColumnEncryption>,
    renewal_identity: Option<&RenewalNodeIdentity>,
) -> Result<ResourceDependencyCheck, DbErr> {
    if operated_nodes.is_empty()
        || operated_nodes.iter().any(|node| {
            !tinycloud_auth::identity::principal_did(node).is_ok_and(|canonical| canonical == *node)
        })
    {
        return Err(unavailable());
    }
    crate::space_purge_records::lock(tx).await?;
    // Signed native projections may survive without ordinary graph indexes
    // after a partial restore. Their absence is uncertainty, not a zero grant.
    let mut copies = Vec::new();
    for row in policy_v3_root::Entity::find().all(tx).await? {
        if row.revoked_at.is_none() {
            copies.push((row.root_cid, row.authorization_bytes));
        }
    }
    for row in policy_v3_session::Entity::find().all(tx).await? {
        if row.state == "admitted" {
            copies.push((row.session_cid, row.authorization_bytes));
        }
    }
    for (cid, bytes) in copies {
        let targets = crate::space_purge_records::policy::inventory_authorization_targets(&bytes)?;
        let mut relevant_copy = false;
        for copy_target in targets {
            if let crate::space_purge_records::policy::PolicyTarget::Resource(resource) =
                copy_target
            {
                relevant_copy |= relevant(target, &resource)?;
            }
        }
        if relevant_copy {
            let cid: Cid = cid.parse().map_err(|_| unavailable())?;
            let id = Hash::from(cid);
            if crate::hash::hash(&bytes) != id
                || delegation::Entity::find_by_id(id).one(tx).await?.is_none()
            {
                return Err(unavailable());
            }
        }
    }
    let mut outside = Vec::new();
    let mut ambiguous = BTreeSet::new();
    let mut candidates = BTreeSet::new();
    for cap in abilities::Entity::find().all(tx).await? {
        if decrypt(&cap.ability) && relevant(target, &cap.resource)? {
            candidates.insert(cap.delegation);
        }
    }
    for id in candidates {
        let graph = load_graph(tx, &[id], renewal_identity, now).await?;
        let row = graph.delegation(&id).ok_or_else(unavailable)?;
        if did_principal_matches(&row.delegatee, target.owner_did()) {
            continue;
        }
        if renewal_identity
            .is_some_and(|identity| did_principal_matches(&row.delegatee, &identity.renewer_did))
        {
            continue;
        }
        let (bytes, info) = decode(row, encryption)?;
        let mut caps: Vec<_> = info
            .capabilities
            .iter()
            .filter(|cap| decrypt(&cap.ability))
            .filter_map(|cap| match relevant(target, &cap.resource) {
                Ok(true) => Some(Ok(cap.clone())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<_, _>>()?;
        if caps.is_empty() {
            return Err(unavailable());
        }
        // Known inactive chains disappear from the live set. Other validation
        // failures are uncertainty, never evidence of zero dependencies.
        if graph.is_revoked(&id) || graph.first_revoked_ancestor(&id).is_some() {
            continue;
        }
        let chain_ids = graph.chain_ids_from(&id);
        let mut inactive = false;
        for chain_id in chain_ids {
            let ancestor = graph.delegation(&chain_id).ok_or_else(unavailable)?;
            let expiry = graph
                .effective_expiry(&chain_id)
                .and_then(|time| OffsetDateTime::from_unix_timestamp(time).ok())
                .or(ancestor.expiry);
            inactive |= expiry.is_some_and(|expiry| expiry <= now)
                || ancestor.not_before.is_some_and(|start| start > now);
        }
        if inactive {
            continue;
        }
        let has_prefix = caps.iter().any(|cap| {
            matches!(
                key_id::parse(&cap.resource.to_string()),
                Ok(key_id::EncryptionResource::KeyPrefix(_))
            )
        });
        if has_prefix && target.as_str() == target.network_id() {
            // A namespace is not invocable. Keep its live registered grant as
            // unknown dependency evidence; never turn it into a positive read.
            ambiguous.insert(id);
            continue;
        }
        for cap in &mut caps {
            if matches!(
                key_id::parse(&cap.resource.to_string()),
                Ok(key_id::EncryptionResource::KeyPrefix(_))
            ) {
                cap.resource = target.as_str().parse().map_err(|_| unavailable())?;
            }
        }
        match invocation::authorize_holder_with_graph(
            tx,
            &row.delegatee,
            &caps,
            &[id.to_cid(0x55)],
            now,
            &graph,
        )
        .await
        {
            Ok(()) => {}
            Err(invocation::Error::Db(error)) => return Err(error),
            Err(_) => return Err(unavailable()),
        }
        if native_outside(tx, target, row, &bytes, &info).await? {
            if !graph.has_covering_path_to(
                [id],
                |cap| decrypt(&cap.ability) && relevant(target, &cap.resource).unwrap_or(false),
                |_| true,
                |row| row.id == id,
            ) {
                return Err(unavailable());
            }
            outside.push(DependencyIdentity::Grant(id));
        } else {
            ambiguous.insert(id);
        }
    }
    // The #117 graph has its own canonical signed profile and status validator.
    for row in policy_delegation::Entity::find().all(tx).await? {
        let encoded = serde_json::to_vec(&row.artifact_json).map_err(|_| unavailable())?;
        let verified = AuthorityArtifactVerifier
            .verify(&encoded)
            .map_err(|_| unavailable())?;
        let artifact = verified.artifact();
        if artifact.delegation_cid != row.delegation_cid {
            return Err(unavailable());
        }
        let mut matches = false;
        for cap in &artifact.capabilities {
            if let Some(raw) = cap.get("resource").and_then(serde_json::Value::as_str) {
                let resource: Resource = raw.parse().map_err(|_| unavailable())?;
                if relevant(target, &resource)? {
                    let actions = cap
                        .get("actions")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(unavailable)?;
                    matches |= actions.iter().any(|action| {
                        action.as_str().is_some_and(|action| {
                            crate::policy_capability::ability_matches(action, DECRYPT_ACTION)
                        })
                    });
                }
            }
        }
        if !matches {
            continue;
        }
        match crate::policy_authority::validate_transaction_authority(tx, &row.delegation_cid, now)
            .await
        {
            Ok(()) => {}
            Err(
                AuthorityError::DelegationRevoked
                | AuthorityError::DelegationAncestorRevoked
                | AuthorityError::SessionTimeInvalid,
            ) => continue,
            Err(_) => return Err(unavailable()),
        }
        let cid: Cid = row.delegation_cid.parse().map_err(|_| unavailable())?;
        let id = Hash::from(cid);
        if matches!(
            artifact.role,
            DelegationRole::PolicySessionRoot | DelegationRole::PolicySessionDescendant
        ) {
            if !did_principal_matches(
                artifact.fact_value("ownerDid").map_err(|_| unavailable())?,
                target.owner_did(),
            ) {
                return Err(unavailable());
            }
            if !did_principal_matches(
                &artifact.audience_did,
                artifact
                    .fact_value("sessionSubjectDid")
                    .map_err(|_| unavailable())?,
            ) {
                return Err(unavailable());
            }
            if !did_principal_matches(&artifact.audience_did, target.owner_did()) {
                outside.push(DependencyIdentity::Grant(id));
            }
        } else if !did_principal_matches(&artifact.audience_did, target.owner_did()) {
            ambiguous.insert(id);
        }
    }
    for row in encryption_network_member::Entity::find()
        .filter(encryption_network_member::Column::NetworkId.eq(target.network_id()))
        .all(tx)
        .await?
    {
        let canonical =
            tinycloud_auth::identity::principal_did(&row.node_id).map_err(|_| unavailable())?;
        if canonical != row.node_id {
            return Err(unavailable());
        }
        if !operated_nodes.contains(&canonical) {
            outside.push(DependencyIdentity::Member(canonical));
        }
    }
    let snapshot = ResourceDependencySnapshot::canonical(target.clone(), outside)
        .map_err(|_| unavailable())?;
    Ok(ResourceDependencyCheck {
        proven_outside: snapshot,
        ambiguous_grants: ambiguous,
    })
}
