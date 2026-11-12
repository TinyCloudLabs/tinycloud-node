//! Policy authority targets use two persisted capability representations.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyTarget {
    Space(String),
    Resource(Resource),
}

/// Read authority targets without interpreting paths, signatures, or policy
/// decisions. Malformed persisted authority fails reconciliation closed.
pub fn capability_target(value: &serde_json::Value) -> Result<PolicyTarget, DbErr> {
    if let Some(resource) = value.get("resource") {
        let resource = resource
            .as_str()
            .ok_or_else(|| failure("invalid policy resource"))?
            .parse::<Resource>()
            .map_err(|_| failure("invalid policy resource"))?;
        return Ok(match resource.space() {
            Some(space) => PolicyTarget::Space(space.to_string()),
            None => PolicyTarget::Resource(resource),
        });
    }
    let cap =
        crate::policy_capability::parse(value).map_err(|_| failure("invalid policy capability"))?;
    let space = cap
        .space
        .parse::<tinycloud_auth::resource::SpaceId>()
        .map_err(|_| failure("invalid policy space"))?;
    if space.to_string() != cap.space {
        return Err(failure("noncanonical policy space"));
    }
    Ok(PolicyTarget::Space(cap.space))
}

pub fn native_policy_targets(bytes: &[u8]) -> Result<Vec<PolicyTarget>, DbErr> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| failure("invalid persisted native policy"))?;
    value
        .get("capabilityCeiling")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| failure("missing policy capability ceiling"))?
        .iter()
        .map(capability_target)
        .collect()
}

fn unexpired(expiry: &str) -> Result<bool, DbErr> {
    Ok(
        OffsetDateTime::parse(expiry, &Rfc3339).map_err(|_| failure("invalid policy expiry"))?
            > OffsetDateTime::now_utc(),
    )
}

fn summary(
    graph: &mut Graph,
    id: Hash,
    active: bool,
    targets: Vec<PolicyTarget>,
    removed: Option<&str>,
) {
    let record = graph.records.entry(id).or_default();
    record.kinds.insert("delegation");
    record.active |= active;
    for target in targets {
        match target {
            PolicyTarget::Space(space) => {
                if removed == Some(space.as_str()) {
                    graph.direct_policy.insert(id);
                }
                record.spaces.insert(space);
            }
            PolicyTarget::Resource(resource) => {
                record.resources.push(resource);
            }
        }
    }
}

pub(super) async fn preload(
    tx: &DatabaseTransaction,
    graph: &mut Graph,
    seeds: &mut HashSet<Hash>,
    removed: Option<&str>,
    lease: &mut Lease<'_>,
) -> Result<(), DbErr> {
    for row in models::policy_delegation::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        let artifact: crate::policy_authority::PolicyDelegation =
            serde_json::from_value(row.artifact_json)
                .map_err(|_| failure("invalid persisted policy delegation"))?;
        if artifact.delegation_cid != row.delegation_cid || artifact.expires_at != row.expires_at {
            return Err(failure("policy authority index mismatch"));
        }
        let id = cid(&row.delegation_cid)?;
        let targets = artifact
            .capabilities
            .iter()
            .map(capability_target)
            .collect::<Result<Vec<_>, _>>()?;
        graph.records.entry(id).or_default().blocked |= row.revoked_at.is_some();
        summary(
            graph,
            id,
            row.revoked_at.is_none() && unexpired(&row.expires_at)?,
            targets,
            removed,
        );
        for parent in artifact.proof_cids {
            graph.extra(id, cid(&parent)?, false);
        }
    }
    for row in models::owner_share_policy::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        let id = cid(&row.policy_cid)?;
        let root_revoked = roots_revoked(
            tx,
            &[&row.owner_delegation_cid, &row.enforcement_delegation_cid],
        )
        .await?;
        graph.records.entry(id).or_default().blocked |= row.revoked_at.is_some() || root_revoked;
        summary(
            graph,
            id,
            row.revoked_at.is_none() && !root_revoked && unexpired(&row.expires_at)?,
            vec![PolicyTarget::Space(row.space_id)],
            removed,
        );
        for parent in [row.owner_delegation_cid, row.enforcement_delegation_cid] {
            let parent = cid(&parent)?;
            graph.extra(id, parent, false);
            graph.extra(parent, id, false);
        }
    }
    for row in models::policy_v3_registration::Entity::find()
        .all(tx)
        .await?
    {
        lease.keep(tx).await?;
        let id = cid(&row.policy_cid)?;
        let revoked = models::policy_v3_root::Entity::find()
            .filter(models::policy_v3_root::Column::PolicyCid.eq(&row.policy_cid))
            .filter(models::policy_v3_root::Column::RevokedAt.is_not_null())
            .one(tx)
            .await?
            .is_some()
            || roots_revoked(tx, &[&row.policy_root_cid, &row.enforcement_root_cid]).await?;
        summary(
            graph,
            id,
            !revoked && unexpired(&row.expires_at)?,
            native_policy_targets(&row.policy_bytes)?,
            removed,
        );
        for parent in [row.policy_root_cid, row.enforcement_root_cid] {
            let parent = cid(&parent)?;
            graph.extra(id, parent, false);
            graph.extra(parent, id, false);
        }
    }
    for row in models::policy_v3_root::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        graph
            .records
            .entry(cid(&row.root_cid)?)
            .or_default()
            .blocked |= row.revoked_at.is_some();
    }
    for row in models::policy_v3_session::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        graph
            .records
            .entry(cid(&row.session_cid)?)
            .or_default()
            .blocked |= row.state != "admitted";
        graph.extra(cid(&row.session_cid)?, cid(&row.policy_cid)?, false);
    }
    seeds.extend(graph.direct_policy.iter().copied());
    Ok(())
}

pub(super) async fn remove(
    tx: &DatabaseTransaction,
    deleted: &HashSet<Hash>,
    lease: &mut Lease<'_>,
) -> Result<(), DbErr> {
    for row in models::policy_challenge::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        let mut erase = false;
        for field in ["policyDelegationCid", "enforcementDelegationCid"] {
            let reference = row
                .challenge_json
                .get(field)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| failure("invalid persisted policy challenge"))?;
            erase |= deleted.contains(&cid(reference)?);
        }
        if erase {
            models::policy_challenge::Entity::delete_by_id(row.challenge_id)
                .exec(tx)
                .await?;
        }
    }
    // Remove projections by CID identity rather than assuming one CID codec.
    for row in models::policy_v3_session::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.session_cid)?) {
            remove_handles(tx, &row.session_cid).await?;
            models::policy_v3_session::Entity::delete_by_id(row.session_cid)
                .exec(tx)
                .await?;
        }
    }
    for row in models::policy_v3_root::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.root_cid)?) {
            models::policy_v3_root::Entity::delete_by_id(row.root_cid)
                .exec(tx)
                .await?;
        }
    }
    for row in models::policy_edge::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.child_cid)?) || deleted.contains(&cid(&row.parent_cid)?) {
            models::policy_edge::Entity::delete_by_id((row.child_cid, row.position))
                .exec(tx)
                .await?;
        }
    }
    for row in models::policy_delegation::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.delegation_cid)?) {
            models::policy_issuance_audit::Entity::delete_many()
                .filter(
                    models::policy_issuance_audit::Column::SessionDelegationCid
                        .eq(&row.delegation_cid),
                )
                .exec(tx)
                .await?;
            remove_handles(tx, &row.delegation_cid).await?;
            models::policy_delegation::Entity::delete_by_id(row.delegation_cid)
                .exec(tx)
                .await?;
        }
    }
    for row in models::policy_v3_registration::Entity::find()
        .all(tx)
        .await?
    {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.policy_cid)?) {
            remove_policy_links(tx, &row.policy_cid).await?;
            models::policy_v3_registration::Entity::delete_by_id(row.policy_cid)
                .exec(tx)
                .await?;
        }
    }
    for row in models::owner_share_policy::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.policy_cid)?) {
            remove_policy_links(tx, &row.policy_cid).await?;
            models::owner_share_policy::Entity::delete_by_id(row.policy_cid)
                .exec(tx)
                .await?;
        }
    }
    Ok(())
}

async fn remove_handles(tx: &DatabaseTransaction, cid: &str) -> Result<(), DbErr> {
    for row in models::share_session_handle::Entity::find()
        .filter(models::share_session_handle::Column::AuthoritySessionCid.eq(cid))
        .all(tx)
        .await?
    {
        models::share_holder_read_jti::Entity::delete_many()
            .filter(models::share_holder_read_jti::Column::SessionHandle.eq(&row.session_handle))
            .exec(tx)
            .await?;
        models::share_policy_presentation_jti::Entity::delete_many()
            .filter(
                models::share_policy_presentation_jti::Column::SessionHandle
                    .eq(&row.session_handle),
            )
            .exec(tx)
            .await?;
        models::share_session_handle::Entity::delete_by_id(row.session_handle)
            .exec(tx)
            .await?;
    }
    Ok(())
}
async fn remove_policy_links(tx: &DatabaseTransaction, policy: &str) -> Result<(), DbErr> {
    models::policy_v3_challenge::Entity::delete_many()
        .filter(models::policy_v3_challenge::Column::PolicyCid.eq(policy))
        .exec(tx)
        .await?;
    models::share_policy_presentation_jti::Entity::delete_many()
        .filter(models::share_policy_presentation_jti::Column::PolicyCid.eq(policy))
        .exec(tx)
        .await?;
    Ok(())
}

async fn roots_revoked(tx: &DatabaseTransaction, roots: &[&str]) -> Result<bool, DbErr> {
    let ids = roots
        .iter()
        .map(|root| cid(root))
        .collect::<Result<Vec<_>, _>>()?;
    if !revocation::effective_rows(tx, &ids).await?.is_empty() {
        return Ok(true);
    }
    Ok(models::policy_delegation::Entity::find()
        .filter(models::policy_delegation::Column::DelegationCid.is_in(roots.iter().copied()))
        .filter(models::policy_delegation::Column::RevokedAt.is_not_null())
        .one(tx)
        .await?
        .is_some())
}
