//! Shared signed-record lifecycle. All destructive decisions run under one
//! transaction advisory lock, with proof closure recomputed before removal.
use crate::{
    encryption::{maybe_decrypt, ColumnEncryption, RowBinding},
    hash::{hash, Hash},
    models::{
        self, abilities, delegation, delegation_cid_alias, invocation, revocation,
        space_purge_shared_residue as residue,
    },
    relationships::{invoked_abilities, parent_delegations},
    space_purge_ledger::LedgerKeys,
    types::Resource,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, DbErr, EntityTrait, QueryFilter, QuerySelect, Statement, TransactionTrait,
};
use std::collections::{HashMap, HashSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudInvocation},
    ipld_core::cid::Cid,
};

pub mod policy;

const PAGE: usize = 64;
pub const SWEEP_INTERVAL_SECONDS: i64 = 24 * 60 * 60;

pub async fn lock<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    if db.get_database_backend() == DatabaseBackend::Postgres {
        db.execute_unprepared("SELECT pg_advisory_xact_lock(1413698384,2871)")
            .await?;
    }
    Ok(())
}

/// Writers acquire a shared lock before signed bytes, proof links or live roots
/// change. GC's exclusive lock never serializes ordinary writers with each other.
pub async fn operation<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    if db.get_database_backend() == DatabaseBackend::Postgres {
        db.execute_unprepared("SELECT pg_advisory_xact_lock_shared(1413698384,2871)")
            .await?;
    }
    Ok(())
}

struct Lease<'a> {
    job: Option<&'a crate::space_purge_worker::ClaimedPurge>,
    last: std::time::Instant,
}
impl Lease<'_> {
    async fn keep(&mut self, tx: &DatabaseTransaction) -> Result<(), DbErr> {
        if self.last.elapsed() >= std::time::Duration::from_secs(10) {
            if let Some(job) = self.job {
                if !crate::space_purge_worker::renew(tx, job).await? {
                    return Err(failure("purge signed-record lease expired"));
                }
            }
            self.last = std::time::Instant::now();
        }
        Ok(())
    }
}

#[derive(Default)]
struct Record {
    kinds: HashSet<&'static str>,
    active: bool,
    blocked: bool,
    resources: Vec<Resource>,
    spaces: HashSet<String>,
}
#[derive(Default)]
struct Graph {
    records: HashMap<Hash, Record>,
    parents: HashMap<Hash, HashSet<Hash>>,
    aliases: HashMap<Hash, HashSet<Hash>>,
    revocations: HashMap<Hash, HashSet<Hash>>,
    extra_parents: HashMap<Hash, HashSet<Hash>>,
    extra_children: HashMap<Hash, HashSet<Hash>>,
    control_edges: HashSet<(Hash, Hash)>,
    controls: HashMap<Hash, HashSet<Hash>>,
    direct_policy: HashSet<Hash>,
}

fn failure(message: &str) -> DbErr {
    DbErr::Custom(message.into())
}
fn cid(value: &str) -> Result<Hash, DbErr> {
    value
        .parse::<Cid>()
        .map(Hash::from)
        .map_err(|_| failure("invalid signed proof reference"))
}

impl Graph {
    fn extra(&mut self, child: Hash, parent: Hash, control: bool) {
        self.extra_parents.entry(child).or_default().insert(parent);
        self.extra_children.entry(parent).or_default().insert(child);
        if control {
            self.control_edges.insert((child, parent));
        }
    }
    async fn peers(
        &mut self,
        tx: &DatabaseTransaction,
        ids: &[Hash],
    ) -> Result<HashSet<Hash>, DbErr> {
        let unseen: Vec<_> = ids
            .iter()
            .filter(|id| !self.aliases.contains_key(id))
            .copied()
            .collect();
        for page in unseen.chunks(PAGE) {
            let rows = delegation_cid_alias::Entity::find()
                .filter(
                    Condition::any()
                        .add(delegation_cid_alias::Column::Id.is_in(page.iter().copied()))
                        .add(delegation_cid_alias::Column::Canonical.is_in(page.iter().copied())),
                )
                .all(tx)
                .await?;
            let canonical: HashSet<_> = rows.iter().map(|row| row.canonical).collect();
            let mut groups: HashMap<Hash, HashSet<Hash>> = HashMap::new();
            for chunk in canonical.iter().copied().collect::<Vec<_>>().chunks(PAGE) {
                for row in delegation_cid_alias::Entity::find()
                    .filter(delegation_cid_alias::Column::Canonical.is_in(chunk.iter().copied()))
                    .all(tx)
                    .await?
                {
                    groups
                        .entry(row.canonical)
                        .or_default()
                        .extend([row.id, row.canonical]);
                }
            }
            for group in groups.into_values() {
                for id in &group {
                    self.aliases.insert(*id, group.clone());
                }
            }
            for id in page {
                self.aliases
                    .entry(*id)
                    .or_insert_with(|| HashSet::from([*id]));
            }
        }
        Ok(ids
            .iter()
            .flat_map(|id| self.aliases[id].iter().copied())
            .collect())
    }

    async fn discover(
        &mut self,
        tx: &DatabaseTransaction,
        seeds: HashSet<Hash>,
        descendants: bool,
        lease: &mut Lease<'_>,
    ) -> Result<HashSet<Hash>, DbErr> {
        let mut visited = HashSet::new();
        let mut pending = seeds;
        while !pending.is_empty() {
            let batch: Vec<_> = pending.drain().collect();
            for page in batch.chunks(PAGE) {
                lease.keep(tx).await?;
                let peers = self.peers(tx, page).await?;
                visited.extend(peers.iter().copied());
                let column = if descendants {
                    parent_delegations::Column::Parent
                } else {
                    parent_delegations::Column::Child
                };
                let links = parent_delegations::Entity::find()
                    .filter(column.is_in(peers.iter().copied()))
                    .all(tx)
                    .await?;
                for link in links {
                    let children = self.peers(tx, &[link.child]).await?;
                    let parents = self.peers(tx, &[link.parent]).await?;
                    for child in &children {
                        self.parents
                            .entry(*child)
                            .or_default()
                            .extend(parents.iter().copied());
                    }
                    pending.extend(
                        if descendants { children } else { parents }
                            .into_iter()
                            .filter(|id| !visited.contains(id)),
                    );
                }
                let special: HashSet<_> = peers
                    .iter()
                    .flat_map(|id| {
                        if descendants {
                            self.extra_children
                                .get(id)
                                .into_iter()
                                .flatten()
                                .map(|child| (*child, *id))
                                .collect::<Vec<_>>()
                        } else {
                            self.extra_parents
                                .get(id)
                                .into_iter()
                                .flatten()
                                .map(|parent| (*id, *parent))
                                .collect::<Vec<_>>()
                        }
                    })
                    .collect();
                for (child, parent) in special {
                    let children = self.peers(tx, &[child]).await?;
                    let parents = self.peers(tx, &[parent]).await?;
                    if self.control_edges.contains(&(child, parent)) {
                        for id in &children {
                            self.controls
                                .entry(*id)
                                .or_default()
                                .extend(parents.iter().copied());
                        }
                    }
                    if (if descendants { &parents } else { &children }).is_disjoint(&peers) {
                        continue;
                    }
                    for child in &children {
                        self.parents
                            .entry(*child)
                            .or_default()
                            .extend(parents.iter().copied());
                    }
                    pending.extend(
                        if descendants { children } else { parents }
                            .into_iter()
                            .filter(|id| !visited.contains(id)),
                    );
                }
                let values: Vec<_> = peers.iter().copied().collect();
                // A retained proof keeps the signed revocations that describe it.
                for (subject, row) in revocation::effective_rows(tx, &values).await? {
                    self.revocations.entry(subject).or_default().insert(row.id);
                    if !visited.contains(&row.id) {
                        pending.insert(row.id);
                    }
                }
                if !descendants {
                    for row in revocation::Entity::find()
                        .filter(revocation::Column::Id.is_in(values))
                        .all(tx)
                        .await?
                    {
                        let parents = self.peers(tx, &[row.revoked]).await?;
                        for parent in &parents {
                            self.revocations.entry(*parent).or_default().insert(row.id);
                        }
                        pending.extend(parents.into_iter().filter(|id| !visited.contains(id)));
                    }
                }
            }
        }
        Ok(visited)
    }

    fn closure(&self, roots: HashSet<Hash>) -> HashSet<Hash> {
        let mut needed = HashSet::new();
        let mut pending: Vec<_> = roots.into_iter().collect();
        while let Some(id) = pending.pop() {
            if !needed.insert(id) {
                continue;
            }
            for links in [
                self.parents.get(&id),
                self.aliases.get(&id),
                self.revocations.get(&id),
            ]
            .into_iter()
            .flatten()
            {
                pending.extend(links.iter().copied());
            }
        }
        needed
    }
}

struct Targets<'a> {
    keys: &'a LedgerKeys,
    removed: Option<&'a str>,
    completed: HashMap<String, bool>,
    retired: HashMap<String, bool>,
}
impl Targets<'_> {
    async fn owner_retired(
        &mut self,
        tx: &DatabaseTransaction,
        owner: &str,
    ) -> Result<bool, DbErr> {
        let canonical = tinycloud_auth::identity::canonicalize_principal(owner)
            .map_err(|_| failure("invalid resource owner"))?;
        let owner = canonical.as_str();
        if let Some(value) = self.retired.get(owner) {
            return Ok(*value);
        }
        let mut retired = false;
        for key in self.keys.key_ids() {
            let digest = self
                .keys
                .target_hmac(key, "owner", owner)
                .map_err(|_| failure("purge owner key unavailable"))?;
            if models::space_retirement::Entity::find_by_id((digest, key.to_owned()))
                .one(tx)
                .await?
                .is_some()
            {
                retired = true;
                break;
            }
        }
        self.retired.insert(owner.into(), retired);
        Ok(retired)
    }
    async fn space_live(&mut self, tx: &DatabaseTransaction, space: &str) -> Result<bool, DbErr> {
        if self.removed == Some(space) {
            return Ok(false);
        }
        if let Some(complete) = self.completed.get(space) {
            return Ok(!complete);
        }
        let mut complete = false;
        for key in self.keys.key_ids() {
            let digest = self
                .keys
                .target_hmac(key, "space", space)
                .map_err(|_| failure("purge space key unavailable"))?;
            if models::space_purge_tombstone::Entity::find_by_id((digest, key.to_owned()))
                .one(tx)
                .await?
                .is_some()
            {
                complete = true;
                break;
            }
        }
        self.completed.insert(space.into(), complete);
        Ok(!complete)
    }
    async fn resource_live(
        &mut self,
        tx: &DatabaseTransaction,
        resource: &Resource,
    ) -> Result<Option<bool>, DbErr> {
        match resource {
            Resource::TinyCloud(resource) => self
                .space_live(tx, &resource.space().to_string())
                .await
                .map(Some),
            Resource::Other(uri) => {
                let owner = if uri.as_str().starts_with("urn:tinycloud:encryption:") {
                    crate::encryption_network::key_id::parse(uri.as_str())
                        .map_err(|_| failure("invalid signed resource owner"))?
                        .owner_did()
                        .to_owned()
                } else if uri.as_str().starts_with("did:") {
                    tinycloud_auth::identity::canonicalize_principal(uri.as_str())
                        .map_err(|_| failure("invalid signed resource owner"))?
                } else {
                    return Ok(None);
                };
                Ok(Some(!self.owner_retired(tx, &owner).await?))
            }
        }
    }
}

async fn snapshot(
    tx: &DatabaseTransaction,
    mut seeds: HashSet<Hash>,
    keys: &LedgerKeys,
    removed: Option<&str>,
    encryption: Option<&ColumnEncryption>,
    lease: &mut Lease<'_>,
) -> Result<(Graph, HashSet<Hash>, HashSet<Hash>), DbErr> {
    let mut graph = Graph::default();
    policy::preload(tx, &mut graph, &mut seeds, removed, lease).await?;
    for row in models::policy_edge::Entity::find().all(tx).await? {
        graph.extra(cid(&row.child_cid)?, cid(&row.parent_cid)?, false);
    }
    let mut controls = abilities::Entity::find()
        .select_only()
        .columns([abilities::Column::Delegation, abilities::Column::Resource])
        .filter(abilities::Column::Resource.starts_with("urn:cid:"))
        .into_tuple::<(Hash, Resource)>()
        .all(tx)
        .await?;
    controls.extend(
        invoked_abilities::Entity::find()
            .select_only()
            .columns([
                invoked_abilities::Column::Invocation,
                invoked_abilities::Column::Resource,
            ])
            .filter(invoked_abilities::Column::Resource.starts_with("urn:cid:"))
            .into_tuple::<(Hash, Resource)>()
            .all(tx)
            .await?,
    );
    for (child, resource) in controls {
        let text = resource.to_string();
        graph.extra(
            child,
            cid(text
                .strip_prefix("urn:cid:")
                .ok_or_else(|| failure("invalid control reference"))?)?,
            true,
        );
    }
    let candidates = graph.discover(tx, seeds, false, lease).await?;
    let relevant = graph.discover(tx, candidates.clone(), true, lease).await?;
    graph.records.retain(|id, _| relevant.contains(id));
    let now = OffsetDateTime::now_utc();
    let mut roots = HashSet::new();
    let mut targets = Targets {
        keys,
        removed,
        completed: HashMap::new(),
        retired: HashMap::new(),
    };
    for page in relevant.iter().copied().collect::<Vec<_>>().chunks(PAGE) {
        lease.keep(tx).await?;
        let revoked: HashSet<_> = revocation::effective_rows(tx, page)
            .await?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        for (id, expiry) in delegation::Entity::find()
            .select_only()
            .columns([delegation::Column::Id, delegation::Column::Expiry])
            .filter(delegation::Column::Id.is_in(page.iter().copied()))
            .into_tuple::<(Hash, Option<OffsetDateTime>)>()
            .all(tx)
            .await?
        {
            let record = graph.records.entry(id).or_default();
            record.kinds.insert("delegation");
            record.blocked |= revoked.contains(&id);
            record.active |= expiry.is_none_or(|expiry| now < expiry);
        }
        for row in invocation::Entity::find()
            .filter(invocation::Column::Id.is_in(page.iter().copied()))
            .all(tx)
            .await?
        {
            let bytes = maybe_decrypt(
                encryption,
                &row.serialization,
                RowBinding::new("invocation", "serialization", &[&Vec::<u8>::from(row.id)]),
                row.serialization_format,
            )
            .map_err(|_| failure("purge invocation decoding unavailable"))?;
            if hash(&bytes) != row.id {
                return Err(failure("purge invocation hash mismatch"));
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| failure("invalid stored invocation"))?;
            let (signed, _) = <TinyCloudInvocation as HeaderEncode>::decode(text)
                .map_err(|_| failure("invalid stored invocation"))?;
            let record = graph.records.entry(row.id).or_default();
            record.kinds.insert("invocation");
            record.active |= signed.payload().expiration.as_seconds() > now.unix_timestamp() as f64;
        }
        for id in revocation::Entity::find()
            .select_only()
            .column(revocation::Column::Id)
            .filter(revocation::Column::Id.is_in(page.iter().copied()))
            .into_tuple::<Hash>()
            .all(tx)
            .await?
        {
            graph
                .records
                .entry(id)
                .or_default()
                .kinds
                .insert("revocation");
        }
        let mut capabilities = abilities::Entity::find()
            .select_only()
            .columns([abilities::Column::Delegation, abilities::Column::Resource])
            .filter(abilities::Column::Delegation.is_in(page.iter().copied()))
            .into_tuple::<(Hash, Resource)>()
            .all(tx)
            .await?;
        capabilities.extend(
            invoked_abilities::Entity::find()
                .select_only()
                .columns([
                    invoked_abilities::Column::Invocation,
                    invoked_abilities::Column::Resource,
                ])
                .filter(invoked_abilities::Column::Invocation.is_in(page.iter().copied()))
                .into_tuple::<(Hash, Resource)>()
                .all(tx)
                .await?,
        );
        for (id, resource) in capabilities {
            graph
                .records
                .entry(id)
                .or_default()
                .resources
                .push(resource);
        }
        for (id, space) in crate::relationships::event_order::Entity::find()
            .select_only()
            .columns([
                crate::relationships::event_order::Column::Event,
                crate::relationships::event_order::Column::Space,
            ])
            .filter(crate::relationships::event_order::Column::Event.is_in(page.iter().copied()))
            .into_tuple::<(Hash, String)>()
            .all(tx)
            .await?
        {
            if graph
                .records
                .get(&id)
                .is_some_and(|record| record.active && !record.blocked)
                && targets.space_live(tx, &space).await?
            {
                roots.insert(id);
            }
        }
        // Current values and tombstones are live records even after their write's signature expires.
        for (id, space) in models::current_kv::Entity::find()
            .select_only()
            .columns([
                models::current_kv::Column::Invocation,
                models::current_kv::Column::Space,
            ])
            .filter(models::current_kv::Column::Invocation.is_in(page.iter().copied()))
            .into_tuple::<(Hash, String)>()
            .all(tx)
            .await?
        {
            if targets.space_live(tx, &space).await? {
                roots.insert(id);
            }
        }
    }
    let mut unresolved = HashSet::new();
    for (id, record) in &graph.records {
        lease.keep(tx).await?;
        if !record.active || record.blocked {
            continue;
        }
        let mut known_live = false;
        let mut unknown = false;
        for space in &record.spaces {
            known_live |= targets.space_live(tx, space).await?;
        }
        for resource in &record.resources {
            if resource.to_string().starts_with("urn:cid:") {
                continue;
            }
            match targets.resource_live(tx, resource).await? {
                Some(true) => known_live = true,
                Some(false) => {}
                None => unknown = true,
            }
        }
        if known_live {
            roots.insert(*id);
        } else if unknown {
            unresolved.insert(*id);
        }
    }
    // Control grants are live only while their target is needed by independent
    // live evidence. Cycles of otherwise unused control grants cannot retain themselves.
    let mut needed = graph.closure(roots.clone());
    loop {
        let mut changed = false;
        for (id, targets) in &graph.controls {
            if graph
                .records
                .get(id)
                .is_some_and(|record| record.active && !record.blocked)
                && !needed.is_disjoint(targets)
                && roots.insert(*id)
            {
                changed = true;
            }
        }
        if !changed {
            break;
        }
        needed = graph.closure(roots.clone());
    }
    for (id, targets) in &graph.controls {
        if graph
            .records
            .get(id)
            .is_some_and(|record| record.active && !record.blocked)
            && !needed.contains(id)
            && targets
                .iter()
                .all(|target| !graph.records.contains_key(target))
        {
            unresolved.insert(*id);
        }
    }
    if !unresolved.is_subset(&needed) {
        return Err(failure("signed resource ownership unavailable"));
    }
    let deleted = relevant.difference(&needed).copied().collect();
    Ok((graph, candidates, deleted))
}

pub(crate) struct Accounting {
    retained: u64,
    counts: Vec<(Vec<u8>, u64)>,
}
impl Accounting {
    pub(crate) fn emit(self) {
        for (hash, count) in self.counts {
            metric(&hash, count);
        }
    }
}
async fn accounting(
    tx: &DatabaseTransaction,
    mut jobs: HashSet<String>,
    current: &str,
    lease: &mut Lease<'_>,
) -> Result<Accounting, DbErr> {
    jobs.insert(current.into());
    let retained = count(tx, current).await?;
    let mut counts = Vec::new();
    for page in jobs.into_iter().collect::<Vec<_>>().chunks(PAGE) {
        for (id, hash) in models::space_purge_job::Entity::find()
            .select_only()
            .columns([
                models::space_purge_job::Column::PurgeId,
                models::space_purge_job::Column::TombstoneHmac,
            ])
            .filter(models::space_purge_job::Column::PurgeId.is_in(page.iter().cloned()))
            .into_tuple::<(String, Vec<u8>)>()
            .all(tx)
            .await?
        {
            lease.keep(tx).await?;
            counts.push((hash, count(tx, &id).await?));
        }
    }
    Ok(Accounting { retained, counts })
}

async fn remove_records(
    tx: &DatabaseTransaction,
    graph: &Graph,
    deleted: &HashSet<Hash>,
    lease: &mut Lease<'_>,
) -> Result<HashSet<String>, DbErr> {
    let ids: Vec<_> = deleted.iter().copied().collect();
    let mut affected = HashSet::new();
    let mut actors = HashSet::new();
    for page in ids.chunks(PAGE) {
        lease.keep(tx).await?;
        affected.extend(
            residue::Entity::find()
                .select_only()
                .column(residue::Column::PurgeId)
                .filter(residue::Column::RecordId.is_in(page.iter().copied()))
                .into_tuple::<String>()
                .all(tx)
                .await?,
        );
        for (a, b) in delegation::Entity::find()
            .select_only()
            .columns([delegation::Column::Delegator, delegation::Column::Delegatee])
            .filter(delegation::Column::Id.is_in(page.iter().copied()))
            .into_tuple::<(String, String)>()
            .all(tx)
            .await?
        {
            actors.extend([a, b]);
        }
        actors.extend(
            invocation::Entity::find()
                .select_only()
                .column(invocation::Column::Invoker)
                .filter(invocation::Column::Id.is_in(page.iter().copied()))
                .into_tuple::<String>()
                .all(tx)
                .await?,
        );
        actors.extend(
            revocation::Entity::find()
                .select_only()
                .column(revocation::Column::Revoker)
                .filter(revocation::Column::Id.is_in(page.iter().copied()))
                .into_tuple::<String>()
                .all(tx)
                .await?,
        );
        let refs: HashSet<_> = page
            .iter()
            .flat_map(|id| {
                graph
                    .aliases
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| HashSet::from([*id]))
            })
            .collect();
        models::current_kv::Entity::delete_many()
            .filter(models::current_kv::Column::Invocation.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        models::kv_delete::Entity::delete_many()
            .filter(
                Condition::any()
                    .add(models::kv_delete::Column::InvocationId.is_in(page.iter().copied()))
                    .add(
                        models::kv_delete::Column::DeletedInvocationId.is_in(page.iter().copied()),
                    ),
            )
            .exec(tx)
            .await?;
        models::kv_write::Entity::delete_many()
            .filter(models::kv_write::Column::Invocation.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        crate::relationships::event_order::Entity::delete_many()
            .filter(crate::relationships::event_order::Column::Event.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        invoked_abilities::Entity::delete_many()
            .filter(invoked_abilities::Column::Invocation.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        abilities::Entity::delete_many()
            .filter(abilities::Column::Delegation.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        parent_delegations::Entity::delete_many()
            .filter(
                Condition::any()
                    .add(parent_delegations::Column::Child.is_in(refs.iter().copied()))
                    .add(parent_delegations::Column::Parent.is_in(refs)),
            )
            .exec(tx)
            .await?;
        // Aliases and revocations must go before their referenced delegation rows.
        delegation_cid_alias::Entity::delete_many()
            .filter(delegation_cid_alias::Column::Id.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        revocation::Entity::delete_many()
            .filter(revocation::Column::Id.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        models::invocation_replay::Entity::delete_many()
            .filter(models::invocation_replay::Column::ContentHash.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        residue::Entity::delete_many()
            .filter(residue::Column::RecordId.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
    }
    policy::remove(tx, deleted, lease).await?;
    // A referenced delegation and its revocation may occur in different pages.
    for page in ids.chunks(PAGE) {
        lease.keep(tx).await?;
        delegation::Entity::delete_many()
            .filter(delegation::Column::Id.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
        invocation::Entity::delete_many()
            .filter(invocation::Column::Id.is_in(page.iter().copied()))
            .exec(tx)
            .await?;
    }
    for row in models::policy_edge::Entity::find().all(tx).await? {
        lease.keep(tx).await?;
        if deleted.contains(&cid(&row.child_cid)?) || deleted.contains(&cid(&row.parent_cid)?) {
            models::policy_edge::Entity::delete_by_id((row.child_cid, row.position))
                .exec(tx)
                .await?;
        }
    }
    for page in actors.into_iter().collect::<Vec<_>>().chunks(PAGE) {
        lease.keep(tx).await?;
        models::actor::Entity::delete_many().filter(models::actor::Column::Id.is_in(page.iter().cloned()))
            .filter(sea_orm::sea_query::Expr::cust("NOT EXISTS(SELECT 1 FROM delegation d WHERE d.delegator=actor.id OR d.delegatee=actor.id)
                AND NOT EXISTS(SELECT 1 FROM invocation i WHERE i.invoker=actor.id)
                AND NOT EXISTS(SELECT 1 FROM revocation r WHERE r.revoker=actor.id)"))
            .exec(tx).await?;
    }
    Ok(affected)
}

/// Called inside the lease-checked terminal transaction, before its tombstone.
/// All target links disappear atomically with completion; other live proofs stay unchanged.
pub(crate) async fn complete_space(
    tx: &DatabaseTransaction,
    job: &crate::space_purge_worker::ClaimedPurge,
    keys: &LedgerKeys,
    encryption: Option<&ColumnEncryption>,
) -> Result<Accounting, DbErr> {
    lock(tx).await?;
    let space = job.space.as_str();
    let purge_id = job.purge_id.as_str();
    let mut lease = Lease {
        job: Some(job),
        last: std::time::Instant::now(),
    };
    let roots = tx
        .query_all(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT event AS id FROM event_order WHERE space=$1
         UNION SELECT delegation AS id FROM ability WHERE split_part(resource,'/',1)=$1
         UNION SELECT invocation AS id FROM invoked_abilities WHERE split_part(resource,'/',1)=$1",
            [space.into()],
        ))
        .await?;
    let seeds = roots
        .into_iter()
        .map(|row| row.try_get::<Hash>("", "id"))
        .collect::<Result<HashSet<_>, _>>()?;
    let mut direct = seeds.clone();
    let (graph, _, deleted) =
        snapshot(tx, seeds, keys, Some(space), encryption, &mut lease).await?;
    direct.extend(graph.direct_policy.iter().copied());
    let linked: HashSet<_> = direct
        .iter()
        .flat_map(|id| {
            graph
                .aliases
                .get(id)
                .cloned()
                .unwrap_or_else(|| HashSet::from([*id]))
        })
        .collect();
    for sql in [
        "DELETE FROM current_kv WHERE space=$1",
        "DELETE FROM kv_delete WHERE space=$1",
        "DELETE FROM kv_write WHERE space=$1",
        "DELETE FROM event_order WHERE space=$1",
        "DELETE FROM epoch_order WHERE space=$1",
        "DELETE FROM epoch_head WHERE space=$1",
        "DELETE FROM epoch WHERE space=$1",
        "DELETE FROM ability WHERE split_part(resource,'/',1)=$1",
        "DELETE FROM invoked_abilities WHERE split_part(resource,'/',1)=$1",
    ] {
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            sql,
            [space.into()],
        ))
        .await?;
    }
    let affected = remove_records(tx, &graph, &deleted, &mut lease).await?;
    for id in linked.difference(&deleted) {
        lease.keep(tx).await?;
        if let Some(record) = graph.records.get(id) {
            for kind in &record.kinds {
                residue::Entity::insert(residue::ActiveModel {
                    purge_id: Set(purge_id.into()),
                    record_kind: Set((*kind).into()),
                    record_id: Set(*id),
                })
                .on_conflict(
                    sea_orm::sea_query::OnConflict::columns([
                        residue::Column::PurgeId,
                        residue::Column::RecordKind,
                        residue::Column::RecordId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec_without_returning(tx)
                .await?;
            }
        }
    }
    accounting(tx, affected, purge_id, &mut lease).await
}

pub async fn count<C: ConnectionTrait>(db: &C, purge_id: &str) -> Result<u64, DbErr> {
    use sea_orm::PaginatorTrait;
    residue::Entity::find()
        .filter(residue::Column::PurgeId.eq(purge_id))
        .count(db)
        .await
}

/// Durable wakeup is written in the revocation transaction and visible only after commit.
pub async fn request_for_records<C: ConnectionTrait>(db: &C, ids: &[Hash]) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Postgres {
        return Ok(());
    }
    for page in ids.chunks(PAGE) {
        let seeds = page
            .iter()
            .enumerate()
            .map(|(i, _)| format!("(${}::BYTEA)", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql=format!("WITH RECURSIVE edges(child,parent) AS (
            SELECT child,parent FROM parent_delegation UNION SELECT id,canonical FROM delegation_cid_alias
            UNION SELECT canonical,id FROM delegation_cid_alias), affected(id) AS (
            SELECT id FROM (VALUES {seeds}) seed(id) UNION SELECT e.parent FROM edges e JOIN affected a ON e.child=a.id)
            UPDATE space_purge_job SET next_attempt_at=clock_timestamp() WHERE phase='complete'
            AND purge_id IN(SELECT purge_id FROM space_purge_shared_residue WHERE record_id IN(SELECT id FROM affected))");
        db.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            sql,
            page.iter().copied().map(Into::into),
        ))
        .await?;
    }
    Ok(())
}

/// Retirement and policy revocation can release proofs belonging to another
/// purge owner. Wake every existing residue job, not just same-owner space jobs.
pub async fn request_all<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    if db.get_database_backend() == DatabaseBackend::Postgres {
        db.execute_unprepared("UPDATE space_purge_job j SET next_attempt_at=clock_timestamp()
            WHERE phase='complete' AND EXISTS(SELECT 1 FROM space_purge_shared_residue r WHERE r.purge_id=j.purge_id)").await?;
    }
    Ok(())
}

/// Revisit one completed purge without a raw space identifier, including jobs
/// left by standalone deletion before a subsequent owner retirement.
pub async fn sweep(
    db: &DatabaseConnection,
    purge_id: &str,
    keys: &LedgerKeys,
    encryption: Option<&ColumnEncryption>,
) -> Result<u64, DbErr> {
    let tx = db.begin().await?;
    lock(&tx).await?;
    let result = sweep_transaction(&tx, purge_id, keys, encryption).await?;
    let retained = result.retained;
    tx.commit().await?;
    result.emit();
    Ok(retained)
}

/// Called by the worker every bounded iteration; each successful scan schedules
/// its next check no later than 24 hours. Durable wakeups make revocation immediate.
pub async fn sweep_next(
    db: &DatabaseConnection,
    keys: &LedgerKeys,
    encryption: Option<&ColumnEncryption>,
) -> Result<bool, DbErr> {
    let tx = db.begin().await?;
    lock(&tx).await?;
    let row=tx.query_one(Statement::from_string(DatabaseBackend::Postgres,
        "SELECT purge_id FROM space_purge_job j WHERE phase='complete' AND next_attempt_at<=clock_timestamp()
         AND EXISTS(SELECT 1 FROM space_purge_shared_residue r WHERE r.purge_id=j.purge_id)
         ORDER BY next_attempt_at,purge_id LIMIT 1 FOR UPDATE SKIP LOCKED".to_owned())).await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let result = sweep_transaction(
        &tx,
        &row.try_get::<String>("", "purge_id")?,
        keys,
        encryption,
    )
    .await?;
    tx.commit().await?;
    result.emit();
    Ok(true)
}

async fn sweep_transaction(
    tx: &DatabaseTransaction,
    purge_id: &str,
    keys: &LedgerKeys,
    encryption: Option<&ColumnEncryption>,
) -> Result<Accounting, DbErr> {
    let job = models::space_purge_job::Entity::find_by_id(purge_id)
        .lock_exclusive()
        .one(tx)
        .await?
        .ok_or_else(|| failure("missing residue purge job"))?;
    if job.phase != "complete" {
        return Err(failure("residue sweep requires completed purge"));
    }
    let seeds = residue::Entity::find()
        .select_only()
        .column(residue::Column::RecordId)
        .filter(residue::Column::PurgeId.eq(purge_id))
        .into_tuple::<Hash>()
        .all(tx)
        .await?
        .into_iter()
        .collect();
    let mut lease = Lease {
        job: None,
        last: std::time::Instant::now(),
    };
    let (graph, _, deleted) = snapshot(tx, seeds, keys, None, encryption, &mut lease).await?;
    let affected = remove_records(tx, &graph, &deleted, &mut lease).await?;
    models::space_purge_job::Entity::update_many()
        .col_expr(
            models::space_purge_job::Column::NextAttemptAt,
            sea_orm::sea_query::Expr::value(
                OffsetDateTime::now_utc() + time::Duration::seconds(SWEEP_INTERVAL_SECONDS),
            ),
        )
        .filter(models::space_purge_job::Column::PurgeId.eq(purge_id))
        .exec(tx)
        .await?;
    accounting(tx, affected, purge_id, &mut lease).await
}

pub async fn refresh_metrics<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT j.tombstone_hmac,count(*) AS retained FROM space_purge_job j
         JOIN space_purge_shared_residue r ON r.purge_id=j.purge_id GROUP BY j.tombstone_hmac"
                .to_owned(),
        ))
        .await?;
    for row in rows {
        metric(
            &row.try_get::<Vec<u8>>("", "tombstone_hmac")?,
            row.try_get::<i64>("", "retained")? as u64,
        );
    }
    Ok(())
}

pub fn metric(purge_hash: &[u8], retained: u64) {
    use std::sync::OnceLock;
    static METRIC: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
    let gauge = METRIC.get_or_init(|| {
        prometheus::register_int_gauge_vec!(
            "tinycloud_space_purge_retained_signed_records",
            "Retained signed records per opaque purged-target hash.",
            &["purge_hash"]
        )
        .expect("purge residue metric registers once")
    });
    let hash = hex::encode(purge_hash);
    if retained == 0 {
        let _ = gauge.remove_label_values(&[&hash]);
    } else {
        gauge
            .with_label_values(&[&hash])
            .set(retained.min(i64::MAX as u64) as i64);
    }
    tracing::info!(target:"tinycloud::space_purge",purge_hash=%hash,retained_signed_records=retained,"Purge signed-record accounting");
}
