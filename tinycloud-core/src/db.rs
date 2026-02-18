use crate::events::{epoch_hash, Delegation, Event, HashError, Invocation, Operation, Revocation};
use crate::hash::Hash;
use crate::keys::{get_did_key, Secrets};
use crate::migrations::Migrator;
use crate::models::*;
use crate::relationships::*;
use crate::storage::{
    either::EitherError, Content, HashBuffer, ImmutableDeleteStore, ImmutableReadStore,
    ImmutableStaging, ImmutableWriteStore, StorageSetup, StoreSize,
};
use crate::types::{CapabilitiesReadParams, ListFilters, Metadata, Resource, SpaceIdWrap};
use crate::util::{Capability, DelegationInfo};
use sea_orm::{
    entity::prelude::*,
    error::{DbErr, RuntimeErr, SqlxError},
    query::*,
    sea_query::OnConflict,
    ConnectionTrait, DatabaseTransaction, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use std::collections::HashMap;
use tinycloud_lib::{
    authorization::{EncodingError, TinyCloudDelegation},
    resource::{Path, SpaceId},
};

#[derive(Debug, Clone)]
pub struct SpaceDatabase<C, B, S> {
    conn: C,
    storage: B,
    secrets: S,
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub rev: Hash,
    pub seq: i64,
    pub committed_events: Vec<Hash>,
    pub consumed_epochs: Vec<Hash>,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TxError<S: StorageSetup, K: Secrets> {
    #[error("database error: {0}")]
    Db(#[from] DbErr),
    #[error(transparent)]
    Ucan(#[from] tinycloud_lib::ssi::ucan::Error),
    #[error(transparent)]
    Cacao(#[from] tinycloud_lib::cacaos::siwe_cacao::VerificationError),
    #[error(transparent)]
    InvalidDelegation(#[from] delegation::DelegationError),
    #[error(transparent)]
    InvalidInvocation(#[from] invocation::InvocationError),
    #[error(transparent)]
    InvalidRevocation(#[from] revocation::RevocationError),
    #[error("Epoch Hashing Err: {0}")]
    EpochHashingErr(#[from] HashError),
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    #[error(transparent)]
    StoreSetup(S::Error),
    #[error(transparent)]
    Secrets(K::Error),
    #[error("Space not found")]
    SpaceNotFound,
    #[error("Invalid delegation CID: {0}")]
    InvalidCid(String),
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TxStoreError<B, S, K>
where
    B: ImmutableReadStore + ImmutableWriteStore<S> + ImmutableDeleteStore + StorageSetup,
    S: ImmutableStaging,
    S::Writable: 'static + Unpin,
    K: Secrets,
{
    #[error(transparent)]
    Tx(#[from] TxError<B, K>),
    #[error(transparent)]
    StoreRead(<B as ImmutableReadStore>::Error),
    #[error(transparent)]
    StoreWrite(<B as ImmutableWriteStore<S>>::Error),
    #[error(transparent)]
    StoreDelete(<B as ImmutableDeleteStore>::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Missing Input for requested action")]
    MissingInput,
}

impl<B, S, K> From<DbErr> for TxStoreError<B, S, K>
where
    B: ImmutableReadStore + ImmutableWriteStore<S> + ImmutableDeleteStore + StorageSetup,
    S: ImmutableStaging,
    S::Writable: 'static + Unpin,
    K: Secrets,
{
    fn from(e: DbErr) -> Self {
        TxStoreError::Tx(e.into())
    }
}

impl<B, K> SpaceDatabase<DatabaseConnection, B, K> {
    pub async fn new(conn: DatabaseConnection, storage: B, secrets: K) -> Result<Self, DbErr> {
        Migrator::up(&conn, None).await?;
        Ok(Self {
            conn,
            storage,
            secrets,
        })
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    K: Secrets,
{
    pub async fn stage_key(&self, space_id: &SpaceId) -> Result<String, K::Error> {
        self.secrets.stage_keypair(space_id).await.map(get_did_key)
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait,
{
    // to allow users to make custom read queries
    pub async fn readable(&self) -> Result<DatabaseTransaction, DbErr> {
        self.conn
            .begin_with_config(None, Some(sea_orm::AccessMode::ReadOnly))
            .await
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    B: StoreSize,
{
    pub async fn store_size(&self, space_id: &SpaceId) -> Result<Option<u64>, B::Error> {
        self.storage.total_size(space_id).await
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait,
{
    pub async fn check_db_connection(&self) -> Result<(), DbErr> {
        // there's a `ping` method on the connection, but we can't access it from here
        // but starting a transaction should be enough to check the connection
        self.conn.begin().await.map(|_| ())
    }
}

pub type InvocationInputs<W> = HashMap<(SpaceId, Path), (Metadata, HashBuffer<W>)>;

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait,
    B: StorageSetup,
    K: Secrets,
{
    async fn transact(
        &self,
        events: Vec<Event>,
    ) -> Result<HashMap<SpaceId, Commit>, TxError<B, K>> {
        let tx = self
            .conn
            .begin_with_config(Some(sea_orm::IsolationLevel::ReadUncommitted), None)
            .await?;

        let commit = transact(&tx, &self.storage, &self.secrets, events).await?;

        tx.commit().await?;

        Ok(commit)
    }

    pub async fn delegate(
        &self,
        delegation: Delegation,
    ) -> Result<HashMap<SpaceId, Commit>, TxError<B, K>> {
        self.transact(vec![Event::Delegation(Box::new(delegation))])
            .await
    }

    pub async fn revoke(
        &self,
        revocation: Revocation,
    ) -> Result<HashMap<SpaceId, Commit>, TxError<B, K>> {
        self.transact(vec![Event::Revocation(Box::new(revocation))])
            .await
    }

    pub async fn invoke<S>(
        &self,
        invocation: Invocation,
        mut inputs: InvocationInputs<S::Writable>,
    ) -> Result<
        (
            HashMap<SpaceId, Commit>,
            Vec<InvocationOutcome<B::Readable>>,
        ),
        TxStoreError<B, S, K>,
    >
    where
        B: ImmutableWriteStore<S> + ImmutableDeleteStore + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        let mut stages = HashMap::new();
        let mut ops = Vec::new();
        // for each capability being invoked
        for cap in invocation.0.capabilities.iter() {
            match cap.resource.tinycloud_resource().and_then(|r| {
                Some((
                    r.space(),
                    r.service().as_str(),
                    cap.ability.as_ref().as_ref(),
                    r.path()?,
                ))
            }) {
                // stage inputs for content writes
                Some((space, "kv", "tinycloud.kv/put", path)) => {
                    let (metadata, mut stage) = inputs
                        .remove(&(space.clone(), path.clone()))
                        .ok_or(TxStoreError::MissingInput)?;

                    let value = stage.hash();

                    stages.insert((space.clone(), path.clone()), stage);
                    // add write for tx
                    ops.push(Operation::KvWrite {
                        space: space.clone(),
                        key: path.clone(),
                        metadata,
                        value,
                    });
                }
                // add delete for tx
                Some((space, "kv", "tinycloud.kv/del", path)) => {
                    ops.push(Operation::KvDelete {
                        space: space.clone(),
                        key: path.clone(),
                        version: None,
                    });
                }
                _ => {}
            }
        }

        let tx = self
            .conn
            .begin_with_config(Some(sea_orm::IsolationLevel::ReadUncommitted), None)
            .await?;
        let caps = invocation.0.capabilities.clone();
        let invoker = invocation.0.invoker.clone();
        // Extract capabilities read params from UCAN facts field
        // Facts is Vec<JsonValue>, we look for an object with capabilitiesReadParams key
        let caps_read_params: Option<CapabilitiesReadParams> = invocation
            .0
            .invocation
            .payload()
            .facts
            .as_ref()
            .and_then(|facts| {
                facts.iter().find_map(|fact| {
                    fact.as_object()
                        .and_then(|obj| obj.get("capabilitiesReadParams"))
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                })
            });
        //  verify and commit invocation and kv operations
        let commit = transact(
            &tx,
            &self.storage,
            &self.secrets,
            vec![Event::Invocation(Box::new(invocation), ops)],
        )
        .await?;

        let mut results = Vec::new();
        // perform and record side effects
        for cap in caps.iter().filter_map(|c| {
            c.resource.tinycloud_resource().and_then(|r| {
                Some((
                    r.space(),
                    r.service().as_str(),
                    c.ability.as_ref().as_ref(),
                    r.path()?,
                ))
            })
        }) {
            match cap {
                (space, "kv", "tinycloud.kv/get", path) => results.push(InvocationOutcome::KvRead(
                    get_kv(&tx, &self.storage, space, path)
                        .await
                        .map_err(|e| match e {
                            EitherError::A(e) => TxStoreError::Tx(e.into()),
                            EitherError::B(e) => TxStoreError::StoreRead(e),
                        })?,
                )),
                (space, "kv", "tinycloud.kv/list", path) => {
                    results.push(InvocationOutcome::KvList(list(&tx, space, path).await?))
                }
                (space, "kv", "tinycloud.kv/del", path) => {
                    let kv = get_kv_entity(&tx, space, path).await?;
                    if let Some(kv) = kv {
                        self.storage
                            .remove(space, &kv.value)
                            .await
                            .map_err(TxStoreError::StoreDelete)?;
                    }
                    results.push(InvocationOutcome::KvDelete)
                }
                (space, "kv", "tinycloud.kv/put", path) => {
                    if let Some(stage) = stages.remove(&(space.clone(), path.clone())) {
                        self.storage
                            .persist(space, stage)
                            .await
                            .map_err(TxStoreError::StoreWrite)?;
                        results.push(InvocationOutcome::KvWrite)
                    }
                }
                (space, "kv", "tinycloud.kv/metadata", path) => results.push(
                    InvocationOutcome::KvMetadata(metadata(&tx, space, path).await?),
                ),
                (space, "capabilities", "tinycloud.capabilities/read", path)
                    if path.as_str() == "all" =>
                {
                    match &caps_read_params {
                        None => {
                            // Backward compatible: no params means return all valid delegations
                            results.push(InvocationOutcome::OpenSessions(
                                get_valid_delegations(&tx, space).await?,
                            ))
                        }
                        Some(CapabilitiesReadParams::List { filters }) => {
                            // List with optional filters
                            results.push(InvocationOutcome::OpenSessions(
                                get_filtered_delegations(&tx, space, &invoker, filters.as_ref())
                                    .await?,
                            ))
                        }
                        Some(CapabilitiesReadParams::Chain { delegation_cid }) => {
                            // Get the delegation chain for a specific delegation
                            results.push(InvocationOutcome::DelegationChain(
                                get_delegation_chain(&tx, space, delegation_cid).await?,
                            ))
                        }
                    }
                }
                _ => {}
            };
        }

        // commit tx if all side effects worked
        tx.commit().await?;
        Ok((commit, results))
    }
}

#[derive(Debug)]
pub enum InvocationOutcome<R> {
    KvList(Vec<Path>),
    KvDelete,
    KvMetadata(Option<Metadata>),
    KvWrite,
    KvRead(Option<(Metadata, Hash, Content<R>)>),
    OpenSessions(HashMap<Hash, DelegationInfo>),
    /// Ordered delegation chain from leaf to root
    DelegationChain(Vec<DelegationInfo>),
}

impl<S: StorageSetup, K: Secrets> From<delegation::Error> for TxError<S, K> {
    fn from(e: delegation::Error) -> Self {
        match e {
            delegation::Error::InvalidDelegation(e) => Self::InvalidDelegation(e),
            delegation::Error::Db(e) => Self::Db(e),
        }
    }
}

impl<S: StorageSetup, K: Secrets> From<invocation::Error> for TxError<S, K> {
    fn from(e: invocation::Error) -> Self {
        match e {
            invocation::Error::InvalidInvocation(e) => Self::InvalidInvocation(e),
            invocation::Error::Db(e) => Self::Db(e),
        }
    }
}

impl<S: StorageSetup, K: Secrets> From<revocation::Error> for TxError<S, K> {
    fn from(e: revocation::Error) -> Self {
        match e {
            revocation::Error::InvalidRevocation(e) => Self::InvalidRevocation(e),
            revocation::Error::Db(e) => Self::Db(e),
        }
    }
}

async fn event_spaces<'a, C: ConnectionTrait>(
    db: &C,
    ev: &'a [(Hash, Event)],
) -> Result<HashMap<SpaceId, Vec<&'a (Hash, Event)>>, DbErr> {
    // get orderings of events listed as revoked by events in the ev list
    let mut spaces = HashMap::<SpaceId, Vec<&'a (Hash, Event)>>::new();
    let revoked_events = event_order::Entity::find()
        .filter(
            event_order::Column::Event.is_in(ev.iter().filter_map(|(_, e)| match e {
                Event::Revocation(r) => Some(Hash::from(r.0.revoked)),
                _ => None,
            })),
        )
        .all(db)
        .await?;
    for e in ev {
        match &e.1 {
            Event::Delegation(d) => {
                for space in d.0.spaces() {
                    let entry = spaces.entry(space.clone()).or_default();
                    if !entry.iter().any(|(h, _)| h == &e.0) {
                        entry.push(e);
                    }
                }
            }
            Event::Invocation(i, _) => {
                for space in i.0.spaces() {
                    let entry = spaces.entry(space.clone()).or_default();
                    if !entry.iter().any(|(h, _)| h == &e.0) {
                        entry.push(e);
                    }
                }
            }
            Event::Revocation(r) => {
                let r_hash = Hash::from(r.0.revoked);
                for revoked in &revoked_events {
                    if r_hash == revoked.event {
                        let entry = spaces.entry(revoked.space.0.clone()).or_default();
                        if !entry.iter().any(|(h, _)| h == &e.0) {
                            entry.push(e);
                        }
                    }
                }
            }
        }
    }
    Ok(spaces)
}

pub(crate) async fn transact<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    store_setup: &S,
    secrets: &K,
    events: Vec<Event>,
) -> Result<HashMap<SpaceId, Commit>, TxError<S, K>> {
    // for each event, get the hash and the relevent space(s)
    let event_hashes = events
        .into_iter()
        .map(|e| (e.hash(), e))
        .collect::<Vec<(Hash, Event)>>();
    let event_spaces = event_spaces(db, &event_hashes).await?;
    let mut new_spaces = event_hashes
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Delegation(d) => Some(d.0.capabilities.iter().filter_map(|c| {
                match (&c.resource, c.ability.as_ref().as_ref()) {
                    (Resource::TinyCloud(r), "tinycloud.space/host")
                        if r.path().is_none()
                            && r.service().as_str() == "space"
                            && r.query().is_none()
                            && r.fragment().is_none() =>
                    {
                        Some(SpaceIdWrap(r.space().clone()))
                    }
                    _ => None,
                }
            })),
            _ => None,
        })
        .flatten()
        .collect::<Vec<SpaceIdWrap>>();
    new_spaces.dedup();

    if !new_spaces.is_empty() {
        match space::Entity::insert_many(
            new_spaces
                .iter()
                .cloned()
                .map(|id| space::Model { id })
                .map(space::ActiveModel::from),
        )
        .on_conflict(
            OnConflict::column(space::Column::Id)
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
    }

    // get max sequence for each of the spaces
    let mut max_seqs = event_order::Entity::find()
        .filter(event_order::Column::Space.is_in(event_spaces.keys().cloned().map(SpaceIdWrap)))
        .select_only()
        .column(event_order::Column::Space)
        .column_as(event_order::Column::Seq.max(), "max_seq")
        .group_by(event_order::Column::Space)
        .into_tuple::<(SpaceIdWrap, i64)>()
        .all(db)
        .await?
        .into_iter()
        .fold(HashMap::new(), |mut m, (space, seq)| {
            m.insert(space, seq + 1);
            m
        });

    // get 'most recent' epochs for each of the spaces
    let mut most_recent = epoch::Entity::find()
        .select_only()
        .left_join(epoch_order::Entity)
        .filter(
            Condition::all()
                .add(epoch::Column::Space.is_in(event_spaces.keys().cloned().map(SpaceIdWrap)))
                .add(epoch_order::Column::Child.is_null()),
        )
        .column(epoch::Column::Space)
        .column(epoch::Column::Id)
        .into_tuple::<(SpaceIdWrap, Hash)>()
        .all(db)
        .await?
        .into_iter()
        .fold(
            HashMap::new(),
            |mut m: HashMap<SpaceIdWrap, Vec<Hash>>, (space, epoch)| {
                m.entry(space).or_default().push(epoch);
                m
            },
        );

    // get all the orderings and associated data
    let (epoch_order, space_order, event_order, epochs) = event_spaces
        .into_iter()
        .map(|(space, events)| {
            let parents = most_recent.remove(&space).unwrap_or_default();
            let epoch = epoch_hash(&space, &events, &parents)?;
            let seq = max_seqs.remove(&space).unwrap_or(0);
            Ok((space, (epoch, events, seq, parents)))
        })
        .collect::<Result<HashMap<_, _>, HashError>>()?
        .into_iter()
        .map(|(space, (epoch, hashes, seq, parents))| {
            (
                parents
                    .iter()
                    .map(|parent| epoch_order::Model {
                        parent: *parent,
                        child: epoch,
                        space: space.clone().into(),
                    })
                    .map(epoch_order::ActiveModel::from)
                    .collect::<Vec<epoch_order::ActiveModel>>(),
                (
                    space.clone(),
                    (
                        seq,
                        epoch,
                        parents,
                        hashes
                            .iter()
                            .enumerate()
                            .map(|(i, (h, _))| (*h, i as i64))
                            .collect::<HashMap<_, _>>(),
                    ),
                ),
                hashes
                    .into_iter()
                    .enumerate()
                    .map(|(es, (hash, _))| event_order::Model {
                        event: *hash,
                        space: space.clone().into(),
                        seq,
                        epoch,
                        epoch_seq: es as i64,
                    })
                    .map(event_order::ActiveModel::from)
                    .collect::<Vec<event_order::ActiveModel>>(),
                epoch::Model {
                    seq,
                    id: epoch,
                    space: space.into(),
                },
            )
        })
        .fold(
            (
                Vec::<epoch_order::ActiveModel>::new(),
                HashMap::<SpaceId, (i64, Hash, Vec<Hash>, HashMap<Hash, i64>)>::new(),
                Vec::<event_order::ActiveModel>::new(),
                Vec::<epoch::ActiveModel>::new(),
            ),
            |(mut eo, mut so, mut ev, mut ep), (eo2, order, ev2, ep2)| {
                eo.extend(eo2);
                ev.extend(ev2);
                so.insert(order.0, order.1);
                ep.push(ep2.into());
                (eo, so, ev, ep)
            },
        );

    // save epochs
    epoch::Entity::insert_many(epochs)
        .exec(db)
        .await
        .map_err(|e| match e {
            DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(_))) => TxError::SpaceNotFound,
            _ => e.into(),
        })?;

    // save epoch orderings
    if !epoch_order.is_empty() {
        epoch_order::Entity::insert_many(epoch_order)
            .exec(db)
            .await?;
    }

    // save event orderings
    event_order::Entity::insert_many(event_order)
        .exec(db)
        .await?;

    for (hash, event) in event_hashes {
        match event {
            Event::Delegation(d) => delegation::process(db, *d).await?,
            Event::Invocation(i, ops) => {
                invocation::process(
                    db,
                    *i,
                    ops.into_iter()
                        .map(|op| {
                            let v = space_order
                                .get(op.space())
                                .and_then(|(s, e, _, h)| Some((s, e, h.get(&hash)?)))
                                .unwrap();
                            op.version(*v.0, *v.1, *v.2)
                        })
                        .collect(),
                )
                .await?
            }
            Event::Revocation(r) => revocation::process(db, *r).await?,
        };
    }

    for space in new_spaces {
        store_setup
            .create(&space.0)
            .await
            .map_err(TxError::StoreSetup)?;
        secrets
            .save_keypair(&space.0)
            .await
            .map_err(TxError::Secrets)?;
    }

    Ok(space_order
        .into_iter()
        .map(|(o, (seq, rev, consumed_epochs, h))| {
            (
                o,
                Commit {
                    seq,
                    rev,
                    consumed_epochs,
                    committed_events: h.keys().cloned().collect(),
                },
            )
        })
        .collect())
}

async fn list<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    prefix: &Path,
) -> Result<Vec<Path>, DbErr> {
    // get content id for key from db
    let mut list = kv_write::Entity::find()
        .filter(
            Condition::all()
                .add(kv_write::Column::Key.starts_with(prefix.as_str()))
                .add(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone()))),
        )
        .find_also_related(kv_delete::Entity)
        .filter(kv_delete::Column::InvocationId.is_null())
        .all(db)
        .await?
        .into_iter()
        .map(|(kv, _)| kv.key.0)
        .collect::<Vec<Path>>();
    list.dedup();
    Ok(list)
}

async fn metadata<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<Metadata>, DbErr> {
    match get_kv_entity(db, space_id, key).await? {
        Some(entry) => Ok(Some(entry.metadata)),
        None => Ok(None),
    }
}

async fn get_kv<C: ConnectionTrait, B: ImmutableReadStore>(
    db: &C,
    store: &B,
    space_id: &SpaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<(Metadata, Hash, Content<B::Readable>)>, EitherError<DbErr, B::Error>> {
    let e = match get_kv_entity(db, space_id, key)
        .await
        .map_err(EitherError::A)?
    {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let content_hash = e.value;
    let c = match store
        .read(space_id, &content_hash)
        .await
        .map_err(EitherError::B)?
    {
        Some(c) => c,
        None => return Ok(None),
    };
    Ok(Some((e.metadata, content_hash, c)))
}

async fn get_kv_entity<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<kv_write::Model>, DbErr> {
    // Ok(if let Some((seq, epoch, epoch_seq)) = version {
    //     event_order::Entity::find_by_id((epoch, epoch_seq, space_id.clone().into()))
    //         .reverse_join(kv_write::Entity)
    //         .find_also_related(kv_delete::Entity)
    //         .filter(
    //             Condition::all()
    //                 .add(kv_write::Column::Key.eq(key))
    //                 .add(kv_write::Column::Space.eq(space_id.clone().into()))
    //                 .add(kv_delete::Column::InvocationId.is_null()),
    //         )
    //         .one(db)
    //         .await?
    //         .map(|(kv, _)| kv)
    // } else {
    // we want to find the latest kv_write which is not deleted
    Ok(kv_write::Entity::find()
        .filter(
            Condition::all()
                .add(kv_write::Column::Key.eq(key.as_str()))
                .add(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone()))),
        )
        .order_by_desc(kv_write::Column::Seq)
        .order_by_desc(kv_write::Column::Epoch)
        .order_by_desc(kv_write::Column::EpochSeq)
        .find_also_related(kv_delete::Entity)
        .filter(kv_delete::Column::InvocationId.is_null())
        .one(db)
        .await?
        .map(|(kv, _)| kv))
}

async fn get_valid_delegations<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
) -> Result<HashMap<Hash, DelegationInfo>, TxError<S, K>> {
    let (dels, abilities): (Vec<delegation::Model>, Vec<Vec<abilities::Model>>) =
        delegation::Entity::find()
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await?
            .into_iter()
            .unzip();
    let parents = dels.load_many(parent_delegations::Entity, db).await?;
    let now = time::OffsetDateTime::now_utc();
    Ok(dels
        .into_iter()
        .zip(abilities)
        .zip(parents)
        .filter_map(|((del, ability), parents)| {
            if del.expiry.map(|e| e > now).unwrap_or(true)
                && del.not_before.map(|n| n <= now).unwrap_or(true)
                && ability.iter().any(|a| a.resource.space() == Some(space_id))
            {
                Some(match TinyCloudDelegation::from_bytes(&del.serialization) {
                    Ok(delegation) => Ok((
                        del.id,
                        DelegationInfo {
                            delegator: del.delegator,
                            delegate: del.delegatee,
                            parents: parents.into_iter().map(|p| p.parent.to_cid(0x55)).collect(),
                            expiry: del.expiry,
                            not_before: del.not_before,
                            issued_at: del.issued_at,
                            capabilities: ability
                                .into_iter()
                                .map(|a| Capability {
                                    resource: a.resource,
                                    ability: a.ability,
                                })
                                .collect(),
                            delegation,
                        },
                    )),
                    Err(e) => Err(e),
                })
            } else {
                None
            }
        })
        .collect::<Result<HashMap<Hash, DelegationInfo>, EncodingError>>()?)
}

/// Resolve a session key DID (did:key:...) to its root PKH DID (did:pkh:...).
///
/// Session keys are delegated to from PKH DIDs. This function traverses the delegation
/// chain to find the root PKH DID that authorized the session key.
///
/// Returns the original DID if it's already a PKH DID or if no delegation chain is found.
async fn resolve_pkh_did<C: ConnectionTrait>(db: &C, did: &str) -> Result<String, DbErr> {
    // If already a PKH DID, return it directly
    if did.starts_with("did:pkh:") {
        return Ok(did.to_string());
    }

    // Look for a delegation where this DID is the delegatee
    // The delegator would be the next step up in the chain
    let mut current_did = did.to_string();
    let mut visited = std::collections::HashSet::new();

    loop {
        // Prevent infinite loops
        if !visited.insert(current_did.clone()) {
            break;
        }

        // Find a delegation where current_did is the delegatee
        let parent_delegation = delegation::Entity::find()
            .filter(delegation::Column::Delegatee.eq(&current_did))
            .one(db)
            .await?;

        match parent_delegation {
            Some(del) => {
                // Found a parent - check if it's a PKH DID
                if del.delegator.starts_with("did:pkh:") {
                    return Ok(del.delegator);
                }
                // Continue up the chain
                current_did = del.delegator;
            }
            None => {
                // No parent found - return what we have
                break;
            }
        }
    }

    // Return the original DID if we couldn't resolve to a PKH
    Ok(did.to_string())
}

/// Get delegations with optional filters applied.
/// Filters by direction (created/received relative to invoker), path prefix, and actions.
async fn get_filtered_delegations<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
    invoker: &str,
    filters: Option<&ListFilters>,
) -> Result<HashMap<Hash, DelegationInfo>, TxError<S, K>> {
    // Resolve session key DID to PKH DID for direction filtering
    let pkh_did = resolve_pkh_did(db, invoker)
        .await
        .unwrap_or_else(|_| invoker.to_string());

    let (dels, abilities): (Vec<delegation::Model>, Vec<Vec<abilities::Model>>) =
        delegation::Entity::find()
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await?
            .into_iter()
            .unzip();
    let parents = dels.load_many(parent_delegations::Entity, db).await?;
    let now = time::OffsetDateTime::now_utc();

    // Extract filter values
    let direction = filters.and_then(|f| f.direction.as_deref());
    let path_prefix = filters.and_then(|f| f.path.as_deref());
    let actions = filters.and_then(|f| f.actions.as_ref());

    Ok(dels
        .into_iter()
        .zip(abilities)
        .zip(parents)
        .filter_map(|((del, ability), parents)| {
            // Time validity check
            if !(del.expiry.map(|e| e > now).unwrap_or(true)
                && del.not_before.map(|n| n <= now).unwrap_or(true))
            {
                return None;
            }

            // Space membership check
            if !ability.iter().any(|a| a.resource.space() == Some(space_id)) {
                return None;
            }

            // Direction filter (using resolved PKH DID, not session key DID)
            match direction {
                Some("created") if del.delegator != pkh_did => return None,
                Some("received") if del.delegatee != pkh_did => return None,
                _ => {}
            }

            // Path prefix filter
            if let Some(prefix) = path_prefix {
                let has_matching_path = ability.iter().any(|a| {
                    a.resource
                        .tinycloud_resource()
                        .and_then(|r| r.path())
                        .map(|p| p.as_str().starts_with(prefix))
                        .unwrap_or(false)
                });
                if !has_matching_path {
                    return None;
                }
            }

            // Actions filter
            if let Some(action_list) = actions {
                let has_matching_action = ability.iter().any(|a| {
                    action_list
                        .iter()
                        .any(|action| a.ability.as_ref().as_ref() == action.as_str())
                });
                if !has_matching_action {
                    return None;
                }
            }

            Some(match TinyCloudDelegation::from_bytes(&del.serialization) {
                Ok(delegation) => Ok((
                    del.id,
                    DelegationInfo {
                        delegator: del.delegator,
                        delegate: del.delegatee,
                        parents: parents.into_iter().map(|p| p.parent.to_cid(0x55)).collect(),
                        expiry: del.expiry,
                        not_before: del.not_before,
                        issued_at: del.issued_at,
                        capabilities: ability
                            .into_iter()
                            .map(|a| Capability {
                                resource: a.resource,
                                ability: a.ability,
                            })
                            .collect(),
                        delegation,
                    },
                )),
                Err(e) => Err(e),
            })
        })
        .collect::<Result<HashMap<Hash, DelegationInfo>, EncodingError>>()?)
}

/// Get the delegation chain for a specific delegation, ordered from leaf to root.
/// The chain includes the requested delegation and all its ancestors.
async fn get_delegation_chain<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
    delegation_cid: &str,
) -> Result<Vec<DelegationInfo>, TxError<S, K>> {
    use tinycloud_lib::ipld_core::cid::Cid;

    // Parse the delegation CID
    let cid: Cid = delegation_cid
        .parse()
        .map_err(|_| TxError::<S, K>::InvalidCid(delegation_cid.to_string()))?;
    let start_hash: Hash = cid.into();

    let mut chain = Vec::new();
    let mut current_hash = start_hash;
    let now = time::OffsetDateTime::now_utc();

    // Traverse the chain following parent relationships
    loop {
        // Find the delegation with this hash
        let del_with_abilities = delegation::Entity::find_by_id(current_hash)
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await?;

        if del_with_abilities.is_empty() {
            break;
        }

        let (del, ability) = del_with_abilities.into_iter().next().unwrap();

        // Time validity check
        if !(del.expiry.map(|e| e > now).unwrap_or(true)
            && del.not_before.map(|n| n <= now).unwrap_or(true))
        {
            break;
        }

        // Space membership check
        if !ability.iter().any(|a| a.resource.space() == Some(space_id)) {
            break;
        }

        // Get parent relationships
        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(current_hash))
            .all(db)
            .await?;

        let parent_cids: Vec<Cid> = parents.iter().map(|p| p.parent.to_cid(0x55)).collect();

        // Create DelegationInfo
        let delegation = TinyCloudDelegation::from_bytes(&del.serialization)?;
        let info = DelegationInfo {
            delegator: del.delegator,
            delegate: del.delegatee,
            parents: parent_cids.clone(),
            expiry: del.expiry,
            not_before: del.not_before,
            issued_at: del.issued_at,
            capabilities: ability
                .into_iter()
                .map(|a| Capability {
                    resource: a.resource,
                    ability: a.ability,
                })
                .collect(),
            delegation,
        };

        chain.push(info);

        // Move to the first parent (if any) to continue the chain
        // Note: We follow the first parent; for multiple parents, this gives one path
        if let Some(first_parent) = parents.into_iter().next() {
            current_hash = first_parent.parent;
        } else {
            // No more parents, we've reached the root
            break;
        }
    }

    Ok(chain)
}

#[cfg(test)]
mod test {
    use crate::{keys::StaticSecret, storage::memory::MemoryStore};

    use super::*;
    use sea_orm::{ConnectOptions, Database};

    async fn get_db() -> Result<SpaceDatabase<sea_orm::DbConn, MemoryStore, StaticSecret>, DbErr> {
        SpaceDatabase::new(
            Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?,
            MemoryStore::default(),
            StaticSecret::new([0u8; 32].to_vec()).unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn basic() {
        let _db = get_db().await.unwrap();
    }
}
