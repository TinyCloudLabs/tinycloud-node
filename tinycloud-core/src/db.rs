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
use crate::types::{Metadata, NamespaceIdWrap, Resource};
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
    resource::{NamespaceId, Path},
};

#[derive(Debug, Clone)]
pub struct NamespaceDatabase<C, B, S> {
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
    #[error("Namespace not found")]
    NamespaceNotFound,
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

impl<B, K> NamespaceDatabase<DatabaseConnection, B, K> {
    pub async fn new(conn: DatabaseConnection, storage: B, secrets: K) -> Result<Self, DbErr> {
        Migrator::up(&conn, None).await?;
        Ok(Self {
            conn,
            storage,
            secrets,
        })
    }
}

impl<C, B, K> NamespaceDatabase<C, B, K>
where
    K: Secrets,
{
    pub async fn stage_key(&self, namespace: &NamespaceId) -> Result<String, K::Error> {
        self.secrets.stage_keypair(namespace).await.map(get_did_key)
    }
}

impl<C, B, K> NamespaceDatabase<C, B, K>
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

impl<C, B, K> NamespaceDatabase<C, B, K>
where
    B: StoreSize,
{
    pub async fn store_size(&self, namespace: &NamespaceId) -> Result<Option<u64>, B::Error> {
        self.storage.total_size(namespace).await
    }
}

impl<C, B, K> NamespaceDatabase<C, B, K>
where
    C: TransactionTrait,
{
    pub async fn check_db_connection(&self) -> Result<(), DbErr> {
        // there's a `ping` method on the connection, but we can't access it from here
        // but starting a transaction should be enough to check the connection
        self.conn.begin().await.map(|_| ())
    }
}

pub type InvocationInputs<W> = HashMap<(NamespaceId, Path), (Metadata, HashBuffer<W>)>;

impl<C, B, K> NamespaceDatabase<C, B, K>
where
    C: TransactionTrait,
    B: StorageSetup,
    K: Secrets,
{
    async fn transact(
        &self,
        events: Vec<Event>,
    ) -> Result<HashMap<NamespaceId, Commit>, TxError<B, K>> {
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
    ) -> Result<HashMap<NamespaceId, Commit>, TxError<B, K>> {
        self.transact(vec![Event::Delegation(Box::new(delegation))])
            .await
    }

    pub async fn revoke(
        &self,
        revocation: Revocation,
    ) -> Result<HashMap<NamespaceId, Commit>, TxError<B, K>> {
        self.transact(vec![Event::Revocation(Box::new(revocation))])
            .await
    }

    pub async fn invoke<S>(
        &self,
        invocation: Invocation,
        mut inputs: InvocationInputs<S::Writable>,
    ) -> Result<
        (
            HashMap<NamespaceId, Commit>,
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
                    r.namespace(),
                    r.service().as_str(),
                    cap.ability.as_ref().as_ref(),
                    r.path()?,
                ))
            }) {
                // stage inputs for content writes
                Some((namespace, "kv", "tinycloud.kv/put", path)) => {
                    let (metadata, mut stage) = inputs
                        .remove(&(namespace.clone(), path.clone()))
                        .ok_or(TxStoreError::MissingInput)?;

                    let value = stage.hash();

                    stages.insert((namespace.clone(), path.clone()), stage);
                    // add write for tx
                    ops.push(Operation::KvWrite {
                        namespace: namespace.clone(),
                        key: path.clone(),
                        metadata,
                        value,
                    });
                }
                // add delete for tx
                Some((namespace, "kv", "tinycloud.kv/del", path)) => {
                    ops.push(Operation::KvDelete {
                        namespace: namespace.clone(),
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
                    r.namespace(),
                    r.service().as_str(),
                    c.ability.as_ref().as_ref(),
                    r.path()?,
                ))
            })
        }) {
            match cap {
                (namespace, "kv", "tinycloud.kv/get", path) => results.push(InvocationOutcome::KvRead(
                    get_kv(&tx, &self.storage, namespace, path)
                        .await
                        .map_err(|e| match e {
                            EitherError::A(e) => TxStoreError::Tx(e.into()),
                            EitherError::B(e) => TxStoreError::StoreRead(e),
                        })?,
                )),
                (namespace, "kv", "tinycloud.kv/list", path) => {
                    results.push(InvocationOutcome::KvList(list(&tx, namespace, path).await?))
                }
                (namespace, "kv", "tinycloud.kv/del", path) => {
                    let kv = get_kv_entity(&tx, namespace, path).await?;
                    if let Some(kv) = kv {
                        self.storage
                            .remove(namespace, &kv.value)
                            .await
                            .map_err(TxStoreError::StoreDelete)?;
                    }
                    results.push(InvocationOutcome::KvDelete)
                }
                (namespace, "kv", "tinycloud.kv/put", path) => {
                    if let Some(stage) = stages.remove(&(namespace.clone(), path.clone())) {
                        self.storage
                            .persist(namespace, stage)
                            .await
                            .map_err(TxStoreError::StoreWrite)?;
                        results.push(InvocationOutcome::KvWrite)
                    }
                }
                (namespace, "kv", "tinycloud.kv/metadata", path) => results.push(
                    InvocationOutcome::KvMetadata(metadata(&tx, namespace, path).await?),
                ),
                (namespace, "capabilities", "tinycloud.capabilities/read", path)
                    if path.as_str() == "all" =>
                {
                    results.push(InvocationOutcome::OpenSessions(
                        get_valid_delegations(&tx, namespace).await?,
                    ))
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
    KvRead(Option<(Metadata, Content<R>)>),
    OpenSessions(HashMap<Hash, DelegationInfo>),
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

async fn event_namespaces<'a, C: ConnectionTrait>(
    db: &C,
    ev: &'a [(Hash, Event)],
) -> Result<HashMap<NamespaceId, Vec<&'a (Hash, Event)>>, DbErr> {
    // get orderings of events listed as revoked by events in the ev list
    let mut namespaces = HashMap::<NamespaceId, Vec<&'a (Hash, Event)>>::new();
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
                for namespace in d.0.namespaces() {
                    let entry = namespaces.entry(namespace.clone()).or_default();
                    if !entry.iter().any(|(h, _)| h == &e.0) {
                        entry.push(e);
                    }
                }
            }
            Event::Invocation(i, _) => {
                for namespace in i.0.namespaces() {
                    let entry = namespaces.entry(namespace.clone()).or_default();
                    if !entry.iter().any(|(h, _)| h == &e.0) {
                        entry.push(e);
                    }
                }
            }
            Event::Revocation(r) => {
                let r_hash = Hash::from(r.0.revoked);
                for revoked in &revoked_events {
                    if r_hash == revoked.event {
                        let entry = namespaces.entry(revoked.namespace.0.clone()).or_default();
                        if !entry.iter().any(|(h, _)| h == &e.0) {
                            entry.push(e);
                        }
                    }
                }
            }
        }
    }
    Ok(namespaces)
}

pub(crate) async fn transact<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    store_setup: &S,
    secrets: &K,
    events: Vec<Event>,
) -> Result<HashMap<NamespaceId, Commit>, TxError<S, K>> {
    // for each event, get the hash and the relevent namespace(s)
    let event_hashes = events
        .into_iter()
        .map(|e| (e.hash(), e))
        .collect::<Vec<(Hash, Event)>>();
    let event_namespaces = event_namespaces(db, &event_hashes).await?;
    let mut new_namespaces = event_hashes
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Delegation(d) => Some(d.0.capabilities.iter().filter_map(|c| {
                match (&c.resource, c.ability.as_ref().as_ref()) {
                    (Resource::TinyCloud(r), "tinycloud.namespace/host")
                        if r.path().is_none()
                            && r.service().as_str() == "namespace"
                            && r.query().is_none()
                            && r.fragment().is_none() =>
                    {
                        Some(NamespaceIdWrap(r.namespace().clone()))
                    }
                    _ => None,
                }
            })),
            _ => None,
        })
        .flatten()
        .collect::<Vec<NamespaceIdWrap>>();
    new_namespaces.dedup();

    if !new_namespaces.is_empty() {
        match namespace::Entity::insert_many(
            new_namespaces
                .iter()
                .cloned()
                .map(|id| namespace::Model { id })
                .map(namespace::ActiveModel::from),
        )
        .on_conflict(
            OnConflict::column(namespace::Column::Id)
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

    // get max sequence for each of the namespaces
    let mut max_seqs = event_order::Entity::find()
        .filter(event_order::Column::Namespace.is_in(event_namespaces.keys().cloned().map(NamespaceIdWrap)))
        .select_only()
        .column(event_order::Column::Namespace)
        .column_as(event_order::Column::Seq.max(), "max_seq")
        .group_by(event_order::Column::Namespace)
        .into_tuple::<(NamespaceIdWrap, i64)>()
        .all(db)
        .await?
        .into_iter()
        .fold(HashMap::new(), |mut m, (namespace, seq)| {
            m.insert(namespace, seq + 1);
            m
        });

    // get 'most recent' epochs for each of the namespaces
    let mut most_recent = epoch::Entity::find()
        .select_only()
        .left_join(epoch_order::Entity)
        .filter(
            Condition::all()
                .add(epoch::Column::Namespace.is_in(event_namespaces.keys().cloned().map(NamespaceIdWrap)))
                .add(epoch_order::Column::Child.is_null()),
        )
        .column(epoch::Column::Namespace)
        .column(epoch::Column::Id)
        .into_tuple::<(NamespaceIdWrap, Hash)>()
        .all(db)
        .await?
        .into_iter()
        .fold(
            HashMap::new(),
            |mut m: HashMap<NamespaceIdWrap, Vec<Hash>>, (namespace, epoch)| {
                m.entry(namespace).or_default().push(epoch);
                m
            },
        );

    // get all the orderings and associated data
    let (epoch_order, namespace_order, event_order, epochs) = event_namespaces
        .into_iter()
        .map(|(namespace, events)| {
            let parents = most_recent.remove(&namespace).unwrap_or_default();
            let epoch = epoch_hash(&namespace, &events, &parents)?;
            let seq = max_seqs.remove(&namespace).unwrap_or(0);
            Ok((namespace, (epoch, events, seq, parents)))
        })
        .collect::<Result<HashMap<_, _>, HashError>>()?
        .into_iter()
        .map(|(namespace, (epoch, hashes, seq, parents))| {
            (
                parents
                    .iter()
                    .map(|parent| epoch_order::Model {
                        parent: *parent,
                        child: epoch,
                        namespace: namespace.clone().into(),
                    })
                    .map(epoch_order::ActiveModel::from)
                    .collect::<Vec<epoch_order::ActiveModel>>(),
                (
                    namespace.clone(),
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
                        namespace: namespace.clone().into(),
                        seq,
                        epoch,
                        epoch_seq: es as i64,
                    })
                    .map(event_order::ActiveModel::from)
                    .collect::<Vec<event_order::ActiveModel>>(),
                epoch::Model {
                    seq,
                    id: epoch,
                    namespace: namespace.into(),
                },
            )
        })
        .fold(
            (
                Vec::<epoch_order::ActiveModel>::new(),
                HashMap::<NamespaceId, (i64, Hash, Vec<Hash>, HashMap<Hash, i64>)>::new(),
                Vec::<event_order::ActiveModel>::new(),
                Vec::<epoch::ActiveModel>::new(),
            ),
            |(mut eo, mut oo, mut ev, mut ep), (eo2, order, ev2, ep2)| {
                eo.extend(eo2);
                ev.extend(ev2);
                oo.insert(order.0, order.1);
                ep.push(ep2.into());
                (eo, oo, ev, ep)
            },
        );

    // save epochs
    epoch::Entity::insert_many(epochs)
        .exec(db)
        .await
        .map_err(|e| match e {
            DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(_))) => TxError::NamespaceNotFound,
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
                            let v = namespace_order
                                .get(op.namespace())
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

    for namespace in new_namespaces {
        store_setup
            .create(&namespace.0)
            .await
            .map_err(TxError::StoreSetup)?;
        secrets
            .save_keypair(&namespace.0)
            .await
            .map_err(TxError::Secrets)?;
    }

    Ok(namespace_order
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
    namespace: &NamespaceId,
    prefix: &Path,
) -> Result<Vec<Path>, DbErr> {
    // get content id for key from db
    let mut list = kv_write::Entity::find()
        .filter(
            Condition::all()
                .add(kv_write::Column::Key.starts_with(prefix.as_str()))
                .add(kv_write::Column::Namespace.eq(NamespaceIdWrap(namespace.clone()))),
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
    namespace: &NamespaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<Metadata>, DbErr> {
    match get_kv_entity(db, namespace, key).await? {
        Some(entry) => Ok(Some(entry.metadata)),
        None => Ok(None),
    }
}

async fn get_kv<C: ConnectionTrait, B: ImmutableReadStore>(
    db: &C,
    store: &B,
    namespace: &NamespaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<(Metadata, Content<B::Readable>)>, EitherError<DbErr, B::Error>> {
    let e = match get_kv_entity(db, namespace, key)
        .await
        .map_err(EitherError::A)?
    {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let c = match store.read(namespace, &e.value).await.map_err(EitherError::B)? {
        Some(c) => c,
        None => return Ok(None),
    };
    Ok(Some((e.metadata, c)))
}

async fn get_kv_entity<C: ConnectionTrait>(
    db: &C,
    namespace: &NamespaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<kv_write::Model>, DbErr> {
    // Ok(if let Some((seq, epoch, epoch_seq)) = version {
    //     event_order::Entity::find_by_id((epoch, epoch_seq, namespace.clone().into()))
    //         .reverse_join(kv_write::Entity)
    //         .find_also_related(kv_delete::Entity)
    //         .filter(
    //             Condition::all()
    //                 .add(kv_write::Column::Key.eq(key))
    //                 .add(kv_write::Column::Namespace.eq(namespace.clone().into()))
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
                .add(kv_write::Column::Namespace.eq(NamespaceIdWrap(namespace.clone()))),
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
    namespace: &NamespaceId,
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
                && ability.iter().any(|a| a.resource.namespace() == Some(namespace))
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

#[cfg(test)]
mod test {
    use crate::{keys::StaticSecret, storage::memory::MemoryStore};

    use super::*;
    use sea_orm::{ConnectOptions, Database};

    async fn get_db() -> Result<NamespaceDatabase<sea_orm::DbConn, MemoryStore, StaticSecret>, DbErr> {
        NamespaceDatabase::new(
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
