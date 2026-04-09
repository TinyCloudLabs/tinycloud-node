use crate::encryption::ColumnEncryption;
use crate::events::{
    epoch_hash, Delegation, Event, HashError, HeaderEncode, Invocation, Operation, Revocation,
    TinyCloudInvocation,
};
use crate::hash::Hash;
use crate::keys::{get_did_key, Secrets};
use crate::migrations::Migrator;
use crate::models::*;
use crate::relationships::*;
use crate::replication::{
    decode_hash, encode_hash, KvReplicationError, KvReplicationEvent, KvReplicationOperation,
    KvReplicationSequence, ReplicationApplyResponse, ReplicationExportRequest,
    ReplicationExportResponse,
};
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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use tinycloud_auth::{
    authorization::{EncodingError, TinyCloudDelegation},
    resource::{Path, SpaceId},
};

#[derive(Debug, Clone)]
pub struct SpaceDatabase<C, B, S> {
    conn: C,
    storage: B,
    secrets: S,
    encryption: Option<ColumnEncryption>,
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub rev: Hash,
    pub seq: i64,
    pub committed_events: Vec<Hash>,
    pub consumed_epochs: Vec<Hash>,
}

#[derive(Debug, Clone)]
pub struct TransactResult {
    pub commits: HashMap<SpaceId, Commit>,
    pub skipped_spaces: Vec<SpaceId>,
    /// CIDs of delegations that were processed (saved) regardless of space existence.
    /// Used to return a CID even when all spaces were skipped.
    pub delegation_cids: Vec<Hash>,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TxError<S: StorageSetup, K: Secrets> {
    #[error("database error: {0}")]
    Db(#[from] DbErr),
    #[error(transparent)]
    Ucan(#[from] tinycloud_auth::ssi::ucan::Error),
    #[error(transparent)]
    Cacao(#[from] tinycloud_auth::cacaos::siwe_cacao::VerificationError),
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
    #[error("encryption error: {0}")]
    Encryption(#[from] crate::encryption::EncryptionError),
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
            encryption: None,
        })
    }

    pub fn with_encryption(mut self, encryption: Option<ColumnEncryption>) -> Self {
        self.encryption = encryption;
        self
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
    C: ConnectionTrait,
    B: ImmutableReadStore,
{
    pub async fn public_kv_get(
        &self,
        space_id: &SpaceId,
        key: &Path,
    ) -> Result<Option<(Metadata, Hash, Content<B::Readable>)>, EitherError<DbErr, B::Error>> {
        get_kv(&self.conn, &self.storage, space_id, key).await
    }

    pub async fn public_kv_metadata(
        &self,
        space_id: &SpaceId,
        key: &Path,
    ) -> Result<Option<Metadata>, DbErr> {
        metadata(&self.conn, space_id, key).await
    }

    pub async fn public_kv_list(
        &self,
        space_id: &SpaceId,
        prefix: &Path,
    ) -> Result<Vec<Path>, DbErr> {
        list(&self.conn, space_id, prefix).await
    }

    pub async fn replication_session_delegation_active(
        &self,
        delegation_hash: Option<Hash>,
    ) -> Result<bool, DbErr> {
        let Some(delegation_hash) = delegation_hash else {
            return Ok(true);
        };

        let now = time::OffsetDateTime::now_utc();
        let delegation = delegation::Entity::find_by_id(delegation_hash)
            .one(&self.conn)
            .await?;
        let revoked = revocation::Entity::find()
            .filter(revocation::Column::Revoked.eq(delegation_hash))
            .one(&self.conn)
            .await?;

        if revoked.is_some() {
            return Ok(false);
        }

        Ok(delegation
            .map(|delegation| {
                delegation.expiry.map(|expiry| expiry > now).unwrap_or(true)
                    && delegation
                        .not_before
                        .map(|not_before| not_before <= now)
                        .unwrap_or(true)
            })
            .unwrap_or(false))
    }

    pub async fn export_kv_replication(
        &self,
        request: &ReplicationExportRequest,
    ) -> Result<ReplicationExportResponse, KvReplicationError> {
        let space_id = parse_replication_space_id(&request.space_id)?;
        let prefix = request
            .prefix
            .as_deref()
            .map(parse_replication_path)
            .transpose()?;
        let since_seq = request.since_seq.unwrap_or(-1);
        let limit = request.limit.unwrap_or(32).max(1) as u64;
        let seqs =
            select_kv_replication_seqs(&self.conn, &space_id, prefix.as_ref(), since_seq, limit)
                .await?;
        if seqs.is_empty() {
            return Ok(ReplicationExportResponse {
                space_id: request.space_id.clone(),
                prefix: request.prefix.clone(),
                requested_since_seq: request.since_seq,
                exported_until_seq: request.since_seq,
                sequences: Vec::new(),
            });
        }

        let mut sequences = BTreeMap::<i64, KvReplicationSequence>::new();
        for seq in &seqs {
            let events = event_order::Entity::find()
                .filter(
                    Condition::all()
                        .add(event_order::Column::Space.eq(SpaceIdWrap(space_id.clone())))
                        .add(event_order::Column::Seq.eq(*seq)),
                )
                .order_by_asc(event_order::Column::EpochSeq)
                .all(&self.conn)
                .await?;

            let mut sequence = None::<KvReplicationSequence>;
            for committed in events {
                let invocation = invocation::Entity::find_by_id(committed.event)
                    .one(&self.conn)
                    .await?
                    .ok_or(KvReplicationError::UnsupportedInvocation {
                        invocation_id: encode_hash(committed.event),
                        reason:
                            "non-invocation events in a replication sequence are not yet supported",
                    })?;

                let serialization = crate::encryption::maybe_decrypt(
                    self.encryption.as_ref(),
                    &invocation.serialization,
                )?;
                let invocation_string = String::from_utf8(serialization).map_err(|error| {
                    KvReplicationError::InvalidInvocationUtf8 {
                        invocation_id: encode_hash(committed.event),
                        reason: error.to_string(),
                    }
                })?;
                let parsed_invocation =
                    Invocation::from_header_ser::<TinyCloudInvocation>(&invocation_string)
                        .map_err(|error| KvReplicationError::InvalidInvocation {
                            invocation_id: encode_hash(committed.event),
                            reason: error.to_string(),
                        })?;
                let delegations = export_invocation_delegations(
                    &self.conn,
                    self.encryption.as_ref(),
                    &encode_hash(committed.event),
                    &parsed_invocation.0.parents,
                )
                .await?;

                let writes = kv_write::Entity::find()
                    .filter(
                        Condition::all()
                            .add(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone())))
                            .add(kv_write::Column::Invocation.eq(committed.event)),
                    )
                    .all(&self.conn)
                    .await?;

                let operation = if let [write] = writes.as_slice() {
                    if let Some(prefix) = prefix.as_ref() {
                        if !write.key.0.as_str().starts_with(prefix.as_str()) {
                            return Err(KvReplicationError::UnsupportedInvocation {
                                invocation_id: encode_hash(committed.event),
                                reason: "partial prefix export for a shared sequence is not yet supported",
                            });
                        }
                    }

                    let content = self
                        .storage
                        .read_to_vec(&space_id, &write.value)
                        .await
                        .map_err(|error| KvReplicationError::StoreRead(error.to_string()))?
                        .ok_or_else(|| KvReplicationError::MissingBlock {
                            invocation_id: encode_hash(committed.event),
                            hash: encode_hash(write.value),
                        })?;

                    KvReplicationOperation::Put {
                        key: write.key.to_string(),
                        value_hash: encode_hash(write.value),
                        metadata: write.metadata.clone(),
                        content,
                    }
                } else if !writes.is_empty() {
                    return Err(KvReplicationError::UnsupportedInvocation {
                        invocation_id: encode_hash(committed.event),
                        reason:
                            "multi-key kv write invocations are not yet supported for replication export",
                    });
                } else if let Some(delete) =
                    kv_delete::Entity::find_by_id((committed.event, SpaceIdWrap(space_id.clone())))
                        .one(&self.conn)
                        .await?
                {
                    if let Some(prefix) = prefix.as_ref() {
                        if !delete.key.0.as_str().starts_with(prefix.as_str()) {
                            return Err(KvReplicationError::UnsupportedInvocation {
                                invocation_id: encode_hash(committed.event),
                                reason: "partial prefix export for a shared sequence is not yet supported",
                            });
                        }
                    }

                    let deleted_ordering = event_order::Entity::find()
                        .filter(
                            Condition::all()
                                .add(event_order::Column::Space.eq(SpaceIdWrap(space_id.clone())))
                                .add(event_order::Column::Event.eq(delete.deleted_invocation_id)),
                        )
                        .one(&self.conn)
                        .await?
                        .ok_or_else(|| KvReplicationError::MissingDeletedWrite {
                            invocation_id: encode_hash(committed.event),
                        })?;

                    KvReplicationOperation::Delete {
                        key: delete.key.to_string(),
                        deleted_invocation_id: encode_hash(delete.deleted_invocation_id),
                        deleted_seq: deleted_ordering.seq,
                        deleted_epoch: encode_hash(deleted_ordering.epoch),
                        deleted_epoch_seq: deleted_ordering.epoch_seq,
                    }
                } else {
                    return Err(KvReplicationError::UnsupportedInvocation {
                        invocation_id: encode_hash(committed.event),
                        reason: "non-kv events in a replication sequence are not yet supported",
                    });
                };

                let entry = sequence.get_or_insert_with(|| KvReplicationSequence {
                    seq: committed.seq,
                    epoch: encode_hash(committed.epoch),
                    events: Vec::new(),
                });
                if entry.epoch != encode_hash(committed.epoch) {
                    return Err(KvReplicationError::UnsupportedInvocation {
                        invocation_id: encode_hash(committed.event),
                        reason: "sequence mapped to multiple epochs",
                    });
                }

                entry.events.push(KvReplicationEvent {
                    invocation_id: encode_hash(committed.event),
                    invocation: invocation_string,
                    delegations,
                    operation,
                });
            }

            if let Some(sequence) = sequence {
                sequences.insert(*seq, sequence);
            }
        }

        let exported_until_seq = sequences.keys().next_back().copied();
        Ok(ReplicationExportResponse {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            requested_since_seq: request.since_seq,
            exported_until_seq,
            sequences: sequences.into_values().collect(),
        })
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait + ConnectionTrait,
    B: ImmutableReadStore + StorageSetup,
    K: Secrets,
{
    pub async fn apply_kv_replication<S>(
        &self,
        export: &ReplicationExportResponse,
        staging: &S,
    ) -> Result<ReplicationApplyResponse, KvReplicationError>
    where
        B: ImmutableWriteStore<S> + ImmutableDeleteStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        let space_id = parse_replication_space_id(&export.space_id)?;
        let mut applied_sequences = 0usize;
        let mut applied_events = 0usize;

        for sequence in &export.sequences {
            let mut events = Vec::new();
            for event in &sequence.events {
                self.import_invocation_delegations(event).await?;
                let invocation_hash = decode_hash(&event.invocation_id, "invocationId")?;
                if invocation::Entity::find_by_id(invocation_hash)
                    .one(&self.conn)
                    .await?
                    .is_some()
                {
                    continue;
                }

                let (invocation, operation) = self
                    .rebuild_kv_replication_event(&space_id, event, staging)
                    .await?;
                events.push(Event::Invocation(Box::new(invocation), vec![operation]));
            }

            if events.is_empty() {
                continue;
            }

            applied_events += events.len();
            self.transact(events)
                .await
                .map_err(|error| KvReplicationError::Tx(error.to_string()))?;
            applied_sequences += 1;
        }

        Ok(ReplicationApplyResponse {
            space_id: export.space_id.clone(),
            requested_since_seq: export.requested_since_seq,
            peer_url: None,
            applied_sequences,
            applied_events,
            applied_until_seq: export.exported_until_seq,
        })
    }

    async fn rebuild_kv_replication_event<S>(
        &self,
        space_id: &SpaceId,
        event: &KvReplicationEvent,
        staging: &S,
    ) -> Result<(Invocation, Operation), KvReplicationError>
    where
        B: ImmutableWriteStore<S> + ImmutableDeleteStore + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        let invocation = Invocation::from_header_ser::<TinyCloudInvocation>(&event.invocation)
            .map_err(|error| KvReplicationError::Tx(error.to_string()))?;

        match &event.operation {
            KvReplicationOperation::Put {
                key,
                value_hash,
                metadata,
                content,
            } => {
                let key = parse_replication_path(key)?;
                let hash = decode_hash(value_hash, "valueHash")?;
                let mut staged = staging
                    .stage(space_id)
                    .await
                    .map_err(|error| KvReplicationError::Stage(error.to_string()))?;
                futures::io::AsyncWriteExt::write_all(&mut staged, content)
                    .await
                    .map_err(KvReplicationError::Io)?;
                futures::io::AsyncWriteExt::close(&mut staged)
                    .await
                    .map_err(KvReplicationError::Io)?;
                self.storage
                    .persist_keyed(space_id, staged, &hash)
                    .await
                    .map_err(|error| KvReplicationError::StoreWrite(error.to_string()))?;

                Ok((
                    invocation,
                    Operation::KvWrite {
                        space: space_id.clone(),
                        key,
                        value: hash,
                        metadata: metadata.clone(),
                    },
                ))
            }
            KvReplicationOperation::Delete { .. } => {
                let (key, deleted_invocation_id, deleted_seq, deleted_epoch, deleted_epoch_seq) =
                    match &event.operation {
                        KvReplicationOperation::Delete {
                            key,
                            deleted_invocation_id,
                            deleted_seq,
                            deleted_epoch,
                            deleted_epoch_seq,
                            ..
                        } => (
                            parse_replication_path(key)?,
                            decode_hash(deleted_invocation_id, "deletedInvocationId")?,
                            *deleted_seq,
                            decode_hash(deleted_epoch, "deletedEpoch")?,
                            *deleted_epoch_seq,
                        ),
                        _ => unreachable!(),
                    };

                let deleted_write = if let Some(write) = kv_write::Entity::find()
                    .filter(
                        Condition::all()
                            .add(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone())))
                            .add(kv_write::Column::Key.eq(key.as_str()))
                            .add(kv_write::Column::Invocation.eq(deleted_invocation_id)),
                    )
                    .one(&self.conn)
                    .await?
                {
                    write
                } else if let Some(write) = kv_write::Entity::find()
                    .filter(
                        Condition::all()
                            .add(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone())))
                            .add(kv_write::Column::Key.eq(key.as_str()))
                            .add(kv_write::Column::Seq.eq(deleted_seq))
                            .add(kv_write::Column::Epoch.eq(deleted_epoch))
                            .add(kv_write::Column::EpochSeq.eq(deleted_epoch_seq)),
                    )
                    .one(&self.conn)
                    .await?
                {
                    write
                } else {
                    return Err(KvReplicationError::MissingDeletedWrite {
                        invocation_id: event.invocation_id.clone(),
                    });
                };

                Ok((
                    invocation,
                    Operation::KvDelete {
                        space: space_id.clone(),
                        key,
                        version: Some((
                            deleted_write.seq,
                            deleted_write.epoch,
                            deleted_write.epoch_seq,
                        )),
                    },
                ))
            }
        }
    }

    async fn import_invocation_delegations(
        &self,
        event: &KvReplicationEvent,
    ) -> Result<(), KvReplicationError> {
        for delegation_header in &event.delegations {
            let delegation = Delegation::from_header_ser::<TinyCloudDelegation>(delegation_header)
                .map_err(|error| KvReplicationError::InvalidInvocation {
                    invocation_id: event.invocation_id.clone(),
                    reason: format!("invalid delegation chain entry: {error}"),
                })?;
            let delegation_hash = crate::hash::hash(&delegation.1);

            if delegation::Entity::find_by_id(delegation_hash)
                .one(&self.conn)
                .await?
                .is_some()
            {
                continue;
            }

            self.transact(vec![Event::Delegation(Box::new(delegation))])
                .await
                .map_err(|error| KvReplicationError::Tx(error.to_string()))?;
        }

        Ok(())
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
    async fn transact(&self, events: Vec<Event>) -> Result<TransactResult, TxError<B, K>> {
        let tx = self
            .conn
            .begin_with_config(Some(sea_orm::IsolationLevel::ReadUncommitted), None)
            .await?;

        let result = transact(
            &tx,
            &self.storage,
            &self.secrets,
            events,
            self.encryption.as_ref(),
        )
        .await?;

        tx.commit().await?;

        Ok(result)
    }

    pub async fn delegate(&self, delegation: Delegation) -> Result<TransactResult, TxError<B, K>> {
        self.transact(vec![Event::Delegation(Box::new(delegation))])
            .await
    }

    pub async fn revoke(&self, revocation: Revocation) -> Result<TransactResult, TxError<B, K>> {
        self.transact(vec![Event::Revocation(Box::new(revocation))])
            .await
    }

    pub async fn invoke<S>(
        &self,
        invocation: Invocation,
        mut inputs: InvocationInputs<S::Writable>,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
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
            self.encryption.as_ref(),
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
                                get_valid_delegations(&tx, space, self.encryption.as_ref()).await?,
                            ))
                        }
                        Some(CapabilitiesReadParams::List { filters }) => {
                            // List with optional filters
                            results.push(InvocationOutcome::OpenSessions(
                                get_filtered_delegations(
                                    &tx,
                                    space,
                                    &invoker,
                                    filters.as_ref(),
                                    self.encryption.as_ref(),
                                )
                                .await?,
                            ))
                        }
                        Some(CapabilitiesReadParams::Chain { delegation_cid }) => {
                            // Get the delegation chain for a specific delegation
                            results.push(InvocationOutcome::DelegationChain(
                                get_delegation_chain(
                                    &tx,
                                    space,
                                    delegation_cid,
                                    self.encryption.as_ref(),
                                )
                                .await?,
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
    SqlResult(serde_json::Value),
    SqlExport(Vec<u8>),
    DuckDbResult(serde_json::Value),
    DuckDbExport(Vec<u8>),
    DuckDbArrow(Vec<u8>),
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
    encryption: Option<&ColumnEncryption>,
) -> Result<TransactResult, TxError<S, K>> {
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

    // For delegation-only transactions, skip spaces that don't exist yet
    // instead of failing with SpaceNotFound
    let is_delegation_only = event_hashes
        .iter()
        .all(|(_, e)| matches!(e, Event::Delegation(_)));

    let (event_spaces, skipped_spaces) = if is_delegation_only {
        let new_space_ids: HashSet<SpaceId> = new_spaces.iter().map(|s| s.0.clone()).collect();
        // Spaces that were just created via new_spaces are definitely existing
        let all_space_ids: Vec<SpaceIdWrap> = event_spaces
            .keys()
            .filter(|s| !new_space_ids.contains(s))
            .cloned()
            .map(SpaceIdWrap)
            .collect();

        let existing: HashSet<SpaceId> = if all_space_ids.is_empty() {
            HashSet::new()
        } else {
            space::Entity::find()
                .filter(space::Column::Id.is_in(all_space_ids))
                .all(db)
                .await?
                .into_iter()
                .map(|s| s.id.0)
                .collect()
        };

        // new_spaces are always existing (just inserted above)
        let existing: HashSet<SpaceId> = existing.into_iter().chain(new_space_ids).collect();

        let skipped: Vec<SpaceId> = event_spaces
            .keys()
            .filter(|s| !existing.contains(s))
            .cloned()
            .collect();

        let filtered: HashMap<_, _> = event_spaces
            .into_iter()
            .filter(|(s, _)| existing.contains(s))
            .collect();

        (filtered, skipped)
    } else {
        (event_spaces, vec![])
    };

    // If all spaces were filtered out, we still process delegations below
    // but skip epoch/event ordering creation
    if !event_spaces.is_empty() {
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
                DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(ref db_err))) => {
                    tracing::warn!(
                        error = %e,
                        db_error = %db_err,
                        db_error_code = ?db_err.code(),
                        "epoch insert failed with database error"
                    );
                    TxError::SpaceNotFound
                }
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

        let mut delegation_cids = Vec::new();
        for (hash, event) in event_hashes {
            match event {
                Event::Delegation(d) => {
                    let cid = delegation::process(db, *d, encryption).await?;
                    delegation_cids.push(cid);
                }
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
                        encryption,
                    )
                    .await?;
                }
                Event::Revocation(r) => {
                    revocation::process(db, *r).await?;
                }
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

        Ok(TransactResult {
            commits: space_order
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
                .collect(),
            skipped_spaces,
            delegation_cids,
        })
    } else {
        // Auth-only facts can still be persisted even when no service-space ordering applies.
        let mut delegation_cids = Vec::new();
        for (_, event) in event_hashes {
            match event {
                Event::Delegation(d) => {
                    let cid = delegation::process(db, *d, encryption).await?;
                    delegation_cids.push(cid);
                }
                Event::Revocation(r) => {
                    revocation::process(db, *r).await?;
                }
                Event::Invocation(_, _) => {
                    unreachable!("non-delegation events with empty event_spaces")
                }
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

        Ok(TransactResult {
            commits: HashMap::new(),
            skipped_spaces,
            delegation_cids,
        })
    }
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

fn parse_replication_space_id(space_id: &str) -> Result<SpaceId, KvReplicationError> {
    SpaceId::from_str(space_id)
        .map_err(|_| KvReplicationError::InvalidSpaceId(space_id.to_string()))
}

fn parse_replication_path(path: &str) -> Result<Path, KvReplicationError> {
    Path::from_str(path).map_err(|_| KvReplicationError::InvalidPath(path.to_string()))
}

async fn select_kv_replication_seqs<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    prefix: Option<&Path>,
    since_seq: i64,
    limit: u64,
) -> Result<Vec<i64>, KvReplicationError> {
    if prefix.is_none() {
        return Ok(event_order::Entity::find()
            .select_only()
            .column(event_order::Column::Seq)
            .filter(event_order::Column::Space.eq(SpaceIdWrap(space_id.clone())))
            .filter(event_order::Column::Seq.gt(since_seq))
            .order_by_asc(event_order::Column::Seq)
            .group_by(event_order::Column::Seq)
            .limit(limit)
            .into_tuple::<i64>()
            .all(db)
            .await?);
    }

    let prefix = prefix.expect("checked above");
    let mut seqs = BTreeSet::new();

    let write_seqs = kv_write::Entity::find()
        .select_only()
        .column(kv_write::Column::Seq)
        .filter(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone())))
        .filter(kv_write::Column::Seq.gt(since_seq))
        .filter(kv_write::Column::Key.like(format!("{}%", prefix.as_str())))
        .order_by_asc(kv_write::Column::Seq)
        .group_by(kv_write::Column::Seq)
        .into_tuple::<i64>()
        .all(db)
        .await?;
    seqs.extend(write_seqs);

    let deletes = kv_delete::Entity::find()
        .filter(kv_delete::Column::Space.eq(SpaceIdWrap(space_id.clone())))
        .filter(kv_delete::Column::Key.like(format!("{}%", prefix.as_str())))
        .all(db)
        .await?;
    for delete in deletes {
        if let Some(ordering) = event_order::Entity::find()
            .filter(
                Condition::all()
                    .add(event_order::Column::Space.eq(SpaceIdWrap(space_id.clone())))
                    .add(event_order::Column::Event.eq(delete.invocation_id))
                    .add(event_order::Column::Seq.gt(since_seq)),
            )
            .one(db)
            .await?
        {
            seqs.insert(ordering.seq);
        }
    }

    Ok(seqs.into_iter().take(limit as usize).collect())
}

async fn export_invocation_delegations<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
    invocation_id: &str,
    parents: &[tinycloud_auth::authorization::Cid],
) -> Result<Vec<String>, KvReplicationError> {
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    let mut stack = parents
        .iter()
        .map(|cid| (Hash::from(*cid), false))
        .collect::<Vec<_>>();
    let mut encoded = HashMap::<Hash, String>::new();

    while let Some((hash, expanded)) = stack.pop() {
        if seen.contains(&hash) {
            continue;
        }

        if expanded {
            let delegation =
                encoded
                    .remove(&hash)
                    .ok_or(KvReplicationError::UnsupportedInvocation {
                        invocation_id: invocation_id.to_string(),
                        reason: "missing encoded parent delegation",
                    })?;
            seen.insert(hash);
            ordered.push(delegation);
            continue;
        }

        let model = delegation::Entity::find_by_id(hash).one(db).await?.ok_or(
            KvReplicationError::UnsupportedInvocation {
                invocation_id: invocation_id.to_string(),
                reason: "missing parent delegation",
            },
        )?;

        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(hash))
            .all(db)
            .await?;

        let serialization = crate::encryption::maybe_decrypt(encryption, &model.serialization)?;
        let header = TinyCloudDelegation::from_bytes(&serialization)?.encode()?;

        encoded.insert(hash, header);
        stack.push((hash, true));
        for parent in parents.into_iter().rev() {
            if !seen.contains(&parent.parent) {
                stack.push((parent.parent, false));
            }
        }
    }

    Ok(ordered)
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
    encryption: Option<&ColumnEncryption>,
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
    dels.into_iter()
        .zip(abilities)
        .zip(parents)
        .filter_map(|((del, ability), parents)| {
            if del.expiry.map(|e| e > now).unwrap_or(true)
                && del.not_before.map(|n| n <= now).unwrap_or(true)
                && ability.iter().any(|a| a.resource.space() == Some(space_id))
            {
                let serialization =
                    match crate::encryption::maybe_decrypt(encryption, &del.serialization) {
                        Ok(s) => s,
                        Err(e) => return Some(Err(TxError::Encryption(e))),
                    };
                Some(match TinyCloudDelegation::from_bytes(&serialization) {
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
                    Err(e) => Err(TxError::Encoding(e)),
                })
            } else {
                None
            }
        })
        .collect::<Result<HashMap<Hash, DelegationInfo>, TxError<S, K>>>()
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
    encryption: Option<&ColumnEncryption>,
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

    dels.into_iter()
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

            let serialization =
                match crate::encryption::maybe_decrypt(encryption, &del.serialization) {
                    Ok(s) => s,
                    Err(e) => return Some(Err(TxError::Encryption(e))),
                };
            Some(match TinyCloudDelegation::from_bytes(&serialization) {
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
                Err(e) => Err(TxError::Encoding(e)),
            })
        })
        .collect::<Result<HashMap<Hash, DelegationInfo>, TxError<S, K>>>()
}

/// Get the delegation chain for a specific delegation, ordered from leaf to root.
/// The chain includes the requested delegation and all its ancestors.
async fn get_delegation_chain<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
    delegation_cid: &str,
    encryption: Option<&ColumnEncryption>,
) -> Result<Vec<DelegationInfo>, TxError<S, K>> {
    use tinycloud_auth::ipld_core::cid::Cid;

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
        let serialization = crate::encryption::maybe_decrypt(encryption, &del.serialization)?;
        let delegation = TinyCloudDelegation::from_bytes(&serialization)?;
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
