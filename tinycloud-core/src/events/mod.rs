use crate::{
    hash::{hash, Hash},
    types::Metadata,
    util::{DelegationInfo, InvocationInfo, RevocationInfo},
};
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
pub use tinycloud_lib::{
    authorization::{
        EncodingError, HeaderEncode, TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation,
    },
    ipld_core::cid::Cid,
    multihash_codetable::Code,
    resource::{Path, SpaceId},
};

#[derive(Debug)]
pub struct SerializedEvent<T>(pub T, pub(crate) Vec<u8>);

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum FromReqErr<T> {
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    #[error(transparent)]
    TryFrom(T),
}

impl<T> SerializedEvent<T> {
    pub fn from_header_ser<I>(s: &str) -> Result<Self, FromReqErr<T::Error>>
    where
        T: TryFrom<I>,
        I: HeaderEncode,
    {
        I::decode(s)
            .map_err(FromReqErr::from)
            .and_then(|(i, s)| Ok(Self(T::try_from(i).map_err(FromReqErr::TryFrom)?, s)))
    }

    /// Hash the serialized bytes of this event.
    /// This produces a deterministic hash that can be converted to a CID.
    pub fn hash(&self) -> Hash {
        hash(&self.1)
    }
}

pub type Delegation = SerializedEvent<DelegationInfo>;
pub type Invocation = SerializedEvent<InvocationInfo>;
pub type Revocation = SerializedEvent<RevocationInfo>;

#[derive(Debug, Hash, PartialEq, Eq)]
pub(crate) enum Operation {
    KvWrite {
        space: SpaceId,
        key: Path,
        value: Hash,
        metadata: Metadata,
    },
    KvDelete {
        space: SpaceId,
        key: Path,
        version: Option<(i64, Hash, i64)>,
    },
}

impl Operation {
    pub fn version(self, seq: i64, epoch: Hash, epoch_seq: i64) -> VersionedOperation {
        match self {
            Self::KvWrite {
                space,
                key,
                value,
                metadata,
            } => VersionedOperation::KvWrite {
                space,
                key,
                value,
                metadata,
                seq,
                epoch,
                epoch_seq,
            },
            Self::KvDelete {
                space,
                key,
                version,
            } => VersionedOperation::KvDelete {
                space,
                key,
                version,
            },
        }
    }

    pub fn space(&self) -> &SpaceId {
        match self {
            Self::KvWrite { space, .. } => space,
            Self::KvDelete { space, .. } => space,
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub(crate) enum VersionedOperation {
    KvWrite {
        space: SpaceId,
        key: Path,
        value: Hash,
        metadata: Metadata,
        seq: i64,
        epoch: Hash,
        epoch_seq: i64,
    },
    KvDelete {
        space: SpaceId,
        key: Path,
        version: Option<(i64, Hash, i64)>,
    },
}

#[derive(Debug)]
pub(crate) enum Event {
    Invocation(Box<Invocation>, Vec<Operation>),
    Delegation(Box<Delegation>),
    Revocation(Box<Revocation>),
}

impl Event {
    pub fn hash(&self) -> Hash {
        match self {
            Event::Delegation(d) => hash(&d.1),
            Event::Invocation(i, _) => hash(&i.1),
            Event::Revocation(r) => hash(&r.1),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(Cid),
    Many(Vec<Cid>),
}

#[derive(Debug, Serialize, Deserialize)]
struct Epoch {
    pub parents: Vec<Cid>,
    pub events: Vec<OneOrMany>,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("encoding error: {0}")]
    EncodeError(#[from] EncodeError<std::collections::TryReserveError>),
}

pub(crate) fn epoch_hash(
    space: &SpaceId,
    events: &[&(Hash, Event)],
    parents: &[Hash],
) -> Result<Hash, HashError> {
    Ok(hash(&serde_ipld_dagcbor::to_vec(&Epoch {
        parents: parents.iter().map(|h| h.to_cid(0x71)).collect(),
        events: events
            .iter()
            .map(|(h, e)| {
                Ok(match e {
                    Event::Invocation(_, ops) => hash_inv(h, space, ops)?,
                    Event::Delegation(_) => OneOrMany::One(h.to_cid(RAW_CODEC)),
                    Event::Revocation(_) => OneOrMany::One(h.to_cid(RAW_CODEC)),
                })
            })
            .collect::<Result<Vec<OneOrMany>, HashError>>()?,
    })?))
}

const CBOR_CODEC: u64 = 0x71;
const RAW_CODEC: u64 = 0x55;

fn hash_inv(inv_hash: &Hash, sp: &SpaceId, ops: &[Operation]) -> Result<OneOrMany, HashError> {
    #[derive(Debug, Serialize)]
    #[serde(untagged)]
    enum Op<'a> {
        KvWrite {
            key: &'a Path,
            value: Cid,
            metadata: &'a Metadata,
        },
        KvDelete {
            key: &'a Path,
            version: Option<(i64, Cid, i64)>,
        },
    }

    let ops = ops
        .iter()
        .filter_map(|op| match op {
            Operation::KvWrite {
                space,
                key,
                value,
                metadata,
            } if space == sp => Some(Op::KvWrite {
                key,
                value: value.to_cid(CBOR_CODEC),
                metadata,
            }),
            Operation::KvDelete {
                space,
                key,
                version,
            } if space == sp => Some(Op::KvDelete {
                key,
                version: version.map(|(v, h, s)| (v, h.to_cid(CBOR_CODEC), s)),
            }),
            _ => None,
        })
        .map(|op| Ok(hash(&serde_ipld_dagcbor::to_vec(&op)?).to_cid(CBOR_CODEC)))
        .collect::<Result<Vec<_>, HashError>>()?;

    Ok(if ops.is_empty() {
        OneOrMany::One(inv_hash.to_cid(RAW_CODEC))
    } else {
        let mut v = vec![inv_hash.to_cid(RAW_CODEC)];
        v.extend(ops);
        OneOrMany::Many(v)
    })
}
