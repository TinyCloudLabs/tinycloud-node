use crate::{
    hash::{hash, Hash},
    types::Metadata,
    util::{DelegationInfo, InvocationInfo, RevocationInfo},
};
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
pub use tinycloud_auth::{
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

    pub fn serialized_bytes(&self) -> &[u8] {
        &self.1
    }

    pub fn content_hash(&self) -> Hash {
        hash(self.serialized_bytes())
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
                seq,
                epoch,
                epoch_seq,
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
        seq: i64,
        epoch: Hash,
        epoch_seq: i64,
    },
}

#[derive(Debug)]
pub(crate) enum Event {
    Invocation(Box<Invocation>, Vec<Operation>),
    /// A KV mutation that has already been authorized by the enclosing
    /// application protocol. This is private to the database composition
    /// layer; public invocations continue through the full UCAN validator.
    InternalInvocation(Box<Invocation>, Vec<Operation>),
    /// TC-409: an invocation whose envelope was already verified once at
    /// the admission boundary (`AdmittedInvocation::admit`). Distinct from
    /// `InternalInvocation`: execution still re-runs the full
    /// authorization graph, caveat containment, revocation ordering, chain
    /// limits, and storage authorization, and re-checks signed time
    /// validity — only the cryptographic signature check is skipped.
    AdmittedInvocation(Box<Invocation>, Vec<Operation>),
    Delegation(Box<Delegation>),
    Revocation(Box<Revocation>),
}

impl Event {
    pub fn hash(&self) -> Hash {
        match self {
            Event::Delegation(d) => hash(&d.1),
            Event::Invocation(i, _) => hash(&i.1),
            Event::InternalInvocation(i, _) => hash(&i.1),
            Event::AdmittedInvocation(i, _) => hash(&i.1),
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
                    Event::InternalInvocation(_, ops) => hash_inv(h, space, ops)?,
                    Event::AdmittedInvocation(_, ops) => hash_inv(h, space, ops)?,
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
                ..
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

#[cfg(test)]
mod signature_encoding_tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};
    use std::str::FromStr;
    use tinycloud_auth::cacaos::siwe::{encode_eip55, Message};
    use tinycloud_auth::cacaos::siwe_cacao::{Payload, Signature};

    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    #[tokio::test]
    async fn siwe_signature_encodings_have_one_delegation_cid() {
        let key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        let message = Message::from_str(&format!(
            "127.0.0.1 wants you to sign in with your Ethereum account:\n0x{}\n\n\nURI: http://127.0.0.1\nVersion: 1\nChain ID: 1\nNonce: testnonce123\nIssued At: 2026-10-14T00:00:00Z",
            encode_eip55(&address)
        ))
        .unwrap();
        let (signed, recovery) = key
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut low = [0u8; 65];
        low[..64].copy_from_slice(signed.to_bytes().as_ref());
        low[64] = u8::from(recovery) + 27;

        let mut high = low;
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let digit = ORDER[index] as i16 - low[32 + index] as i16 - borrow;
            high[32 + index] = digit as u8;
            borrow = i16::from(digit < 0);
        }
        assert_eq!(borrow, 0);
        high[64] = if low[64] == 27 { 28 } else { 27 };

        let mut canonical_cid = None;
        for (label, signature) in [
            ("low-v27/28", low),
            ("low-v0/1", {
                let mut s = low;
                s[64] -= 27;
                s
            }),
            ("high-v27/28", high),
            ("high-v0/1", {
                let mut s = high;
                s[64] -= 27;
                s
            }),
        ] {
            let cacao = Payload::from(message.clone())
                .sign::<tinycloud_auth::cacaos::siwe_cacao::Eip191>(Signature::from(signature));
            let header = URL_SAFE.encode(serde_ipld_dagcbor::to_vec(&cacao).unwrap());
            let event = Delegation::from_header_ser::<TinyCloudDelegation>(&header);
            if label.starts_with("high") {
                assert!(
                    event.is_err(),
                    "{label} must be rejected before CID assignment"
                );
                continue;
            }
            let event = event.unwrap();
            let TinyCloudDelegation::Cacao(decoded) = &event.0.delegation else {
                panic!("expected CACAO");
            };
            assert!(decoded.verify().await.is_ok(), "{label}");
            assert_eq!(
                decoded.signature().as_ref(),
                &low,
                "{label} decoded signature"
            );
            let cid = event.content_hash().to_cid(0x55);
            if let Some(canonical_cid) = canonical_cid {
                assert_eq!(cid, canonical_cid, "{label} must use the canonical CID");
            } else {
                canonical_cid = Some(cid);
            }
        }
    }
}
