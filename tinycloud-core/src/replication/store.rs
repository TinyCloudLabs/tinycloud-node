use crate::hash::Hash;
use serde::Serialize;
use tinycloud_auth::authorization::EncodingError;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerSubscription {
    pub peer: String,
    pub scope: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KvReplicationError {
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),
    #[error("encryption error: {0}")]
    Encryption(#[from] crate::encryption::EncryptionError),
    #[error("invocation encoding error: {0}")]
    Encoding(#[from] EncodingError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid invocation utf-8 for {invocation_id}: {reason}")]
    InvalidInvocationUtf8 {
        invocation_id: String,
        reason: String,
    },
    #[error("invalid replicated invocation {invocation_id}: {reason}")]
    InvalidInvocation {
        invocation_id: String,
        reason: String,
    },
    #[error("invalid hash encoding for {label}: {value}")]
    InvalidHashEncoding { label: &'static str, value: String },
    #[error("invalid space id: {0}")]
    InvalidSpaceId(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("store read error: {0}")]
    StoreRead(String),
    #[error("store write error: {0}")]
    StoreWrite(String),
    #[error("stage error: {0}")]
    Stage(String),
    #[error("transaction error: {0}")]
    Tx(String),
    #[error("missing block {hash} for invocation {invocation_id}")]
    MissingBlock { invocation_id: String, hash: String },
    #[error("missing deleted write metadata for invocation {invocation_id}")]
    MissingDeletedWrite { invocation_id: String },
    #[error("unsupported replicated invocation {invocation_id}: {reason}")]
    UnsupportedInvocation {
        invocation_id: String,
        reason: &'static str,
    },
}

pub fn encode_hash(hash: Hash) -> String {
    Vec::<u8>::from(hash)
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn decode_hash(value: &str, label: &'static str) -> Result<Hash, KvReplicationError> {
    if value.len() % 2 != 0 {
        return Err(KvReplicationError::InvalidHashEncoding {
            label,
            value: value.to_string(),
        });
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<_> = value.as_bytes().chunks_exact(2).collect();
    for chunk in chars {
        let pair =
            std::str::from_utf8(chunk).map_err(|_| KvReplicationError::InvalidHashEncoding {
                label,
                value: value.to_string(),
            })?;
        let byte =
            u8::from_str_radix(pair, 16).map_err(|_| KvReplicationError::InvalidHashEncoding {
                label,
                value: value.to_string(),
            })?;
        bytes.push(byte);
    }
    Hash::try_from(bytes).map_err(|_| KvReplicationError::InvalidHashEncoding {
        label,
        value: value.to_string(),
    })
}
