//! Opaque append-only transport for restore-independent purge records.
use std::io::{Error, ErrorKind};

pub const PREFIX: &str = "_purge-ledger/";

pub(crate) fn validate_key(key: &str) -> Result<(), Error> {
    let suffix = key
        .strip_prefix(PREFIX)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid ledger prefix"))?;
    if key.len() > 1024
        || suffix.split('/').any(|part| {
            part.is_empty()
                || part.starts_with('.')
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
        })
    {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid ledger path"));
    }
    Ok(())
}

#[rocket::async_trait]
pub trait PurgeLedgerStore: Send + Sync {
    /// Publish bytes once. A different existing body returns AlreadyExists.
    async fn append_purge_record(&self, key: &str, body: &[u8]) -> Result<(), Error>;
    async fn read_purge_record(&self, key: &str) -> Result<Option<Vec<u8>>, Error>;
    async fn list_purge_records(&self) -> Result<Vec<String>, Error>;
}
