//! Opaque append-only transport for restore-independent purge records.
//!
//! The ledger lives in its own store, never in the KV block / SQL object
//! store it describes (TC-2871): in production a separate S3 bucket with
//! Object Lock (COMPLIANCE) and a deny-delete policy, so a purge, a lifecycle
//! rule on the data bucket, or a data-bucket credential can never remove or
//! rewrite a ledger record. The data bucket itself never carries Object Lock;
//! that would make erasure impossible.
use rocket::http::hyper::Uri;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};

#[path = "purge_ledger_fs.rs"]
mod fs;
#[path = "purge_ledger_s3.rs"]
mod s3;

pub use fs::FsPurgeLedger;
pub use s3::S3PurgeLedger;

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

/// `[storage.purge_ledger]`. `Local` is for single-host and development
/// nodes; production uses `S3` with a bucket of its own.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum PurgeLedgerConfig {
    Local { path: PathBuf },
    S3(S3PurgeLedgerConfig),
}

/// The ledger bucket. Credentials are optional: when both are set they are
/// used for the ledger client only, so the data-bucket credential needs no
/// ledger rights and the ledger credential none on data. The ledger
/// credential needs `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on
/// this bucket; reconciliation and restore read and list it. Deny every
/// delete and retention change.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct S3PurgeLedgerConfig {
    pub bucket: String,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub endpoint: Option<Uri>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
}

impl std::fmt::Debug for S3PurgeLedgerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3PurgeLedgerConfig")
            .field("bucket", &self.bucket)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Where the block store keeps data, for the separation check.
pub enum DataStoreLocation<'a> {
    Local(&'a Path),
    S3 {
        bucket: &'a str,
        endpoint: Option<&'a Uri>,
    },
}

impl PurgeLedgerConfig {
    /// Refuse a ledger that shares storage with the data it records: the same
    /// bucket on the same endpoint, or a directory inside, equal to, or
    /// containing the block directory. Paths are compared as configured;
    /// relative paths are resolved against the working directory.
    pub fn validate_separate_from(&self, data: &DataStoreLocation<'_>) -> Result<(), String> {
        match (self, data) {
            (Self::S3(ledger), _) if ledger.access_key_id.is_some() != ledger.secret_access_key.is_some() => {
                Err("storage.purge_ledger: set both access_key_id and secret_access_key, or neither".into())
            }
            (Self::S3(ledger), DataStoreLocation::S3 { bucket, endpoint })
                if ledger.bucket == *bucket
                    && ledger.endpoint.as_ref().map(ToString::to_string)
                        == endpoint.map(ToString::to_string) =>
            {
                Err("storage.purge_ledger.bucket must not be the block storage bucket".into())
            }
            (Self::Local { path }, DataStoreLocation::Local(blocks)) => {
                let ledger = absolute(path)?;
                let blocks = absolute(blocks)?;
                if ledger.starts_with(&blocks) || blocks.starts_with(&ledger) {
                    Err("storage.purge_ledger.path must not overlap the block storage path".into())
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    pub async fn open(&self) -> Result<PurgeLedger, Error> {
        Ok(match self {
            Self::Local { path } => PurgeLedger::Local(FsPurgeLedger::new(path.clone())?),
            Self::S3(config) => PurgeLedger::S3(S3PurgeLedger::new(config).await),
        })
    }
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|error| format!("storage.purge_ledger: {error}"))
}

pub enum PurgeLedger {
    Local(FsPurgeLedger),
    S3(S3PurgeLedger),
}

#[rocket::async_trait]
impl PurgeLedgerStore for PurgeLedger {
    async fn append_purge_record(&self, key: &str, body: &[u8]) -> Result<(), Error> {
        match self {
            Self::Local(store) => store.append_purge_record(key, body).await,
            Self::S3(store) => store.append_purge_record(key, body).await,
        }
    }
    async fn read_purge_record(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        match self {
            Self::Local(store) => store.read_purge_record(key).await,
            Self::S3(store) => store.read_purge_record(key).await,
        }
    }
    async fn list_purge_records(&self) -> Result<Vec<String>, Error> {
        match self {
            Self::Local(store) => store.list_purge_records().await,
            Self::S3(store) => store.list_purge_records().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(bucket: &str, endpoint: Option<&str>) -> PurgeLedgerConfig {
        PurgeLedgerConfig::S3(S3PurgeLedgerConfig {
            bucket: bucket.into(),
            endpoint: endpoint.map(|e| e.parse().unwrap()),
            region: None,
            access_key_id: None,
            secret_access_key: None,
        })
    }

    #[test]
    fn ledger_must_not_share_the_block_bucket_or_directory() {
        let minio: Uri = "http://127.0.0.1:9000".parse().unwrap();
        let data = DataStoreLocation::S3 {
            bucket: "node-data",
            endpoint: Some(&minio),
        };
        assert!(s3("node-data", Some("http://127.0.0.1:9000"))
            .validate_separate_from(&data)
            .is_err());
        assert!(s3("node-purge-ledger", Some("http://127.0.0.1:9000"))
            .validate_separate_from(&data)
            .is_ok());
        // Same name on another endpoint is another bucket.
        assert!(s3("node-data", None).validate_separate_from(&data).is_ok());
        let aws = DataStoreLocation::S3 {
            bucket: "node-data",
            endpoint: None,
        };
        assert!(s3("node-data", None).validate_separate_from(&aws).is_err());

        let blocks = PathBuf::from("/srv/tinycloud/data/blocks");
        let data = DataStoreLocation::Local(&blocks);
        for path in [
            "/srv/tinycloud/data/blocks",
            "/srv/tinycloud/data/blocks/_purge-ledger",
            "/srv/tinycloud/data",
        ] {
            let ledger = PurgeLedgerConfig::Local { path: path.into() };
            assert!(ledger.validate_separate_from(&data).is_err(), "{path}");
        }
        let ledger = PurgeLedgerConfig::Local {
            path: "/srv/tinycloud/data/purge-ledger".into(),
        };
        assert!(ledger.validate_separate_from(&data).is_ok());
    }

    #[test]
    fn ledger_credentials_come_in_pairs_and_never_print() {
        let PurgeLedgerConfig::S3(mut config) = s3("node-purge-ledger", None) else {
            unreachable!()
        };
        config.access_key_id = Some("AKIAEXAMPLE".into());
        let blocks = PathBuf::from("/srv/blocks");
        assert!(PurgeLedgerConfig::S3(config.clone())
            .validate_separate_from(&DataStoreLocation::Local(&blocks))
            .is_err());
        config.secret_access_key = Some("ledger-secret-value".into());
        assert!(PurgeLedgerConfig::S3(config.clone())
            .validate_separate_from(&DataStoreLocation::Local(&blocks))
            .is_ok());
        assert!(!format!("{config:?}").contains("ledger-secret-value"));
    }
}
