//! Bounded physical repair under an authenticated prefix and global restore
//! drain. This module neither constructs proofs nor changes durable progress.
use super::{
    file_system::FileSystemStore,
    purge_reconcile::{PrefixStoreKind, RestoreDrain, VerifiedPurgePrefix},
    s3::S3BlockStore,
    sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore, S3SqlObjectStore},
};
use std::io::{Error, ErrorKind};
use tinycloud_auth::resource::SpaceId;
#[cfg(feature = "duckdb")]
use tinycloud_core::duckdb::DuckDbService;
use tinycloud_core::sql::SqlService;

pub enum RestorePurgeStore<'a> {
    KvFileSystem(&'a FileSystemStore),
    KvS3(&'a S3BlockStore),
    SqlFileSystem(&'a FsSqlObjectStore),
    SqlS3(&'a S3SqlObjectStore),
    SqliteCache(&'a SqlService),
    #[cfg(feature = "duckdb")]
    DuckDbCache(&'a DuckDbService),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePrefixOutcome {
    MoreObjects,
    VerifiedEmpty,
}

/// The reconciler owns proof construction, expiring repair claims and all
/// forward-only DB/ledger transitions. Each retry lists from the beginning;
/// a provider cursor is never treated as durable deletion progress.
pub async fn purge_restore_prefix_batch(
    store: RestorePurgeStore<'_>,
    _drain: &RestoreDrain,
    verified: &VerifiedPurgePrefix,
) -> Result<RestorePrefixOutcome, Error> {
    let empty = match (store, verified.store_kind()) {
        (RestorePurgeStore::KvFileSystem(store), PrefixStoreKind::KvFileSystem) => {
            let space = filesystem_space(verified.prefix())?;
            store.purge_space_batch(&space).await.map_err(failed)?
        }
        (RestorePurgeStore::KvS3(store), PrefixStoreKind::KvS3) => {
            let space = canonical_space(verified.prefix())?;
            store.purge_space_batch(&space).await.map_err(failed)?
        }
        (RestorePurgeStore::SqlFileSystem(store), PrefixStoreKind::SqlFileSystem) => {
            // A hashed SQL namespace is purged directly. No owner or SpaceId
            // is inferred, recovered, or fabricated for this branch.
            let prefix =
                SqlPhysicalPrefix::parse(verified.prefix()).map_err(|_| invalid_prefix())?;
            store.purge_prefix_batch(&prefix).await.map_err(failed)?
        }
        (RestorePurgeStore::SqlS3(store), PrefixStoreKind::SqlS3) => {
            let prefix =
                SqlPhysicalPrefix::parse(verified.prefix()).map_err(|_| invalid_prefix())?;
            store.purge_prefix_batch(&prefix).await.map_err(failed)?
        }
        (RestorePurgeStore::SqliteCache(service), PrefixStoreKind::SqliteCache) => {
            let space = canonical_space(verified.prefix())?;
            service
                .drain_and_evict_space(&space)
                .await
                .map_err(failed)?;
            true
        }
        #[cfg(feature = "duckdb")]
        (RestorePurgeStore::DuckDbCache(service), PrefixStoreKind::DuckDbCache) => {
            let space = canonical_space(verified.prefix())?;
            service
                .drain_and_evict_space(&space)
                .await
                .map_err(failed)?;
            true
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "authenticated prefix storage kind mismatch",
            ));
        }
    };
    Ok(if empty {
        RestorePrefixOutcome::VerifiedEmpty
    } else {
        RestorePrefixOutcome::MoreObjects
    })
}

fn failed<E>(_: E) -> Error {
    Error::other("authenticated prefix repair unavailable")
}

fn invalid_prefix() -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        "invalid authenticated storage prefix",
    )
}

fn filesystem_space(prefix: &str) -> Result<SpaceId, Error> {
    let raw = prefix.strip_suffix('/').ok_or_else(invalid_prefix)?;
    let mut components = raw.split('/');
    let owner = components.next().ok_or_else(invalid_prefix)?;
    let name = components.next().ok_or_else(invalid_prefix)?;
    if components.next().is_some()
        || [owner, name].iter().any(|component| {
            component.is_empty() || matches!(*component, "." | "..") || component.contains('\\')
        })
    {
        return Err(invalid_prefix());
    }
    let space: SpaceId = format!("tinycloud:{owner}:{name}")
        .parse()
        .map_err(|_| invalid_prefix())?;
    if format!("{}/{}/", space.suffix(), space.name()) != prefix {
        return Err(invalid_prefix());
    }
    Ok(space)
}

fn canonical_space(prefix: &str) -> Result<SpaceId, Error> {
    let raw = prefix.strip_suffix('/').ok_or_else(invalid_prefix)?;
    if raw.contains('/') || raw.contains('\\') {
        return Err(invalid_prefix());
    }
    let space: SpaceId = raw.parse().map_err(|_| invalid_prefix())?;
    if format!("{space}/") != prefix {
        return Err(invalid_prefix());
    }
    Ok(space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_prefixes_require_one_exact_round_tripping_space_namespace() {
        let space: SpaceId =
            "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
                .parse()
                .unwrap();
        assert!(filesystem_space(&format!("{}/{}/", space.suffix(), space.name())).is_ok());
        assert!(canonical_space(&format!("{space}/")).is_ok());
        for invalid in [
            "",
            "/",
            "../",
            "_purge-ledger/owners/",
            "sql/v1/",
            "key:test/../",
            "key:test/./",
            "key:test//",
            "key:test/files/extra/",
            "key:test/files",
            "key:test/files\\other/",
        ] {
            assert!(filesystem_space(invalid).is_err());
        }
        for invalid in [
            "",
            "/",
            "tinycloud:",
            "tinycloud:key:test:files",
            "_purge-ledger/",
            "sql/v1/",
            "tinycloud:key:test:files/extra/",
            "tinycloud:key:test:files\\other/",
        ] {
            assert!(canonical_space(invalid).is_err());
        }
    }
}
