//! Physical SQL-prefix transport. Callers authenticate the prefix against the
//! acceptance ledger and drain writers before invoking deletion.
use super::*;
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::sql::store::key::{dec, enc};

/// One exact SQL space namespace, including an irreversible hashed component.
/// Parsing validates scope only; ledger authentication belongs to the caller.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SqlPhysicalPrefix(String);
impl SqlPhysicalPrefix {
    pub fn for_space(space: &SpaceId) -> Self {
        Self(format!("{KEY_ROOT}{}/", enc(&space.to_string())))
    }
    pub fn parse(prefix: &str) -> Result<Self, SqlStoreError> {
        let component = prefix
            .strip_prefix(KEY_ROOT)
            .and_then(|s| s.strip_suffix('/'))
            .ok_or(SqlStoreError::Invalid("invalid SQL purge prefix"))?;
        let hashed = component.strip_prefix('~').is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        let reversible = dec(component)
            .ok()
            .and_then(|raw| {
                raw.parse::<SpaceId>()
                    .ok()
                    .filter(|space| space.to_string() == raw && enc(&raw) == component)
            })
            .is_some();
        if !hashed && !reversible {
            return Err(SqlStoreError::Invalid("invalid SQL purge prefix"));
        }
        Ok(Self(prefix.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn component(&self) -> &str {
        self.0
            .strip_prefix(KEY_ROOT)
            .unwrap()
            .strip_suffix('/')
            .unwrap()
    }
}

pub struct SqlPrefixPage {
    pub prefixes: Vec<SqlPhysicalPrefix>,
    pub next_cursor: Option<String>,
}

impl S3SqlObjectStore {
    /// Provider continuation tokens are opaque and are never stored as purge progress.
    pub async fn list_purge_prefixes(
        &self,
        cursor: Option<&str>,
    ) -> Result<SqlPrefixPage, SqlStoreError> {
        let page = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(KEY_ROOT)
            .delimiter("/")
            .max_keys(256)
            .set_continuation_token(cursor.map(str::to_owned))
            .send()
            .await
            .map_err(|_| SqlStoreError::Backend("SQL purge inventory unavailable".into()))?;
        let mut prefixes = Vec::new();
        for entry in page.common_prefixes() {
            let prefix = entry
                .prefix()
                .ok_or(SqlStoreError::Invalid("missing SQL prefix"))?;
            if prefix == format!("{KEY_ROOT}_probe/") {
                continue;
            }
            prefixes.push(SqlPhysicalPrefix::parse(prefix)?);
        }
        let next_cursor = page.next_continuation_token().map(str::to_owned);
        if page.is_truncated() == Some(true) && next_cursor.is_none() {
            return Err(SqlStoreError::Invalid("incomplete SQL prefix listing"));
        }
        Ok(SqlPrefixPage {
            prefixes,
            next_cursor,
        })
    }
    /// Re-list from the start on every invocation. True requires an empty listing.
    pub async fn purge_prefix_batch(
        &self,
        prefix: &SqlPhysicalPrefix,
    ) -> Result<bool, SqlStoreError> {
        let page = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix.as_str())
            .max_keys(256)
            .send()
            .await
            .map_err(|_| SqlStoreError::Backend("SQL purge listing unavailable".into()))?;
        if page.contents().is_empty() {
            return Ok(!page.is_truncated().unwrap_or(false));
        }
        for entry in page.contents() {
            let key = entry
                .key()
                .filter(|key| key.starts_with(prefix.as_str()))
                .ok_or(SqlStoreError::Invalid("object outside SQL purge prefix"))?;
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|_| SqlStoreError::Backend("SQL purge deletion unavailable".into()))?;
        }
        Ok(false)
    }
}

fn checked_directory(path: &Path) -> Result<bool, SqlStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(SqlStoreError::Invalid("unsafe SQL purge directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SqlStoreError::Backend(
            "SQL purge directory unavailable".into(),
        )),
    }
}
impl FsSqlObjectStore {
    fn purge_root(&self) -> Result<Option<PathBuf>, SqlStoreError> {
        let mut path = self.root.clone();
        for component in ["", "sql", "v1"] {
            if !component.is_empty() {
                path.push(component);
            }
            if !checked_directory(&path)? {
                return Ok(None);
            }
        }
        Ok(Some(path))
    }
    /// Filesystem keyset pages use at most 257 retained names. A restart begins at None.
    pub async fn list_purge_prefixes(
        &self,
        cursor: Option<&str>,
    ) -> Result<SqlPrefixPage, SqlStoreError> {
        let Some(root) = self.purge_root()? else {
            return Ok(SqlPrefixPage {
                prefixes: vec![],
                next_cursor: None,
            });
        };
        let mut names = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(root)
            .map_err(|_| SqlStoreError::Backend("SQL prefix inventory unavailable".into()))?
        {
            let entry = entry
                .map_err(|_| SqlStoreError::Backend("SQL prefix inventory unavailable".into()))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SqlStoreError::Invalid("invalid SQL prefix encoding"))?;
            if name == "_probe" {
                continue;
            }
            let prefix = SqlPhysicalPrefix::parse(&format!("{KEY_ROOT}{name}/"))?;
            checked_directory(&entry.path())?;
            if cursor.is_some_and(|cursor| prefix.as_str() <= cursor) {
                continue;
            }
            names.insert(prefix);
            if names.len() > 257 {
                names.pop_last();
            }
        }
        let truncated = names.len() > 256;
        if truncated {
            names.pop_last();
        }
        let prefixes: Vec<_> = names.into_iter().collect();
        let next_cursor = truncated.then(|| prefixes.last().unwrap().as_str().to_owned());
        Ok(SqlPrefixPage {
            prefixes,
            next_cursor,
        })
    }
    pub async fn purge_prefix_batch(
        &self,
        prefix: &SqlPhysicalPrefix,
    ) -> Result<bool, SqlStoreError> {
        let Some(root) = self.purge_root()? else {
            return Ok(true);
        };
        let target = root.join(prefix.component());
        if !checked_directory(&target)? {
            return Ok(true);
        }
        let mut budget = 256;
        let empty = remove_batch(&target, &mut budget, 0)?;
        if empty && budget == 256 {
            match std::fs::remove_dir(&target) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
                Err(error) if error.kind() == ErrorKind::DirectoryNotEmpty => Ok(false),
                Err(_) => Err(SqlStoreError::Backend(
                    "SQL purge deletion unavailable".into(),
                )),
            }
        } else {
            Ok(false)
        }
    }
}

// Only unlink leaf paths. A symlink is unlinked, never traversed. Parent/root
// components are checked separately; ordinary writers must already be drained.
fn remove_batch(path: &Path, budget: &mut usize, depth: usize) -> Result<bool, SqlStoreError> {
    if depth > 8 {
        return Err(SqlStoreError::Invalid("unexpected SQL purge depth"));
    }
    let mut empty = true;
    for entry in std::fs::read_dir(path)
        .map_err(|_| SqlStoreError::Backend("SQL purge listing unavailable".into()))?
    {
        let entry =
            entry.map_err(|_| SqlStoreError::Backend("SQL purge listing unavailable".into()))?;
        if *budget == 0 {
            return Ok(false);
        }
        empty = false;
        let kind = entry
            .file_type()
            .map_err(|_| SqlStoreError::Backend("SQL purge metadata unavailable".into()))?;
        let result = if kind.is_dir() {
            if !remove_batch(&entry.path(), budget, depth + 1)? {
                continue;
            }
            std::fs::remove_dir(entry.path())
        } else {
            std::fs::remove_file(entry.path())
        };
        match result {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => {
                return Err(SqlStoreError::Backend(
                    "SQL purge deletion unavailable".into(),
                ))
            }
        }
        *budget -= 1;
    }
    Ok(empty)
}
