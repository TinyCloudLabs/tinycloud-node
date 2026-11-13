use super::*;
use crate::storage::purge_inventory::{PhysicalSpacePrefix, SpacePrefixPage};

impl FileSystemStore {
    /// Keyset pages retain at most 257 candidates while scanning directory names.
    /// Symlink directories are refused, and the reserved ledger is never traversed.
    pub async fn list_purge_prefixes(
        &self,
        cursor: Option<&str>,
    ) -> Result<SpacePrefixPage, IoError> {
        let mut names = std::collections::BTreeMap::new();
        let mut owners = tokio::fs::read_dir(&self.path).await?;
        while let Some(owner) = owners.next_entry().await? {
            let suffix = owner
                .file_name()
                .into_string()
                .map_err(|_| IoError::new(ErrorKind::InvalidData, "invalid owner path"))?;
            if suffix == "_purge-ledger" {
                continue;
            }
            let kind = owner.file_type().await?;
            if kind.is_symlink() {
                return Err(IoError::new(ErrorKind::InvalidData, "unsafe owner path"));
            }
            if !kind.is_dir() {
                continue;
            }
            let mut spaces = tokio::fs::read_dir(owner.path()).await?;
            while let Some(entry) = spaces.next_entry().await? {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| IoError::new(ErrorKind::InvalidData, "invalid space path"))?;
                let kind = entry.file_type().await?;
                if kind.is_symlink() {
                    return Err(IoError::new(ErrorKind::InvalidData, "unsafe space path"));
                }
                if !kind.is_dir() {
                    continue;
                }
                let space = format!("tinycloud:{suffix}:{name}")
                    .parse::<SpaceId>()
                    .map_err(|_| {
                        IoError::new(ErrorKind::InvalidData, "invalid physical space identity")
                    })?;
                if space.suffix() != suffix || space.name().as_str() != name {
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        "noncanonical physical space identity",
                    ));
                }
                let prefix = format!("{suffix}/{name}/");
                if cursor.is_some_and(|cursor| prefix.as_str() <= cursor) {
                    continue;
                }
                names.insert(prefix, space);
                if names.len() > 257 {
                    names.pop_last();
                }
            }
        }
        let truncated = names.len() > 256;
        if truncated {
            names.pop_last();
        }
        let next_cursor = truncated.then(|| names.last_key_value().unwrap().0.clone());
        let prefixes = names
            .into_iter()
            .map(|(prefix, space)| PhysicalSpacePrefix { prefix, space })
            .collect();
        Ok(SpacePrefixPage {
            prefixes,
            next_cursor,
        })
    }
}
