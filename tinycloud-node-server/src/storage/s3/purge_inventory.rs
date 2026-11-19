use super::*;
use crate::storage::purge_inventory::{PhysicalSpacePrefix, SpacePrefixPage};

impl S3BlockStore {
    pub async fn list_purge_prefixes(
        &self,
        cursor: Option<&str>,
    ) -> Result<SpacePrefixPage, S3StoreError> {
        let page = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(KV_SCAN_PREFIX)
            .delimiter("/")
            .max_keys(256)
            .set_continuation_token(cursor.map(str::to_owned))
            .send()
            .await
            .map_err(S3Error::from)?;
        let mut prefixes = Vec::new();
        for item in page.common_prefixes() {
            let prefix = item.prefix().ok_or_else(|| {
                IoError::new(
                    std::io::ErrorKind::InvalidData,
                    "missing physical space prefix",
                )
            })?;
            let space = prefix
                .strip_suffix('/')
                .and_then(|name| name.parse::<SpaceId>().ok())
                .ok_or_else(|| {
                    IoError::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid physical space identity",
                    )
                })?;
            if format!("{space}/") != prefix {
                return Err(IoError::new(
                    std::io::ErrorKind::InvalidData,
                    "noncanonical physical space identity",
                )
                .into());
            }
            prefixes.push(PhysicalSpacePrefix {
                space,
                prefix: prefix.into(),
            });
        }
        let next_cursor = page.next_continuation_token().map(str::to_owned);
        if page.is_truncated() == Some(true) && next_cursor.is_none() {
            return Err(IoError::new(
                std::io::ErrorKind::InvalidData,
                "incomplete physical space listing",
            )
            .into());
        }
        Ok(SpacePrefixPage {
            prefixes,
            next_cursor,
        })
    }
}
