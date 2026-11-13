use super::*;
use crate::storage::purge_ledger::{validate_key, PurgeLedgerStore, PREFIX};

#[rocket::async_trait]
impl PurgeLedgerStore for S3BlockStore {
    async fn append_purge_record(&self, key: &str, body: &[u8]) -> Result<(), IoError> {
        validate_key(key)?;
        match self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .if_none_match("*")
            .body(ByteStream::from(body.to_vec()))
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(error)
                if error.as_service_error().and_then(|e| e.code())
                    == Some("PreconditionFailed") =>
            {
                if self.read_purge_record(key).await?.as_deref() == Some(body) {
                    Ok(())
                } else {
                    Err(IoError::new(
                        std::io::ErrorKind::AlreadyExists,
                        "ledger record already exists",
                    ))
                }
            }
            Err(error) => Err(IoError::other(error)),
        }
    }

    async fn read_purge_record(&self, key: &str) -> Result<Option<Vec<u8>>, IoError> {
        validate_key(key)?;
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(object) => Ok(Some(
                object
                    .body
                    .collect()
                    .await
                    .map_err(IoError::other)?
                    .into_bytes()
                    .to_vec(),
            )),
            Err(error) if error.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
            Err(error) => Err(IoError::other(error)),
        }
    }

    async fn list_purge_records(&self) -> Result<Vec<String>, IoError> {
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(PREFIX)
            .into_paginator()
            .send();
        let mut entries = Vec::new();
        while let Some(page) = pages.try_next().await.map_err(IoError::other)? {
            for item in page.contents() {
                let key = item
                    .key()
                    .ok_or_else(|| IoError::other("missing ledger object key"))?;
                validate_key(key)?;
                entries.push(key.to_owned());
            }
        }
        Ok(entries)
    }
}
