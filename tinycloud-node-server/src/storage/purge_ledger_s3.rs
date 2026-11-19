use super::{validate_key, PurgeLedgerStore, S3PurgeLedgerConfig, PREFIX};
use aws_sdk_s3::{
    config::{Credentials, Region},
    error::ProvideErrorMetadata,
    primitives::ByteStream,
    types::ChecksumAlgorithm,
    Client,
};
use std::io::Error as IoError;

/// The purge ledger's own bucket and client, separate from the block store.
#[derive(Debug, Clone)]
pub struct S3PurgeLedger {
    client: Client,
    bucket: String,
}

impl S3PurgeLedger {
    pub async fn new(config: &S3PurgeLedgerConfig) -> Self {
        let general = crate::storage::s3::aws_config().await;
        // Default checksums (unlike the block client): an Object Lock bucket
        // refuses a PUT that carries no checksum.
        let mut builder = aws_sdk_s3::config::Builder::from(&general);
        if let Some(endpoint) = &config.endpoint {
            builder = builder
                .endpoint_url(endpoint.to_string())
                .force_path_style(true);
        }
        if let Some(region) = &config.region {
            builder = builder.region(Region::new(region.clone()));
        }
        if let (Some(id), Some(secret)) = (&config.access_key_id, &config.secret_access_key) {
            builder = builder.credentials_provider(Credentials::new(
                id,
                secret,
                None,
                None,
                "tinycloud-purge-ledger",
            ));
        }
        Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn client(&self) -> (&Client, &str) {
        (&self.client, &self.bucket)
    }
}

#[rocket::async_trait]
impl PurgeLedgerStore for S3PurgeLedger {
    async fn append_purge_record(&self, key: &str, body: &[u8]) -> Result<(), IoError> {
        validate_key(key)?;
        match self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .if_none_match("*")
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
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
