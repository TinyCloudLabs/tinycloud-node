//! Where the at-rest keyring mirrors its sealed ARK rows and escrow bundles
//! (TC-887): next to the blocks, so a database restored to before an ARK
//! row was written can still open blocks stored after it.
//!
//! - S3: objects under `_tc/at-rest/` in the block bucket. The boot size scan
//!   only counts `{space}/{hash}` keys, so these are never charged to a space.
//! - Filesystem: files under `{datadir}/at-rest/`, outside the block
//!   directory (whose size scan treats every subdirectory as a DID).

use std::path::{Component, Path, PathBuf};

use aws_sdk_s3::{
    error::{GetObjectError, GetObjectErrorKind},
    types::{ByteStream, SdkError},
    Client,
};
use futures::TryStreamExt;
use tinycloud_core::at_rest::{
    store::{MirrorError, MirrorObjectTooLarge, MAX_MIRROR_OBJECT, MIRROR_PREFIX},
    KeyMirror,
};

use super::s3::{new_client, S3BlockConfig};

/// Control objects in the S3 block bucket.
pub struct S3KeyMirror {
    client: Client,
    bucket: String,
}

impl S3KeyMirror {
    pub async fn new(config: &S3BlockConfig) -> Self {
        Self {
            client: new_client(config).await,
            bucket: config.bucket.clone(),
        }
    }
}

fn check_name(name: &str) -> Result<(), MirrorError> {
    let ok = name.starts_with(MIRROR_PREFIX)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
        && !name.contains("..");
    if ok {
        Ok(())
    } else {
        Err(format!("invalid at-rest mirror name {name:?}").into())
    }
}

#[async_trait::async_trait]
impl KeyMirror for S3KeyMirror {
    async fn put(&self, name: &str, bytes: Vec<u8>) -> Result<(), MirrorError> {
        check_name(name)?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(name)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| aws_sdk_s3::Error::from(e).into())
            .map(|_| ())
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, MirrorError> {
        check_name(name)?;
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(name)
            .send()
            .await
        {
            Ok(o) => {
                // A key object is a few hundred bytes; anything far larger
                // is junk planted in the bucket, never read into memory.
                if o.content_length() > MAX_MIRROR_OBJECT as i64 {
                    return Err(Box::new(MirrorObjectTooLarge));
                }
                let mut body = o.body;
                let mut out = Vec::new();
                while let Some(chunk) = body.try_next().await? {
                    if out.len() + chunk.len() > MAX_MIRROR_OBJECT {
                        return Err(Box::new(MirrorObjectTooLarge));
                    }
                    out.extend_from_slice(&chunk);
                }
                Ok(Some(out))
            }
            Err(SdkError::ServiceError {
                err:
                    GetObjectError {
                        kind: GetObjectErrorKind::NoSuchKey(_),
                        ..
                    },
                ..
            }) => Ok(None),
            Err(e) => Err(aws_sdk_s3::Error::from(e).into()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MirrorError> {
        check_name(prefix)?;
        let pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();
        let names = pages
            .map_err(|e| -> MirrorError { aws_sdk_s3::Error::from(e).into() })
            .try_fold(Vec::new(), |mut acc, page| async move {
                acc.extend(
                    page.contents
                        .into_iter()
                        .flatten()
                        .filter_map(|o| o.key().map(str::to_owned)),
                );
                Ok(acc)
            })
            .await?;
        Ok(names)
    }
}

/// Control files under a local directory.
pub struct FsKeyMirror {
    root: PathBuf,
}

impl FsKeyMirror {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, name: &str) -> Result<PathBuf, MirrorError> {
        check_name(name)?;
        let rel = Path::new(name);
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(format!("invalid at-rest mirror name {name:?}").into());
        }
        Ok(self.root.join(rel))
    }
}

#[async_trait::async_trait]
impl KeyMirror for FsKeyMirror {
    async fn put(&self, name: &str, bytes: Vec<u8>) -> Result<(), MirrorError> {
        let path = self.path(name)?;
        let dir = path.parent().ok_or("mirror path has no parent")?;
        tokio::fs::create_dir_all(dir).await?;
        // Write, fsync, then rename, so a crash never leaves a half-written
        // or unsynced key file under the final name. The temporary name is
        // unique, so concurrent writers of one object never collide.
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("mirror path has no file name")?;
        let tmp = dir.join(format!("{file_name}.{:016x}.tmp", rand::random::<u64>()));
        let mut file = tokio::fs::File::create(&tmp).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, &path).await?;
        tokio::fs::File::open(dir).await?.sync_all().await?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, MirrorError> {
        let path = self.path(name)?;
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.len() > MAX_MIRROR_OBJECT as u64 => {
                return Err(Box::new(MirrorObjectTooLarge))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MirrorError> {
        check_name(prefix)?;
        // Names are "_tc/at-rest/<file>": one directory level to scan.
        let (dir_name, file_prefix) = prefix.rsplit_once('/').ok_or("prefix has no directory")?;
        let dir = self.path(&format!("{dir_name}/"))?;
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if let Ok(file) = entry.file_name().into_string() {
                if file.starts_with(file_prefix) && !file.ends_with(".tmp") {
                    names.push(format!("{dir_name}/{file}"));
                }
            }
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fs_mirror_round_trips_lists_and_refuses_escapes() {
        let dir = tempfile::tempdir().unwrap();
        let m = FsKeyMirror::new(dir.path().to_path_buf());
        assert!(m.list("_tc/at-rest/ark-").await.unwrap().is_empty());
        m.put("_tc/at-rest/ark-0000000001-ab.json", b"one".to_vec())
            .await
            .unwrap();
        m.put("_tc/at-rest/escrow-cd.json", b"two".to_vec())
            .await
            .unwrap();
        assert_eq!(
            m.get("_tc/at-rest/ark-0000000001-ab.json").await.unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(m.get("_tc/at-rest/missing.json").await.unwrap(), None);
        assert_eq!(
            m.list("_tc/at-rest/ark-").await.unwrap(),
            vec!["_tc/at-rest/ark-0000000001-ab.json".to_string()]
        );
        for bad in [
            "../x",
            "_tc/at-rest/../../etc",
            "other/x",
            "_tc/at-rest/a b",
        ] {
            assert!(m.put(bad, vec![]).await.is_err(), "{bad}");
        }
    }
}
