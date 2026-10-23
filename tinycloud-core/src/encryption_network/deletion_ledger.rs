//! Append-only deletion ledger, kept outside the database.
//!
//! Every deleted key adds one JSON line `{networkId, keyPath, keyVersion,
//! deletedAt}`. The delete path appends and fsyncs the lines of a delete
//! before its database transaction commits, so a crash cannot lose a
//! deletion that the database recorded. [`replay`] re-applies a ledger to a
//! database (seed NULL, state `deleted`); a restore runs it as its first step.
//!
//! The file is only ever appended to. Replay is idempotent.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait, EntityTrait, TransactionTrait};
use serde::{Deserialize, Serialize};

use crate::{db::begin_write_transaction, models::encryption_network_key};

use super::service::{now_rfc3339, EncryptionServiceError};

/// Key row state written by a delete.
pub const KEY_STATE_DELETED: &str = "deleted";

/// One deleted key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerEntry {
    pub network_id: String,
    pub key_path: String,
    pub key_version: i64,
    pub deleted_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DeletionLedgerError {
    #[error("deletion ledger I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("deletion ledger path is invalid: {0}")]
    Path(&'static str),
    #[error("deletion ledger entry could not be encoded: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),
}

impl From<DeletionLedgerError> for EncryptionServiceError {
    fn from(err: DeletionLedgerError) -> Self {
        EncryptionServiceError::DeletionLedger(err.to_string())
    }
}

/// Configuration-time check of the ledger path: absolute, with a file name.
/// Opening is separate ([`DeletionLedger::open`]) so a preflight does not
/// touch the filesystem.
pub fn validate_path(path: &Path) -> Result<(), &'static str> {
    let text = path.to_str().ok_or("must be valid UTF-8")?;
    if text.is_empty() || text.contains('\0') {
        return Err("must not be empty");
    }
    if !path.is_absolute() {
        return Err("must be an absolute path");
    }
    if path.file_name().is_none() || text.ends_with('/') {
        return Err("must name a file");
    }
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("must not contain `..`");
    }
    Ok(())
}

/// An open ledger file. Appends are serialized and durable on return.
#[derive(Debug)]
pub struct DeletionLedger {
    path: PathBuf,
    file: Mutex<File>,
}

impl DeletionLedger {
    /// Opens (creating if absent) the ledger for appending. The file is
    /// created with mode 0600. A final line left without its newline by a
    /// crash is terminated so later appends start on a fresh line. The file
    /// and its directory are fsynced before this returns.
    pub fn open(path: &Path) -> Result<Self, DeletionLedgerError> {
        validate_path(path).map_err(DeletionLedgerError::Path)?;
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        let length = file.metadata()?.len();
        if length > 0 {
            let mut last = [0u8; 1];
            file.seek(SeekFrom::Start(length - 1))?;
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
            }
        }
        file.sync_all()?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one line per entry in a single write, then fsyncs. Returns only
    /// after the lines are durable. Blocking; async callers use
    /// [`DeletionLedger::append_blocking_task`].
    pub fn append(&self, entries: &[LedgerEntry]) -> Result<(), DeletionLedgerError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut lines = Vec::new();
        for entry in entries {
            serde_json::to_writer(&mut lines, entry)?;
            lines.push(b'\n');
        }
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        file.write_all(&lines)?;
        file.sync_all()?;
        Ok(())
    }

    /// [`DeletionLedger::append`] on the blocking pool.
    pub async fn append_blocking_task(
        self: &Arc<Self>,
        entries: Vec<LedgerEntry>,
    ) -> Result<(), DeletionLedgerError> {
        let ledger = Arc::clone(self);
        tokio::task::spawn_blocking(move || ledger.append(&entries))
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))?
    }
}

/// What a ledger file holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LedgerContents {
    pub entries: Vec<LedgerEntry>,
    /// 1-based numbers of non-empty lines that are not a ledger entry.
    pub malformed_lines: Vec<usize>,
}

/// Reads every line of a ledger file.
pub fn read(path: &Path) -> Result<LedgerContents, DeletionLedgerError> {
    let bytes = std::fs::read(path)?;
    let mut contents = LedgerContents::default();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<LedgerEntry>(line) {
            Ok(entry) => contents.entries.push(entry),
            Err(_) => contents.malformed_lines.push(index + 1),
        }
    }
    Ok(contents)
}

/// Result of [`replay`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayReport {
    pub entries: usize,
    /// Rows set to `deleted` with a NULL seed.
    pub applied: usize,
    /// Rows already `deleted` with no seed.
    pub already_deleted: usize,
    /// Rows whose key version is newer than the ledger entry (a later
    /// re-create): left alone.
    pub newer_version: usize,
    /// Entries with no row in this database.
    pub missing_row: usize,
    pub malformed_lines: Vec<usize>,
}

/// Re-applies the ledger at `path`: every named key row whose version is at
/// most the entry's is set to `deleted` with a NULL seed. One transaction;
/// idempotent. Rows the database does not have are counted, not created.
pub async fn replay<C: TransactionTrait>(
    db: &C,
    path: &Path,
) -> Result<ReplayReport, DeletionLedgerError> {
    let contents = read(path)?;
    let mut report = ReplayReport {
        entries: contents.entries.len(),
        malformed_lines: contents.malformed_lines,
        ..ReplayReport::default()
    };
    let tx = begin_write_transaction(db, None).await?;
    match apply(&tx, &contents.entries, &mut report).await {
        Ok(()) => tx.commit().await?,
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(err);
        }
    }
    Ok(report)
}

async fn apply<C: ConnectionTrait>(
    db: &C,
    entries: &[LedgerEntry],
    report: &mut ReplayReport,
) -> Result<(), DeletionLedgerError> {
    for entry in entries {
        let row = encryption_network_key::Entity::find_by_id((
            entry.network_id.clone(),
            entry.key_path.clone(),
        ))
        .one(db)
        .await?;
        let Some(row) = row else {
            report.missing_row += 1;
            continue;
        };
        if row.key_version > entry.key_version {
            report.newer_version += 1;
            continue;
        }
        if row.state == KEY_STATE_DELETED && row.sealed_seed.is_none() {
            report.already_deleted += 1;
            continue;
        }
        let mut active: encryption_network_key::ActiveModel = row.into();
        active.state = Set(KEY_STATE_DELETED.to_string());
        active.sealed_seed = Set(None);
        active.updated_at = Set(now_rfc3339());
        active.update(db).await?;
        report.applied += 1;
    }
    Ok(())
}
