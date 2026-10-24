//! Append-only deletion ledger, kept outside the database.
//!
//! One JSON line per delete OPERATION, then one line that settles it:
//!
//! - an intent `{op, networkId, keys: [{keyPath, keyVersion}], deletedAt}`,
//!   appended and fsynced after the delete's database changes and before the
//!   transaction commits (`op` is the CID of the owner's credential);
//! - `{"committed": op}` after the commit, or `{"aborted": op}` when the commit
//!   failed while the process lives.
//!
//! A crash between the intent and its settling line leaves the intent open.
//! Every node start settles open intents against the database before the
//! routes mount ([`DeletionLedger::settle_open_intents`]): rows deleted at that
//! version mean the commit happened, otherwise the delete is aborted.
//!
//! [`replay`] re-applies a ledger to a database (seed NULL, state `deleted`)
//! and is the first step of a restore. It applies committed and still-open
//! intents and skips aborted ones. The file is only ever appended to, never
//! rotated.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait, EntityTrait, TransactionTrait};
use serde::{Deserialize, Serialize};

use crate::{db::begin_write_transaction, models::encryption_network_key};

use super::{
    key_id::{KeyKind, KeyLocation},
    keys::KeyState,
    network_id::NetworkId,
    service::{now_rfc3339, EncryptionServiceError},
};

/// One key a delete operation deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerKey {
    pub key_path: String,
    pub key_version: i64,
}

/// One delete operation: every key it deleted, in one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    /// CID of the credential the owner signed.
    pub op: String,
    pub network_id: String,
    pub keys: Vec<LedgerKey>,
    pub deleted_at: String,
}

/// The operation `committed` names has committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Committed {
    pub committed: String,
}

/// The operation `aborted` names did not commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aborted {
    pub aborted: String,
}

/// A ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Record {
    Intent(Intent),
    Committed(Committed),
    Aborted(Aborted),
}

impl Record {
    pub fn committed(op: &str) -> Self {
        Self::Committed(Committed {
            committed: op.to_string(),
        })
    }

    pub fn aborted(op: &str) -> Self {
        Self::Aborted(Aborted {
            aborted: op.to_string(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeletionLedgerError {
    #[error("deletion ledger I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("deletion ledger path is invalid: {0}")]
    Path(&'static str),
    #[error("deletion ledger entry could not be encoded: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("deletion ledger file was renamed or removed")]
    Moved,
    #[error("deletion ledger line {0} is malformed")]
    Malformed(usize),
    #[error("deletion ledger holds {0} key entries that are not valid keys")]
    Refused(usize),
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),
}

impl DeletionLedgerError {
    /// A fixed name for logs: it carries no path, key or database text.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Path(_) => "path",
            Self::Encode(_) => "encode",
            Self::Moved => "moved",
            Self::Malformed(_) => "malformed",
            Self::Refused(_) => "refused",
            Self::Db(_) => "db",
        }
    }
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
    dropped_tail_bytes: usize,
}

impl DeletionLedger {
    /// Opens (creating if absent) the ledger for appending. The file mode is
    /// forced to 0600. A final line that a crash left unterminated is kept if
    /// it is a whole record and otherwise dropped: a record is acted on only
    /// after its append returned, so an unterminated partial line was never
    /// followed by a commit. The file and its directory are fsynced before
    /// this returns.
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let dropped_tail_bytes = repair_tail(&mut file)?;
        file.sync_all()?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            dropped_tail_bytes,
        })
    }

    /// A ledger over an already opened file, to exercise write failures.
    #[cfg(test)]
    pub(super) fn from_file(path: &Path, file: File) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            dropped_tail_bytes: 0,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes of an unfinished final line that [`DeletionLedger::open`] removed.
    pub fn dropped_tail_bytes(&self) -> usize {
        self.dropped_tail_bytes
    }

    /// Appends one line and fsyncs. Returns only after the line is durable, and
    /// fails, writing nothing, if the file the handle names is no longer the
    /// file at the ledger path. Blocking; async callers use
    /// [`DeletionLedger::append_async`].
    pub fn append(&self, record: &Record) -> Result<(), DeletionLedgerError> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.check_not_moved(&file)?;
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(())
    }

    /// [`DeletionLedger::append`] on the blocking pool.
    pub async fn append_async(self: &Arc<Self>, record: Record) -> Result<(), DeletionLedgerError> {
        let ledger = Arc::clone(self);
        tokio::task::spawn_blocking(move || ledger.append(&record))
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))?
    }

    #[cfg(unix)]
    fn check_not_moved(&self, file: &File) -> Result<(), DeletionLedgerError> {
        use std::os::unix::fs::MetadataExt;
        let handle = file.metadata()?;
        let on_disk = std::fs::metadata(&self.path).map_err(|_| DeletionLedgerError::Moved)?;
        if handle.dev() != on_disk.dev() || handle.ino() != on_disk.ino() {
            return Err(DeletionLedgerError::Moved);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_not_moved(&self, _file: &File) -> Result<(), DeletionLedgerError> {
        Ok(())
    }

    /// The start-time replay. Applies the ledger to the database exactly as a
    /// restore does (see [`replay`]: committed and still-open operations
    /// apply, aborted ones do not), then closes every operation that was
    /// still open with a `committed` line, since the replay has made it
    /// true. Fails, closing nothing, when the ledger cannot be read, the
    /// database errors, or the ledger holds entries that are not valid keys.
    pub async fn replay_at_start<C: TransactionTrait>(
        &self,
        db: &C,
    ) -> Result<ReplayReport, DeletionLedgerError> {
        let report = replay(db, &self.path).await?;
        if report.refused > 0 {
            return Err(DeletionLedgerError::Refused(report.refused));
        }
        let open: Vec<String> = read(&self.path)?
            .open_intents()
            .into_iter()
            .map(|intent| intent.op.clone())
            .collect();
        for op in open {
            self.append(&Record::committed(&op))?;
        }
        Ok(report)
    }
}

/// Whether the delete named by `intent` committed: every key is `deleted` at
/// the intent's key version, or at a later one after a re-create.
pub(super) async fn intent_committed<C: ConnectionTrait>(
    db: &C,
    intent: &Intent,
) -> Result<bool, sea_orm::DbErr> {
    for key in &intent.keys {
        let row = encryption_network_key::Entity::find_by_id((
            intent.network_id.clone(),
            key.key_path.clone(),
        ))
        .one(db)
        .await?;
        let deleted = row.is_some_and(|row| {
            row.key_version > key.key_version
                || (row.key_version == key.key_version && row.state == KeyState::Deleted.as_str())
        });
        if !deleted {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Keeps a final line that is a whole record (adding its newline) and removes
/// one that is not. Returns the bytes removed.
fn repair_tail(file: &mut File) -> Result<usize, DeletionLedgerError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.last().is_none_or(|last| *last == b'\n') {
        return Ok(0);
    }
    let start = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    if serde_json::from_slice::<Record>(&bytes[start..]).is_ok() {
        file.write_all(b"\n")?;
        return Ok(0);
    }
    file.set_len(start as u64)?;
    Ok(bytes.len() - start)
}

/// What a ledger file holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LedgerContents {
    pub records: Vec<Record>,
    /// The final line is not a whole record.
    pub torn_tail: bool,
}

impl LedgerContents {
    /// Intents that no `committed` or `aborted` line names.
    pub fn open_intents(&self) -> Vec<&Intent> {
        let settled: std::collections::HashSet<&str> = self
            .records
            .iter()
            .filter_map(|record| match record {
                Record::Committed(Committed { committed }) => Some(committed.as_str()),
                Record::Aborted(Aborted { aborted }) => Some(aborted.as_str()),
                Record::Intent(_) => None,
            })
            .collect();
        self.intents()
            .filter(|intent| !settled.contains(intent.op.as_str()))
            .collect()
    }

    fn intents(&self) -> impl Iterator<Item = &Intent> {
        self.records.iter().filter_map(|record| match record {
            Record::Intent(intent) => Some(intent),
            _ => None,
        })
    }

    fn aborted_ops(&self) -> std::collections::HashSet<&str> {
        self.records
            .iter()
            .filter_map(|record| match record {
                Record::Aborted(Aborted { aborted }) => Some(aborted.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// Reads every line of a ledger file. An unfinished final line is reported as
/// `torn_tail`; a malformed line anywhere else is an error.
pub fn read(path: &Path) -> Result<LedgerContents, DeletionLedgerError> {
    let bytes = std::fs::read(path)?;
    let lines: Vec<(usize, &[u8])> = bytes
        .split(|byte| *byte == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.iter().all(u8::is_ascii_whitespace))
        .collect();
    let mut contents = LedgerContents::default();
    for (position, (index, line)) in lines.iter().enumerate() {
        match serde_json::from_slice::<Record>(line) {
            Ok(record) => contents.records.push(record),
            Err(_) if position + 1 == lines.len() => contents.torn_tail = true,
            Err(_) => return Err(DeletionLedgerError::Malformed(index + 1)),
        }
    }
    Ok(contents)
}

/// Result of [`replay`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayReport {
    /// Delete operations in the ledger.
    pub operations: usize,
    /// Operations skipped because they aborted.
    pub aborted_operations: usize,
    /// Rows set to `deleted` with a NULL seed.
    pub applied: usize,
    /// Rows already `deleted` with no seed.
    pub already_deleted: usize,
    /// Rows whose key version is newer than the ledger's (a later re-create):
    /// left alone.
    pub newer_version: usize,
    /// Keys with no row in this database.
    pub missing_row: usize,
    /// Keys whose row is not a deletable key: left alone.
    pub not_deletable: usize,
    /// Keys whose network id or path is not a valid key: skipped.
    pub refused: usize,
    /// The final line was not a whole record.
    pub torn_tail: bool,
}

/// Re-applies the ledger at `path`: every named key whose row is a deletable
/// key of at most the entry's version is set to `deleted` with a NULL seed.
/// Committed and still-open operations apply; aborted ones do not. One
/// transaction; idempotent. Rows the database does not have are counted, not
/// created.
pub async fn replay<C: TransactionTrait>(
    db: &C,
    path: &Path,
) -> Result<ReplayReport, DeletionLedgerError> {
    let contents = read(path)?;
    let aborted = contents.aborted_ops();
    let mut report = ReplayReport {
        torn_tail: contents.torn_tail,
        ..ReplayReport::default()
    };
    let mut to_apply = Vec::new();
    let mut seen = HashMap::new();
    for intent in contents.intents() {
        report.operations += 1;
        if aborted.contains(intent.op.as_str()) {
            report.aborted_operations += 1;
        } else if seen.insert(intent.op.as_str(), ()).is_none() {
            to_apply.push(intent);
        }
    }
    let tx = begin_write_transaction(db, None).await?;
    match apply(&tx, &to_apply, &mut report).await {
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
    intents: &[&Intent],
    report: &mut ReplayReport,
) -> Result<(), DeletionLedgerError> {
    for intent in intents {
        let Ok(network) = intent.network_id.parse::<NetworkId>() else {
            report.refused += intent.keys.len();
            continue;
        };
        for key in &intent.keys {
            // A path the key grammar refuses is never applied.
            if network.to_string() != intent.network_id
                || KeyLocation::new(&network, &key.key_path).is_err()
            {
                report.refused += 1;
                continue;
            }
            let row = encryption_network_key::Entity::find_by_id((
                intent.network_id.clone(),
                key.key_path.clone(),
            ))
            .one(db)
            .await?;
            let Some(row) = row else {
                report.missing_row += 1;
                continue;
            };
            if KeyKind::parse(&row.kind) != Some(KeyKind::Deletable) {
                report.not_deletable += 1;
                continue;
            }
            if row.key_version > key.key_version {
                report.newer_version += 1;
                continue;
            }
            if row.state == KeyState::Deleted.as_str() && row.sealed_seed.is_none() {
                report.already_deleted += 1;
                continue;
            }
            let mut active: encryption_network_key::ActiveModel = row.into();
            active.state = Set(KeyState::Deleted.as_str().to_string());
            active.sealed_seed = Set(None);
            active.updated_at = Set(now_rfc3339());
            active.update(db).await?;
            report.applied += 1;
        }
    }
    Ok(())
}
