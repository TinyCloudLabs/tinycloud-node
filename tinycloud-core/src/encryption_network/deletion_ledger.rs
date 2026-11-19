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
//! Every node start replays the ledger onto the database before the routes
//! mount ([`DeletionLedger::replay_at_start`]): committed and still-open
//! operations are applied, and each open operation is then closed with a
//! `committed` line. Only an operation whose commit is known not to have
//! happened is settled `aborted`.
//!
//! [`replay`] re-applies a ledger to a database (seed NULL, state `deleted`)
//! and is the first step of a restore. It applies committed and still-open
//! intents and skips aborted ones.
//!
//! Lines are only ever appended, with one exception:
//! [`DeletionLedger::prune_owners`] removes the settled operations of given
//! owners by writing the remaining lines to `<ledger path>.prune.tmp` and
//! renaming that over the ledger, so the ledger path always names a whole
//! file. [`DeletionLedger::open`] removes a temporary file an interrupted
//! prune left behind.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
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
    #[error("deletion ledger is locked by another process")]
    LockHeld,
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
            Self::LockHeld => "lock_held",
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

/// How often `open` tries the lock while another process holds it.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// How long `open` waits for the lock before it fails with
/// [`DeletionLedgerError::LockHeld`].
const LOCK_WAIT_LIMIT: Duration = Duration::from_secs(60);

/// The lock file of a ledger: the ledger path with `.lock` appended.
fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// The file [`DeletionLedger::prune_owners`] writes before renaming it over
/// the ledger: the ledger path with `.prune.tmp` appended.
fn prune_temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".prune.tmp");
    PathBuf::from(name)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Fsyncs the directory holding `path`, so a created, renamed or removed
/// entry in it is durable.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

/// Opens the ledger file for reading and appending and forces its mode to
/// 0600. With `create` false a missing file is an error.
fn open_ledger_file(path: &Path, create: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Writes `bytes` to a new file at `temp` with mode 0600 and fsyncs it. A
/// file already there is a leftover of an earlier failed prune and is
/// replaced; `create_new` never follows a link planted at the name.
fn write_prune_temp(temp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    remove_if_present(temp)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Takes a non-blocking exclusive `flock`. `Ok(false)` means another open
/// file description holds it.
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    loop {
        // SAFETY: `flock` takes a descriptor that `file` keeps open for the
        // duration of the call and reads or writes no memory of ours.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::WouldBlock => return Ok(false),
            std::io::ErrorKind::Interrupted => continue,
            _ => return Err(error),
        }
    }
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> std::io::Result<bool> {
    Ok(true)
}

/// Creates (never deletes) the lock file next to the ledger with mode 0600
/// and takes its exclusive lock, retrying every `interval` for up to `limit`.
/// The lock lasts as long as the returned file is open.
fn acquire_lock(
    path: &Path,
    interval: Duration,
    limit: Duration,
) -> Result<File, DeletionLedgerError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock_file = options.open(lock_path(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        lock_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let started = Instant::now();
    let mut waited = false;
    loop {
        if try_lock_exclusive(&lock_file)? {
            return Ok(lock_file);
        }
        if !waited {
            waited = true;
            ::tracing::warn!(
                event = "deletion_ledger_lock_wait",
                "deletion ledger is locked by another process: waiting for it"
            );
        }
        if started.elapsed() >= limit {
            return Err(DeletionLedgerError::LockHeld);
        }
        std::thread::sleep(interval);
    }
}

/// An open ledger file. Appends are serialized and durable on return. While
/// the value lives, an exclusive lock on `<ledger path>.lock` keeps another
/// process from opening the same ledger.
#[derive(Debug)]
pub struct DeletionLedger {
    path: PathBuf,
    file: Mutex<File>,
    dropped_tail_bytes: usize,
    /// Set when a failed append left bytes that could not be removed; later
    /// appends fail rather than write after them.
    unrepaired: AtomicBool,
    /// Holds the lock; closed with the ledger.
    _lock: Option<File>,
}

impl DeletionLedger {
    /// Opens (creating if absent) the ledger for appending. Before it reads or
    /// changes the ledger file it takes an exclusive lock on
    /// `<ledger path>.lock`, waiting up to 60 seconds (one try every 500 ms)
    /// when another process holds it, then fails with
    /// [`DeletionLedgerError::LockHeld`]. The file mode is
    /// forced to 0600. A final line that a crash left unterminated is kept if
    /// it is a whole record and otherwise dropped: a record is acted on only
    /// after its append returned, so an unterminated partial line was never
    /// followed by a commit. The file and its directory are fsynced before
    /// this returns.
    pub fn open(path: &Path) -> Result<Self, DeletionLedgerError> {
        Self::open_waiting(path, LOCK_RETRY_INTERVAL, LOCK_WAIT_LIMIT)
    }

    /// [`DeletionLedger::open`] with the lock retry interval and limit given.
    pub(super) fn open_waiting(
        path: &Path,
        lock_interval: Duration,
        lock_limit: Duration,
    ) -> Result<Self, DeletionLedgerError> {
        validate_path(path).map_err(DeletionLedgerError::Path)?;
        let lock = acquire_lock(path, lock_interval, lock_limit)?;
        // Left by a prune that stopped before its rename took effect: the
        // ledger path names a whole file either way.
        remove_if_present(&prune_temp_path(path))?;
        let mut file = open_ledger_file(path, true)?;
        let dropped_tail_bytes = repair_tail(&mut file)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            dropped_tail_bytes,
            unrepaired: AtomicBool::new(false),
            _lock: Some(lock),
        })
    }

    /// A ledger over an already opened file, to exercise write failures.
    #[cfg(test)]
    pub(super) fn from_file(path: &Path, file: File) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            dropped_tail_bytes: 0,
            unrepaired: AtomicBool::new(false),
            _lock: None,
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
    /// file at the ledger path. If the write or the fsync fails, the file is
    /// cut back to its length before the call, so a partial line is never
    /// followed by another. Blocking; async callers use
    /// [`DeletionLedger::append_async`].
    pub fn append(&self, record: &Record) -> Result<(), DeletionLedgerError> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        self.append_line(&line, |file, bytes| file.write_all(bytes))
    }

    /// [`DeletionLedger::append`] with the write step supplied by the caller.
    pub(super) fn append_line(
        &self,
        line: &[u8],
        write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), DeletionLedgerError> {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.check_not_moved(&file)?;
        self.refuse_if_unrepaired()?;
        let length_before = file.metadata()?.len();
        if let Err(error) = write(&mut file, line).and_then(|()| file.sync_all()) {
            let unchanged = file
                .metadata()
                .is_ok_and(|metadata| metadata.len() == length_before);
            if !unchanged
                && file
                    .set_len(length_before)
                    .and_then(|()| file.sync_all())
                    .is_err()
            {
                self.unrepaired.store(true, Ordering::SeqCst);
                ::tracing::error!(
                    event = "deletion_ledger_unrepaired",
                    "a failed ledger append left bytes that could not be removed: later appends fail"
                );
            }
            return Err(error.into());
        }
        Ok(())
    }

    fn refuse_if_unrepaired(&self) -> Result<(), DeletionLedgerError> {
        if self.unrepaired.load(Ordering::SeqCst) {
            return Err(std::io::Error::other(
                "an earlier failed append left bytes in the ledger that could not be removed",
            )
            .into());
        }
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

    /// Removes every SETTLED operation (an intent that a `committed` or
    /// `aborted` line names) whose network belongs to one of `owners`,
    /// together with the lines that settle it. `owners` are canonical DIDs, as
    /// [`NetworkId::owner_did`] gives them. An open operation is kept and
    /// counted as `skipped_open`. Every other line is kept byte for byte and
    /// in order. Which owners may be pruned is the caller's decision.
    ///
    /// It holds the append mutex throughout (the ledger lock is held while
    /// the ledger is open), writes the kept lines to `<ledger path>.prune.tmp`
    /// with mode 0600 and fsyncs it, renames it over the ledger, fsyncs the
    /// directory and reopens the append handle on the new file. A crash at
    /// any point leaves the ledger path naming the old file or the new one,
    /// each whole, and the next [`DeletionLedger::open`] removes a leftover
    /// temporary file. When nothing is removed the file is not rewritten. If
    /// the directory fsync or the reopen fails, the handle still names the
    /// replaced file, so later appends fail as [`DeletionLedgerError::Moved`]
    /// until the ledger is opened again. Blocking.
    pub fn prune_owners(
        &self,
        owners: &BTreeSet<String>,
    ) -> Result<PruneReport, DeletionLedgerError> {
        self.prune_owners_at(owners, |_| Ok(()))
    }

    /// [`DeletionLedger::prune_owners`], calling `at` at each [`PrunePoint`].
    /// An error from `at` stops the prune there as a crash would: nothing is
    /// cleaned up and the handle is not reopened.
    pub(super) fn prune_owners_at(
        &self,
        owners: &BTreeSet<String>,
        mut at: impl FnMut(PrunePoint) -> std::io::Result<()>,
    ) -> Result<PruneReport, DeletionLedgerError> {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.check_not_moved(&file)?;
        self.refuse_if_unrepaired()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (kept, report) = prune_lines(&bytes, owners)?;
        if report.pruned_lines == 0 {
            return Ok(report);
        }
        let temp = prune_temp_path(&self.path);
        if let Err(error) = write_prune_temp(&temp, &kept) {
            let _ = std::fs::remove_file(&temp);
            return Err(error.into());
        }
        at(PrunePoint::TempWritten)?;
        if let Err(error) = std::fs::rename(&temp, &self.path) {
            let _ = std::fs::remove_file(&temp);
            return Err(error.into());
        }
        at(PrunePoint::Renamed)?;
        sync_parent(&self.path)?;
        *file = open_ledger_file(&self.path, false)?;
        Ok(report)
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

/// Steps of [`DeletionLedger::prune_owners`] at which a test can stop it as a
/// crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrunePoint {
    /// The temporary file is written and fsynced; the ledger is untouched.
    TempWritten,
    /// The temporary file has been renamed over the ledger.
    Renamed,
}

/// Result of [`DeletionLedger::prune_owners`]: counts only, never a DID or an
/// operation.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneReport {
    /// Settled operations of the given owners that were removed.
    pub pruned_operations: usize,
    /// Lines removed: those operations and the lines that settled them.
    pub pruned_lines: usize,
    /// Operations of the given owners that are still open: kept.
    pub skipped_open: usize,
    /// Lines left in the file.
    pub kept_lines: usize,
}

/// The bytes [`DeletionLedger::prune_owners`] keeps, and its counts. A file
/// that does not end in a newline or holds a line that is not a record is
/// refused: `open` and failed appends never leave either.
fn prune_lines(
    bytes: &[u8],
    owners: &BTreeSet<String>,
) -> Result<(Vec<u8>, PruneReport), DeletionLedgerError> {
    let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
    if bytes.last().is_some_and(|last| *last != b'\n') {
        return Err(DeletionLedgerError::Malformed(lines.len()));
    }
    let records = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if line.iter().all(u8::is_ascii_whitespace) {
                return Ok(None);
            }
            serde_json::from_slice::<Record>(line)
                .map(Some)
                .map_err(|_| DeletionLedgerError::Malformed(index + 1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    fn settling_op(record: &Option<Record>) -> Option<&str> {
        match record {
            Some(Record::Committed(Committed { committed })) => Some(committed.as_str()),
            Some(Record::Aborted(Aborted { aborted })) => Some(aborted.as_str()),
            _ => None,
        }
    }
    let settled: HashSet<&str> = records.iter().filter_map(settling_op).collect();
    let mut report = PruneReport::default();
    let mut dropped = vec![false; lines.len()];
    let mut dropped_ops = HashSet::new();
    let mut kept_ops = HashSet::new();
    for (index, record) in records.iter().enumerate() {
        let Some(Record::Intent(intent)) = record else {
            continue;
        };
        let listed = intent
            .network_id
            .parse::<NetworkId>()
            .is_ok_and(|network| owners.contains(network.owner_did()));
        if listed && settled.contains(intent.op.as_str()) {
            dropped[index] = true;
            dropped_ops.insert(intent.op.as_str());
            report.pruned_operations += 1;
        } else {
            report.skipped_open += usize::from(listed);
            kept_ops.insert(intent.op.as_str());
        }
    }
    for (index, record) in records.iter().enumerate() {
        // A settling line stays while any intent it names stays.
        if let Some(op) = settling_op(record) {
            dropped[index] = dropped_ops.contains(op) && !kept_ops.contains(op);
        }
    }
    let mut kept = Vec::with_capacity(bytes.len());
    for (line, drop_line) in lines.iter().zip(dropped) {
        if drop_line {
            report.pruned_lines += 1;
        } else {
            kept.extend_from_slice(line);
            report.kept_lines += 1;
        }
    }
    Ok((kept, report))
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
