//! The threshold-member key record on the share volume and its file discipline.
//!
//! Layout: `<share dir>/member/<network-hash>/key`, mode 0600, in directories of
//! mode 0700. The record is
//! `version(u8) || u32be(len(U)) || U || u32be(len(app_id)) || app_id ||
//! u32be(len(instance_id)) || instance_id || seed(32)`, where `U` is the
//! canonical network URN and `app_id`/`instance_id` are the strings dstack
//! `/Info` returned when the key was generated. Nothing may follow the seed.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{LocalIdentity, MemberKeyError, MAX_IDENTITY_FIELD_BYTES, MAX_URN_BYTES};

pub(super) const RECORD_VERSION: u8 = 1;
pub(super) const MEMBER_DIR: &str = "member";
pub(super) const KEY_FILE: &str = "key";
pub(super) const UNLINKED_FILE: &str = "unlinked";
const TEMP_PREFIX: &str = ".tmp-";

/// The directory name for network `urn`: lowercase hex of `SHA-256(U)`.
///
/// `U` is the canonical URN (`NetworkId`'s `Display`, which canonicalizes the
/// owner principal), so every accepted spelling of one network maps to one
/// directory. The digest has a fixed length and only `[0-9a-f]`, so no URN
/// character (`:` in DIDs, for one) reaches the filesystem. The record repeats
/// `U`, and a load compares it, so a digest collision can't mix networks.
pub fn network_dir_name(urn: &str) -> String {
    hex::encode(Sha256::digest(urn.as_bytes()))
}

pub(super) fn network_dir(root: &Path, urn: &str) -> PathBuf {
    root.join(MEMBER_DIR).join(network_dir_name(urn))
}

/// A decoded key record. The seed is wiped when the record drops.
pub(super) struct KeyRecord {
    pub(super) network: String,
    pub(super) identity: LocalIdentity,
    pub(super) seed: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("network", &self.network)
            .field("identity", &self.identity)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl KeyRecord {
    /// A record with a fresh seed from the OS CSPRNG.
    pub(super) fn generate(network: &str, identity: &LocalIdentity) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self {
            network: network.to_owned(),
            identity: identity.clone(),
            seed,
        }
    }

    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let fields = [
            self.network.as_bytes(),
            self.identity.app_id.as_bytes(),
            self.identity.instance_id.as_bytes(),
        ];
        let len = 1 + fields.iter().map(|f| 4 + f.len()).sum::<usize>() + 32;
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.push(RECORD_VERSION);
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(self.seed.as_ref());
        out
    }

    /// Strict decode: known version, bounded non-empty UTF-8 fields, a
    /// canonical URN, exactly 32 seed bytes and nothing after them.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, MemberKeyError> {
        let mut rest = bytes;
        let (&version, tail) = rest
            .split_first()
            .ok_or(MemberKeyError::MalformedRecord("empty"))?;
        if version != RECORD_VERSION {
            return Err(MemberKeyError::MalformedRecord("unknown version"));
        }
        rest = tail;
        let network = take_field(&mut rest, MAX_URN_BYTES)?;
        if !super::is_canonical_urn(&network) {
            return Err(MemberKeyError::MalformedRecord("noncanonical network"));
        }
        let app_id = take_field(&mut rest, MAX_IDENTITY_FIELD_BYTES)?;
        let instance_id = take_field(&mut rest, MAX_IDENTITY_FIELD_BYTES)?;
        let seed: [u8; 32] = rest
            .try_into()
            .map_err(|_| MemberKeyError::MalformedRecord("seed length"))?;
        Ok(Self {
            network,
            identity: LocalIdentity {
                app_id,
                instance_id,
            },
            seed: Zeroizing::new(seed),
        })
    }
}

fn take_field(rest: &mut &[u8], cap: usize) -> Result<String, MemberKeyError> {
    if rest.len() < 4 {
        return Err(MemberKeyError::MalformedRecord("truncated"));
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if len == 0 || len > cap || rest.len() - 4 < len {
        return Err(MemberKeyError::MalformedRecord("field length"));
    }
    let field = std::str::from_utf8(&rest[4..4 + len])
        .map_err(|_| MemberKeyError::MalformedRecord("field encoding"))?
        .to_owned();
    *rest = &rest[4 + len..];
    Ok(field)
}

/// Create `dir`, which is `<share root>/member/<network hash>`, below an
/// existing share root. The root is never created, so a key can't land off
/// the share volume when it isn't mounted: a missing root is refused. Each
/// missing level is created alone with mode 0700, and its parent fsynced.
pub(super) fn ensure_dir(dir: &Path) -> Result<(), MemberKeyError> {
    let member = dir
        .parent()
        .ok_or(MemberKeyError::MalformedRecord("record path"))?;
    let root = member
        .parent()
        .ok_or(MemberKeyError::MalformedRecord("record path"))?;
    match fs::metadata(root) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(MemberKeyError::ShareDirMissing),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(MemberKeyError::ShareDirMissing)
        }
        Err(error) => return Err(error.into()),
    }
    create_level(root, member)?;
    create_level(member, dir)
}

/// Create `dir` in `parent` unless it exists, then fsync `parent`.
fn create_level(parent: &Path, dir: &Path) -> Result<(), MemberKeyError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => sync_dir(parent),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn sync_dir(dir: &Path) -> Result<(), MemberKeyError> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn temp_path(dir: &Path, name: &str) -> PathBuf {
    let mut tag = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut tag);
    dir.join(format!("{name}{TEMP_PREFIX}{}", hex::encode(tag)))
}

/// Write `bytes` to a new exclusive temp file of mode 0600 in `dir` and fsync it.
fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, MemberKeyError> {
    let path = temp_path(dir, name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = written {
        let _ = zero_and_remove(&path);
        return Err(error.into());
    }
    Ok(path)
}

/// Read the record at `path` without following a symlink. `Ok(None)` when no
/// record exists.
pub(super) fn read_record(path: &Path) -> Result<Option<KeyRecord>, MemberKeyError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(MemberKeyError::MalformedRecord("not a regular file"))
        }
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(MemberKeyError::MalformedRecord("not a regular file"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    KeyRecord::decode(&bytes).map(Some)
}

/// Install `candidate` as `<dir>/key` unless a record is already there, and
/// return the record that is installed afterwards.
///
/// Single winner: the record is written to an exclusive temp file and fsynced,
/// then `link(2)`ed to `key`. `link` never replaces an existing name, so of
/// any number of concurrent installers exactly one creates `key`; every other
/// one gets `EEXIST`, wipes its candidate and loads the winner. The directory
/// is fsynced before the record is returned, so a returned key is durable.
pub(super) fn install_or_load(
    dir: &Path,
    candidate: KeyRecord,
) -> Result<KeyRecord, MemberKeyError> {
    ensure_dir(dir)?;
    let key = dir.join(KEY_FILE);
    if let Some(existing) = read_record(&key)? {
        return Ok(existing);
    }
    let temp = write_temp(dir, KEY_FILE, &candidate.encode())?;
    match fs::hard_link(&temp, &key) {
        Ok(()) => {
            // `temp` and `key` now share one inode: unlink the temp name
            // only, never overwrite it.
            fs::remove_file(&temp)?;
            sync_dir(dir)?;
            Ok(candidate)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            // Another installer won; wipe this candidate and load the winner.
            zero_and_remove(&temp)?;
            drop(candidate);
            sync_dir(dir)?;
            read_record(&key)?.ok_or(MemberKeyError::MalformedRecord("vanished during install"))
        }
        Err(error) => {
            zero_and_remove(&temp)?;
            Err(error.into())
        }
    }
}

/// Overwrite `path` with zeros, fsync it, then unlink it.
fn zero_and_remove(path: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let len = file.metadata()?.len() as usize;
    file.write_all(&vec![0u8; len])?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)
}

/// Zero-overwrite and unlink every temp key record in `dir`, then fsync `dir`
/// if anything was removed. Returns how many were removed.
///
/// A temp record holds a seed until `install_or_load` unlinks it, so a crash
/// in between leaves one behind. Call only while no install into `dir` can be
/// in flight: every install runs under `MemberKeys`'s generate lock, so any
/// temp record seen while holding it is a leftover.
pub(super) fn sweep_temp_records(dir: &Path) -> Result<usize, MemberKeyError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let prefix = format!("{KEY_FILE}{TEMP_PREFIX}");
    let mut swept = 0;
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            zero_and_remove(&entry.path())?;
            swept += 1;
        }
    }
    if swept > 0 {
        sync_dir(dir)?;
    }
    Ok(swept)
}

/// Logical unlink of the key in `dir` (D7.4 steps 2-3): zero-overwrite and
/// fsync the record and any leftover temp record, unlink them, fsync `dir`.
/// On a copy-on-write filesystem the overwrite writes new blocks; the old
/// ones are not destroyed.
pub(super) fn unlink_key(dir: &Path) -> Result<(), MemberKeyError> {
    zero_and_remove(&dir.join(KEY_FILE))?;
    sweep_temp_records(dir)?;
    sync_dir(dir)
}

/// Durably replace `<dir>/unlinked` with `bytes` (temp, fsync, rename, fsync dir).
pub(super) fn write_unlinked_record(dir: &Path, bytes: &[u8]) -> Result<(), MemberKeyError> {
    let temp = write_temp(dir, UNLINKED_FILE, bytes)?;
    fs::rename(&temp, dir.join(UNLINKED_FILE))?;
    sync_dir(dir)
}
