//! Durable share store: candidate persistence, activation pin and retirement.
//! Details: TC-2221
//!
//! A member keeps at most one generation current, at most one candidate
//! awaiting activation, and positive-proof records for everything it erased.
//! Nothing in the workspace calls this module yet; the node runtime wires it
//! in a later slice.
//!
//! Layout under `<dir>/<network-hash>/`:
//!
//! * `lock`: advisory exclusive lock held for the store's lifetime; exactly
//!   one `ShareStore` may be open for a network at a time.
//! * `state`: versioned record of the pinned certificate, the pending
//!   candidate, accepted ceremony ids and retired generations.
//! * `proofs/<cert-digest>`: the signed certificate bytes plus, once
//!   activated, the owner activation statement and readiness receipts.
//! * `share-<cert-digest>`: `CandidateShare::to_bytes()` for this member's
//!   share under that certificate.
//! * `dealt/<ceremony-id>`: marker written once a ceremony id is consumed;
//!   the id is never fresh again.
//!
//! Every write is write-temp, fsync, rename, fsync-directory, and temporary
//! files are uniquely named, created with `create_new`, and zeroed plus
//! unlinked on any failure; the next open sweeps leftovers and refuses to
//! open if one cannot be removed. The pin is the highest certificate on
//! the single chain verified from genesis through `verify_activation` for
//! every activated proof; a restart refuses a recorded `state` pin the
//! proofs cannot support. Shares are erased only on positive proof — a
//! verified activation that moves past them, a fresh ceremony for their
//! predecessor, or no record at all — and the `state` record commits every
//! removal before its file unlink, so a crash is always recovered as
//! "erasure owed", never as a missing promised share.
//!
//! Filesystem prerequisite: the network directory must live on a
//! filesystem where `File::try_lock` provides an exclusive advisory lock
//! (local POSIX filesystems; network filesystems such as NFS are not
//! supported — an implementation that cannot lock yields
//! [`StoreError::LockUnsupported`], never `Busy`).
//!
//! Frozen-store recovery: activated equivocation freezes the store
//! durably — the fork's activated proof is persisted and the freeze
//! survives restarts. Recovery is operator-only, never automatic: the
//! operator audits the equivocation evidence in `proofs/`, removes the
//! network directory for the branch to abandon (the whole `<network-hash>`
//! directory is self-contained), and provisions a fresh ceremony and
//! directory for the retained chain. The store itself never selects a
//! branch or resumes service.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    activation::{verify_activation, ReadinessReceipt, ReadyQuorum},
    ceremony::{AuthorizedCeremony, DidSignatureVerifier, SignedStatement, TrustAnchor},
    cert::{
        verify_certificate, verify_successor, CandidateShare, CertificateBody, SignedCertificate,
        VerifiedCertificate,
    },
    encoding::{Decoder, Encoder},
    error::{CertError, Error},
    ids::{CeremonyId, CertDigest, Did, MemberIndex, NetworkUrn},
    KeyShare,
};

/// One retired generation. The predecessor it was retired against decides
/// reachability: only a digest naming the CURRENT pin as its predecessor
/// can ever be presented again, so records keyed to superseded pins are
/// pruned on every pin advance. Details: TC-2221
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredGeneration {
    /// Retired certificate digest.
    pub digest: CertDigest,
    /// The certificate this retired generation descended from — `None` for
    /// a genesis root.
    pub predecessor: Option<CertDigest>,
    /// Retirement sequence counter for this member.
    pub erased_at: u64,
}

/// Hard bounds on the durable lists: the store REFUSES the operation that
/// would cross them rather than letting `state` grow past what a reopen
/// can parse. Details: TC-2221
const MAX_RETIRED: usize = 65_536;
const MAX_SEEN_CEREMONIES: usize = 65_536;

/// The pending candidate record.
#[derive(Clone, Debug)]
struct CandidateRecord {
    digest: CertDigest,
    ceremony: CeremonyId,
    predecessor: Option<CertDigest>,
    receipt_sent: bool,
}

/// The single ceremony admissible for installation: the most recently
/// accepted fresh id and the predecessor it was bound to. A superseded or
/// retired id stays in `seen_ceremonies` (history) but can never install.
#[derive(Clone, Debug)]
struct ActiveCeremony {
    id: CeremonyId,
    predecessor: Option<CertDigest>,
}

#[derive(Clone, Debug, Default)]
struct State {
    pin: Option<CertDigest>,
    candidate: Option<CandidateRecord>,
    active_ceremony: Option<ActiveCeremony>,
    seen_ceremonies: Vec<CeremonyId>,
    retired: Vec<RetiredGeneration>,
    seq: u64,
}

fn encode_state(state: &State) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u8(3);
    e.u8(u8::from(state.pin.is_some()));
    if let Some(pin) = state.pin {
        e.fixed(pin.as_bytes());
    }
    e.u8(u8::from(state.candidate.is_some()));
    if let Some(candidate) = &state.candidate {
        e.fixed(candidate.digest.as_bytes());
        e.fixed(candidate.ceremony.as_bytes());
        e.u8(u8::from(candidate.predecessor.is_some()));
        if let Some(predecessor) = candidate.predecessor {
            e.fixed(predecessor.as_bytes());
        }
        e.u8(u8::from(candidate.receipt_sent));
    }
    e.u8(u8::from(state.active_ceremony.is_some()));
    if let Some(active) = &state.active_ceremony {
        e.fixed(active.id.as_bytes());
        e.u8(u8::from(active.predecessor.is_some()));
        if let Some(predecessor) = active.predecessor {
            e.fixed(predecessor.as_bytes());
        }
    }
    // Ceremony ids and retired entries are bounded by the write caps; u32
    // cannot overflow below memory limits.
    e.u32(state.seen_ceremonies.len() as u32);
    for id in &state.seen_ceremonies {
        e.fixed(id.as_bytes());
    }
    e.u32(state.retired.len() as u32);
    for retired in &state.retired {
        e.fixed(retired.digest.as_bytes());
        e.u8(u8::from(retired.predecessor.is_some()));
        if let Some(predecessor) = retired.predecessor {
            e.fixed(predecessor.as_bytes());
        }
        e.u64(retired.erased_at);
    }
    e.u64(state.seq);
    e.finish()
}

fn decode_state(bytes: &[u8]) -> Result<State, StoreError> {
    let mut d = Decoder::new(bytes)?;
    if d.u8()? != 3 {
        return Err(Error::InvalidEncoding.into());
    }
    let pin = if d.u8()? == 1 {
        Some(CertDigest::new(d.fixed()?))
    } else {
        None
    };
    let candidate = if d.u8()? == 1 {
        Some(CandidateRecord {
            digest: CertDigest::new(d.fixed()?),
            ceremony: CeremonyId::new(d.fixed()?),
            predecessor: if d.u8()? == 1 {
                Some(CertDigest::new(d.fixed()?))
            } else {
                None
            },
            receipt_sent: d.u8()? == 1,
        })
    } else {
        None
    };
    let active_ceremony = if d.u8()? == 1 {
        Some(ActiveCeremony {
            id: CeremonyId::new(d.fixed()?),
            predecessor: if d.u8()? == 1 {
                Some(CertDigest::new(d.fixed()?))
            } else {
                None
            },
        })
    } else {
        None
    };
    let seen_len = usize::try_from(d.u32()?).map_err(|_| Error::InvalidEncoding)?;
    if seen_len > 1_000_000 {
        return Err(Error::InvalidEncoding.into());
    }
    let mut seen_ceremonies = Vec::with_capacity(seen_len.min(4096));
    for _ in 0..seen_len {
        seen_ceremonies.push(CeremonyId::new(d.fixed()?));
    }
    let retired_len = usize::try_from(d.u32()?).map_err(|_| Error::InvalidEncoding)?;
    if retired_len > 1_000_000 {
        return Err(Error::InvalidEncoding.into());
    }
    let mut retired = Vec::with_capacity(retired_len.min(4096));
    for _ in 0..retired_len {
        retired.push(RetiredGeneration {
            digest: CertDigest::new(d.fixed()?),
            predecessor: if d.u8()? == 1 {
                Some(CertDigest::new(d.fixed()?))
            } else {
                None
            },
            erased_at: d.u64()?,
        });
    }
    let seq = d.u64()?;
    d.finish()?;
    Ok(State {
        pin,
        candidate,
        active_ceremony,
        seen_ceremonies,
        retired,
        seq,
    })
}

fn encode_signed_certificate(signed: &SignedCertificate) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u8(1);
    e.lp(&signed.body.encode());
    e.lp(&signed.owner_signature);
    e.finish()
}

fn decode_signed_certificate(bytes: &[u8]) -> Result<SignedCertificate, StoreError> {
    let mut d = Decoder::new(bytes)?;
    if d.u8()? != 1 {
        return Err(Error::InvalidEncoding.into());
    }
    let body = CertificateBody::decode(d.lp(64 * 1024)?)?;
    let owner_signature = d.lp(512)?.to_vec();
    d.finish()?;
    Ok(SignedCertificate {
        body,
        owner_signature,
    })
}

fn encode_proof(
    signed: &SignedCertificate,
    activation: Option<&SignedStatement>,
    receipts: &[ReadinessReceipt],
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u8(1);
    e.lp(&encode_signed_certificate(signed));
    e.u8(u8::from(activation.is_some()));
    if let Some(activation) = activation {
        e.lp(&activation.bytes);
        e.lp(&activation.signature);
        // Receipts are bounded by n <= 16 members.
        e.u16(receipts.len() as u16);
        for receipt in receipts {
            e.u16(receipt.index.get());
            e.lp(&receipt.signature);
        }
    }
    e.finish()
}

/// An activated proof's owner statement and member receipts. Details: TC-2221
type ProofActivation = (SignedStatement, Vec<ReadinessReceipt>);

fn decode_proof(bytes: &[u8]) -> Result<(SignedCertificate, Option<ProofActivation>), StoreError> {
    let mut d = Decoder::new(bytes)?;
    if d.u8()? != 1 {
        return Err(Error::InvalidEncoding.into());
    }
    let signed = decode_signed_certificate(d.lp(128 * 1024)?)?;
    let activation = if d.u8()? == 1 {
        let statement = SignedStatement {
            bytes: d.lp(64 * 1024)?.to_vec(),
            signature: d.lp(512)?.to_vec(),
        };
        let count = usize::from(d.u16()?);
        if count > 16 {
            return Err(Error::InvalidEncoding.into());
        }
        let mut receipts = Vec::with_capacity(count);
        for _ in 0..count {
            receipts.push(ReadinessReceipt {
                index: MemberIndex::new(d.u16()?)?,
                signature: d.lp(512)?.to_vec(),
            });
        }
        Some((statement, receipts))
    } else {
        None
    };
    d.finish()?;
    Ok((signed, activation))
}

/// Store errors. Details: TC-2221
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Filesystem failure.
    #[error("share store I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Threshold encoding/verification failure.
    #[error("{0}")]
    Crypto(#[from] Error),
    /// Certificate verification failure.
    #[error("{0}")]
    Cert(#[from] CertError),
    /// On-disk content failed to decode or a recorded promise lacks proof.
    #[error("share store state is inconsistent")]
    Corrupt,
    /// A second candidate exists before the first was erased.
    #[error("candidate already installed")]
    CandidateExists,
    /// The certificate does not extend the pin, or a genesis arrives after one.
    #[error("activation does not extend the pinned certificate")]
    InvalidActivation,
    /// A durable list reached its bound; the operation is refused rather
    /// than letting `state` grow past what a reopen can parse.
    #[error("share store durable list is at capacity")]
    Capacity,
    /// Activated equivocation froze the pin; further activations are refused.
    #[error("activated equivocation froze the pin")]
    Equivocation,
    /// Another `ShareStore` already holds this network's lock.
    #[error("share store is already open for this network")]
    Busy,
    /// The certificate belongs to a retired generation; its share was erased
    /// under durable proof and must never come back.
    #[error("certificate belongs to a retired generation")]
    Retired,
    /// The filesystem cannot provide the exclusive open lock.
    #[error("share store lock unsupported on this filesystem")]
    LockUnsupported,
}

/// Result of presenting an authorized ceremony to the store. Details: TC-2221
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptOutcome {
    /// First sight of this ceremony id: dealt marker written, id consumed,
    /// and any unactivated candidate for its predecessor erased.
    Fresh,
    /// Ceremony id already consumed; nothing changed.
    Replay,
}

/// One member's durable share store for one network. Details: TC-2221
///
/// `member` is this node's DID; a ceremony is accepted only when it names
/// this member among its recipients. `open` holds an exclusive advisory
/// lock on the network directory for the store's lifetime, so two openers
/// — same process or sibling processes — can never cache divergent state.
pub struct ShareStore {
    network_dir: PathBuf,
    anchor: TrustAnchor,
    member: Did,
    _lock: fs::File,
    inner: Mutex<Inner>,
}

struct Inner {
    state: State,
    pin: Option<VerifiedCertificate>,
    /// Every certificate on the verified activated chain, by digest.
    verified: BTreeMap<CertDigest, VerifiedCertificate>,
    equivocation: bool,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    use std::io::Write;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tag = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!(
        "{}.tmp-{}-{tag}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("part"),
        std::process::id()
    );
    let tmp = path.with_file_name(name);
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        // The temp may hold plaintext secret bytes: zero before unlinking.
        let _ = erase_share_file(&tmp);
    }
    result
}

fn erase_share_file(path: &Path) -> Result<(), StoreError> {
    // Never follow links or traverse directories: a store path that is not a
    // regular file is removed as a bare name, never written through — a
    // `*.tmp-*` symlink can otherwise make `open` zero a victim file
    // outside the store.
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !meta.is_file() {
        if meta.is_dir() {
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        return Ok(());
    }
    let length = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    // Zeroing writes through the inode: a name with more than one link —
    // or one that stops being a regular file between metadata and open —
    // must be dropped as a bare name, never overwritten. O_NOFOLLOW keeps
    // that check atomic with the open.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if meta.nlink() > 1 {
            fs::remove_file(path)?;
            if let Some(parent) = path.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
            return Ok(());
        }
        use std::io::Write;
        const O_NOFOLLOW: i32 = 0x20000;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)?;
        file.write_all(&Zeroizing::new(vec![0u8; length]))?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.write_all(&Zeroizing::new(vec![0u8; length]))?;
        file.sync_all()?;
    }
    fs::remove_file(path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn share_path(dir: &Path, digest: &CertDigest) -> PathBuf {
    dir.join(format!("share-{}", hex(digest.as_bytes())))
}

fn proof_path(dir: &Path, digest: &CertDigest) -> PathBuf {
    dir.join("proofs").join(hex(digest.as_bytes()))
}

/// Record a retirement durably before its unlink: the entry carries the
/// certificate the retired generation descended from, which is the only
/// pin context under which the digest can ever be presented again.
/// Details: TC-2221
fn record_retired(state: &mut State, digest: CertDigest, predecessor: Option<CertDigest>) {
    state.seq = state.seq.saturating_add(1);
    state.retired.push(RetiredGeneration {
        digest,
        predecessor,
        erased_at: state.seq,
    });
}

/// Compact the retirement list only when it nears the bound: an entry is
/// reachable — and therefore must be kept — only while the pin equals its
/// recorded predecessor; dead entries are dropped first. Reachable entries
/// are never dropped: if the list still overflows, the operation must be
/// refused instead of resurrecting a retired share. Details: TC-2221
fn compact_retired(state: &mut State, pin: Option<CertDigest>) -> bool {
    if state.retired.len() <= MAX_RETIRED {
        return true;
    }
    state.retired.retain(|r| r.predecessor == pin);
    state.retired.len() <= MAX_RETIRED
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        if let Some(hi) = HEX.get(usize::from(byte >> 4)) {
            out.push(*hi as char);
        }
        if let Some(lo) = HEX.get(usize::from(byte & 0x0f)) {
            out.push(*lo as char);
        }
    }
    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => byte.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

fn decode_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = text.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(*bytes.get(i.saturating_mul(2))?)?;
        let lo = hex_val(*bytes.get(i.saturating_mul(2).saturating_add(1))?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn store_dir(dir: &Path, network: &NetworkUrn) -> PathBuf {
    let digest = Sha256::digest(network.as_bytes());
    let name = hex(digest.get(..16).unwrap_or_default());
    dir.join(name)
}

/// Zero and unlink any leftover `*.tmp-*` or `*.tmp` write-temp file under
/// the network directory. Runs inside `open` after the lock is taken; a
/// temp that cannot be removed (it may hold plaintext secret bytes) refuses
/// the open rather than surviving silently.
fn sweep_temps(network_dir: &Path) -> Result<(), StoreError> {
    for sub in [
        network_dir.to_path_buf(),
        network_dir.join("proofs"),
        network_dir.join("dealt"),
    ] {
        for entry in fs::read_dir(&sub)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(".tmp") || name.contains(".tmp-") {
                erase_share_file(&entry.path())?;
            }
        }
    }
    Ok(())
}

impl ShareStore {
    /// Open or create the member's share directory and converge it. Details: TC-2221
    ///
    /// Convergence order: rebuild the verified activated chain from `proofs/`,
    /// refuse a recorded pin the chain cannot prove, then apply the erase
    /// rules — R1 (superseded generations), C2 (losing candidates), S1
    /// (files named in no record) and orphan dealt markers.
    pub fn open(
        dir: &Path,
        network: &NetworkUrn,
        anchor: TrustAnchor,
        member: Did,
        v: &impl DidSignatureVerifier,
    ) -> Result<Self, StoreError> {
        let network_dir = store_dir(dir, network);
        // Fsync only what this call created — network_dir, proofs, dealt,
        // and the first pre-existing parent that must record them. Ancestors
        // above that belong to the caller; an execute-only one must not be
        // required readable.
        let existed = network_dir.exists();
        fs::create_dir_all(network_dir.join("proofs"))?;
        fs::create_dir_all(network_dir.join("dealt"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&network_dir, fs::Permissions::from_mode(0o700))?;
        }
        fs::File::open(&network_dir)?.sync_all()?;
        fs::File::open(network_dir.join("proofs"))?.sync_all()?;
        fs::File::open(network_dir.join("dealt"))?.sync_all()?;
        if !existed {
            if let Some(parent) = network_dir.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
        }

        // One opener per network directory, held for the store's lifetime.
        let lock_path = network_dir.join("lock");
        let lock_file = {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&lock_path)?
        };
        // A held contender is Busy; an implementation that cannot lock at
        // all (an unsupported filesystem) is a distinct refusal: the store
        // will not run where the single-opener guarantee cannot be made.
        lock_file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => StoreError::Busy,
            std::fs::TryLockError::Error(_) => StoreError::LockUnsupported,
        })?;

        sweep_temps(&network_dir)?;

        let mut state = match fs::read(network_dir.join("state")) {
            Ok(bytes) => decode_state(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        let mut state_dirty = false;

        // Orphan dealt markers: a marker whose id was never recorded consumed
        // the id anyway, so a retried authorization is never "new".
        for entry in fs::read_dir(network_dir.join("dealt"))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == "state" || name.len() != 64 {
                continue;
            }
            let Some(id_bytes) = decode_hex(name) else {
                continue;
            };
            let id = CeremonyId::new(id_bytes);
            if !state.seen_ceremonies.contains(&id) {
                state.seen_ceremonies.push(id);
                state_dirty = true;
            }
        }

        // Load every proof; a malformed file is corruption, never skipped.
        let mut proofs: BTreeMap<CertDigest, SignedCertificate> = BTreeMap::new();
        let mut activations: BTreeMap<CertDigest, (SignedStatement, Vec<ReadinessReceipt>)> =
            BTreeMap::new();
        for entry in fs::read_dir(network_dir.join("proofs"))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(".tmp") || name.contains(".tmp-") {
                continue;
            }
            let (signed, activation) = decode_proof(&fs::read(entry.path())?)?;
            let digest = signed.body.digest();
            if hex(digest.as_bytes()) != name {
                return Err(StoreError::Corrupt);
            }
            proofs.insert(digest, signed);
            if let Some((statement, receipts)) = activation {
                activations.insert(digest, (statement, receipts));
            }
        }

        // Build the activated chain from genesis forward. Two activated
        // successors of one certificate (or two activated geneses) freeze the
        // pin at the fork.
        let mut verified: BTreeMap<CertDigest, VerifiedCertificate> = BTreeMap::new();
        let mut chain: Vec<CertDigest> = Vec::new();
        let mut equivocation = false;
        // Every flagged activation is verified before it can extend the pin
        // or count toward a fork; an activation flag alone proves nothing.
        let mut geneses: Vec<VerifiedCertificate> = Vec::new();
        for signed in proofs.values() {
            let Some((statement, receipts)) = activations.get(&signed.body.digest()) else {
                continue;
            };
            if signed.body.previous().is_some() {
                continue;
            }
            let verified_cert = verify_certificate(&anchor, signed, v)?;
            verify_activation(
                &verified_cert,
                receipts,
                ReadyQuorum::AllHolders,
                statement,
                v,
            )?;
            geneses.push(verified_cert);
        }
        geneses.sort_by(|a, b| a.digest().as_bytes().cmp(b.digest().as_bytes()));
        if geneses.len() > 1 {
            equivocation = true;
        }
        for genesis in &geneses {
            verified.insert(genesis.digest(), genesis.clone());
        }
        if let Some(first) = geneses.into_iter().next() {
            let mut current = first;
            chain.push(current.digest());
            verified.insert(current.digest(), current.clone());
            loop {
                let mut successors: Vec<VerifiedCertificate> = Vec::new();
                for signed in proofs.values() {
                    if signed.body.previous() != Some(&current.digest()) {
                        continue;
                    }
                    let Some((statement, receipts)) = activations.get(&signed.body.digest()) else {
                        continue;
                    };
                    let next = verify_successor(&current, signed, v)?;
                    verify_activation(&next, receipts, ReadyQuorum::AllHolders, statement, v)?;
                    successors.push(next);
                }
                successors.sort_by(|a, b| a.digest().as_bytes().cmp(b.digest().as_bytes()));
                if successors.len() > 1 {
                    // The pin stops advancing at the fork; every verified fork
                    // child is retained so a recorded pin among them is
                    // proven (not corruption) and their shares retire.
                    equivocation = true;
                    for next in successors {
                        verified.insert(next.digest(), next);
                    }
                    break;
                }
                let Some(next) = successors.into_iter().next() else {
                    break;
                };
                verified.insert(next.digest(), next.clone());
                chain.push(next.digest());
                current = next;
            }
        }
        // Fixpoint: descendants of ANY verified activated certificate —
        // including descendants of a fork's losing branch — are verified
        // activated too. They cannot move the pin (the fork already froze
        // it) but they keep their recorded pin proven and their shares
        // retire by the same rules instead of reading as corruption.
        loop {
            let mut added = Vec::new();
            for signed in proofs.values() {
                let digest = signed.body.digest();
                if verified.contains_key(&digest) {
                    continue;
                }
                let Some(parent) = signed.body.previous().and_then(|p| verified.get(p)) else {
                    continue;
                };
                let Some((statement, receipts)) = activations.get(&digest) else {
                    continue;
                };
                let next = verify_successor(parent, signed, v)?;
                verify_activation(&next, receipts, ReadyQuorum::AllHolders, statement, v)?;
                added.push(next);
            }
            if added.is_empty() {
                break;
            }
            for next in added {
                verified.insert(next.digest(), next);
            }
        }

        let computed_pin = chain.last().copied();
        let pin = computed_pin.and_then(|d| verified.get(&d).cloned());

        // A recorded pin must be a verified activated certificate: either on
        // the surviving chain or an equivocated branch descendant. Anything
        // else is corruption.
        if let Some(recorded) = state.pin {
            if !verified.contains_key(&recorded) {
                return Err(StoreError::Corrupt);
            }
        }

        // The chain tip being a retired digest is a durable contradiction:
        // it means the member's usable share is precisely the one the
        // record erased (a never-activated candidate that later gained an
        // activated proof on disk — peer sync, operator restore). The live
        // path refuses the same certificate as `Retired`; reopening freezes
        // rather than letting R1 erase the still-live share underneath it.
        // Superseded pins mid-chain are normal history: every outgoing pin
        // keeps its proof and its retirement record.
        if !equivocation
            && computed_pin.is_some_and(|tip| state.retired.iter().any(|r| r.digest == tip))
        {
            equivocation = true;
        }

        // Candidate reconciliation and R1/C2/S1 erasure run ONLY on an
        // unequivocal chain. Once activated equivocation is on disk the
        // store freezes in place: the recorded verified pin stands, every
        // share file is kept (losing nothing is the whole point of the
        // freeze), and only the operator's recovery path rewrites it.
        if !equivocation {
            // The pin's share is this member's live key material: durable
            // proof says it was installed and never retired, so its absence
            // is disk damage the store must not guess past.
            if let Some(pin) = computed_pin {
                let holds_member = verified
                    .get(&pin)
                    .map(|c| c.body().members().iter().any(|m| m.node == member))
                    .unwrap_or(false);
                if holds_member && !share_path(&network_dir, &pin).exists() {
                    return Err(StoreError::Corrupt);
                }
            }

            // Candidate reconciliation. Chain membership and C2 losses are
            // judged BEFORE the missing-file check: a candidate already
            // retired by durable proof is settled even when its share is
            // gone, while a still-live receipt-bearing candidate that lost
            // its share is the only case that is truly corrupt.
            let mut owed_erasures: Vec<PathBuf> = Vec::new();
            if let Some(candidate) = state.candidate.clone() {
                let share = share_path(&network_dir, &candidate.digest);
                let proof = proof_path(&network_dir, &candidate.digest);
                if chain.contains(&candidate.digest) {
                    // Already activated before the crash; the chain is the
                    // record.
                    state.candidate = None;
                    state_dirty = true;
                } else {
                    // C2: the candidate lost if its predecessor is covered
                    // by the pin (any pin for a genesis predecessor) or the
                    // chain moved past it through another certificate.
                    let lost = match candidate.predecessor {
                        None => computed_pin.is_some(),
                        Some(p) => chain
                            .iter()
                            .position(|d| *d == p)
                            .map_or(computed_pin.is_some(), |i| {
                                computed_pin != Some(p) || i.saturating_add(1) < chain.len()
                            }),
                    };
                    if lost {
                        // Commit the retirement first; the unlink is owed
                        // work a crash simply re-discovers as S1.
                        record_retired(&mut state, candidate.digest, candidate.predecessor);
                        state.candidate = None;
                        state.pin = computed_pin;
                        write_atomic(&network_dir.join("state"), &encode_state(&state))?;
                        owed_erasures.push(share);
                    } else if !share.exists() || !proof.exists() {
                        if candidate.receipt_sent {
                            // A receipt was signed over a durable install;
                            // a missing file means the member promised what
                            // it cannot serve.
                            return Err(StoreError::Corrupt);
                        }
                        state.candidate = None;
                        state.pin = computed_pin;
                        write_atomic(&network_dir.join("state"), &encode_state(&state))?;
                        owed_erasures.push(share);
                    }
                }
            }

            // R1 and S1 over share files. Every retirement is committed to
            // `state` before its unlink; files left by a crash re-enter here
            // as owed work on the next open.
            for entry in fs::read_dir(&network_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(hex_digest) = name.strip_prefix("share-") else {
                    continue;
                };
                let Some(digest_bytes) = decode_hex(hex_digest) else {
                    // An unnamed partial write (including .tmp leftovers)
                    // can never have been recorded; S1 erases it.
                    erase_share_file(&entry.path())?;
                    continue;
                };
                let digest = CertDigest::new(digest_bytes);
                let is_pin = computed_pin == Some(digest);
                let is_candidate = state.candidate.as_ref().is_some_and(|c| c.digest == digest);
                if is_pin || is_candidate {
                    continue;
                }
                if verified.contains_key(&digest) {
                    // Superseded activated generation (R1).
                    if !state.retired.iter().any(|r| r.digest == digest) {
                        let predecessor = proofs[&digest].body.previous().copied();
                        record_retired(&mut state, digest, predecessor);
                        state.pin = computed_pin;
                        write_atomic(&network_dir.join("state"), &encode_state(&state))?;
                    }
                    owed_erasures.push(entry.path());
                } else {
                    // Outside the activated chain and named in no record:
                    // S1 erases unconditionally (the pin's existence changes
                    // nothing — such a file never had a durable install
                    // record).
                    erase_share_file(&entry.path())?;
                }
            }

            if state.pin != computed_pin || state_dirty {
                state.pin = computed_pin;
                write_atomic(&network_dir.join("state"), &encode_state(&state))?;
            }

            // Owed unlinks run only after every corresponding `state`
            // commit.
            for path in &owed_erasures {
                erase_share_file(path)?;
            }

            if state.pin != computed_pin || state_dirty {
                state.pin = computed_pin;
                write_atomic(&network_dir.join("state"), &encode_state(&state))?;
            }
        }

        // The in-memory pin: normally the computed chain tip; on
        // equivocation the recorded verified pin (a branch descendant is
        // proven, not corruption), so a reopen is the same freeze the live
        // store hit.
        let pin = if equivocation {
            state
                .pin
                .and_then(|d| verified.get(&d).cloned())
                .or_else(|| computed_pin.and_then(|d| verified.get(&d).cloned()))
        } else {
            pin
        };

        Ok(Self {
            network_dir,
            anchor,
            member,
            _lock: lock_file,
            inner: Mutex::new(Inner {
                state,
                pin,
                verified,
                equivocation,
            }),
        })
    }

    /// The pinned certificate, if any activation chain exists. Details: TC-2221
    pub fn pinned(&self) -> Option<VerifiedCertificate> {
        self.inner.lock().ok()?.pin.clone()
    }

    /// Whether activated equivocation froze the pin. Details: TC-2221
    pub fn equivocation(&self) -> bool {
        self.inner.lock().map(|i| i.equivocation).unwrap_or(true)
    }

    /// Retired generations recorded so far. Details: TC-2221
    pub fn retired(&self) -> Vec<RetiredGeneration> {
        self.inner
            .lock()
            .map(|i| i.state.retired.clone())
            .unwrap_or_default()
    }

    /// The bound share for the pinned certificate, or none when this member
    /// holds no share for it. Details: TC-2221
    ///
    /// Returns `Equivocation` when a disk-discovered fork froze the pin: a
    /// frozen store never exports share material.
    pub fn current_share(&self) -> Result<Option<KeyShare>, StoreError> {
        use std::io::Read;
        let inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        if inner.equivocation {
            return Err(StoreError::Equivocation);
        }
        let Some(pin) = inner.pin.clone() else {
            return Ok(None);
        };
        let path = share_path(&self.network_dir, &pin.digest());
        if !path.exists() {
            return Ok(None);
        }
        let mut bytes = Zeroizing::new([0u8; 67]);
        fs::File::open(&path)?.read_exact(&mut *bytes)?;
        let candidate = CandidateShare::from_bytes(&*bytes)?;
        Ok(Some(KeyShare::bind(candidate, &pin)?))
    }

    /// The pending candidate's digest and member index, awaiting its
    /// readiness receipt. Details: TC-2221
    pub fn pending_candidate(&self) -> Option<(CertDigest, MemberIndex)> {
        use std::io::Read;
        let inner = self.inner.lock().ok()?;
        let candidate = inner.state.candidate.as_ref()?;
        let path = share_path(&self.network_dir, &candidate.digest);
        let mut bytes = Zeroizing::new([0u8; 67]);
        fs::File::open(path).ok()?.read_exact(&mut *bytes).ok()?;
        let share = CandidateShare::from_bytes(&*bytes).ok()?;
        Some((candidate.digest, share.index()))
    }

    /// Durably install a candidate share for `signed`. Details: TC-2221
    ///
    /// `signed` must verify as the successor of the current pin (or as a
    /// genesis before any pin), `ceremony` must be one this store already
    /// accepted for that predecessor, and the persisted file is read back
    /// and bound before the candidate is recorded — a receipt can never be
    /// signed over bytes that were not verified durable. Returns the
    /// candidate certificate digest.
    pub fn install_candidate(
        &self,
        signed: &SignedCertificate,
        candidate: CandidateShare,
        ceremony: &AuthorizedCeremony,
        v: &impl DidSignatureVerifier,
    ) -> Result<CertDigest, StoreError> {
        use std::io::Read;
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        if inner.equivocation {
            return Err(StoreError::Equivocation);
        }
        if inner.state.candidate.is_some() {
            return Err(StoreError::CandidateExists);
        }
        // Only the currently admissible ceremony — the most recently
        // accepted fresh id FOR the current pin — may install. Superseded
        // and retired ids stay in `seen` as history but can never install,
        // so a candidate erased by C1 cannot be resurrected. The recorded
        // predecessor must equal the actual pin: a crash can restore an
        // `active_ceremony` whose accepted-for pin the proofs then move
        // past, and that id is contextually stale, never admissible.
        let admissible = inner.state.active_ceremony.as_ref().is_some_and(|a| {
            a.id == ceremony.statement().id
                && a.predecessor == inner.pin.as_ref().map(|p| p.digest())
        });
        if ceremony.anchor() != &self.anchor || !admissible {
            return Err(Error::InvalidCeremony.into());
        }
        let (verified, predecessor) = match &inner.pin {
            Some(pin) => (verify_successor(pin, signed, v)?, Some(pin.digest())),
            None => {
                if signed.body.previous().is_some() {
                    return Err(StoreError::InvalidActivation);
                }
                (verify_certificate(&self.anchor, signed, v)?, None)
            }
        };
        if ceremony.statement().current != predecessor {
            return Err(StoreError::InvalidActivation);
        }
        let digest = verified.digest();
        // The certificate body carries no ceremony id, so a superseded
        // ceremony's certificate could arrive under the fresh admissible
        // label. The durable retirement record — not the label — decides:
        // an erased share never resurrects.
        if inner.state.retired.iter().any(|r| r.digest == digest) {
            return Err(StoreError::Retired);
        }
        let index = candidate.index();
        write_atomic(
            &proof_path(&self.network_dir, &digest),
            &encode_proof(signed, None, &[]),
        )?;
        let bytes = candidate.to_bytes();
        write_atomic(&share_path(&self.network_dir, &digest), &*bytes)?;
        drop(bytes);
        // §5.3: read the persisted file back and bind it before the
        // candidate is permitted to receive a receipt.
        let mut persisted = Zeroizing::new([0u8; 67]);
        fs::File::open(share_path(&self.network_dir, &digest))?.read_exact(&mut *persisted)?;
        let reloaded = CandidateShare::from_bytes(&*persisted)?;
        if reloaded.index() != index {
            return Err(StoreError::Corrupt);
        }
        let _bound = KeyShare::bind(reloaded, &verified)?;
        let mut next = inner.state.clone();
        next.candidate = Some(CandidateRecord {
            digest,
            ceremony: ceremony.statement().id,
            predecessor,
            receipt_sent: false,
        });
        write_atomic(&self.network_dir.join("state"), &encode_state(&next))?;
        inner.state = next;
        Ok(digest)
    }

    /// Record that this member's readiness receipt was sent. Details: TC-2221
    ///
    /// Called only after `install_candidate` committed; a restart that finds
    /// `receipt_sent` with a missing share file refuses to open.
    pub fn mark_receipt_sent(&self) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        let mut next = inner.state.clone();
        let Some(candidate) = &mut next.candidate else {
            return Err(StoreError::Corrupt);
        };
        candidate.receipt_sent = true;
        write_atomic(&self.network_dir.join("state"), &encode_state(&next))?;
        inner.state = next;
        Ok(())
    }

    /// Record a verified activation; promotes the candidate when it matches
    /// and retires every superseded share. Details: TC-2221
    ///
    /// Proof and share order keeps the crash window safe: the activated proof
    /// lands first, so a restart recomputes the higher pin from `proofs/` and
    /// finishes retirement even if `state` was never rewritten.
    pub fn record_activation(
        &self,
        signed: &SignedCertificate,
        activation: &SignedStatement,
        receipts: &[ReadinessReceipt],
        v: &impl DidSignatureVerifier,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        if inner.equivocation {
            return Err(StoreError::Equivocation);
        }
        // Idempotent: a certificate already on the verified activated chain
        // is a no-op, so concurrent or replayed recordings converge.
        if inner.verified.contains_key(&signed.body.digest()) {
            return Ok(());
        }
        // A certificate naming any verified chain certificate other than the
        // pin as its predecessor is activated fork evidence: persist the
        // activated proof durably first, then freeze the store.
        if let Some(parent) = signed.body.previous().and_then(|p| inner.verified.get(p)) {
            if inner
                .pin
                .as_ref()
                .is_none_or(|pin| pin.digest() != parent.digest())
            {
                let fork = verify_successor(parent, signed, v)?;
                verify_activation(&fork, receipts, ReadyQuorum::AllHolders, activation, v)?;
                write_atomic(
                    &proof_path(&self.network_dir, &fork.digest()),
                    &encode_proof(signed, Some(activation), receipts),
                )?;
                inner.equivocation = true;
                return Err(StoreError::Equivocation);
            }
        }
        // A second ACTIVATED genesis is the same equivocation reopening
        // freezes on: verify it, persist the proof durably, then freeze —
        // never silently drop the evidence.
        if signed.body.previous().is_none() && inner.pin.is_some() {
            let root = verify_certificate(&self.anchor, signed, v)?;
            verify_activation(&root, receipts, ReadyQuorum::AllHolders, activation, v)?;
            write_atomic(
                &proof_path(&self.network_dir, &root.digest()),
                &encode_proof(signed, Some(activation), receipts),
            )?;
            inner.equivocation = true;
            return Err(StoreError::Equivocation);
        }
        let verified = match &inner.pin {
            Some(pin) => verify_successor(pin, signed, v)?,
            None => verify_certificate(&self.anchor, signed, v)?,
        };
        verify_activation(&verified, receipts, ReadyQuorum::AllHolders, activation, v)?;
        let digest = verified.digest();
        // The durable retirement record rules out re-activation too: a
        // losing candidate whose share was erased must never be re-pinned
        // by a late `record_activation` — the erased share cannot serve.
        if inner.state.retired.iter().any(|r| r.digest == digest) {
            return Err(StoreError::Retired);
        }
        write_atomic(
            &proof_path(&self.network_dir, &digest),
            &encode_proof(signed, Some(activation), receipts),
        )?;
        // `state` commits every removal BEFORE the unlink, so a crash is
        // recovered as "erasure owed", never as a missing promised share;
        // the in-memory record moves only after its durable copy exists.
        let mut next = inner.state.clone();
        let mut erasures: Vec<PathBuf> = Vec::new();
        // C2: a pending candidate that lost to this activation is erased; the
        // winning candidate's record is cleared (the chain is its record).
        if let Some(candidate) = next.candidate.take() {
            if candidate.digest != digest
                && !next.retired.iter().any(|r| r.digest == candidate.digest)
            {
                record_retired(&mut next, candidate.digest, candidate.predecessor);
                erasures.push(share_path(&self.network_dir, &candidate.digest));
            }
        }
        // R1: the outgoing pin's share is retired.
        if let Some(old_pin) = &inner.pin {
            let old = old_pin.digest();
            if !next.retired.iter().any(|r| r.digest == old) {
                record_retired(&mut next, old, old_pin.body().previous().copied());
                erasures.push(share_path(&self.network_dir, &old));
            }
        }
        next.pin = Some(digest);
        // Retirement history is audit data and is kept; only when the list
        // nears the bound are provably-dead entries (keyed to superseded
        // pins) compacted away — reachable ones are never evicted, the
        // operation is refused instead of resurrecting a share.
        if !compact_retired(&mut next, Some(digest)) {
            return Err(StoreError::Capacity);
        }
        // Ceremonies accepted against the old pin are stale: the next
        // admissible ceremony must be accepted afresh for this pin.
        next.active_ceremony = None;
        write_atomic(&self.network_dir.join("state"), &encode_state(&next))?;
        inner.state = next;
        inner.pin = Some(verified.clone());
        inner.verified.insert(digest, verified);
        for path in &erasures {
            erase_share_file(path)?;
        }
        Ok(())
    }

    /// Present a freshly verified authorized ceremony before any dealing.
    /// Details: TC-2221
    ///
    /// The ceremony must be anchored to this store's owner/network, name this
    /// member among its recipients, and pin the current certificate as its
    /// predecessor. A fresh id then erases any unactivated candidate for that
    /// predecessor (C1), writes the dealt marker and consumes the id; a
    /// replayed id changes nothing.
    pub fn accept_ceremony(
        &self,
        ceremony: &AuthorizedCeremony,
    ) -> Result<AcceptOutcome, StoreError> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        if inner.equivocation {
            return Err(StoreError::Equivocation);
        }
        let statement = ceremony.statement();
        // A ceremony for another owner/network, another member, or a chain
        // position this store is not at is not ours to consume.
        if ceremony.anchor() != &self.anchor
            || !statement.recipients.iter().any(|r| r.node == self.member)
            || statement.current != inner.pin.as_ref().map(|p| p.digest())
        {
            return Err(Error::InvalidCeremony.into());
        }
        if inner.state.seen_ceremonies.contains(&statement.id) {
            return Ok(AcceptOutcome::Replay);
        }
        // `state` commits the removal and the new admissible ceremony before
        // the unlink and before the dealt marker; a crash re-discovers the
        // unlink as S1 and the marker's id as consumed. The in-memory record
        // is touched only after its durable copy exists, so a failed write
        // leaves the live state identical to disk — a retry sees the same
        // ceremony as fresh, not a phantom replay.
        let mut next = inner.state.clone();
        let mut owed: Option<PathBuf> = None;
        if let Some(candidate) = &next.candidate {
            if candidate.predecessor == statement.current {
                let digest = candidate.digest;
                let predecessor = candidate.predecessor;
                record_retired(&mut next, digest, predecessor);
                next.candidate = None;
                owed = Some(share_path(&self.network_dir, &digest));
            }
        }
        // Refuse rather than let the durable lists grow past their bounds;
        // dead retirement records are compacted first so legitimate
        // long-lived stores never hit the wall.
        if next.seen_ceremonies.len() >= MAX_SEEN_CEREMONIES
            || !compact_retired(&mut next, inner.pin.as_ref().map(|p| p.digest()))
        {
            return Err(StoreError::Capacity);
        }
        next.seen_ceremonies.push(statement.id);
        next.active_ceremony = Some(ActiveCeremony {
            id: statement.id,
            predecessor: statement.current,
        });
        write_atomic(&self.network_dir.join("state"), &encode_state(&next))?;
        inner.state = next;
        let marker = write_atomic(
            &self
                .network_dir
                .join("dealt")
                .join(hex(statement.id.as_bytes())),
            b"",
        );
        // The erasure debt is already durable in `state.retired`; attempt the
        // unlink even if the marker write failed so a retry (or the next
        // open) never finds the retired share still live.
        if let Some(path) = owed {
            erase_share_file(&path)?;
        }
        marker?;
        Ok(AcceptOutcome::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::{
        activation::{activation_preimage, readiness_preimage},
        ceremony::{tests::Signers, CeremonyKind},
        cert::{self, tests as cert_tests},
        curve::Scalar,
        ids::*,
        KeyShare,
    };

    use super::*;

    static TAG: AtomicU64 = AtomicU64::new(0);

    /// A temporary store directory removed on drop — tests leave nothing
    /// under `/tmp` behind.
    struct Tmp(PathBuf);

    impl std::ops::Deref for Tmp {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir() -> Tmp {
        let tag = TAG.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("tc2221-store-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Tmp(path)
    }

    fn netdir(dir: &Path, network: &NetworkUrn) -> PathBuf {
        store_dir(dir, network)
    }
    fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let to = dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir(&entry.path(), &to)?;
            } else {
                fs::copy(entry.path(), &to)?;
            }
        }
        Ok(())
    }

    /// Make every entry under `dir` writable again — a read-only-dir fault
    /// must be undone before the disk can be restored or cleaned up.
    #[cfg(unix)]
    fn make_writable(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    make_writable(&path);
                }
            }
        }
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    }

    #[cfg(not(unix))]
    fn make_writable(_dir: &Path) {}

    fn open(dir: &Path, signers: &Signers) -> ShareStore {
        ShareStore::open(
            dir,
            &signers.anchor().network,
            signers.anchor().clone(),
            Signers::did(1),
            signers,
        )
        .unwrap()
    }

    fn receipts_for(cert: &VerifiedCertificate, signers: &Signers) -> Vec<ReadinessReceipt> {
        cert.body()
            .members()
            .iter()
            .map(|m| ReadinessReceipt {
                index: m.index,
                signature: signers
                    .sign(&m.node, &readiness_preimage(cert.body(), m.index).unwrap()),
            })
            .collect()
    }

    fn activation_for(
        cert: &VerifiedCertificate,
        receipts: &[ReadinessReceipt],
        signers: &Signers,
    ) -> SignedStatement {
        let bytes = activation_preimage(cert.body(), receipts).unwrap();
        SignedStatement {
            signature: signers.sign(&cert.anchor().expected_owner, &bytes),
            bytes,
        }
    }

    fn mk_candidate(mut raw: KeyShare, body: &CertificateBody) -> CandidateShare {
        let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
        CandidateShare::new(body.transcript_hash(), raw.index, scalar)
    }

    /// Genesis: install member 1's share, send receipt, record activation.
    fn activated_genesis(
        store: &ShareStore,
        signers: &Signers,
    ) -> (SignedCertificate, VerifiedCertificate) {
        let (cert, mut shares) = cert_tests::genesis(signers);
        let share = shares.remove(0);
        let signed = cert::tests::sign(cert.body().clone(), signers);
        let candidate = mk_candidate(share, cert.body());
        store.accept_ceremony(&signers.genesis()).unwrap();
        store
            .install_candidate(&signed, candidate, &signers.genesis(), signers)
            .unwrap();
        store.mark_receipt_sent().unwrap();
        let receipts = receipts_for(&cert, signers);
        let activation = activation_for(&cert, &receipts, signers);
        store
            .record_activation(&signed, &activation, &receipts, signers)
            .unwrap();
        (signed, cert)
    }

    /// A successor certificate over the same ceremony and shares, distinct
    /// only by transcript; used where two candidates compete.
    fn sibling_successor(
        signers: &Signers,
        prev: &VerifiedCertificate,
        ceremony: &AuthorizedCeremony,
        transcript: u8,
    ) -> SignedCertificate {
        let (public, _shares) = cert_tests::material(11, Threshold::new(2, 3).unwrap());
        let body = CertificateBody::successor(
            prev,
            ceremony,
            &public,
            &TranscriptHash::new([transcript; 32]),
        )
        .unwrap();
        cert::tests::sign(body, signers)
    }

    #[test]
    fn candidate_share_codec_round_trips_and_refuses_noncanonical() {
        let signers = Signers::new();
        let (cert, mut shares) = cert_tests::genesis(&signers);
        let candidate = mk_candidate(shares.remove(0), cert.body());
        let bytes = candidate.to_bytes();
        let restored = CandidateShare::from_bytes(bytes.as_slice()).unwrap();
        assert!(KeyShare::bind(restored, &cert).is_ok());

        type Mutate = (&'static str, fn(&mut Vec<u8>));
        let cases: [Mutate; 7] = [
            ("empty", |b: &mut Vec<u8>| b.clear()),
            ("version", |b: &mut Vec<u8>| b[0] = 2),
            ("index-zero", |b: &mut Vec<u8>| {
                b[33] = 0;
                b[34] = 0;
            }),
            ("index-17", |b: &mut Vec<u8>| {
                b[33] = 0;
                b[34] = 17;
            }),
            ("zero-scalar", |b: &mut Vec<u8>| {
                for x in &mut b[35..] {
                    *x = 0;
                }
            }),
            ("truncated", |b: &mut Vec<u8>| {
                b.truncate(66);
            }),
            ("trailing", |b: &mut Vec<u8>| b.push(0)),
        ];
        for (tag, mutate) in cases {
            let mut bad = bytes.to_vec();
            mutate(&mut bad);
            assert!(
                CandidateShare::from_bytes(&bad).is_err(),
                "{tag} must be refused"
            );
        }
    }

    #[test]
    fn candidate_persists_across_restart_until_activation() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let store = open(&dir, &signers);
        let (_signed, cert) = activated_genesis(&store, &signers);
        assert_eq!(store.pinned().unwrap().digest(), cert.digest());

        let (s_succ, mut raw, ceremony) = cert_tests::successor(
            &signers,
            &cert,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        let candidate = mk_candidate(raw.remove(0), &s_succ.body);
        assert_eq!(
            store.accept_ceremony(&ceremony).unwrap(),
            AcceptOutcome::Fresh
        );
        let digest = store
            .install_candidate(&s_succ, candidate, &ceremony, &signers)
            .unwrap();
        drop(store);

        // Restart: the persisted candidate is pending, the old pin stands.
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert_eq!(store.pinned().unwrap().digest(), cert.digest());
        assert_eq!(store.pending_candidate().unwrap().0, digest);
        assert!(store.current_share().unwrap().is_some());
        drop(store);

        // Activate, then restart again: new pin, old share retired.
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        let succ = verify_successor(&cert, &s_succ, &signers).unwrap();
        let receipts = receipts_for(&succ, &signers);
        let activation = activation_for(&succ, &receipts, &signers);
        store
            .record_activation(&s_succ, &activation, &receipts, &signers)
            .unwrap();
        drop(store);
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert_eq!(store.pinned().unwrap().digest(), succ.digest());
        assert!(store.pending_candidate().is_none());
        let share = store.current_share().unwrap().unwrap();
        assert_eq!(share.index().get(), 1);
    }

    #[test]
    fn orphan_share_files_are_swept_without_state_record() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            activated_genesis(&store, &signers);
        }
        let ndir = netdir(&dir, &network);
        let stray = ndir.join(format!("share-{}", hex(&[7; 32])));
        fs::write(&stray, [9u8; 67]).unwrap();
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(!stray.exists());
        assert!(store.current_share().unwrap().is_some());
    }

    #[test]
    fn candidate_without_receipt_is_dropped_when_share_missing() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (s_succ, mut raw, ceremony) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            let candidate = mk_candidate(raw.remove(0), &s_succ.body);
            store.accept_ceremony(&ceremony).unwrap();
            let digest = store
                .install_candidate(&s_succ, candidate, &ceremony, &signers)
                .unwrap();
            drop(store);
            let ndir = netdir(&dir, &network);
            fs::remove_file(ndir.join(format!("share-{}", hex(digest.as_bytes())))).unwrap();
        }
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.pending_candidate().is_none());
        assert!(store.current_share().unwrap().is_some());
    }

    #[test]
    fn sent_receipt_with_missing_share_is_corruption() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (s_succ, mut raw, ceremony) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            let candidate = mk_candidate(raw.remove(0), &s_succ.body);
            store.accept_ceremony(&ceremony).unwrap();
            let digest = store
                .install_candidate(&s_succ, candidate, &ceremony, &signers)
                .unwrap();
            store.mark_receipt_sent().unwrap();
            drop(store);
            let ndir = netdir(&dir, &network);
            fs::remove_file(ndir.join(format!("share-{}", hex(digest.as_bytes())))).unwrap();
        }
        assert!(ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers
        )
        .is_err());
    }

    #[test]
    fn retried_ceremony_erases_first_candidate_and_replay_is_noop() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed, cert) = activated_genesis(&store, &signers);

        // Ceremony X installs a candidate, then aborts.
        let (s_x, mut raw_x, ceremony_x) = cert_tests::successor(
            &signers,
            &cert,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        assert_eq!(
            store.accept_ceremony(&ceremony_x).unwrap(),
            AcceptOutcome::Fresh
        );
        let cand_x = mk_candidate(raw_x.remove(0), &s_x.body);
        let digest_x = store
            .install_candidate(&s_x, cand_x, &ceremony_x, &signers)
            .unwrap();
        store.mark_receipt_sent().unwrap();
        let ndir = netdir(&dir, &signers.anchor().network);
        assert!(ndir
            .join(format!("share-{}", hex(digest_x.as_bytes())))
            .exists());

        // Ceremony Y for the same predecessor: C1 erases X's candidate first.
        let mut stmt_y = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt_y.id = CeremonyId::new([61; 32]);
        stmt_y.current = Some(cert.digest());
        stmt_y.epoch = cert.body().epoch().checked_next().unwrap();
        stmt_y.rekey = cert.body().rekey();
        let ceremony_y =
            AuthorizedCeremony::verify_for(&cert, &signers.statement(&stmt_y), &signers).unwrap();
        assert_eq!(
            store.accept_ceremony(&ceremony_y).unwrap(),
            AcceptOutcome::Fresh
        );
        assert!(!ndir
            .join(format!("share-{}", hex(digest_x.as_bytes())))
            .exists());
        assert!(store.pending_candidate().is_none());

        // Replaying X's authorization changes nothing.
        assert_eq!(
            store.accept_ceremony(&ceremony_x).unwrap(),
            AcceptOutcome::Replay
        );
    }

    #[test]
    fn losing_candidate_is_erased_on_other_successor_activation() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed, cert) = activated_genesis(&store, &signers);

        let (s_d, mut raw, ceremony_d) = cert_tests::successor(
            &signers,
            &cert,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        let cand = mk_candidate(raw.remove(0), &s_d.body);
        store.accept_ceremony(&ceremony_d).unwrap();
        let digest_d = store
            .install_candidate(&s_d, cand, &ceremony_d, &signers)
            .unwrap();
        let ndir = netdir(&dir, &signers.anchor().network);
        assert!(ndir
            .join(format!("share-{}", hex(digest_d.as_bytes())))
            .exists());

        // A different successor of the same predecessor activates (C2).
        let s_e = sibling_successor(&signers, &cert, &ceremony_d, 0xe0);
        let cert_e = verify_successor(&cert, &s_e, &signers).unwrap();
        let receipts = receipts_for(&cert_e, &signers);
        let activation = activation_for(&cert_e, &receipts, &signers);
        store
            .record_activation(&s_e, &activation, &receipts, &signers)
            .unwrap();
        assert!(!ndir
            .join(format!("share-{}", hex(digest_d.as_bytes())))
            .exists());
        assert!(store.pending_candidate().is_none());
        assert_eq!(store.pinned().unwrap().digest(), cert_e.digest());
    }

    #[test]
    fn genesis_candidate_is_erased_by_later_genesis() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (cert_g1, mut shares) = cert_tests::genesis(&signers);
        let share = shares.remove(0);
        let signed_g1 = cert::tests::sign(cert_g1.body().clone(), &signers);
        let cand = mk_candidate(share, cert_g1.body());
        store.accept_ceremony(&signers.genesis()).unwrap();
        let digest_g1 = store
            .install_candidate(&signed_g1, cand, &signers.genesis(), &signers)
            .unwrap();

        // A second genesis activation erases G1 (C2, predecessor "none").
        let mut stmt_g2 = signers.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
        stmt_g2.id = CeremonyId::new([0x92; 32]);
        let ceremony_g2 = AuthorizedCeremony::verify_genesis(
            &signers.anchor(),
            &signers.statement(&stmt_g2),
            &signers,
        )
        .unwrap();
        let (public_g2, _shares_g2) = cert_tests::material(11, Threshold::new(2, 3).unwrap());
        let body_g2 = CertificateBody::genesis(
            &signers.anchor(),
            &ceremony_g2,
            &public_g2,
            &TranscriptHash::new([0x93; 32]),
        )
        .unwrap();
        let signed_g2 = cert::tests::sign(body_g2, &signers);
        let cert_g2 = verify_certificate(&signers.anchor(), &signed_g2, &signers).unwrap();
        let receipts = receipts_for(&cert_g2, &signers);
        let activation = activation_for(&cert_g2, &receipts, &signers);
        store
            .record_activation(&signed_g2, &activation, &receipts, &signers)
            .unwrap();
        let ndir = netdir(&dir, &signers.anchor().network);
        assert!(!ndir
            .join(format!("share-{}", hex(digest_g1.as_bytes())))
            .exists());
        assert_eq!(store.pinned().unwrap().digest(), cert_g2.digest());
    }

    #[test]
    fn activation_proof_advances_pin_past_state_crash() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let digest_old;
        let digest_succ;
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            digest_old = cert.digest();
            let (s_succ, mut raw, ceremony_succ) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            store.accept_ceremony(&ceremony_succ).unwrap();
            store
                .install_candidate(
                    &s_succ,
                    mk_candidate(raw.remove(0), &s_succ.body),
                    &ceremony_succ,
                    &signers,
                )
                .unwrap();
            store.mark_receipt_sent().unwrap();
            let succ = verify_successor(&cert, &s_succ, &signers).unwrap();
            digest_succ = succ.digest();
            // Crash simulation: activated proof written, state never updated.
            let receipts = receipts_for(&succ, &signers);
            let activation = activation_for(&succ, &receipts, &signers);
            let ndir = netdir(&dir, &network);
            fs::write(
                ndir.join(format!("proofs/{}", hex(digest_succ.as_bytes()))),
                encode_proof(&s_succ, Some(&activation), &receipts),
            )
            .unwrap();
        }
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert_eq!(store.pinned().unwrap().digest(), digest_succ);
        let ndir = netdir(&dir, &network);
        assert!(!ndir
            .join(format!("share-{}", hex(digest_old.as_bytes())))
            .exists());
    }

    #[test]
    fn state_pin_outside_activated_chain_is_corruption() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            activated_genesis(&store, &signers);
        }
        let ndir = netdir(&dir, &network);
        let state_path = ndir.join("state");
        let mut state = decode_state(&fs::read(&state_path).unwrap()).unwrap();
        state.pin = Some(CertDigest::new([0xee; 32]));
        fs::write(&state_path, encode_state(&state)).unwrap();
        assert!(ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers
        )
        .is_err());
    }

    #[test]
    fn equivocated_successors_freeze_the_pin() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let old_digest;
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            old_digest = cert.digest();
            let (s_a, _ra, _ca) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            let s_b = sibling_successor(&signers, &cert, &_ca, 0xb0);
            let ndir = netdir(&dir, &network);
            for s in [&s_a, &s_b] {
                let cert = verify_successor(&cert, s, &signers).unwrap();
                let receipts = receipts_for(&cert, &signers);
                let activation = activation_for(&cert, &receipts, &signers);
                fs::write(
                    ndir.join(format!("proofs/{}", hex(cert.digest().as_bytes()))),
                    encode_proof(s, Some(&activation), &receipts),
                )
                .unwrap();
            }
        }
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.equivocation());
        assert_eq!(store.pinned().unwrap().digest(), old_digest);
    }

    #[test]
    fn concurrent_retirement_converges_once() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let s_succ;
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (s, mut raw, c) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            let cand = mk_candidate(raw.remove(0), &s.body);
            store.accept_ceremony(&c).unwrap();
            store.install_candidate(&s, cand, &c, &signers).unwrap();
            store.mark_receipt_sent().unwrap();
            s_succ = s;
        }
        let store = Arc::new(open(&dir, &signers));
        let pinned = store.pinned().unwrap();
        let succ = verify_successor(&pinned, &s_succ, &signers).unwrap();
        let receipts = receipts_for(&succ, &signers);
        let activation = activation_for(&succ, &receipts, &signers);
        let old_digest = pinned.digest();

        let mut joins = Vec::new();
        for _ in 0..4 {
            let store = Arc::clone(&store);
            let s = s_succ.clone();
            let a = activation.clone();
            let r = receipts.clone();
            let signers = Signers::new();
            joins.push(std::thread::spawn(move || {
                store.record_activation(&s, &a, &r, &signers).unwrap();
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        drop(store);
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert_eq!(store.pinned().unwrap().digest(), succ.digest());
        let ndir = netdir(&dir, &network);
        assert!(!ndir
            .join(format!("share-{}", hex(old_digest.as_bytes())))
            .exists());
        assert_eq!(store.retired().len(), 1);
    }

    #[test]
    fn dealt_marker_consumes_ceremony_id_across_restart() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let ceremony;
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (_s, _r, c) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            ceremony = c;
        }
        // Crash between dealt marker and state write: marker exists, id unseen.
        let ndir = netdir(&dir, &network);
        fs::write(
            ndir.join(format!("dealt/{}", hex(ceremony.statement().id.as_bytes()))),
            b"",
        )
        .unwrap();
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert_eq!(
            store.accept_ceremony(&ceremony).unwrap(),
            AcceptOutcome::Replay
        );
    }

    #[test]
    fn unverified_activation_flag_is_never_trusted() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (s_succ, mut raw, ceremony) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            let candidate = mk_candidate(raw.remove(0), &s_succ.body);
            store.accept_ceremony(&ceremony).unwrap();
            store
                .install_candidate(&s_succ, candidate, &ceremony, &signers)
                .unwrap();
            // A flagged activation with an empty statement and zero receipts.
            let succ = verify_successor(&cert, &s_succ, &signers).unwrap();
            let activation = SignedStatement {
                bytes: Vec::new(),
                signature: Vec::new(),
            };
            let ndir = netdir(&dir, &network);
            fs::write(
                ndir.join(format!("proofs/{}", hex(succ.digest().as_bytes()))),
                encode_proof(&s_succ, Some(&activation), &[]),
            )
            .unwrap();
        }
        // The flag alone must not pin the successor.
        assert!(ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers
        )
        .is_err());
    }

    #[test]
    fn second_opener_is_refused_while_first_holds_lock() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let network = signers.anchor().network.clone();
        assert!(matches!(
            ShareStore::open(
                &dir,
                &network,
                signers.anchor().clone(),
                Signers::did(1),
                &signers
            ),
            Err(StoreError::Busy)
        ));
        drop(store);
        let _reopened = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
    }

    #[test]
    fn foreign_or_unbound_ceremony_is_rejected() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed, cert) = activated_genesis(&store, &signers);
        let ndir = netdir(&dir, &signers.anchor().network);

        // Install a candidate under the genuine successor ceremony.
        let (s_x, mut raw, ceremony_x) = cert_tests::successor(
            &signers,
            &cert,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        store.accept_ceremony(&ceremony_x).unwrap();
        let cand = mk_candidate(raw.remove(0), &s_x.body);
        let digest_x = store
            .install_candidate(&s_x, cand, &ceremony_x, &signers)
            .unwrap();
        let share_path = ndir.join(format!("share-{}", hex(digest_x.as_bytes())));
        assert!(share_path.exists());

        // A ceremony verified under a different anchor is not ours.
        let other = TrustAnchor {
            expected_owner: Signers::did(9),
            network: NetworkUrn::new("tinycloud:test:other").unwrap(),
        };
        let mut foreign_stmt = signers.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
        foreign_stmt.id = CeremonyId::new([0xf1; 32]);
        foreign_stmt.owner = Signers::did(9);
        foreign_stmt.network = other.network.clone();
        let foreign =
            AuthorizedCeremony::verify_genesis(&other, &signers.statement(&foreign_stmt), &signers)
                .unwrap();
        assert!(store.accept_ceremony(&foreign).is_err());
        assert!(share_path.exists());

        // A ceremony that drops this member from its recipients is rejected.
        let mut stmt = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt.id = CeremonyId::new([0xf2; 32]);
        stmt.current = Some(cert.digest());
        stmt.epoch = cert.body().epoch().checked_next().unwrap();
        stmt.rekey = cert.body().rekey();
        stmt.recipients[0].node = Signers::did(9);
        let excluding =
            AuthorizedCeremony::verify_for(&cert, &signers.statement(&stmt), &signers).unwrap();
        assert!(store.accept_ceremony(&excluding).is_err());
        assert!(share_path.exists());

        // A ceremony for a stale chain position is rejected: activate the
        // candidate, then present a different authorized ceremony still
        // pinned to the old certificate.
        let cert_x = verify_successor(&cert, &s_x, &signers).unwrap();
        let receipts = receipts_for(&cert_x, &signers);
        let activation = activation_for(&cert_x, &receipts, &signers);
        store
            .record_activation(&s_x, &activation, &receipts, &signers)
            .unwrap();
        let mut stmt = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt.id = CeremonyId::new([0xf3; 32]);
        stmt.current = Some(cert.digest());
        stmt.epoch = cert.body().epoch().checked_next().unwrap();
        stmt.rekey = cert.body().rekey();
        let stale =
            AuthorizedCeremony::verify_for(&cert, &signers.statement(&stmt), &signers).unwrap();
        assert!(store.accept_ceremony(&stale).is_err());

        drop(store);
    }

    #[test]
    fn forked_activation_is_persisted_and_freezes_everything() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let digest_b;
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (s1, mut raw, c1) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            store.accept_ceremony(&c1).unwrap();
            let cand = mk_candidate(raw.remove(0), &s1.body);
            store.install_candidate(&s1, cand, &c1, &signers).unwrap();
            store.mark_receipt_sent().unwrap();
            // The candidate activates; then a sibling activation over the
            // same predecessor arrives: fork evidence for a verified
            // predecessor that is no longer the pin.
            let cert_a = verify_successor(&cert, &s1, &signers).unwrap();
            let receipts_a = receipts_for(&cert_a, &signers);
            let activation_a = activation_for(&cert_a, &receipts_a, &signers);
            store
                .record_activation(&s1, &activation_a, &receipts_a, &signers)
                .unwrap();
            let s_b = sibling_successor(&signers, &cert, &c1, 0xb1);
            let cert_b = verify_successor(&cert, &s_b, &signers).unwrap();
            digest_b = cert_b.digest();
            let receipts_b = receipts_for(&cert_b, &signers);
            let activation_b = activation_for(&cert_b, &receipts_b, &signers);
            assert!(matches!(
                store.record_activation(&s_b, &activation_b, &receipts_b, &signers),
                Err(StoreError::Equivocation)
            ));
            assert!(store.equivocation());
            // The fork proof must be durable.
            assert!(netdir(&dir, &network)
                .join(format!("proofs/{}", hex(digest_b.as_bytes())))
                .exists());
            // A frozen store exports nothing and accepts nothing new.
            assert!(matches!(
                store.current_share(),
                Err(StoreError::Equivocation)
            ));
            let mut stmt_c = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
            stmt_c.id = CeremonyId::new([0xcc; 32]);
            stmt_c.current = Some(cert.digest());
            stmt_c.epoch = cert.body().epoch().checked_next().unwrap();
            stmt_c.rekey = cert.body().rekey();
            let c_ceremony =
                AuthorizedCeremony::verify_for(&cert, &signers.statement(&stmt_c), &signers)
                    .unwrap();
            assert!(store.accept_ceremony(&c_ceremony).is_err());
        }
        // The freeze persists across restart.
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.equivocation());
        let _ = digest_b;
    }

    #[test]
    fn retired_receipted_candidate_with_missing_share_converges() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let digest_c;
        let succ_digest;
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            let (s_c, mut raw, ceremony_c) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            store.accept_ceremony(&ceremony_c).unwrap();
            let cand = mk_candidate(raw.remove(0), &s_c.body);
            digest_c = store
                .install_candidate(&s_c, cand, &ceremony_c, &signers)
                .unwrap();
            store.mark_receipt_sent().unwrap();
            // A different successor activates; the proof lands but the
            // candidate's share file is lost before `state` commits (the
            // crash window this ordering now survives).
            let s_w = sibling_successor(&signers, &cert, &ceremony_c, 0xd0);
            let cert_w = verify_successor(&cert, &s_w, &signers).unwrap();
            succ_digest = cert_w.digest();
            let receipts = receipts_for(&cert_w, &signers);
            let activation = activation_for(&cert_w, &receipts, &signers);
            let ndir = netdir(&dir, &network);
            fs::write(
                ndir.join(format!("proofs/{}", hex(succ_digest.as_bytes()))),
                encode_proof(&s_w, Some(&activation), &receipts),
            )
            .unwrap();
            // The winner's share was installed before activation — the
            // durable-install state its receipts imply.
            let (_pub_w, mut raw_w) = cert_tests::material(11, Threshold::new(2, 3).unwrap());
            let winner_share = mk_candidate(raw_w.remove(0), &s_w.body).to_bytes();
            fs::write(share_path(&ndir, &succ_digest), &winner_share).unwrap();
            fs::remove_file(ndir.join(format!("share-{}", hex(digest_c.as_bytes())))).unwrap();
        }
        // Restart: the durable retirement proof settles the candidate even
        // though its share is gone; the store converges, not Corrupt.
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert_eq!(store.pinned().unwrap().digest(), succ_digest);
        assert!(store.pending_candidate().is_none());
        assert!(store.retired().iter().any(|r| r.digest == digest_c));
    }

    #[test]
    fn leftover_temp_files_are_swept_on_open() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            activated_genesis(&store, &signers);
        }
        let ndir = netdir(&dir, &network);
        let plain = ndir.join("share-0123456789abcdef.tmp-99-7");
        fs::write(&plain, [0x55u8; 67]).unwrap();
        let old_style = ndir.join("state.tmp");
        fs::write(&old_style, [0x55u8; 4]).unwrap();
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(!plain.exists());
        assert!(!old_style.exists());
        assert!(store.current_share().unwrap().is_some());
    }

    #[test]
    fn superseded_ceremony_id_cannot_reinstall() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed, cert) = activated_genesis(&store, &signers);

        // Ceremony X installs, then ceremony Y supersedes it (C1 erases X).
        let (s_x, mut raw_x, ceremony_x) = cert_tests::successor(
            &signers,
            &cert,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        store.accept_ceremony(&ceremony_x).unwrap();
        let cand_x = mk_candidate(raw_x.remove(0), &s_x.body);
        let cand_x_again = mk_candidate(raw_x.remove(0), &s_x.body);
        store
            .install_candidate(&s_x, cand_x, &ceremony_x, &signers)
            .unwrap();

        let mut stmt_y = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt_y.id = CeremonyId::new([0x61; 32]);
        stmt_y.current = Some(cert.digest());
        stmt_y.epoch = cert.body().epoch().checked_next().unwrap();
        stmt_y.rekey = cert.body().rekey();
        let ceremony_y =
            AuthorizedCeremony::verify_for(&cert, &signers.statement(&stmt_y), &signers).unwrap();
        assert_eq!(
            store.accept_ceremony(&ceremony_y).unwrap(),
            AcceptOutcome::Fresh
        );

        // X's id is still in `seen` (history) but is no longer admissible:
        // the retired candidate cannot be resurrected.
        assert!(matches!(
            store.install_candidate(&s_x, cand_x_again, &ceremony_x, &signers),
            Err(StoreError::Crypto(Error::InvalidCeremony))
        ));

        // A candidate under Y — the admissible ceremony — still installs.
        let s_y = sibling_successor(&signers, &cert, &ceremony_y, 0x70);
        let (_pub_y, mut shares_y) = cert_tests::material(11, Threshold::new(2, 3).unwrap());
        let cand_y = mk_candidate(shares_y.remove(0), &s_y.body);
        store
            .install_candidate(&s_y, cand_y, &ceremony_y, &signers)
            .unwrap();
    }

    #[test]
    fn frozen_store_reopens_classifying_fork_descendants() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            let (_signed, cert) = activated_genesis(&store, &signers);
            // G -> A activates and pins; a sibling A' freezes the store.
            let (s_a, mut raw, c_a) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            store.accept_ceremony(&c_a).unwrap();
            let cand = mk_candidate(raw.remove(0), &s_a.body);
            store.install_candidate(&s_a, cand, &c_a, &signers).unwrap();
            store.mark_receipt_sent().unwrap();
            let cert_a = verify_successor(&cert, &s_a, &signers).unwrap();
            let receipts_a = receipts_for(&cert_a, &signers);
            let activation_a = activation_for(&cert_a, &receipts_a, &signers);
            store
                .record_activation(&s_a, &activation_a, &receipts_a, &signers)
                .unwrap();
            let s_fork = sibling_successor(&signers, &cert, &c_a, 0xf0);
            let cert_fork = verify_successor(&cert, &s_fork, &signers).unwrap();
            let receipts_f = receipts_for(&cert_fork, &signers);
            let activation_f = activation_for(&cert_fork, &receipts_f, &signers);
            assert!(matches!(
                store.record_activation(&s_fork, &activation_f, &receipts_f, &signers),
                Err(StoreError::Equivocation)
            ));
            // B: a descendant of the pinned branch, activated durably.
            let (s_b, _r, _c) = cert_tests::successor(
                &signers,
                &cert_a,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            let cert_b = verify_successor(&cert_a, &s_b, &signers).unwrap();
            let receipts_b = receipts_for(&cert_b, &signers);
            let activation_b = activation_for(&cert_b, &receipts_b, &signers);
            let ndir = netdir(&dir, &network);
            fs::write(
                ndir.join(format!("proofs/{}", hex(cert_b.digest().as_bytes()))),
                encode_proof(&s_b, Some(&activation_b), &receipts_b),
            )
            .unwrap();
        }
        // Restart: the frozen store reopens as frozen — the descendant of
        // the losing branch is classified, not corruption.
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.equivocation());
        assert!(matches!(
            store.current_share(),
            Err(StoreError::Equivocation)
        ));
    }

    #[test]
    fn unremovable_temp_refuses_open() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        {
            let store = open(&dir, &signers);
            activated_genesis(&store, &signers);
        }
        // A non-empty directory where a temp file is expected cannot be
        // overwritten, unlinked as a file, or removed as an empty dir —
        // the sweep must refuse the open.
        let ndir = netdir(&dir, &network);
        let stuck = ndir.join("state.tmp-1-1");
        fs::create_dir(&stuck).unwrap();
        fs::write(stuck.join("content"), [0x55u8; 4]).unwrap();
        assert!(ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers
        )
        .is_err());
        fs::remove_dir_all(&stuck).unwrap();
        let _reopened = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
    }

    /// Seeded model-based test: a scripted scheduler drives random sequences
    /// of accept / install / receipt / activate / fork / reopen /
    /// crash-at-every-step / second-opener over a real `ShareStore`, and a
    /// reference model asserts the store's invariants after every step.
    /// A failing run prints its seed so it can be replayed. Details: TC-2221
    mod model {
        use super::super::tests::*;
        use crate::ceremony::CeremonyRecipient;
        use std::collections::{BTreeMap, BTreeSet, VecDeque};

        /// splitmix64; cheap and stable across platforms for reproducing runs.
        struct Rng(u64);

        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                z ^ (z >> 31)
            }

            fn pick(&mut self, n: u64) -> u64 {
                self.next() % n
            }
        }

        /// The reference model: what a correct store may expose after each
        /// step, derived only from successful operations (never from the
        /// store's private state).
        #[derive(Default)]
        struct Model {
            /// The activated chain, genesis first; the last entry is the pin.
            pins: Vec<VerifiedCertificate>,
            /// Signed certificates ever produced, by digest.
            signed: BTreeMap<[u8; 32], SignedCertificate>,
            /// Ceremonies accepted for each pinned predecessor, by the
            /// predecessor digest; used to build fork siblings.
            ceremonies_by_pred: BTreeMap<[u8; 32], AuthorizedCeremony>,
            /// Every ceremony ever accepted (for stale/replay probes).
            ceremonies: Vec<AuthorizedCeremony>,
            seen: Vec<CeremonyId>,
            /// The admissible ceremony: (id, predecessor it was accepted
            /// for). A restored record whose predecessor is no longer the
            /// pin is contextually stale.
            active: Option<(CeremonyId, Option<CertDigest>)>,
            /// (candidate digest, receipt_sent) — at most one pending
            /// candidate, always a successor of the pin.
            pending: Option<(CertDigest, bool)>,
            /// Digests retired by a committed operation or discovered
            /// erasure: their share files may exist only as owed debt.
            retired: BTreeSet<[u8; 32]>,
            /// Shares whose erasure is owed; empty at every operation
            /// boundary in this harness (it never injects I/O failures).
            debt: BTreeSet<[u8; 32]>,
            /// The pin's member set no longer names this node (a legal
            /// member-drop reshare): no live share is owed.
            dropped: bool,
            frozen: bool,
            /// The pin and share-file set recorded at the moment the store
            /// froze: the freeze is terminal, so neither may ever move.
            frozen_pin: Option<CertDigest>,
            frozen_files: Option<BTreeSet<[u8; 32]>>,
        }

        /// The model's own parser for the on-disk v3 `state` record — the
        /// observable contract a crash leaves behind, independent of the
        /// store's internals. Returns `None` for any unreadable or
        /// unparsable file.
        #[derive(Debug)]
        struct ParsedState {
            pin: Option<CertDigest>,
            candidate: Option<(CertDigest, bool)>,
            active: Option<(CeremonyId, Option<CertDigest>)>,
            retired: BTreeSet<[u8; 32]>,
        }

        fn parse_state(bytes: &[u8]) -> Option<ParsedState> {
            let mut cur = 0usize;
            let take = |n: usize, cur: &mut usize| -> Option<&[u8]> {
                let end = cur.checked_add(n)?;
                let slice = bytes.get(*cur..end)?;
                *cur = end;
                Some(slice)
            };
            if take(1, &mut cur)? != [3] {
                return None;
            }
            let opt32 = |cur: &mut usize| -> Option<Option<[u8; 32]>> {
                match take(1, cur)? {
                    [0] => Some(None),
                    [1] => take(32, cur).map(|s| Some(s.try_into().unwrap())),
                    _ => None,
                }
            };
            let pin = opt32(&mut cur)?.map(CertDigest::new);
            let candidate = if take(1, &mut cur)? == [1] {
                let digest = CertDigest::new(take(32, &mut cur)?.try_into().unwrap());
                take(32, &mut cur)?; // ceremony id
                opt32(&mut cur)?; // predecessor
                let receipt = take(1, &mut cur)? == [1];
                Some((digest, receipt))
            } else {
                None
            };
            let active = if take(1, &mut cur)? == [1] {
                let id = CeremonyId::new(take(32, &mut cur)?.try_into().unwrap());
                let pred = opt32(&mut cur)?.map(CertDigest::new);
                Some((id, pred))
            } else {
                None
            };
            let seen_len = u32::from_be_bytes(take(4, &mut cur)?.try_into().unwrap()) as usize;
            if seen_len > 1_000_000 {
                return None;
            }
            for _ in 0..seen_len {
                take(32, &mut cur)?;
            }
            let retired_len = u32::from_be_bytes(take(4, &mut cur)?.try_into().unwrap()) as usize;
            if retired_len > 1_000_000 {
                return None;
            }
            let mut retired = BTreeSet::new();
            for _ in 0..retired_len {
                retired.insert(take(32, &mut cur)?.try_into().unwrap());
                opt32(&mut cur)?; // predecessor (v3)
                take(8, &mut cur)?; // erased_at
            }
            take(8, &mut cur)?; // seq
            if cur != bytes.len() {
                return None;
            }
            Some(ParsedState {
                pin,
                candidate,
                active,
                retired,
            })
        }

        struct Runner<'a> {
            signers: &'a Signers,
            dir: &'a Path,
            network: NetworkUrn,
            store: Option<ShareStore>,
            model: Model,
            rng: Rng,
            /// Recent `state` file contents for crash replays.
            snapshots: VecDeque<Vec<u8>>,
            /// How many operations the scheduler actually executed — a run
            /// that stalls on damage and never recovers fails this count.
            executed: usize,
            /// How many lawful refusals were rolled back to continue.
            recoveries: usize,
            /// Executions per operation kind, for the run summary.
            ops: BTreeMap<&'static str, u64>,
            /// Pre-fault disk backup used to recover after a lawful refusal.
            backup: Option<PathBuf>,
            /// Whether this seed may inject fork evidence; a quarter of
            /// seeds never fork so most runs exercise long unfrozen chains.
            fork_allowed: bool,
            transcript: u8,
        }

        impl<'a> Runner<'a> {
            fn ndir(&self) -> PathBuf {
                netdir(self.dir, &self.network)
            }

            fn store(&mut self) -> &mut ShareStore {
                self.store.as_mut().unwrap()
            }

            /// A cheap digest of every regular file under the network dir —
            /// used to prove a refused second opener touches nothing.
            fn disk_hash(&self) -> u64 {
                let mut hash = 0xcbf29ce484222325u64;
                for sub in [
                    self.ndir(),
                    self.ndir().join("proofs"),
                    self.ndir().join("dealt"),
                ] {
                    let mut entries: Vec<(String, Vec<u8>)> = fs::read_dir(&sub)
                        .map(|rd| {
                            rd.flatten()
                                .filter_map(|e| {
                                    let name = e.file_name().to_str()?.to_owned();
                                    let bytes = fs::read(e.path()).ok()?;
                                    Some((name, bytes))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    entries.sort();
                    for (name, bytes) in entries {
                        for b in name.bytes().chain(bytes) {
                            hash = (hash ^ u64::from(b)).wrapping_mul(0x100000001b3);
                        }
                    }
                }
                hash
            }

            /// Copy the member's entire share dir for a later restore —
            /// called before every open-path damage op so the scheduler can
            /// roll the disk back and continue the run after a lawful
            /// refusal.
            fn save_disk(&mut self) {
                let backup = self.dir.join("model-backup");
                if backup.exists() {
                    fs::remove_dir_all(&backup).unwrap();
                }
                copy_dir(&self.ndir(), &backup).unwrap();
                self.backup = Some(backup);
            }

            /// Roll the share dir back to the snapshot `save_disk` took.
            fn restore_disk(&mut self) {
                let backup = self.backup.take().expect("restore needs a snapshot");
                let ndir = self.ndir();
                if ndir.exists() {
                    make_writable(&ndir);
                    fs::remove_dir_all(&ndir).unwrap();
                }
                copy_dir(&backup, &ndir).unwrap();
                fs::remove_dir_all(&backup).unwrap();
            }

            fn mark_op(&mut self, op: &'static str) {
                self.executed += 1;
                *self.ops.entry(op).or_default() += 1;
            }

            /// Whether `proofs/` can still prove `pin`: its own proof file
            /// plus every ancestor's up to genesis must exist. Used only to
            /// classify a `Corrupt` refusal — the store's own verification
            /// stays authoritative.
            fn pin_is_provable(&self, pin: &CertDigest) -> bool {
                let mut current = Some(*pin);
                while let Some(digest) = current {
                    let Ok(bytes) = fs::read(proof_path(&self.ndir(), &digest)) else {
                        return false;
                    };
                    let Ok((signed, _)) = decode_proof(&bytes) else {
                        return false;
                    };
                    current = signed.body.previous().copied();
                }
                true
            }

            fn share_files(&self) -> BTreeSet<[u8; 32]> {
                let mut out = BTreeSet::new();
                if let Ok(entries) = fs::read_dir(self.ndir()) {
                    for entry in entries.flatten() {
                        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                            continue;
                        };
                        if let Some(hex) = name.strip_prefix("share-") {
                            if let Some(digest) = decode_hex(hex) {
                                out.insert(digest);
                            }
                        }
                    }
                }
                out
            }

            fn snapshot(&mut self) {
                let state = self.ndir().join("state");
                if let Ok(bytes) = fs::read(&state) {
                    self.snapshots.push_back(bytes);
                    while self.snapshots.len() > 4 {
                        self.snapshots.pop_front();
                    }
                }
            }

            /// Every rule the store must satisfy at an operation boundary —
            /// called after EVERY scheduler step. Details: TC-2221
            fn assert_boundary(&self, seed: u64, step: usize) {
                let m = &self.model;
                let store = self
                    .store
                    .as_ref()
                    .expect("seed: closed store outside a crash arm");
                let files = self.share_files();
                // Rule 11: the state file is always exactly one v2 record.
                let parsed = fs::read(self.ndir().join("state"))
                    .ok()
                    .and_then(|b| parse_state(&b));
                assert!(
                    parsed.is_some(),
                    "seed {seed} step {step}: state file does not parse as v3"
                );
                // Rule 12: the model and the parsed state never diverge —
                // pin, candidate (with its receipt flag, I6) and the
                // admissible ceremony are exactly what the disk records.
                if let Some(p) = &parsed {
                    assert_eq!(
                        p.pin,
                        m.pins.last().map(|p| p.digest()),
                        "seed {seed} step {step}: disk pin diverged from model"
                    );
                    assert_eq!(
                        p.candidate, m.pending,
                        "seed {seed} step {step}: disk candidate diverged from model"
                    );
                    assert_eq!(
                        p.active, m.active,
                        "seed {seed} step {step}: disk admissible ceremony diverged"
                    );
                    // Rule 7 tail: `retired` never names a live generation.
                    let pin_d = m.pins.last().map(|p| p.digest());
                    let pend_d = m.pending.map(|(d, _)| d);
                    for r in &p.retired {
                        assert!(
                            Some(CertDigest::new(*r)) != pin_d
                                && Some(CertDigest::new(*r)) != pend_d,
                            "seed {seed} step {step}: retired names a live share"
                        );
                    }
                }
                // Rule 4: once frozen, frozen forever — the recorded pin and
                // share set are immutable; nothing is ever erased or
                // exported.
                // Rule 4: once frozen, frozen forever — the recorded pin is
                // immutable and nothing is exported or erased past it.
                if m.frozen {
                    assert!(
                        store.equivocation(),
                        "seed {seed} step {step}: frozen store thawed"
                    );
                    assert!(
                        matches!(store.current_share(), Err(StoreError::Equivocation)),
                        "seed {seed} step {step}: frozen store exports a share"
                    );
                    // The recorded pin stands — it may be an older
                    // generation than the model's tip when a late fault
                    // moved the model past the durable write.
                    assert_eq!(
                        store.pinned().map(|p| p.digest()),
                        m.frozen_pin,
                        "seed {seed} step {step}: frozen pin moved"
                    );
                    // Nothing past the recorded pin is ever erased: the
                    // share set at freeze is a floor, not an equality — a
                    // crash can add candidates the freeze then keeps.
                    for d in m.frozen_files.clone().unwrap_or_default() {
                        assert!(
                            files.contains(&d),
                            "seed {seed} step {step}: a share frozen in place was lost"
                        );
                    }
                    for digest in &files {
                        assert!(
                            m.signed.contains_key(digest),
                            "seed {seed} step {step}: foreign share file on frozen store"
                        );
                    }
                    return;
                }
                // Rule 3 / rule 1: exactly one pin, and only the pin's share
                // is ever usable.
                let pin = m.pins.last().map(|p| p.digest());
                assert_eq!(
                    store.pinned().map(|p| p.digest()),
                    pin,
                    "seed {seed} step {step}: pin diverged from model"
                );
                // At most one pending candidate, always the pin's successor.
                assert_eq!(
                    store.pending_candidate().map(|(d, _)| d),
                    m.pending.map(|(d, _)| d),
                    "seed {seed} step {step}: pending candidate diverged"
                );
                // Rule 2: no live share is lost; rule 7: nothing retired is
                // live except as recorded debt — the on-disk share set is
                // exactly {pin?} ∪ {pending?} ∪ debt.
                let mut live: BTreeSet<[u8; 32]> = BTreeSet::new();
                // A member-drop pin owes no live share to this node — the
                // new cohort's share was never installed and the old pin's
                // is retired. A pending candidate, though, is this node's
                // own share (install only ever binds our index): it is owed
                // regardless of the pin's member set.
                if let Some(d) = pin {
                    if !m.dropped {
                        live.insert(*d.as_bytes());
                    }
                }
                if let Some((d, _)) = m.pending {
                    live.insert(*d.as_bytes());
                }
                for digest in &live {
                    assert!(
                        files.contains(digest),
                        "seed {seed} step {step}: live share missing"
                    );
                }
                for digest in &files {
                    assert!(
                        live.contains(digest) || m.debt.contains(digest),
                        "seed {seed} step {step}: share file {} outside live {:?} and debt \
                         (pins={} pending={:?} dropped={} ops={:?})",
                        hex(digest),
                        live.iter().map(|d| hex(d)).collect::<Vec<_>>(),
                        m.pins.len(),
                        m.pending,
                        m.dropped,
                        self.ops
                    );
                }
                assert!(
                    m.debt.is_subset(&files),
                    "seed {seed} step {step}: erasure debt dropped"
                );
                // Rule 7 half: a retired share may exist only as debt.
                for digest in &files {
                    if m.retired.contains(digest) {
                        assert!(
                            m.debt.contains(digest),
                            "seed {seed} step {step}: retired share live without debt"
                        );
                    }
                }
                // Rule 6 + usable share: with a pin file on disk the bound
                // share is exported.
                if let Some(d) = pin {
                    if !m.dropped && files.contains(d.as_bytes()) {
                        assert!(
                            matches!(store.current_share(), Ok(Some(_))),
                            "seed {seed} step {step}: pinned share not usable"
                        );
                    }
                }
                // Rule 8: no temp files survive a boundary.
                if let Ok(entries) = fs::read_dir(self.ndir()) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name = name.to_str().unwrap_or("");
                        assert!(
                            !name.ends_with(".tmp") && !name.contains(".tmp-"),
                            "seed {seed} step {step}: leftover temp {name}"
                        );
                    }
                }
            }

            /// Fresh ceremony for the current pin with a never-used id.
            fn fresh_ceremony(&mut self) -> AuthorizedCeremony {
                let pin = self.model.pins.last().unwrap();
                let mut stmt = self
                    .signers
                    .body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
                self.transcript = self.transcript.wrapping_add(1).max(64);
                let mut id_bytes = [0x60u8; 32];
                id_bytes[0] = 0x60 ^ (self.transcript);
                id_bytes[31] = self.transcript;
                stmt.id = CeremonyId::new(id_bytes);
                stmt.current = Some(pin.digest());
                stmt.epoch = pin.body().epoch().checked_next().unwrap();
                stmt.rekey = pin.body().rekey();
                AuthorizedCeremony::verify_for(pin, &self.signers.statement(&stmt), self.signers)
                    .unwrap()
            }

            /// A signed successor certificate of the pin under `ceremony`.
            fn fresh_signed(
                &mut self,
                ceremony: &AuthorizedCeremony,
            ) -> (SignedCertificate, KeyShare) {
                self.transcript = self.transcript.wrapping_add(1).max(64);
                let pin = self.model.pins.last().unwrap();
                let (public, mut shares) = cert_tests::material(11, Threshold::new(2, 3).unwrap());
                let body = match CertificateBody::successor(
                    pin,
                    ceremony,
                    &public,
                    &TranscriptHash::new([self.transcript; 32]),
                ) {
                    Ok(body) => body,
                    Err(e) => panic!(
                        "fresh_signed: {e:?} pin={} cer_current={:?} cer_epoch={:?} pin_epoch={:?}",
                        hex(pin.digest().as_bytes()),
                        ceremony.statement().current.map(|d| hex(d.as_bytes())),
                        ceremony.statement().epoch,
                        pin.body().epoch(),
                    ),
                };
                (cert::tests::sign(body, self.signers), shares.remove(0))
            }

            fn accept(&mut self, seed: u64, step: usize) -> Option<AuthorizedCeremony> {
                let ceremony = self.fresh_ceremony();
                let outcome = self.store().accept_ceremony(&ceremony);
                match outcome {
                    Ok(AcceptOutcome::Fresh) => {}
                    other => panic!("seed {seed} step {step}: fresh accept gave {other:?}"),
                }
                // C1: a fresh accept erases any unactivated candidate for
                // the same predecessor.
                if let Some((digest, _)) = self.model.pending.take() {
                    self.model.retired.insert(*digest.as_bytes());
                }
                let id = ceremony.statement().id;
                self.model.seen.push(id);
                self.model.active = Some((id, ceremony.statement().current));
                self.model.ceremonies.push(ceremony.clone());
                let pred = self.model.pins.last().unwrap().digest();
                self.model
                    .ceremonies_by_pred
                    .insert(*pred.as_bytes(), ceremony.clone());
                Some(ceremony)
            }

            fn install(&mut self, seed: u64, step: usize, ceremony: &AuthorizedCeremony) {
                let (signed, raw) = self.fresh_signed(ceremony);
                let candidate = mk_candidate(raw, &signed.body);
                let signers = self.signers;
                let digest = self
                    .store()
                    .install_candidate(&signed, candidate, ceremony, signers)
                    .unwrap_or_else(|e| panic!("seed {seed} step {step}: install failed: {e:?}"));
                self.model.signed.insert(*digest.as_bytes(), signed);
                assert!(
                    self.model.pending.is_none(),
                    "seed {seed} step {step}: model lost pending"
                );
                self.model.pending = Some((digest, false));
            }

            /// Rule 9: after any crash the reopened store is consistent with
            /// some crash-free projection of history — resync the model to
            /// what the store actually exposes (truncating the pin chain and
            /// forgetting the admissible id if the state reverted).
            fn resync(&mut self, seed: u64, step: usize) {
                let parsed = fs::read(self.ndir().join("state"))
                    .ok()
                    .and_then(|b| parse_state(&b));
                let store = self.store.as_ref().unwrap();
                if store.equivocation() {
                    // The freeze point is recorded once: everything after
                    // is terminal immutability, checked at every boundary.
                    // The recorded pin may sit before the model's tip — a
                    // freeze discovered at open truncates the model to the
                    // recorded position, not the crash-free projection.
                    match store.pinned() {
                        Some(pin) => {
                            let pos = self
                                .model
                                .pins
                                .iter()
                                .position(|p| p.digest() == pin.digest());
                            if let Some(pos) = pos {
                                self.model.pins.truncate(pos + 1);
                            }
                        }
                        None => self.model.pins.clear(),
                    }
                    if self.model.frozen_pin.is_none() {
                        self.model.frozen_pin = store.pinned().map(|p| p.digest());
                        self.model.frozen_files = Some(self.share_files());
                    }
                    self.model.frozen = true;
                    // Frozen resync still reads what the disk records: the
                    // state file is the durable truth for pending/active
                    // too — assertions below only check their tails.
                    self.model.active = parsed.as_ref().and_then(|p| p.active);
                    self.model.pending = parsed.as_ref().and_then(|p| p.candidate);
                    return;
                }
                let m = &mut self.model;
                match store.pinned() {
                    Some(pin) => {
                        if let Some(pos) = m.pins.iter().position(|p| p.digest() == pin.digest()) {
                            m.pins.truncate(pos + 1);
                        } else if let Some(signed) = m.signed.get(pin.digest().as_bytes()).cloned()
                        {
                            // A pin discovered on disk (proof written while
                            // the member was offline — e.g. a member-drop):
                            // extend the model chain to the verified tip.
                            let cert =
                                verify_successor(m.pins.last().unwrap(), &signed, self.signers)
                                    .unwrap_or_else(|e| {
                                        panic!(
                                    "seed {seed} step {step}: disk pin not a chain successor: {e:?}"
                                )
                                    });
                            m.pins.push(cert);
                        } else {
                            panic!("seed {seed} step {step}: reopen pinned unknown certificate")
                        }
                    }
                    None => {
                        m.pins.clear();
                        m.dropped = false;
                    }
                }
                // Member-drop: when the tip's member set no longer names
                // this node, the pin owes no usable share.
                if let Some(pin) = m.pins.last() {
                    m.dropped = !pin
                        .body()
                        .members()
                        .iter()
                        .any(|cm| cm.node == Signers::did(1));
                }
                // The candidate record on disk is the durable truth: digest
                // AND the receipt flag (I6 survives every reopen).
                m.pending = parsed.as_ref().and_then(|p| p.candidate);
                assert_eq!(
                    store.pending_candidate().map(|(d, _)| d),
                    m.pending.map(|(d, _)| d),
                    "seed {seed} step {step}: disk candidate ≠ exposed candidate"
                );
                // A reopened candidate must be the pin's successor — open's
                // own convergence rule, asserted here too.
                if let (Some((d, _)), Some(pin)) = (m.pending, m.pins.last()) {
                    let signed = &m.signed[d.as_bytes()];
                    assert_eq!(
                        signed.body.previous(),
                        Some(&pin.digest()),
                        "seed {seed} step {step}: reopened candidate is not the pin's successor"
                    );
                }
                // The admissible ceremony is persisted on disk; a reverted
                // id whose predecessor is again the pin may install, any
                // other is contextually stale and must be refused.
                m.active = parsed.and_then(|p| p.active);
            }

            /// The disk must be byte-for-byte what open found when the
            /// outcome is a freeze: open freezes in place — nothing is
            /// erased or rewritten once equivocation is discovered.
            fn assert_frozen_outcome(
                &self,
                seed: u64,
                step: usize,
                files_before: &BTreeSet<[u8; 32]>,
                state_before: &Option<Vec<u8>>,
            ) {
                let store = self.store.as_ref().unwrap();
                if !store.equivocation() {
                    return;
                }
                let files_after = self.share_files();
                for d in files_before {
                    assert!(
                        files_after.contains(d),
                        "seed {seed} step {step}: frozen open erased a share"
                    );
                }
                let state_after = fs::read(self.ndir().join("state")).ok();
                if let Some(before) = state_before {
                    assert_eq!(
                        before.as_slice(),
                        state_after.as_deref().unwrap_or(&[]),
                        "seed {seed} step {step}: frozen open rewrote state"
                    );
                }
            }
        }

        impl<'a> Runner<'a> {
            /// Reopen the store. The snapshot is taken BEFORE open so the
            /// frozen path can prove nothing present before was lost and a
            /// lawful refusal can roll the disk back entirely.
            fn reopen(&mut self, seed: u64, step: usize) {
                let files_before = self.share_files();
                let state_before = fs::read(self.ndir().join("state")).ok();
                self.store = None;
                match ShareStore::open(
                    self.dir,
                    &self.network,
                    self.signers.anchor().clone(),
                    Signers::did(1),
                    self.signers,
                ) {
                    Ok(store) => {
                        self.store = Some(store);
                        self.assert_frozen_outcome(seed, step, &files_before, &state_before);
                        // Undo any permission fault the injected damage
                        // left: open repaired what it needed; the rest is
                        // the harness's job.
                        make_writable(&self.ndir());
                        self.resync(seed, step);
                        // Open idempotence: while the store is not frozen,
                        // open∘open is byte-identical with open — the second
                        // open rewrites nothing on disk.
                        if !self.model.frozen && self.rng.pick(5) == 0 {
                            let before = fs::read(self.ndir().join("state")).unwrap();
                            self.store = None;
                            self.store = Some(
                                ShareStore::open(
                                    self.dir,
                                    &self.network,
                                    self.signers.anchor().clone(),
                                    Signers::did(1),
                                    self.signers,
                                )
                                .unwrap_or_else(|e| {
                                    panic!("seed {seed} step {step}: idempotent reopen: {e:?}")
                                }),
                            );
                            let after = fs::read(self.ndir().join("state")).unwrap();
                            assert_eq!(
                                before, after,
                                "seed {seed} step {step}: second open rewrote state"
                            );
                        }
                    }
                    Err(e) => {
                        // Lawful refusals: disk damage the store must not
                        // guess past — a torn or unparsable `state`, a
                        // receipted candidate whose share file is gone, an
                        // activated pin whose share is missing (the member
                        // promised a share it cannot serve), or a pin's
                        // proof lost with it (equivocation evidence must
                        // not be silently dropped either).
                        let parsed = fs::read(self.ndir().join("state"))
                            .ok()
                            .and_then(|b| parse_state(&b));
                        let lawful = match &parsed {
                            None => true,
                            Some(p) => {
                                if let StoreError::Io(io) = &e {
                                    // A read-only-dir (or similar) fault:
                                    // the store may fail anywhere on the
                                    // path it can no longer write.
                                    matches!(
                                        io.kind(),
                                        std::io::ErrorKind::PermissionDenied
                                            | std::io::ErrorKind::ReadOnlyFilesystem
                                    )
                                } else if !matches!(e, StoreError::Corrupt) {
                                    false
                                } else if p.candidate.is_some_and(|(d, sent)| {
                                    sent && (!share_path(&self.ndir(), &d).exists()
                                        || !proof_path(&self.ndir(), &d).exists())
                                }) {
                                    true
                                } else {
                                    // A recorded pin the store can no
                                    // longer serve — its share is gone —
                                    // or prove: its own proof or any
                                    // ancestor's proof up to genesis was
                                    // lost while the member was offline.
                                    p.pin.is_some_and(|d| {
                                        !share_path(&self.ndir(), &d).exists()
                                            || !self.pin_is_provable(&d)
                                    })
                                }
                            }
                        };
                        assert!(
                            lawful,
                            "seed {seed} step {step}: reopen failed: {e:?} \
                             parsed={:?} shares={:?} proofs={:?}",
                            parsed,
                            self.share_files()
                                .iter()
                                .map(|d| hex(d))
                                .collect::<Vec<_>>(),
                            fs::read_dir(self.ndir().join("proofs"))
                                .map(|rd| rd
                                    .flatten()
                                    .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                                    .collect::<Vec<_>>())
                                .unwrap_or_default()
                        );
                        // The store refused honestly; a real deployment
                        // recovers from backup. Roll the disk back to the
                        // pre-fault snapshot and continue the run.
                        if self.backup.is_some() {
                            self.restore_disk();
                            self.recoveries += 1;
                        }
                        self.store = Some(
                            ShareStore::open(
                                self.dir,
                                &self.network,
                                self.signers.anchor().clone(),
                                Signers::did(1),
                                self.signers,
                            )
                            .unwrap_or_else(|e| {
                                panic!("seed {seed} step {step}: restored disk refused: {e:?}")
                            }),
                        );
                        self.resync(seed, step);
                    }
                }
            }
        }

        /// Encode `state` in the pre-release version-1 layout (everything
        /// except the `active_ceremony` option) to probe legacy decoding.
        fn encode_state_v1(state: &State) -> Vec<u8> {
            let mut e = Encoder::new();
            e.u8(1);
            e.u8(u8::from(state.pin.is_some()));
            if let Some(pin) = state.pin {
                e.fixed(pin.as_bytes());
            }
            e.u8(u8::from(state.candidate.is_some()));
            if let Some(candidate) = &state.candidate {
                e.fixed(candidate.digest.as_bytes());
                e.fixed(candidate.ceremony.as_bytes());
                e.u8(u8::from(candidate.predecessor.is_some()));
                if let Some(predecessor) = candidate.predecessor {
                    e.fixed(predecessor.as_bytes());
                }
                e.u8(u8::from(candidate.receipt_sent));
            }
            e.u32(state.seen_ceremonies.len() as u32);
            for id in &state.seen_ceremonies {
                e.fixed(id.as_bytes());
            }
            e.u32(state.retired.len() as u32);
            for retired in &state.retired {
                e.fixed(retired.digest.as_bytes());
                e.u64(retired.erased_at);
            }
            e.u64(state.seq);
            e.finish()
        }

        /// One seeded run: genesis activation, then `steps` weighted random
        /// operations with boundary assertions after every single step.
        fn run_seed(dir: &Path, signers: &Signers, seed: u64, steps: usize) {
            let network = signers.anchor().network.clone();
            let mut runner = Runner {
                signers,
                dir,
                network: network.clone(),
                store: Some(open(dir, signers)),
                model: Model::default(),
                rng: Rng(seed),
                snapshots: VecDeque::new(),
                transcript: 63,
                executed: 0,
                recoveries: 0,
                ops: BTreeMap::new(),
                backup: None,
                fork_allowed: seed % 4 != 3,
            };
            let (signed, cert) = activated_genesis(runner.store.as_ref().unwrap(), signers);
            runner.model.pins.push(cert);
            runner
                .model
                .signed
                .insert(*signed.body.digest().as_bytes(), signed);
            let genesis_ceremony = signers.genesis();
            runner.model.seen.push(genesis_ceremony.statement().id);
            runner.model.ceremonies.push(genesis_ceremony);
            runner.snapshot();

            for step in 0..steps {
                // Every step executes a real op or a deliberate no-op;
                // a lawful refusal is rolled back and the run continues.
                let frozen = runner.model.frozen;
                let pending = runner.model.pending;
                let fork_allowed = runner.fork_allowed;
                let roll = runner.rng.pick(100);
                match roll {
                    // Fresh accept + install under the admissible id.
                    0..=21 if !frozen => {
                        runner.mark_op("accept_install");
                        if let Some(ceremony) = runner.accept(seed, step) {
                            runner.install(seed, step, &ceremony);
                        }
                    }
                    // Accept only (candidate window stays empty).
                    22..=29 if !frozen => {
                        runner.mark_op("accept");
                        runner.accept(seed, step);
                    }
                    // Replay or stale accept: a seen id whose context still
                    // matches the pin replays (informational — the stale
                    // install op proves it can never install); a contextually
                    // stale id is refused outright.
                    30..=37 if !frozen => {
                        runner.mark_op("accept_stale");
                        let n = runner.model.ceremonies.len();
                        if n > 0 {
                            let ceremony =
                                runner.model.ceremonies[runner.rng.pick(n as u64) as usize].clone();
                            let pin = runner.model.pins.last().unwrap().digest();
                            let expect_replay = ceremony.statement().current == Some(pin);
                            match runner.store().accept_ceremony(&ceremony) {
                                Ok(AcceptOutcome::Replay) if expect_replay => {}
                                Err(e) if !expect_replay && matches!(e, StoreError::Crypto(_)) => {}
                                other => panic!(
                                    "seed {seed} step {step}: stale/replay accept gave {other:?}"
                                ),
                            }
                        }
                    }
                    // Stale install: any non-admissible ceremony id —
                    // including retired ones — must fail.
                    38..=41 if !frozen => {
                        runner.mark_op("install_stale");
                        let stale: Vec<AuthorizedCeremony> = runner
                            .model
                            .ceremonies
                            .iter()
                            .filter(|c| {
                                runner.model.active.map(|(id, _)| id) != Some(c.statement().id)
                            })
                            .cloned()
                            .collect();
                        if !stale.is_empty() {
                            let ceremony =
                                stale[runner.rng.pick(stale.len() as u64) as usize].clone();
                            // The certificate only has to be a valid pin
                            // successor; the stale ceremony argument is what
                            // the admissible-id check refuses first.
                            let construction = runner.fresh_ceremony();
                            let (signed, raw) = runner.fresh_signed(&construction);
                            let candidate = mk_candidate(raw, &signed.body);
                            assert!(
                                runner
                                    .store()
                                    .install_candidate(&signed, candidate, &ceremony, signers)
                                    .is_err(),
                                "seed {seed} step {step}: stale ceremony id installed"
                            );
                        }
                    }
                    // Install under the admissible id when none is pending.
                    // The restored record binds the pin it was accepted for:
                    // if a crash revert moved the pin past it the id is
                    // contextually stale and must be refused, never built.
                    44..=51 if !frozen && pending.is_none() => {
                        runner.mark_op("install_admissible");
                        if let Some((id, pred)) = runner.model.active {
                            let pin = runner.model.pins.last().unwrap().digest();
                            let ceremony = runner
                                .model
                                .ceremonies
                                .iter()
                                .find(|c| c.statement().id == id)
                                .unwrap()
                                .clone();
                            if pred == Some(pin) {
                                runner.install(seed, step, &ceremony);
                            } else {
                                let construction = runner.fresh_ceremony();
                                let (signed, raw) = runner.fresh_signed(&construction);
                                let candidate = mk_candidate(raw, &signed.body);
                                assert!(
                                    runner
                                        .store()
                                        .install_candidate(&signed, candidate, &ceremony, signers)
                                        .is_err(),
                                    "seed {seed} step {step}: pin-stale ceremony id installed"
                                );
                            }
                        }
                    }
                    // Rule 6: receipt only over a durable share.
                    52..=59 if !frozen && pending.is_some() => {
                        runner.mark_op("receipt");
                        runner
                            .store()
                            .mark_receipt_sent()
                            .unwrap_or_else(|e| panic!("seed {seed} step {step}: receipt: {e:?}"));
                        runner.model.pending = pending.map(|(d, _)| (d, true));
                    }
                    // Verified activation: the only legal pin advance.
                    60..=73 if !frozen && pending.is_some() => {
                        runner.mark_op("activate");
                        let (digest, _) = pending.unwrap();
                        let signed = runner.model.signed[digest.as_bytes()].clone();
                        let cert =
                            verify_successor(runner.model.pins.last().unwrap(), &signed, signers)
                                .unwrap();
                        let receipts = receipts_for(&cert, signers);
                        let activation = activation_for(&cert, &receipts, signers);
                        runner
                            .store()
                            .record_activation(&signed, &activation, &receipts, signers)
                            .unwrap_or_else(|e| {
                                panic!("seed {seed} step {step}: activation: {e:?}")
                            });
                        if let Some(old) = runner.model.pins.last() {
                            runner.model.retired.insert(*old.digest().as_bytes());
                        }
                        runner.model.pins.push(cert);
                        // The new pin may re-admit or still exclude this
                        // node — recompute, never carry stale.
                        runner.model.dropped = !runner
                            .model
                            .pins
                            .last()
                            .unwrap()
                            .body()
                            .members()
                            .iter()
                            .any(|cm| cm.node == Signers::did(1));
                        runner.model.pending = None;
                        runner.model.active = None;
                    }
                    // Fork evidence — rare, and gated per seed so most runs
                    // stay long-lived. Two paths: an activated sibling or
                    // second genesis proof written to disk (discovered at
                    // next open), or a live record_activation fork.
                    68..=70 if !frozen && fork_allowed => {
                        runner.mark_op("fork");
                        let live = runner.rng.pick(3) == 0;
                        let genesis_fork = runner.model.pins.len() < 2 || runner.rng.pick(3) == 0;
                        let (signed, cert, receipts, activation) = if genesis_fork {
                            // A second activated genesis is equivocation at
                            // the chain root.
                            let ceremony = signers.genesis();
                            let (public, _shares) =
                                cert_tests::material(17, Threshold::new(2, 3).unwrap());
                            let body = CertificateBody::genesis(
                                &signers.anchor(),
                                &ceremony,
                                &public,
                                &TranscriptHash::new([0xF1; 32]),
                            )
                            .unwrap();
                            let signed = cert::tests::sign(body, signers);
                            let cert =
                                verify_certificate(&signers.anchor(), &signed, signers).unwrap();
                            let receipts = receipts_for(&cert, signers);
                            let activation = activation_for(&cert, &receipts, signers);
                            (signed, cert, receipts, activation)
                        } else {
                            let i =
                                1 + runner.rng.pick((runner.model.pins.len() - 1) as u64) as usize;
                            let pred = runner.model.pins[i - 1].clone();
                            // A disk-discovered pin (member-drop) may have
                            // no locally-accepted ceremony to fork under —
                            // skip when the scheduler can't build one.
                            let Some(ceremony) = runner
                                .model
                                .ceremonies_by_pred
                                .get(pred.digest().as_bytes())
                                .cloned()
                            else {
                                continue;
                            };
                            runner.transcript = runner.transcript.wrapping_add(1);
                            let signed =
                                sibling_successor(signers, &pred, &ceremony, runner.transcript);
                            let cert = verify_successor(&pred, &signed, signers).unwrap();
                            let receipts = receipts_for(&cert, signers);
                            let activation = activation_for(&cert, &receipts, signers);
                            (signed, cert, receipts, activation)
                        };
                        runner
                            .model
                            .signed
                            .insert(*cert.digest().as_bytes(), signed.clone());
                        if live && !genesis_fork {
                            // The live path: the store itself detects and
                            // persists the fork, then freezes.
                            assert!(matches!(
                                runner.store().record_activation(
                                    &signed,
                                    &activation,
                                    &receipts,
                                    signers
                                ),
                                Err(StoreError::Equivocation)
                            ));
                            runner.reopen(seed, step);
                        } else {
                            let path = proof_path(&runner.ndir(), &cert.digest());
                            fs::write(&path, encode_proof(&signed, Some(&activation), &receipts))
                                .unwrap();
                            runner.reopen(seed, step);
                        }
                        assert!(
                            runner.model.frozen,
                            "seed {seed} step {step}: activated fork did not freeze"
                        );
                    }
                    // Proof-file loss: an activated certificate's proof
                    // disappears before reopen — convergence to an earlier
                    // crash-free point, never corruption.
                    71..=73 => {
                        runner.mark_op("proof_loss");
                        let proofs: Vec<PathBuf> = fs::read_dir(runner.ndir().join("proofs"))
                            .map(|rd| rd.flatten().map(|e| e.path()).collect())
                            .unwrap_or_default();
                        if !proofs.is_empty() {
                            runner.store = None;
                            runner.save_disk();
                            let path =
                                proofs[runner.rng.pick(proofs.len() as u64) as usize].clone();
                            let _ = fs::remove_file(path);
                            runner.reopen(seed, step);
                        }
                    }
                    // Resurrection probe: a retired certificate must never
                    // reinstall, even under the admissible ceremony id.
                    74..=77 if !frozen && runner.model.pending.is_none() => {
                        runner.mark_op("resurrect_probe");
                        let pin = runner.model.pins.last().map(|p| p.digest());
                        let candidates: Vec<SignedCertificate> = runner
                            .model
                            .retired
                            .iter()
                            .filter_map(|d| runner.model.signed.get(d))
                            .filter(|s| s.body.previous().copied() == pin)
                            .cloned()
                            .collect();
                        if let (Some((id, _)), false) = (runner.model.active, candidates.is_empty())
                        {
                            let signed = candidates
                                [runner.rng.pick(candidates.len() as u64) as usize]
                                .clone();
                            let ceremony = runner
                                .model
                                .ceremonies
                                .iter()
                                .find(|c| c.statement().id == id)
                                .unwrap()
                                .clone();
                            let (_, mut shares) =
                                cert_tests::material(11, Threshold::new(2, 3).unwrap());
                            let candidate = mk_candidate(shares.remove(0), &signed.body);
                            assert!(
                                matches!(
                                    runner
                                        .store()
                                        .install_candidate(&signed, candidate, &ceremony, signers),
                                    Err(StoreError::Retired)
                                ),
                                "seed {seed} step {step}: retired certificate reinstalled"
                            );
                            // The activation path must refuse a retired
                            // digest too (C1/C2): an erased share can never
                            // be re-pinned by a late record_activation.
                            let cert = verify_successor(
                                runner.model.pins.last().unwrap(),
                                &signed,
                                signers,
                            )
                            .unwrap();
                            let receipts = receipts_for(&cert, signers);
                            let activation = activation_for(&cert, &receipts, signers);
                            assert!(
                                matches!(
                                    runner.store().record_activation(
                                        &signed,
                                        &activation,
                                        &receipts,
                                        signers
                                    ),
                                    Err(StoreError::Retired)
                                ),
                                "seed {seed} step {step}: retired certificate reactivated"
                            );
                        }
                    }
                    // Rule 10: a second opener is Busy and changes nothing
                    // on disk.
                    78..=83 => {
                        runner.mark_op("busy");
                        let before = runner.disk_hash();
                        assert!(matches!(
                            ShareStore::open(
                                dir,
                                &network,
                                signers.anchor().clone(),
                                Signers::did(1),
                                signers
                            ),
                            Err(StoreError::Busy)
                        ));
                        assert_eq!(
                            runner.disk_hash(),
                            before,
                            "seed {seed} step {step}: Busy opener mutated the disk"
                        );
                    }
                    // Clean reopen.
                    84..=88 => {
                        runner.mark_op("reopen");
                        runner.reopen(seed, step);
                    }
                    // Member-drop: a reshared certificate that no longer
                    // names this node arrives as activated proof. The pin
                    // must advance to it — the member's share is then owed
                    // to nobody and nothing about it is corruption.
                    89..=91 if !frozen => {
                        runner.mark_op("member_drop");
                        let pin = runner.model.pins.last().unwrap().clone();
                        let mut stmt =
                            signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
                        runner.transcript = runner.transcript.wrapping_add(1).max(64);
                        let mut id_bytes = [0x70u8; 32];
                        id_bytes[0] = 0x70 ^ runner.transcript;
                        id_bytes[31] = runner.transcript;
                        stmt.id = CeremonyId::new(id_bytes);
                        stmt.current = Some(pin.digest());
                        stmt.epoch = pin.body().epoch().checked_next().unwrap();
                        stmt.rekey = pin.body().rekey();
                        stmt.recipients = (1..=3u16)
                            .map(|i| CeremonyRecipient {
                                index: MemberIndex::new(i).unwrap(),
                                node: Signers::did(i as u8 + 1),
                                hpke_public_key: [(i as u8) + 1; 32],
                            })
                            .collect();
                        let ceremony = AuthorizedCeremony::verify_for(
                            &pin,
                            &signers.statement(&stmt),
                            signers,
                        )
                        .unwrap();
                        let body = CertificateBody::successor(
                            &pin,
                            &ceremony,
                            &cert_tests::material(11, Threshold::new(2, 3).unwrap()).0,
                            &TranscriptHash::new([runner.transcript; 32]),
                        )
                        .unwrap();
                        let signed = cert::tests::sign(body, signers);
                        let cert = verify_successor(&pin, &signed, signers).unwrap();
                        let receipts = receipts_for(&cert, signers);
                        let activation = activation_for(&cert, &receipts, signers);
                        runner
                            .model
                            .signed
                            .insert(*cert.digest().as_bytes(), signed.clone());
                        fs::write(
                            proof_path(&runner.ndir(), &cert.digest()),
                            encode_proof(&signed, Some(&activation), &receipts),
                        )
                        .unwrap();
                        let old = pin.digest();
                        runner.reopen(seed, step);
                        runner.model.retired.insert(*old.as_bytes());
                        assert!(
                            runner.model.dropped || runner.model.frozen,
                            "seed {seed} step {step}: member-drop pin not adopted"
                        );
                    }
                    // Crash replays and disk damage. The disk is backed up
                    // BEFORE the fault so a lawful refusal can roll it back
                    // and the run can continue (a real deployment restores
                    // from backup the same way).
                    _ => {
                        runner.mark_op("crash");
                        runner.save_disk();
                        match runner.rng.pick(9) {
                            0 if !runner.snapshots.is_empty() => {
                                runner.store = None;
                                let i = runner.rng.pick(runner.snapshots.len() as u64) as usize;
                                let bytes = runner.snapshots[i].clone();
                                fs::write(runner.ndir().join("state"), &bytes).unwrap();
                            }
                            1 => {
                                let n = runner.model.seen.len();
                                if n > 0 {
                                    let id = runner.model.seen[runner.rng.pick(n as u64) as usize];
                                    let marker =
                                        runner.ndir().join("dealt").join(hex(id.as_bytes()));
                                    let _ = fs::remove_file(marker);
                                }
                            }
                            2 => {
                                runner.store = None;
                                let debris = runner
                                    .ndir()
                                    .join(format!("share-{}.tmp-1-9", hex(&[0xAB; 32])));
                                fs::write(&debris, [0x55u8; 67]).unwrap();
                            }
                            3 => {
                                // A torn `state`: atomic renames make this
                                // disk damage, so open must refuse — never
                                // adopt a truncated record.
                                runner.store = None;
                                let state = runner.ndir().join("state");
                                if let Ok(bytes) = fs::read(&state) {
                                    if bytes.len() > 4 {
                                        fs::write(&state, &bytes[..bytes.len() / 2]).unwrap();
                                    }
                                }
                            }
                            4 => {
                                // Delete a share file the state does not
                                // record: unrecorded disk damage.
                                runner.store = None;
                                let live: BTreeSet<[u8; 32]> = {
                                    let mut s = BTreeSet::new();
                                    if let Some(p) = runner.model.pins.last() {
                                        s.insert(*p.digest().as_bytes());
                                    }
                                    if let Some((d, _)) = runner.model.pending {
                                        s.insert(*d.as_bytes());
                                    }
                                    s
                                };
                                let victims: Vec<PathBuf> = fs::read_dir(runner.ndir())
                                    .map(|rd| {
                                        rd.flatten()
                                            .filter(|e| {
                                                e.file_name()
                                                    .to_str()
                                                    .and_then(|n| n.strip_prefix("share-"))
                                                    .and_then(decode_hex)
                                                    .is_some_and(|d| !live.contains(&d))
                                            })
                                            .map(|e| e.path())
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                if !victims.is_empty() {
                                    let _ = fs::remove_file(
                                        &victims[runner.rng.pick(victims.len() as u64) as usize],
                                    );
                                }
                            }
                            5 => {
                                // The pin's share file is lost: the store
                                // promised a share it can no longer serve —
                                // open must refuse, then restore.
                                runner.store = None;
                                if let Some(p) = runner.model.pins.last() {
                                    let _ =
                                        fs::remove_file(share_path(&runner.ndir(), &p.digest()));
                                }
                                if runner.model.frozen {
                                    runner.model.frozen_files = Some(runner.share_files());
                                }
                            }
                            6 => {
                                // The pin's proof AND share are lost
                                // together: the activated record cannot be
                                // proven or served — refuse, then restore.
                                runner.store = None;
                                if let Some(p) = runner.model.pins.last() {
                                    let _ =
                                        fs::remove_file(share_path(&runner.ndir(), &p.digest()));
                                    let _ =
                                        fs::remove_file(proof_path(&runner.ndir(), &p.digest()));
                                }
                                if runner.model.frozen {
                                    runner.model.frozen_files = Some(runner.share_files());
                                }
                            }
                            #[cfg(unix)]
                            7 => {
                                // Read-only directories: writes fail
                                // anywhere on the path; a refusal is lawful
                                // and the disk rolls back.
                                use std::os::unix::fs::PermissionsExt;
                                runner.store = None;
                                for sub in [
                                    runner.ndir(),
                                    runner.ndir().join("proofs"),
                                    runner.ndir().join("dealt"),
                                ] {
                                    let _ = fs::set_permissions(
                                        &sub,
                                        fs::Permissions::from_mode(0o500),
                                    );
                                }
                            }
                            8 => {
                                // Compound damage: `state` reverted AND the
                                // pin's share file lost — whichever the
                                // store sees first, the outcome stays
                                // lawful.
                                runner.store = None;
                                if !runner.snapshots.is_empty() {
                                    let i = runner.rng.pick(runner.snapshots.len() as u64) as usize;
                                    let bytes = runner.snapshots[i].clone();
                                    fs::write(runner.ndir().join("state"), &bytes).unwrap();
                                }
                                if let Some(p) = runner.model.pins.last() {
                                    let _ =
                                        fs::remove_file(share_path(&runner.ndir(), &p.digest()));
                                }
                            }
                            _ => runner.store = None,
                        }
                        runner.reopen(seed, step);
                    }
                }
                runner.assert_boundary(seed, step);
                runner.snapshot();
            }
            eprintln!(
                "model seed {seed}: {} steps executed ({} recoveries) ops={:?} frozen={}",
                runner.executed, runner.recoveries, runner.ops, runner.model.frozen
            );
            assert!(
                runner.executed >= steps * 2 / 3,
                "seed {seed}: only {} of {steps} steps executed",
                runner.executed
            );
        }

        /// Legacy `state` files must be handled explicitly: anything but the
        /// current version is refused at decode, never silently upgraded.
        /// Details: TC-2221
        #[test]
        fn legacy_state_versions_are_refused_explicitly() {
            let signers = Signers::new();
            let dir = tmpdir();
            let network = signers.anchor().network.clone();
            {
                let store = open(&dir, &signers);
                activated_genesis(&store, &signers);
                let state = store.inner.lock().unwrap().state.clone();
                drop(store);
                // Version 1 (pre-release, no admissible-ceremony slot).
                fs::write(
                    netdir(&dir, &network).join("state"),
                    encode_state_v1(&state),
                )
                .unwrap();
                assert!(ShareStore::open(
                    &dir,
                    &network,
                    signers.anchor().clone(),
                    Signers::did(1),
                    &signers
                )
                .is_err());
                // Version 2 (no predecessor on retired entries).
                let mut v2 = encode_state(&state);
                v2[0] = 2;
                fs::write(netdir(&dir, &network).join("state"), &v2).unwrap();
                assert!(ShareStore::open(
                    &dir,
                    &network,
                    signers.anchor().clone(),
                    Signers::did(1),
                    &signers
                )
                .is_err());
                // Unknown future version.
                let mut future = encode_state(&state);
                future[0] = 4;
                fs::write(netdir(&dir, &network).join("state"), &future).unwrap();
                assert!(ShareStore::open(
                    &dir,
                    &network,
                    signers.anchor().clone(),
                    Signers::did(1),
                    &signers
                )
                .is_err());
            }
        }

        #[test]
        fn seeded_model_invariants_hold_across_crashes() {
            // Debug builds pay full fsync + verify cost per step, so CI runs
            // a bounded slice; the release suite sweeps the wider seed space.
            // Replay any failure with the printed seed.
            let seeds: u64 = if cfg!(debug_assertions) { 4 } else { 64 };
            for seed in 0..seeds {
                let signers = Signers::new();
                let dir = tmpdir();
                run_seed(&dir, &signers, seed, 220);
            }
        }
    }

    /// P1-a: a frozen reopen keeps the recorded verified pin and erases
    /// NOTHING — the member's last share is never lost to a fork.
    /// Details: TC-2221
    #[test]
    fn frozen_reopen_keeps_pin_and_every_share() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let digest_a;
        let digest_z;
        {
            let store = open(&dir, &signers);
            let (_signed_g, cert_g) = activated_genesis(&store, &signers);
            // A: activated candidate (retires G); Z: receipted candidate on A.
            let (s_a, mut raw_a, c_a) = cert_tests::successor(
                &signers,
                &cert_g,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            store.accept_ceremony(&c_a).unwrap();
            store
                .install_candidate(
                    &s_a,
                    mk_candidate(raw_a.remove(0), &s_a.body),
                    &c_a,
                    &signers,
                )
                .unwrap();
            store.mark_receipt_sent().unwrap();
            let cert_a = verify_successor(&cert_g, &s_a, &signers).unwrap();
            digest_a = cert_a.digest();
            let receipts_a = receipts_for(&cert_a, &signers);
            let activation_a = activation_for(&cert_a, &receipts_a, &signers);
            store
                .record_activation(&s_a, &activation_a, &receipts_a, &signers)
                .unwrap();
            let mut stmt_z = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
            stmt_z.id = CeremonyId::new([0x62; 32]);
            stmt_z.current = Some(cert_a.digest());
            stmt_z.epoch = cert_a.body().epoch().checked_next().unwrap();
            stmt_z.rekey = cert_a.body().rekey();
            let c_z =
                AuthorizedCeremony::verify_for(&cert_a, &signers.statement(&stmt_z), &signers)
                    .unwrap();
            let body_z = CertificateBody::successor(
                &cert_a,
                &c_z,
                &cert_tests::material(11, Threshold::new(2, 3).unwrap()).0,
                &TranscriptHash::new([0x5a; 32]),
            )
            .unwrap();
            let s_z = cert::tests::sign(body_z, &signers);
            let mut raw_z = cert_tests::material(11, Threshold::new(2, 3).unwrap()).1;
            store.accept_ceremony(&c_z).unwrap();
            digest_z = store
                .install_candidate(
                    &s_z,
                    mk_candidate(raw_z.remove(0), &s_z.body),
                    &c_z,
                    &signers,
                )
                .unwrap();
            store.mark_receipt_sent().unwrap();
            // Fork evidence: an activated sibling of A.
            let s_fork = sibling_successor(&signers, &cert_g, &c_a, 0xf0);
            let cert_f = verify_successor(&cert_g, &s_fork, &signers).unwrap();
            let receipts_f = receipts_for(&cert_f, &signers);
            let activation_f = activation_for(&cert_f, &receipts_f, &signers);
            assert!(matches!(
                store.record_activation(&s_fork, &activation_f, &receipts_f, &signers),
                Err(StoreError::Equivocation)
            ));
        }
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.equivocation());
        // The recorded pin stands — verified activated, never lowered.
        assert_eq!(store.pinned().unwrap().digest(), digest_a);
        // Nothing is erased while equivocated: A's share and the receipted
        // candidate's share both survive.
        let ndir = netdir(&dir, &network);
        assert!(ndir
            .join(format!("share-{}", hex(digest_a.as_bytes())))
            .exists());
        assert!(ndir
            .join(format!("share-{}", hex(digest_z.as_bytes())))
            .exists());
    }

    /// P1-b: a retired candidate certificate can never be reinstalled,
    /// even under the currently admissible ceremony. Details: TC-2221
    #[test]
    fn retired_candidate_cert_cannot_reinstall() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed_g, cert_g) = activated_genesis(&store, &signers);
        let (s_x, mut raw_x, c_x) = cert_tests::successor(
            &signers,
            &cert_g,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        store.accept_ceremony(&c_x).unwrap();
        let digest_x = store
            .install_candidate(
                &s_x,
                mk_candidate(raw_x.remove(0), &s_x.body),
                &c_x,
                &signers,
            )
            .unwrap();
        store.mark_receipt_sent().unwrap();
        // A fresh ceremony supersedes X (C1 retires and erases the share).
        let mut stmt_y = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt_y.id = CeremonyId::new([0x61; 32]);
        stmt_y.current = Some(cert_g.digest());
        stmt_y.epoch = cert_g.body().epoch().checked_next().unwrap();
        stmt_y.rekey = cert_g.body().rekey();
        let ceremony_y =
            AuthorizedCeremony::verify_for(&cert_g, &signers.statement(&stmt_y), &signers).unwrap();
        assert_eq!(
            store.accept_ceremony(&ceremony_y).unwrap(),
            AcceptOutcome::Fresh
        );
        assert!(store.retired().iter().any(|r| r.digest == digest_x));
        // Reinstalling X's certificate — the same cert whose share C1
        // erased — under the now-admissible ceremony must be refused.
        let (s_x2, mut raw_x2, _c) = cert_tests::successor(
            &signers,
            &cert_g,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        assert_eq!(s_x2.body.digest(), digest_x);
        assert!(matches!(
            store.install_candidate(
                &s_x2,
                mk_candidate(raw_x2.remove(0), &s_x2.body),
                &ceremony_y,
                &signers
            ),
            Err(StoreError::Retired)
        ));
    }

    /// The activation path obeys the retirement record too: a C1-retired
    /// candidate's certificate — still a valid successor of the pin — must
    /// never be re-pinned by a late `record_activation`. Details: TC-2221
    #[test]
    fn retired_candidate_cert_cannot_reactivate() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed_g, cert_g) = activated_genesis(&store, &signers);
        let (s_x, mut raw_x, c_x) = cert_tests::successor(
            &signers,
            &cert_g,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        store.accept_ceremony(&c_x).unwrap();
        let digest_x = store
            .install_candidate(
                &s_x,
                mk_candidate(raw_x.remove(0), &s_x.body),
                &c_x,
                &signers,
            )
            .unwrap();
        store.mark_receipt_sent().unwrap();
        // A fresh ceremony over the same pin retires and erases X (C1).
        let mut stmt_y = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt_y.id = CeremonyId::new([0x62; 32]);
        stmt_y.current = Some(cert_g.digest());
        stmt_y.epoch = cert_g.body().epoch().checked_next().unwrap();
        stmt_y.rekey = cert_g.body().rekey();
        let ceremony_y =
            AuthorizedCeremony::verify_for(&cert_g, &signers.statement(&stmt_y), &signers).unwrap();
        assert_eq!(
            store.accept_ceremony(&ceremony_y).unwrap(),
            AcceptOutcome::Fresh
        );
        assert!(store.retired().iter().any(|r| r.digest == digest_x));
        // X's certificate is still a perfectly valid successor of the pin;
        // the durable retirement record — not lineage — refuses it.
        let cert_x = verify_successor(&cert_g, &s_x, &signers).unwrap();
        let receipts = receipts_for(&cert_x, &signers);
        let activation = activation_for(&cert_x, &receipts, &signers);
        assert!(matches!(
            store.record_activation(&s_x, &activation, &receipts, &signers),
            Err(StoreError::Retired)
        ));
        // The pin did not move and the erased share stays erased.
        assert_eq!(store.pinned().map(|p| p.digest()), Some(cert_g.digest()));
        assert!(!share_path(&netdir(&dir, &signers.anchor().network), &digest_x).exists());
    }

    /// P3-1: an ACTIVATED proof for a retired certificate arriving on disk
    /// (peer sync, operator restore) while the store is closed must freeze
    /// the next open — the live path already refuses the same proof as
    /// `Retired`; reopening must never R1-erase the live pin share.
    /// Details: TC-2221
    #[test]
    fn activated_proof_of_retired_candidate_freezes_reopen() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let (s_x, digest_x, receipts_x, activation_x, cert_g) = {
            let store = open(&dir, &signers);
            let (_signed_g, cert_g) = activated_genesis(&store, &signers);
            let (s_x, mut raw_x, c_x) = cert_tests::successor(
                &signers,
                &cert_g,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
            store.accept_ceremony(&c_x).unwrap();
            let digest_x = store
                .install_candidate(
                    &s_x,
                    mk_candidate(raw_x.remove(0), &s_x.body),
                    &c_x,
                    &signers,
                )
                .unwrap();
            store.mark_receipt_sent().unwrap();
            // A fresh ceremony retires X (C1); the share is erased.
            let mut stmt_y = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
            stmt_y.id = CeremonyId::new([0x63; 32]);
            stmt_y.current = Some(cert_g.digest());
            stmt_y.epoch = cert_g.body().epoch().checked_next().unwrap();
            stmt_y.rekey = cert_g.body().rekey();
            let ceremony_y =
                AuthorizedCeremony::verify_for(&cert_g, &signers.statement(&stmt_y), &signers)
                    .unwrap();
            store.accept_ceremony(&ceremony_y).unwrap();
            assert!(store.retired().iter().any(|r| r.digest == digest_x));
            let cert_x = verify_successor(&cert_g, &s_x, &signers).unwrap();
            let receipts = receipts_for(&cert_x, &signers);
            let activation = activation_for(&cert_x, &receipts, &signers);
            (s_x, digest_x, receipts, activation, cert_g)
        };
        // An activated X proof lands on disk while the store is closed —
        // indistinguishable from peer sync or an operator restore.
        fs::write(
            proof_path(&netdir(&dir, &network), &digest_x),
            encode_proof(&s_x, Some(&activation_x), &receipts_x),
        )
        .unwrap();
        // Reopen: the chain now runs through a durably retired digest — the
        // store freezes; it must NOT advance the pin to X and erase G's
        // still-live share.
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.equivocation());
        assert!(matches!(
            store.current_share(),
            Err(StoreError::Equivocation)
        ));
        assert_eq!(store.pinned().map(|p| p.digest()), Some(cert_g.digest()));
        assert!(share_path(&netdir(&dir, &network), &cert_g.digest()).exists());
    }

    /// P3-2: a `*.tmp-*` name that is a HARDLINK — not a symlink — must be
    /// unlinked, never zeroed: writing zeros through the inode rewrites the
    /// file it shares storage with outside the store. Details: TC-2221
    #[test]
    #[cfg(unix)]
    fn hardlinked_temp_name_is_unlinked_never_zeroed() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let victim = dir.join("victim-share-backup");
        fs::write(&victim, [0x5Au8; 64]).unwrap();
        {
            let _store = open(&dir, &signers);
            activated_genesis(&_store, &signers);
            let link = netdir(&dir, &network).join("state.tmp-7-7");
            fs::hard_link(&victim, &link).unwrap();
        }
        // The sweep removes the link; the victim keeps its bytes.
        let _store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(!netdir(&dir, &network).join("state.tmp-7-7").exists());
        assert_eq!(fs::read(&victim).unwrap(), vec![0x5Au8; 64]);
    }

    /// P3-3: a second ACTIVATED genesis presented to the live store is the
    /// same equivocation evidence reopening freezes on — persist it and
    /// freeze; do not silently drop it. Details: TC-2221
    #[test]
    fn live_second_activated_genesis_persists_and_freezes() {
        let signers = Signers::new();
        let dir = tmpdir();
        let network = signers.anchor().network.clone();
        let store = open(&dir, &signers);
        let (_signed_g, cert_g) = activated_genesis(&store, &signers);
        // A second genesis certificate over the same ceremony.
        let ceremony = signers.genesis();
        let (public, _shares) = cert_tests::material(17, Threshold::new(2, 3).unwrap());
        let body = CertificateBody::genesis(
            &signers.anchor(),
            &ceremony,
            &public,
            &TranscriptHash::new([0xF2; 32]),
        )
        .unwrap();
        let signed = cert::tests::sign(body, &signers);
        let cert_g2 = verify_certificate(&signers.anchor(), &signed, &signers).unwrap();
        let receipts = receipts_for(&cert_g2, &signers);
        let activation = activation_for(&cert_g2, &receipts, &signers);
        assert!(matches!(
            store.record_activation(&signed, &activation, &receipts, &signers),
            Err(StoreError::Equivocation)
        ));
        assert!(store.equivocation());
        // The evidence is durable and the pin does not move.
        assert!(proof_path(&netdir(&dir, &network), &cert_g2.digest()).exists());
        drop(store);
        let store = ShareStore::open(
            &dir,
            &network,
            signers.anchor().clone(),
            Signers::did(1),
            &signers,
        )
        .unwrap();
        assert!(store.equivocation());
        assert_eq!(store.pinned().map(|p| p.digest()), Some(cert_g.digest()));
    }

    /// P3-4a: retirement history is audit data — it survives a pin advance
    /// (nothing is silently dropped), yet a retired digest still cannot
    /// come back. Compaction only evicts provably-dead entries when the
    /// list nears the bound. Details: TC-2221
    #[test]
    fn pin_advance_keeps_retirement_audit_without_resurrecting() {
        let signers = Signers::new();
        let dir = tmpdir();
        let store = open(&dir, &signers);
        let (_signed_g, cert_g) = activated_genesis(&store, &signers);
        // C1-retire candidate X under the genesis pin.
        let (s_x, mut raw_x, c_x) = cert_tests::successor(
            &signers,
            &cert_g,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
        store.accept_ceremony(&c_x).unwrap();
        let digest_x = store
            .install_candidate(
                &s_x,
                mk_candidate(raw_x.remove(0), &s_x.body),
                &c_x,
                &signers,
            )
            .unwrap();
        let mut stmt_y = signers.body(CeremonyKind::Reshare, Threshold::new(2, 3).unwrap());
        stmt_y.id = CeremonyId::new([0x64; 32]);
        stmt_y.current = Some(cert_g.digest());
        stmt_y.epoch = cert_g.body().epoch().checked_next().unwrap();
        stmt_y.rekey = cert_g.body().rekey();
        let ceremony_y =
            AuthorizedCeremony::verify_for(&cert_g, &signers.statement(&stmt_y), &signers).unwrap();
        store.accept_ceremony(&ceremony_y).unwrap();
        assert!(store.retired().iter().any(|r| r.digest == digest_x));
        // Activate successor Y under the same pin (reshare preserves mpk,
        // so Y reuses the genesis key material with a fresh transcript).
        let s_y = sibling_successor(&signers, &cert_g, &ceremony_y, 0x71);
        let (_pub_y, mut raw_y) = cert_tests::material(11, Threshold::new(2, 3).unwrap());
        store
            .install_candidate(
                &s_y,
                mk_candidate(raw_y.remove(0), &s_y.body),
                &ceremony_y,
                &signers,
            )
            .unwrap();
        store.mark_receipt_sent().unwrap();
        let cert_y = verify_successor(&cert_g, &s_y, &signers).unwrap();
        let receipts = receipts_for(&cert_y, &signers);
        let activation = activation_for(&cert_y, &receipts, &signers);
        store
            .record_activation(&s_y, &activation, &receipts, &signers)
            .unwrap();
        // Audit survives the pin advance; the record also carries the
        // predecessor it was retired against (needed by bounded pruning).
        let entry = store
            .retired()
            .into_iter()
            .find(|r| r.digest == digest_x)
            .expect("retirement audit must survive a pin advance");
        assert_eq!(entry.predecessor, Some(cert_g.digest()));
        // Reinstalling X is refused either way: the retirement record when
        // reachable, stale lineage after the pin moved.
        assert!(store
            .install_candidate(
                &s_x,
                mk_candidate(raw_x.remove(0), &s_x.body),
                &ceremony_y,
                &signers
            )
            .is_err());
    }

    /// P3-4c: at the bound, dead retirement records are compacted away
    /// while every reachable one is kept; a list of only reachable records
    /// reports overflow so the operation is refused. Details: TC-2221
    #[test]
    fn compact_retired_drops_only_dead_entries_at_the_bound() {
        let pin = CertDigest::new([0x10; 32]);
        let mut state = State {
            pin: Some(pin),
            candidate: None,
            active_ceremony: None,
            seen_ceremonies: Vec::new(),
            retired: Vec::new(),
            seq: 0,
        };
        // One reachable entry + a pile of dead ones.
        record_retired(&mut state, CertDigest::new([0xAA; 32]), Some(pin));
        for i in 0..(MAX_RETIRED + 8) {
            let mut bytes = [0u8; 32];
            bytes[31] = (i % 250) as u8;
            bytes[30] = (i / 250) as u8;
            record_retired(
                &mut state,
                CertDigest::new(bytes),
                Some(CertDigest::new([0xEE; 32])),
            );
        }
        assert!(compact_retired(&mut state, Some(pin)));
        assert_eq!(state.retired.len(), 1);
        assert_eq!(state.retired[0].predecessor, Some(pin));
        // Nothing but reachable entries left → the bound reports overflow.
        let mut full = state.clone();
        full.retired = (0..=MAX_RETIRED)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = (i % 250) as u8;
                bytes[30] = (i / 250) as u8;
                bytes[29] = 0xBB;
                RetiredGeneration {
                    digest: CertDigest::new(bytes),
                    predecessor: Some(pin),
                    erased_at: i as u64,
                }
            })
            .collect();
        assert!(!compact_retired(&mut full, Some(pin)));
    }

    /// P3-4b: the retired and seen-ceremony lists are bounded: decoding a
    /// state file claiming absurd lengths refuses rather than allocating,
    /// and the store itself never writes past its own caps. Details: TC-2221
    #[test]
    fn state_lists_are_bounded_at_decode() {
        // More retired entries than the decoder bound → refuse, never parse.
        let mut e = Encoder::new();
        e.u8(3);
        e.u8(0); // pin
        e.u8(0); // candidate
        e.u8(0); // active ceremony
        e.u32(0); // seen
        e.u32(1_000_001); // retired_count above the bound
        for _ in 0..100 {
            e.fixed(&[0xAB; 32]);
            e.u8(0);
            e.u64(0);
        }
        e.u64(0);
        assert!(decode_state(&e.finish()).is_err());
        let mut e = Encoder::new();
        e.u8(3);
        e.u8(0);
        e.u8(0);
        e.u8(0);
        e.u32(1_000_001); // seen above the bound
        e.u32(0);
        e.u64(0);
        assert!(decode_state(&e.finish()).is_err());
    }
}
