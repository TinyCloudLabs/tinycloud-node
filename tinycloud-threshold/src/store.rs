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
//! unlinked on any failure; the next open sweeps leftovers. The pin is the
//! highest certificate on the single chain verified from genesis through
//! `verify_activation` for every activated proof; a restart refuses a
//! recorded `state` pin the proofs cannot support. Shares are erased only
//! on positive proof — a verified activation that moves past them, a fresh
//! ceremony for their predecessor, or no record at all — and the `state`
//! record commits every removal before its file unlink, so a crash is
//! always recovered as "erasure owed", never as a missing promised share.

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

/// One retired generation. Details: TC-2221
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredGeneration {
    /// Retired certificate digest.
    pub digest: CertDigest,
    /// Retirement sequence counter for this member.
    pub erased_at: u64,
}

/// The pending candidate record.
#[derive(Clone, Debug)]
struct CandidateRecord {
    digest: CertDigest,
    ceremony: CeremonyId,
    predecessor: Option<CertDigest>,
    receipt_sent: bool,
}

#[derive(Clone, Debug, Default)]
struct State {
    pin: Option<CertDigest>,
    candidate: Option<CandidateRecord>,
    seen_ceremonies: Vec<CeremonyId>,
    retired: Vec<RetiredGeneration>,
    seq: u64,
}

fn encode_state(state: &State) -> Vec<u8> {
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
    // Ceremony ids and retired entries are bounded by the on-disk format cap
    // enforced in decode_state; u32 cannot overflow below memory limits.
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

fn decode_state(bytes: &[u8]) -> Result<State, StoreError> {
    let mut d = Decoder::new(bytes)?;
    if d.u8()? != 1 {
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
            erased_at: d.u64()?,
        });
    }
    let seq = d.u64()?;
    d.finish()?;
    Ok(State {
        pin,
        candidate,
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
    /// Activated equivocation froze the pin; further activations are refused.
    #[error("activated equivocation froze the pin")]
    Equivocation,
    /// Another `ShareStore` already holds this network's lock.
    #[error("share store is already open for this network")]
    Busy,
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
    if !path.exists() {
        return Ok(());
    }
    let length = usize::try_from(fs::metadata(path)?.len()).unwrap_or(usize::MAX);
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

fn record_retired(state: &mut State, digest: CertDigest) {
    state.seq = state.seq.saturating_add(1);
    state.retired.push(RetiredGeneration {
        digest,
        erased_at: state.seq,
    });
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
/// the network directory. Runs inside `open` after the lock is taken.
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
                let _ = erase_share_file(&entry.path());
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
        fs::create_dir_all(network_dir.join("proofs"))?;
        fs::create_dir_all(network_dir.join("dealt"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&network_dir, fs::Permissions::from_mode(0o700))?;
        }
        // Fsync every parent so the directory hierarchy itself is durable
        // even if power is lost before the first write completes.
        fs::File::open(&network_dir)?.sync_all()?;
        fs::File::open(dir)?.sync_all()?;

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
        lock_file.try_lock().map_err(|_| StoreError::Busy)?;

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
        let computed_pin = chain.last().copied();
        let pin = computed_pin.and_then(|d| verified.get(&d).cloned());

        // A recorded pin must be a verified activated certificate: either on
        // the surviving chain or an equivocated fork child. Anything else is
        // corruption.
        if let Some(recorded) = state.pin {
            if !verified.contains_key(&recorded) {
                return Err(StoreError::Corrupt);
            }
        }

        // Candidate reconciliation. Chain membership and C2 losses are
        // judged BEFORE the missing-file check: a candidate already retired
        // by durable proof is settled even when its share is gone, while a
        // still-live receipt-bearing candidate that lost its share is the
        // only case that is truly corrupt.
        let mut owed_erasures: Vec<PathBuf> = Vec::new();
        if let Some(candidate) = state.candidate.clone() {
            let share = share_path(&network_dir, &candidate.digest);
            let proof = proof_path(&network_dir, &candidate.digest);
            if chain.contains(&candidate.digest) {
                // Already activated before the crash; the chain is the record.
                state.candidate = None;
                state_dirty = true;
            } else {
                // C2: the candidate lost if its predecessor is covered by the
                // pin (any pin for a genesis predecessor) or the chain moved
                // past it through another certificate.
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
                    // Commit the retirement first; the unlink is owed work a
                    // crash simply re-discovers as S1.
                    record_retired(&mut state, candidate.digest);
                    state.candidate = None;
                    state.pin = computed_pin;
                    write_atomic(&network_dir.join("state"), &encode_state(&state))?;
                    owed_erasures.push(share);
                } else if !share.exists() || !proof.exists() {
                    if candidate.receipt_sent {
                        // A receipt was signed over a durable install; a
                        // missing file means the member promised what it
                        // cannot serve.
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
        // `state` before its unlink; files left by a crash re-enter here as
        // owed work on the next open.
        for entry in fs::read_dir(&network_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(hex_digest) = name.strip_prefix("share-") else {
                continue;
            };
            let Some(digest_bytes) = decode_hex(hex_digest) else {
                // An unnamed partial write (including .tmp leftovers) can
                // never have been recorded; S1 erases it.
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
                    record_retired(&mut state, digest);
                    state.pin = computed_pin;
                    write_atomic(&network_dir.join("state"), &encode_state(&state))?;
                    state_dirty = false;
                }
                owed_erasures.push(entry.path());
            } else {
                // Outside the activated chain and named in no record: S1
                // erases unconditionally (the pin's existence changes
                // nothing — such a file never had a durable install record).
                erase_share_file(&entry.path())?;
            }
        }

        if state.pin != computed_pin || state_dirty {
            state.pin = computed_pin;
            write_atomic(&network_dir.join("state"), &encode_state(&state))?;
        }

        // Owed unlinks run only after every corresponding `state` commit.
        for path in &owed_erasures {
            erase_share_file(path)?;
        }

        if state.pin != computed_pin || state_dirty {
            state.pin = computed_pin;
            write_atomic(&network_dir.join("state"), &encode_state(&state))?;
        }

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
        // The candidate may only be installed under a ceremony this store
        // accepted for the same predecessor.
        if ceremony.anchor() != &self.anchor
            || !inner
                .state
                .seen_ceremonies
                .contains(&ceremony.statement().id)
        {
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
        inner.state.candidate = Some(CandidateRecord {
            digest,
            ceremony: ceremony.statement().id,
            predecessor,
            receipt_sent: false,
        });
        write_atomic(&self.network_dir.join("state"), &encode_state(&inner.state))?;
        Ok(digest)
    }

    /// Record that this member's readiness receipt was sent. Details: TC-2221
    ///
    /// Called only after `install_candidate` committed; a restart that finds
    /// `receipt_sent` with a missing share file refuses to open.
    pub fn mark_receipt_sent(&self) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        let Some(candidate) = &mut inner.state.candidate else {
            return Err(StoreError::Corrupt);
        };
        candidate.receipt_sent = true;
        write_atomic(&self.network_dir.join("state"), &encode_state(&inner.state))
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
        let verified = match &inner.pin {
            Some(pin) => verify_successor(pin, signed, v)?,
            None => verify_certificate(&self.anchor, signed, v)?,
        };
        verify_activation(&verified, receipts, ReadyQuorum::AllHolders, activation, v)?;
        let digest = verified.digest();
        write_atomic(
            &proof_path(&self.network_dir, &digest),
            &encode_proof(signed, Some(activation), receipts),
        )?;
        // `state` commits every removal BEFORE the unlink, so a crash is
        // recovered as "erasure owed", never as a missing promised share.
        let mut erasures: Vec<PathBuf> = Vec::new();
        // C2: a pending candidate that lost to this activation is erased; the
        // winning candidate's record is cleared (the chain is its record).
        if let Some(candidate) = inner.state.candidate.take() {
            if candidate.digest != digest
                && !inner
                    .state
                    .retired
                    .iter()
                    .any(|r| r.digest == candidate.digest)
            {
                record_retired(&mut inner.state, candidate.digest);
                erasures.push(share_path(&self.network_dir, &candidate.digest));
            }
        }
        // R1: the outgoing pin's share is retired.
        if let Some(old_pin) = &inner.pin {
            let old = old_pin.digest();
            if !inner.state.retired.iter().any(|r| r.digest == old) {
                record_retired(&mut inner.state, old);
                erasures.push(share_path(&self.network_dir, &old));
            }
        }
        inner.pin = Some(verified.clone());
        inner.verified.insert(digest, verified);
        inner.state.pin = Some(digest);
        write_atomic(&self.network_dir.join("state"), &encode_state(&inner.state))?;
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
        // `state` commits the removal before the unlink and before the dealt
        // marker; a crash re-discovers the unlink as S1.
        let mut owed: Option<PathBuf> = None;
        if let Some(candidate) = &inner.state.candidate {
            if candidate.predecessor == statement.current {
                let digest = candidate.digest;
                record_retired(&mut inner.state, digest);
                inner.state.candidate = None;
                owed = Some(share_path(&self.network_dir, &digest));
            }
        }
        inner.state.seen_ceremonies.push(statement.id);
        write_atomic(&self.network_dir.join("state"), &encode_state(&inner.state))?;
        write_atomic(
            &self
                .network_dir
                .join("dealt")
                .join(hex(statement.id.as_bytes())),
            b"",
        )?;
        if let Some(path) = owed {
            erase_share_file(&path)?;
        }
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

    fn tmpdir() -> PathBuf {
        let tag = TAG.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("tc2221-store-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn netdir(dir: &Path, network: &NetworkUrn) -> PathBuf {
        store_dir(dir, network)
    }

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
            let (s_succ, _raw, _ceremony) = cert_tests::successor(
                &signers,
                &cert,
                CeremonyKind::Reshare,
                Threshold::new(2, 3).unwrap(),
                11,
            );
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
}
