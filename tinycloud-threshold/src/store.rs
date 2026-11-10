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
//! * `state`: versioned record of the pinned certificate, the pending
//!   candidate, accepted ceremony ids and retired generations.
//! * `proofs/<cert-digest>`: the signed certificate bytes plus, once
//!   activated, the owner activation statement and readiness receipts.
//! * `share-<cert-digest>`: `CandidateShare::to_bytes()` for this member's
//!   share under that certificate.
//! * `dealt/<ceremony-id>`: marker written before the first secret-bearing
//!   message of that ceremony leaves; the id is consumed forever.
//!
//! Every write is write-temp, fsync, rename, fsync-directory. The pin is the
//! highest-epoch certificate whose activation chain verifies from genesis; a
//! restart replays `proofs/` to recompute it and refuses a recorded `state`
//! pin the proofs cannot support. Shares are erased only on positive proof:
//! a verified activation that moves past them, a fresh ceremony for their
//! predecessor, or no record at all.

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
    ids::{CeremonyId, CertDigest, MemberIndex, NetworkUrn},
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
pub struct ShareStore {
    network_dir: PathBuf,
    anchor: TrustAnchor,
    inner: Mutex<Inner>,
}

struct Inner {
    state: State,
    pin: Option<VerifiedCertificate>,
    equivocation: bool,
}

fn create_file(path: &Path) -> Result<fs::File, StoreError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut file = create_file(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
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
            if name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
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
        let mut geneses: Vec<VerifiedCertificate> = Vec::new();
        for signed in proofs.values() {
            if signed.body.previous().is_some() || !activations.contains_key(&signed.body.digest())
            {
                continue;
            }
            geneses.push(verify_certificate(&anchor, signed, v)?);
        }
        geneses.sort_by(|a, b| a.digest().as_bytes().cmp(b.digest().as_bytes()));
        if geneses.len() > 1 {
            equivocation = true;
        }
        if let Some(first) = geneses.into_iter().next() {
            let mut current = first;
            chain.push(current.digest());
            verified.insert(current.digest(), current.clone());
            loop {
                let mut successors: Vec<VerifiedCertificate> = Vec::new();
                for signed in proofs.values() {
                    if signed.body.previous() != Some(&current.digest())
                        || !activations.contains_key(&signed.body.digest())
                    {
                        continue;
                    }
                    successors.push(verify_successor(&current, signed, v)?);
                }
                successors.sort_by(|a, b| a.digest().as_bytes().cmp(b.digest().as_bytes()));
                if successors.len() > 1 {
                    // The pin stops advancing at the fork.
                    equivocation = true;
                    break;
                }
                let Some(next) = successors.into_iter().next() else {
                    break;
                };
                let (statement, receipts) =
                    activations.get(&next.digest()).ok_or(StoreError::Corrupt)?;
                verify_activation(&next, receipts, ReadyQuorum::AllHolders, statement, v)?;
                verified.insert(next.digest(), next.clone());
                chain.push(next.digest());
                current = next;
            }
        }
        let computed_pin = chain.last().copied();
        let pin = computed_pin.and_then(|d| verified.get(&d).cloned());

        // A recorded pin the activated chain cannot prove is corruption.
        if let Some(recorded) = state.pin {
            if !chain.contains(&recorded) {
                return Err(StoreError::Corrupt);
            }
        }

        // Candidate reconciliation.
        if let Some(candidate) = state.candidate.clone() {
            let share = share_path(&network_dir, &candidate.digest);
            let proof = proof_path(&network_dir, &candidate.digest);
            if !share.exists() || !proof.exists() {
                if candidate.receipt_sent {
                    // A receipt was signed over a durable install; a missing
                    // file means the member promised what it cannot serve.
                    return Err(StoreError::Corrupt);
                }
                let _ = erase_share_file(&share);
                state.candidate = None;
                state_dirty = true;
            } else if chain.contains(&candidate.digest) {
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
                    erase_share_file(&share)?;
                    record_retired(&mut state, candidate.digest);
                    state.candidate = None;
                    state_dirty = true;
                }
            }
        }

        // R1 and S1 over share files.
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
            if chain.contains(&digest) {
                // Superseded activated generation (R1).
                erase_share_file(&entry.path())?;
                if !state.retired.iter().any(|r| r.digest == digest) {
                    record_retired(&mut state, digest);
                    state_dirty = true;
                }
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

        Ok(Self {
            network_dir,
            anchor,
            inner: Mutex::new(Inner {
                state,
                pin,
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
    pub fn current_share(&self) -> Result<Option<KeyShare>, StoreError> {
        let pin = self
            .inner
            .lock()
            .map_err(|_| StoreError::Corrupt)?
            .pin
            .clone();
        let Some(pin) = pin else { return Ok(None) };
        let path = share_path(&self.network_dir, &pin.digest());
        if !path.exists() {
            return Ok(None);
        }
        let bytes = Zeroizing::new(fs::read(path)?);
        let candidate = CandidateShare::from_bytes(&bytes)?;
        Ok(Some(KeyShare::bind(candidate, &pin)?))
    }

    /// The pending candidate's digest and member index, awaiting its
    /// readiness receipt. Details: TC-2221
    pub fn pending_candidate(&self) -> Option<(CertDigest, MemberIndex)> {
        let inner = self.inner.lock().ok()?;
        let candidate = inner.state.candidate.as_ref()?;
        let path = share_path(&self.network_dir, &candidate.digest);
        let bytes = fs::read(path).ok()?;
        let share = CandidateShare::from_bytes(&bytes).ok()?;
        Some((candidate.digest, share.index()))
    }

    /// Durably install a candidate share for `signed`. Details: TC-2221
    ///
    /// `signed` must verify as the successor of the current pin (or as a
    /// genesis before any pin). The candidate's bytes bind against the
    /// certificate, then proof and share are written before the state record:
    /// a crash before the record leaves orphan files the next open sweeps.
    /// Returns the candidate certificate digest.
    pub fn install_candidate(
        &self,
        signed: &SignedCertificate,
        candidate: CandidateShare,
        ceremony: &AuthorizedCeremony,
        v: &impl DidSignatureVerifier,
    ) -> Result<CertDigest, StoreError> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        if inner.state.candidate.is_some() {
            return Err(StoreError::CandidateExists);
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
        let bytes = candidate.to_bytes();
        let reloaded = CandidateShare::from_bytes(bytes.as_slice())?;
        // The written form must bind before it is persisted.
        let _bound = KeyShare::bind(reloaded, &verified)?;
        let digest = verified.digest();
        write_atomic(
            &proof_path(&self.network_dir, &digest),
            &encode_proof(signed, None, &[]),
        )?;
        write_atomic(&share_path(&self.network_dir, &digest), bytes.as_slice())?;
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
        // Idempotent: a certificate already activated on the pinned chain is
        // a no-op, so concurrent or replayed recordings converge.
        if inner
            .pin
            .as_ref()
            .is_some_and(|pin| pin.digest() == signed.body.digest())
        {
            return Ok(());
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
        // C2: a pending candidate that lost to this activation is erased; the
        // winning candidate's record is cleared (the chain is its record).
        if let Some(candidate) = inner.state.candidate.take() {
            if candidate.digest != digest {
                erase_share_file(&share_path(&self.network_dir, &candidate.digest))?;
                if !inner
                    .state
                    .retired
                    .iter()
                    .any(|r| r.digest == candidate.digest)
                {
                    record_retired(&mut inner.state, candidate.digest);
                }
            }
        }
        // R1: the outgoing pin's share is retired.
        if let Some(old_pin) = &inner.pin {
            let old = old_pin.digest();
            erase_share_file(&share_path(&self.network_dir, &old))?;
            if !inner.state.retired.iter().any(|r| r.digest == old) {
                record_retired(&mut inner.state, old);
            }
        }
        inner.pin = Some(verified);
        inner.state.pin = Some(digest);
        write_atomic(&self.network_dir.join("state"), &encode_state(&inner.state))
    }

    /// Present a freshly verified authorized ceremony before any dealing.
    /// Details: TC-2221
    ///
    /// A new id erases any unactivated candidate for the same predecessor
    /// (C1), writes the dealt marker and consumes the id; a replayed id
    /// changes nothing.
    pub fn accept_ceremony(
        &self,
        ceremony: &AuthorizedCeremony,
    ) -> Result<AcceptOutcome, StoreError> {
        let id = ceremony.statement().id;
        let mut inner = self.inner.lock().map_err(|_| StoreError::Corrupt)?;
        if inner.state.seen_ceremonies.contains(&id) {
            return Ok(AcceptOutcome::Replay);
        }
        let predecessor = ceremony.statement().current;
        if let Some(candidate) = &inner.state.candidate {
            if candidate.predecessor == predecessor {
                let digest = candidate.digest;
                erase_share_file(&share_path(&self.network_dir, &digest))?;
                record_retired(&mut inner.state, digest);
                inner.state.candidate = None;
            }
        }
        write_atomic(
            &self.network_dir.join("dealt").join(hex(id.as_bytes())),
            b"",
        )?;
        inner.state.seen_ceremonies.push(id);
        write_atomic(&self.network_dir.join("state"), &encode_state(&inner.state))?;
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
        let digest = store
            .install_candidate(&s_succ, candidate, &ceremony, &signers)
            .unwrap();
        drop(store);

        // Restart: the persisted candidate is pending, the old pin stands.
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
        assert_eq!(store.pinned().unwrap().digest(), cert.digest());
        assert_eq!(store.pending_candidate().unwrap().0, digest);
        assert!(store.current_share().unwrap().is_some());
        drop(store);

        // Activate, then restart again: new pin, old share retired.
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
        let succ = verify_successor(&cert, &s_succ, &signers).unwrap();
        let receipts = receipts_for(&succ, &signers);
        let activation = activation_for(&succ, &receipts, &signers);
        store
            .record_activation(&s_succ, &activation, &receipts, &signers)
            .unwrap();
        drop(store);
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
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
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
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
            let digest = store
                .install_candidate(&s_succ, candidate, &ceremony, &signers)
                .unwrap();
            drop(store);
            let ndir = netdir(&dir, &network);
            fs::remove_file(ndir.join(format!("share-{}", hex(digest.as_bytes())))).unwrap();
        }
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
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
            let digest = store
                .install_candidate(&s_succ, candidate, &ceremony, &signers)
                .unwrap();
            store.mark_receipt_sent().unwrap();
            drop(store);
            let ndir = netdir(&dir, &network);
            fs::remove_file(ndir.join(format!("share-{}", hex(digest.as_bytes())))).unwrap();
        }
        assert!(ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).is_err());
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
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
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
        assert!(ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).is_err());
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
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
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
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
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
        let store = ShareStore::open(&dir, &network, signers.anchor().clone(), &signers).unwrap();
        assert_eq!(
            store.accept_ceremony(&ceremony).unwrap(),
            AcceptOutcome::Replay
        );
    }
}
