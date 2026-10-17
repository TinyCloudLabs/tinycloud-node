//! The node's at-rest keyring (TC-887 S1): loads or provisions the ARK under
//! W, keeps every generation, serves per-space DEKs ([`DataKeyProvider`]),
//! maintains the escrow bundle, decides the encrypt gate, and runs the
//! in-TEE share intake for recovery ("locked, not lost") and the ceremony
//! test-unlock.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use sea_orm::DbErr;
use tinycloud_at_rest_escrow::{
    Ark, ArkId, Digest32, Efp, EscrowBundle, EscrowError, HolderRecipient, RecipientPolicy,
    RecoveryIdentity, SharePayload, VerificationRecord,
};

use super::hierarchy::{
    chain_ark, new_dek, object_name_key, open_ark, open_chain, seal_ark, unwrap_dek, DekTagKey,
    Kek, WrapKey, W_LABEL,
};
use super::store::{
    ark_mirror_name, dek_mirror_name, escrow_mirror_name, record_mirror_name, AtRestStore,
    KeyMirror, MirrorObjectTooLarge, MirroredArk, MirroredDek, ARK_MIRROR_PREFIX, MIRROR_PREFIX,
};
use super::{DataKey, DataKeyError, DataKeyProvider, DekId, ObjectNameKey};
use crate::models::{at_rest_escrow, at_rest_key, space_data_key};

const DEK_CACHE: usize = 4096;
/// Share submissions per boot: a burst of this many, then one per refill.
const SHARE_BURST: u32 = 10;
const SHARE_REFILL: Duration = Duration::from_secs(6);

/// How the node runs its keyring.
#[derive(Clone, Debug, Default)]
pub struct KeyringConfig {
    /// Make ARK generation 1 if none exists.
    pub provision: bool,
    /// Escrow holders pinned in config; empty means no escrow.
    pub holders: Vec<HolderRecipient>,
    /// Hardware-only by default; software (X25519) holders need the explicit
    /// test/self-host opt-in.
    pub recipient_policy: RecipientPolicy,
    /// `at_rest.escrow.verified_fp`: the bundle a ceremony verified.
    pub pinned_efp: Option<Efp>,
    /// The TEE identity written into verification records (informational).
    pub app_id: Option<String>,
    pub compose_hash: Option<String>,
    /// Whether mirror writes at boot and after recovery must succeed. True
    /// once keys may seal data (mode other than `off`); with it false, a
    /// mirror that can't be written is logged and the database alone serves,
    /// so mirror contents never stop a node that encrypts nothing.
    pub require_mirror: bool,
    /// `at_rest.escrow.allow_resplit_before_verify`: let a holder change
    /// re-split at boot, but only while nothing is pinned, the active
    /// escrow has no verified ceremony record, and no data key has ever
    /// been made (so nothing was ever sealed). For fixing a wrong holder
    /// before the ceremony; otherwise a holder change refuses the boot.
    pub allow_resplit_before_verify: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AtRestError {
    #[error("at-rest key store: {0}")]
    Store(#[from] DbErr),
    #[error("at-rest key mirror: {0}")]
    Mirror(String),
    #[error("at-rest key state is inconsistent: {0}")]
    Inconsistent(&'static str),
    #[error("at-rest key change lost a race: {0}")]
    Conflict(&'static str),
    #[error("at_rest.escrow.verified_fp pins an escrow that is not for the configured recipients and the newest key; the node never re-splits while a fingerprint is pinned")]
    EscrowPinned,
    #[error("the configured escrow recipients differ from the active escrow bundle's; the node never re-splits on its own (before the ceremony, at_rest.escrow.allow_resplit_before_verify allows it; afterwards an explicit re-escrow is needed)")]
    EscrowHoldersChanged,
    #[error("a space's data key is unavailable: {0}")]
    DekUnavailable(&'static str),
    #[error("at-rest escrow: {0}")]
    Escrow(#[from] EscrowError),
    #[error("at-rest keys are locked")]
    Locked,
    #[error("at-rest keys are not provisioned")]
    NotProvisioned,
}

impl AtRestError {
    /// Whether retrying may help: the store or mirror was unreachable, the
    /// keys are locked, or a concurrent change won. Everything else needs an
    /// operator.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Store(_)
                | Self::Mirror(_)
                | Self::Conflict(_)
                | Self::Locked
                | Self::NotProvisioned
                | Self::DekUnavailable(_)
        )
    }

    /// A stable reason for API answers: a code plus, where it's static and
    /// key-free, the explanation. Backend details (SQL, S3) stay in the log.
    pub fn reason(&self) -> String {
        match self {
            Self::Store(_) => "store_unavailable".into(),
            Self::Mirror(_) => "mirror_unavailable".into(),
            Self::Inconsistent(why) => format!("inconsistent: {why}"),
            Self::Conflict(why) => format!("conflict: {why}"),
            Self::EscrowPinned => "escrow_pinned".into(),
            Self::EscrowHoldersChanged => "escrow_holders_changed".into(),
            Self::DekUnavailable(why) => format!("dek_unavailable: {why}"),
            Self::Escrow(e) => format!("escrow: {e}"),
            Self::Locked => "locked".into(),
            Self::NotProvisioned => "not_provisioned".into(),
        }
    }
}

/// Why `encrypt` may not be enabled. Every variant is an operator action.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum GateRefusal {
    #[error("at-rest keys are locked; recover with two escrow shares first")]
    Locked,
    #[error("at-rest keys are not provisioned")]
    NotProvisioned,
    #[error("no escrow recipients are configured; set at_rest.escrow.recipients (or, on a self-hosted Static-root node, acknowledge at_rest.escrow_none)")]
    NoEscrow,
    #[error("the active escrow bundle's recipients differ from the configured recipients")]
    RecipientsMismatch,
    #[error("the escrow has software (X25519) holders, which only an explicit test/self-host opt-in allows")]
    SoftwareRecipients,
    #[error("at_rest.escrow.verified_fp is unset; run the escrow ceremony and pin the verified fingerprint {efp}")]
    NotPinned { efp: String },
    #[error("at_rest.escrow.verified_fp ({pinned}) is not the active escrow bundle ({efp}); re-run the ceremony")]
    PinMismatch { pinned: String, efp: String },
    #[error("escrow {efp} has no valid verification record; run the ceremony test-unlock")]
    NotVerified { efp: String },
    /// Not a configuration problem: the store, mirror or stored escrow could
    /// not be read. Fix that (or retry); don't re-run the ceremony.
    #[error("could not evaluate the escrow: {0}")]
    Unavailable(String),
}

/// How a passing gate was satisfied.
#[derive(Debug, PartialEq, Eq)]
pub enum GatePass {
    Verified {
        efp: Efp,
    },
    /// Self-host with `escrow_none` acknowledged: no escrow exists.
    Unescrowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringState {
    NotProvisioned,
    Locked,
    Unlocked,
}

/// Public facts for `/info` and the recovery endpoint.
#[derive(Clone, Debug)]
pub struct EscrowView {
    pub state: KeyringState,
    pub ark_id: ArkId,
    pub generation: u32,
    pub efp: Efp,
    pub canary_fp: Digest32,
    pub verified: bool,
    pub recovery_recipient: String,
    pub shares_held: Vec<u8>,
    pub bundle: EscrowBundle,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ShareOutcome {
    /// Valid; waiting for more shares.
    Held { shares_held: Vec<u8> },
    /// Unlocked node: all three shares rebuilt the ARK; record written.
    Verified { efp: Efp },
    /// Locked node: two shares recovered the ARK; resealed and unlocked.
    Unlocked,
}

#[derive(Debug, thiserror::Error)]
pub enum ShareRefusal {
    #[error("too many share submissions; retry later")]
    RateLimited,
    #[error("no escrow bundle to recover against: {0}")]
    NoBundle(&'static str),
    #[error("share rejected: {0}")]
    Invalid(#[from] EscrowError),
    #[error("{0}")]
    Keyring(#[from] AtRestError),
}

struct Generation {
    ark_id: ArkId,
    ark: Ark,
    kek: Kek,
}

struct Keys {
    gens: BTreeMap<u32, Generation>,
    nk: ObjectNameKey,
    dek_tag: DekTagKey,
}

impl Keys {
    fn newest(&self) -> (u32, &Generation) {
        let (g, gen) = self
            .gens
            .last_key_value()
            .expect("keys_from_newest loads ≥ 1 generation");
        (*g, gen)
    }
}

enum Phase {
    NotProvisioned,
    Locked { generation: u32, ark_id: ArkId },
    Unlocked(Arc<Keys>),
}

struct ShareIntake {
    identity: RecoveryIdentity,
    efp: Option<Efp>,
    held: [Option<SharePayload>; 3],
    tokens: u32,
    refilled: Instant,
}

impl ShareIntake {
    fn new() -> Self {
        Self {
            identity: RecoveryIdentity::generate(),
            efp: None,
            held: [None, None, None],
            tokens: SHARE_BURST,
            refilled: Instant::now(),
        }
    }

    fn take_token(&mut self) -> bool {
        let earned = (self.refilled.elapsed().as_secs() / SHARE_REFILL.as_secs()) as u32;
        if earned > 0 {
            self.tokens = (self.tokens + earned).min(SHARE_BURST);
            self.refilled += SHARE_REFILL * earned;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn held_indices(&self) -> Vec<u8> {
        self.held.iter().flatten().map(|s| s.index).collect()
    }

    fn clear(&mut self) {
        self.held = [None, None, None];
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formats any UTC time")
}

fn mirror_err(e: impl std::fmt::Display) -> AtRestError {
    AtRestError::Mirror(e.to_string())
}

/// A mirror read where an oversized object counts as absent (it can't be a
/// key object) rather than an error that would stop the caller.
async fn get_capped(
    mirror: &dyn KeyMirror,
    name: &str,
) -> Result<Option<Vec<u8>>, super::store::MirrorError> {
    match mirror.get(name).await {
        Err(e) if e.is::<MirrorObjectTooLarge>() => {
            tracing::warn!(object = ?name, "ignoring an oversized at-rest mirror object");
            Ok(None)
        }
        other => other,
    }
}

fn ark_id_of(row: &at_rest_key::Model) -> Result<ArkId, AtRestError> {
    row.ark_id
        .as_slice()
        .try_into()
        .map(ArkId)
        .map_err(|_| AtRestError::Inconsistent("ark_id is not 16 bytes"))
}

fn backend(e: impl std::error::Error + Send + Sync + 'static) -> DataKeyError {
    DataKeyError::Backend(Box::new(e))
}

/// Generations must be exactly 1..=n.
fn check_contiguous(rows: &[at_rest_key::Model]) -> Result<(), AtRestError> {
    for (i, row) in rows.iter().enumerate() {
        if row.generation != i as i32 + 1 {
            return Err(AtRestError::Inconsistent("ARK generations are not 1..n"));
        }
    }
    Ok(())
}

/// A row that may hold generation `row.generation`'s ARK. Mirror rows are
/// unauthenticated until a chain from an authenticated ARK opens them.
#[derive(Clone)]
struct Candidate {
    row: at_rest_key::Model,
    from_db: bool,
}

/// Candidates per generation: the database row first, then mirrored rows
/// that differ from it.
type Candidates = BTreeMap<u32, Vec<Candidate>>;

fn candidates(db: &[at_rest_key::Model], mirrored: Vec<at_rest_key::Model>) -> Candidates {
    let mut out = Candidates::new();
    for row in db {
        out.entry(row.generation as u32)
            .or_default()
            .push(Candidate {
                row: row.clone(),
                from_db: true,
            });
    }
    for row in mirrored {
        let list = out.entry(row.generation as u32).or_default();
        if !list.iter().any(|c| c.row == row) {
            list.push(Candidate {
                row,
                from_db: false,
            });
        }
    }
    out
}

/// Walk down from an authenticated ARK at `top`. For every older generation,
/// pick the candidate whose chain opens under the newer ARK. That is the
/// only path recovery has, so nothing is accepted because W alone opens it.
///
/// With `repair_w` (boot under the root that sealed the rows), a generation
/// with no working chain is accepted if it opens under W, and its chain is
/// rebuilt (logged). Without it (recovery under a new root), that is an
/// error.
///
/// Returns the rows for 1..=top as they must be stored, and the keys.
fn resolve_chain(
    cands: &Candidates,
    top: &at_rest_key::Model,
    top_ark: Ark,
    repair_w: Option<&WrapKey>,
) -> Result<(Vec<at_rest_key::Model>, Keys), AtRestError> {
    let top_g = u32::try_from(top.generation)
        .map_err(|_| AtRestError::Inconsistent("ARK generation out of range"))?;
    let top_id = ark_id_of(top)?;
    // The newest generation has no successor, so it never carries a chain.
    let mut chosen = vec![at_rest_key::Model {
        chain: None,
        ..top.clone()
    }];
    let mut gens = BTreeMap::new();
    gens.insert(
        top_g,
        Generation {
            ark_id: top_id,
            kek: Kek::derive(&top_ark),
            ark: top_ark.clone(),
        },
    );
    let mut newer = (top_ark, top_id);
    for g in (1..top_g).rev() {
        let list = cands.get(&g).map(Vec::as_slice).unwrap_or_default();
        let by_chain = list.iter().find_map(|c| {
            let id = ark_id_of(&c.row).ok()?;
            let chain = c.row.chain.as_deref()?;
            let ark = open_chain(&newer.0, &newer.1, chain, &id, g).ok()?;
            Some((c.row.clone(), ark, id))
        });
        let found = match (by_chain, repair_w) {
            (Some(found), _) => found,
            (None, Some(w)) => list
                .iter()
                .find_map(|c| {
                    let id = ark_id_of(&c.row).ok()?;
                    let ark = open_ark(w, &c.row.sealed, &id, g, &c.row.w_label).ok()?;
                    let mut row = c.row.clone();
                    row.chain = Some(chain_ark(&newer.0, &newer.1, &ark, &id, g));
                    tracing::warn!(
                        generation = g,
                        "at-rest ARK chain was missing or did not open; rebuilt it from the newer generation"
                    );
                    Some((row, ark, id))
                })
                .ok_or(AtRestError::Inconsistent(
                    "an older ARK generation opens neither by its chain nor under W",
                ))?,
            (None, None) => {
                return Err(AtRestError::Inconsistent(
                    "an older ARK generation's chain is missing or does not open",
                ))
            }
        };
        let (row, ark, id) = found;
        gens.insert(
            g,
            Generation {
                ark_id: id,
                kek: Kek::derive(&ark),
                ark: ark.clone(),
            },
        );
        chosen.push(row);
        newer = (ark, id);
    }
    chosen.reverse();
    let ark_1 = &gens.get(&1).expect("the walk ends at generation 1").ark;
    let keys = Keys {
        nk: object_name_key(ark_1),
        dek_tag: DekTagKey::derive(ark_1),
        gens,
    };
    Ok((chosen, keys))
}

/// Unlock under this root's W: the newest generation (at least the
/// database's newest) whose row opens under W and whose chain reaches
/// generation 1. Mirrored generations that don't authenticate or don't
/// connect are skipped with a warning. `Ok(None)`: nothing opens (locked).
fn unlock_under_w(
    w: &WrapKey,
    db_newest: u32,
    cands: &Candidates,
) -> Result<Option<(Vec<at_rest_key::Model>, Keys)>, AtRestError> {
    for (&g, list) in cands.iter().rev() {
        if g < db_newest.max(1) {
            break;
        }
        for c in list {
            let Ok(id) = ark_id_of(&c.row) else { continue };
            let Ok(ark) = open_ark(w, &c.row.sealed, &id, g, &c.row.w_label) else {
                continue;
            };
            match resolve_chain(cands, &c.row, ark, Some(w)) {
                Ok(found) => return Ok(Some(found)),
                // The database's own newest row: a broken store, fail loudly.
                Err(e) if c.from_db => return Err(e),
                Err(e) => tracing::warn!(
                    generation = g,
                    error = %e,
                    "ignoring a mirrored ARK generation whose chain does not reach generation 1"
                ),
            }
        }
        if g > db_newest {
            tracing::warn!(
                generation = g,
                "ignoring a mirrored ARK generation the database lacks: it does not authenticate under this node's root"
            );
        }
    }
    Ok(None)
}

/// Store what `resolve_chain` chose: insert generations the database lacks, and
/// update the seal or chain of those it has. Every row was authenticated.
async fn persist_chosen(
    store: &AtRestStore,
    db: &[at_rest_key::Model],
    chosen: &[at_rest_key::Model],
) -> Result<(), AtRestError> {
    for row in chosen {
        match db.iter().find(|d| d.generation == row.generation) {
            None => {
                tracing::warn!(
                    generation = row.generation,
                    "at-rest ARK row was missing from the database; restored an authenticated copy from the mirror"
                );
                store.insert_key(row.clone()).await?;
            }
            Some(d) if d.ark_id == row.ark_id => {
                if d.sealed != row.sealed || d.w_label != row.w_label {
                    store
                        .reseal_key(row.generation, &row.w_label, row.sealed.clone())
                        .await?;
                }
                if d.chain != row.chain {
                    match &row.chain {
                        Some(chain) => store.set_chain(row.generation, chain.clone()).await?,
                        None => store.clear_chain(row.generation).await?,
                    }
                }
            }
            Some(_) => {
                return Err(AtRestError::Inconsistent(
                    "the database holds a different ARK for a generation the authenticated chain covers",
                ))
            }
        }
    }
    Ok(())
}

/// Mirrored ARK rows, unauthenticated. Junk objects (not JSON, a newer
/// format, bad fields) are always skipped with a warning. An object that
/// can't be read at all is skipped too when `tolerate_unreadable` (the
/// database already has rows, so the mirror is only a supplement);
/// otherwise it fails the call, as does a failure to list.
async fn mirrored_rows(
    mirror: &dyn KeyMirror,
    tolerate_unreadable: bool,
) -> Result<Vec<at_rest_key::Model>, AtRestError> {
    let mut names = mirror.list(ARK_MIRROR_PREFIX).await.map_err(mirror_err)?;
    names.sort();
    let mut rows = Vec::new();
    for name in names {
        let bytes = match get_capped(mirror, &name).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(error) if tolerate_unreadable => {
                tracing::warn!(object = ?name, %error, "ignoring an at-rest mirror object that can't be read");
                continue;
            }
            Err(error) => return Err(mirror_err(error)),
        };
        let parsed = serde_json::from_slice::<MirroredArk>(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|m| m.into_row().map_err(|e| e.to_string()));
        match parsed {
            Ok(row) if row.generation >= 1 && row.ark_id.len() == 16 => rows.push(row),
            Ok(_) => {
                tracing::warn!(object = ?name, "ignoring an at-rest mirror object with bad fields")
            }
            Err(error) => {
                tracing::warn!(object = ?name, %error, "ignoring an unreadable at-rest mirror object")
            }
        }
    }
    Ok(rows)
}

/// The generation a locked node waits for. The pinned bundle names it when
/// one is found (the pin is attested config); otherwise the database's
/// newest; otherwise (empty database) the mirror's only contiguous run.
fn locked_target(
    db: &[at_rest_key::Model],
    cands: &Candidates,
    pinned: Option<&EscrowBundle>,
) -> Result<(u32, ArkId), AtRestError> {
    if let Some(b) = pinned {
        let known = cands
            .get(&b.generation)
            .is_some_and(|l| l.iter().any(|c| c.row.ark_id == b.ark_id.0));
        if known && b.generation as usize >= db.len() {
            return Ok((b.generation, b.ark_id));
        }
    }
    if let Some(newest) = db.last() {
        return Ok((newest.generation as u32, ark_id_of(newest)?));
    }
    let mut target = None;
    for g in 1.. {
        match cands.get(&g).map(Vec::as_slice) {
            Some([only]) => target = Some((g, ark_id_of(&only.row)?)),
            Some([]) | None => break,
            Some(_) => return Err(AtRestError::Inconsistent(
                "the mirror holds conflicting ARK rows and no pinned escrow names the right one",
            )),
        }
    }
    target.ok_or(AtRestError::Inconsistent(
        "sealed at-rest material exists but no ARK row or mirrored ARK was found",
    ))
}

pub struct AtRestKeyring {
    store: AtRestStore,
    mirror: Arc<dyn KeyMirror>,
    w: WrapKey,
    config: KeyringConfig,
    phase: RwLock<Phase>,
    deks: Mutex<LruCache<(String, u32), DataKey>>,
    current: Mutex<LruCache<String, DekId>>,
    /// The EFP last confirmed present in the mirror, so `/info` and the gate
    /// don't GET it every call.
    escrow_mirrored: Mutex<Option<String>>,
    intake: tokio::sync::Mutex<ShareIntake>,
    dek_create: tokio::sync::Mutex<()>,
}

impl AtRestKeyring {
    /// Load the keyring at boot.
    ///
    /// - The newest generation that opens under this root's W, with a chain
    ///   down to generation 1, unlocks the keys. Mirrored generations the
    ///   database lacks (a restore to an earlier point) are stored only once
    ///   they authenticate this way; anything else in the mirror (forged,
    ///   junk, gapped) is skipped with a warning. A chain that is missing or
    ///   doesn't open is rebuilt and logged.
    /// - Rows exist but nothing opens: **locked** (data intact; recover with
    ///   two shares of the pinned escrow).
    /// - No rows anywhere: provision generation 1 if `config.provision`,
    ///   else not provisioned. Never when any sealed material exists without
    ///   an ARK (data keys, escrow rows, any mirror object), and never after
    ///   a store or mirror error.
    pub async fn open(
        store: AtRestStore,
        mirror: Arc<dyn KeyMirror>,
        root: &[u8],
        config: KeyringConfig,
    ) -> Result<Self, AtRestError> {
        let keyring = Self {
            store,
            mirror,
            w: WrapKey::derive(root),
            config,
            phase: RwLock::new(Phase::NotProvisioned),
            deks: Mutex::new(LruCache::new(
                NonZeroUsize::new(DEK_CACHE).expect("non-zero"),
            )),
            current: Mutex::new(LruCache::new(
                NonZeroUsize::new(DEK_CACHE).expect("non-zero"),
            )),
            escrow_mirrored: Mutex::new(None),
            intake: tokio::sync::Mutex::new(ShareIntake::new()),
            dek_create: tokio::sync::Mutex::new(()),
        };
        keyring.load().await?;
        if keyring.state() == KeyringState::Unlocked {
            keyring.establish_escrow().await?;
        }
        Ok(keyring)
    }

    /// Read the stored and mirrored rows and set the phase.
    async fn load(&self) -> Result<(), AtRestError> {
        let mut db = self.store.keys().await?;
        check_contiguous(&db)?;
        let mirrored = mirrored_rows(&*self.mirror, !db.is_empty()).await?;
        if db.is_empty() && mirrored.is_empty() {
            if self.store.has_space_keys().await?
                || self.store.has_escrow_rows().await?
                || !self
                    .mirror
                    .list(MIRROR_PREFIX)
                    .await
                    .map_err(mirror_err)?
                    .is_empty()
            {
                // Another process may have provisioned since we read: its
                // ARK row is written before anything else.
                db = self.store.keys().await?;
                if db.is_empty() {
                    return Err(AtRestError::Inconsistent(
                        "sealed at-rest material exists but no ARK row or mirrored ARK was found",
                    ));
                }
            } else if self.config.provision {
                let ark = Ark::generate();
                let ark_id = ArkId::generate();
                self.store
                    .insert_key(at_rest_key::Model {
                        generation: 1,
                        ark_id: ark_id.0.to_vec(),
                        w_label: W_LABEL.into(),
                        sealed: seal_ark(&self.w, &ark, &ark_id, 1),
                        chain: None,
                        created_at: now_rfc3339(),
                    })
                    .await?;
                // Another process may have won the insert; use what's stored.
                db = self.store.keys().await?;
                if db.first().map(|r| r.ark_id.as_slice()) == Some(&ark_id.0[..]) {
                    tracing::info!(generation = 1, %ark_id, "at-rest root key provisioned");
                }
            } else {
                return Ok(());
            }
            check_contiguous(&db)?;
        }
        let cands = candidates(&db, mirrored);
        if let Some((mut chosen, keys)) = unlock_under_w(&self.w, db.len() as u32, &cands)? {
            // Only chains and ARK ids come from the chosen rows. Seal bytes
            // are never taken from the mirror: a generation the database has
            // keeps its own seal, and one it lacks gets a fresh seal under W.
            for row in chosen.iter_mut() {
                match db.iter().find(|d| d.generation == row.generation) {
                    Some(d) if d.ark_id == row.ark_id => {
                        row.sealed = d.sealed.clone();
                        row.w_label = d.w_label.clone();
                    }
                    Some(_) => {} // persist_chosen refuses this
                    None => {
                        let g = row.generation as u32;
                        let gen = &keys.gens[&g];
                        row.sealed = seal_ark(&self.w, &gen.ark, &gen.ark_id, g);
                        row.w_label = W_LABEL.into();
                    }
                }
            }
            persist_chosen(&self.store, &db, &chosen).await?;
            for row in self.store.keys().await? {
                self.mirror_soft(Self::mirror_row(&*self.mirror, &row).await)?;
            }
            *self.phase.write() = Phase::Unlocked(Arc::new(keys));
            return Ok(());
        }
        // A stored or mirrored escrow bundle that can't be read must not
        // stop the boot: the node then just has no bundle to recover with.
        let pinned = match self.pinned_bundle().await {
            Ok(b) => b,
            Err(e @ (AtRestError::Store(_) | AtRestError::Mirror(_))) => return Err(e),
            Err(error) => {
                tracing::warn!(%error, "ignoring the pinned escrow bundle: it can't be read");
                None
            }
        };
        let (generation, ark_id) = locked_target(&db, &cands, pinned.as_ref())?;
        tracing::warn!(
            generation,
            "at-rest keys locked: this node's root cannot unseal the ARK"
        );
        *self.phase.write() = Phase::Locked { generation, ark_id };
        Ok(())
    }

    async fn mirror_row(
        mirror: &dyn KeyMirror,
        row: &at_rest_key::Model,
    ) -> Result<(), AtRestError> {
        let name = ark_mirror_name(row.generation as u32, &hex::encode(&row.ark_id));
        let body = serde_json::to_vec(&MirroredArk::from_row(row)).expect("serializable");
        if get_capped(mirror, &name)
            .await
            .map_err(mirror_err)?
            .as_deref()
            != Some(body.as_slice())
        {
            mirror.put(&name, body).await.map_err(mirror_err)?;
        }
        Ok(())
    }

    pub fn state(&self) -> KeyringState {
        match &*self.phase.read() {
            Phase::NotProvisioned => KeyringState::NotProvisioned,
            Phase::Locked { .. } => KeyringState::Locked,
            Phase::Unlocked(_) => KeyringState::Unlocked,
        }
    }

    /// A boot-time mirror write: fatal only when `require_mirror`.
    fn mirror_soft(&self, result: Result<(), AtRestError>) -> Result<(), AtRestError> {
        match result {
            Err(AtRestError::Mirror(error)) if !self.config.require_mirror => {
                tracing::warn!(%error, "at-rest key mirror could not be written; continuing (nothing is encrypted)");
                Ok(())
            }
            other => other,
        }
    }

    fn keys(&self) -> Result<Arc<Keys>, AtRestError> {
        match &*self.phase.read() {
            Phase::Unlocked(keys) => Ok(keys.clone()),
            Phase::Locked { .. } => Err(AtRestError::Locked),
            Phase::NotProvisioned => Err(AtRestError::NotProvisioned),
        }
    }

    fn parse_bundle(row: &at_rest_escrow::Model) -> Result<EscrowBundle, AtRestError> {
        let bundle = EscrowBundle::from_json(row.bundle.as_bytes())?;
        if bundle.fingerprint().to_string() != row.efp {
            return Err(AtRestError::Inconsistent(
                "stored escrow bundle does not match its fingerprint",
            ));
        }
        Ok(bundle)
    }

    /// At boot (and after a rotation or recovery): make sure the newest
    /// generation has an active escrow bundle for exactly the configured
    /// holders. This is the only place a bundle is ever created or
    /// activated; request paths only read ([`Self::active_bundle`]).
    ///
    /// - An active bundle for other holders: refused
    ///   ([`AtRestError::EscrowHoldersChanged`]); the node never re-splits on
    ///   its own.
    /// - None active and `verified_fp` pinned: the pinned bundle, from the
    ///   database or the mirror (the pin authenticates it), is re-activated;
    ///   anything else is [`AtRestError::EscrowPinned`].
    /// - None active, no pin: a mirrored bundle whose mirrored ceremony
    ///   record verifies under the ARK is restored (a database restore
    ///   doesn't force a new ceremony); otherwise a new bundle is made.
    ///
    /// A verification record the database lost is restored from the mirror
    /// when it verifies under the ARK.
    async fn establish_escrow(&self) -> Result<(), AtRestError> {
        if self.config.holders.is_empty() {
            return Ok(());
        }
        let keys = self.keys()?;
        let (g, gen) = keys.newest();
        if let Some(row) = self.store.active_escrow(g as i32).await? {
            let bundle = Self::parse_bundle(&row)?;
            if bundle.ark_id != gen.ark_id {
                return Err(AtRestError::Inconsistent(
                    "the active escrow bundle is for another ARK",
                ));
            }
            if bundle.holders() == self.config.holders {
                self.mirror_soft(self.mirror_escrow(&row).await)?;
                if row.record.is_none() {
                    self.restore_record(&gen.ark, &bundle).await?;
                }
                return Ok(());
            }
            if !self.may_resplit(&bundle).await? {
                return Err(AtRestError::EscrowHoldersChanged);
            }
            tracing::warn!(
                generation = g,
                "re-splitting an unverified escrow for corrected holders (allow_resplit_before_verify); the ceremony starts over"
            );
        }
        let wanted = |b: &EscrowBundle| {
            b.holders() == self.config.holders && b.ark_id == gen.ark_id && b.generation == g
        };
        let restored = match self.config.pinned_efp {
            Some(_) => match self.pinned_bundle().await?.filter(wanted) {
                Some(bundle) => Some(bundle),
                None => return Err(AtRestError::EscrowPinned),
            },
            None => self
                .verified_mirrored_bundle(&gen.ark)
                .await?
                .filter(wanted),
        };
        let (bundle, created) = match restored {
            Some(bundle) => (bundle, false),
            None => (
                EscrowBundle::create(
                    &gen.ark,
                    gen.ark_id,
                    g,
                    &self.config.holders,
                    self.config.recipient_policy,
                )?,
                true,
            ),
        };
        let row = at_rest_escrow::Model {
            efp: bundle.fingerprint().to_string(),
            generation: g as i32,
            bundle: serde_json::to_string(&bundle).expect("serializable"),
            active: true,
            record: None,
            created_at: now_rfc3339(),
        };
        self.store.activate_escrow(row.clone()).await?;
        self.mirror_soft(self.mirror_escrow(&row).await)?;
        if created {
            tracing::warn!(
                generation = g,
                efp = %row.efp,
                "at-rest escrow bundle created; the escrow ceremony must verify it before encryption can be enabled"
            );
        } else {
            tracing::warn!(
                generation = g,
                efp = %row.efp,
                "at-rest escrow bundle was missing from the database; restored an authenticated copy from the mirror"
            );
            if self
                .store
                .escrow(&row.efp)
                .await?
                .and_then(|r| r.record)
                .is_none()
            {
                self.restore_record(&gen.ark, &bundle).await?;
            }
        }
        Ok(())
    }

    /// A holder change may re-split only when explicitly allowed, nothing is
    /// pinned, the active escrow was never verified, and no data key has
    /// ever been made.
    async fn may_resplit(&self, active: &EscrowBundle) -> Result<bool, AtRestError> {
        Ok(self.config.allow_resplit_before_verify
            && self.config.pinned_efp.is_none()
            && self.verified_record(active).await?.is_none()
            && !self.store.has_space_keys().await?)
    }

    /// A ceremony record for `bundle` from the mirror, stored only if its
    /// MAC verifies under the ARK.
    async fn restore_record(&self, ark: &Ark, bundle: &EscrowBundle) -> Result<(), AtRestError> {
        let efp = bundle.fingerprint().to_string();
        let bytes = match get_capped(&*self.mirror, &record_mirror_name(&efp)).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(()),
            Err(error) => {
                tracing::warn!(%efp, %error, "can't read the mirrored ceremony record; not restoring it");
                return Ok(());
            }
        };
        match VerificationRecord::from_json(&bytes) {
            Ok(record) if record.verify(ark, bundle).is_ok() => {
                let json = serde_json::to_string(&record).expect("serializable");
                self.store.save_record(&efp, json).await?;
                tracing::warn!(%efp, "at-rest ceremony record was missing from the database; restored a verified copy from the mirror");
            }
            _ => tracing::warn!(%efp, "ignoring a mirrored ceremony record that does not verify"),
        }
        Ok(())
    }

    /// An unpinned node after a database restore: a mirrored bundle that a
    /// mirrored ceremony record proves (MAC under the ARK) was verified.
    async fn verified_mirrored_bundle(
        &self,
        ark: &Ark,
    ) -> Result<Option<EscrowBundle>, AtRestError> {
        let names = self
            .mirror
            .list(&format!("{MIRROR_PREFIX}record-"))
            .await
            .map_err(mirror_err)?;
        for name in names {
            let Ok(Some(bytes)) = get_capped(&*self.mirror, &name).await else {
                continue;
            };
            let Ok(record) = VerificationRecord::from_json(&bytes) else {
                continue;
            };
            let efp = record.efp.to_string();
            let Ok(Some(bundle_bytes)) = get_capped(&*self.mirror, &escrow_mirror_name(&efp)).await
            else {
                continue;
            };
            let Ok(bundle) = EscrowBundle::from_json(&bundle_bytes) else {
                continue;
            };
            if bundle.fingerprint() == record.efp && record.verify(ark, &bundle).is_ok() {
                return Ok(Some(bundle));
            }
        }
        Ok(None)
    }

    /// The newest generation's active bundle. Read-only: request paths never
    /// create, activate or mirror anything.
    async fn active_bundle(&self) -> Result<Option<EscrowBundle>, AtRestError> {
        if self.config.holders.is_empty() {
            return Ok(None);
        }
        let keys = self.keys()?;
        let (g, gen) = keys.newest();
        let Some(row) = self.store.active_escrow(g as i32).await? else {
            return Ok(None);
        };
        let bundle = Self::parse_bundle(&row)?;
        Ok((bundle.ark_id == gen.ark_id).then_some(bundle))
    }

    async fn mirror_escrow(&self, row: &at_rest_escrow::Model) -> Result<(), AtRestError> {
        if self.escrow_mirrored.lock().as_deref() == Some(row.efp.as_str()) {
            return Ok(());
        }
        let name = escrow_mirror_name(&row.efp);
        if get_capped(&*self.mirror, &name)
            .await
            .map_err(mirror_err)?
            .is_none()
        {
            self.mirror
                .put(&name, row.bundle.clone().into_bytes())
                .await
                .map_err(mirror_err)?;
        }
        *self.escrow_mirrored.lock() = Some(row.efp.clone());
        Ok(())
    }

    /// The pinned bundle, from the database or else the mirror. Only a bundle
    /// whose fingerprint equals the pin is returned.
    async fn pinned_bundle(&self) -> Result<Option<EscrowBundle>, AtRestError> {
        let Some(pinned) = self.config.pinned_efp else {
            return Ok(None);
        };
        let efp = pinned.to_string();
        if let Some(row) = self.store.escrow(&efp).await? {
            return Self::parse_bundle(&row).map(Some);
        }
        let Some(bytes) = get_capped(&*self.mirror, &escrow_mirror_name(&efp))
            .await
            .map_err(mirror_err)?
        else {
            return Ok(None);
        };
        let bundle = EscrowBundle::from_json(&bytes)?;
        Ok((bundle.fingerprint() == pinned).then_some(bundle))
    }

    /// The bundle shares are checked against: the active one when unlocked,
    /// the pinned one when locked (storage is untrusted, the pin is attested).
    async fn intake_bundle(&self) -> Result<EscrowBundle, ShareRefusal> {
        let locked = match &*self.phase.read() {
            Phase::NotProvisioned => {
                return Err(ShareRefusal::NoBundle("keys are not provisioned"))
            }
            Phase::Locked { generation, ark_id } => Some((*generation, *ark_id)),
            Phase::Unlocked(_) => None,
        };
        match locked {
            Some((generation, ark_id)) => {
                let bundle = self.pinned_bundle().await?.ok_or(ShareRefusal::NoBundle(
                    "no bundle matches at_rest.escrow.verified_fp",
                ))?;
                if bundle.generation != generation || bundle.ark_id != ark_id {
                    return Err(ShareRefusal::NoBundle(
                        "the pinned bundle escrows a different ARK generation",
                    ));
                }
                Ok(bundle)
            }
            None => self
                .active_bundle()
                .await?
                .ok_or(ShareRefusal::NoBundle("no active escrow bundle")),
        }
    }

    /// Facts for `/info` and `GET /at-rest/recovery`.
    pub async fn escrow_view(&self) -> Result<Option<EscrowView>, AtRestError> {
        let state = self.state();
        let bundle = match self.intake_bundle().await {
            Ok(b) => b,
            Err(ShareRefusal::Keyring(e)) => return Err(e),
            Err(_) => return Ok(None),
        };
        let verified = match state {
            KeyringState::Unlocked => self.verified_record(&bundle).await?.is_some(),
            _ => false,
        };
        let intake = self.intake.lock().await;
        let shares_held = if intake.efp == Some(bundle.fingerprint()) {
            intake.held_indices()
        } else {
            Vec::new()
        };
        Ok(Some(EscrowView {
            state,
            ark_id: bundle.ark_id,
            generation: bundle.generation,
            efp: bundle.fingerprint(),
            canary_fp: bundle.canary_fp,
            verified,
            recovery_recipient: intake.identity.recipient(),
            shares_held,
            bundle,
        }))
    }

    /// The active escrow's verification record, only if its MAC verifies
    /// under the loaded ARK. `None` when locked, unescrowed or unverified.
    pub async fn verification_record(&self) -> Result<Option<VerificationRecord>, AtRestError> {
        if self.state() != KeyringState::Unlocked {
            return Ok(None);
        }
        match self.active_bundle().await? {
            Some(bundle) => self.verified_record(&bundle).await,
            None => Ok(None),
        }
    }

    async fn verified_record(
        &self,
        bundle: &EscrowBundle,
    ) -> Result<Option<VerificationRecord>, AtRestError> {
        let keys = self.keys()?;
        let Some(gen) = keys.gens.get(&bundle.generation) else {
            return Ok(None);
        };
        let Some(row) = self.store.escrow(&bundle.fingerprint().to_string()).await? else {
            return Ok(None);
        };
        let Some(json) = row.record else {
            return Ok(None);
        };
        // A record this node can't read (newer version, corrupt) is an
        // error to surface, not "unverified".
        let record = VerificationRecord::from_json(json.as_bytes())?;
        Ok(record.verify(&gen.ark, bundle).is_ok().then_some(record))
    }

    /// The encrypt gate. `escrow_none` is the explicit self-host
    /// acknowledgement that no escrow exists; it only applies when no
    /// recipients are configured.
    pub async fn gate(&self, escrow_none: bool) -> Result<GatePass, GateRefusal> {
        match self.state() {
            KeyringState::Locked => return Err(GateRefusal::Locked),
            KeyringState::NotProvisioned => return Err(GateRefusal::NotProvisioned),
            KeyringState::Unlocked => {}
        }
        if self.config.holders.is_empty() {
            return if escrow_none {
                Ok(GatePass::Unescrowed)
            } else {
                Err(GateRefusal::NoEscrow)
            };
        }
        let bundle = match self.active_bundle().await {
            Ok(Some(b)) => b,
            Ok(None) => {
                return Err(GateRefusal::Unavailable(
                    "no active escrow bundle; restart the node to escrow the key".into(),
                ))
            }
            Err(e) => {
                tracing::warn!(error = %e, "at-rest escrow gate could not read the escrow");
                return Err(GateRefusal::Unavailable(e.reason()));
            }
        };
        if bundle.holders() != self.config.holders {
            return Err(GateRefusal::RecipientsMismatch);
        }
        if bundle
            .check_recipients(self.config.recipient_policy)
            .is_err()
        {
            return Err(GateRefusal::SoftwareRecipients);
        }
        let efp = bundle.fingerprint();
        match self.config.pinned_efp {
            None => {
                return Err(GateRefusal::NotPinned {
                    efp: efp.to_string(),
                })
            }
            Some(p) if p != efp => {
                return Err(GateRefusal::PinMismatch {
                    pinned: p.to_string(),
                    efp: efp.to_string(),
                })
            }
            Some(_) => {}
        }
        match self.verified_record(&bundle).await {
            Ok(Some(_)) => Ok(GatePass::Verified { efp }),
            Ok(None) => Err(GateRefusal::NotVerified {
                efp: efp.to_string(),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "at-rest escrow gate could not read the ceremony record");
                Err(GateRefusal::Unavailable(e.reason()))
            }
        }
    }

    /// Take one wrapped share (age file to this boot's recovery recipient).
    ///
    /// Each share is checked against its commitment before it occupies one of
    /// three slots (one per index). Only shares that pass (decrypt and match
    /// a commitment) spend this boot's submission budget, so junk can't
    /// starve genuine holders; the HTTP layer limits failures per client.
    /// Share bytes are never logged.
    pub async fn submit_share(&self, wrapped: &[u8]) -> Result<ShareOutcome, ShareRefusal> {
        let mut intake = self.intake.lock().await;
        let share = intake.identity.open(wrapped)?;
        let bundle = self.intake_bundle().await?;
        bundle.verify_share(&share)?;
        if !intake.take_token() {
            return Err(ShareRefusal::RateLimited);
        }
        let efp = bundle.fingerprint();
        if intake.efp != Some(efp) {
            intake.clear();
            intake.efp = Some(efp);
        }
        let index = share.index;
        intake.held[usize::from(index) - 1] = Some(share);
        tracing::info!(%efp, index, "at-rest escrow share accepted");

        let held: Vec<SharePayload> = intake.held.iter().flatten().cloned().collect();
        let outcome = match self.state() {
            KeyringState::Locked if held.len() >= 2 => {
                // A failed combine drops the held shares; holders resubmit.
                let ark = bundle
                    .recover(&held[0], &held[1])
                    .inspect_err(|_| intake.clear())?;
                self.unlock_with(ark, &bundle).await?;
                intake.clear();
                ShareOutcome::Unlocked
            }
            KeyringState::Unlocked if held.len() == 3 => {
                let keys = self.keys()?;
                let gen = keys
                    .gens
                    .get(&bundle.generation)
                    .ok_or(AtRestError::Inconsistent(
                        "escrowed generation is not loaded",
                    ))?;
                let unlock = bundle
                    .test_unlock(&gen.ark, &held)
                    .inspect_err(|_| intake.clear())?;
                let record = VerificationRecord::seal(
                    &gen.ark,
                    &bundle,
                    &unlock,
                    self.config.app_id.clone(),
                    self.config.compose_hash.clone(),
                    now_rfc3339(),
                )?;
                let json = serde_json::to_string(&record).expect("serializable");
                self.store
                    .save_record(&efp.to_string(), json.clone())
                    .await
                    .map_err(AtRestError::from)?;
                self.mirror
                    .put(&record_mirror_name(&efp.to_string()), json.into_bytes())
                    .await
                    .map_err(mirror_err)?;
                intake.clear();
                tracing::warn!(%efp, "at-rest escrow verified: all three shares rebuilt the ARK");
                ShareOutcome::Verified { efp }
            }
            _ => ShareOutcome::Held {
                shares_held: intake.held_indices(),
            },
        };
        Ok(outcome)
    }

    /// Locked → unlocked with a recovered ARK: authenticate every older
    /// generation by its chain (database rows first, then mirrored ones),
    /// re-seal all of them under this node's W, store, mirror, serve keys.
    async fn unlock_with(&self, ark: Ark, bundle: &EscrowBundle) -> Result<(), AtRestError> {
        let db = self.store.keys().await?;
        check_contiguous(&db)?;
        if (bundle.generation as usize) < db.len() {
            return Err(AtRestError::Inconsistent(
                "recovered ARK is not the newest generation",
            ));
        }
        let cands = candidates(&db, mirrored_rows(&*self.mirror, !db.is_empty()).await?);
        let top = cands
            .get(&bundle.generation)
            .and_then(|l| l.iter().find(|c| c.row.ark_id == bundle.ark_id.0))
            .map(|c| c.row.clone())
            .ok_or(AtRestError::Inconsistent(
                "no stored or mirrored row for the recovered generation",
            ))?;
        // Under a new root the rows still carry the old W: every older
        // generation must open by its chain, or recovery fails loudly.
        let (mut chosen, keys) = resolve_chain(&cands, &top, ark, None)?;
        for row in chosen.iter_mut() {
            let g = row.generation as u32;
            let gen = &keys.gens[&g];
            row.sealed = seal_ark(&self.w, &gen.ark, &gen.ark_id, g);
            row.w_label = W_LABEL.into();
        }
        persist_chosen(&self.store, &db, &chosen).await?;
        for row in self.store.keys().await? {
            self.mirror_soft(Self::mirror_row(&*self.mirror, &row).await)?;
        }
        *self.phase.write() = Phase::Unlocked(Arc::new(keys));
        tracing::warn!(
            generation = bundle.generation,
            "at-rest keys recovered from escrow and resealed under this node's root"
        );
        // The keys are already unlocked; an escrow problem (for example a
        // database that lost the bundle row) is reported, not undone.
        if let Err(error) = self.establish_escrow().await {
            tracing::error!(%error, "at-rest keys recovered, but the escrow could not be re-established");
        }
        Ok(())
    }

    /// Start ARK generation n+1. Older generations stay readable through the
    /// chain; new DEKs wrap under the new KEK. The new generation has no
    /// verified escrow until a ceremony runs, so the gate closes.
    ///
    /// The new row and the older generation's chain are written in one
    /// transaction. If another node rotated first, nothing is written, this
    /// keyring reloads what is stored, and the call returns
    /// [`AtRestError::Conflict`].
    pub async fn rotate_ark(&self) -> Result<u32, AtRestError> {
        let keys = self.keys()?;
        let (g, old) = keys.newest();
        let next = g + 1;
        let ark = Ark::generate();
        let ark_id = ArkId::generate();
        let won = self
            .store
            .rotate(
                at_rest_key::Model {
                    generation: next as i32,
                    ark_id: ark_id.0.to_vec(),
                    w_label: W_LABEL.into(),
                    sealed: seal_ark(&self.w, &ark, &ark_id, next),
                    chain: None,
                    created_at: now_rfc3339(),
                },
                chain_ark(&ark, &ark_id, &old.ark, &old.ark_id, g),
            )
            .await?;
        self.load().await?;
        if self.state() != KeyringState::Unlocked {
            return Err(AtRestError::Inconsistent(
                "the stored newest generation does not open under this node's root",
            ));
        }
        self.current.lock().clear();
        if !won {
            let newest = self.keys()?.newest().0;
            return Err(if newest > g {
                AtRestError::Conflict(
                    "another node rotated the ARK first; reloaded the stored generations",
                )
            } else {
                // The newest generation carried a chain with no successor
                // (a restored or garbage row). Reloading cleared it.
                AtRestError::Inconsistent(
                    "the newest ARK generation carried a stale chain; it has been cleared, retry the rotation",
                )
            });
        }
        self.establish_escrow().await?;
        tracing::warn!(generation = next, %ark_id, "at-rest ARK rotated");
        Ok(next)
    }

    /// A mirrored DEK row for `space`, only if its wrap authenticates under
    /// the stated generation's KEK for exactly this space and id.
    fn authentic_mirrored_dek(
        keys: &Keys,
        space: &str,
        dek_id: u32,
        bytes: &[u8],
    ) -> Option<(space_data_key::Model, DataKey)> {
        let row = serde_json::from_slice::<MirroredDek>(bytes)
            .ok()?
            .into_row(space)
            .ok()?;
        if row.dek_id as u32 != dek_id {
            return None;
        }
        let gen = keys.gens.get(&(row.generation as u32))?;
        let key = unwrap_dek(
            &gen.kek,
            &row.wrapped,
            space,
            DekId::new(dek_id),
            row.generation as u32,
            &gen.ark_id,
        )
        .ok()?;
        Some((row, key))
    }

    /// The mirror object holding a space's DEK, as bytes. An object that is
    /// present but too large to be one fails closed for the space: it must
    /// never read as "absent", or a new DEK would be made and mirrored over
    /// it.
    async fn dek_object(&self, name: &str) -> Result<Option<Vec<u8>>, DataKeyError> {
        match self.mirror.get(name).await {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.is::<MirrorObjectTooLarge>() => Err(backend(AtRestError::DekUnavailable(
                "the mirrored object for this data key is oversized",
            ))),
            Err(e) => Err(backend(mirror_err(e))),
        }
    }

    /// A space's DEK row from the mirror, put back into the database once
    /// it authenticates.
    ///
    /// A mirrored object that doesn't authenticate is **never ignored**: it
    /// may be the genuine key under an ARK generation this node hasn't
    /// loaded (a restore plus a failed boot read), and making a new DEK
    /// would strand everything sealed under it. The space fails closed
    /// ([`AtRestError::DekUnavailable`], a 503) until the generation loads
    /// or an operator removes the object.
    async fn restore_dek(
        &self,
        keys: &Keys,
        space: &str,
        dek_id: u32,
    ) -> Result<Option<space_data_key::Model>, DataKeyError> {
        let name = dek_mirror_name(&keys.dek_tag.tag(space), dek_id);
        let Some(bytes) = self.dek_object(&name).await? else {
            return Ok(None);
        };
        let Some((row, _)) = Self::authentic_mirrored_dek(keys, space, dek_id, &bytes) else {
            let newest = keys.newest().0;
            let names_unloaded_generation =
                serde_json::from_slice::<MirroredDek>(&bytes).is_ok_and(|m| m.generation > newest);
            tracing::error!(
                dek_id,
                names_unloaded_generation,
                "a mirrored data key for this space does not authenticate; refusing to make a new one"
            );
            return Err(backend(AtRestError::DekUnavailable(
                if names_unloaded_generation {
                    "the mirrored data key names an ARK generation this node hasn't loaded; restart once the key mirror is readable"
                } else {
                    "the mirror holds a data key object for this space that does not authenticate"
                },
            )));
        };
        tracing::warn!(
            dek_id,
            "at-rest data key was missing from the database; restored from the mirror"
        );
        self.store.insert_dek(row).await.map_err(backend)?;
        let id = i32::try_from(dek_id).map_err(|_| DataKeyError::UnknownKey {
            dek_id: DekId::new(dek_id),
        })?;
        self.store.dek(space, id).await.map_err(backend)
    }

    /// Make sure the mirror holds exactly this DEK row before any object is
    /// sealed under it. An existing object is never overwritten: if it
    /// isn't this exact row (a genuine different key, junk, or a key under
    /// a generation not loaded), the space fails closed.
    async fn mirror_dek(
        &self,
        keys: &Keys,
        row: &space_data_key::Model,
    ) -> Result<(), DataKeyError> {
        let dek_id = row.dek_id as u32;
        let name = dek_mirror_name(&keys.dek_tag.tag(&row.space), dek_id);
        if let Some(bytes) = self.dek_object(&name).await? {
            return match Self::authentic_mirrored_dek(keys, &row.space, dek_id, &bytes) {
                Some((m, _)) if m.generation == row.generation && m.wrapped == row.wrapped => {
                    Ok(())
                }
                _ => Err(backend(AtRestError::DekUnavailable(
                    "the mirror holds different bytes for this data key; it is never overwritten",
                ))),
            };
        }
        let body = serde_json::to_vec(&MirroredDek::from_row(row)).expect("serializable");
        self.mirror
            .put(&name, body)
            .await
            .map_err(|e| backend(mirror_err(e)))
    }

    /// Generate, store and return the space's first DEK row. If another
    /// process won the insert, its row is returned.
    async fn create_dek(
        &self,
        keys: &Keys,
        space: &str,
    ) -> Result<space_data_key::Model, DataKeyError> {
        let (g, gen) = keys.newest();
        let (wrapped, _) = new_dek(&gen.kek, space, DekId::new(1), g, &gen.ark_id);
        self.store
            .insert_dek(space_data_key::Model {
                space: space.to_owned(),
                dek_id: 1,
                generation: g as i32,
                wrapped,
                created_at: now_rfc3339(),
            })
            .await
            .map_err(backend)?;
        self.store
            .dek(space, 1)
            .await
            .map_err(backend)?
            .ok_or_else(|| backend(AtRestError::Inconsistent("inserted data key is missing")))
    }

    async fn load_dek(
        &self,
        keys: &Keys,
        row: &space_data_key::Model,
    ) -> Result<DataKey, DataKeyError> {
        let dek_id = DekId::new(row.dek_id as u32);
        let gen = keys.gens.get(&(row.generation as u32)).ok_or_else(|| {
            backend(AtRestError::Inconsistent(
                "data key names an unknown ARK generation",
            ))
        })?;
        let key = unwrap_dek(
            &gen.kek,
            &row.wrapped,
            &row.space,
            dek_id,
            row.generation as u32,
            &gen.ark_id,
        )
        .map_err(backend)?;
        self.deks
            .lock()
            .put((row.space.clone(), dek_id.get()), key.clone());
        Ok(key)
    }
}

fn locked(e: AtRestError) -> DataKeyError {
    match e {
        AtRestError::Locked | AtRestError::NotProvisioned => DataKeyError::Locked,
        other => backend(other),
    }
}

#[async_trait::async_trait]
impl DataKeyProvider for AtRestKeyring {
    async fn current_key(&self, space: &str) -> Result<DataKey, DataKeyError> {
        let keys = self.keys().map_err(locked)?;
        let cached = self.current.lock().get(space).copied();
        if let Some(id) = cached {
            return self.key(space, id).await;
        }
        let row = match self.store.newest_dek(space).await.map_err(backend)? {
            Some(row) => row,
            None => {
                let _create = self.dek_create.lock().await;
                match self.store.newest_dek(space).await.map_err(backend)? {
                    Some(row) => row,
                    // A database restored to before this space's first DEK:
                    // objects may still be sealed under the mirrored one.
                    None => match self.restore_dek(&keys, space, 1).await? {
                        Some(row) => row,
                        None => self.create_dek(&keys, space).await?,
                    },
                }
            }
        };
        // First use of this space's current key in this process.
        self.mirror_dek(&keys, &row).await?;
        let key = self.load_dek(&keys, &row).await?;
        self.current.lock().put(space.to_owned(), key.id());
        Ok(key)
    }

    async fn key(&self, space: &str, dek_id: DekId) -> Result<DataKey, DataKeyError> {
        let keys = self.keys().map_err(locked)?;
        if let Some(key) = self.deks.lock().get(&(space.to_owned(), dek_id.get())) {
            return Ok(key.clone());
        }
        let Ok(id) = i32::try_from(dek_id.get()) else {
            return Err(DataKeyError::UnknownKey { dek_id });
        };
        let row = match self.store.dek(space, id).await.map_err(backend)? {
            Some(row) => Some(row),
            None => self.restore_dek(&keys, space, dek_id.get()).await?,
        };
        match row {
            Some(row) => self.load_dek(&keys, &row).await,
            None => Err(DataKeyError::UnknownKey { dek_id }),
        }
    }

    fn object_name_key(&self) -> Result<ObjectNameKey, DataKeyError> {
        Ok(self.keys().map_err(locked)?.nk.clone())
    }
}

#[cfg(test)]
mod tests;
