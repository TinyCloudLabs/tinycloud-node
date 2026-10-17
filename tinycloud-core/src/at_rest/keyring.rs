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
    chain_ark, new_dek, object_name_key, open_ark, open_chain, seal_ark, unwrap_dek, Kek, WrapKey,
    W_LABEL,
};
use super::store::{
    ark_mirror_name, escrow_mirror_name, AtRestStore, KeyMirror, MirroredArk, ARK_MIRROR_PREFIX,
    MIRROR_PREFIX,
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
}

#[derive(Debug, thiserror::Error)]
pub enum AtRestError {
    #[error("at-rest key store: {0}")]
    Store(#[from] DbErr),
    #[error("at-rest key mirror: {0}")]
    Mirror(String),
    #[error("at-rest key state is inconsistent: {0}")]
    Inconsistent(&'static str),
    #[error("at-rest escrow: {0}")]
    Escrow(#[from] EscrowError),
    #[error("at-rest keys are locked")]
    Locked,
    #[error("at-rest keys are not provisioned")]
    NotProvisioned,
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
}

impl Keys {
    fn newest(&self) -> (u32, &Generation) {
        let (g, gen) = self.gens.last_key_value().expect("at least generation 1");
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

/// Open every generation from the rows: the newest under W, older ones via
/// their chain (or W). `Ok(None)` means the newest doesn't open under W.
fn unlock_rows(w: &WrapKey, rows: &[at_rest_key::Model]) -> Result<Option<Keys>, AtRestError> {
    for (i, row) in rows.iter().enumerate() {
        if row.generation != i as i32 + 1 {
            return Err(AtRestError::Inconsistent("ARK generations are not 1..n"));
        }
    }
    let newest = rows.last().expect("caller checked non-empty");
    let newest_id = ark_id_of(newest)?;
    let Ok(ark) = open_ark(
        w,
        &newest.sealed,
        &newest_id,
        newest.generation as u32,
        &newest.w_label,
    ) else {
        return Ok(None);
    };
    keys_from_newest(w, rows, ark).map(Some)
}

fn keys_from_newest(
    w: &WrapKey,
    rows: &[at_rest_key::Model],
    newest_ark: Ark,
) -> Result<Keys, AtRestError> {
    let mut gens = BTreeMap::new();
    let mut newer: Option<(Ark, ArkId)> = None;
    let mut ark = Some(newest_ark);
    for row in rows.iter().rev() {
        let id = ark_id_of(row)?;
        let g = row.generation as u32;
        let this = match ark.take() {
            Some(a) => a,
            None => {
                let (n_ark, n_id) = newer.as_ref().expect("set after the newest");
                row.chain
                    .as_deref()
                    .and_then(|c| open_chain(n_ark, n_id, c, &id, g).ok())
                    .or_else(|| open_ark(w, &row.sealed, &id, g, &row.w_label).ok())
                    .ok_or(AtRestError::Inconsistent(
                        "an older ARK generation opens neither by chain nor by W",
                    ))?
            }
        };
        newer = Some((this.clone(), id));
        gens.insert(
            g,
            Generation {
                ark_id: id,
                kek: Kek::derive(&this),
                ark: this,
            },
        );
    }
    let nk = object_name_key(&gens.get(&1).expect("generation 1 exists").ark);
    Ok(Keys { gens, nk })
}

pub struct AtRestKeyring {
    store: AtRestStore,
    mirror: Arc<dyn KeyMirror>,
    w: WrapKey,
    config: KeyringConfig,
    phase: RwLock<Phase>,
    deks: Mutex<LruCache<(String, u32), DataKey>>,
    current: Mutex<LruCache<String, DekId>>,
    intake: tokio::sync::Mutex<ShareIntake>,
    dek_create: tokio::sync::Mutex<()>,
}

impl AtRestKeyring {
    /// Load the keyring at boot.
    ///
    /// - Rows open under this root's W: unlocked.
    /// - Rows exist but don't open: **locked** (data intact; recover with two
    ///   shares).
    /// - No rows: restore them from the mirror if it has any; otherwise
    ///   provision generation 1 if `config.provision`, else not provisioned.
    ///   A store or mirror error fails the call; it never provisions over
    ///   uncertainty, and never when data keys exist without an ARK.
    pub async fn open(
        store: AtRestStore,
        mirror: Arc<dyn KeyMirror>,
        root: &[u8],
        config: KeyringConfig,
    ) -> Result<Self, AtRestError> {
        let w = WrapKey::derive(root);
        let mut rows = store.keys().await?;
        if rows.is_empty() {
            rows = Self::restore_rows(&store, &*mirror).await?;
        }
        if rows.is_empty() {
            if store.has_space_keys().await? {
                return Err(AtRestError::Inconsistent(
                    "data keys exist but no ARK row or mirrored ARK was found",
                ));
            }
            if config.provision {
                let ark = Ark::generate();
                let ark_id = ArkId::generate();
                store
                    .insert_key(at_rest_key::Model {
                        generation: 1,
                        ark_id: ark_id.0.to_vec(),
                        w_label: W_LABEL.into(),
                        sealed: seal_ark(&w, &ark, &ark_id, 1),
                        chain: None,
                        created_at: now_rfc3339(),
                    })
                    .await?;
                // Another process may have won the insert; use what's stored.
                rows = store.keys().await?;
                tracing::info!(generation = 1, %ark_id, "at-rest root key provisioned");
            }
        }
        let phase = if rows.is_empty() {
            Phase::NotProvisioned
        } else {
            match unlock_rows(&w, &rows)? {
                Some(keys) => {
                    for row in &rows {
                        Self::mirror_row(&*mirror, row).await?;
                    }
                    Phase::Unlocked(Arc::new(keys))
                }
                None => {
                    let newest = rows.last().expect("non-empty");
                    tracing::warn!(
                        generation = newest.generation,
                        "at-rest keys locked: this node's root cannot unseal the ARK"
                    );
                    Phase::Locked {
                        generation: newest.generation as u32,
                        ark_id: ark_id_of(newest)?,
                    }
                }
            }
        };
        let keyring = Self {
            store,
            mirror,
            w,
            config,
            phase: RwLock::new(phase),
            deks: Mutex::new(LruCache::new(
                NonZeroUsize::new(DEK_CACHE).expect("non-zero"),
            )),
            current: Mutex::new(LruCache::new(
                NonZeroUsize::new(DEK_CACHE).expect("non-zero"),
            )),
            intake: tokio::sync::Mutex::new(ShareIntake::new()),
            dek_create: tokio::sync::Mutex::new(()),
        };
        if keyring.state() == KeyringState::Unlocked {
            keyring.ensure_escrow().await?;
        }
        Ok(keyring)
    }

    async fn restore_rows(
        store: &AtRestStore,
        mirror: &dyn KeyMirror,
    ) -> Result<Vec<at_rest_key::Model>, AtRestError> {
        let mut names = mirror.list(ARK_MIRROR_PREFIX).await.map_err(mirror_err)?;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        names.sort();
        for name in names {
            let bytes =
                mirror
                    .get(&name)
                    .await
                    .map_err(mirror_err)?
                    .ok_or(AtRestError::Inconsistent(
                        "mirrored ARK vanished while listing",
                    ))?;
            let row = serde_json::from_slice::<MirroredArk>(&bytes)
                .map_err(mirror_err)?
                .into_row()
                .map_err(mirror_err)?;
            store.insert_key(row).await?;
        }
        tracing::warn!("at-rest ARK rows were missing from the database; restored from the mirror");
        Ok(store.keys().await?)
    }

    async fn mirror_row(
        mirror: &dyn KeyMirror,
        row: &at_rest_key::Model,
    ) -> Result<(), AtRestError> {
        let name = ark_mirror_name(row.generation as u32, &hex::encode(&row.ark_id));
        let body = serde_json::to_vec(&MirroredArk::from_row(row)).expect("serializable");
        if mirror.get(&name).await.map_err(mirror_err)?.as_deref() != Some(body.as_slice()) {
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

    fn keys(&self) -> Result<Arc<Keys>, AtRestError> {
        match &*self.phase.read() {
            Phase::Unlocked(keys) => Ok(keys.clone()),
            Phase::Locked { .. } => Err(AtRestError::Locked),
            Phase::NotProvisioned => Err(AtRestError::NotProvisioned),
        }
    }

    fn parse_bundle(row: &at_rest_escrow::Model) -> Result<EscrowBundle, AtRestError> {
        let bundle: EscrowBundle = serde_json::from_str(&row.bundle)
            .map_err(|_| AtRestError::Inconsistent("stored escrow bundle is not valid JSON"))?;
        bundle.validate()?;
        if bundle.fingerprint().to_string() != row.efp {
            return Err(AtRestError::Inconsistent(
                "stored escrow bundle does not match its fingerprint",
            ));
        }
        Ok(bundle)
    }

    /// Make sure the newest generation is escrowed to exactly the configured
    /// holders. A different holder list re-splits the same ARK into a new
    /// bundle (new EFP, so a new ceremony); old bundles are kept inactive.
    async fn ensure_escrow(&self) -> Result<Option<EscrowBundle>, AtRestError> {
        if self.config.holders.is_empty() {
            return Ok(None);
        }
        let keys = self.keys()?;
        let (g, gen) = keys.newest();
        if let Some(row) = self.store.active_escrow(g as i32).await? {
            let bundle = Self::parse_bundle(&row)?;
            if bundle.holders() == self.config.holders && bundle.ark_id == gen.ark_id {
                self.mirror_escrow(&row).await?;
                return Ok(Some(bundle));
            }
        }
        let bundle = EscrowBundle::create(
            &gen.ark,
            gen.ark_id,
            g,
            &self.config.holders,
            self.config.recipient_policy,
        )?;
        let row = at_rest_escrow::Model {
            efp: bundle.fingerprint().to_string(),
            generation: g as i32,
            bundle: serde_json::to_string(&bundle).expect("serializable"),
            active: true,
            record: None,
            created_at: now_rfc3339(),
        };
        self.store.activate_escrow(row.clone()).await?;
        self.mirror_escrow(&row).await?;
        tracing::warn!(
            generation = g,
            efp = %row.efp,
            "at-rest escrow bundle created; the escrow ceremony must verify it before encryption can be enabled"
        );
        Ok(Some(bundle))
    }

    async fn mirror_escrow(&self, row: &at_rest_escrow::Model) -> Result<(), AtRestError> {
        let name = escrow_mirror_name(&row.efp);
        if self.mirror.get(&name).await.map_err(mirror_err)?.is_none() {
            self.mirror
                .put(&name, row.bundle.clone().into_bytes())
                .await
                .map_err(mirror_err)?;
        }
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
        let Some(bytes) = self
            .mirror
            .get(&escrow_mirror_name(&efp))
            .await
            .map_err(mirror_err)?
        else {
            return Ok(None);
        };
        let bundle: EscrowBundle = serde_json::from_slice(&bytes)
            .map_err(|_| AtRestError::Inconsistent("mirrored escrow bundle is not valid JSON"))?;
        bundle.validate()?;
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
            None => self.ensure_escrow().await?.ok_or(ShareRefusal::NoBundle(
                "no escrow recipients are configured",
            )),
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
        let Ok(record) = serde_json::from_str::<VerificationRecord>(&json) else {
            return Ok(None);
        };
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
        let bundle = match self.ensure_escrow().await {
            Ok(Some(b)) => b,
            _ => return Err(GateRefusal::NoEscrow),
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
            _ => Err(GateRefusal::NotVerified {
                efp: efp.to_string(),
            }),
        }
    }

    /// Take one wrapped share (age file to this boot's recovery recipient).
    ///
    /// Each share is checked against its commitment before it occupies one of
    /// three slots (one per index); submissions are rate limited per boot.
    /// Share bytes are never logged.
    pub async fn submit_share(&self, wrapped: &[u8]) -> Result<ShareOutcome, ShareRefusal> {
        let mut intake = self.intake.lock().await;
        if !intake.take_token() {
            return Err(ShareRefusal::RateLimited);
        }
        let share = intake.identity.open(wrapped)?;
        let bundle = self.intake_bundle().await?;
        bundle.verify_share(&share)?;
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
                    .put(
                        &format!("{MIRROR_PREFIX}record-{efp}.json"),
                        json.into_bytes(),
                    )
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

    /// Locked → unlocked with a recovered newest ARK: re-seal every
    /// generation under this node's W, mirror, and serve keys.
    async fn unlock_with(&self, ark: Ark, bundle: &EscrowBundle) -> Result<(), AtRestError> {
        let rows = self.store.keys().await?;
        let newest = rows.last().ok_or(AtRestError::NotProvisioned)?;
        if newest.generation as u32 != bundle.generation || ark_id_of(newest)? != bundle.ark_id {
            return Err(AtRestError::Inconsistent(
                "recovered ARK is not the newest generation",
            ));
        }
        let keys = keys_from_newest(&self.w, &rows, ark)?;
        for (g, gen) in &keys.gens {
            self.store
                .reseal_key(
                    *g as i32,
                    W_LABEL,
                    seal_ark(&self.w, &gen.ark, &gen.ark_id, *g),
                )
                .await?;
        }
        for row in self.store.keys().await? {
            Self::mirror_row(&*self.mirror, &row).await?;
        }
        *self.phase.write() = Phase::Unlocked(Arc::new(keys));
        tracing::warn!(
            generation = bundle.generation,
            "at-rest keys recovered from escrow and resealed under this node's root"
        );
        Ok(())
    }

    /// Start ARK generation n+1. Older generations stay readable through the
    /// chain; new DEKs wrap under the new KEK. The new generation has no
    /// verified escrow until a ceremony runs, so the gate closes.
    pub async fn rotate_ark(&self) -> Result<u32, AtRestError> {
        let keys = self.keys()?;
        let (g, old) = keys.newest();
        let next = g + 1;
        let ark = Ark::generate();
        let ark_id = ArkId::generate();
        self.store
            .insert_key(at_rest_key::Model {
                generation: next as i32,
                ark_id: ark_id.0.to_vec(),
                w_label: W_LABEL.into(),
                sealed: seal_ark(&self.w, &ark, &ark_id, next),
                chain: None,
                created_at: now_rfc3339(),
            })
            .await?;
        self.store
            .set_chain(g as i32, chain_ark(&ark, &ark_id, &old.ark, &old.ark_id, g))
            .await?;
        let rows = self.store.keys().await?;
        let keys = unlock_rows(&self.w, &rows)?.ok_or(AtRestError::Inconsistent(
            "a just-written generation does not open",
        ))?;
        for row in &rows {
            Self::mirror_row(&*self.mirror, row).await?;
        }
        *self.phase.write() = Phase::Unlocked(Arc::new(keys));
        self.current.lock().clear();
        self.ensure_escrow().await?;
        Ok(next)
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
                    None => {
                        let (g, gen) = keys.newest();
                        let id = DekId::new(1);
                        let (wrapped, _) = new_dek(&gen.kek, space, id, g, &gen.ark_id);
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
                        // Another process may have won; serve whatever is stored.
                        self.store
                            .dek(space, 1)
                            .await
                            .map_err(backend)?
                            .ok_or_else(|| {
                                backend(AtRestError::Inconsistent("inserted data key is missing"))
                            })?
                    }
                }
            }
        };
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
        match self.store.dek(space, id).await.map_err(backend)? {
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
