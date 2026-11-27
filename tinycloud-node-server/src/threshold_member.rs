//! Threshold-member key: a member's identity for one threshold network N,
//! generated inside the CVM and kept on the member's share volume (gate A
//! v5.1 D7). It is never derived from dstack's key-derivation endpoint, so a
//! provider KMS rotation, which changes every key that endpoint returns,
//! leaves it unchanged.
//!
//! - [`MemberKeys`] owns the key records under `<share dir>/member/`
//!   (D7.1, D7.2, D7.4).
//! - [`member_attestation`] is the `POST /threshold/<N>/member-attestation`
//!   handler body (D7.3); the caller mounts it.
//! - [`binding`] holds the `report_data` and proof-of-possession encodings and
//!   the owner-side check.
//! - [`admission`] verifies the owner's admission of this member.
//!
//! No path here logs, returns or stores key material outside the record file.

pub mod admission;
pub mod binding;
mod record;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use tinycloud_core::encryption_network::NetworkId;
use zeroize::Zeroizing;

pub use admission::{AdmissionRefused, InvocationAdmission, OwnerAdmission};
pub use record::network_dir_name;

/// The owner's admission ability for a threshold member (Naomi, 2026-11-27).
pub const MEMBER_ADMIT_ACTION: &str = "tinycloud.encryption/member.admit";

/// HKDF-SHA256 `info` for the member's Ed25519 signing key.
pub const SIGN_LABEL: &[u8] = b"tinycloud/threshold-member/v1/sign";

/// Most keys this member keeps, across all owners, while it holds no share
/// or candidate of their network. A pending key exists only between an
/// owner's admission and the ceremony that hands this member its share;
/// beyond the cap the member refuses new admissions until a ceremony
/// completes or a pending key expires.
///
/// Disk bound: pending key records take at most
/// `64 × MAX_KEY_RECORD_BYTES = 64 × 1581 = 101,184` bytes, plus their
/// directories.
pub const MAX_PENDING_KEYS: usize = 64;

/// Most pending keys one network owner can make this member keep, so one
/// confused or compromised owner session can't take the global cap.
pub const MAX_PENDING_KEYS_PER_OWNER: usize = 2;

/// How long a pending key lives before it is unlinked. A ceremony is relayed
/// by the owner's device within minutes, and a failed one is retried with a
/// fresh ceremony id under the same admission. 24 hours covers retries across
/// a working day and an overnight relay outage, while a key that never gets a
/// share leaves the volume the next day. A key with no share protects nothing,
/// so the expiry costs at most a fresh admission.
pub const PENDING_KEY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Longest accepted network URN, in bytes (the crate's certificate cap).
pub const MAX_URN_BYTES: usize = 1024;
/// Longest accepted dstack `app_id` or `instance_id`, in bytes.
pub const MAX_IDENTITY_FIELD_BYTES: usize = 256;
/// Largest key record file: version byte, length-prefixed URN, `app_id` and
/// `instance_id` at their caps, and the 32-byte seed (1581 bytes).
pub const MAX_KEY_RECORD_BYTES: usize =
    1 + (4 + MAX_URN_BYTES) + 2 * (4 + MAX_IDENTITY_FIELD_BYTES) + 32;
const _: () = assert!(MAX_KEY_RECORD_BYTES == 1581);

/// True when `urn` is exactly the canonical spelling of a network id.
pub fn is_canonical_urn(urn: &str) -> bool {
    urn.len() <= MAX_URN_BYTES
        && urn
            .parse::<NetworkId>()
            .is_ok_and(|network| network.to_string() == urn)
}

/// N's canonical URN, when N can name a member key: canonical and at most
/// [`MAX_URN_BYTES`], so its record decodes and its binding encodes. Checked
/// before any file or directory is created.
fn member_urn(network: &NetworkId) -> Result<String, MemberKeyError> {
    let urn = network.to_string();
    if urn.len() > MAX_URN_BYTES {
        return Err(MemberKeyError::InvalidNetwork("network URN is too long"));
    }
    if !is_canonical_urn(&urn) {
        return Err(MemberKeyError::InvalidNetwork(
            "network URN is not canonical",
        ));
    }
    Ok(urn)
}

/// The `did:key` of a raw Ed25519 public key.
pub fn member_did(public_key: &[u8; 32]) -> String {
    use tinycloud_auth::ipld_core::cid::multibase;
    let multicodec = [[0xed, 0x01].as_slice(), public_key.as_slice()].concat();
    format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, multicodec)
    )
}

/// A refused or failed member-key operation. Carries no key material.
#[derive(Debug, thiserror::Error)]
pub enum MemberKeyError {
    #[error("member_admission_refused: {0}")]
    AdmissionRefused(#[from] AdmissionRefused),
    #[error("member_key_invalid_request: {0}")]
    InvalidRequest(&'static str),
    #[error("member_key_invalid_network: {0}")]
    InvalidNetwork(&'static str),
    #[error("member_key_pending_cap: {MAX_PENDING_KEYS} pending member keys already exist")]
    PendingCapReached,
    #[error("member_key_owner_pending_cap: the network owner already has {MAX_PENDING_KEYS_PER_OWNER} pending member keys")]
    OwnerPendingCapReached,
    #[error("member_key_identity_mismatch: the key record names another {0}")]
    IdentityMismatch(&'static str),
    #[error("member_key_record_malformed: {0}")]
    MalformedRecord(&'static str),
    #[error("member_key_missing: this member holds a share or candidate of the network but no key record")]
    KeyMissing,
    #[error("member_key_absent: no key record for the network")]
    NoKey,
    #[error("member_key_still_held: this member still holds a share or candidate of the network")]
    StillHeld,
    #[error("member_key_unlinked: the member key was unlinked before it could sign")]
    Unlinked,
    #[error("member_key_share_dir_missing: the share volume directory does not exist")]
    ShareDirMissing,
    #[error("member_key_identity_unavailable: {0}")]
    IdentityUnavailable(String),
    #[error("member_key_holdings_unknown: {0}")]
    HoldingsUnknown(String),
    #[error("member_key_quote_failed: {0}")]
    Quote(String),
    #[error("member_key_io: {0}")]
    Io(#[from] std::io::Error),
}

impl MemberKeyError {
    /// The audit reason for a refusal: a fixed name, never request content.
    fn reason(&self) -> &'static str {
        match self {
            Self::AdmissionRefused(_) => "unauthorized",
            Self::InvalidRequest(_) => "invalid-request",
            Self::InvalidNetwork(_) => "invalid-network",
            Self::PendingCapReached => "pending-cap",
            Self::OwnerPendingCapReached => "owner-pending-cap",
            Self::IdentityMismatch(_) => "identity-mismatch",
            Self::MalformedRecord(_) => "malformed-record",
            Self::KeyMissing => "key-missing",
            Self::NoKey => "no-key",
            Self::StillHeld => "still-held",
            Self::Unlinked => "unlinked",
            Self::ShareDirMissing => "share-dir-missing",
            Self::IdentityUnavailable(_) => "identity-unavailable",
            Self::HoldingsUnknown(_) => "holdings-unknown",
            Self::Quote(_) => "quote-failed",
            Self::Io(_) => "io",
        }
    }
}

/// This CVM's identity as dstack `/Info` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalIdentity {
    pub app_id: String,
    pub instance_id: String,
}

impl LocalIdentity {
    /// Read `/Info` from the guest agent at `socket`. Refuses an empty or
    /// over-long `app_id` or `instance_id` (an app without instance ids has
    /// nothing to bind a member key to).
    pub async fn read(socket: &str) -> Result<Self, MemberKeyError> {
        let info = crate::dstack::get_info_at(socket)
            .await
            .map_err(|error| MemberKeyError::IdentityUnavailable(format!("{error:#}")))?;
        for (name, value) in [("app_id", &info.app_id), ("instance_id", &info.instance_id)] {
            if value.is_empty() || value.len() > MAX_IDENTITY_FIELD_BYTES {
                return Err(MemberKeyError::IdentityUnavailable(format!(
                    "{name} is empty or too long"
                )));
            }
        }
        Ok(Self {
            app_id: info.app_id,
            instance_id: info.instance_id,
        })
    }
}

/// What this member holds of a network, supplied by the share store.
pub trait MemberHoldings: Send + Sync {
    /// True when this member holds a share or a candidate share of `network`.
    /// A key is *pending* while this is false.
    fn holds_share_or_candidate(&self, network: &NetworkId) -> anyhow::Result<bool>;
}

/// One non-secret audit event for the caller to record in `encryption_audit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberKeyAudit {
    /// `member_key_refused`, `member_key_expired` or `member_key_unlinked`.
    pub event: &'static str,
    pub network: String,
    /// The member key's DID, when one exists.
    pub member_did: Option<String>,
    /// `refused` or `unlinked` (a logical erasure, never a physical one).
    pub outcome: &'static str,
    pub reason: &'static str,
}

impl MemberKeyAudit {
    fn refused(network: &NetworkId, error: &MemberKeyError) -> Self {
        Self {
            event: "member_key_refused",
            network: network.to_string(),
            member_did: None,
            outcome: "refused",
            reason: error.reason(),
        }
    }
}

/// Why a member key is logically erased.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlinkReason {
    /// The member erased its last share and candidate of the network.
    LastShare,
    /// The key stayed pending for [`PENDING_KEY_TTL`].
    PendingTtl,
}

impl UnlinkReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::LastShare => "last-share",
            Self::PendingTtl => "pending-ttl",
        }
    }

    fn event(self) -> &'static str {
        match self {
            Self::LastShare => "member_key_unlinked",
            Self::PendingTtl => "member_key_expired",
        }
    }
}

/// A derived member signing key. It lives only in its network's slot in
/// [`MemberKeys`], is wiped on drop and is never printed.
struct MemberKey {
    network: String,
    signing: SigningKey,
}

impl std::fmt::Debug for MemberKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberKey")
            .field("network", &self.network)
            .field("did", &self.did())
            .field("signing", &"<redacted>")
            .finish()
    }
}

impl MemberKey {
    fn from_record(record: &record::KeyRecord) -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, record.seed.as_ref())
            .expand(SIGN_LABEL, secret.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self {
            network: record.network.clone(),
            signing: SigningKey::from_bytes(&secret),
        }
    }

    fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn did(&self) -> String {
        member_did(&self.public_key())
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    fn public(&self) -> MemberPublicKey {
        MemberPublicKey {
            network: self.network.clone(),
            public_key: self.public_key(),
        }
    }
}

/// The public half of a loaded member key. Signing goes through
/// [`MemberKeys::sign`], so an unlink revokes every holder at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberPublicKey {
    network: String,
    public_key: [u8; 32],
}

impl MemberPublicKey {
    /// The raw Ed25519 public key `P`.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The member DID the certificate names.
    pub fn did(&self) -> String {
        member_did(&self.public_key)
    }

    /// The canonical URN of the key's network.
    pub fn network(&self) -> &str {
        &self.network
    }
}

/// The threshold-member key records on one share volume, and the signing
/// keys loaded from them.
pub struct MemberKeys {
    root: PathBuf,
    /// Serializes the pending-cap check with key generation, loading keys
    /// into their slots and unlinking them, in this process. The record
    /// install itself is single-winner on disk.
    generate: Mutex<()>,
    /// One signing-key slot per network URN, the only place a signing key
    /// lives. Taken after `generate`, never across an await.
    slots: Mutex<HashMap<String, MemberKey>>,
}

impl MemberKeys {
    /// Key records under `share_dir/member/`.
    pub fn new(share_dir: &Path) -> Self {
        Self {
            root: share_dir.to_path_buf(),
            generate: Mutex::new(()),
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<String, MemberKey>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Put the key of `record` in its network's slot, replacing any other.
    /// Call with `generate` held.
    fn activate(&self, record: &record::KeyRecord) -> MemberPublicKey {
        let key = MemberKey::from_record(record);
        let public = key.public();
        self.slots().insert(record.network.clone(), key);
        public
    }

    /// Sign `message` with the member key of `network`, if that key is still
    /// `member_pk`. Refused with [`MemberKeyError::Unlinked`] once the key
    /// was unlinked or replaced, so nothing signs with a key after D7.4's
    /// first step.
    pub fn sign(
        &self,
        network: &NetworkId,
        member_pk: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64], MemberKeyError> {
        match self.slots().get(&network.to_string()) {
            Some(key) if key.public_key() == *member_pk => Ok(key.sign(message)),
            _ => Err(MemberKeyError::Unlinked),
        }
    }

    fn dir(&self, network: &NetworkId) -> PathBuf {
        record::network_dir(&self.root, &network.to_string())
    }

    /// The key record for `network`, checked against this CVM's identity.
    /// `Ok(None)` when there is none. A record for another network, app or
    /// instance, or one that doesn't decode, is refused and left untouched.
    fn checked_record(
        &self,
        network: &NetworkId,
        identity: &LocalIdentity,
    ) -> Result<Option<record::KeyRecord>, MemberKeyError> {
        let Some(found) = record::read_record(&self.dir(network).join(record::KEY_FILE))? else {
            return Ok(None);
        };
        if found.network != network.to_string() {
            return Err(MemberKeyError::IdentityMismatch("network"));
        }
        if found.identity.app_id != identity.app_id {
            return Err(MemberKeyError::IdentityMismatch("app_id"));
        }
        if found.identity.instance_id != identity.instance_id {
            return Err(MemberKeyError::IdentityMismatch("instance_id"));
        }
        Ok(Some(found))
    }

    /// The member key for `network`, for a member operation: loads it into
    /// its slot and returns its public half. Never creates one.
    pub fn load(
        &self,
        network: &NetworkId,
        identity: &LocalIdentity,
    ) -> Result<MemberPublicKey, MemberKeyError> {
        let _generate = self.generate.lock().unwrap_or_else(|e| e.into_inner());
        let found = self
            .checked_record(network, identity)?
            .ok_or(MemberKeyError::NoKey)?;
        Ok(self.activate(&found))
    }

    /// The member key for `network` after a verified owner admission: the
    /// installed one, or a new one if there is none, loaded into its slot.
    /// Call only after [`OwnerAdmission::verify`] succeeded.
    ///
    /// A pending key older than [`PENDING_KEY_TTL`] is unlinked first and
    /// replaced. A missing key while the member holds a share or candidate of
    /// `network` is refused, as is a new key beyond [`MAX_PENDING_KEYS`] or
    /// beyond [`MAX_PENDING_KEYS_PER_OWNER`] for N's owner.
    ///
    /// Audit events go to `audit` as they happen, so an expiry is recorded
    /// even when a later step refuses the admission.
    pub fn admit(
        &self,
        network: &NetworkId,
        identity: &LocalIdentity,
        holdings: &dyn MemberHoldings,
        now: SystemTime,
        audit: &mut Vec<MemberKeyAudit>,
    ) -> Result<MemberPublicKey, MemberKeyError> {
        let urn = member_urn(network)?;
        let _generate = self.generate.lock().unwrap_or_else(|e| e.into_inner());
        record::sweep_temp_records(&self.dir(network))?;
        let held = holds(holdings, network)?;
        if let Some(found) = self.checked_record(network, identity)? {
            if held || !self.expired(network, now)? {
                return Ok(self.activate(&found));
            }
            drop(found);
            audit.push(self.unlink(network, UnlinkReason::PendingTtl)?);
        } else if held {
            return Err(MemberKeyError::KeyMissing);
        }
        let (pending, owned) = self.pending_keys(holdings, network.owner_did())?;
        if pending >= MAX_PENDING_KEYS {
            return Err(MemberKeyError::PendingCapReached);
        }
        if owned >= MAX_PENDING_KEYS_PER_OWNER {
            return Err(MemberKeyError::OwnerPendingCapReached);
        }
        let installed = record::install_or_load(
            &self.dir(network),
            record::KeyRecord::generate(&urn, identity),
        )?;
        Ok(self.activate(&installed))
    }

    fn expired(&self, network: &NetworkId, now: SystemTime) -> Result<bool, MemberKeyError> {
        // The record is written once and never modified, so its mtime is
        // its install time.
        let installed = std::fs::metadata(self.dir(network).join(record::KEY_FILE))?.modified()?;
        Ok(now.duration_since(installed).unwrap_or_default() >= PENDING_KEY_TTL)
    }

    /// The networks of the installed key records that decode.
    ///
    /// A record that doesn't decode names no network this member can prove it
    /// holds nothing of, so it is never erased (D7.4 positive proof), and it
    /// is left out of the pending count: every record this module writes
    /// decodes (`admit` validates N first), so an undecodable one is damage
    /// or tampering, which an owner admission can't produce, and it must not
    /// hold a cap slot forever. It stays on disk, refused for its network.
    fn installed(&self) -> Result<Vec<NetworkId>, MemberKeyError> {
        let mut found = Vec::new();
        for dir in self.network_dirs()? {
            if let Ok(Some(record)) = record::read_record(&dir.join(record::KEY_FILE)) {
                if let Ok(network) = record.network.parse() {
                    found.push(network);
                }
            }
        }
        Ok(found)
    }

    /// Every per-network directory under `member/`.
    fn network_dirs(&self) -> Result<Vec<PathBuf>, MemberKeyError> {
        let members = self.root.join(record::MEMBER_DIR);
        let entries = match std::fs::read_dir(&members) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        entries
            .map(|entry| Ok(entry?.path()))
            .collect::<Result<_, std::io::Error>>()
            .map_err(Into::into)
    }

    /// Installed keys whose network this member holds no share or candidate
    /// of: all of them, and those of `owner`'s networks.
    fn pending_keys(
        &self,
        holdings: &dyn MemberHoldings,
        owner: &str,
    ) -> Result<(usize, usize), MemberKeyError> {
        let (mut pending, mut owned) = (0, 0);
        for network in self.installed()? {
            if !holds(holdings, &network)? {
                pending += 1;
                if network.owner_did() == owner {
                    owned += 1;
                }
            }
        }
        Ok((pending, owned))
    }

    /// Unlink every pending key older than [`PENDING_KEY_TTL`]
    /// (`member_key_expired`), after wiping every leftover temp record under
    /// `member/`. Keys of networks the member holds a share or candidate of,
    /// and records that don't decode, are never touched. Each event goes to
    /// `audit` as its key is unlinked, so a later failure loses none.
    pub fn expire_pending(
        &self,
        holdings: &dyn MemberHoldings,
        now: SystemTime,
        audit: &mut Vec<MemberKeyAudit>,
    ) -> Result<(), MemberKeyError> {
        let _generate = self.generate.lock().unwrap_or_else(|e| e.into_inner());
        for dir in self.network_dirs()? {
            record::sweep_temp_records(&dir)?;
        }
        for network in self.installed()? {
            if !holds(holdings, &network)? && self.expired(&network, now)? {
                audit.push(self.unlink(&network, UnlinkReason::PendingTtl)?);
            }
        }
        Ok(())
    }

    /// Unlink the key of `network` after the member erased its last share and
    /// candidate of it. Call only on that positive proof; the key of a
    /// network the member still holds anything of is never unlinked.
    pub fn unlink_after_last_share(
        &self,
        network: &NetworkId,
        holdings: &dyn MemberHoldings,
    ) -> Result<MemberKeyAudit, MemberKeyError> {
        let _generate = self.generate.lock().unwrap_or_else(|e| e.into_inner());
        if holds(holdings, network)? {
            return Err(MemberKeyError::StillHeld);
        }
        self.unlink(network, UnlinkReason::LastShare)
    }

    /// D7.4: wipe the in-memory key, so no holder can sign with it any more,
    /// zero-overwrite and unlink the record, then record
    /// `member_key_unlinked_at`. Call with `generate` held, so nothing loads
    /// the key back while the record still exists.
    fn unlink(
        &self,
        network: &NetworkId,
        reason: UnlinkReason,
    ) -> Result<MemberKeyAudit, MemberKeyError> {
        drop(self.slots().remove(&network.to_string()));
        let dir = self.dir(network);
        let found =
            record::read_record(&dir.join(record::KEY_FILE))?.ok_or(MemberKeyError::NoKey)?;
        if found.network != network.to_string() {
            return Err(MemberKeyError::IdentityMismatch("network"));
        }
        let did = MemberKey::from_record(&found).did();
        drop(found);
        record::unlink_key(&dir)?;
        let unlinked_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| MemberKeyError::InvalidRequest("clock"))?;
        let unlinked = serde_json::json!({
            "version": 1,
            "member_key_unlinked_at": unlinked_at,
            "reason": reason.as_str(),
            "member_did": did,
        });
        record::write_unlinked_record(&dir, unlinked.to_string().as_bytes())?;
        tracing::info!(reason = reason.as_str(), "threshold member key unlinked");
        Ok(MemberKeyAudit {
            event: reason.event(),
            network: network.to_string(),
            member_did: Some(did),
            outcome: "unlinked",
            reason: reason.as_str(),
        })
    }
}

fn holds(holdings: &dyn MemberHoldings, network: &NetworkId) -> Result<bool, MemberKeyError> {
    holdings
        .holds_share_or_candidate(network)
        .map_err(|error| MemberKeyError::HoldingsUnknown(format!("{error:#}")))
}

/// The request body of `POST /threshold/<N>/member-attestation`: only the
/// owner's fresh challenge. No key, digest or `report_data` is accepted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequest {
    /// 32 bytes as 64 lowercase hex characters.
    pub nonce: String,
}

/// The answer: `member_pk` (raw Ed25519 key, hex), the dstack `quote` (hex)
/// and `event_log`, and `pop_sig` (Ed25519 signature, hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub member_pk: String,
    pub quote: String,
    pub event_log: String,
    pub pop_sig: String,
}

/// The handler's result and the audit events the caller must record, in
/// order, whether or not it succeeded.
#[derive(Debug)]
pub struct AttestationOutcome {
    pub result: Result<AttestationResponse, MemberKeyError>,
    pub audit: Vec<MemberKeyAudit>,
}

/// What the attestation handler needs from the node.
pub struct MemberAttestation<'a> {
    pub keys: &'a MemberKeys,
    /// The dstack guest agent socket.
    pub dstack_socket: &'a str,
    pub holdings: &'a dyn MemberHoldings,
}

fn parse_nonce(body: &Value) -> Result<[u8; 32], MemberKeyError> {
    let request: AttestationRequest = serde_json::from_value(body.clone())
        .map_err(|_| MemberKeyError::InvalidRequest("body must be exactly {\"nonce\"}"))?;
    let canonical = request.nonce.len() == 64
        && request
            .nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut nonce = [0u8; 32];
    if !canonical || hex::decode_to_slice(&request.nonce, &mut nonce).is_err() {
        return Err(MemberKeyError::InvalidRequest(
            "nonce must be 64 lowercase hex characters",
        ));
    }
    Ok(nonce)
}

/// `POST /threshold/<N>/member-attestation {nonce}` (D7.3).
///
/// `network` is the path segment; the handler binds N's canonical URN, not
/// that spelling. It checks the body, verifies the owner's admission, reads
/// this CVM's identity from dstack, loads or creates the member key, quotes
/// `R` and signs the proof of possession. A refused request creates nothing
/// and yields a `member_key_refused` audit event.
pub async fn member_attestation(
    ctx: &MemberAttestation<'_>,
    network: &str,
    body: &Value,
    admission: &dyn OwnerAdmission,
) -> AttestationOutcome {
    let network = match network
        .parse::<NetworkId>()
        .map_err(|_| MemberKeyError::InvalidNetwork("invalid network id"))
        .and_then(|network| member_urn(&network).map(|_| network))
    {
        Ok(network) => network,
        // No audit event: the request names no network a row could record.
        Err(error) => {
            return AttestationOutcome {
                result: Err(error),
                audit: Vec::new(),
            }
        }
    };
    let mut audit = Vec::new();
    let result = attest(ctx, &network, body, admission, &mut audit).await;
    if let Err(error) = &result {
        tracing::info!(
            reason = error.reason(),
            "threshold member attestation refused"
        );
        audit.push(MemberKeyAudit::refused(&network, error));
    }
    AttestationOutcome { result, audit }
}

async fn attest(
    ctx: &MemberAttestation<'_>,
    network: &NetworkId,
    body: &Value,
    admission: &dyn OwnerAdmission,
    audit: &mut Vec<MemberKeyAudit>,
) -> Result<AttestationResponse, MemberKeyError> {
    let nonce = parse_nonce(body)?;
    admission.verify(network, body).await?;
    let identity = LocalIdentity::read(ctx.dstack_socket).await?;
    let key = ctx
        .keys
        .admit(network, &identity, ctx.holdings, SystemTime::now(), audit)?;
    let urn = network.to_string();
    // Only P is held across the quote; the signature goes through the slot
    // afterwards and is refused if the key was unlinked meanwhile.
    let public_key = key.public_key();
    let report_data = binding::report_data(&urn, &public_key, &nonce)
        .map_err(|_| MemberKeyError::InvalidRequest("binding input"))?;
    let quote = crate::dstack::get_quote(ctx.dstack_socket, &report_data)
        .await
        .map_err(|error| MemberKeyError::Quote(format!("{error:#}")))?;
    let raw_quote = hex::decode(quote.quote.trim_start_matches("0x"))
        .map_err(|_| MemberKeyError::Quote("quote is not hex".into()))?;
    let pop = binding::pop_message(&urn, &nonce, &raw_quote)
        .map_err(|_| MemberKeyError::InvalidRequest("binding input"))?;
    let pop_sig = ctx.keys.sign(network, &public_key, &pop)?;
    Ok(AttestationResponse {
        member_pk: hex::encode(public_key),
        quote: hex::encode(&raw_quote),
        event_log: quote.event_log,
        pop_sig: hex::encode(pop_sig),
    })
}
