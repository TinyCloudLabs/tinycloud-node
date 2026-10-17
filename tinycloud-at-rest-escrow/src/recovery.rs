//! Moving a share from a holder into a TEE: the per-boot recovery identity,
//! the attested binding, and the wrap/unwrap of a share.

use std::io::Read;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::bundle::seal_armored;
use crate::recipients::ParsedRecipient;
use crate::share::PAYLOAD_LEN;
use crate::{sha256, ArkId, Digest32, Efp, EscrowError, SharePayload};

/// Largest wrapped share the TEE reads. A real one is about 400 bytes.
pub const MAX_WRAPPED_SHARE: usize = 4096;
const BINDING_PREFIX: &str = "xyz.tinycloud.at-rest/recovery-key/v1\\0";

/// What `GET /at-rest/recovery?nonce=` returns. Every field is public. Only
/// what the holder recomputes and the verified quote prove anything; the
/// rest is a convenience for humans.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInfo {
    /// `"dstack"` when `quote` is a TDX quote, `"classic"` outside a TEE.
    pub mode: String,
    /// `"locked"` or `"unlocked"`.
    pub state: String,
    pub ark_id: ArkId,
    pub generation: u32,
    pub efp: Efp,
    pub canary_fp: Digest32,
    /// Per-boot X25519 age recipient. Its identity never leaves TEE memory.
    pub recovery_recipient: String,
    /// See [`recovery_binding`].
    pub binding: String,
    pub binding_sha256: Digest32,
    /// Hex TDX quote whose REPORTDATA is `binding_sha256 ‖ 32 zero bytes`.
    pub quote: Option<String>,
    /// dstack event log (JSON text) for replaying RTMR3.
    pub event_log: Option<String>,
    /// Indices of valid shares the TEE holds for this boot.
    pub shares_held: Vec<u8>,
}

/// `xyz.tinycloud.at-rest/recovery-key/v1\0:<recipient>:<efp>:<nonce>`. The
/// `\0` is two characters (backslash, zero), as in `/attestation`.
pub fn recovery_binding(recipient: &str, efp: &Efp, nonce: &str) -> String {
    format!("{BINDING_PREFIX}:{recipient}:{efp}:{nonce}")
}

/// SHA-256 of the binding's UTF-8 bytes; the TDX REPORTDATA's first half.
pub fn binding_digest(binding: &str) -> Digest32 {
    Digest32(sha256(binding.as_bytes()))
}

/// 1-64 chars of `A-Z a-z 0-9 - _` (same rule as `/attestation`).
pub fn validate_nonce(nonce: &str) -> Result<(), EscrowError> {
    if (1..=64).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(EscrowError::Binding(
            "nonce must be 1-64 chars of A-Z a-z 0-9 - _",
        ))
    }
}

/// The TEE's per-boot recovery key. Made fresh at every boot, held only in
/// memory, never serialized.
pub struct RecoveryIdentity(age::x25519::Identity);

impl Default for RecoveryIdentity {
    fn default() -> Self {
        Self::generate()
    }
}

impl RecoveryIdentity {
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    pub fn recipient(&self) -> String {
        self.0.to_public().to_string()
    }

    /// Decrypt a wrapped share (armored or binary age) and decode it. The
    /// caller must still check it against the bundle.
    pub fn open(&self, wrapped: &[u8]) -> Result<SharePayload, EscrowError> {
        if wrapped.len() > MAX_WRAPPED_SHARE {
            return Err(EscrowError::ShareFormat);
        }
        let age_err = |_| EscrowError::Age("wrapped share does not decrypt".into());
        let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(wrapped))
            .map_err(age_err)?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.0 as &dyn age::Identity))
            .map_err(age_err)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
        // One byte past a payload is enough to reject anything longer.
        (&mut reader)
            .take(PAYLOAD_LEN as u64 + 1)
            .read_to_end(&mut plain)
            .map_err(|_| EscrowError::Age("wrapped share does not decrypt".into()))?;
        SharePayload::decode(&plain)
    }
}

impl std::fmt::Debug for RecoveryIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryIdentity({})", self.recipient())
    }
}

/// Holder side. Seal a decrypted share to a TEE recovery recipient. Only
/// X25519 recipients are accepted: the TEE's identity is software.
///
/// Call this only after the TEE's quote and binding have been verified.
pub fn wrap_share(recovery_recipient: &str, share: &SharePayload) -> Result<String, EscrowError> {
    let recipient = recovery_recipient
        .parse::<age::x25519::Recipient>()
        .map_err(|_| EscrowError::Binding("recovery recipient is not an age1 X25519 recipient"))?;
    seal_armored(&ParsedRecipient::X25519(recipient), &share.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::EscrowBundle;

    #[test]
    fn wrapped_share_round_trips_through_the_recovery_identity_only() {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle = EscrowBundle::create(&ark, ark_id, 1, &holders).unwrap();
        let shares = open_all(&bundle, &ids);
        let tee = RecoveryIdentity::generate();
        let wrapped = wrap_share(&tee.recipient(), &shares[2]).unwrap();

        let opened = tee.open(wrapped.as_bytes()).unwrap();
        bundle.verify_share(&opened).unwrap();
        assert_eq!(opened.index, 3);
        assert!(RecoveryIdentity::generate()
            .open(wrapped.as_bytes())
            .is_err());
    }

    #[test]
    fn open_rejects_oversize_and_non_share_plaintext() {
        let tee = RecoveryIdentity::generate();
        assert!(tee.open(&vec![b'a'; MAX_WRAPPED_SHARE + 1]).is_err());
        assert!(tee.open(b"garbage").is_err());
        // A valid age file to the right key that does not hold a share.
        let recipient: age::x25519::Recipient = tee.recipient().parse().unwrap();
        let junk = seal_armored(
            &ParsedRecipient::X25519(recipient.clone()),
            &[7u8; PAYLOAD_LEN],
        )
        .unwrap();
        assert!(matches!(
            tee.open(junk.as_bytes()),
            Err(EscrowError::ShareFormat)
        ));
        let long = seal_armored(&ParsedRecipient::X25519(recipient), &[7u8; 10_000]).unwrap();
        assert!(tee.open(long.as_bytes()).is_err());
    }

    #[test]
    fn wrap_refuses_tag_recipients() {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle = EscrowBundle::create(&ark, ark_id, 1, &holders).unwrap();
        let share = &open_all(&bundle, &ids)[0];
        assert!(wrap_share(&tag_identity().1, share).is_err());
    }

    #[test]
    fn binding_and_nonce_rules() {
        let efp = Digest32([0xab; 32]);
        let b = recovery_binding("age1xyz", &efp, "n0nce");
        assert_eq!(
            b,
            format!("xyz.tinycloud.at-rest/recovery-key/v1\\0:age1xyz:{efp}:n0nce")
        );
        assert_ne!(
            binding_digest(&b),
            binding_digest(&recovery_binding("age1xyz", &efp, "other"))
        );
        validate_nonce("A-z_09").unwrap();
        for bad in ["", "a b", "a:b", &"x".repeat(65)] {
            assert!(validate_nonce(bad).is_err(), "{bad:?}");
        }
    }
}
