//! Shared, node-keyed pseudonyms for request and database telemetry.

use hmac::digest::CtOutput;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tinycloud_auth::resource::SpaceId;

use crate::keys::StaticSecret;

type PseudonymHmac = Hmac<Sha256>;

/// A constant-time comparable digest; emit its bytes as 64 lowercase hex digits.
pub type Pseudonym = CtOutput<PseudonymHmac>;

/// Cached keyed HMAC state, derived once from the resolved node secret.
///
/// Share one startup instance with an `Arc`. Deliberately has no `Debug`
/// implementation. The same node secret preserves pseudonyms across restarts;
/// rotating the secret rotates pseudonyms. Domains separate account, space and
/// service/space-scoped database identities without retaining their raw values.
pub struct Pseudonymizer {
    account: PseudonymHmac,
    space: PseudonymHmac,
    db: PseudonymHmac,
}

impl Pseudonymizer {
    /// Derive the telemetry-only key without retaining the node secret.
    pub fn new(secret: &StaticSecret) -> Self {
        let key = secret.derive_key(b"tinycloud/telemetry/pseudonyms/v1");
        // HMAC accepts every key length; the constructor cannot reject 32 bytes.
        let mut account = PseudonymHmac::new_from_slice(&key).expect("HMAC accepts 32-byte keys");
        account.update(b"account\0");
        let mut space = PseudonymHmac::new_from_slice(&key).expect("HMAC accepts 32-byte keys");
        space.update(b"space\0");
        let mut db = PseudonymHmac::new_from_slice(&key).expect("HMAC accepts 32-byte keys");
        db.update(b"db\0");
        Self { account, space, db }
    }

    /// Hash the canonical target space-owner DID, not the caller's identity.
    pub fn account_hash(&self, space: &SpaceId) -> Pseudonym {
        let mut account = self.account.clone();
        account.update(space.did().as_str().as_bytes());
        account.finalize()
    }

    /// Hash the exact canonical `SpaceId` display bytes without allocating.
    pub fn space_hash(&self, space: &SpaceId) -> Pseudonym {
        let mut hash = self.space.clone();
        update_space(&mut hash, space);
        hash.finalize()
    }

    /// Hash service, canonical SpaceId display and physical name in the `db\0` domain.
    ///
    /// Each field is prefixed with its byte length as a big-endian `u32`, so
    /// embedded NULs cannot introduce field-boundary collisions. Callers supply
    /// their fixed service identifier and exact physical name; no lowercasing,
    /// path normalization or raw-identity logging occurs here. Canonical space
    /// bytes are streamed without allocating a formatted string.
    ///
    /// Returns an error if a field's byte length cannot be encoded as `u32`.
    pub fn db_hash(
        &self,
        service: &str,
        space: &SpaceId,
        physical_name: &str,
    ) -> Result<Pseudonym, std::num::TryFromIntError> {
        let service_len = u32::try_from(service.len())?;
        let space_len = u32::try_from(
            b"tinycloud:".len() + space.suffix().len() + 1 + space.name().as_str().len(),
        )?;
        let physical_len = u32::try_from(physical_name.len())?;
        let mut db = self.db.clone();
        db.update(&service_len.to_be_bytes());
        db.update(service.as_bytes());
        db.update(&space_len.to_be_bytes());
        update_space(&mut db, space);
        db.update(&physical_len.to_be_bytes());
        db.update(physical_name.as_bytes());
        Ok(db.finalize())
    }
}

fn update_space(hash: &mut PseudonymHmac, space: &SpaceId) {
    hash.update(b"tinycloud:");
    hash.update(space.suffix().as_bytes());
    hash.update(b":");
    hash.update(space.name().as_str().as_bytes());
}
