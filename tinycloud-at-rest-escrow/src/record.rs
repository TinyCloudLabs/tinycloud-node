//! The verification record a TEE writes after a successful test-unlock.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{lp, Ark, ArkId, Digest32, Efp, EscrowBundle, EscrowError, TestUnlock};

const RECORD_VERSION: u32 = 1;
const MAC_INFO: &[u8] = b"tinycloud/at-rest/escrow-record/v1";
const ALL_INDICES: [u8; 3] = [1, 2, 3];
const ALL_PAIRS: [[u8; 2]; 3] = [[1, 2], [1, 3], [2, 3]];

/// Proof that all three escrowed shares were decrypted by their holders and
/// that every pair rebuilt the ARK inside the TEE.
///
/// `mac` is HMAC-SHA256 under a key derived from the ARK, so storage that can
/// rewrite rows can't mint or alter a record. Only a holder of the ARK (the
/// TEE) can check it. Operators pin `efp` after reading a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRecord {
    pub version: u32,
    pub efp: Efp,
    pub ark_id: ArkId,
    pub generation: u32,
    pub verified_indices: Vec<u8>,
    pub pairs: Vec<[u8; 2]>,
    pub canary_fp: Digest32,
    /// The TEE identity that ran the test-unlock, if any (informational).
    pub app_id: Option<String>,
    pub compose_hash: Option<String>,
    /// RFC 3339, the TEE's clock (informational; not a freshness proof).
    pub verified_at: String,
    pub mac: Digest32,
}

impl VerificationRecord {
    /// Parse a record: version first, then strict fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, EscrowError> {
        crate::parse_versioned(bytes, "verification record", RECORD_VERSION)
    }

    /// TEE only. Seal a record for a test-unlock of `bundle`.
    pub fn seal(
        ark: &Ark,
        bundle: &EscrowBundle,
        unlock: &TestUnlock,
        app_id: Option<String>,
        compose_hash: Option<String>,
        verified_at: String,
    ) -> Result<Self, EscrowError> {
        if unlock.efp != bundle.fingerprint() {
            return Err(EscrowError::Record(
                "test-unlock was for a different bundle",
            ));
        }
        let mut record = Self {
            version: RECORD_VERSION,
            efp: unlock.efp,
            ark_id: bundle.ark_id,
            generation: bundle.generation,
            verified_indices: ALL_INDICES.to_vec(),
            pairs: unlock.pairs.clone(),
            canary_fp: bundle.canary_fp,
            app_id,
            compose_hash,
            verified_at,
            mac: Digest32([0; 32]),
        };
        record.mac = record.compute_mac(ark);
        Ok(record)
    }

    fn compute_mac(&self, ark: &Ark) -> Digest32 {
        let mut info = Vec::new();
        lp(&mut info, MAC_INFO);
        let key = ark.derive(&self.ark_id, &info);
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice()).expect("any key length");
        let mut body = Vec::with_capacity(256);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.extend_from_slice(&self.efp.0);
        body.extend_from_slice(&self.ark_id.0);
        body.extend_from_slice(&self.generation.to_be_bytes());
        lp(&mut body, &self.verified_indices);
        lp(&mut body, &self.pairs.concat());
        body.extend_from_slice(&self.canary_fp.0);
        for opt in [&self.app_id, &self.compose_hash] {
            match opt {
                None => body.push(0),
                Some(v) => {
                    body.push(1);
                    lp(&mut body, v.as_bytes());
                }
            }
        }
        lp(&mut body, self.verified_at.as_bytes());
        mac.update(&body);
        Digest32(mac.finalize().into_bytes().into())
    }

    /// TEE only. The record is authentic (MAC under `ark`), belongs to
    /// `bundle`, and covers all three shares and all three pairs.
    pub fn verify(&self, ark: &Ark, bundle: &EscrowBundle) -> Result<(), EscrowError> {
        if self.version != RECORD_VERSION {
            return Err(EscrowError::Record("unsupported version"));
        }
        if self.compute_mac(ark) != self.mac {
            return Err(EscrowError::Record("MAC does not verify under this ARK"));
        }
        self.covers(bundle)
    }

    /// Public checks (no ARK): the record names `bundle` and claims full
    /// coverage. Holders and operators run this before pinning `efp`.
    pub fn covers(&self, bundle: &EscrowBundle) -> Result<(), EscrowError> {
        if self.efp != bundle.fingerprint()
            || self.ark_id != bundle.ark_id
            || self.generation != bundle.generation
            || self.canary_fp != bundle.canary_fp
        {
            return Err(EscrowError::Record(
                "record is for a different escrow bundle",
            ));
        }
        if self.verified_indices != ALL_INDICES || self.pairs != ALL_PAIRS {
            return Err(EscrowError::Record(
                "record does not cover all three shares and pairs",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    type Edit = Box<dyn Fn(&mut VerificationRecord)>;

    fn sealed() -> (Ark, EscrowBundle, VerificationRecord) {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let unlock = bundle.test_unlock(&ark, &open_all(&bundle, &ids)).unwrap();
        let record = VerificationRecord::seal(
            &ark,
            &bundle,
            &unlock,
            Some("app".into()),
            None,
            "2026-10-17T00:00:00Z".into(),
        )
        .unwrap();
        (ark, bundle, record)
    }

    #[test]
    fn sealed_record_verifies_and_survives_json() {
        let (ark, bundle, record) = sealed();
        record.verify(&ark, &bundle).unwrap();
        let back: VerificationRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        back.verify(&ark, &bundle).unwrap();
    }

    #[test]
    fn any_edit_or_other_ark_breaks_the_mac() {
        let (ark, bundle, record) = sealed();
        assert!(record.verify(&Ark::generate(), &bundle).is_err());
        let edits: Vec<Edit> = vec![
            Box::new(|r| r.app_id = Some("other".into())),
            Box::new(|r| r.app_id = None),
            Box::new(|r| r.compose_hash = Some(String::new())),
            Box::new(|r| r.verified_at.push('x')),
            Box::new(|r| r.mac.0[0] ^= 1),
        ];
        for edit in edits {
            let mut forged = record.clone();
            edit(&mut forged);
            assert!(forged.verify(&ark, &bundle).is_err());
        }
    }

    #[test]
    fn record_does_not_cover_a_different_or_partial_escrow() {
        let (ark, bundle, record) = sealed();
        // Same ARK, re-split to the same holders: new ciphertexts, new EFP.
        let resplit = EscrowBundle::create(
            &ark,
            bundle.ark_id,
            1,
            &bundle.holders(),
            RecipientPolicy::AllowSoftware,
        )
        .unwrap();
        assert!(record.verify(&ark, &resplit).is_err());

        let mut partial = record.clone();
        partial.verified_indices = vec![1, 2];
        partial.pairs = vec![[1, 2]];
        partial.mac = partial.compute_mac(&ark);
        assert!(partial.verify(&ark, &bundle).is_err());
    }
}
