//! The escrow bundle: three sealed shares, their commitments and the canary.

use std::io::Write;

use serde::{Deserialize, Serialize};
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::recipients::{
    parse, validate_holders, HolderRecipient, ParsedRecipient, RecipientKind, RecipientPolicy,
};
use crate::share::{SharePayload, PAYLOAD_LEN};
use crate::{
    canary_fingerprint, lp, sha256, Ark, ArkId, Digest32, Efp, EscrowError, HOLDERS, THRESHOLD,
};

const BUNDLE_VERSION: u32 = 1;
const EFP_DOMAIN: &[u8] = b"tinycloud/at-rest/escrow-bundle/v1";
const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
/// An armored age file for a 58-byte payload and one stanza is under 1 KiB.
const MAX_CIPHERTEXT: usize = 4096;

/// One holder's entry in a bundle. Public data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowShare {
    /// 1..=3, the Shamir x-coordinate.
    pub index: u8,
    pub holder: String,
    pub recipient: String,
    /// See [`SharePayload::commitment`].
    pub commitment: Digest32,
    /// ASCII-armored age file sealed to `recipient`. Save it as a file and
    /// open it with `age -d -i <identity>`.
    pub ciphertext: String,
}

/// Everything needed to recover one ARK generation from two holders. Public
/// data: it is stored next to the node's data and handed to the holders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowBundle {
    pub version: u32,
    pub ark_id: ArkId,
    pub generation: u32,
    pub threshold: u8,
    /// See [`canary_fingerprint`].
    pub canary_fp: Digest32,
    pub shares: Vec<EscrowShare>,
}

/// Proof that every pair of shares rebuilt the in-TEE ARK. Only
/// [`EscrowBundle::test_unlock`] makes one, so a
/// [`VerificationRecord`](crate::VerificationRecord) can't be sealed without
/// a real test-unlock.
#[derive(Debug)]
pub struct TestUnlock {
    pub(crate) efp: Efp,
    pub(crate) pairs: Vec<[u8; 2]>,
}

impl TestUnlock {
    pub fn efp(&self) -> Efp {
        self.efp
    }
}

pub(crate) fn seal_armored(
    recipient: &ParsedRecipient,
    plaintext: &[u8],
) -> Result<String, EscrowError> {
    let age_err = |e: &dyn std::fmt::Display| EscrowError::Age(e.to_string());
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient.as_age()))
        .map_err(|e| age_err(&e))?;
    let mut out = Vec::new();
    let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
        .map_err(|e| age_err(&e))?;
    let mut writer = encryptor.wrap_output(armor).map_err(|e| age_err(&e))?;
    writer.write_all(plaintext).map_err(|e| age_err(&e))?;
    writer
        .finish()
        .and_then(|armor| armor.finish())
        .map_err(|e| age_err(&e))?;
    String::from_utf8(out).map_err(|_| EscrowError::Age("armor is not UTF-8".into()))
}

/// Combine two shares. The caller has already checked them against the bundle.
fn combine(a: &SharePayload, b: &SharePayload) -> Result<Ark, EscrowError> {
    let shares = Zeroizing::new(vec![a.share.to_vec(), b.share.to_vec()]);
    let secret = Zeroizing::new(Gf256::combine_array(&*shares).map_err(|_| EscrowError::Shamir)?);
    Ark::from_slice(&secret).ok_or(EscrowError::Shamir)
}

impl EscrowBundle {
    /// TEE only. Split `ark` 2-of-3 and seal share i to `holders[i]`.
    /// Software (X25519) holders are refused unless `policy` allows them.
    ///
    /// Before returning, every pair of fresh shares is combined and compared
    /// with `ark`, so a split that can't be recovered never leaves this call.
    pub fn create(
        ark: &Ark,
        ark_id: ArkId,
        generation: u32,
        holders: &[HolderRecipient],
        policy: RecipientPolicy,
    ) -> Result<Self, EscrowError> {
        validate_holders(holders, policy)?;
        let split = Zeroizing::new(
            Gf256::split_array(
                usize::from(THRESHOLD),
                usize::from(HOLDERS),
                ark.expose(),
                rand::rngs::OsRng,
            )
            .map_err(|_| EscrowError::Shamir)?,
        );
        let payloads = split
            .iter()
            .map(|s| SharePayload::new(ark_id, generation, s))
            .collect::<Result<Vec<_>, _>>()?;
        let mut shares = Vec::with_capacity(holders.len());
        for (i, (holder, payload)) in holders.iter().zip(&payloads).enumerate() {
            if usize::from(payload.index) != i + 1 {
                return Err(EscrowError::Shamir);
            }
            let recipient = parse(&holder.holder, &holder.recipient)?;
            shares.push(EscrowShare {
                index: payload.index,
                holder: holder.holder.clone(),
                recipient: holder.recipient.clone(),
                commitment: payload.commitment(),
                ciphertext: seal_armored(&recipient, &payload.encode())?,
            });
        }
        let bundle = Self {
            version: BUNDLE_VERSION,
            ark_id,
            generation,
            threshold: THRESHOLD,
            canary_fp: canary_fingerprint(ark, &ark_id, generation),
            shares,
        };
        bundle.validate()?;
        bundle.test_unlock(ark, &payloads)?;
        Ok(bundle)
    }

    /// Parse a bundle: version first, then strict fields, then [`validate`](Self::validate).
    pub fn from_json(bytes: &[u8]) -> Result<Self, EscrowError> {
        let bundle: Self = crate::parse_versioned(bytes, "escrow bundle", BUNDLE_VERSION)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Structural checks. Every other method calls this first. Any recipient
    /// kind passes here; apply a policy with [`check_recipients`](Self::check_recipients).
    pub fn validate(&self) -> Result<(), EscrowError> {
        if self.version != BUNDLE_VERSION {
            return Err(EscrowError::Bundle("unsupported version"));
        }
        if self.threshold != THRESHOLD {
            return Err(EscrowError::Bundle("threshold must be 2"));
        }
        if self.shares.len() != usize::from(HOLDERS) {
            return Err(EscrowError::Bundle("bundle must hold exactly 3 shares"));
        }
        for (i, share) in self.shares.iter().enumerate() {
            if usize::from(share.index) != i + 1 {
                return Err(EscrowError::Bundle(
                    "shares must be indexed 1, 2, 3 in order",
                ));
            }
            if share.ciphertext.len() > MAX_CIPHERTEXT || !share.ciphertext.starts_with(ARMOR_BEGIN)
            {
                return Err(EscrowError::Bundle(
                    "share ciphertext is not an armored age file",
                ));
            }
        }
        validate_holders(&self.holders(), RecipientPolicy::AllowSoftware)?;
        Ok(())
    }

    /// The holders' recipient kinds, refusing software holders unless
    /// `policy` allows them.
    pub fn check_recipients(
        &self,
        policy: RecipientPolicy,
    ) -> Result<Vec<RecipientKind>, EscrowError> {
        self.validate()?;
        validate_holders(&self.holders(), policy)
    }

    /// The holders and recipients, in index order.
    pub fn holders(&self) -> Vec<HolderRecipient> {
        self.shares
            .iter()
            .map(|s| HolderRecipient {
                holder: s.holder.clone(),
                recipient: s.recipient.clone(),
            })
            .collect()
    }

    pub fn share_for(&self, holder: &str) -> Option<&EscrowShare> {
        self.shares.iter().find(|s| s.holder == holder)
    }

    /// The escrow fingerprint:
    /// `SHA-256(lp(domain) ‖ version ‖ ark_id ‖ generation ‖ threshold ‖ canary_fp ‖ n ‖
    ///   for each share: index ‖ lp(holder) ‖ lp(recipient) ‖ commitment ‖ SHA-256(ciphertext))`.
    pub fn fingerprint(&self) -> Efp {
        let mut pre = Vec::with_capacity(512);
        lp(&mut pre, EFP_DOMAIN);
        pre.extend_from_slice(&self.version.to_be_bytes());
        pre.extend_from_slice(&self.ark_id.0);
        pre.extend_from_slice(&self.generation.to_be_bytes());
        pre.push(self.threshold);
        pre.extend_from_slice(&self.canary_fp.0);
        pre.push(u8::try_from(self.shares.len()).unwrap_or(u8::MAX));
        for s in &self.shares {
            pre.push(s.index);
            lp(&mut pre, s.holder.as_bytes());
            lp(&mut pre, s.recipient.as_bytes());
            pre.extend_from_slice(&s.commitment.0);
            pre.extend_from_slice(&sha256(s.ciphertext.as_bytes()));
        }
        Digest32(sha256(&pre))
    }

    /// Check one decrypted share against this bundle without a second share.
    pub fn verify_share(&self, payload: &SharePayload) -> Result<(), EscrowError> {
        self.validate()?;
        if payload.ark_id != self.ark_id || payload.generation != self.generation {
            return Err(EscrowError::ShareMismatch);
        }
        let entry = &self.shares[usize::from(payload.index) - 1];
        if entry.commitment != payload.commitment() {
            return Err(EscrowError::Commitment {
                index: payload.index,
            });
        }
        Ok(())
    }

    /// Parse and check a share as decrypted by a holder (`age -d` output).
    pub fn open_share(&self, decrypted: &[u8]) -> Result<SharePayload, EscrowError> {
        if decrypted.len() != PAYLOAD_LEN {
            return Err(EscrowError::ShareFormat);
        }
        let payload = SharePayload::decode(decrypted)?;
        self.verify_share(&payload)?;
        Ok(payload)
    }

    /// TEE only (the result is the ARK). Rebuild the ARK from two distinct,
    /// committed shares and check it against the canary.
    pub fn recover(&self, a: &SharePayload, b: &SharePayload) -> Result<Ark, EscrowError> {
        self.verify_share(a)?;
        self.verify_share(b)?;
        if a.index == b.index {
            return Err(EscrowError::DuplicateIndex { index: a.index });
        }
        let ark = combine(a, b)?;
        if canary_fingerprint(&ark, &self.ark_id, self.generation) != self.canary_fp {
            return Err(EscrowError::Canary);
        }
        Ok(ark)
    }

    /// TEE only. The ceremony check: given all three shares, every pair must
    /// rebuild exactly `ark` (constant-time compare) and its canary.
    pub fn test_unlock(
        &self,
        ark: &Ark,
        shares: &[SharePayload],
    ) -> Result<TestUnlock, EscrowError> {
        self.validate()?;
        if canary_fingerprint(ark, &self.ark_id, self.generation) != self.canary_fp {
            return Err(EscrowError::Canary);
        }
        let mut by_index: [Option<&SharePayload>; HOLDERS as usize] = [None; HOLDERS as usize];
        for share in shares {
            self.verify_share(share)?;
            let slot = &mut by_index[usize::from(share.index) - 1];
            if slot.is_some() {
                return Err(EscrowError::DuplicateIndex { index: share.index });
            }
            *slot = Some(share);
        }
        let [Some(s1), Some(s2), Some(s3)] = by_index else {
            return Err(EscrowError::Holders(
                "test-unlock needs the shares of all three holders".into(),
            ));
        };
        let mut pairs = Vec::with_capacity(3);
        for (a, b) in [(s1, s2), (s1, s3), (s2, s3)] {
            if !self.recover(a, b)?.ct_eq(ark) {
                return Err(EscrowError::Canary);
            }
            pairs.push([a.index, b.index]);
        }
        Ok(TestUnlock {
            efp: self.fingerprint(),
            pairs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    type Mutation = Box<dyn Fn(&mut EscrowBundle)>;

    #[test]
    fn create_then_two_holders_recover_and_one_cannot() {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let shares = open_all(&bundle, &ids);

        for (a, b) in [(0, 1), (0, 2), (1, 2), (2, 0)] {
            assert!(bundle.recover(&shares[a], &shares[b]).unwrap().ct_eq(&ark));
        }
        // One share, twice, is still one share.
        assert!(matches!(
            bundle.recover(&shares[0], &shares[0]),
            Err(EscrowError::DuplicateIndex { index: 1 })
        ));
    }

    #[test]
    fn a_single_share_is_independent_of_the_ark() {
        // Same share-1 polynomial evaluation could come from any ARK: with
        // threshold 2 the y-bytes of one share are uniform. Check that two
        // splits of the same ARK give unrelated share bytes.
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let a = open_all(
            &EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap(),
            &ids,
        );
        let b = open_all(
            &EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap(),
            &ids,
        );
        assert_ne!(a[0].share.as_slice(), b[0].share.as_slice());
        assert_ne!(&a[0].share[1..], ark.expose().as_slice());
    }

    #[test]
    fn tampered_share_or_wrong_ark_fails_before_combining() {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let shares = open_all(&bundle, &ids);

        let mut flipped = shares[1].clone();
        flipped.share[5] ^= 0x40;
        assert!(matches!(
            bundle.recover(&shares[0], &flipped),
            Err(EscrowError::Commitment { index: 2 })
        ));

        let other = EscrowBundle::create(
            &Ark::generate(),
            ArkId::generate(),
            1,
            &holders,
            RecipientPolicy::AllowSoftware,
        )
        .unwrap();
        let foreign = open_all(&other, &ids);
        assert!(matches!(
            bundle.recover(&shares[0], &foreign[1]),
            Err(EscrowError::ShareMismatch)
        ));
    }

    #[test]
    fn forged_commitment_still_fails_the_canary() {
        // An attacker who controls the stored bundle can rewrite a commitment
        // to match a junk share. The canary still rejects the combination.
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let mut bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let shares = open_all(&bundle, &ids);
        let mut junk = shares[1].clone();
        junk.share[7] ^= 1;
        bundle.shares[1].commitment = junk.commitment();
        assert!(matches!(
            bundle.recover(&shares[0], &junk),
            Err(EscrowError::Canary)
        ));
    }

    #[test]
    fn test_unlock_needs_all_three_and_the_same_ark() {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let shares = open_all(&bundle, &ids);

        let ok = bundle.test_unlock(&ark, &shares).unwrap();
        assert_eq!(ok.efp(), bundle.fingerprint());
        assert_eq!(ok.pairs, vec![[1, 2], [1, 3], [2, 3]]);

        assert!(bundle.test_unlock(&ark, &shares[..2]).is_err());
        let dup = [shares[0].clone(), shares[0].clone(), shares[2].clone()];
        assert!(matches!(
            bundle.test_unlock(&ark, &dup),
            Err(EscrowError::DuplicateIndex { index: 1 })
        ));
        assert!(matches!(
            bundle.test_unlock(&Ark::generate(), &shares),
            Err(EscrowError::Canary)
        ));
    }

    #[test]
    fn fingerprint_covers_recipients_commitments_ciphertexts_and_canary() {
        let (ark, ark_id, holders, _) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let efp = bundle.fingerprint();
        let mutations: Vec<Mutation> = vec![
            Box::new(|b| b.shares[0].recipient = x25519_identity().to_public().to_string()),
            Box::new(|b| b.shares[1].holder = "mallory".into()),
            Box::new(|b| b.shares[2].commitment.0[0] ^= 1),
            Box::new(|b| b.shares[0].ciphertext.push('\n')),
            Box::new(|b| b.canary_fp.0[31] ^= 1),
            Box::new(|b| b.generation = 2),
            Box::new(|b| b.ark_id.0[0] ^= 1),
        ];
        for mutate in mutations {
            let mut changed = bundle.clone();
            mutate(&mut changed);
            assert_ne!(changed.fingerprint(), efp);
        }
        // Stable across a JSON round trip (what holders and the node exchange).
        let json = serde_json::to_string(&bundle).unwrap();
        let back: EscrowBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.fingerprint(), efp);
    }

    #[test]
    fn validate_rejects_malformed_bundles() {
        let (ark, ark_id, holders, _) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let mutations: Vec<Mutation> = vec![
            Box::new(|b| b.version = 2),
            Box::new(|b| b.threshold = 1),
            Box::new(|b| {
                b.shares.pop();
            }),
            Box::new(|b| b.shares.swap(0, 1)),
            Box::new(|b| b.shares[0].ciphertext = "not age".into()),
            Box::new(|b| b.shares[2].holder = b.shares[0].holder.clone()),
        ];
        for mutate in mutations {
            let mut bad = bundle.clone();
            mutate(&mut bad);
            assert!(bad.validate().is_err());
        }
        let unknown = serde_json::to_string(&bundle)
            .unwrap()
            .replacen('{', "{\"extra\":1,", 1);
        assert!(serde_json::from_str::<EscrowBundle>(&unknown).is_err());
    }

    #[test]
    fn hardware_shares_open_with_their_own_p256_key_only() {
        let (ark, ark_id, holders, ids) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        // Share 1 is piv-p256 (age1yubikey1), share 2 is p256tag (age1tag1).
        assert!(bundle.shares[0].recipient.starts_with("age1yubikey1"));
        assert!(bundle.shares[1].recipient.starts_with("age1tag1"));
        for (i, j) in [(0, 1), (1, 0), (0, 2), (1, 2)] {
            assert!(
                ids[j].open(&bundle.shares[i].ciphertext).is_err(),
                "{j} opened {i}"
            );
        }
        for (i, (id, entry)) in ids.iter().zip(&bundle.shares).take(2).enumerate() {
            let share = bundle
                .open_share(&id.open(&entry.ciphertext).unwrap())
                .unwrap();
            assert_eq!(usize::from(share.index), i + 1);
        }
    }

    #[test]
    fn software_holders_need_the_explicit_policy() {
        let (ark, ark_id, holders, _) = escrow_fixture();
        assert!(matches!(
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::HardwareOnly),
            Err(EscrowError::Recipient { holder, .. }) if holder == "safe"
        ));
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        assert!(bundle
            .check_recipients(RecipientPolicy::HardwareOnly)
            .is_err());
        assert_eq!(
            bundle
                .check_recipients(RecipientPolicy::AllowSoftware)
                .unwrap(),
            vec![
                RecipientKind::PivP256,
                RecipientKind::P256Tag,
                RecipientKind::X25519
            ]
        );
    }

    #[test]
    fn newer_versions_are_reported_as_versions_not_unknown_fields() {
        let (ark, ark_id, holders, _) = escrow_fixture();
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let json = serde_json::to_vec(&bundle).unwrap();
        assert_eq!(EscrowBundle::from_json(&json).unwrap(), bundle);

        let mut v2: serde_json::Value = serde_json::from_slice(&json).unwrap();
        v2["version"] = 2.into();
        v2["kdf"] = "new".into();
        let err = EscrowBundle::from_json(&serde_json::to_vec(&v2).unwrap()).unwrap_err();
        assert!(
            matches!(
                err,
                EscrowError::Version {
                    found: 2,
                    supported: 1,
                    ..
                }
            ),
            "{err}"
        );
        // Duplicate keys are refused (the typed parse sees them all).
        let dup = String::from_utf8(json.clone()).unwrap().replacen(
            "\"generation\":1",
            "\"generation\":7,\"generation\":1",
            1,
        );
        assert!(matches!(
            EscrowBundle::from_json(dup.as_bytes()),
            Err(EscrowError::Json { .. })
        ));
        // Same version with an unknown field is still refused.
        let mut extra: serde_json::Value = serde_json::from_slice(&json).unwrap();
        extra["kdf"] = "new".into();
        assert!(matches!(
            EscrowBundle::from_json(&serde_json::to_vec(&extra).unwrap()),
            Err(EscrowError::Json { .. })
        ));
        assert!(matches!(
            EscrowBundle::from_json(b"{}"),
            Err(EscrowError::Json { .. })
        ));

        let info = serde_json::json!({"version": 9, "mode": "dstack", "future": true});
        assert!(matches!(
            crate::RecoveryInfo::from_json(info.to_string().as_bytes()),
            Err(EscrowError::Version { found: 9, .. })
        ));
        let record = serde_json::json!({"version": 3, "efp": "x"});
        assert!(matches!(
            crate::VerificationRecord::from_json(record.to_string().as_bytes()),
            Err(EscrowError::Version { found: 3, .. })
        ));
    }
}
