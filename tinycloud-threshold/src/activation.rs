//! Candidate-bound readiness claims and owner-authorized activation. Details: TC-2222

use crate::{
    ceremony::{verify_signature, DidSignatureVerifier, SignedStatement},
    cert::{CertificateBody, VerifiedCertificate},
    dst,
    encoding::Encoder,
    error::Error,
    ids::{CertDigest, MemberIndex, TranscriptHash},
};

/// Member-signed claim of durable candidate installation. Details: TC-2222
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessReceipt {
    /// Candidate member coordinate. Details: TC-2222
    pub index: MemberIndex,
    /// Node signature over the exact candidate readiness preimage. Details: TC-2222
    pub signature: Vec<u8>,
}

/// Explicit ready-holder quorum policy. Details: TC-2222
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadyQuorum {
    /// Every new holder must supply a receipt. Details: TC-2222
    AllHolders,
    /// Require t plus this positive total unavailable-ready-signer budget, including dishonest claims. Details: TC-2222
    WithOutageBudget(u16),
}

/// Exact candidate/transcript/member/public-share readiness signing preimage. Details: TC-2222
pub fn readiness_preimage(
    candidate: &CertificateBody,
    index: MemberIndex,
) -> Result<Vec<u8>, Error> {
    let point = candidate.public_material().public_share(index)?;
    Ok(readiness_hash(
        &candidate.digest(),
        candidate.transcript_hash(),
        index,
        &point,
    )
    .to_vec())
}

fn readiness_hash(
    digest: &CertDigest,
    transcript: TranscriptHash,
    index: MemberIndex,
    point: &[u8; 96],
) -> [u8; 32] {
    let mut e = Encoder::new();
    e.fixed(digest.as_bytes());
    e.fixed(transcript.as_bytes());
    e.u16(index.get());
    e.fixed(point);
    dst::tagged_hash(dst::READY, &e.finish())
}

fn receipt_indices(
    candidate: &CertificateBody,
    receipts: &[ReadinessReceipt],
) -> Result<(), Error> {
    if receipts.len() > usize::from(candidate.public_material().threshold().n()) {
        return Err(Error::InvalidReadiness);
    }
    let mut seen = [false; 16];
    for receipt in receipts {
        if !candidate.members().iter().any(|m| m.index == receipt.index)
            || receipt.signature.is_empty()
            || receipt.signature.len() > 512
        {
            return Err(Error::InvalidReadiness);
        }
        let position = usize::from(receipt.index.get())
            .checked_sub(1)
            .ok_or(Error::InvalidReadiness)?;
        let entry = seen.get_mut(position).ok_or(Error::InvalidReadiness)?;
        if *entry {
            return Err(Error::InvalidReadiness);
        }
        *entry = true;
    }
    Ok(())
}

fn activation_hash(digest: &CertDigest, receipts: &[ReadinessReceipt]) -> Vec<u8> {
    let mut hashes: Vec<_> = receipts
        .iter()
        .map(|receipt| {
            let mut e = Encoder::new();
            e.u8(1);
            e.u16(receipt.index.get());
            e.lp(&receipt.signature);
            dst::tagged_hash(dst::READY, &e.finish())
        })
        .collect();
    hashes.sort_unstable();
    let mut e = Encoder::new();
    e.fixed(digest.as_bytes());
    for hash in hashes {
        e.fixed(&hash);
    }
    dst::tagged_hash(dst::ACTIVATE, &e.finish()).to_vec()
}

/// Build the owner's 32-byte activation preimage; this helper does not authenticate receipt claims. Details: TC-2222
pub fn activation_preimage(
    candidate: &CertificateBody,
    receipts: &[ReadinessReceipt],
) -> Result<Vec<u8>, Error> {
    receipt_indices(candidate, receipts)?;
    Ok(activation_hash(&candidate.digest(), receipts))
}

/// Verify every unique member claim before quorum counting, hashing and owner approval. Details: TC-2222
pub fn verify_activation(
    candidate: &VerifiedCertificate,
    receipts: &[ReadinessReceipt],
    q: ReadyQuorum,
    activation: &SignedStatement,
    v: &impl DidSignatureVerifier,
) -> Result<(), Error> {
    receipt_indices(candidate.body(), receipts)?;
    let digest = candidate.digest();
    let transcript = candidate.body().transcript_hash();
    for receipt in receipts {
        let member = candidate
            .member(receipt.index)
            .map_err(|_| Error::InvalidReadiness)?;
        let point = candidate
            .body()
            .public_material()
            .public_share(receipt.index)?;
        let preimage = readiness_hash(&digest, transcript, receipt.index, &point);
        verify_signature(v, &member.node, &preimage, &receipt.signature)?;
    }
    let threshold = candidate.public_key_set().context().threshold();
    let required = match q {
        ReadyQuorum::AllHolders => threshold.n(),
        ReadyQuorum::WithOutageBudget(0) => return Err(Error::InvalidReadiness),
        ReadyQuorum::WithOutageBudget(budget) => {
            let required = threshold
                .t()
                .checked_add(budget)
                .ok_or(Error::InvalidReadiness)?;
            if required > threshold.n() {
                return Err(Error::InvalidReadiness);
            }
            required
        }
    };
    if receipts.len() < usize::from(required) {
        return Err(Error::NotEnoughReady);
    }
    let expected = activation_hash(&digest, receipts);
    if activation.bytes != expected {
        return Err(Error::InvalidReadiness);
    }
    verify_signature(
        v,
        &candidate.anchor().expected_owner,
        &expected,
        &activation.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ceremony::tests::Signers, cert::tests};

    fn receipts(cert: &VerifiedCertificate, signers: &Signers) -> Vec<ReadinessReceipt> {
        (1..=cert.key_context().threshold().n())
            .map(|i| {
                let index = MemberIndex::new(i).unwrap();
                ReadinessReceipt {
                    index,
                    signature: signers.sign(
                        &Signers::did(i as u8),
                        &readiness_preimage(cert.body(), index).unwrap(),
                    ),
                }
            })
            .collect()
    }
    fn activation(
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

    #[test]
    fn activation_requires_unique_exact_candidate_receipts_and_owner_approval() {
        let signers = Signers::new();
        let (cert, _) = tests::genesis(&signers);
        let mut receipts = receipts(&cert, &signers);
        let signed = activation(&cert, &receipts, &signers);
        assert!(
            verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &signed, &signers).is_ok()
        );
        receipts.reverse();
        assert!(
            verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &signed, &signers).is_ok()
        );
        assert!(verify_activation(
            &cert,
            &receipts[..2],
            ReadyQuorum::AllHolders,
            &signed,
            &signers
        )
        .is_err());
        assert!(verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(0),
            &signed,
            &signers
        )
        .is_err());
        assert!(verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(1),
            &signed,
            &signers
        )
        .is_ok());
        assert!(verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(2),
            &signed,
            &signers
        )
        .is_err());
        assert!(verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(u16::MAX),
            &signed,
            &signers
        )
        .is_err());
        let duplicate = vec![
            receipts[0].clone(),
            receipts[0].clone(),
            receipts[1].clone(),
        ];
        assert!(verify_activation(
            &cert,
            &duplicate,
            ReadyQuorum::AllHolders,
            &signed,
            &signers
        )
        .is_err());
        let mut wrong = receipts.clone();
        wrong[0].index = MemberIndex::new(4).unwrap();
        assert!(
            verify_activation(&cert, &wrong, ReadyQuorum::AllHolders, &signed, &signers).is_err()
        );
        let mut wrong = receipts.clone();
        wrong[0].signature[0] ^= 1;
        assert!(
            verify_activation(&cert, &wrong, ReadyQuorum::AllHolders, &signed, &signers).is_err()
        );
        let mut wrong = signed.clone();
        wrong.signature[0] ^= 1;
        assert!(
            verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &wrong, &signers).is_err()
        );
        let (other, _, _) = tests::successor(
            &signers,
            &cert,
            crate::ceremony::CeremonyKind::Refresh,
            cert.key_context().threshold(),
            11,
        );
        let other = crate::cert::verify_successor(&cert, &other, &signers).unwrap();
        assert!(verify_activation(
            &other,
            &receipts,
            ReadyQuorum::AllHolders,
            &signed,
            &signers
        )
        .is_err());
    }

    #[test]
    fn declared_budget_counts_every_unavailable_ready_holder() {
        let signers = Signers::new();
        let (genesis, _) = tests::genesis(&signers);
        let (candidate, _, _) = tests::successor(
            &signers,
            &genesis,
            crate::ceremony::CeremonyKind::Reshare,
            crate::ids::Threshold::new(3, 4).unwrap(),
            11,
        );
        let cert = crate::cert::verify_successor(&genesis, &candidate, &signers).unwrap();
        let receipts = receipts(&cert, &signers);
        let signed = activation(&cert, &receipts, &signers);
        assert!(verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(1),
            &signed,
            &signers
        )
        .is_ok());
        assert!(verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(2),
            &signed,
            &signers
        )
        .is_err());
        assert!(verify_activation(
            &cert,
            &receipts[..3],
            ReadyQuorum::WithOutageBudget(1),
            &signed,
            &signers
        )
        .is_err());
    }
}

#[cfg(test)]
mod verification_order_tests {
    use super::*;
    use crate::ceremony::tests::Signers;
    use crate::error::SignatureError;
    use crate::ids::Did;
    use std::cell::Cell;

    struct Observed<'a> {
        signers: &'a Signers,
        calls: Cell<usize>,
    }
    impl DidSignatureVerifier for Observed<'_> {
        fn verify(
            &self,
            signer: &Did,
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), SignatureError> {
            self.calls.set(self.calls.get() + 1);
            self.signers.verify(signer, message, signature)
        }
    }
    #[test]
    fn under_quorum_or_zero_budget_never_skips_supplied_member_signatures() {
        let signers = Signers::new();
        let (cert, _) = crate::cert::tests::genesis(&signers);
        let receipt = ReadinessReceipt {
            index: MemberIndex::new(1).unwrap(),
            signature: signers.sign(
                &Signers::did(1),
                &readiness_preimage(cert.body(), MemberIndex::new(1).unwrap()).unwrap(),
            ),
        };
        let observed = Observed {
            signers: &signers,
            calls: Cell::new(0),
        };
        let dummy = SignedStatement {
            bytes: vec![0; 32],
            signature: vec![0; 64],
        };
        assert_eq!(
            verify_activation(
                &cert,
                std::slice::from_ref(&receipt),
                ReadyQuorum::AllHolders,
                &dummy,
                &observed
            ),
            Err(Error::NotEnoughReady)
        );
        assert_eq!(observed.calls.get(), 1);
        observed.calls.set(0);
        assert_eq!(
            verify_activation(
                &cert,
                std::slice::from_ref(&receipt),
                ReadyQuorum::WithOutageBudget(0),
                &dummy,
                &observed
            ),
            Err(Error::InvalidReadiness)
        );
        assert_eq!(observed.calls.get(), 1);
        observed.calls.set(0);
        assert_eq!(
            verify_activation(
                &cert,
                &[receipt.clone(), receipt],
                ReadyQuorum::AllHolders,
                &dummy,
                &observed
            ),
            Err(Error::InvalidReadiness)
        );
        assert_eq!(observed.calls.get(), 0);
    }
}
