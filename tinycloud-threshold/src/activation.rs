#[cfg(test)]
use crate::ids::MemberIndex;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ceremony::tests::Signers, cert::tests};

    fn receipts(cert: &VerifiedCertificate, signers: &Signers) -> Vec<ReadinessReceipt> {
        (1..=cert.key_context().threshold().n()).map(|i| {
            let index = MemberIndex::new(i).unwrap();
            ReadinessReceipt { index, signature: signers.sign(&Signers::did(i as u8), &readiness_preimage(cert.body(), index).unwrap()) }
        }).collect()
    }
    fn activation(cert: &VerifiedCertificate, receipts: &[ReadinessReceipt], signers: &Signers) -> SignedStatement {
        let bytes = activation_preimage(cert.body(), receipts).unwrap();
        SignedStatement { signature: signers.sign(&cert.anchor().expected_owner, &bytes), bytes }
    }

    #[test]
    fn activation_requires_unique_exact_candidate_receipts_and_owner_approval() {
        let signers = Signers::new();
        let (cert, _) = tests::genesis(&signers);
        let mut receipts = receipts(&cert, &signers);
        let signed = activation(&cert, &receipts, &signers);
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &signed, &signers).is_ok());
        receipts.reverse();
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &signed, &signers).is_ok());
        assert!(verify_activation(&cert, &receipts[..2], ReadyQuorum::AllHolders, &signed, &signers).is_err());
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::WithOutageBudget(0), &signed, &signers).is_err());
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::WithOutageBudget(1), &signed, &signers).is_ok());
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::WithOutageBudget(2), &signed, &signers).is_err());
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::WithOutageBudget(u16::MAX), &signed, &signers).is_err());
        let duplicate = vec![receipts[0].clone(), receipts[0].clone(), receipts[1].clone()];
        assert!(verify_activation(&cert, &duplicate, ReadyQuorum::AllHolders, &signed, &signers).is_err());
        let mut wrong = receipts.clone(); wrong[0].index = MemberIndex::new(4).unwrap();
        assert!(verify_activation(&cert, &wrong, ReadyQuorum::AllHolders, &signed, &signers).is_err());
        let mut wrong = receipts.clone(); wrong[0].signature[0] ^= 1;
        assert!(verify_activation(&cert, &wrong, ReadyQuorum::AllHolders, &signed, &signers).is_err());
        let mut wrong = signed.clone(); wrong.signature[0] ^= 1;
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &wrong, &signers).is_err());
        let (other, _, _) = tests::successor(&signers, &cert, crate::ceremony::CeremonyKind::Refresh, cert.key_context().threshold(), 11);
        let other = crate::cert::verify_successor(&cert, &other, &signers).unwrap();
        assert!(verify_activation(&other, &receipts, ReadyQuorum::AllHolders, &signed, &signers).is_err());
    }

    #[test]
    fn declared_budget_counts_every_unavailable_ready_holder() {
        let signers = Signers::new();
        let (genesis, _) = tests::genesis(&signers);
        let (candidate, _, _) = tests::successor(&signers, &genesis, crate::ceremony::CeremonyKind::Reshare, crate::ids::Threshold::new(3, 4).unwrap(), 11);
        let cert = crate::cert::verify_successor(&genesis, &candidate, &signers).unwrap();
        let receipts = receipts(&cert, &signers);
        let signed = activation(&cert, &receipts, &signers);
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::WithOutageBudget(1), &signed, &signers).is_ok());
        assert!(verify_activation(&cert, &receipts, ReadyQuorum::WithOutageBudget(2), &signed, &signers).is_err());
        assert!(verify_activation(&cert, &receipts[..3], ReadyQuorum::WithOutageBudget(1), &signed, &signers).is_err());
    }
}
