#[cfg(test)]
use crate::derive::DecryptRequest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ceremony::{tests::Signers, CeremonyKind}, cert::tests, curve::{G1, G2}, ids::Threshold};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn attribution_requires_exact_request_context_and_a_real_member_signature() {
        let signers = Signers::new();
        let (cert, shares) = tests::genesis(&signers);
        let mut rng = ChaCha20Rng::from_seed([61; 32]);
        let tsk = crate::TransportSecretKey::generate(&mut rng);
        let req = DecryptRequest::new(&cert.key_context(), crate::checkpoint::identity(&cert.key_context(), "fault/key"), tsk.public_key()).unwrap();
        let valid = crate::issue_share(&shares[0], &crate::checkpoint::authorize(req.clone()), &mut rng).unwrap();
        let mut proof = FaultProof { signature: signers.sign(&Signers::did(1), &valid.signing_preimage(&req).unwrap()), request: req.clone(), share: valid.clone() };
        assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::ValidShare));
        for equation in 0..2 {
            proof.share = valid.clone();
            if equation == 0 { proof.share.c2 = proof.share.c2.add(&G2::generator()); }
            else { proof.share.c3 = proof.share.c3.add(&G1::generator()); }
            proof.signature = signers.sign(&Signers::did(1), &proof.share.signing_preimage(&req).unwrap());
            assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::Fault(shares[0].index()));
        }
        proof.signature[0] ^= 1;
        assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::InvalidSignature));
        proof.share = valid.clone();
        proof.signature = signers.sign(&Signers::did(1), &valid.signing_preimage(&req).unwrap());
        let (next, _, _) = tests::successor(&signers, &cert, CeremonyKind::Rekey, Threshold::new(2, 3).unwrap(), 12);
        let next = crate::cert::verify_successor(&cert, &next, &signers).unwrap();
        assert_eq!(verify_fault_proof(&next, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch));
        proof.request = DecryptRequest::new(&cert.key_context(), crate::checkpoint::identity(&cert.key_context(), "different/key"), tsk.public_key()).unwrap();
        assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch));
        assert!(matches!(proof.share.signing_preimage(&proof.request), Err(crate::Error::ContextMismatch)));
        proof.request = DecryptRequest::new(&cert.key_context(), crate::checkpoint::identity(&cert.key_context(), "fault/key"), crate::TransportSecretKey::generate(&mut rng).public_key()).unwrap();
        assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch));
        proof.request = req;
        proof.share.member = crate::ids::MemberIndex::new(4).unwrap();
        assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch));
    }
}
