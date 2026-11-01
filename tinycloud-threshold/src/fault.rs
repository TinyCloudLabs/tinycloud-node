//! Attribution of member-signed responses under the anchored certificate. Details: TC-2222

use crate::{
    ceremony::{verify_signature, DidSignatureVerifier},
    cert::VerifiedCertificate,
    derive::{verify_share, DecryptRequest, EncryptedKeyShare},
    error::ShareError,
    ids::MemberIndex,
};

/// Member response, supplied request and raw node signature. Details: TC-2222
#[derive(Clone, Debug)]
pub struct FaultProof {
    /// Exact request answered by the encrypted share. Details: TC-2222
    pub request: DecryptRequest,
    /// Request-digest-bound encrypted response. Details: TC-2222
    pub share: EncryptedKeyShare,
    /// Signature over the amended fallible response preimage. Details: TC-2222
    pub signature: Vec<u8>,
}

/// Reason that evidence does not establish the named member's fault. Details: TC-2222
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotAFaultReason {
    /// Request, share, member or certificate bindings differ. Details: TC-2222
    ContextMismatch,
    /// Matching member signature is absent or invalid. Details: TC-2222
    InvalidSignature,
    /// Both share equations hold. Details: TC-2222
    ValidShare,
}

/// Only a bound, member-signed response can produce attribution. Details: TC-2222
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultVerdict {
    /// Correct-context signed share fails an equation for this member. Details: TC-2222
    Fault(MemberIndex),
    /// The supplied evidence does not establish a fault. Details: TC-2222
    NotAFault(NotAFaultReason),
}

/// Check all bindings before the node signature, and the signature before algebra. Details: TC-2222
pub fn verify_fault_proof(
    cert: &VerifiedCertificate,
    p: &FaultProof,
    v: &impl DidSignatureVerifier,
) -> FaultVerdict {
    let context = cert.public_key_set().context();
    let req = &p.request;
    let share = &p.share;
    let context_digest = context.digest();
    if req.context_digest != context_digest
        || req.network != *context.network()
        || req.identity.network() != context.network()
        || req.rekey != context.rekey()
        || req.epoch != context.epoch()
        || req.certificate != *context.certificate()
        || share.context_digest != context_digest
    {
        return FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch);
    }
    let Ok(member) = cert.member(share.index()) else {
        return FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch);
    };
    let Ok(preimage) = share.signing_preimage(req) else {
        return FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch);
    };
    if verify_signature(v, &member.node, &preimage, &p.signature).is_err() {
        return FaultVerdict::NotAFault(NotAFaultReason::InvalidSignature);
    }
    match verify_share(cert.public_key_set(), req, share) {
        Ok(()) => FaultVerdict::NotAFault(NotAFaultReason::ValidShare),
        Err(ShareError::ContextMismatch) => {
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        }
        Err(ShareError::Invalid { member }) => FaultVerdict::Fault(member),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ceremony::{tests::Signers, CeremonyKind},
        cert::tests,
        curve::{G1, G2},
        ids::Threshold,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn attribution_requires_exact_request_context_and_a_real_member_signature() {
        let signers = Signers::new();
        let (cert, shares) = tests::genesis(&signers);
        let mut rng = ChaCha20Rng::from_seed([61; 32]);
        let tsk = crate::TransportSecretKey::generate(&mut rng);
        let req = DecryptRequest::new(
            &cert.key_context(),
            crate::checkpoint::identity(&cert.key_context(), "fault/key"),
            tsk.public_key(),
        )
        .unwrap();
        let valid = crate::issue_share(
            &shares[0],
            &crate::checkpoint::authorize(req.clone()),
            &mut rng,
        )
        .unwrap();
        let mut proof = FaultProof {
            signature: signers.sign(&Signers::did(1), &valid.signing_preimage(&req).unwrap()),
            request: req.clone(),
            share: valid.clone(),
        };
        assert_eq!(
            verify_fault_proof(&cert, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ValidShare)
        );
        for equation in 0..2 {
            proof.share = valid.clone();
            if equation == 0 {
                proof.share.c2 = proof.share.c2.add(&G2::generator());
            } else {
                proof.share.c3 = proof.share.c3.add(&G1::generator());
            }
            proof.signature = signers.sign(
                &Signers::did(1),
                &proof.share.signing_preimage(&req).unwrap(),
            );
            assert_eq!(
                verify_fault_proof(&cert, &proof, &signers),
                FaultVerdict::Fault(shares[0].index())
            );
        }
        proof.signature[0] ^= 1;
        assert_eq!(
            verify_fault_proof(&cert, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::InvalidSignature)
        );
        proof.share = valid.clone();
        proof.signature = signers.sign(&Signers::did(1), &valid.signing_preimage(&req).unwrap());
        let (next, _, _) = tests::successor(
            &signers,
            &cert,
            CeremonyKind::Rekey,
            Threshold::new(2, 3).unwrap(),
            12,
        );
        let next = crate::cert::verify_successor(&cert, &next, &signers).unwrap();
        assert_eq!(
            verify_fault_proof(&next, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        );
        proof.request = DecryptRequest::new(
            &cert.key_context(),
            crate::checkpoint::identity(&cert.key_context(), "different/key"),
            tsk.public_key(),
        )
        .unwrap();
        assert_eq!(
            verify_fault_proof(&cert, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        );
        assert!(matches!(
            proof.share.signing_preimage(&proof.request),
            Err(crate::Error::ContextMismatch)
        ));
        proof.request = DecryptRequest::new(
            &cert.key_context(),
            crate::checkpoint::identity(&cert.key_context(), "fault/key"),
            crate::TransportSecretKey::generate(&mut rng).public_key(),
        )
        .unwrap();
        assert_eq!(
            verify_fault_proof(&cert, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        );
        proof.request = req;
        proof.share.member = crate::ids::MemberIndex::new(4).unwrap();
        assert_eq!(
            verify_fault_proof(&cert, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        );
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use crate::{
        ceremony::tests::Signers,
        cert::{tests, CertificateBody},
        ids::NetworkUrn,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn genuine_response_is_not_a_fault_for_a_different_network_certificate() {
        let signers = Signers::new();
        let (cert, shares) = tests::genesis(&signers);
        let mut rng = ChaCha20Rng::from_seed([62; 32]);
        let req = DecryptRequest::new(
            &cert.key_context(),
            crate::checkpoint::identity(&cert.key_context(), "replay/key"),
            crate::TransportSecretKey::generate(&mut rng).public_key(),
        )
        .unwrap();
        let share = crate::issue_share(
            &shares[0],
            &crate::checkpoint::authorize(req.clone()),
            &mut rng,
        )
        .unwrap();
        let proof = FaultProof {
            signature: signers.sign(&Signers::did(1), &share.signing_preimage(&req).unwrap()),
            request: req,
            share,
        };
        let mut encoded = cert.body().encode();
        encoded[5] = b'x';
        let body = CertificateBody::decode(&encoded).unwrap();
        let anchor = crate::ceremony::TrustAnchor {
            network: NetworkUrn::new("xinycloud:test:certificates").unwrap(),
            ..signers.anchor()
        };
        let other =
            crate::cert::verify_certificate(&anchor, &tests::sign(body, &signers), &signers)
                .unwrap();
        assert_eq!(
            verify_fault_proof(&other, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        );
    }
}
