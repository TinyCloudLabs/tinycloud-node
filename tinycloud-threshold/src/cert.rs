#[cfg(test)]
use crate::{context::KeyContext, curve::{Scalar, G2}, derive::{KeyShare, MasterPublicKey}, ids::*};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ceremony::{tests::Signers, CeremonyKind, CeremonyStatement};

    pub(crate) fn material(seed: u8, threshold: Threshold) -> (PublicMaterial, Vec<KeyShare>) {
        let context = KeyContext::test(
            Signers::new().anchor().network,
            RekeyCounter::new(0), Epoch::new(0), CertDigest::new([0; 32]), threshold,
        );
        let (public, shares, _) = crate::checkpoint::dealer(seed, context);
        let constant = public.mpk.0.clone();
        let first = public.public_shares[0].1.sub(&constant);
        let commitments = if threshold.t() == 2 {
            vec![constant, first]
        } else {
            assert_eq!(threshold.t(), 3);
            let second = public.public_shares[1].1.sub(&constant);
            let two = Scalar::from_u64(2);
            let quadratic = second.sub(&first.mul(&two)).mul(&two.inverse().unwrap());
            let linear = first.sub(&quadratic);
            vec![constant, linear, quadratic]
        };
        let material = PublicMaterial::from_commitments(threshold, commitments).unwrap();
        for (i, pk) in &material.public_shares {
            assert_eq!(pk, &public.public_shares.iter().find(|(j, _)| j == i).unwrap().1);
        }
        (material, shares)
    }
    pub(crate) fn sign(body: CertificateBody, signers: &Signers) -> SignedCertificate {
        let owner_signature = signers.sign(&body.owner, &body.owner_statement());
        SignedCertificate { body, owner_signature }
    }
    pub(crate) fn genesis(signers: &Signers) -> (VerifiedCertificate, Vec<KeyShare>) {
        let (public, raw) = material(11, Threshold::new(2, 3).unwrap());
        let transcript = TranscriptHash::new([51; 32]);
        let body = CertificateBody::genesis(&signers.anchor(), &signers.genesis(), &public, &transcript).unwrap();
        let cert = verify_certificate(&signers.anchor(), &sign(body, signers), signers).unwrap();
        let bound = raw.into_iter().map(|mut raw| {
            let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
            KeyShare::bind(CandidateShare::new(transcript, raw.index, scalar), &cert).unwrap()
        }).collect();
        (cert, bound)
    }
    pub(crate) fn successor(
        signers: &Signers, prev: &VerifiedCertificate, kind: CeremonyKind,
        threshold: Threshold, seed: u8,
    ) -> (SignedCertificate, Vec<KeyShare>, AuthorizedCeremony) {
        let mut stmt = signers.body(kind, threshold);
        stmt.id = CeremonyId::new([52; 32]);
        stmt.current = Some(prev.digest());
        stmt.epoch = prev.body.epoch.checked_next().unwrap();
        stmt.rekey = if kind == CeremonyKind::Rekey { prev.body.rekey.checked_next().unwrap() } else { prev.body.rekey };
        let ceremony = AuthorizedCeremony::verify_for(prev, &signers.statement(&stmt), signers).unwrap();
        let (public, shares) = material(seed, threshold);
        let body = CertificateBody::successor(prev, &ceremony, &public, &TranscriptHash::new([53; 32])).unwrap();
        (sign(body, signers), shares, ceremony)
    }

    #[test]
    fn dealer_certificate_chain_preserves_master_until_rekey_and_binds_candidates() {
        let signers = Signers::new();
        let (genesis, shares) = genesis(&signers);
        assert_eq!(shares[0].context(), &genesis.key_context());
        let (reshare, raw, _) = successor(&signers, &genesis, CeremonyKind::Reshare, Threshold::new(3, 4).unwrap(), 11);
        let reshare = verify_successor(&genesis, &reshare, &signers).unwrap();
        assert_eq!(reshare.public_key_set().master_public_key(), genesis.public_key_set().master_public_key());
        assert_eq!(reshare.key_context().epoch().get(), 1);
        assert_eq!(reshare.key_context().threshold(), Threshold::new(3, 4).unwrap());
        for mut raw in raw {
            let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
            assert!(KeyShare::bind(CandidateShare::new(reshare.body.transcript, raw.index, scalar), &reshare).is_ok());
        }
        let (rekey, _, _) = successor(&signers, &reshare, CeremonyKind::Rekey, Threshold::new(2, 3).unwrap(), 12);
        let rekey = verify_successor(&reshare, &rekey, &signers).unwrap();
        assert_ne!(rekey.public_key_set().master_public_key(), reshare.public_key_set().master_public_key());
        assert_eq!(rekey.key_context().epoch().get(), 2);
        assert_eq!(rekey.key_context().rekey().get(), 1);
        assert!(verify_successor(&rekey, &sign(genesis.body.clone(), &signers), &signers).is_err());
        assert!(KeyShare::bind(CandidateShare::new(genesis.body.transcript, shares[0].index, Scalar::from_u64(1)), &genesis).is_err());
        assert!(KeyShare::bind(CandidateShare::new(TranscriptHash::new([99; 32]), shares[0].index, Scalar::from_u64(1)), &genesis).is_err());
    }

    #[test]
    fn decoded_certificate_invariants_apply_before_verified_contexts_exist() {
        let signers = Signers::new();
        let (cert, _) = genesis(&signers);
        assert_eq!(CertificateBody::decode(&cert.body.encode()).unwrap().encode(), cert.body.encode());
        let threshold_offset = 1 + 4 + cert.body.network.as_bytes().len()
            + 4 + cert.body.owner.as_bytes().len() + 8 + 8 + 2;
        for (t, n) in [(1u16, 3u16), (4, 3), (2, 17)] {
            let mut bytes = cert.body.encode();
            bytes[threshold_offset..threshold_offset + 2].copy_from_slice(&t.to_be_bytes());
            bytes[threshold_offset + 2..threshold_offset + 4].copy_from_slice(&n.to_be_bytes());
            assert!(CertificateBody::decode(&bytes).is_err());
        }
        for mutation in 0..9 {
            let mut body = cert.body.clone();
            match mutation {
                0 => body.members.swap(0, 1),
                1 => body.members[1].node = body.members[0].node.clone(),
                2 => body.public.commitments.pop().map(|_| ()).unwrap(),
                3 => body.public.commitments[0] = G2::generator(),
                4 => body.public.commitments[1] = G2::identity(),
                5 => body.epoch = Epoch::new(1),
                6 => body.rekey = RekeyCounter::new(1),
                7 => body.genesis_t = 1,
                _ => body.previous_mpk = Some(body.public.mpk.clone()),
            }
            assert!(CertificateBody::decode(&body.encode()).is_err());
        }
        let mut body = cert.body.clone();
        body.public.commitments = vec![G2::generator(), G2::identity().sub(&G2::generator())];
        body.public.mpk = MasterPublicKey(G2::generator());
        assert!(CertificateBody::decode(&body.encode()).is_err());
        let mut bytes = cert.body.encode(); bytes.push(0);
        assert!(CertificateBody::decode(&bytes).is_err());
        for length in 0..cert.body.encode().len() {
            assert!(CertificateBody::decode(&cert.body.encode()[..length]).is_err());
        }
        let mut impostor = cert.body.clone(); impostor.owner = Signers::did(9);
        assert!(matches!(verify_certificate(&signers.anchor(), &sign(impostor, &signers), &signers), Err(CertError::AnchorMismatch)));
    }

    #[test]
    fn pinned_lineage_checks_every_generation_field_and_overflow() {
        let signers = Signers::new();
        let (prev, _) = genesis(&signers);
        let (valid, _, _) = successor(&signers, &prev, CeremonyKind::Reshare, Threshold::new(2, 3).unwrap(), 11);
        for mutation in 0..6 {
            let mut body = valid.body.clone();
            match mutation {
                0 => body.previous = Some(CertDigest::new([99; 32])),
                1 => body.epoch = Epoch::new(2),
                2 => body.rekey = RekeyCounter::new(1),
                3 => body.genesis_t = 3,
                4 => body.public = material(12, body.public.threshold).0,
                _ => body.network = NetworkUrn::new("other").unwrap(),
            }
            assert!(verify_successor(&prev, &sign(body, &signers), &signers).is_err());
        }
        let (rekey, _, _) = successor(&signers, &prev, CeremonyKind::Rekey, Threshold::new(2, 3).unwrap(), 12);
        let mut missing = rekey.body.clone(); missing.previous_mpk = None;
        assert!(verify_successor(&prev, &sign(missing, &signers), &signers).is_err());
        let mut body = valid.body.clone(); body.epoch = Epoch::new(u64::MAX);
        let max = verify_certificate(&signers.anchor(), &sign(body, &signers), &signers).unwrap();
        assert!(matches!(verify_successor(&max, &valid, &signers), Err(CertError::Invalid(Error::CounterOverflow))));
        let mut body = rekey.body.clone(); body.epoch = Epoch::new(u64::MAX); body.rekey = RekeyCounter::new(u64::MAX);
        let max = verify_certificate(&signers.anchor(), &sign(body, &signers), &signers).unwrap();
        let mut stmt: CeremonyStatement = signers.body(CeremonyKind::Rekey, Threshold::new(2, 3).unwrap());
        stmt.current = Some(max.digest());
        assert!(matches!(AuthorizedCeremony::verify_for(&max, &signers.statement(&stmt), &signers), Err(Error::CounterOverflow)));
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use crate::{
        activation::{activation_preimage, readiness_preimage, verify_activation, ReadinessReceipt, ReadyQuorum},
        ceremony::tests::Signers,
        fault::{verify_fault_proof, FaultProof, FaultVerdict, NotAFaultReason},
        *,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn certificate_authorization_share_fault_activation_smoke() {
        let signers = Signers::new();
        let ceremony = signers.genesis();
        let (cert, shares) = tests::genesis(&signers);
        assert_eq!(ceremony.threshold(), cert.key_context().threshold());
        println!("1. PASS: owner-signed ceremony and anchored test-dealer certificate");
        let mut rng = ChaCha20Rng::from_seed([71; 32]);
        let tsk = TransportSecretKey::generate(&mut rng);
        let request = DecryptRequest::new(
            &cert.key_context(), crate::checkpoint::identity(&cert.key_context(), "smoke/key"), tsk.public_key(),
        ).unwrap();
        let auth = crate::checkpoint::authorize(request.clone());
        let issued: Vec<_> = shares.iter().map(|s| issue_share(s, &auth, &mut rng).unwrap()).collect();
        let encrypted = combine(cert.public_key_set(), &request, &issued).unwrap();
        let derived = decrypt_derived_key(&encrypted, &tsk, cert.public_key_set(), &request).unwrap();
        let data = DataKey::new([0x42; 32]);
        let wrapped = wrap_key(cert.public_key_set().master_public_key(), request.identity(), &data, &mut rng).unwrap();
        assert_eq!(unwrap_key(&derived, request.identity(), &wrapped).unwrap().as_bytes(), data.as_bytes());
        println!("2. PASS: certificate-bound shares issue, combine, derive and unwrap");
        let mut bad = issued[0].clone();
        bad.c3 = bad.c3.add(&crate::curve::G1::generator());
        let signature = signers.sign(&Signers::did(1), &bad.signing_preimage(&request).unwrap());
        let proof = FaultProof { request: request.clone(), share: bad, signature };
        assert_eq!(verify_fault_proof(&cert, &proof, &signers), FaultVerdict::Fault(shares[0].index()));
        println!("3. PASS: genuine correctly bound signed bad response attributes its signer");
        let (next, _, _) = tests::successor(&signers, &cert, crate::ceremony::CeremonyKind::Rekey, cert.key_context().threshold(), 12);
        let next = verify_successor(&cert, &next, &signers).unwrap();
        assert_eq!(verify_fault_proof(&next, &proof, &signers), FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch));
        println!("4. PASS: old response under re-keyed certificate is NotAFault");
        let receipts: Vec<_> = shares.iter().map(|share| ReadinessReceipt {
            index: share.index(),
            signature: signers.sign(&cert.member(share.index()).unwrap().node, &readiness_preimage(cert.body(), share.index()).unwrap()),
        }).collect();
        let bytes = activation_preimage(cert.body(), &receipts).unwrap();
        let activation = crate::ceremony::SignedStatement {
            signature: signers.sign(&cert.anchor().expected_owner, &bytes), bytes,
        };
        verify_activation(&cert, &receipts, ReadyQuorum::AllHolders, &activation, &signers).unwrap();
        assert!(verify_activation(&cert, &receipts[..2], ReadyQuorum::AllHolders, &activation, &signers).is_err());
        println!("5. PASS: all-holder receipts activate; under-quorum receipt set does not");
    }
}
