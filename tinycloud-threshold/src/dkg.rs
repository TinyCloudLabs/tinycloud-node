//! Genesis GJKR New-DKG over owner-closed rounds. Details: TC-2220

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ceremony::{tests::Signers, AuthorizedCeremony, CeremonyKind, Decode},
        curve::{Scalar, G2},
        dst,
        error::Error,
        ids::*,
        seal::{seal_dealing, CeremonyHpkeSecretKey, DealingContext},
    };
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha2::{Digest, Sha256};

    fn idx(i: u16) -> MemberIndex {
        MemberIndex::new(i).unwrap()
    }

    fn pair(value: u64, blinding: u64) -> SharePair {
        SharePair {
            value: Scalar::from_u64(value),
            blinding: Scalar::from_u64(blinding),
        }
    }

    const R: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x01,
    ];

    fn sealed(recipient: u16, seed: u8) -> crate::seal::SealedDealing {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (_, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let context = DealingContext {
            ceremony_digest: [seed; 32],
            round: 1,
            sender: idx(1),
            recipient: idx(recipient),
            commitment_hash: [7; 32],
        };
        seal_dealing(&public, &context, &[0; 64], &mut rng).unwrap()
    }

    fn deal() -> DkgDeal {
        let g = G2::generator();
        DkgDeal {
            commitments: vec![g.clone(), g.mul(&Scalar::from_u64(2))],
            dealings: vec![(idx(1), sealed(1, 3)), (idx(2), sealed(2, 4))],
        }
    }

    fn rejects_every_truncation_and_trailing_byte<M: Decode>(bytes: &[u8]) {
        for cut in 0..bytes.len() {
            assert!(M::decode(&bytes[..cut]).is_err(), "truncated at {cut}");
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(M::decode(&trailing).is_err());
        let mut version = bytes.to_vec();
        version[0] = 2;
        assert!(matches!(M::decode(&version), Err(Error::InvalidEncoding)));
    }

    #[test]
    fn dkg_start_label_is_distinct_from_and_not_a_prefix_of_every_frozen_tag() {
        assert_eq!(DKG_START, b"TC-THRESHOLD-V1-DKG-START");
        assert_eq!(dst::DOMAINS.len(), 19);
        for tag in dst::DOMAINS {
            assert_ne!(*tag, DKG_START);
            assert!(!tag.starts_with(DKG_START));
            assert!(!DKG_START.starts_with(tag));
        }
    }

    #[test]
    fn initial_transcript_hashes_the_exact_ceremony_digest() {
        let signers = Signers::new();
        let ceremony = signers.genesis();
        let mut hash = Sha256::new();
        hash.update(25u32.to_be_bytes());
        hash.update(b"TC-THRESHOLD-V1-DKG-START");
        hash.update(ceremony.digest());
        let expected: [u8; 32] = hash.finalize().into();
        assert_eq!(dkg_initial_transcript(&ceremony).as_bytes(), &expected);
        assert_ne!(expected, [0; 32]);
        assert_ne!(expected, ceremony.digest());

        let mut body = signers.body(CeremonyKind::Genesis, ceremony.threshold());
        body.id = CeremonyId::new([42; 32]);
        let other = AuthorizedCeremony::verify_genesis(
            &signers.anchor(),
            &signers.statement(&body),
            &signers,
        )
        .unwrap();
        assert_ne!(
            dkg_initial_transcript(&other),
            dkg_initial_transcript(&ceremony)
        );
    }

    #[test]
    fn deal_payload_has_the_exact_layout_and_rejects_noncanonical_bytes() {
        let deal = deal();
        let bytes = deal.encode();
        let mut expected = vec![1, 0, 2];
        for c in &deal.commitments {
            expected.extend_from_slice(&c.encode());
        }
        expected.extend_from_slice(&[0, 2]);
        for (index, dealing) in &deal.dealings {
            let envelope = dealing.encode();
            expected.extend_from_slice(&index.get().to_be_bytes());
            expected.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
            expected.extend_from_slice(&envelope);
        }
        assert_eq!(bytes, expected);
        assert_eq!(DkgDeal::decode(&bytes).unwrap().encode(), bytes);
        rejects_every_truncation_and_trailing_byte::<DkgDeal>(&bytes);

        let swapped = DkgDeal {
            commitments: deal.commitments.clone(),
            dealings: vec![(idx(2), sealed(2, 4)), (idx(1), sealed(1, 3))],
        };
        assert!(DkgDeal::decode(&swapped.encode()).is_err());
        let duplicate = DkgDeal {
            commitments: deal.commitments.clone(),
            dealings: vec![(idx(1), sealed(1, 3)), (idx(1), sealed(1, 4))],
        };
        assert!(DkgDeal::decode(&duplicate.encode()).is_err());

        let mut bad_point = bytes.clone();
        // Setting the infinity flag on a nonzero compressed x is invalid.
        bad_point[3] ^= 0x40;
        assert!(DkgDeal::decode(&bad_point).is_err());
        let mut bad_envelope = bytes.clone();
        let envelope_version = 3 + 2 * 96 + 2 + 2 + 4;
        bad_envelope[envelope_version] = 2;
        assert!(DkgDeal::decode(&bad_envelope).is_err());
        let mut index_zero = bytes.clone();
        index_zero[3 + 2 * 96 + 2..3 + 2 * 96 + 4].copy_from_slice(&[0, 0]);
        assert!(DkgDeal::decode(&index_zero).is_err());

        assert!(matches!(
            DkgDeal::decode(&[1, 0, 17]),
            Err(Error::LimitExceeded)
        ));
        let mut many_dealings = vec![1, 0, 0];
        many_dealings.extend_from_slice(&[0, 17]);
        assert!(matches!(
            DkgDeal::decode(&many_dealings),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn complaint_payload_is_a_sorted_unique_index_list() {
        let complaints = DkgComplaints {
            dealers: vec![idx(2), idx(5)],
        };
        let bytes = complaints.encode();
        assert_eq!(bytes, vec![1, 0, 2, 0, 2, 0, 5]);
        assert_eq!(DkgComplaints::decode(&bytes).unwrap().encode(), bytes);
        assert_eq!(
            DkgComplaints::decode(&[1, 0, 0]).unwrap().dealers,
            Vec::<MemberIndex>::new()
        );
        rejects_every_truncation_and_trailing_byte::<DkgComplaints>(&bytes);
        for invalid in [
            vec![1, 0, 2, 0, 5, 0, 2],
            vec![1, 0, 2, 0, 2, 0, 2],
            vec![1, 0, 1, 0, 0],
            vec![1, 0, 1, 0, 17],
        ] {
            assert!(DkgComplaints::decode(&invalid).is_err());
        }
        assert!(matches!(
            DkgComplaints::decode(&[1, 0, 17]),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn published_pair_payloads_share_one_canonical_layout() {
        let entries = || vec![(idx(1), pair(7, 8)), (idx(3), pair(9, 10))];
        let answers = DkgAnswers { answers: entries() }.encode();
        let extraction = DkgExtractionComplaints {
            complaints: entries(),
        }
        .encode();
        let reconstruction = DkgReconstruction { values: entries() }.encode();
        let mut expected = vec![1, 0, 2];
        for (index, value, blinding) in [(1u16, 7u8, 8u8), (3, 9, 10)] {
            expected.extend_from_slice(&index.to_be_bytes());
            let mut scalar = [0; 32];
            scalar[31] = value;
            expected.extend_from_slice(&scalar);
            scalar[31] = blinding;
            expected.extend_from_slice(&scalar);
        }
        assert_eq!(answers, expected);
        assert_eq!(extraction, expected);
        assert_eq!(reconstruction, expected);
        assert_eq!(DkgAnswers::decode(&answers).unwrap().encode(), answers);
        assert_eq!(
            DkgExtractionComplaints::decode(&extraction)
                .unwrap()
                .encode(),
            extraction
        );
        assert_eq!(
            DkgReconstruction::decode(&reconstruction).unwrap().encode(),
            reconstruction
        );
        rejects_every_truncation_and_trailing_byte::<DkgAnswers>(&answers);
        rejects_every_truncation_and_trailing_byte::<DkgExtractionComplaints>(&extraction);
        rejects_every_truncation_and_trailing_byte::<DkgReconstruction>(&reconstruction);

        let mut noncanonical = expected.clone();
        noncanonical[5..37].copy_from_slice(&R);
        assert!(matches!(
            DkgAnswers::decode(&noncanonical),
            Err(Error::InvalidScalar)
        ));
        let mut blinding = expected.clone();
        blinding[37..69].copy_from_slice(&R);
        assert!(matches!(
            DkgReconstruction::decode(&blinding),
            Err(Error::InvalidScalar)
        ));
        let mut unsorted = expected.clone();
        unsorted[3..5].copy_from_slice(&[0, 3]);
        unsorted[69..71].copy_from_slice(&[0, 1]);
        assert!(DkgExtractionComplaints::decode(&unsorted).is_err());
        let mut duplicate = expected;
        duplicate[69..71].copy_from_slice(&[0, 1]);
        assert!(DkgAnswers::decode(&duplicate).is_err());
        assert!(matches!(
            DkgAnswers::decode(&[1, 0, 17]),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn feldman_payload_allows_individual_identity_coefficients() {
        let g = G2::generator();
        let feldman = DkgFeldman {
            commitments: vec![g.clone(), G2::identity(), g.mul(&Scalar::from_u64(3))],
        };
        let bytes = feldman.encode();
        assert_eq!(bytes.len(), 3 + 3 * 96);
        assert_eq!(&bytes[..3], &[1, 0, 3]);
        assert_eq!(&bytes[3 + 96..3 + 192], &G2::identity().encode());
        assert_eq!(DkgFeldman::decode(&bytes).unwrap().encode(), bytes);
        rejects_every_truncation_and_trailing_byte::<DkgFeldman>(&bytes);
        let mut off_curve = bytes.clone();
        off_curve[3 + 95] ^= 1;
        assert!(DkgFeldman::decode(&off_curve).is_err());
        assert!(matches!(
            DkgFeldman::decode(&[1, 0, 17]),
            Err(Error::LimitExceeded)
        ));
    }

    proptest! {
        #[test]
        fn random_payload_bytes_reject_or_reencode_canonically(
            bytes in proptest::collection::vec(any::<u8>(), 0..1400)
        ) {
            if let Ok(v) = DkgDeal::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
            if let Ok(v) = DkgComplaints::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
            if let Ok(v) = DkgAnswers::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
            if let Ok(v) = DkgFeldman::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
            if let Ok(v) = DkgExtractionComplaints::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
            if let Ok(v) = DkgReconstruction::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
        }

        #[test]
        fn structured_payload_mutations_reject_or_reencode_canonically(
            offset in 0usize..2048,
            mask in 1u8..=255
        ) {
            let valid = [
                deal().encode(),
                DkgComplaints { dealers: vec![idx(1), idx(4)] }.encode(),
                DkgAnswers { answers: vec![(idx(2), pair(3, 4))] }.encode(),
                DkgFeldman { commitments: vec![G2::generator(), G2::identity()] }.encode(),
            ];
            for bytes in valid {
                let mut mutated = bytes.clone();
                let n = mutated.len();
                mutated[offset % n] ^= mask;
                if let Ok(v) = DkgDeal::decode(&mutated) { prop_assert_eq!(v.encode(), mutated.clone()); }
                if let Ok(v) = DkgComplaints::decode(&mutated) { prop_assert_eq!(v.encode(), mutated.clone()); }
                if let Ok(v) = DkgAnswers::decode(&mutated) { prop_assert_eq!(v.encode(), mutated.clone()); }
                if let Ok(v) = DkgFeldman::decode(&mutated) { prop_assert_eq!(v.encode(), mutated.clone()); }
            }
        }
    }
}
