//! Authorized redistribution of the current master secret to a new cohort over
//! owner-closed rounds. Details: TC-2221
//!
//! Current-certificate dealers deal (R1) and answer (R3); authorized recipients
//! complain (R2). Members and `reshare_verify_transcript` apply the same public
//! rules to the authenticated round records. Liveness assumes the trusted owner
//! relay delivers every conforming member's message.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ceremony::{tests::Signers, CeremonyKind, Decode},
        curve::{Scalar, G2},
        dkg::{dkg_initial_transcript, DKG_START},
        dst,
        error::Error,
        ids::*,
    };
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    fn idx(i: u16) -> MemberIndex {
        MemberIndex::new(i).unwrap()
    }

    const R: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x01,
    ];

    fn answers() -> ReshareAnswers {
        ReshareAnswers {
            answers: vec![(idx(1), Scalar::from_u64(7)), (idx(3), Scalar::from_u64(9))],
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
    fn reshare_start_label_is_distinct_from_and_not_a_prefix_of_every_frozen_tag() {
        assert_eq!(RESHARE_START, b"TC-THRESHOLD-V1-RESHARE-START");
        assert_eq!(dst::DOMAINS.len(), 19);
        for tag in dst::DOMAINS.iter().copied().chain([DKG_START]) {
            assert_ne!(tag, RESHARE_START);
            assert!(!tag.starts_with(RESHARE_START));
            assert!(!RESHARE_START.starts_with(tag));
        }
    }

    #[test]
    fn initial_transcript_hashes_the_exact_ceremony_digest_for_reshare_and_refresh() {
        let signers = Signers::new();
        let (current, _) = crate::cert::tests::genesis(&signers);
        let mut links = Vec::new();
        for kind in [CeremonyKind::Reshare, CeremonyKind::Refresh] {
            let (_, _, ceremony) = crate::cert::tests::successor(
                &signers,
                &current,
                kind,
                current.key_context().threshold(),
                11,
            );
            let mut hash = Sha256::new();
            hash.update(29u32.to_be_bytes());
            hash.update(b"TC-THRESHOLD-V1-RESHARE-START");
            hash.update(ceremony.digest());
            let expected: [u8; 32] = hash.finalize().into();
            let link = reshare_initial_transcript(&ceremony);
            assert_eq!(link.as_bytes(), &expected);
            assert_ne!(link, dkg_initial_transcript(&ceremony));
            assert_ne!(expected, ceremony.digest());
            links.push(link);
        }
        // The ceremony digest binds the kind.
        assert_ne!(links[0], links[1]);
    }

    #[test]
    fn answer_payload_has_the_exact_layout_and_rejects_noncanonical_bytes() {
        let bytes = answers().encode();
        let mut expected = vec![1, 0, 2];
        for (index, value) in [(1u16, 7u8), (3, 9)] {
            expected.extend_from_slice(&index.to_be_bytes());
            let mut scalar = [0; 32];
            scalar[31] = value;
            expected.extend_from_slice(&scalar);
        }
        assert_eq!(bytes, expected);
        assert_eq!(ReshareAnswers::decode(&bytes).unwrap().encode(), bytes);
        assert_eq!(
            ReshareAnswers::decode(&[1, 0, 0]).unwrap().answers.len(),
            0
        );
        rejects_every_truncation_and_trailing_byte::<ReshareAnswers>(&bytes);

        let mut noncanonical = expected.clone();
        noncanonical[5..37].copy_from_slice(&R);
        assert!(matches!(
            ReshareAnswers::decode(&noncanonical),
            Err(Error::InvalidScalar)
        ));
        let mut unsorted = expected.clone();
        unsorted[3..5].copy_from_slice(&[0, 3]);
        unsorted[37..39].copy_from_slice(&[0, 1]);
        assert!(ReshareAnswers::decode(&unsorted).is_err());
        let mut duplicate = expected.clone();
        duplicate[37..39].copy_from_slice(&[0, 1]);
        assert!(ReshareAnswers::decode(&duplicate).is_err());
        let mut zero = expected;
        zero[3..5].copy_from_slice(&[0, 0]);
        assert!(ReshareAnswers::decode(&zero).is_err());
        assert!(matches!(
            ReshareAnswers::decode(&[1, 0, 17]),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn redistribution_rounds_reuse_the_genesis_deal_and_complaint_layouts() {
        // R1 carries Feldman coefficients in the genesis R1 layout; R2 is the
        // genesis complaint list. Individual coefficients may be the identity.
        let deal = ReshareDeal {
            commitments: vec![G2::generator(), G2::identity()],
            dealings: Vec::new(),
        };
        let bytes = deal.encode();
        assert_eq!(&bytes[..3], &[1, 0, 2]);
        assert_eq!(&bytes[3 + 96..3 + 192], &G2::identity().encode());
        assert_eq!(&bytes[3 + 192..], &[0, 0]);
        assert_eq!(ReshareDeal::decode(&bytes).unwrap().encode(), bytes);
        let complaints = ReshareComplaints {
            dealers: vec![idx(2)],
        };
        assert_eq!(complaints.encode(), vec![1, 0, 1, 0, 2]);
    }

    proptest! {
        #[test]
        fn random_answer_bytes_reject_or_reencode_canonically(
            bytes in proptest::collection::vec(any::<u8>(), 0..800)
        ) {
            if let Ok(v) = ReshareAnswers::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
        }

        #[test]
        fn structured_answer_mutations_reject_or_reencode_canonically(
            offset in 0usize..256,
            mask in 1u8..=255
        ) {
            let mut mutated = answers().encode();
            let n = mutated.len();
            mutated[offset % n] ^= mask;
            if let Ok(v) = ReshareAnswers::decode(&mutated) { prop_assert_eq!(v.encode(), mutated.clone()); }
        }
    }
}
