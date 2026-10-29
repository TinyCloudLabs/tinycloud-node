#[cfg(test)]
use crate::{error::{Error, SignatureError}, ids::*};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use std::collections::BTreeMap;

    pub(crate) struct Signers {
        keys: BTreeMap<Did, SigningKey>,
    }
    impl Signers {
        pub(crate) fn new() -> Self {
            let keys = (0..=16)
                .map(|i| (Self::did(i), SigningKey::from_bytes(&[i; 32])))
                .collect();
            Self { keys }
        }
        pub(crate) fn did(i: u8) -> Did {
            Did::new(format!("did:key:tc2222-fixture-{i}")).unwrap()
        }
        pub(crate) fn anchor(&self) -> TrustAnchor {
            TrustAnchor {
                expected_owner: Self::did(0),
                network: NetworkUrn::new("tinycloud:test:certificates").unwrap(),
            }
        }
        pub(crate) fn sign(&self, did: &Did, preimage: &[u8]) -> Vec<u8> {
            self.keys[did].sign(preimage).to_bytes().to_vec()
        }
        pub(crate) fn statement(&self, body: &CeremonyStatement) -> SignedStatement {
            SignedStatement {
                bytes: body.encode(),
                signature: self.sign(&body.owner, &body.signing_preimage()),
            }
        }
        pub(crate) fn genesis(&self) -> AuthorizedCeremony {
            let body = self.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
            AuthorizedCeremony::verify_genesis(&self.anchor(), &self.statement(&body), self).unwrap()
        }
        pub(crate) fn body(&self, kind: CeremonyKind, threshold: Threshold) -> CeremonyStatement {
            CeremonyStatement {
                kind,
                id: CeremonyId::new([41; 32]),
                network: self.anchor().network,
                owner: Self::did(0),
                current: None,
                threshold,
                rekey: RekeyCounter::new(0),
                epoch: Epoch::new(0),
                recipients: (1..=threshold.n())
                    .map(|i| CeremonyRecipient {
                        index: MemberIndex::new(i).unwrap(),
                        node: Self::did(i as u8),
                        hpke_public_key: [i as u8; 32],
                    })
                    .collect(),
            }
        }
    }
    impl DidSignatureVerifier for Signers {
        fn verify(&self, signer: &Did, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
            let key: VerifyingKey = self.keys.get(signer).ok_or(SignatureError::Invalid)?.verifying_key();
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|_| SignatureError::Invalid)?;
            key.verify_strict(message, &signature).map_err(|_| SignatureError::Invalid)
        }
    }

    #[test]
    fn ceremony_substitutions_require_the_owner_signature() {
        let signers = Signers::new();
        let body = signers.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
        let signed = signers.statement(&body);
        let verified = AuthorizedCeremony::verify_genesis(&signers.anchor(), &signed, &signers).unwrap();
        assert_eq!(verified.threshold(), body.threshold);
        for mutation in 0..7 {
            let mut changed = body.clone();
            match mutation {
                0 => changed.recipients[0].hpke_public_key = [99; 32],
                1 => changed.recipients[0].node = Signers::did(9),
                2 => changed.id = CeremonyId::new([42; 32]),
                3 => changed.network = NetworkUrn::new("other").unwrap(),
                4 => changed.owner = Signers::did(9),
                5 => changed.epoch = Epoch::new(1),
                _ => changed.threshold = Threshold::new(3, 3).unwrap(),
            }
            let forged = SignedStatement { bytes: changed.encode(), signature: signed.signature.clone() };
            assert!(AuthorizedCeremony::verify_genesis(&signers.anchor(), &forged, &signers).is_err());
        }
        let other = TrustAnchor { expected_owner: Signers::did(9), ..signers.anchor() };
        assert!(AuthorizedCeremony::verify_genesis(&other, &signed, &signers).is_err());
    }

    #[test]
    fn ceremony_decoding_checks_budget_directory_and_canonical_bytes() {
        let signers = Signers::new();
        let invalid_budget = signers.body(CeremonyKind::Genesis, Threshold::new(3, 4).unwrap());
        assert!(matches!(AuthorizedCeremony::verify_genesis(&signers.anchor(), &signers.statement(&invalid_budget), &signers), Err(Error::UnsupportedFaultBudget)));
        let body = signers.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
        assert_eq!(CeremonyStatement::decode(&body.encode()).unwrap().encode(), body.encode());
        for mutation in 0..4 {
            let mut changed = body.clone();
            match mutation {
                0 => changed.recipients.swap(0, 1),
                1 => changed.recipients[1].node = changed.recipients[0].node.clone(),
                2 => changed.recipients[1].index = changed.recipients[0].index,
                _ => { changed.recipients.pop(); }
            }
            assert!(CeremonyStatement::decode(&changed.encode()).is_err());
        }
        let mut bytes = body.encode();
        bytes.push(0);
        assert!(CeremonyStatement::decode(&bytes).is_err());
        for length in 0..body.encode().len() {
            assert!(CeremonyStatement::decode(&body.encode()[..length]).is_err());
        }
    }
}

#[cfg(test)]
mod round_tests {
    use super::*;
    use super::tests::Signers;

    #[derive(Debug, Eq, PartialEq)]
    struct Byte(u8);
    impl Decode for Byte {
        fn decode(bytes: &[u8]) -> Result<Self, Error> {
            match bytes { [byte] => Ok(Self(*byte)), _ => Err(Error::InvalidEncoding) }
        }
    }
    fn message(c: &AuthorizedCeremony, member: u16, payload: &[u8], signers: &Signers) -> SignedStatement {
        let bytes = ceremony_message_body(c, 1, MemberCohort::Recipients, MemberIndex::new(member).unwrap(), payload).unwrap();
        SignedStatement {
            signature: signers.sign(&Signers::did(member as u8), &ceremony_message_preimage(&bytes).unwrap()), bytes,
        }
    }
    fn close(c: &AuthorizedCeremony, prev: &TranscriptHash, messages: &[SignedStatement], signers: &Signers) -> SignedStatement {
        let bytes = round_closure_body(c, 1, prev, messages).unwrap();
        SignedStatement {
            signature: signers.sign(&signers.anchor().expected_owner, &round_closure_preimage(&bytes).unwrap()), bytes,
        }
    }

    #[test]
    fn closure_commits_owner_order_member_signatures_ceremony_round_and_previous() {
        let signers = Signers::new();
        let ceremony = signers.genesis();
        let prev = TranscriptHash::new([0; 32]);
        let messages = vec![message(&ceremony, 1, &[7], &signers), message(&ceremony, 2, &[8], &signers)];
        let closure = close(&ceremony, &prev, &messages, &signers);
        let round = ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &closure, &messages, &signers).unwrap();
        assert_eq!(round.messages()[0].payload(), &Ok(Byte(7)));
        assert_ne!(round.transcript_hash(), prev);
        let mut reordered = messages.clone(); reordered.reverse();
        assert!(ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &closure, &reordered, &signers).is_err());
        assert!(ClosedRound::<Byte>::verify(&ceremony, 2, &prev, &closure, &messages, &signers).is_err());
        assert!(ClosedRound::<Byte>::verify(&ceremony, 1, &TranscriptHash::new([9; 32]), &closure, &messages, &signers).is_err());
        let mut changed = signers.body(CeremonyKind::Genesis, ceremony.threshold()); changed.id = CeremonyId::new([99; 32]);
        let other = AuthorizedCeremony::verify_genesis(&signers.anchor(), &signers.statement(&changed), &signers).unwrap();
        assert!(ClosedRound::<Byte>::verify(&other, 1, &prev, &closure, &messages, &signers).is_err());
        let mut invalid = messages.clone(); invalid[0].signature[0] ^= 1;
        let signed_invalid = close(&ceremony, &prev, &invalid, &signers);
        assert!(matches!(ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &signed_invalid, &invalid, &signers), Err(Error::InvalidSignature)));
        let mut invalid_owner = closure.clone(); invalid_owner.signature[0] ^= 1;
        assert!(matches!(ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &invalid_owner, &messages, &signers), Err(Error::InvalidSignature)));
    }

    #[test]
    fn closed_round_preserves_authenticated_equivocation_and_malformed_payloads() {
        let signers = Signers::new();
        let ceremony = signers.genesis();
        let prev = TranscriptHash::new([0; 32]);
        let one = message(&ceremony, 1, &[7], &signers);
        let messages = vec![one.clone(), one, message(&ceremony, 1, &[8], &signers), message(&ceremony, 2, &[], &signers)];
        let closure = close(&ceremony, &prev, &messages, &signers);
        let round = ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &closure, &messages, &signers).unwrap();
        assert_eq!(round.messages()[0].payload(), &Ok(Byte(7)));
        assert_eq!(round.messages()[2].payload(), &Ok(Byte(8)));
        assert_eq!(round.messages()[3].payload(), &Err(Error::InvalidEncoding));
        assert_eq!(round.messages()[0].member(), round.messages()[2].member());
        assert!(ceremony_message_body(&ceremony, 1, MemberCohort::Current, MemberIndex::new(1).unwrap(), &[7]).is_err());
    }
}

#[cfg(test)]
mod cohort_tests {
    use super::*;
    use super::tests::Signers;

    struct Payload;
    impl Decode for Payload {
        fn decode(_: &[u8]) -> Result<Self, Error> { Ok(Self) }
    }

    #[test]
    fn overlapping_indices_resolve_only_in_the_signed_cohort() {
        let signers = Signers::new();
        let (current, _) = crate::cert::tests::genesis(&signers);
        let mut body = signers.body(CeremonyKind::Reshare, current.key_context().threshold());
        body.current = Some(current.digest());
        body.epoch = current.key_context().epoch().checked_next().unwrap();
        body.recipients[0].node = Signers::did(9);
        let ceremony = AuthorizedCeremony::verify_for(&current, &signers.statement(&body), &signers).unwrap();
        let index = MemberIndex::new(1).unwrap();
        let mut messages = Vec::new();
        for (cohort, did) in [(MemberCohort::Current, Signers::did(1)), (MemberCohort::Recipients, Signers::did(9))] {
            let bytes = ceremony_message_body(&ceremony, 1, cohort, index, &[7]).unwrap();
            messages.push(SignedStatement { signature: signers.sign(&did, &ceremony_message_preimage(&bytes).unwrap()), bytes });
        }
        let prev = TranscriptHash::new([0; 32]);
        let close = |messages: &[SignedStatement]| {
            let bytes = round_closure_body(&ceremony, 1, &prev, messages).unwrap();
            SignedStatement { signature: signers.sign(&signers.anchor().expected_owner, &round_closure_preimage(&bytes).unwrap()), bytes }
        };
        let round = ClosedRound::<Payload>::verify(&ceremony, 1, &prev, &close(&messages), &messages, &signers).unwrap();
        assert_eq!(round.messages()[0].cohort(), MemberCohort::Current);
        assert_eq!(round.messages()[1].cohort(), MemberCohort::Recipients);
        assert_eq!(round.messages()[0].statement(), &messages[0]);
        let mut forged = messages.clone();
        forged[1].signature = signers.sign(&Signers::did(1), &ceremony_message_preimage(&forged[1].bytes).unwrap());
        assert!(matches!(ClosedRound::<Payload>::verify(&ceremony, 1, &prev, &close(&forged), &forged, &signers), Err(Error::InvalidSignature)));
        let mut stale = body.clone(); stale.current = Some(CertDigest::new([99; 32]));
        assert!(AuthorizedCeremony::verify_for(&current, &signers.statement(&stale), &signers).is_err());
        let (rekey, _, rekey_ceremony) = crate::cert::tests::successor(&signers, &current, CeremonyKind::Rekey, current.key_context().threshold(), 12);
        assert!(ceremony_message_body(&rekey_ceremony, 1, MemberCohort::Current, index, &[7]).is_err());
        assert!(crate::cert::verify_successor(&current, &rekey, &signers).is_ok());
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    use super::tests::Signers;

    struct Payload;
    impl Decode for Payload {
        fn decode(_: &[u8]) -> Result<Self, Error> { Ok(Self) }
    }

    #[test]
    fn round_byte_and_signature_caps_precede_authentication() {
        let signers = Signers::new();
        let c = signers.genesis();
        let index = MemberIndex::new(1).unwrap();
        assert!(ceremony_message_body(&c, 1, MemberCohort::Recipients, index, &vec![0; 65_536]).is_err());
        let bytes = ceremony_message_body(&c, 1, MemberCohort::Recipients, index, &[0; 60_000]).unwrap();
        let message = SignedStatement { signature: signers.sign(&Signers::did(1), &ceremony_message_preimage(&bytes).unwrap()), bytes };
        let prev = TranscriptHash::new([0; 32]);
        assert!(round_closure_body(&c, 1, &prev, &vec![message.clone(); 70]).is_err());
        let mut oversized = message.clone(); oversized.signature = vec![0; 513];
        assert!(round_closure_body(&c, 1, &prev, &[oversized]).is_err());
        let mut malformed = message.clone(); malformed.bytes.push(0);
        let mut closure = SignedStatement { bytes: vec![0; 98], signature: vec![0; 64] };
        assert!(ClosedRound::<Payload>::verify(&c, 1, &prev, &closure, &[malformed], &signers).is_err());
        closure.bytes = vec![0; 65_537];
        assert!(ClosedRound::<Payload>::verify(&c, 1, &prev, &closure, &[message], &signers).is_err());
    }
}
