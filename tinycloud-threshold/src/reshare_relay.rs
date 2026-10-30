//! Test-only owner relay driving real redistribution states over signed closed
//! rounds. Details: TC-2221
//!
//! Completion scenarios deliver every honest message and keep at least t valid
//! old dealers. Omissions and substitutions below are explicit failure cases
//! chosen by each test, not a broadcast model. Nothing here claims that old
//! shares stop working: old and new key contexts stay separate, and old shares
//! keep working with the old certificate until integration erases them.

use std::collections::BTreeMap;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde_json::{json, Value};

use crate::{
    ceremony::{
        ceremony_message_body, ceremony_message_preimage, round_closure_body,
        round_closure_preimage, tests::Signers, AuthorizedCeremony, CeremonyKind,
        CeremonyRecipient, CeremonyStatement, ClosedRound, Decode, DidSignatureVerifier,
        MemberCohort, SignedStatement,
    },
    cert::{
        verify_certificate, verify_successor, CandidateShare, CertificateBody, PublicMaterial,
        SignedCertificate, VerifiedCertificate,
    },
    checkpoint::{authorize, identity},
    curve::{Scalar, G2},
    derive::{
        combine, decrypt_derived_key, issue_share, verify_share, DecryptRequest,
        EncryptedKeyShare, KeyShare, TransportSecretKey,
    },
    dkg::{dkg_initial_transcript, DkgRoundRecord},
    dkg_relay::commitment_hash,
    dst,
    error::{CombineError, Error, ShareError, SignatureError},
    ibe::{unwrap_key, wrap_key, DataKey, IbeCiphertext},
    ids::*,
    reshare::*,
    seal::{
        open_dealing, seal_dealing, CeremonyHpkePublicKey, CeremonyHpkeSecretKey, DealingContext,
    },
};

use CeremonyKind::{Refresh, Reshare};
use MemberCohort::{Current, Recipients};

pub(crate) fn idx(i: u16) -> MemberIndex {
    MemberIndex::new(i).unwrap()
}

// ------------------------------------------------------------------ fixture

/// The current certificate, its bound shares, and an owner-authorized successor
/// ceremony whose directory holds real ceremony recipient keys.
pub(crate) struct Fixture {
    pub(crate) signers: Signers,
    pub(crate) current: VerifiedCertificate,
    pub(crate) shares: BTreeMap<u16, KeyShare>,
    pub(crate) statement: SignedStatement,
    pub(crate) ceremony: AuthorizedCeremony,
    pub(crate) seed: u8,
}

/// Successor statement for `current`: new threshold, recipient DIDs in index
/// order, and recipient keys regenerated from `seed`.
pub(crate) fn statement_body(
    current: &VerifiedCertificate,
    kind: CeremonyKind,
    t: u16,
    n: u16,
    seed: u8,
    dids: &[u8],
) -> CeremonyStatement {
    assert_eq!(dids.len(), usize::from(n));
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let context = current.key_context();
    CeremonyStatement {
        kind,
        id: CeremonyId::new([seed; 32]),
        network: current.anchor().network.clone(),
        owner: current.anchor().expected_owner.clone(),
        current: Some(current.digest()),
        threshold: Threshold::new(t, n).unwrap(),
        rekey: context.rekey(),
        epoch: context.epoch().checked_next().unwrap(),
        recipients: dids
            .iter()
            .enumerate()
            .map(|(k, did)| CeremonyRecipient {
                index: idx(k as u16 + 1),
                node: Signers::did(*did),
                hpke_public_key: CeremonyHpkeSecretKey::generate(&mut rng).1.encode(),
            })
            .collect(),
    }
}

pub(crate) fn fixture_on(
    current: VerifiedCertificate,
    shares: impl IntoIterator<Item = KeyShare>,
    kind: CeremonyKind,
    t: u16,
    n: u16,
    seed: u8,
    dids: &[u8],
) -> Fixture {
    let signers = Signers::new();
    let body = statement_body(&current, kind, t, n, seed, dids);
    let statement = signers.statement(&body);
    let ceremony = AuthorizedCeremony::verify_for(&current, &statement, &signers).unwrap();
    let shares = shares.into_iter().map(|s| (s.index().get(), s)).collect();
    Fixture {
        signers,
        current,
        shares,
        statement,
        ceremony,
        seed,
    }
}

/// A test-dealer genesis certificate with every share bound to it.
pub(crate) fn dealer_genesis(t: u16, n: u16) -> (VerifiedCertificate, Vec<KeyShare>) {
    let signers = Signers::new();
    let threshold = Threshold::new(t, n).unwrap();
    let (public, raw) = crate::cert::tests::material(11, threshold);
    let ceremony = AuthorizedCeremony::verify_genesis(
        &signers.anchor(),
        &signers.statement(&signers.body(CeremonyKind::Genesis, threshold)),
        &signers,
    )
    .unwrap();
    let transcript = TranscriptHash::new([51; 32]);
    let body = CertificateBody::genesis(&signers.anchor(), &ceremony, &public, &transcript).unwrap();
    let cert = verify_certificate(
        &signers.anchor(),
        &crate::cert::tests::sign(body, &signers),
        &signers,
    )
    .unwrap();
    let shares = raw
        .into_iter()
        .map(|mut raw| {
            let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
            KeyShare::bind(CandidateShare::new(transcript, raw.index, scalar), &cert).unwrap()
        })
        .collect();
    (cert, shares)
}

/// Redistribution from the 2-of-3 test-dealer genesis to recipients did 1..=n.
pub(crate) fn fixture(kind: CeremonyKind, t: u16, n: u16, seed: u8) -> Fixture {
    let (current, shares) = dealer_genesis(2, 3);
    let dids: Vec<u8> = (1..=n as u8).collect();
    fixture_on(current, shares, kind, t, n, seed, &dids)
}

/// A verified pinned successor of `f.current` (same master key) and its shares.
pub(crate) fn newer_certificate(f: &Fixture) -> (VerifiedCertificate, Vec<KeyShare>) {
    let (signed, raw, _) = crate::cert::tests::successor(
        &f.signers,
        &f.current,
        Reshare,
        Threshold::new(2, 3).unwrap(),
        // Seed 11 matches the test-dealer genesis, so the successor keeps its mpk.
        11,
    );
    let newer = verify_successor(&f.current, &signed, &f.signers).unwrap();
    let transcript = newer.body().transcript_hash();
    let shares = raw
        .into_iter()
        .map(|mut raw| {
            let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
            KeyShare::bind(CandidateShare::new(transcript, raw.index, scalar), &newer).unwrap()
        })
        .collect();
    (newer, shares)
}

impl Fixture {
    /// Regenerate new member j's ceremony recipient key from the fixture seed.
    pub(crate) fn secret(&self, j: u16) -> CeremonyHpkeSecretKey {
        let mut rng = ChaCha20Rng::from_seed([self.seed; 32]);
        let mut key = None;
        for _ in 1..=j {
            key = Some(CeremonyHpkeSecretKey::generate(&mut rng).0);
        }
        key.unwrap()
    }

    pub(crate) fn member_rng(&self, i: u16) -> ChaCha20Rng {
        let mut seed = [self.seed; 32];
        seed[0] = i as u8;
        seed[1] = 0xd2;
        ChaCha20Rng::from_seed(seed)
    }

    /// The node DID for a coordinate in the named cohort.
    pub(crate) fn did(&self, cohort: MemberCohort, member: u16) -> Did {
        match cohort {
            Current => self.current.member(idx(member)).unwrap().node.clone(),
            Recipients => self.ceremony.recipients()[usize::from(member - 1)]
                .node
                .clone(),
        }
    }

    pub(crate) fn sign_bytes(
        &self,
        cohort: MemberCohort,
        member: u16,
        bytes: Vec<u8>,
    ) -> SignedStatement {
        let preimage = ceremony_message_preimage(&bytes).unwrap();
        SignedStatement {
            signature: self.signers.sign(&self.did(cohort, member), &preimage),
            bytes,
        }
    }

    pub(crate) fn sign(
        &self,
        cohort: MemberCohort,
        member: u16,
        message: &ReshareMessage,
    ) -> SignedStatement {
        assert_eq!(
            message.signing_preimage(),
            ceremony_message_preimage(message.body()).unwrap()
        );
        self.sign_bytes(cohort, member, message.body().to_vec())
    }

    pub(crate) fn n(&self) -> u16 {
        self.ceremony.threshold().n()
    }

    pub(crate) fn old_t(&self) -> u16 {
        self.current.key_context().threshold().t()
    }
}

// -------------------------------------------------------------------- relay

/// The signed cohort byte and coordinate of a member envelope.
pub(crate) fn sender(statement: &SignedStatement) -> (u8, u16) {
    (
        statement.bytes[34],
        u16::from_be_bytes([statement.bytes[35], statement.bytes[36]]),
    )
}

/// Messages the owner is about to close for one round. R1 and R3 default to
/// the current-certificate dealer cohort, R2 to the recipient cohort.
pub(crate) struct Outbox<'a> {
    round: u8,
    fixture: &'a Fixture,
    rng: &'a mut ChaCha20Rng,
    pub(crate) messages: Vec<SignedStatement>,
}

impl Outbox<'_> {
    pub(crate) fn round(&self) -> u8 {
        self.round
    }
    pub(crate) fn fixture(&self) -> &Fixture {
        self.fixture
    }
    pub(crate) fn ceremony(&self) -> &AuthorizedCeremony {
        &self.fixture.ceremony
    }
    pub(crate) fn rng(&mut self) -> &mut ChaCha20Rng {
        &mut *self.rng
    }
    fn cohort(&self) -> MemberCohort {
        if self.round == 2 {
            Recipients
        } else {
            Current
        }
    }
    fn key(&self, member: u16) -> (u8, u16) {
        (self.cohort() as u8, member)
    }
    /// A member-signed envelope for this round under an explicit cohort.
    pub(crate) fn signed_as(
        &self,
        cohort: MemberCohort,
        member: u16,
        payload: &[u8],
    ) -> SignedStatement {
        let bytes = ceremony_message_body(
            &self.fixture.ceremony,
            self.round,
            cohort,
            idx(member),
            payload,
        )
        .unwrap();
        self.fixture.sign_bytes(cohort, member, bytes)
    }
    pub(crate) fn has(&self, member: u16) -> bool {
        let key = self.key(member);
        self.messages.iter().any(|m| sender(m) == key)
    }
    pub(crate) fn payload(&self, member: u16) -> Vec<u8> {
        let key = self.key(member);
        self.messages
            .iter()
            .find(|m| sender(m) == key)
            .expect("member message in this round")
            .bytes[41..]
            .to_vec()
    }
    pub(crate) fn remove(&mut self, member: u16) {
        let key = self.key(member);
        self.messages.retain(|m| sender(m) != key);
    }
    pub(crate) fn replace(&mut self, member: u16, payload: &[u8]) {
        let signed = self.signed_as(self.cohort(), member, payload);
        let key = self.key(member);
        let position = self.messages.iter().position(|m| sender(m) == key);
        self.remove(member);
        match position {
            Some(p) => self.messages.insert(p, signed),
            None => self.messages.push(signed),
        }
    }
    pub(crate) fn push(&mut self, member: u16, payload: &[u8]) {
        let signed = self.signed_as(self.cohort(), member, payload);
        self.messages.push(signed);
    }
    pub(crate) fn push_as(&mut self, cohort: MemberCohort, member: u16, payload: &[u8]) {
        let signed = self.signed_as(cohort, member, payload);
        self.messages.push(signed);
    }
    pub(crate) fn duplicate(&mut self, member: u16) {
        let key = self.key(member);
        let copy = self
            .messages
            .iter()
            .find(|m| sender(m) == key)
            .cloned()
            .expect("member message in this round");
        self.messages.push(copy);
    }
    /// Move the listed members' first messages to the front, in this order.
    pub(crate) fn order(&mut self, order: &[u16]) {
        let mut front = Vec::new();
        for member in order {
            let key = self.key(*member);
            if let Some(p) = self.messages.iter().position(|m| sender(m) == key) {
                front.push(self.messages.remove(p));
            }
        }
        front.append(&mut self.messages);
        self.messages = front;
    }
}

pub(crate) type Outcome = Result<(CandidateShare, ReshareOutput), Error>;

pub(crate) struct Run {
    pub(crate) fixture: Fixture,
    /// Receiver outcomes by new coordinate.
    pub(crate) outcomes: BTreeMap<u16, Outcome>,
    /// Each dealer's R3 payload as produced by its own state.
    pub(crate) answers: BTreeMap<u16, Result<Vec<u8>, Error>>,
    pub(crate) transcript: ReshareTranscript,
}

impl Run {
    pub(crate) fn verify(&self) -> Result<ReshareOutput, Error> {
        reshare_verify_transcript(
            &self.fixture.ceremony,
            &self.fixture.current,
            &self.transcript,
            &self.fixture.signers,
        )
    }
}

struct Relay<'a, V> {
    fixture: &'a Fixture,
    verifier: &'a V,
    previous: TranscriptHash,
    transcript: ReshareTranscript,
    rng: ChaCha20Rng,
}

impl<V: DidSignatureVerifier> Relay<'_, V> {
    fn close<M: Decode>(
        &mut self,
        round: u8,
        messages: Vec<SignedStatement>,
        tamper: &mut impl FnMut(&mut Outbox),
    ) -> ClosedRound<M> {
        let mut outbox = Outbox {
            round,
            fixture: self.fixture,
            rng: &mut self.rng,
            messages,
        };
        tamper(&mut outbox);
        let messages = outbox.messages;
        let c = &self.fixture.ceremony;
        let bytes = round_closure_body(c, round, &self.previous, &messages).unwrap();
        let closure = SignedStatement {
            signature: self.fixture.signers.sign(
                &self.fixture.signers.anchor().expected_owner,
                &round_closure_preimage(&bytes).unwrap(),
            ),
            bytes,
        };
        let closed =
            ClosedRound::<M>::verify(c, round, &self.previous, &closure, &messages, self.verifier)
                .unwrap();
        self.previous = closed.transcript_hash();
        self.transcript
            .rounds
            .push(DkgRoundRecord { closure, messages });
        closed
    }
}

/// Run every old dealer's and new recipient's real state through a signing
/// owner relay.
pub(crate) fn drive<V: DidSignatureVerifier>(
    fixture: Fixture,
    verifier: &V,
    mut tamper: impl FnMut(&mut Outbox),
) -> Run {
    let mut relay = Relay {
        fixture: &fixture,
        verifier,
        previous: reshare_initial_transcript(&fixture.ceremony),
        transcript: ReshareTranscript { rounds: Vec::new() },
        rng: ChaCha20Rng::from_seed([fixture.seed ^ 0xaa; 32]),
    };
    let mut dealers = BTreeMap::new();
    let mut r1 = Vec::new();
    for (i, share) in &fixture.shares {
        let mut rng = fixture.member_rng(*i);
        let (state, message) =
            reshare_deal(&fixture.ceremony, &fixture.current, share, &mut rng).unwrap();
        assert_eq!(message.round(), 1);
        r1.push(fixture.sign(Current, *i, &message));
        dealers.insert(*i, state);
    }
    let closed1 = relay.close::<ReshareDeal>(1, r1, &mut tamper);
    let mut receivers = BTreeMap::new();
    let mut r2 = Vec::new();
    for j in 1..=fixture.n() {
        let started =
            reshare_start_receiver(&fixture.ceremony, &fixture.current, idx(j), fixture.secret(j));
        match started.and_then(|s| s.complain(&closed1)) {
            Ok((state, message)) => {
                assert_eq!(message.round(), 2);
                r2.push(fixture.sign(Recipients, j, &message));
                receivers.insert(j, Ok(state));
            }
            Err(e) => {
                receivers.insert(j, Err(e));
            }
        }
    }
    let closed2 = relay.close::<ReshareComplaints>(2, r2, &mut tamper);
    let mut answers = BTreeMap::new();
    let mut r3 = Vec::new();
    for (i, state) in dealers {
        match state.answer(&closed1, &closed2) {
            Ok(message) => {
                assert_eq!(message.round(), 3);
                answers.insert(i, Ok(message.body()[41..].to_vec()));
                r3.push(fixture.sign(Current, i, &message));
            }
            Err(e) => {
                answers.insert(i, Err(e));
            }
        }
    }
    let closed3 = relay.close::<ReshareAnswers>(3, r3, &mut tamper);
    let outcomes = receivers
        .into_iter()
        .map(|(j, state)| (j, state.and_then(|s| s.finish(&closed2, &closed3))))
        .collect();
    let transcript = relay.transcript;
    Run {
        fixture,
        outcomes,
        answers,
        transcript,
    }
}

pub(crate) fn run_with(fixture: Fixture, tamper: impl FnMut(&mut Outbox)) -> Run {
    let signers = Signers::new();
    drive(fixture, &signers, tamper)
}

pub(crate) fn run(
    kind: CeremonyKind,
    t: u16,
    n: u16,
    seed: u8,
    tamper: impl FnMut(&mut Outbox),
) -> Run {
    run_with(fixture(kind, t, n, seed), tamper)
}

pub(crate) fn honest(kind: CeremonyKind, t: u16, n: u16, seed: u8) -> Run {
    run(kind, t, n, seed, |_| {})
}

// --------------------------------------------------------------- assertions

type View = (
    Vec<[u8; 96]>,
    [u8; 96],
    Vec<[u8; 96]>,
    Vec<MemberIndex>,
    BTreeMap<MemberIndex, ExcludeReason>,
    TranscriptHash,
);

pub(crate) fn view(output: &ReshareOutput) -> View {
    let n = output.public.threshold().n();
    (
        output.public.commitments().collect(),
        output.public.master_public_key().encode(),
        (1..=n)
            .map(|j| output.public.public_share(idx(j)).unwrap())
            .collect(),
        output.dealers.clone(),
        output.excluded.clone(),
        output.transcript_hash,
    )
}

fn last_hash(run: &Run) -> TranscriptHash {
    let mut previous = reshare_initial_transcript(&run.fixture.ceremony);
    for record in &run.transcript.rounds {
        let mut body = previous.as_bytes().to_vec();
        body.extend_from_slice(&(record.closure.bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(&record.closure.bytes);
        body.extend_from_slice(&(record.closure.signature.len() as u32).to_be_bytes());
        body.extend_from_slice(&record.closure.signature);
        previous = TranscriptHash::new(dst::tagged_hash(dst::TRANSCRIPT, &body));
    }
    previous
}

/// Every listed receiver and the public verifier agree, the master key is the
/// current certificate's, t dealers were selected and each candidate matches
/// its public share.
pub(crate) fn agreed(run: &Run, receivers: &[u16]) -> ReshareOutput {
    let verified = run.verify().unwrap();
    assert_eq!(verified.transcript_hash, last_hash(run));
    assert_eq!(
        verified.public.master_public_key().encode(),
        run.fixture
            .current
            .public_key_set()
            .master_public_key()
            .encode()
    );
    assert_eq!(verified.public.threshold(), run.fixture.ceremony.threshold());
    assert_eq!(verified.dealers.len(), usize::from(run.fixture.old_t()));
    for j in receivers {
        let (candidate, output) = run.outcomes[j].as_ref().unwrap();
        assert_eq!(view(output), view(&verified), "receiver {j}");
        assert_eq!(candidate.index(), idx(*j));
        assert_eq!(candidate.transcript_hash(), verified.transcript_hash);
        assert_eq!(
            G2::generator().mul(&candidate.scalar).encode(),
            verified.public.public_share(idx(*j)).unwrap(),
            "candidate {j} matches its public share"
        );
    }
    verified
}

/// Every listed receiver and the verifier refuse with the same typed error.
pub(crate) fn refused(run: &Run, receivers: &[u16], error: Error) {
    assert_eq!(run.verify().err(), Some(error.clone()));
    for j in receivers {
        assert_eq!(run.outcomes[j].as_ref().err(), Some(&error), "receiver {j}");
    }
}

/// The successor certificate built from the agreed output, and every
/// receiver's candidate bound to it.
pub(crate) struct Next {
    pub(crate) previous: Fixture,
    pub(crate) cert: VerifiedCertificate,
    pub(crate) shares: BTreeMap<u16, KeyShare>,
}

pub(crate) fn install(run: Run, output: &ReshareOutput) -> Next {
    let Run {
        fixture, outcomes, ..
    } = run;
    let body = CertificateBody::successor(
        &fixture.current,
        &fixture.ceremony,
        &output.public,
        &output.transcript_hash,
    )
    .unwrap();
    let cert = verify_successor(
        &fixture.current,
        &crate::cert::tests::sign(body, &fixture.signers),
        &fixture.signers,
    )
    .unwrap();
    let shares = outcomes
        .into_iter()
        .map(|(j, outcome)| {
            let share = KeyShare::bind(outcome.unwrap().0, &cert).unwrap();
            assert_eq!(share.index(), idx(j));
            (j, share)
        })
        .collect();
    Next {
        previous: fixture,
        cert,
        shares,
    }
}

/// Wrap a fixed data key to `path` under the certificate's master key.
pub(crate) fn wrapped(cert: &VerifiedCertificate, path: &str, seed: u8) -> ([u8; 32], IbeCiphertext) {
    let context = cert.key_context();
    let data = [seed; 32];
    let ct = wrap_key(
        cert.public_key_set().master_public_key(),
        &identity(&context, path),
        &DataKey::new(data),
        &mut ChaCha20Rng::from_seed([seed; 32]),
    )
    .unwrap();
    (data, ct)
}

/// Every t-subset of the shares derives the key and unwraps `ct`; t−1 shares
/// return `NotEnoughShares`. Returns the number of subsets exercised.
pub(crate) fn unwraps_through_every_subset(
    cert: &VerifiedCertificate,
    shares: &BTreeMap<u16, KeyShare>,
    path: &str,
    data: &[u8; 32],
    ct: &IbeCiphertext,
    seed: u8,
) -> usize {
    let context = cert.key_context();
    let t = usize::from(context.threshold().t());
    let mut rng = ChaCha20Rng::from_seed([seed ^ 0x5a; 32]);
    let tsk = TransportSecretKey::generate(&mut rng);
    let req = DecryptRequest::new(&context, identity(&context, path), tsk.public_key()).unwrap();
    let auth = authorize(req.clone());
    let issued: Vec<EncryptedKeyShare> = shares
        .values()
        .map(|s| issue_share(s, &auth, &mut rng).unwrap())
        .collect();
    for share in &issued {
        verify_share(cert.public_key_set(), &req, share).unwrap();
    }
    let expected = DataKey::new(*data);
    let mut subsets = 0;
    for mask in 0u32..(1u32 << issued.len()) {
        if mask.count_ones() as usize != t {
            continue;
        }
        let selected: Vec<EncryptedKeyShare> = issued
            .iter()
            .enumerate()
            .filter(|(k, _)| mask & (1u32 << k) != 0)
            .map(|(_, s)| s.clone())
            .collect();
        let encrypted = combine(cert.public_key_set(), &req, &selected).unwrap();
        let key = decrypt_derived_key(&encrypted, &tsk, cert.public_key_set(), &req).unwrap();
        assert_eq!(
            unwrap_key(&key, req.identity(), ct).unwrap().as_bytes(),
            expected.as_bytes()
        );
        subsets += 1;
    }
    assert!(matches!(
        combine(cert.public_key_set(), &req, &issued[..t - 1]),
        Err(CombineError::NotEnoughShares)
    ));
    subsets
}

/// Every t′-subset of the new public shares interpolates to the master key.
pub(crate) fn public_shares_interpolate_to_mpk(public: &PublicMaterial) {
    let t = public.threshold().t();
    let n = public.threshold().n();
    let mpk = public.master_public_key().encode();
    for mask in 0u32..(1u32 << n) {
        if mask.count_ones() != u32::from(t) {
            continue;
        }
        let subset: Vec<MemberIndex> = (1..=n)
            .filter(|j| mask & (1u32 << (j - 1)) != 0)
            .map(idx)
            .collect();
        let sum = subset.iter().fold(G2::identity(), |acc, j| {
            let lambda = crate::poly::lagrange(*j, subset.iter().copied()).unwrap();
            let share = G2::decode(&public.public_share(*j).unwrap(), false).unwrap();
            acc.add(&share.mul(&lambda))
        });
        assert_eq!(sum.encode(), mpk, "{subset:?}");
    }
}

// ----------------------------------------------------------------- payloads

pub(crate) fn complaints(dealers: &[u16]) -> Vec<u8> {
    ReshareComplaints {
        dealers: dealers.iter().map(|i| idx(*i)).collect(),
    }
    .encode()
}

pub(crate) fn answer(recipient: u16, value: u64) -> Vec<u8> {
    ReshareAnswers {
        answers: vec![(idx(recipient), Scalar::from_u64(value))],
    }
    .encode()
}

/// Re-seal one recipient's entry of a dealer's R1 with a canonical wrong value.
/// The commitments are unchanged, so the dealer's own state can still answer.
pub(crate) fn bad_dealing(out: &mut Outbox, dealer: u16, recipient: u16) -> Vec<u8> {
    let mut deal = ReshareDeal::decode(&out.payload(dealer)).unwrap();
    let public = CeremonyHpkePublicKey::decode(
        &out.ceremony().recipients()[usize::from(recipient - 1)].hpke_public_key,
    )
    .unwrap();
    let context = DealingContext {
        ceremony_digest: out.ceremony().digest(),
        round: 1,
        sender: idx(dealer),
        recipient: idx(recipient),
        commitment_hash: commitment_hash(&deal.commitments),
    };
    let mut plaintext = [0u8; 32];
    plaintext[31] = 5;
    let sealed = seal_dealing(&public, &context, &plaintext, out.rng()).unwrap();
    deal.dealings
        .iter_mut()
        .find(|(j, _)| j.get() == recipient)
        .unwrap()
        .1 = sealed;
    deal.encode()
}

/// Open a dealer's R1 entry with the recipient's regenerated key.
pub(crate) fn opened(fixture: &Fixture, deal: &[u8], dealer: u16, recipient: u16) -> Scalar {
    let deal = ReshareDeal::decode(deal).unwrap();
    let context = DealingContext {
        ceremony_digest: fixture.ceremony.digest(),
        round: 1,
        sender: idx(dealer),
        recipient: idx(recipient),
        commitment_hash: commitment_hash(&deal.commitments),
    };
    let sealed = &deal
        .dealings
        .iter()
        .find(|(j, _)| j.get() == recipient)
        .unwrap()
        .1;
    let plaintext = open_dealing(&fixture.secret(recipient), &context, sealed).unwrap();
    assert_eq!(plaintext.len(), 32);
    Scalar::from_bytes(&plaintext[..]).unwrap()
}

fn r2_dealers(run: &Run, recipient: u16) -> Vec<MemberIndex> {
    let message = run.transcript.rounds[1]
        .messages
        .iter()
        .find(|m| sender(m) == (Recipients as u8, recipient))
        .unwrap();
    ReshareComplaints::decode(&message.bytes[41..])
        .unwrap()
        .dealers
}

struct CountingRng {
    inner: ChaCha20Rng,
    draws: usize,
}
impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.draws += 1;
        self.inner.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.draws += 1;
        self.inner.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.draws += 1;
        self.inner.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.draws += 1;
        self.inner.try_fill_bytes(dest)
    }
}
impl CryptoRng for CountingRng {}

fn counting() -> CountingRng {
    CountingRng {
        inner: ChaCha20Rng::from_seed([0x78; 32]),
        draws: 0,
    }
}

fn close_for<M: Decode>(
    f: &Fixture,
    ceremony: &AuthorizedCeremony,
    round: u8,
    previous: &TranscriptHash,
    messages: &[SignedStatement],
) -> Result<ClosedRound<M>, Error> {
    let bytes = round_closure_body(ceremony, round, previous, messages)?;
    let closure = SignedStatement {
        signature: f.signers.sign(
            &f.signers.anchor().expected_owner,
            &round_closure_preimage(&bytes)?,
        ),
        bytes,
    };
    ClosedRound::<M>::verify(ceremony, round, previous, &closure, messages, &f.signers)
}

fn excluded(entries: &[(u16, ExcludeReason)]) -> BTreeMap<MemberIndex, ExcludeReason> {
    entries.iter().map(|(i, r)| (idx(*i), *r)).collect()
}

fn dealers(list: &[u16]) -> Vec<MemberIndex> {
    list.iter().map(|i| idx(*i)).collect()
}

const EMPTY_ANSWERS: [u8; 3] = [1, 0, 0];

// --------------------------------------------------- completion and handoff

#[test]
fn genuine_2of3_to_3of4_preserves_the_master_key_and_binds_every_candidate() {
    let run = honest(Reshare, 3, 4, 0x81);
    let output = agreed(&run, &[1, 2, 3, 4]);
    assert_eq!(output.dealers, dealers(&[1, 2]));
    assert!(output.excluded.is_empty());
    assert_eq!(run.transcript.rounds.len(), 3);
    assert_eq!(output.public.threshold(), Threshold::new(3, 4).unwrap());
    assert_eq!(output.public.commitments().len(), 3);
    for answers in run.answers.values() {
        assert_eq!(answers.as_ref().unwrap().as_slice(), &EMPTY_ANSWERS);
    }
    public_shares_interpolate_to_mpk(&output.public);
    // 3-of-4 is reachable by redistribution although genesis refuses it.
    assert_eq!(
        Threshold::new(3, 4).unwrap().check_genesis_budget(),
        Err(Error::UnsupportedFaultBudget)
    );
    let (data, ct) = wrapped(&run.fixture.current, "records/reshare", 0x81);
    let next = install(run, &output);
    assert_eq!(next.cert.key_context().epoch().get(), 1);
    assert_eq!(
        unwraps_through_every_subset(&next.cert, &next.shares, "records/reshare", &data, &ct, 0x82),
        4
    );
}

#[test]
fn dkg_genesis_reshare_chain_keeps_the_master_key_through_refresh() {
    let dkg = crate::dkg_relay::honest(2, 3, 0x83);
    let genesis_output = crate::dkg_relay::agreed(&dkg, &[1, 2, 3]);
    let crate::dkg_relay::Run {
        fixture: dkg_fixture,
        outcomes,
        ..
    } = dkg;
    let anchor = dkg_fixture.signers.anchor();
    let body = CertificateBody::genesis(
        &anchor,
        &dkg_fixture.ceremony,
        &genesis_output.public,
        &genesis_output.transcript_hash,
    )
    .unwrap();
    let genesis = verify_certificate(
        &anchor,
        &crate::cert::tests::sign(body, &dkg_fixture.signers),
        &dkg_fixture.signers,
    )
    .unwrap();
    let mut held: BTreeMap<u16, KeyShare> = outcomes
        .into_iter()
        .map(|(i, o)| (i, KeyShare::bind(o.unwrap().0, &genesis).unwrap()))
        .collect();
    let mpk = genesis.public_key_set().master_public_key().encode();
    let (data, ct) = wrapped(&genesis, "records/chain", 0x84);
    assert_eq!(
        unwraps_through_every_subset(&genesis, &held, "records/chain", &data, &ct, 0x84),
        3
    );
    let mut current = genesis;
    let steps = [
        (Reshare, 3u16, 4u16, 0x85u8, 4usize),
        (Reshare, 2, 3, 0x86, 3),
        (Refresh, 2, 3, 0x87, 3),
    ];
    for (kind, t, n, seed, subsets) in steps {
        let epoch = current.key_context().epoch().get();
        let dids: Vec<u8> = (1..=n as u8).collect();
        let f = fixture_on(current, held.into_values(), kind, t, n, seed, &dids);
        let run = run_with(f, |_| {});
        let all: Vec<u16> = (1..=n).collect();
        let output = agreed(&run, &all);
        assert_eq!(output.public.master_public_key().encode(), mpk, "{kind:?}");
        public_shares_interpolate_to_mpk(&output.public);
        let next = install(run, &output);
        assert_eq!(next.cert.key_context().epoch().get(), epoch + 1);
        assert_eq!(next.cert.key_context().rekey().get(), 0);
        assert_eq!(
            next.cert.key_context().threshold(),
            Threshold::new(t, n).unwrap()
        );
        assert_eq!(
            unwraps_through_every_subset(&next.cert, &next.shares, "records/chain", &data, &ct, seed),
            subsets
        );
        current = next.cert;
        held = next.shares;
    }
}

#[test]
fn old_shares_stay_in_their_own_context_after_redistribution() {
    let run = honest(Reshare, 2, 3, 0x88);
    let output = agreed(&run, &[1, 2, 3]);
    let transcript = output.transcript_hash;
    let next = install(run, &output);
    let old = &next.previous;
    let old_context = old.current.key_context();
    let new_context = next.cert.key_context();
    assert_ne!(old_context.digest(), new_context.digest());
    let mut rng = ChaCha20Rng::from_seed([0x88; 32]);
    let tsk = TransportSecretKey::generate(&mut rng);
    let old_req = DecryptRequest::new(
        &old_context,
        identity(&old_context, "records/split"),
        tsk.public_key(),
    )
    .unwrap();
    let new_req = DecryptRequest::new(
        &new_context,
        identity(&new_context, "records/split"),
        tsk.public_key(),
    )
    .unwrap();
    let old_issued = issue_share(&old.shares[&1], &authorize(old_req.clone()), &mut rng).unwrap();
    let new_issued: Vec<EncryptedKeyShare> = next
        .shares
        .values()
        .map(|s| issue_share(s, &authorize(new_req.clone()), &mut rng).unwrap())
        .collect();
    assert!(matches!(
        issue_share(&old.shares[&1], &authorize(new_req.clone()), &mut rng),
        Err(Error::ContextMismatch)
    ));
    assert_eq!(
        verify_share(next.cert.public_key_set(), &new_req, &old_issued),
        Err(ShareError::ContextMismatch)
    );
    assert_eq!(
        verify_share(next.cert.public_key_set(), &old_req, &old_issued),
        Err(ShareError::ContextMismatch)
    );
    assert!(matches!(
        combine(
            next.cert.public_key_set(),
            &new_req,
            &[new_issued[0].clone(), old_issued.clone()]
        ),
        Err(CombineError::MixedContexts)
    ));
    assert!(matches!(
        combine(
            old.current.public_key_set(),
            &old_req,
            &[old_issued.clone(), new_issued[1].clone()]
        ),
        Err(CombineError::MixedContexts)
    ));
    // The old scalar is not a candidate share for the new certificate.
    let old_scalar = Scalar::from_bytes(&old.shares[&1].scalar.to_bytes()).unwrap();
    assert!(matches!(
        KeyShare::bind(
            CandidateShare::new(transcript, idx(1), old_scalar),
            &next.cert
        ),
        Err(Error::CandidateMismatch)
    ));
    // Each epoch still derives under its own certificate; nothing here erases
    // the old shares.
    let (data, ct) = wrapped(&old.current, "records/split", 0x89);
    assert_eq!(
        unwraps_through_every_subset(&old.current, &old.shares, "records/split", &data, &ct, 0x8a),
        3
    );
    assert_eq!(
        unwraps_through_every_subset(&next.cert, &next.shares, "records/split", &data, &ct, 0x8b),
        3
    );
}

#[test]
fn fewer_than_t_valid_dealers_abort_everywhere_and_the_old_epoch_stays_usable() {
    let run = run(Reshare, 3, 4, 0x8c, |out| {
        if out.round() == 1 {
            out.remove(2);
            out.remove(3);
        }
    });
    refused(&run, &[1, 2, 3, 4], Error::InsufficientQualified);
    let (data, ct) = wrapped(&run.fixture.current, "records/abort", 0x8c);
    assert_eq!(
        unwraps_through_every_subset(
            &run.fixture.current,
            &run.fixture.shares,
            "records/abort",
            &data,
            &ct,
            0x8d
        ),
        3
    );
}

#[test]
fn within_the_secrecy_budget_but_below_t_valid_dealers_refuses_and_keeps_the_old_epoch() {
    // Old 3-of-4 (reached by redistribution): t−1 = 2 faulty dealers may
    // withhold R1 within the secrecy budget, leaving 2 < t = 3 dealers.
    let first = honest(Reshare, 3, 4, 0x8e);
    let output = agreed(&first, &[1, 2, 3, 4]);
    let next = install(first, &output);
    let f = fixture_on(next.cert, next.shares.into_values(), Reshare, 2, 3, 0x8f, &[1, 2, 3]);
    let run = run_with(f, |out| {
        if out.round() == 1 {
            out.remove(3);
            out.remove(4);
        }
    });
    refused(&run, &[1, 2, 3], Error::InsufficientQualified);
    let (data, ct) = wrapped(&run.fixture.current, "records/liveness", 0x8f);
    assert_eq!(
        unwraps_through_every_subset(
            &run.fixture.current,
            &run.fixture.shares,
            "records/liveness",
            &data,
            &ct,
            0x90
        ),
        4
    );
}

#[test]
fn a_member_of_both_cohorts_signs_distinct_roles() {
    // Old member 1 (did 1) is new member 3; new members 1, 2 and 4 are new nodes.
    let (current, shares) = dealer_genesis(2, 3);
    let f = fixture_on(current, shares, Reshare, 2, 4, 0x91, &[4, 5, 1, 6]);
    assert_eq!(f.did(Current, 1), f.did(Recipients, 3));
    assert_ne!(f.did(Current, 1), f.did(Recipients, 1));
    let mut r2 = Vec::new();
    let run = run_with(f, |out| {
        if out.round() == 2 {
            r2 = out.messages.clone();
        }
    });
    let output = agreed(&run, &[1, 2, 3, 4]);
    assert_eq!(output.dealers, dealers(&[1, 2]));
    let f = &run.fixture;
    let own = r2
        .iter()
        .find(|m| sender(m) == (Recipients as u8, 3))
        .unwrap();
    f.signers
        .verify(
            &Signers::did(1),
            &ceremony_message_preimage(&own.bytes).unwrap(),
            &own.signature,
        )
        .unwrap();
    // did 1 cannot speak for recipient coordinate 1.
    let h0 = reshare_initial_transcript(&f.ceremony);
    let bytes =
        ceremony_message_body(&f.ceremony, 1, Recipients, idx(1), &EMPTY_ANSWERS).unwrap();
    let forged = SignedStatement {
        signature: f
            .signers
            .sign(&Signers::did(1), &ceremony_message_preimage(&bytes).unwrap()),
        bytes,
    };
    assert!(matches!(
        close_for::<ReshareDeal>(f, &f.ceremony, 1, &h0, &[forged]),
        Err(Error::InvalidSignature)
    ));
}

// ------------------------------------------------------- complaints and R3

#[test]
fn t_prime_complainers_exclude_the_dealer_and_it_publishes_no_answer() {
    let run = run(Reshare, 2, 3, 0x92, |out| match out.round() {
        1 => out.order(&[3, 1, 2]),
        2 => {
            out.replace(1, &complaints(&[3]));
            out.replace(2, &complaints(&[3]));
        }
        _ => {}
    });
    assert_eq!(run.answers[&3].as_ref().unwrap().as_slice(), &EMPTY_ANSWERS);
    let from3: Vec<_> = run.transcript.rounds[2]
        .messages
        .iter()
        .filter(|m| sender(m) == (Current as u8, 3))
        .collect();
    assert_eq!(from3.len(), 1);
    assert_eq!(&from3[0].bytes[41..], &EMPTY_ANSWERS);
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(3, ExcludeReason::Complaints)]));
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn false_complaint_is_refuted_by_a_valid_answer() {
    let mut deal = Vec::new();
    let run = run(Reshare, 2, 3, 0x93, |out| match out.round() {
        1 => deal = out.payload(1),
        2 => out.replace(3, &complaints(&[1])),
        _ => {}
    });
    let published = ReshareAnswers::decode(run.answers[&1].as_ref().unwrap()).unwrap();
    assert_eq!(published.answers.len(), 1);
    assert_eq!(published.answers[0].0, idx(3));
    assert_eq!(
        published.answers[0].1.to_bytes(),
        opened(&run.fixture, &deal, 1, 3).to_bytes()
    );
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn one_recipient_bad_value_is_replaced_by_a_valid_answer() {
    let run = run(Reshare, 2, 3, 0x94, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
        2 => assert_eq!(
            ReshareComplaints::decode(&out.payload(2)).unwrap().dealers,
            dealers(&[1])
        ),
        _ => {}
    });
    // Receiver 2's candidate matches its public share only through the answer.
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
    let published = ReshareAnswers::decode(run.answers[&1].as_ref().unwrap()).unwrap();
    assert_eq!(
        published.answers.iter().map(|(j, _)| *j).collect::<Vec<_>>(),
        dealers(&[2])
    );
}

#[test]
fn invalid_answer_excludes_the_dealer_and_the_next_dealer_is_selected() {
    let run = run(Reshare, 2, 3, 0x95, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
        3 => out.replace(1, &answer(2, 5)),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::InvalidAnswer)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

#[test]
fn missing_r3_excludes_only_with_required_answers() {
    let run = run(Reshare, 2, 3, 0x96, |out| match out.round() {
        2 => out.replace(3, &complaints(&[1])),
        3 => {
            out.remove(1);
            out.remove(2);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::MissingAnswer)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

#[test]
fn malformed_r3_excludes_only_with_required_answers() {
    let run = run(Reshare, 2, 3, 0x97, |out| match out.round() {
        2 => out.replace(3, &complaints(&[1])),
        3 => {
            out.replace(1, &[1, 0]);
            out.replace(2, &[1, 0]);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::MissingAnswer)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

#[test]
fn invalid_unsolicited_answer_excludes_its_dealer() {
    let run = run(Reshare, 2, 3, 0x98, |out| {
        if out.round() == 3 {
            out.replace(2, &answer(1, 5));
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(2, ExcludeReason::InvalidAnswer)]));
    assert_eq!(output.dealers, dealers(&[1, 3]));
}

#[test]
fn valid_unsolicited_answer_is_ignored() {
    let mut deal = Vec::new();
    let run = run(Reshare, 2, 3, 0x99, |out| match out.round() {
        1 => deal = out.payload(2),
        3 => {
            let value = opened(out.fixture(), &deal, 2, 1);
            let unsolicited = ReshareAnswers {
                answers: vec![(idx(1), value)],
            };
            out.replace(2, &unsolicited.encode());
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn conflicting_r3_excludes_its_dealer() {
    let run = run(Reshare, 2, 3, 0x9a, |out| {
        if out.round() == 3 {
            out.push(2, &[1, 0, 0, 0]);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.excluded,
        excluded(&[(2, ExcludeReason::Equivocated { round: 3 })])
    );
    assert_eq!(output.dealers, dealers(&[1, 3]));
}

#[test]
fn r3_naming_a_recipient_outside_the_new_cohort_is_malformed() {
    let run = run(Reshare, 2, 3, 0x9b, |out| match out.round() {
        2 => out.replace(3, &complaints(&[1])),
        3 => {
            let mut published = ReshareAnswers::decode(&out.payload(1)).unwrap();
            published.answers.push((idx(4), Scalar::from_u64(1)));
            out.replace(1, &published.encode());
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::MissingAnswer)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

#[test]
fn malformed_r2_supplies_no_complaints() {
    let run = run(Reshare, 2, 3, 0x9c, |out| match out.round() {
        2 => {
            let mut malformed = complaints(&[1]);
            malformed.push(0);
            out.replace(3, &malformed);
        }
        3 => out.remove(1),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn conflicting_r2_supplies_no_complaints_and_does_not_affect_the_same_nodes_dealer_role() {
    // Recipient 1 is the same node (did 1) as old dealer 1.
    let run = run(Reshare, 2, 3, 0x9d, |out| match out.round() {
        2 => {
            out.replace(1, &complaints(&[2]));
            out.push(1, &complaints(&[2, 3]));
        }
        3 => {
            out.remove(2);
            out.remove(3);
        }
        _ => {}
    });
    assert_eq!(run.answers[&2].as_ref().unwrap().as_slice(), &EMPTY_ANSWERS);
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn duplicate_complaints_count_once() {
    // t′ = 3: two distinct complainers, one retransmitting, stay below t′.
    let run = run(Reshare, 3, 5, 0x9e, |out| {
        if out.round() == 2 {
            out.replace(4, &complaints(&[1]));
            out.replace(5, &complaints(&[1]));
            out.duplicate(4);
            out.duplicate(4);
        }
    });
    let published = ReshareAnswers::decode(run.answers[&1].as_ref().unwrap()).unwrap();
    assert_eq!(
        published.answers.iter().map(|(j, _)| *j).collect::<Vec<_>>(),
        dealers(&[4, 5])
    );
    let output = agreed(&run, &[1, 2, 3, 4, 5]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn r2_naming_a_dealer_outside_the_old_cohort_supplies_no_complaints() {
    let run = run(Reshare, 2, 3, 0x9f, |out| match out.round() {
        2 => out.replace(3, &complaints(&[1, 4])),
        3 => out.remove(1),
        _ => {}
    });
    assert_eq!(run.answers[&1].as_ref().unwrap().as_slice(), &EMPTY_ANSWERS);
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

#[test]
fn relay_omitted_complaint_fails_only_the_affected_receiver() {
    // Failure scenario outside the trusted-relay liveness model.
    let run = run(Reshare, 2, 3, 0xa0, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
        2 => out.remove(2),
        _ => {}
    });
    assert!(matches!(
        run.outcomes[&2],
        Err(Error::LocalShareUnavailable)
    ));
    let output = agreed(&run, &[1, 3]);
    assert_eq!(output.dealers, dealers(&[1, 2]));
}

// --------------------------------------------------------------- R1 checks

type Mutation = fn(&mut Outbox);

#[test]
fn r1_public_checks_exclude_malformed_dealings_and_keep_the_master_key() {
    let cases: [(&str, Mutation); 6] = [
        ("t′+1 coefficients", |out| {
            let mut deal = ReshareDeal::decode(&out.payload(1)).unwrap();
            deal.commitments.push(G2::generator());
            out.replace(1, &deal.encode());
        }),
        ("t′−1 coefficients", |out| {
            let mut deal = ReshareDeal::decode(&out.payload(1)).unwrap();
            deal.commitments.pop();
            out.replace(1, &deal.encode());
        }),
        ("identity top coefficient", |out| {
            let mut deal = ReshareDeal::decode(&out.payload(1)).unwrap();
            let top = deal.commitments.len() - 1;
            deal.commitments[top] = G2::identity();
            out.replace(1, &deal.encode());
        }),
        ("constant is not the old public share", |out| {
            let mut deal = ReshareDeal::decode(&out.payload(1)).unwrap();
            deal.commitments[0] = G2::generator().mul(&Scalar::from_u64(5));
            out.replace(1, &deal.encode());
        }),
        ("recipient set is not 1..=n′", |out| {
            let mut deal = ReshareDeal::decode(&out.payload(1)).unwrap();
            deal.dealings.pop();
            out.replace(1, &deal.encode());
        }),
        ("undecodable", |out| out.replace(1, &[1, 0])),
    ];
    for (k, (name, mutate)) in cases.iter().enumerate() {
        let run = run(Reshare, 2, 3, 0xa1 + k as u8, |out| {
            if out.round() == 1 {
                mutate(out);
            }
        });
        // `agreed` also checks that the master key is the current one.
        let output = agreed(&run, &[1, 2, 3]);
        assert_eq!(
            output.excluded,
            excluded(&[(1, ExcludeReason::MalformedDeal)]),
            "{name}"
        );
        assert_eq!(output.dealers, dealers(&[2, 3]), "{name}");
    }
}

#[test]
fn missing_and_equivocated_r1_exclude() {
    let missing = run(Reshare, 2, 3, 0xa7, |out| {
        if out.round() == 1 {
            out.remove(1);
        }
    });
    let output = agreed(&missing, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::MissingDeal)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));

    let equivocated = run(Reshare, 2, 3, 0xa8, |out| {
        if out.round() == 1 {
            let second = bad_dealing(out, 1, 3);
            out.push(1, &second);
        }
    });
    let output = agreed(&equivocated, &[1, 2, 3]);
    assert_eq!(
        output.excluded,
        excluded(&[(1, ExcludeReason::Equivocated { round: 1 })])
    );
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

#[test]
fn dealers_are_the_first_t_in_closed_round_order() {
    let reordered = run(Reshare, 2, 3, 0xa9, |out| {
        if out.round() == 1 {
            out.order(&[3, 1, 2]);
        }
    });
    assert_eq!(agreed(&reordered, &[1, 2, 3]).dealers, dealers(&[3, 1]));

    // A dealer's position is that of its first message.
    let repeated = run(Reshare, 2, 3, 0xaa, |out| {
        if out.round() == 1 {
            out.order(&[3, 1, 2]);
            let copy = out.messages[2].clone();
            out.messages.insert(0, copy);
        }
    });
    assert_eq!(agreed(&repeated, &[1, 2, 3]).dealers, dealers(&[2, 3]));

    // An excluded dealer's place passes to the next eligible dealer.
    let skipped = run(Reshare, 2, 3, 0xab, |out| {
        if out.round() == 1 {
            out.order(&[3, 1, 2]);
            out.replace(3, &[1, 0]);
        }
    });
    let output = agreed(&skipped, &[1, 2, 3]);
    assert_eq!(output.dealers, dealers(&[1, 2]));
    assert_eq!(output.excluded, excluded(&[(3, ExcludeReason::MalformedDeal)]));
}

// --------------------------------------------------------- wrong cohorts

#[test]
fn wrong_cohort_r1_is_ignored_without_blame() {
    // Dealer 1's deal under the recipient role does not count; recipient 2
    // (the same node as dealer 2) sending an R1 under the recipient role does
    // not make dealer 2 equivocate.
    let run = run(Reshare, 2, 3, 0xac, |out| {
        if out.round() == 1 {
            let payload = out.payload(1);
            out.remove(1);
            out.push_as(Recipients, 1, &payload);
            out.push_as(Recipients, 2, &[1, 0]);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::MissingDeal)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

#[test]
fn wrong_cohort_r2_is_ignored_without_blame() {
    // Two old dealers' complaints under the dealer role would reach t′ = 2.
    let run = run(Reshare, 2, 3, 0xad, |out| match out.round() {
        1 => out.order(&[3, 1, 2]),
        2 => {
            out.push_as(Current, 1, &complaints(&[3]));
            out.push_as(Current, 2, &complaints(&[3]));
        }
        _ => {}
    });
    assert_eq!(run.answers[&3].as_ref().unwrap().as_slice(), &EMPTY_ANSWERS);
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.excluded.is_empty());
    assert_eq!(output.dealers, dealers(&[3, 1]));
}

#[test]
fn wrong_cohort_r3_is_ignored_without_blame() {
    let run = run(Reshare, 2, 3, 0xae, |out| match out.round() {
        2 => out.replace(3, &complaints(&[1])),
        3 => {
            // Dealer 1's required answer under the recipient role does not count.
            let genuine = out.payload(1);
            out.remove(1);
            out.push_as(Recipients, 1, &genuine);
            // An invalid answer under the recipient role does not blame dealer 2.
            out.push_as(Recipients, 2, &answer(1, 5));
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::MissingAnswer)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

// ------------------------------------------- authorization and state binding

#[test]
fn dealing_refuses_unauthorized_contexts_before_any_randomness() {
    let f = fixture(Reshare, 2, 3, 0xb0);
    let mut rng = counting();
    let share = &f.shares[&1];
    assert!(matches!(
        reshare_deal(&f.signers.genesis(), &f.current, share, &mut rng),
        Err(Error::InvalidCeremony)
    ));
    let (_, _, rekey) = crate::cert::tests::successor(
        &f.signers,
        &f.current,
        CeremonyKind::Rekey,
        Threshold::new(2, 3).unwrap(),
        12,
    );
    assert!(matches!(
        reshare_deal(&rekey, &f.current, share, &mut rng),
        Err(Error::InvalidCeremony)
    ));
    // The ceremony names a certificate other than the one supplied as current.
    let (newer, newer_shares) = newer_certificate(&f);
    assert!(matches!(
        reshare_deal(&f.ceremony, &newer, &newer_shares[0], &mut rng),
        Err(Error::ContextMismatch)
    ));
    // A share bound to another certificate.
    assert!(matches!(
        reshare_deal(&f.ceremony, &f.current, &newer_shares[0], &mut rng),
        Err(Error::ContextMismatch)
    ));
    // Refresh keeps t, n and the index→DID directory of the current certificate.
    for (t, n, dids) in [
        (2u16, 4u16, vec![1u8, 2, 3, 4]),
        (3, 3, vec![1, 2, 3]),
        (2, 3, vec![2, 1, 3]),
        (2, 3, vec![1, 2, 9]),
    ] {
        let body = statement_body(&f.current, Refresh, t, n, 0xb1, &dids);
        let refresh =
            AuthorizedCeremony::verify_for(&f.current, &f.signers.statement(&body), &f.signers)
                .unwrap();
        assert!(
            matches!(
                reshare_deal(&refresh, &f.current, share, &mut rng),
                Err(Error::InvalidCeremony)
            ),
            "{t}-of-{n} {dids:?}"
        );
    }
    assert_eq!(rng.draws, 0);
    let body = statement_body(&f.current, Refresh, 2, 3, 0xb1, &[1, 2, 3]);
    let refresh =
        AuthorizedCeremony::verify_for(&f.current, &f.signers.statement(&body), &f.signers)
            .unwrap();
    assert!(reshare_deal(&refresh, &f.current, share, &mut rng).is_ok());
    assert!(rng.draws > 0);
    let (state, message) = reshare_deal(&f.ceremony, &f.current, share, &mut rng).unwrap();
    assert_eq!(message.round(), 1);
    assert_eq!(format!("{state:?}"), "ReshareDealer([REDACTED])");
}

#[test]
fn receiver_start_checks_ceremony_index_and_recipient_key() {
    let f = fixture(Reshare, 2, 3, 0xb2);
    assert!(matches!(
        reshare_start_receiver(&f.ceremony, &f.current, idx(1), f.secret(2)),
        Err(Error::ContextMismatch)
    ));
    assert!(matches!(
        reshare_start_receiver(&f.ceremony, &f.current, idx(4), f.secret(1)),
        Err(Error::InvalidIndex)
    ));
    assert!(matches!(
        reshare_start_receiver(&f.signers.genesis(), &f.current, idx(1), f.secret(1)),
        Err(Error::InvalidCeremony)
    ));
    let (newer, _) = newer_certificate(&f);
    assert!(matches!(
        reshare_start_receiver(&f.ceremony, &newer, idx(1), f.secret(1)),
        Err(Error::ContextMismatch)
    ));
    let body = statement_body(&f.current, Refresh, 3, 3, 0xb2, &[1, 2, 3]);
    let refresh =
        AuthorizedCeremony::verify_for(&f.current, &f.signers.statement(&body), &f.signers)
            .unwrap();
    assert!(matches!(
        reshare_start_receiver(&refresh, &f.current, idx(1), f.secret(1)),
        Err(Error::InvalidCeremony)
    ));
    let state = reshare_start_receiver(&f.ceremony, &f.current, idx(1), f.secret(1)).unwrap();
    assert_eq!(format!("{state:?}"), "ReshareReceiving([REDACTED])");
}

#[test]
fn forged_statement_fields_fail_owner_authentication() {
    let f = fixture(Reshare, 3, 4, 0xb3);
    let body = statement_body(&f.current, Reshare, 3, 4, 0xb3, &[1, 2, 3, 4]);
    assert_eq!(body.encode(), f.statement.bytes);
    for mutation in 0..5 {
        let mut changed = body.clone();
        match mutation {
            0 => changed.recipients[3].hpke_public_key = [7; 32],
            1 => changed.recipients[3].node = Signers::did(9),
            2 => {
                changed.recipients[2].node = Signers::did(4);
                changed.recipients[3].node = Signers::did(3);
            }
            3 => changed.threshold = Threshold::new(2, 4).unwrap(),
            _ => changed.current = Some(CertDigest::new([9; 32])),
        }
        let forged = SignedStatement {
            bytes: changed.encode(),
            signature: f.statement.signature.clone(),
        };
        assert!(
            AuthorizedCeremony::verify_for(&f.current, &forged, &f.signers).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn transitions_refuse_other_ceremonies_rounds_and_histories() {
    let f = fixture(Reshare, 2, 3, 0xb4);
    // Same current certificate, another authorized ceremony.
    let other = fixture(Reshare, 2, 3, 0xb5);
    let h0 = reshare_initial_transcript(&f.ceremony);
    let deal = |f: &Fixture, i: u16| {
        let mut rng = f.member_rng(i);
        reshare_deal(&f.ceremony, &f.current, &f.shares[&i], &mut rng).unwrap()
    };
    let receiver =
        |j: u16| reshare_start_receiver(&f.ceremony, &f.current, idx(j), f.secret(j)).unwrap();
    let r1: Vec<_> = (1..=3).map(|i| f.sign(Current, i, &deal(&f, i).1)).collect();
    let closed1 = close_for::<ReshareDeal>(&f, &f.ceremony, 1, &h0, &r1).unwrap();
    let other_r1: Vec<_> = (1..=3)
        .map(|i| other.sign(Current, i, &deal(&other, i).1))
        .collect();
    let foreign = close_for::<ReshareDeal>(
        &other,
        &other.ceremony,
        1,
        &reshare_initial_transcript(&other.ceremony),
        &other_r1,
    )
    .unwrap();
    assert!(matches!(
        receiver(1).complain(&foreign),
        Err(Error::InvalidRound)
    ));
    assert!(close_for::<ReshareDeal>(&f, &f.ceremony, 1, &h0, &other_r1).is_err());
    let on_our_link = close_for::<ReshareDeal>(&other, &other.ceremony, 1, &h0, &other_r1).unwrap();
    assert!(matches!(
        receiver(1).complain(&on_our_link),
        Err(Error::InvalidRound)
    ));
    let rebased =
        close_for::<ReshareDeal>(&f, &f.ceremony, 1, &TranscriptHash::new([9; 32]), &r1).unwrap();
    assert!(matches!(
        receiver(1).complain(&rebased),
        Err(Error::InvalidRound)
    ));
    let dkg_link =
        close_for::<ReshareDeal>(&f, &f.ceremony, 1, &dkg_initial_transcript(&f.ceremony), &r1)
            .unwrap();
    assert!(matches!(
        receiver(1).complain(&dkg_link),
        Err(Error::InvalidRound)
    ));
    let wrong_round = close_for::<ReshareDeal>(&f, &f.ceremony, 3, &h0, &[]).unwrap();
    assert!(matches!(
        receiver(1).complain(&wrong_round),
        Err(Error::InvalidRound)
    ));

    let mut complained = BTreeMap::new();
    let mut r2 = Vec::new();
    for j in 1..=3u16 {
        let (state, message) = receiver(j).complain(&closed1).unwrap();
        r2.push(f.sign(Recipients, j, &message));
        complained.insert(j, state);
    }
    assert_eq!(
        format!("{:?}", complained[&1]),
        "ReshareComplained([REDACTED])"
    );
    let closed2 =
        close_for::<ReshareComplaints>(&f, &f.ceremony, 2, &closed1.transcript_hash(), &r2)
            .unwrap();
    let skipped2 = close_for::<ReshareComplaints>(&f, &f.ceremony, 2, &h0, &r2).unwrap();
    assert!(matches!(
        deal(&f, 1).0.answer(&closed1, &skipped2),
        Err(Error::InvalidRound)
    ));
    assert!(matches!(
        deal(&f, 1).0.answer(&foreign, &closed2),
        Err(Error::InvalidRound)
    ));
    assert!(matches!(
        deal(&f, 1).0.answer(&rebased, &closed2),
        Err(Error::InvalidRound)
    ));
    let r3: Vec<_> = (1..=3)
        .map(|i| f.sign(Current, i, &deal(&f, i).0.answer(&closed1, &closed2).unwrap()))
        .collect();
    let skipped3 =
        close_for::<ReshareAnswers>(&f, &f.ceremony, 3, &closed1.transcript_hash(), &r3).unwrap();
    let chained3 =
        close_for::<ReshareAnswers>(&f, &f.ceremony, 3, &closed2.transcript_hash(), &r3).unwrap();
    assert!(matches!(
        complained.remove(&1).unwrap().finish(&closed2, &skipped3),
        Err(Error::InvalidRound)
    ));
    assert!(matches!(
        complained.remove(&2).unwrap().finish(&skipped2, &chained3),
        Err(Error::InvalidRound)
    ));
    assert!(complained
        .remove(&3)
        .unwrap()
        .finish(&closed2, &chained3)
        .is_ok());
}

#[test]
fn retry_under_a_new_ceremony_cannot_reuse_an_earlier_dealing() {
    let earlier = fixture(Reshare, 2, 3, 0xb6);
    let mut rng = earlier.member_rng(1);
    let (_, message) =
        reshare_deal(&earlier.ceremony, &earlier.current, &earlier.shares[&1], &mut rng).unwrap();
    let earlier_payload = message.body()[41..].to_vec();
    let run = run(Reshare, 2, 3, 0xb7, |out| {
        if out.round() == 1 {
            out.replace(1, &earlier_payload);
        }
    });
    // The earlier dealing passes the public checks but opens for no recipient.
    for j in 1..=3 {
        assert_eq!(r2_dealers(&run, j), dealers(&[1]), "recipient {j}");
    }
    assert_eq!(run.answers[&1].as_ref().unwrap().as_slice(), &EMPTY_ANSWERS);
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.excluded, excluded(&[(1, ExcludeReason::Complaints)]));
    assert_eq!(output.dealers, dealers(&[2, 3]));
}

// ------------------------------------------------------- public verifier

#[test]
fn verifier_recomputes_from_authenticated_records_only() {
    let run = run(Reshare, 2, 3, 0xb8, |out| {
        if out.round() == 1 {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    let f = &run.fixture;
    let verify =
        |t: &ReshareTranscript| reshare_verify_transcript(&f.ceremony, &f.current, t, &f.signers);
    assert_eq!(verify(&run.transcript).unwrap().transcript_hash, output.transcript_hash);
    let mut tampered = run.transcript.clone();
    tampered.rounds[1].messages[0].signature[0] ^= 1;
    assert!(verify(&tampered).is_err());
    let mut swapped = run.transcript.clone();
    swapped.rounds.swap(1, 2);
    assert!(verify(&swapped).is_err());
    let mut missing = run.transcript.clone();
    missing.rounds.pop();
    assert_eq!(verify(&missing).err(), Some(Error::InvalidRound));
    let mut extra = run.transcript.clone();
    extra.rounds.push(run.transcript.rounds[2].clone());
    assert_eq!(verify(&extra).err(), Some(Error::InvalidRound));
    let other = fixture(Reshare, 2, 3, 0xb9);
    assert!(
        reshare_verify_transcript(&other.ceremony, &other.current, &run.transcript, &f.signers)
            .is_err()
    );
    let (newer, _) = newer_certificate(f);
    assert_eq!(
        reshare_verify_transcript(&f.ceremony, &newer, &run.transcript, &f.signers).err(),
        Some(Error::ContextMismatch)
    );
}

struct Refusing;
impl DidSignatureVerifier for Refusing {
    fn verify(&self, _: &Did, _: &[u8], _: &[u8]) -> Result<(), SignatureError> {
        panic!("size bound must precede signature verification")
    }
}

#[test]
fn transcript_bound_of_4_mib_precedes_verification() {
    let f = fixture(Reshare, 2, 3, 0xba);
    let record = |copies: usize| DkgRoundRecord {
        closure: SignedStatement {
            bytes: vec![0; 98],
            signature: vec![0; 64],
        },
        messages: vec![
            SignedStatement {
                bytes: vec![0; 65_536],
                signature: vec![0; 64],
            };
            copies
        ],
    };
    // 64 × (65 536 + 64) + 98 + 64 bytes exceeds 4 194 304.
    let over = ReshareTranscript {
        rounds: vec![record(64)],
    };
    assert_eq!(
        reshare_verify_transcript(&f.ceremony, &f.current, &over, &Refusing).err(),
        Some(Error::LimitExceeded)
    );
    let split = ReshareTranscript {
        rounds: vec![record(32), record(32)],
    };
    assert_eq!(
        reshare_verify_transcript(&f.ceremony, &f.current, &split, &Refusing).err(),
        Some(Error::LimitExceeded)
    );
    let under = ReshareTranscript {
        rounds: vec![record(63)],
    };
    let result = reshare_verify_transcript(&f.ceremony, &f.current, &under, &f.signers);
    assert!(result.is_err());
    assert_ne!(result.err(), Some(Error::LimitExceeded));
}

// --------------------------------------------- within-budget enumeration

/// Faulty old dealer model (R1/R3); `target` is an honest recipient.
fn misdeal(out: &mut Outbox, m: u16, behaviour: u8, target: u16) {
    let present = out.has(m);
    match (out.round(), behaviour) {
        (1, 1) => out.remove(m),
        (1, 2) if present => {
            let mut p = out.payload(m);
            p.pop();
            out.replace(m, &p);
        }
        // 3: bad value, honestly answered; 4: bad value, R3 withheld.
        (1, 3) | (1, 4) if present => {
            let forged = bad_dealing(out, m, target);
            out.replace(m, &forged);
        }
        (1, 5) if present => {
            let mut deal = ReshareDeal::decode(&out.payload(m)).unwrap();
            deal.commitments[0] = G2::generator();
            out.replace(m, &deal.encode());
        }
        (1, 6) if present => {
            let second = bad_dealing(out, m, target);
            out.push(m, &second);
        }
        (3, 4) => out.remove(m),
        (3, 7) => out.replace(m, &answer(target, 5)),
        _ => {}
    }
}
const DEALER_BEHAVIOURS: u8 = 8;

/// Faulty new recipient model (R2); `targets` are honest dealers.
fn miscomplain(out: &mut Outbox, m: u16, behaviour: u8, targets: &[u16]) {
    match (out.round(), behaviour) {
        (2, 1) => out.remove(m),
        (2, 2) => out.replace(m, &complaints(&targets[..1])),
        (2, 3) => out.replace(m, &complaints(targets)),
        (2, 4) => out.replace(m, &[1, 0]),
        (2, 5) => out.push(m, &complaints(targets)),
        _ => {}
    }
}
const RECIPIENT_BEHAVIOURS: u8 = 6;

const ENUMERATION_SEEDS: [u8; 2] = [0x01, 0x9d];

// Coverage: every behaviour assignment of the in-tree `misdeal`/`miscomplain`
// models for (a) old 2-of-3 → new 2-of-3 with faulty old dealer 3 and faulty
// recipient 3, under two seeds (2 × 8 × 6 = 96 ceremonies), and (b) old 3-of-5
// → new 3-of-4 with faulty old dealers 4, 5 (unordered behaviour pairs) and
// faulty recipient 4 in three behaviours (36 × 3 = 108 ceremonies). Faulty
// dealers are placed first in closed R1, so they are selected whenever they
// stay eligible. Every case keeps at least t valid old dealers; the
// below-t refusal is covered by its own tests above. Honest messages are
// always delivered; this is not a claim about arbitrary behaviour.

/// One completion run: honest receivers and the verifier agree, only faulty
/// dealers are excluded, D is the first t eligible dealers in closed order and
/// the master key is the current one (`agreed`).
fn within_budget_agreement(
    old: (u16, u16),
    new: (u16, u16),
    seed: u8,
    dealer_behaviours: &[u8],
    recipient_behaviour: u8,
) {
    let (old_t, old_n) = old;
    let (t, n) = new;
    let faulty_dealers: Vec<u16> = (old_n + 1 - dealer_behaviours.len() as u16..=old_n).collect();
    let order: Vec<u16> = faulty_dealers
        .iter()
        .copied()
        .chain(1..=old_n - dealer_behaviours.len() as u16)
        .collect();
    assert!(old_n - faulty_dealers.len() as u16 >= old_t);
    let (current, shares) = dealer_genesis(old_t, old_n);
    let dids: Vec<u8> = (1..=n as u8).collect();
    let f = fixture_on(current, shares, Reshare, t, n, seed, &dids);
    let run = run_with(f, |out| {
        if out.round() == 1 {
            out.order(&order);
        }
        for (m, behaviour) in faulty_dealers.iter().zip(dealer_behaviours) {
            misdeal(out, *m, *behaviour, 1);
        }
        miscomplain(out, n, recipient_behaviour, &[1, 2]);
    });
    let honest_receivers: Vec<u16> = (1..n).collect();
    let label = format!("{dealer_behaviours:?}/{recipient_behaviour}");
    let output = agreed(&run, &honest_receivers);
    assert!(
        output
            .excluded
            .keys()
            .all(|i| faulty_dealers.contains(&i.get())),
        "{label}"
    );
    let expected: Vec<MemberIndex> = order
        .iter()
        .map(|i| idx(*i))
        .filter(|i| !output.excluded.contains_key(i))
        .take(usize::from(old_t))
        .collect();
    assert_eq!(output.dealers, expected, "{label}");
}

#[test]
fn every_within_budget_fault_pattern_with_t_valid_dealers_agrees_2of3() {
    for seed in ENUMERATION_SEEDS {
        for dealer in 0..DEALER_BEHAVIOURS {
            for recipient in 0..RECIPIENT_BEHAVIOURS {
                within_budget_agreement((2, 3), (2, 3), seed, &[dealer], recipient);
            }
        }
    }
}

#[test]
fn every_within_budget_fault_pattern_with_t_valid_dealers_agrees_3of5_to_3of4() {
    for first in 0..DEALER_BEHAVIOURS {
        for second in first..DEALER_BEHAVIOURS {
            for recipient in [0, 3, 5] {
                within_budget_agreement((3, 5), (3, 4), 0x5e, &[first, second], recipient);
            }
        }
    }
}

// ------------------------------------------------------------------ vectors

fn hex_statement(s: &SignedStatement) -> Value {
    json!({"body": hex::encode(&s.bytes), "signature": hex::encode(&s.signature)})
}

fn reason(r: &ExcludeReason) -> Value {
    match r {
        ExcludeReason::MissingDeal => json!({"reason": "MissingDeal"}),
        ExcludeReason::MalformedDeal => json!({"reason": "MalformedDeal"}),
        ExcludeReason::Equivocated { round } => json!({"reason": "Equivocated", "round": round}),
        ExcludeReason::Complaints => json!({"reason": "Complaints"}),
        ExcludeReason::MissingAnswer => json!({"reason": "MissingAnswer"}),
        ExcludeReason::InvalidAnswer => json!({"reason": "InvalidAnswer"}),
    }
}

fn output_json(o: &ReshareOutput) -> Value {
    let n = o.public.threshold().n();
    json!({
        "dealers": o.dealers.iter().map(|i| i.get()).collect::<Vec<_>>(),
        "excluded": o.excluded.iter().map(|(i, r)| {
            let mut entry = reason(r);
            entry["member"] = json!(i.get());
            entry
        }).collect::<Vec<_>>(),
        "threshold": o.public.threshold().t(),
        "members": n,
        "mpk": hex::encode(o.public.master_public_key().encode()),
        "commitments": o.public.commitments().map(hex::encode).collect::<Vec<_>>(),
        "public_shares": (1..=n).map(|j| json!({
            "member": j,
            "point": hex::encode(o.public.public_share(idx(j)).unwrap()),
        })).collect::<Vec<_>>(),
        "transcript_hash": hex::encode(o.transcript_hash.as_bytes()),
    })
}

fn case(name: &str, description: &str, run: &Run) -> Value {
    let f = &run.fixture;
    let current = f.current.body();
    let inputs = json!({
        "current_certificate": {
            "body": hex::encode(current.encode()),
            "owner_signature": hex::encode(f.signers.sign(&f.current.anchor().expected_owner, &current.owner_statement())),
        },
        "ceremony": hex_statement(&f.statement),
        "ceremony_digest": hex::encode(f.ceremony.digest()),
        "initial_transcript": hex::encode(reshare_initial_transcript(&f.ceremony).as_bytes()),
        "rounds": run.transcript.rounds.iter().map(|r| json!({
            "closure": hex_statement(&r.closure),
            "messages": r.messages.iter().map(hex_statement).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    });
    match run.verify() {
        Ok(output) => {
            json!({"name": name, "description": description, "operation": "reshare_verify_transcript", "inputs": inputs, "outputs": output_json(&output)})
        }
        Err(error) => {
            json!({"name": name, "description": description, "operation": "reshare_verify_transcript", "inputs": inputs, "error": format!("{error:?}")})
        }
    }
}

fn vectors() -> Value {
    let honest_run = honest(Reshare, 3, 4, 0xc1);
    let answered = run(Refresh, 2, 3, 0xc2, |out| {
        if out.round() == 1 {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
    });
    let constant = run(Reshare, 2, 3, 0xc3, |out| {
        if out.round() == 1 {
            let mut deal = ReshareDeal::decode(&out.payload(1)).unwrap();
            deal.commitments[0] = G2::generator();
            out.replace(1, &deal.encode());
        }
    });
    let capped = run(Reshare, 2, 3, 0xc4, |out| match out.round() {
        1 => out.order(&[3, 1, 2]),
        2 => {
            out.replace(1, &complaints(&[3]));
            out.replace(2, &complaints(&[3]));
        }
        _ => {}
    });
    let insufficient = run(Reshare, 2, 3, 0xc5, |out| {
        if out.round() == 1 {
            out.remove(2);
            out.remove(3);
        }
    });
    let cases = vec![
        case("reshare_2of3_to_3of4", "All old dealers and new recipients follow the protocol; dealers 1 and 2 are selected.", &honest_run),
        case("refresh_2of3_answered_complaint", "Dealer 1's value for recipient 2 fails the Feldman check; recipient 2 complains and dealer 1's valid answer replaces it.", &answered),
        case("reshare_wrong_constant", "Dealer 1's constant coefficient is not its old public share; dealers 2 and 3 are selected.", &constant),
        case("reshare_t_prime_complaints", "Dealer 3 deals first; recipients 1 and 2 complain against it, so it publishes no answers and is excluded.", &capped),
        case("reshare_insufficient_dealers", "Only dealer 1 publishes R1.", &insufficient),
    ];
    let signers: Vec<_> = (0..=4u8)
        .map(|i| {
            json!({
                "did": Signers::did(i).as_str(),
                "ed25519_public_key": hex::encode(ed25519_dalek::SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()),
            })
        })
        .collect();
    let anchor = Signers::new().anchor();
    json!({
        "format_version": 1,
        "suite": "BLS12-381 G2 Feldman redistribution; RFC 9180 base mode DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 dealings; Ed25519 test signatures",
        "spec_sections": ["3.2", "3.3", "3.8", "3.10", "S0.4 redistribution appendix"],
        "encoding": "hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed",
        "seeds": {"ceremonies": [0xc1, 0xc2, 0xc3, 0xc4, 0xc5]},
        "dst": {
            "reshare_start": String::from_utf8_lossy(RESHARE_START),
            "commitments": String::from_utf8_lossy(dst::COMMITMENTS),
            "dealing": String::from_utf8_lossy(dst::DEALING),
            "ceremony_auth": String::from_utf8_lossy(dst::CEREMONY_AUTH),
            "ceremony_msg": String::from_utf8_lossy(dst::CEREMONY_MSG),
            "round_close": String::from_utf8_lossy(dst::ROUND_CLOSE),
            "transcript": String::from_utf8_lossy(dst::TRANSCRIPT),
            "network_cert": String::from_utf8_lossy(dst::NETWORK_CERT),
            "cert_statement": String::from_utf8_lossy(dst::CERT_STATEMENT),
        },
        "anchor": {"owner": anchor.expected_owner.as_str(), "network": anchor.network.as_str()},
        "signers": signers,
        "cases": cases,
    })
}

#[test]
fn reshare_vectors_regenerate_byte_for_byte_and_replay() {
    let encoded = format!("{}\n", serde_json::to_string_pretty(&vectors()).unwrap());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1/reshare.json");
    if std::env::var("TC_THRESHOLD_REGEN_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &encoded).unwrap();
    }
    let published = std::fs::read_to_string(&path).unwrap();
    assert_eq!(published, encoded);

    let file: Value = serde_json::from_str(&published).unwrap();
    let signers = Signers::new();
    let bytes = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let statement = |v: &Value| SignedStatement {
        bytes: bytes(&v["body"]),
        signature: bytes(&v["signature"]),
    };
    for case in file["cases"].as_array().unwrap() {
        let inputs = &case["inputs"];
        let current = verify_certificate(
            &signers.anchor(),
            &SignedCertificate {
                body: CertificateBody::decode(&bytes(&inputs["current_certificate"]["body"]))
                    .unwrap(),
                owner_signature: bytes(&inputs["current_certificate"]["owner_signature"]),
            },
            &signers,
        )
        .unwrap();
        let ceremony =
            AuthorizedCeremony::verify_for(&current, &statement(&inputs["ceremony"]), &signers)
                .unwrap();
        assert_eq!(
            reshare_initial_transcript(&ceremony).as_bytes().to_vec(),
            bytes(&inputs["initial_transcript"])
        );
        let transcript = ReshareTranscript {
            rounds: inputs["rounds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| DkgRoundRecord {
                    closure: statement(&r["closure"]),
                    messages: r["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(statement)
                        .collect(),
                })
                .collect(),
        };
        match reshare_verify_transcript(&ceremony, &current, &transcript, &signers) {
            Ok(output) => assert_eq!(output_json(&output), case["outputs"], "{}", case["name"]),
            Err(error) => assert_eq!(format!("{error:?}"), case["error"].as_str().unwrap()),
        }
    }
}
