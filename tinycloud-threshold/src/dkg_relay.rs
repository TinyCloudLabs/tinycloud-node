//! Test-only owner relay driving real member states over signed closed rounds. Details: TC-2220
//!
//! Liveness scenarios deliver every honest message. Omissions and substitutions
//! below are explicit failure cases chosen by each test, not a broadcast model.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde_json::{json, Value};

use crate::{
    ceremony::{
        ceremony_message_body, round_closure_body, round_closure_preimage, tests::Signers,
        AuthorizedCeremony, CeremonyKind, CeremonyRecipient, CeremonyStatement, ClosedRound,
        Decode, DidSignatureVerifier, MemberCohort, SignedStatement,
    },
    cert::{verify_certificate, CandidateShare, CertificateBody},
    curve::{hash_g2, Scalar, G2},
    dkg::*,
    dst,
    error::{Error, SignatureError},
    ids::*,
    seal::{
        open_dealing, seal_dealing, CeremonyHpkePublicKey, CeremonyHpkeSecretKey, DealingContext,
    },
    KeyShare,
};

pub(crate) fn idx(i: u16) -> MemberIndex {
    MemberIndex::new(i).unwrap()
}

pub(crate) fn pair(value: u64, blinding: u64) -> SharePair {
    SharePair {
        value: Scalar::from_u64(value),
        blinding: Scalar::from_u64(blinding),
    }
}

/// Owner, member DIDs, Ed25519 dev keys and a genesis ceremony with real recipient keys.
pub(crate) struct Fixture {
    pub(crate) signers: Signers,
    pub(crate) ceremony: AuthorizedCeremony,
    pub(crate) statement: SignedStatement,
    pub(crate) seed: u8,
}

pub(crate) fn statement(t: u16, n: u16, seed: u8) -> (Signers, SignedStatement) {
    let signers = Signers::new();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let recipients = (1..=n)
        .map(|i| CeremonyRecipient {
            index: idx(i),
            node: Signers::did(i as u8),
            hpke_public_key: CeremonyHpkeSecretKey::generate(&mut rng).1.encode(),
        })
        .collect();
    let body = CeremonyStatement {
        kind: CeremonyKind::Genesis,
        id: CeremonyId::new([seed; 32]),
        network: signers.anchor().network,
        owner: Signers::did(0),
        current: None,
        threshold: Threshold::new(t, n).unwrap(),
        rekey: RekeyCounter::new(0),
        epoch: Epoch::new(0),
        recipients,
    };
    let signed = signers.statement(&body);
    (signers, signed)
}

pub(crate) fn fixture(t: u16, n: u16, seed: u8) -> Fixture {
    let (signers, statement) = statement(t, n, seed);
    let ceremony =
        AuthorizedCeremony::verify_genesis(&signers.anchor(), &statement, &signers).unwrap();
    Fixture {
        signers,
        ceremony,
        statement,
        seed,
    }
}

impl Fixture {
    /// Regenerate member i's ceremony recipient key from the fixture seed.
    pub(crate) fn secret(&self, i: u16) -> CeremonyHpkeSecretKey {
        let mut rng = ChaCha20Rng::from_seed([self.seed; 32]);
        let mut key = None;
        for _ in 1..=i {
            key = Some(CeremonyHpkeSecretKey::generate(&mut rng).0);
        }
        key.unwrap()
    }

    pub(crate) fn member_rng(&self, i: u16) -> ChaCha20Rng {
        let mut seed = [self.seed; 32];
        seed[0] = i as u8;
        seed[1] = 0xd1;
        ChaCha20Rng::from_seed(seed)
    }

    pub(crate) fn sign(&self, member: u16, message: &DkgMessage) -> SignedStatement {
        assert_eq!(
            message.signing_preimage(),
            crate::ceremony::ceremony_message_preimage(message.body()).unwrap()
        );
        SignedStatement {
            bytes: message.body().to_vec(),
            signature: self
                .signers
                .sign(&Signers::did(member as u8), &message.signing_preimage()),
        }
    }

    pub(crate) fn n(&self) -> u16 {
        self.ceremony.threshold().n()
    }

    pub(crate) fn t(&self) -> u16 {
        self.ceremony.threshold().t()
    }
}

fn sender(statement: &SignedStatement) -> u16 {
    u16::from_be_bytes([statement.bytes[35], statement.bytes[36]])
}

/// Messages the owner is about to close for one round.
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
    /// A member-signed envelope carrying arbitrary payload bytes for this round.
    pub(crate) fn signed(&self, member: u16, payload: &[u8]) -> SignedStatement {
        let bytes = ceremony_message_body(
            &self.fixture.ceremony,
            self.round,
            MemberCohort::Recipients,
            idx(member),
            payload,
        )
        .unwrap();
        let preimage = crate::ceremony::ceremony_message_preimage(&bytes).unwrap();
        SignedStatement {
            signature: self
                .fixture
                .signers
                .sign(&Signers::did(member as u8), &preimage),
            bytes,
        }
    }
    pub(crate) fn has(&self, member: u16) -> bool {
        self.messages.iter().any(|m| sender(m) == member)
    }
    pub(crate) fn payload(&self, member: u16) -> Vec<u8> {
        let message = self
            .messages
            .iter()
            .find(|m| sender(m) == member)
            .expect("member message in this round");
        message.bytes[41..].to_vec()
    }
    pub(crate) fn remove(&mut self, member: u16) {
        self.messages.retain(|m| sender(m) != member);
    }
    pub(crate) fn replace(&mut self, member: u16, payload: &[u8]) {
        let signed = self.signed(member, payload);
        let position = self.messages.iter().position(|m| sender(m) == member);
        self.remove(member);
        match position {
            Some(p) => self.messages.insert(p, signed),
            None => self.messages.push(signed),
        }
    }
    pub(crate) fn push(&mut self, member: u16, payload: &[u8]) {
        let signed = self.signed(member, payload);
        self.messages.push(signed);
    }
    pub(crate) fn duplicate(&mut self, member: u16) {
        let copy = self
            .messages
            .iter()
            .find(|m| sender(m) == member)
            .cloned()
            .expect("member message in this round");
        self.messages.push(copy);
    }
}

pub(crate) type Outcome = Result<(CandidateShare, DkgOutput), Error>;

pub(crate) struct Run {
    pub(crate) fixture: Fixture,
    pub(crate) outcomes: BTreeMap<u16, Outcome>,
    /// Members that asked for R6 after the common closed R5.
    pub(crate) reconstruct: BTreeMap<u16, bool>,
    pub(crate) transcript: DkgTranscript,
}

impl Run {
    pub(crate) fn verify(&self) -> Result<DkgOutput, Error> {
        dkg_verify_transcript(
            &self.fixture.ceremony,
            &self.transcript,
            &self.fixture.signers,
        )
    }
}

struct Relay<'a, V> {
    fixture: &'a Fixture,
    verifier: &'a V,
    previous: TranscriptHash,
    transcript: DkgTranscript,
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
        assert_eq!(closed.previous_hash(), self.previous);
        self.previous = closed.transcript_hash();
        self.transcript
            .rounds
            .push(DkgRoundRecord { closure, messages });
        closed
    }
}

type States<S> = BTreeMap<u16, Result<S, Error>>;

fn advance<S, N, M>(
    fixture: &Fixture,
    states: States<S>,
    closed: &ClosedRound<M>,
    round: u8,
    step: impl Fn(S, &ClosedRound<M>) -> Result<(N, DkgMessage), Error>,
) -> (States<N>, Vec<SignedStatement>) {
    let mut next = BTreeMap::new();
    let mut out = Vec::new();
    for (i, state) in states {
        match state.and_then(|s| step(s, closed)) {
            Ok((s, message)) => {
                assert_eq!(message.round(), round);
                out.push(fixture.sign(i, &message));
                next.insert(i, Ok(s));
            }
            Err(e) => {
                next.insert(i, Err(e));
            }
        }
    }
    (next, out)
}

fn stopped<S>(states: &States<S>) -> bool {
    states.values().all(Result::is_err)
}

fn errors<S>(states: States<S>) -> BTreeMap<u16, Outcome> {
    states
        .into_iter()
        .map(|(i, s)| (i, Err(s.err().expect("stopped member"))))
        .collect()
}

/// Run every member's real state machine through a signing owner relay.
pub(crate) fn drive<V: DidSignatureVerifier>(
    fixture: Fixture,
    verifier: &V,
    mut tamper: impl FnMut(&mut Outbox),
) -> Run {
    let n = fixture.n();
    let mut relay = Relay {
        fixture: &fixture,
        verifier,
        previous: dkg_initial_transcript(&fixture.ceremony),
        transcript: DkgTranscript { rounds: Vec::new() },
        rng: ChaCha20Rng::from_seed([fixture.seed ^ 0xaa; 32]),
    };
    let mut dealt = BTreeMap::new();
    let mut r1 = Vec::new();
    for i in 1..=n {
        let mut rng = fixture.member_rng(i);
        let (state, message) =
            dkg_start(&fixture.ceremony, idx(i), fixture.secret(i), &mut rng).unwrap();
        assert_eq!(message.round(), 1);
        r1.push(fixture.sign(i, &message));
        dealt.insert(i, Ok(state));
    }
    let closed1 = relay.close::<DkgDeal>(1, r1, &mut tamper);
    let (complained, r2) = advance(&fixture, dealt, &closed1, 2, DkgDealt::complain);
    let closed2 = relay.close::<DkgComplaints>(2, r2, &mut tamper);
    let (answered, r3) = advance(&fixture, complained, &closed2, 3, DkgComplained::answer);
    let closed3 = relay.close::<DkgAnswers>(3, r3, &mut tamper);
    let (extracting, r4) = advance(&fixture, answered, &closed3, 4, DkgAnswered::extract);
    let mut outcomes = BTreeMap::new();
    let mut reconstruct = BTreeMap::new();
    if stopped(&extracting) {
        outcomes = errors(extracting);
    } else {
        let closed4 = relay.close::<DkgFeldman>(4, r4, &mut tamper);
        let (waiting, r5) = advance(
            &fixture,
            extracting,
            &closed4,
            5,
            DkgExtracting::extraction_complaints,
        );
        let closed5 = relay.close::<DkgExtractionComplaints>(5, r5, &mut tamper);
        let mut reconstructing = BTreeMap::new();
        let mut r6 = Vec::new();
        for (i, state) in waiting {
            match state.and_then(|s| s.after_barrier(&closed5)) {
                Ok(AfterBarrier::Finished(candidate, output)) => {
                    reconstruct.insert(i, false);
                    outcomes.insert(i, Ok((candidate, output)));
                }
                Ok(AfterBarrier::Reconstruct(state, message)) => {
                    assert_eq!(message.round(), 6);
                    reconstruct.insert(i, true);
                    r6.push(fixture.sign(i, &message));
                    reconstructing.insert(i, state);
                }
                Err(e) => {
                    outcomes.insert(i, Err(e));
                }
            }
        }
        if !reconstructing.is_empty() {
            let closed6 = relay.close::<DkgReconstruction>(6, r6, &mut tamper);
            for (i, state) in reconstructing {
                outcomes.insert(i, state.finish(&closed6));
            }
        }
    }
    let transcript = relay.transcript;
    Run {
        fixture,
        outcomes,
        reconstruct,
        transcript,
    }
}

pub(crate) fn run(t: u16, n: u16, seed: u8, tamper: impl FnMut(&mut Outbox)) -> Run {
    let fixture = fixture(t, n, seed);
    let signers = Signers::new();
    drive(fixture, &signers, tamper)
}

pub(crate) fn honest(t: u16, n: u16, seed: u8) -> Run {
    run(t, n, seed, |_| {})
}

type View = (
    Vec<[u8; 96]>,
    [u8; 96],
    Vec<[u8; 96]>,
    BTreeSet<MemberIndex>,
    BTreeMap<MemberIndex, DisqualifyReason>,
    BTreeSet<MemberIndex>,
    TranscriptHash,
);

pub(crate) fn view(output: &DkgOutput) -> View {
    let n = output.public.threshold().n();
    (
        output.public.commitments().collect(),
        output.public.master_public_key().encode(),
        (1..=n)
            .map(|i| output.public.public_share(idx(i)).unwrap())
            .collect(),
        output.qual.clone(),
        output.disqualified.clone(),
        output.reconstructed.clone(),
        output.transcript_hash,
    )
}

/// Every listed member and the public transcript verifier agree; each candidate binds.
pub(crate) fn agreed(run: &Run, members: &[u16]) -> DkgOutput {
    let verified = run.verify().unwrap();
    assert_eq!(verified.transcript_hash, last_hash(run));
    for i in members {
        let (candidate, output) = run.outcomes[i].as_ref().unwrap();
        assert_eq!(view(output), view(&verified), "member {i}");
        assert_eq!(candidate.index(), idx(*i));
        assert_eq!(candidate.transcript_hash(), verified.transcript_hash);
        assert_eq!(
            G2::generator().mul(&candidate.scalar).encode(),
            verified.public.public_share(idx(*i)).unwrap(),
            "candidate {i} matches its public share"
        );
    }
    verified
}

fn last_hash(run: &Run) -> TranscriptHash {
    let mut previous = dkg_initial_transcript(&run.fixture.ceremony);
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

pub(crate) fn members(set: &[u16]) -> BTreeSet<MemberIndex> {
    set.iter().map(|i| idx(*i)).collect()
}

pub(crate) fn sum(points: impl IntoIterator<Item = [u8; 96]>) -> [u8; 96] {
    points
        .into_iter()
        .fold(G2::identity(), |acc, p| {
            acc.add(&G2::decode(&p, true).unwrap())
        })
        .encode()
}

pub(crate) fn commitment_hash(commitments: &[G2]) -> [u8; 32] {
    let mut body = (commitments.len() as u16).to_be_bytes().to_vec();
    for c in commitments {
        body.extend_from_slice(&c.encode());
    }
    dst::tagged_hash(dst::COMMITMENTS, &body)
}

fn pedersen_h() -> G2 {
    hash_g2(b"pedersen-h", dst::PEDERSEN_H)
}

/// Re-seal one recipient's entry of a dealer's R1 with canonical but wrong scalars.
pub(crate) fn bad_dealing(out: &mut Outbox, dealer: u16, recipient: u16) -> Vec<u8> {
    let mut deal = DkgDeal::decode(&out.payload(dealer)).unwrap();
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
    let mut plaintext = [0u8; 64];
    plaintext[31] = 5;
    plaintext[63] = 6;
    let sealed = seal_dealing(&public, &context, &plaintext, out.rng()).unwrap();
    deal.dealings
        .iter_mut()
        .find(|(j, _)| j.get() == recipient)
        .unwrap()
        .1 = sealed;
    deal.encode()
}

/// Open a dealer's R1 entry with the recipient's regenerated key.
pub(crate) fn opened(fixture: &Fixture, deal: &[u8], dealer: u16, recipient: u16) -> SharePair {
    let deal = DkgDeal::decode(deal).unwrap();
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
    SharePair {
        value: Scalar::from_bytes(&plaintext[..32]).unwrap(),
        blinding: Scalar::from_bytes(&plaintext[32..]).unwrap(),
    }
}

/// Add δ(x)=Π(x−root)·D to a Feldman vector: the check passes exactly at the roots.
pub(crate) fn vanishing_feldman(payload: &[u8], roots: &[u16]) -> Vec<u8> {
    let mut feldman = DkgFeldman::decode(payload).unwrap();
    let d = G2::generator().mul(&Scalar::from_u64(0x5eed));
    let mut poly = vec![Scalar::from_u64(1)];
    for root in roots {
        let mut next: Vec<Scalar> = (0..=poly.len()).map(|_| Scalar::from_u64(0)).collect();
        for (k, c) in poly.iter().enumerate() {
            next[k + 1] = next[k + 1].add(c);
            next[k] = next[k].sub(&c.mul(&Scalar::from_u64(u64::from(*root))));
        }
        poly = next;
    }
    assert!(poly.len() <= feldman.commitments.len());
    for (k, c) in poly.iter().enumerate() {
        feldman.commitments[k] = feldman.commitments[k].add(&d.mul(c));
    }
    feldman.encode()
}

fn constants(out: &Outbox, into: &mut BTreeMap<u16, [u8; 96]>) {
    for i in 1..=out.fixture().n() {
        if out.has(i) {
            let feldman = DkgFeldman::decode(&out.payload(i)).unwrap();
            into.insert(i, feldman.commitments[0].encode());
        }
    }
}

fn genuine_mpk(constants: &BTreeMap<u16, [u8; 96]>, qual: &BTreeSet<MemberIndex>) -> [u8; 96] {
    sum(qual.iter().map(|i| constants[&i.get()]))
}

/// A test DID verifier that also accepts `signature || 00`, modelling a
/// signature scheme with more than one valid encoding of one statement.
struct Malleable(Signers);
impl DidSignatureVerifier for Malleable {
    fn verify(&self, signer: &Did, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        match signature {
            [inner @ .., 0] if inner.len() == 64 => self.0.verify(signer, message, inner),
            _ => self.0.verify(signer, message, signature),
        }
    }
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
        inner: ChaCha20Rng::from_seed([0x77; 32]),
        draws: 0,
    }
}

// ---------------------------------------------------------------- completion

#[test]
fn genuine_2of3_completes_with_every_member_and_the_verifier_agreeing() {
    let run = honest(2, 3, 0x31);
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
    assert!(output.reconstructed.is_empty());
    assert_eq!(run.transcript.rounds.len(), 5);
    assert!(run.reconstruct.values().all(|r| !r));
    assert_eq!(output.public.threshold(), Threshold::new(2, 3).unwrap());
    let mut sorted = output.public.commitments().collect::<Vec<_>>();
    assert_eq!(sorted.len(), 2);
    sorted.dedup();
    assert_eq!(sorted.len(), 2);
}

#[test]
fn genesis_3of4_is_refused_before_any_dealing() {
    let (signers, statement) = statement(3, 4, 0x32);
    assert!(matches!(
        AuthorizedCeremony::verify_genesis(&signers.anchor(), &statement, &signers),
        Err(Error::UnsupportedFaultBudget)
    ));
    assert_eq!(
        Threshold::new(3, 4).unwrap().check_genesis_budget(),
        Err(Error::UnsupportedFaultBudget)
    );
    assert_eq!(Threshold::new(3, 5).unwrap().check_genesis_budget(), Ok(()));
}

#[test]
fn three_of_five_with_two_faulty_members_recovers_the_committed_master_key() {
    // Members 4 and 5 are faulty. Dealer 5 publishes a Feldman vector that
    // passes only at indices 4 and 5; member 4 files a false R5 complaint
    // against honest dealer 1; both withhold R6.
    let mut constants_seen = BTreeMap::new();
    let run = run(3, 5, 0x33, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(5), &[4, 5]);
            out.replace(5, &forged);
        }
        5 => {
            let complaint = DkgExtractionComplaints {
                complaints: vec![(idx(1), pair(11, 12))],
            };
            out.replace(4, &complaint.encode());
        }
        6 => {
            out.remove(4);
            out.remove(5);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3, 4, 5]));
    assert!(output.disqualified.is_empty());
    assert_eq!(output.reconstructed, members(&[5]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
    for i in [1, 2, 3] {
        assert!(run.reconstruct[&i]);
    }
}

#[test]
fn one_recipient_bad_private_value_is_replaced_by_a_valid_answer() {
    let mut answer = None;
    let run = run(2, 3, 0x34, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
        2 => assert_eq!(
            DkgComplaints::decode(&out.payload(2)).unwrap().dealers,
            vec![idx(1)]
        ),
        3 => answer = Some(DkgAnswers::decode(&out.payload(1)).unwrap()),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
    let answer = answer.unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].0, idx(2));
}

// ------------------------------------------------------------ R2/R3 rulings

#[test]
fn false_complaint_is_refuted_by_a_valid_answer() {
    let run = run(2, 3, 0x35, |out| {
        if out.round() == 2 {
            out.replace(
                3,
                &DkgComplaints {
                    dealers: vec![idx(1)],
                }
                .encode(),
            );
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

#[test]
fn t_distinct_complainers_disqualify_even_with_valid_answers() {
    let run = run(2, 3, 0x36, |out| {
        if out.round() == 1 {
            let forged = bad_dealing(out, 3, 1);
            out.replace(3, &forged);
            let forged = bad_dealing(out, 3, 2);
            out.replace(3, &forged);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2]));
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(3), DisqualifyReason::Complaints)])
    );
}

#[test]
fn duplicate_complaints_count_once() {
    // t = 3: two distinct complainers, one retransmitting, stay below t.
    let run = run(3, 5, 0x37, |out| {
        if out.round() == 2 {
            let complaint = DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode();
            out.replace(4, &complaint);
            out.replace(5, &complaint);
            out.duplicate(4);
            out.duplicate(4);
        }
    });
    let output = agreed(&run, &[1, 2, 3, 4, 5]);
    assert_eq!(output.qual, members(&[1, 2, 3, 4, 5]));
}

#[test]
fn self_complaints_are_ignored() {
    // Dealer 3 sends member 1 a bad value and complains against itself. With
    // the self-complaint counted, two complainers would reach t = 2.
    let run = run(2, 3, 0x38, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 3, 1);
            out.replace(3, &forged);
        }
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(3)],
            }
            .encode(),
        ),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

#[test]
fn malformed_r2_supplies_no_complaints() {
    // A well-formed complaint with a trailing byte is malformed: it creates no
    // required answer, so dealer 1's missing R3 does not disqualify it.
    let run = run(2, 3, 0x39, |out| match out.round() {
        2 => {
            let mut malformed = DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode();
            malformed.push(0);
            out.replace(3, &malformed);
        }
        3 => out.remove(1),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

#[test]
fn conflicting_r2_content_is_equivocation_even_when_malformed() {
    let run = run(3, 5, 0x3a, |out| {
        if out.round() == 2 {
            out.replace(5, &[1, 0]);
            out.push(5, &[1, 0, 1]);
            out.replace(4, &[1, 0, 1, 0]);
            out.duplicate(4);
        }
    });
    let output = agreed(&run, &[1, 2, 3, 4]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(5), DisqualifyReason::Equivocated { round: 2 })])
    );
    assert_eq!(output.qual, members(&[1, 2, 3, 4]));
}

/// Retransmit a member's first message with an alternate valid signature encoding.
fn alternate_signature(out: &mut Outbox, member: u16) {
    let mut copy = out
        .messages
        .iter()
        .find(|m| sender(m) == member)
        .cloned()
        .unwrap();
    copy.signature.push(0);
    out.messages.push(copy);
}

#[test]
fn different_signature_encoding_is_not_equivocation() {
    let verifier = Malleable(Signers::new());
    let run = drive(fixture(2, 3, 0x3b), &verifier, |out| {
        if out.round() <= 3 {
            alternate_signature(out, 3);
        }
    });
    assert_eq!(run.transcript.rounds[0].messages.len(), 4);
    let verified =
        dkg_verify_transcript(&run.fixture.ceremony, &run.transcript, &verifier).unwrap();
    assert_eq!(verified.qual, members(&[1, 2, 3]));
    assert!(verified.disqualified.is_empty());
    for i in [1, 2, 3] {
        assert_eq!(view(&run.outcomes[&i].as_ref().unwrap().1), view(&verified));
    }

    let changed = drive(fixture(2, 3, 0x3b), &verifier, |out| {
        if out.round() == 1 {
            let forged = bad_dealing(out, 3, 2);
            out.push(3, &forged);
        }
    });
    let verified =
        dkg_verify_transcript(&changed.fixture.ceremony, &changed.transcript, &verifier).unwrap();
    assert_eq!(
        verified.disqualified,
        BTreeMap::from([(idx(3), DisqualifyReason::Equivocated { round: 1 })])
    );
}

#[test]
fn missing_r3_disqualifies_only_with_required_answers() {
    let run = run(2, 3, 0x3c, |out| match out.round() {
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode(),
        ),
        3 => {
            out.remove(1);
            out.remove(2);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(1), DisqualifyReason::MissingAnswer)])
    );
    assert_eq!(output.qual, members(&[2, 3]));
}

#[test]
fn malformed_r3_disqualifies_only_with_required_answers() {
    let run = run(2, 3, 0x3d, |out| match out.round() {
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode(),
        ),
        3 => {
            for dealer in [1, 2] {
                let mut malformed = out.payload(dealer);
                malformed.push(0);
                out.replace(dealer, &malformed);
            }
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(1), DisqualifyReason::MissingAnswer)])
    );
    assert_eq!(output.qual, members(&[2, 3]));
}

#[test]
fn invalid_unsolicited_answer_disqualifies_its_dealer() {
    let run = run(2, 3, 0x3e, |out| {
        if out.round() == 3 {
            let answer = DkgAnswers {
                answers: vec![(idx(3), pair(5, 6))],
            };
            out.replace(2, &answer.encode());
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(2), DisqualifyReason::InvalidAnswer)])
    );
    assert_eq!(output.qual, members(&[1, 3]));
}

#[test]
fn valid_unsolicited_answer_is_ignored() {
    let mut deal = Vec::new();
    let run = run(2, 3, 0x3f, |out| match out.round() {
        1 => deal = out.payload(2),
        3 => {
            let answer = DkgAnswers {
                answers: vec![(idx(3), opened(out.fixture(), &deal, 2, 3))],
            };
            out.replace(2, &answer.encode());
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
}

#[test]
fn relay_omitted_complaint_fails_only_the_affected_member() {
    // Failure scenario outside the trusted-relay liveness model.
    let run = run(2, 3, 0x40, |out| match out.round() {
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
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

// ------------------------------------------------- R4, barrier and R6 rules

#[test]
fn selective_r4_reaches_the_common_barrier_and_is_reconstructed() {
    let mut constants_seen = BTreeMap::new();
    let mut r5 = BTreeMap::new();
    let run = run(2, 3, 0x41, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(3), &[1]);
            out.replace(3, &forged);
        }
        5 => {
            for i in 1..=3 {
                r5.insert(
                    i,
                    DkgExtractionComplaints::decode(&out.payload(i))
                        .unwrap()
                        .complaints
                        .len(),
                );
            }
        }
        _ => {}
    });
    // Member 1's own check passed; member 2 complained. Both waited for the
    // same closed R5 and both entered R6.
    assert_eq!(r5, BTreeMap::from([(1, 0), (2, 1), (3, 0)]));
    assert_eq!(
        run.reconstruct,
        BTreeMap::from([(1, true), (2, true), (3, true)])
    );
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert_eq!(output.reconstructed, members(&[3]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
    assert_eq!(run.transcript.rounds.len(), 6);
}

type Mutation = fn(&mut Outbox);

#[test]
fn bad_missing_and_malformed_r4_are_extraction_faults() {
    let cases: [(&str, Mutation); 5] = [
        ("bad", |out| {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }),
        ("missing", |out| out.remove(3)),
        ("trailing byte", |out| {
            let mut p = out.payload(3);
            p.push(0);
            out.replace(3, &p);
        }),
        ("wrong length", |out| {
            let mut f = DkgFeldman::decode(&out.payload(3)).unwrap();
            f.commitments.pop();
            out.replace(3, &f.encode());
        }),
        ("invalid point", |out| {
            let mut p = out.payload(3);
            p[3 + 95] ^= 1;
            out.replace(3, &p);
        }),
    ];
    for (name, mutate) in cases {
        let mut constants_seen = BTreeMap::new();
        let run = run(2, 3, 0x42, |out| {
            if out.round() == 4 {
                constants(out, &mut constants_seen);
                mutate(out);
            }
        });
        let output = agreed(&run, &[1, 2, 3]);
        assert_eq!(output.qual, members(&[1, 2, 3]), "{name}");
        assert_eq!(output.reconstructed, members(&[3]), "{name}");
        assert_eq!(
            output.public.master_public_key().encode(),
            genuine_mpk(&constants_seen, &output.qual),
            "{name}"
        );
    }
}

#[test]
fn r1_equivocation_disqualifies_but_r4_equivocation_reconstructs() {
    let mut constants_seen = BTreeMap::new();
    let run = run(3, 5, 0x43, |out| match out.round() {
        1 => {
            let second = bad_dealing(out, 5, 1);
            out.push(5, &second);
        }
        4 => {
            constants(out, &mut constants_seen);
            let second = vanishing_feldman(&out.payload(4), &[]);
            out.push(4, &second);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(5), DisqualifyReason::Equivocated { round: 1 })])
    );
    assert_eq!(output.qual, members(&[1, 2, 3, 4]));
    assert_eq!(output.reconstructed, members(&[4]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
}

#[test]
fn every_member_sends_r5_and_an_empty_barrier_finishes() {
    let mut r5 = Vec::new();
    let run = run(2, 3, 0x44, |out| {
        if out.round() == 5 {
            for i in 1..=3 {
                r5.push(DkgExtractionComplaints::decode(&out.payload(i)).unwrap());
            }
            assert_eq!(out.messages.len(), 3);
        }
    });
    assert!(r5.iter().all(|r| r.complaints.is_empty()));
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.reconstructed.is_empty());
    assert_eq!(run.transcript.rounds.len(), 5);
}

#[test]
fn missing_or_malformed_r5_counts_as_an_empty_list() {
    let reference = agreed(&honest(2, 3, 0x45), &[1, 2, 3]);
    for malformed in [false, true] {
        let run = run(2, 3, 0x45, |out| {
            if out.round() == 5 {
                if malformed {
                    out.replace(2, &[1, 0]);
                } else {
                    out.remove(2);
                }
            }
        });
        let output = agreed(&run, &[1, 2, 3]);
        assert!(output.reconstructed.is_empty());
        assert_eq!(output.qual, reference.qual);
        assert_eq!(
            output.public.master_public_key().encode(),
            reference.public.master_public_key().encode()
        );
    }
}

#[test]
fn false_extraction_complaints_are_refuted() {
    // Member 3 complains against dealer 1 with (a) a Pedersen-invalid pair
    // and (b) its genuine, Feldman-valid pair; neither triggers R6.
    for genuine in [false, true] {
        let mut deal = Vec::new();
        let run = run(2, 3, 0x46, |out| match out.round() {
            1 => deal = out.payload(1),
            5 => {
                let value = if genuine {
                    opened(out.fixture(), &deal, 1, 3)
                } else {
                    pair(5, 6)
                };
                let complaint = DkgExtractionComplaints {
                    complaints: vec![(idx(1), value)],
                };
                out.replace(3, &complaint.encode());
            }
            _ => {}
        });
        let output = agreed(&run, &[1, 2, 3]);
        assert!(output.reconstructed.is_empty());
        assert!(run.reconstruct.values().all(|r| !r));
    }
}

#[test]
fn corrupt_dealer_withholding_its_r6_is_recovered_and_kept() {
    let mut constants_seen = BTreeMap::new();
    let run = run(2, 3, 0x47, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => out.remove(3),
        _ => {}
    });
    let output = agreed(&run, &[1, 2]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert_eq!(output.reconstructed, members(&[3]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
}

#[test]
fn invalid_or_equivocated_r6_values_do_not_count() {
    // Dealer 3 is faulted; member 2 equivocates in R6 and member 3 sends an
    // invalid value. Only member 1's value is valid, below t = 2.
    let run = run(2, 3, 0x48, |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => {
            let changed = DkgReconstruction {
                values: vec![(idx(3), pair(1, 2))],
            };
            out.push(2, &changed.encode());
            out.replace(3, &changed.encode());
        }
        _ => {}
    });
    for i in [1, 2, 3] {
        assert!(matches!(run.outcomes[&i], Err(Error::InsufficientRecovery)));
    }
    assert!(matches!(run.verify(), Err(Error::InsufficientRecovery)));
}

#[test]
fn insufficient_valid_r6_values_abort_with_a_typed_error() {
    let run = run(2, 3, 0x49, |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => {
            out.remove(2);
            out.remove(3);
        }
        _ => {}
    });
    for i in [1, 2, 3] {
        assert!(matches!(run.outcomes[&i], Err(Error::InsufficientRecovery)));
    }
    assert!(matches!(run.verify(), Err(Error::InsufficientRecovery)));
}

#[test]
fn fewer_than_t_qualified_dealers_abort_with_a_typed_error() {
    let run = run(2, 3, 0x4a, |out| {
        if out.round() == 1 {
            out.remove(2);
            out.remove(3);
        }
    });
    for i in [1, 2, 3] {
        assert!(matches!(
            run.outcomes[&i],
            Err(Error::InsufficientQualified)
        ));
    }
    assert_eq!(run.transcript.rounds.len(), 3);
    assert!(matches!(run.verify(), Err(Error::InsufficientQualified)));
}

#[test]
fn missing_and_malformed_r1_disqualify() {
    let missing = run(3, 5, 0x4b, |out| {
        if out.round() == 1 {
            out.remove(4);
            let mut truncated = out.payload(5);
            truncated.pop();
            out.replace(5, &truncated);
        }
    });
    let output = agreed(&missing, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([
            (idx(4), DisqualifyReason::MissingDeal),
            (idx(5), DisqualifyReason::MalformedDeal)
        ])
    );
    let malformed = run(3, 5, 0x4c, |out| {
        if out.round() == 1 {
            let mut deal = DkgDeal::decode(&out.payload(5)).unwrap();
            deal.commitments.pop();
            out.replace(5, &deal.encode());
            let mut deal = DkgDeal::decode(&out.payload(4)).unwrap();
            deal.dealings.pop();
            out.replace(4, &deal.encode());
        }
    });
    let output = agreed(&malformed, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([
            (idx(4), DisqualifyReason::MalformedDeal),
            (idx(5), DisqualifyReason::MalformedDeal)
        ])
    );
}

// --------------------------------------------- authorization and state binding

#[test]
fn local_recipient_key_and_context_are_checked_before_any_randomness() {
    let f = fixture(2, 3, 0x50);
    let mut rng = counting();
    assert!(matches!(
        dkg_start(&f.ceremony, idx(1), f.secret(2), &mut rng),
        Err(Error::ContextMismatch)
    ));
    assert!(matches!(
        dkg_start(&f.ceremony, idx(4), f.secret(1), &mut rng),
        Err(Error::InvalidIndex)
    ));
    let signers = Signers::new();
    let (current, _) = crate::cert::tests::genesis(&signers);
    let (_, _, reshare) = crate::cert::tests::successor(
        &signers,
        &current,
        CeremonyKind::Reshare,
        Threshold::new(2, 3).unwrap(),
        // Seed 11 matches the genesis fixture, so the reshare keeps its mpk.
        11,
    );
    assert!(matches!(
        dkg_start(&reshare, idx(1), f.secret(1), &mut rng),
        Err(Error::InvalidCeremony)
    ));
    assert_eq!(rng.draws, 0);
    let (state, message) = dkg_start(&f.ceremony, idx(1), f.secret(1), &mut rng).unwrap();
    assert!(rng.draws > 0);
    assert_eq!(message.round(), 1);
    assert_eq!(format!("{state:?}"), "DkgDealt([REDACTED])");
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

#[test]
fn transitions_refuse_other_ceremonies_rounds_and_histories() {
    let f = fixture(2, 3, 0x51);
    let other = fixture(2, 3, 0x52);
    let h0 = dkg_initial_transcript(&f.ceremony);
    let start = |i: u16| {
        let mut rng = f.member_rng(i);
        dkg_start(&f.ceremony, idx(i), f.secret(i), &mut rng).unwrap()
    };
    let r1: Vec<_> = (1..=3).map(|i| f.sign(i, &start(i).1)).collect();
    let closed1 = close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &r1).unwrap();

    // Another authorized ceremony, its own correct history.
    let other_r1: Vec<_> = (1..=3)
        .map(|i| {
            let mut rng = other.member_rng(i);
            let (_, m) = dkg_start(&other.ceremony, idx(i), other.secret(i), &mut rng).unwrap();
            other.sign(i, &m)
        })
        .collect();
    let foreign = close_for::<DkgDeal>(
        &other,
        &other.ceremony,
        1,
        &dkg_initial_transcript(&other.ceremony),
        &other_r1,
    )
    .unwrap();
    assert!(matches!(
        start(1).0.complain(&foreign),
        Err(Error::InvalidRound)
    ));
    // The same messages are not accepted under this ceremony's closure.
    assert!(close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &other_r1).is_err());

    // Correct ceremony, wrong previous link.
    let rebased =
        close_for::<DkgDeal>(&f, &f.ceremony, 1, &TranscriptHash::new([9; 32]), &r1).unwrap();
    assert!(matches!(
        start(1).0.complain(&rebased),
        Err(Error::InvalidRound)
    ));

    // A round-2 closure presented to the round-1 transition.
    let empty = DkgComplaints { dealers: vec![] }.encode();
    let r2_as_deal: Vec<_> = (1..=3)
        .map(|i| {
            let bytes =
                ceremony_message_body(&f.ceremony, 2, MemberCohort::Recipients, idx(i), &empty)
                    .unwrap();
            let preimage = crate::ceremony::ceremony_message_preimage(&bytes).unwrap();
            SignedStatement {
                signature: f.signers.sign(&Signers::did(i as u8), &preimage),
                bytes,
            }
        })
        .collect();
    let wrong_round = close_for::<DkgDeal>(&f, &f.ceremony, 2, &h0, &r2_as_deal).unwrap();
    assert!(matches!(
        start(1).0.complain(&wrong_round),
        Err(Error::InvalidRound)
    ));

    // Later phase: R3 chained to R1 instead of R2.
    let mut states = BTreeMap::new();
    for i in 1..=3u16 {
        states.insert(i, start(i).0);
    }
    let mut complained = BTreeMap::new();
    let mut r2 = Vec::new();
    for (i, s) in states {
        let (s, m) = s.complain(&closed1).unwrap();
        r2.push(f.sign(i, &m));
        complained.insert(i, s);
    }
    let closed2 =
        close_for::<DkgComplaints>(&f, &f.ceremony, 2, &closed1.transcript_hash(), &r2).unwrap();
    let mut r3 = Vec::new();
    let mut answered = BTreeMap::new();
    for (i, s) in complained {
        let (s, m) = s.answer(&closed2).unwrap();
        r3.push(f.sign(i, &m));
        answered.insert(i, s);
    }
    let skipped =
        close_for::<DkgAnswers>(&f, &f.ceremony, 3, &closed1.transcript_hash(), &r3).unwrap();
    let state = answered.remove(&1).unwrap();
    assert!(matches!(state.extract(&skipped), Err(Error::InvalidRound)));
    let chained =
        close_for::<DkgAnswers>(&f, &f.ceremony, 3, &closed2.transcript_hash(), &r3).unwrap();
    assert!(answered.remove(&2).unwrap().extract(&chained).is_ok());
}

#[test]
fn closed_rounds_reject_wrong_signers_cohorts_and_signatures() {
    let f = fixture(2, 3, 0x53);
    let h0 = dkg_initial_transcript(&f.ceremony);
    let mut rng = f.member_rng(1);
    let (_, message) = dkg_start(&f.ceremony, idx(1), f.secret(1), &mut rng).unwrap();
    let genuine = f.sign(1, &message);
    assert!(close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, std::slice::from_ref(&genuine)).is_ok());

    let mut wrong_signer = genuine.clone();
    wrong_signer.signature = f
        .signers
        .sign(&Signers::did(2), &message.signing_preimage());
    assert!(matches!(
        close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &[wrong_signer]),
        Err(Error::InvalidSignature)
    ));
    let mut flipped = genuine.clone();
    flipped.signature[0] ^= 1;
    assert!(matches!(
        close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &[flipped]),
        Err(Error::InvalidSignature)
    ));
    let mut current_cohort = genuine.clone();
    current_cohort.bytes[34] = MemberCohort::Current as u8;
    current_cohort.signature = f.signers.sign(
        &Signers::did(1),
        &crate::ceremony::ceremony_message_preimage(&current_cohort.bytes).unwrap(),
    );
    assert!(close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &[current_cohort]).is_err());
}

// -------------------------------------------------------- public verifier

#[test]
fn verifier_recomputes_from_authenticated_records_only() {
    let run = run(2, 3, 0x54, |out| {
        if out.round() == 4 {
            let forged = vanishing_feldman(&out.payload(2), &[]);
            out.replace(2, &forged);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.reconstructed, members(&[2]));

    let mut tampered = DkgTranscript {
        rounds: run.transcript.rounds.clone(),
    };
    tampered.rounds[1].messages[0].signature[0] ^= 1;
    assert!(dkg_verify_transcript(&run.fixture.ceremony, &tampered, &run.fixture.signers).is_err());

    let mut swapped = DkgTranscript {
        rounds: run.transcript.rounds.clone(),
    };
    swapped.rounds.swap(2, 3);
    assert!(dkg_verify_transcript(&run.fixture.ceremony, &swapped, &run.fixture.signers).is_err());

    let other = fixture(2, 3, 0x55);
    assert!(dkg_verify_transcript(&other.ceremony, &run.transcript, &run.fixture.signers).is_err());

    let mut missing_r6 = DkgTranscript {
        rounds: run.transcript.rounds.clone(),
    };
    missing_r6.rounds.pop();
    assert!(matches!(
        dkg_verify_transcript(&run.fixture.ceremony, &missing_r6, &run.fixture.signers),
        Err(Error::InvalidRound)
    ));

    let plain = honest(2, 3, 0x56);
    let mut extra = DkgTranscript {
        rounds: plain.transcript.rounds.clone(),
    };
    extra.rounds.push(run.transcript.rounds[5].clone());
    assert!(matches!(
        dkg_verify_transcript(&plain.fixture.ceremony, &extra, &plain.fixture.signers),
        Err(Error::InvalidRound)
    ));
}

struct Refusing;
impl DidSignatureVerifier for Refusing {
    fn verify(&self, _: &Did, _: &[u8], _: &[u8]) -> Result<(), SignatureError> {
        panic!("size bound must precede signature verification")
    }
}

#[test]
fn transcript_bound_of_4_mib_precedes_verification() {
    let f = fixture(2, 3, 0x57);
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
    let over = DkgTranscript {
        rounds: vec![record(64)],
    };
    assert!(matches!(
        dkg_verify_transcript(&f.ceremony, &over, &Refusing),
        Err(Error::LimitExceeded)
    ));
    let split = DkgTranscript {
        rounds: vec![record(32), record(32)],
    };
    assert!(matches!(
        dkg_verify_transcript(&f.ceremony, &split, &Refusing),
        Err(Error::LimitExceeded)
    ));
    let under = DkgTranscript {
        rounds: vec![record(63)],
    };
    let result = dkg_verify_transcript(&f.ceremony, &under, &f.signers);
    assert!(result.is_err());
    assert!(!matches!(result, Err(Error::LimitExceeded)));
}

// ----------------------------------------------------- within-budget property

fn misbehave(out: &mut Outbox, m: u16, behaviour: u8, target: u16) {
    let present = out.has(m);
    match (out.round(), behaviour) {
        (1, 1) => out.remove(m),
        (1, 2) if present => {
            let mut p = out.payload(m);
            p.pop();
            out.replace(m, &p);
        }
        (1, 3) if present => {
            let second = bad_dealing(out, m, target);
            out.push(m, &second);
        }
        (1, 4) | (1, 5) if present => {
            let forged = bad_dealing(out, m, target);
            out.replace(m, &forged);
        }
        (2, 6) => out.replace(
            m,
            &DkgComplaints {
                dealers: vec![idx(target)],
            }
            .encode(),
        ),
        (2, 7) => out.push(m, &[1, 0, 1, 0, target as u8]),
        (3, 5) => out.remove(m),
        (3, 8) => out.replace(
            m,
            &DkgAnswers {
                answers: vec![(idx(target), pair(5, 6))],
            }
            .encode(),
        ),
        (4, 9) if present => {
            let forged = vanishing_feldman(&out.payload(m), &[m]);
            out.replace(m, &forged);
        }
        (4, 10) => out.remove(m),
        (4, 11) if present => {
            let mut p = out.payload(m);
            p.push(0);
            out.replace(m, &p);
        }
        (4, 12) if present => {
            let second = vanishing_feldman(&out.payload(m), &[]);
            out.push(m, &second);
        }
        (5, 13) => out.replace(
            m,
            &DkgExtractionComplaints {
                complaints: vec![(idx(target), pair(5, 6))],
            }
            .encode(),
        ),
        (6, 13) | (5, 14) | (6, 14) => out.remove(m),
        _ => {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn within_budget_fault_patterns_finish_with_identical_outcomes(
        shape in 0usize..2,
        seed in any::<u8>(),
        behaviours in proptest::collection::vec(0u8..15, 2),
    ) {
        let (t, n) = [(2u16, 3u16), (3, 5)][shape];
        let honest_members: Vec<u16> = (1..=n - (t - 1)).collect();
        let faulty: Vec<u16> = (n - (t - 1) + 1..=n).collect();
        let mut constants_seen = BTreeMap::new();
        let run = run(t, n, seed, |out| {
            if out.round() == 4 {
                constants(out, &mut constants_seen);
            }
            for (k, m) in faulty.iter().enumerate() {
                misbehave(out, *m, behaviours[k], 1);
            }
        });
        let output = agreed(&run, &honest_members);
        let faulty_set = members(&faulty);
        prop_assert!(members(&honest_members).is_subset(&output.qual));
        prop_assert!(output.disqualified.keys().all(|i| faulty_set.contains(i)));
        prop_assert!(output.reconstructed.is_subset(&faulty_set));
        prop_assert_eq!(
            output.public.master_public_key().encode(),
            genuine_mpk(&constants_seen, &output.qual)
        );
    }
}

// ------------------------------------------------------------------ vectors

fn hex_statement(s: &SignedStatement) -> Value {
    json!({"body": hex::encode(&s.bytes), "signature": hex::encode(&s.signature)})
}

fn reason(r: &DisqualifyReason) -> Value {
    match r {
        DisqualifyReason::MissingDeal => json!({"reason": "MissingDeal"}),
        DisqualifyReason::MalformedDeal => json!({"reason": "MalformedDeal"}),
        DisqualifyReason::Equivocated { round } => {
            json!({"reason": "Equivocated", "round": round})
        }
        DisqualifyReason::Complaints => json!({"reason": "Complaints"}),
        DisqualifyReason::MissingAnswer => json!({"reason": "MissingAnswer"}),
        DisqualifyReason::InvalidAnswer => json!({"reason": "InvalidAnswer"}),
    }
}

fn output_json(o: &DkgOutput) -> Value {
    let n = o.public.threshold().n();
    json!({
        "qual": o.qual.iter().map(|i| i.get()).collect::<Vec<_>>(),
        "disqualified": o.disqualified.iter().map(|(i, r)| {
            let mut entry = reason(r);
            entry["member"] = json!(i.get());
            entry
        }).collect::<Vec<_>>(),
        "reconstructed": o.reconstructed.iter().map(|i| i.get()).collect::<Vec<_>>(),
        "mpk": hex::encode(o.public.master_public_key().encode()),
        "commitments": o.public.commitments().map(hex::encode).collect::<Vec<_>>(),
        "public_shares": (1..=n).map(|i| json!({
            "member": i,
            "point": hex::encode(o.public.public_share(idx(i)).unwrap()),
        })).collect::<Vec<_>>(),
        "transcript_hash": hex::encode(o.transcript_hash.as_bytes()),
    })
}

fn case(name: &str, description: &str, run: &Run) -> Value {
    let inputs = json!({
        "threshold": run.fixture.t(),
        "members": run.fixture.n(),
        "ceremony": hex_statement(&run.fixture.statement),
        "ceremony_digest": hex::encode(run.fixture.ceremony.digest()),
        "initial_transcript": hex::encode(dkg_initial_transcript(&run.fixture.ceremony).as_bytes()),
        "rounds": run.transcript.rounds.iter().map(|r| json!({
            "closure": hex_statement(&r.closure),
            "messages": r.messages.iter().map(hex_statement).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    });
    match run.verify() {
        Ok(output) => {
            json!({"name": name, "description": description, "operation": "dkg_verify_transcript", "inputs": inputs, "outputs": output_json(&output)})
        }
        Err(error) => {
            json!({"name": name, "description": description, "operation": "dkg_verify_transcript", "inputs": inputs, "error": format!("{error:?}")})
        }
    }
}

fn vectors() -> Value {
    let honest_run = honest(2, 3, 0x61);
    let selective = run(2, 3, 0x62, |out| {
        if out.round() == 4 {
            let forged = vanishing_feldman(&out.payload(3), &[1]);
            out.replace(3, &forged);
        }
    });
    let two_faulty = run(3, 5, 0x63, |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(5), &[4, 5]);
            out.replace(5, &forged);
        }
        5 => out.replace(
            4,
            &DkgExtractionComplaints {
                complaints: vec![(idx(1), pair(11, 12))],
            }
            .encode(),
        ),
        6 => {
            out.remove(4);
            out.remove(5);
        }
        _ => {}
    });
    let answers = run(3, 5, 0x64, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
            let second = bad_dealing(out, 4, 3);
            out.push(4, &second);
            let forged = bad_dealing(out, 5, 1);
            out.replace(5, &forged);
        }
        3 => out.remove(5),
        _ => {}
    });
    let insufficient = run(2, 3, 0x65, |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => {
            out.remove(2);
            out.remove(3);
        }
        _ => {}
    });
    let unqualified = run(2, 3, 0x66, |out| {
        if out.round() == 1 {
            out.remove(2);
            out.remove(3);
        }
    });
    let cases = vec![
        case("genesis_2of3", "All members follow the protocol; R5 is empty and no R6 round exists.", &honest_run),
        case("genesis_2of3_selective_extraction", "Dealer 3's R4 vector passes only member 1's check; member 2's R5 complaint leads to R6 reconstruction of dealer 3.", &selective),
        case("genesis_3of5_two_faulty", "Dealer 5's R4 passes only at members 4 and 5; member 4 files an invalid R5 complaint; members 4 and 5 send no R6.", &two_faulty),
        case("genesis_3of5_answers_and_disqualification", "Dealer 1's bad value to member 2 is answered; dealer 4 sends two R1 messages; dealer 5 does not answer member 1's complaint.", &answers),
        case("insufficient_reconstruction_values", "Only member 1 sends R6 for faulted dealer 3.", &insufficient),
        case("insufficient_qualified_dealers", "Only dealer 1 publishes R1.", &unqualified),
    ];
    let signers: Vec<_> = (0..=5u8)
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
        "suite": "BLS12-381 G2 Pedersen/Feldman GJKR New-DKG; RFC 9180 base mode DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 dealings; Ed25519 test signatures",
        "spec_sections": ["3.2", "3.3", "3.7", "3.10", "S0.3 DKG appendix"],
        "encoding": "hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed",
        "seeds": {"ceremonies": [0x61, 0x62, 0x63, 0x64, 0x65, 0x66]},
        "dst": {
            "dkg_start": String::from_utf8_lossy(DKG_START),
            "pedersen_h": String::from_utf8_lossy(dst::PEDERSEN_H),
            "pedersen_h_message": "pedersen-h",
            "commitments": String::from_utf8_lossy(dst::COMMITMENTS),
            "dealing": String::from_utf8_lossy(dst::DEALING),
            "ceremony_auth": String::from_utf8_lossy(dst::CEREMONY_AUTH),
            "ceremony_msg": String::from_utf8_lossy(dst::CEREMONY_MSG),
            "round_close": String::from_utf8_lossy(dst::ROUND_CLOSE),
            "transcript": String::from_utf8_lossy(dst::TRANSCRIPT),
        },
        "anchor": {"owner": anchor.expected_owner.as_str(), "network": anchor.network.as_str()},
        "signers": signers,
        "cases": cases,
    })
}

#[test]
fn dkg_vectors_regenerate_byte_for_byte_and_replay() {
    let encoded = format!("{}\n", serde_json::to_string_pretty(&vectors()).unwrap());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1/dkg-genesis.json");
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
        let ceremony = AuthorizedCeremony::verify_genesis(
            &signers.anchor(),
            &statement(&inputs["ceremony"]),
            &signers,
        )
        .unwrap();
        assert_eq!(
            dkg_initial_transcript(&ceremony).as_bytes().to_vec(),
            bytes(&inputs["initial_transcript"])
        );
        let transcript = DkgTranscript {
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
        match dkg_verify_transcript(&ceremony, &transcript, &signers) {
            Ok(output) => assert_eq!(output_json(&output), case["outputs"], "{}", case["name"]),
            Err(error) => assert_eq!(format!("{error:?}"), case["error"].as_str().unwrap()),
        }
    }
}

#[test]
fn pedersen_generator_is_the_frozen_hash_to_g2_output() {
    let fixture: Value =
        serde_json::from_str(include_str!("../vectors/v1/primitives.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "pedersen_h")
        .unwrap();
    assert_eq!(
        hex::encode(pedersen_h().encode()),
        case["outputs"]["point"].as_str().unwrap()
    );
    // The relay's commitment check: every member's Pedersen relation holds.
    let run = honest(2, 3, 0x58);
    let deal = DkgDeal::decode(&run.transcript.rounds[0].messages[0].bytes[41..]).unwrap();
    let opened_pair = opened(
        &run.fixture,
        &run.transcript.rounds[0].messages[0].bytes[41..],
        1,
        2,
    );
    let x = Scalar::from_u64(2);
    let expected = deal
        .commitments
        .iter()
        .rev()
        .fold(G2::identity(), |acc, c| acc.mul(&x).add(c));
    assert_eq!(
        G2::generator()
            .mul(&opened_pair.value)
            .add(&pedersen_h().mul(&opened_pair.blinding)),
        expected
    );
}

#[test]
fn certificate_binding_uses_the_dkg_output() {
    let run = honest(2, 3, 0x59);
    let output = agreed(&run, &[1, 2, 3]);
    let f = &run.fixture;
    let body = CertificateBody::genesis(
        &f.signers.anchor(),
        &f.ceremony,
        &output.public,
        &output.transcript_hash,
    )
    .unwrap();
    let cert = verify_certificate(
        &f.signers.anchor(),
        &crate::cert::tests::sign(body, &f.signers),
        &f.signers,
    )
    .unwrap();
    let Run { outcomes, .. } = run;
    for (i, outcome) in outcomes {
        let (candidate, _) = outcome.unwrap();
        let share = KeyShare::bind(candidate, &cert).unwrap();
        assert_eq!(share.index(), idx(i));
    }
}
