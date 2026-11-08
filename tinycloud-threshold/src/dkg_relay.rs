//! Test-only owner relay driving real member states over signed closed rounds. Details: TC-2220
//!
//! Liveness scenarios deliver every honest message. Omissions and substitutions
//! below are explicit failure cases chosen by each test, not a broadcast model.

use std::collections::{BTreeMap, BTreeSet};

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde_json::{json, Value};

use crate::{
    ceremony::{
        ceremony_message_body, round_closure_body, round_closure_preimage, tests::Signers,
        AuthorizedCeremony, CeremonyKind, CeremonyRecipient, CeremonyStatement, ClosedRound,
        Decode, DidSignatureVerifier, MemberCohort, SignedStatement,
    },
    cert::{
        verify_certificate, CandidateShare, CertificateBody, SignedCertificate, VerifiedCertificate,
    },
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

/// Which owner-authorized ceremony kind a scenario runs under. Both use the
/// same GJKR rounds and genesis budget; a re-key is pinned to a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Setup {
    Genesis,
    Rekey,
}

/// Owner, member DIDs, Ed25519 dev keys and a genesis or re-key ceremony with
/// real recipient keys.
pub(crate) struct Fixture {
    pub(crate) signers: Signers,
    pub(crate) ceremony: AuthorizedCeremony,
    pub(crate) statement: SignedStatement,
    /// The pinned certificate a re-key ceremony succeeds; absent at genesis.
    pub(crate) current: Option<VerifiedCertificate>,
    pub(crate) seed: u8,
}

/// Recipient directory with HPKE keys regenerated from `seed`.
fn recipients(n: u16, seed: u8) -> Vec<CeremonyRecipient> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    (1..=n)
        .map(|i| CeremonyRecipient {
            index: idx(i),
            node: Signers::did(i as u8),
            hpke_public_key: CeremonyHpkeSecretKey::generate(&mut rng).1.encode(),
        })
        .collect()
}

/// A re-key statement succeeding `current`, recipients did 1..=n.
pub(crate) fn rekey_statement(
    signers: &Signers,
    current: &VerifiedCertificate,
    t: u16,
    n: u16,
    seed: u8,
) -> SignedStatement {
    let context = current.key_context();
    signers.statement(&CeremonyStatement {
        kind: CeremonyKind::Rekey,
        id: CeremonyId::new([seed; 32]),
        network: signers.anchor().network,
        owner: Signers::did(0),
        current: Some(current.digest()),
        threshold: Threshold::new(t, n).unwrap(),
        rekey: context.rekey().checked_next().unwrap(),
        epoch: context.epoch().checked_next().unwrap(),
        recipients: recipients(n, seed),
    })
}

/// A re-key ceremony pinned to `current`, as a node would authorize it.
pub(crate) fn rekey_fixture_on(current: &VerifiedCertificate, t: u16, n: u16, seed: u8) -> Fixture {
    let signers = Signers::new();
    let statement = rekey_statement(&signers, current, t, n, seed);
    let ceremony = AuthorizedCeremony::verify_for(current, &statement, &signers).unwrap();
    Fixture {
        signers,
        ceremony,
        statement,
        current: Some(current.clone()),
        seed,
    }
}

pub(crate) fn genesis_statement(signers: &Signers, t: u16, n: u16, seed: u8) -> SignedStatement {
    signers.statement(&CeremonyStatement {
        kind: CeremonyKind::Genesis,
        id: CeremonyId::new([seed; 32]),
        network: signers.anchor().network,
        owner: Signers::did(0),
        current: None,
        threshold: Threshold::new(t, n).unwrap(),
        rekey: RekeyCounter::new(0),
        epoch: Epoch::new(0),
        recipients: recipients(n, seed),
    })
}

/// Statement for `setup`; a re-key succeeds the 2-of-3 test-dealer genesis.
pub(crate) fn statement_in(
    setup: Setup,
    t: u16,
    n: u16,
    seed: u8,
) -> (Signers, SignedStatement, Option<VerifiedCertificate>) {
    let signers = Signers::new();
    match setup {
        Setup::Genesis => {
            let signed = genesis_statement(&signers, t, n, seed);
            (signers, signed, None)
        }
        Setup::Rekey => {
            let (current, _) = crate::cert::tests::genesis(&signers);
            let signed = rekey_statement(&signers, &current, t, n, seed);
            (signers, signed, Some(current))
        }
    }
}

/// Verify the statement as the ceremony of its setup, the way a node would.
pub(crate) fn authorize(
    setup: Setup,
    signers: &Signers,
    statement: &SignedStatement,
) -> Result<AuthorizedCeremony, Error> {
    match setup {
        Setup::Genesis => AuthorizedCeremony::verify_genesis(&signers.anchor(), statement, signers),
        Setup::Rekey => {
            let (current, _) = crate::cert::tests::genesis(signers);
            AuthorizedCeremony::verify_for(&current, statement, signers)
        }
    }
}

pub(crate) fn fixture_in(setup: Setup, t: u16, n: u16, seed: u8) -> Fixture {
    let (signers, statement, current) = statement_in(setup, t, n, seed);
    let ceremony = authorize(setup, &signers, &statement).unwrap();
    Fixture {
        signers,
        ceremony,
        statement,
        current,
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

pub(crate) fn run_in(
    setup: Setup,
    t: u16,
    n: u16,
    seed: u8,
    tamper: impl FnMut(&mut Outbox),
) -> Run {
    let fixture = fixture_in(setup, t, n, seed);
    let signers = Signers::new();
    drive(fixture, &signers, tamper)
}

pub(crate) fn run(t: u16, n: u16, seed: u8, tamper: impl FnMut(&mut Outbox)) -> Run {
    run_in(Setup::Genesis, t, n, seed, tamper)
}

pub(crate) fn honest_in(setup: Setup, t: u16, n: u16, seed: u8) -> Run {
    run_in(setup, t, n, seed, |_| {})
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

pub(crate) fn constants(out: &Outbox, into: &mut BTreeMap<u16, [u8; 96]>) {
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

mod genesis_scenarios {
    const SETUP: super::Setup = super::Setup::Genesis;
    include!("dkg_scenarios.rs");
}

mod rekey_scenarios {
    const SETUP: super::Setup = super::Setup::Rekey;
    include!("dkg_scenarios.rs");
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
    let mut inputs = json!({
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
    if let Some(current) = &run.fixture.current {
        let body = current.body();
        inputs["current_certificate"] = json!({
            "body": hex::encode(body.encode()),
            "owner_signature": hex::encode(run.fixture.signers.sign(&current.anchor().expected_owner, &body.owner_statement())),
        });
    }
    match run.verify() {
        Ok(output) => {
            json!({"name": name, "description": description, "operation": "dkg_verify_transcript", "inputs": inputs, "outputs": output_json(&output)})
        }
        Err(error) => {
            json!({"name": name, "description": description, "operation": "dkg_verify_transcript", "inputs": inputs, "error": format!("{error:?}")})
        }
    }
}

fn vectors(setup: Setup) -> Value {
    let seed = |genesis: u8| match setup {
        Setup::Genesis => genesis,
        Setup::Rekey => genesis + 0x30,
    };
    let kind = match setup {
        Setup::Genesis => "genesis",
        Setup::Rekey => "rekey",
    };
    let honest_run = honest_in(setup, 2, 3, seed(0x61));
    let selective = run_in(setup, 2, 3, seed(0x62), |out| {
        if out.round() == 4 {
            let forged = vanishing_feldman(&out.payload(3), &[1]);
            out.replace(3, &forged);
        }
    });
    let two_faulty = run_in(setup, 3, 5, seed(0x63), |out| match out.round() {
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
    let answers = run_in(setup, 3, 5, seed(0x64), |out| match out.round() {
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
    let insufficient = run_in(setup, 2, 3, seed(0x65), |out| match out.round() {
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
    let unqualified = run_in(setup, 2, 3, seed(0x66), |out| {
        if out.round() == 1 {
            out.remove(2);
            out.remove(3);
        }
    });
    let three_of_four = run_in(setup, 3, 4, seed(0x67), |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(4), &[4]);
            out.replace(4, &forged);
        }
        6 => out.remove(4),
        _ => {}
    });
    let cases = vec![
        case(&format!("{kind}_2of3"), "All members follow the protocol; R5 is empty and no R6 round exists.", &honest_run),
        case(&format!("{kind}_2of3_selective_extraction"), "Dealer 3's R4 vector passes only member 1's check; member 2's R5 complaint leads to R6 reconstruction of dealer 3.", &selective),
        case(&format!("{kind}_3of5_two_faulty"), "Dealer 5's R4 passes only at members 4 and 5; member 4 files an invalid R5 complaint; members 4 and 5 send no R6.", &two_faulty),
        case(&format!("{kind}_3of5_answers_and_disqualification"), "Dealer 1's bad value to member 2 is answered; dealer 4 sends two R1 messages; dealer 5 does not answer member 1's complaint.", &answers),
        case("insufficient_reconstruction_values", "Only member 1 sends R6 for faulted dealer 3.", &insufficient),
        case("insufficient_qualified_dealers", "Only dealer 1 publishes R1.", &unqualified),
        case(&format!("{kind}_3of4_one_faulty"), "Dealer 4's R4 passes only its own check; members 1-3 complain in R5; member 4 sends no R6 and members 1-3 reconstruct dealer 4.", &three_of_four),
    ];
    let ceremony_seeds = [0x61u8, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67].map(seed);
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
        "spec_sections": match setup {
            Setup::Genesis => json!(["3.2", "3.3", "3.7", "3.10", "S0.3 DKG appendix"]),
            Setup::Rekey => json!(["3.2", "3.3", "3.7", "3.9", "3.10", "S0.3 DKG appendix", "S0.5 re-key appendix"]),
        },
        "encoding": "hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed",
        "seeds": {"ceremonies": ceremony_seeds},
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

/// Regenerate the document, compare it byte for byte with the published file,
/// then replay every case from the published bytes alone.
fn dkg_vector_file(setup: Setup, name: &str) {
    let encoded = format!(
        "{}\n",
        serde_json::to_string_pretty(&vectors(setup)).unwrap()
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
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
        let ceremony = match setup {
            Setup::Genesis => {
                assert!(inputs.get("current_certificate").is_none());
                AuthorizedCeremony::verify_genesis(
                    &signers.anchor(),
                    &statement(&inputs["ceremony"]),
                    &signers,
                )
                .unwrap()
            }
            Setup::Rekey => {
                let current = verify_certificate(
                    &signers.anchor(),
                    &SignedCertificate {
                        body: CertificateBody::decode(&bytes(
                            &inputs["current_certificate"]["body"],
                        ))
                        .unwrap(),
                        owner_signature: bytes(&inputs["current_certificate"]["owner_signature"]),
                    },
                    &signers,
                )
                .unwrap();
                AuthorizedCeremony::verify_for(&current, &statement(&inputs["ceremony"]), &signers)
                    .unwrap()
            }
        };
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
fn dkg_vectors_regenerate_byte_for_byte_and_replay() {
    dkg_vector_file(Setup::Genesis, "vectors/v1/dkg-genesis.json");
}

#[test]
fn rekey_dkg_vectors_regenerate_byte_for_byte_and_replay() {
    dkg_vector_file(Setup::Rekey, "vectors/v1/dkg-rekey.json");
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
