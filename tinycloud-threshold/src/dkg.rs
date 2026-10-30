//! Genesis GJKR New-DKG over owner-closed rounds. Details: TC-2220
//!
//! Members consume owner-closed rounds in a fixed order through consume-self
//! states; `dkg_verify_transcript` applies the same public rules to the
//! authenticated round records. Liveness under the genesis budget assumes the
//! trusted owner relay delivers every conforming member's message.

use core::fmt;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::{
    ceremony::{
        ceremony_message_body, AuthorizedCeremony, CeremonyKind, ClosedRound, Decode,
        DidSignatureVerifier, MemberCohort, RoundMessage, SignedStatement,
    },
    cert::{CandidateShare, PublicMaterial},
    curve::{hash_g2, Scalar, G2},
    dst,
    encoding::{Decoder, Encoder},
    error::Error,
    ids::{MemberIndex, Threshold, TranscriptHash},
    poly,
    seal::{
        open_dealing, seal_dealing, CeremonyHpkePublicKey, CeremonyHpkeSecretKey, DealingContext,
        SealedDealing,
    },
};

/// Initial transcript link tag; not part of the frozen S0.1 domain table. Details: TC-2220
pub(crate) const DKG_START: &[u8] = b"TC-THRESHOLD-V1-DKG-START";
const PEDERSEN_H_MESSAGE: &[u8] = b"pedersen-h";
const VERSION: u8 = 1;
const MAX_ENTRIES: u16 = 16;
const MESSAGE_CAP: usize = 65_536;
const TRANSCRIPT_CAP: usize = 4_194_304;
const PLAINTEXT_LEN: usize = 64;

const DEAL: u8 = 1;
const COMPLAIN: u8 = 2;
const ANSWER: u8 = 3;
const EXTRACT: u8 = 4;
const EXTRACTION_COMPLAINTS: u8 = 5;
const RECONSTRUCT: u8 = 6;

/// `TH(DKG_START, authorized_ceremony_digest)`, the link preceding closed R1. Details: TC-2220
pub fn dkg_initial_transcript(c: &AuthorizedCeremony) -> TranscriptHash {
    TranscriptHash::new(dst::tagged_hash(DKG_START, &c.digest()))
}

// ------------------------------------------------------------------ payloads

/// A scalar value and its Pedersen blinding value at one member index. Details: TC-2220
pub(crate) struct SharePair {
    pub(crate) value: Scalar,
    pub(crate) blinding: Scalar,
}

impl SharePair {
    fn duplicate(&self) -> Self {
        let zero = Scalar::from_u64(0);
        Self {
            value: self.value.add(&zero),
            blinding: self.blinding.add(&zero),
        }
    }

    fn encode_into(&self, e: &mut Encoder) {
        e.fixed(Zeroizing::new(self.value.to_bytes()).as_slice());
        e.fixed(Zeroizing::new(self.blinding.to_bytes()).as_slice());
    }

    fn decode_from(d: &mut Decoder) -> Result<Self, Error> {
        let value = Zeroizing::new(d.fixed::<32>()?);
        let blinding = Zeroizing::new(d.fixed::<32>()?);
        Ok(Self {
            value: Scalar::from_bytes(value.as_slice())?,
            blinding: Scalar::from_bytes(blinding.as_slice())?,
        })
    }
}

impl fmt::Debug for SharePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharePair([REDACTED])")
    }
}

fn version(d: &mut Decoder) -> Result<(), Error> {
    if d.u8()? != VERSION {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn count(d: &mut Decoder) -> Result<usize, Error> {
    let count = d.u16()?;
    if count > MAX_ENTRIES {
        return Err(Error::LimitExceeded);
    }
    Ok(usize::from(count))
}

fn index_after(d: &mut Decoder, previous: &mut Option<MemberIndex>) -> Result<MemberIndex, Error> {
    let index = MemberIndex::new(d.u16()?)?;
    if previous.is_some_and(|p| index <= p) {
        return Err(Error::InvalidEncoding);
    }
    *previous = Some(index);
    Ok(index)
}

fn encode_points(e: &mut Encoder, points: &[G2]) {
    e.u16(points.len() as u16);
    for point in points {
        e.fixed(&point.encode());
    }
}

fn decode_points(d: &mut Decoder) -> Result<Vec<G2>, Error> {
    let count = count(d)?;
    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        points.push(G2::decode(&d.fixed::<96>()?, true)?);
    }
    Ok(points)
}

fn encode_pairs(entries: &[(MemberIndex, SharePair)]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u8(VERSION);
    e.u16(entries.len() as u16);
    for (index, pair) in entries {
        e.u16(index.get());
        pair.encode_into(&mut e);
    }
    e.finish()
}

fn decode_pairs(bytes: &[u8]) -> Result<Vec<(MemberIndex, SharePair)>, Error> {
    let mut d = Decoder::new(bytes)?;
    version(&mut d)?;
    let count = count(&mut d)?;
    let mut entries = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let index = index_after(&mut d, &mut previous)?;
        entries.push((index, SharePair::decode_from(&mut d)?));
    }
    d.finish()?;
    Ok(entries)
}

/// R1: Pedersen commitments and one sealed dealing per recipient. Details: TC-2220
#[derive(Debug)]
pub struct DkgDeal {
    pub(crate) commitments: Vec<G2>,
    pub(crate) dealings: Vec<(MemberIndex, SealedDealing)>,
}

impl DkgDeal {
    /// `01 || t:u16 || C_k:96… || n:u16 || [(recipient:u16 || lp(sealed))]`. Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(VERSION);
        encode_points(&mut e, &self.commitments);
        e.u16(self.dealings.len() as u16);
        for (index, dealing) in &self.dealings {
            e.u16(index.get());
            e.lp(&dealing.encode());
        }
        e.finish()
    }
}

impl Decode for DkgDeal {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        version(&mut d)?;
        let commitments = decode_points(&mut d)?;
        let count = count(&mut d)?;
        let mut dealings = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let index = index_after(&mut d, &mut previous)?;
            dealings.push((index, SealedDealing::decode(d.lp(MESSAGE_CAP)?)?));
        }
        d.finish()?;
        Ok(Self {
            commitments,
            dealings,
        })
    }
}

/// R2: dealers whose dealing failed for the sender. Details: TC-2220
#[derive(Debug)]
pub struct DkgComplaints {
    pub(crate) dealers: Vec<MemberIndex>,
}

impl DkgComplaints {
    /// `01 || count:u16 || [dealer:u16]`, strictly increasing. Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(VERSION);
        e.u16(self.dealers.len() as u16);
        for dealer in &self.dealers {
            e.u16(dealer.get());
        }
        e.finish()
    }
}

impl Decode for DkgComplaints {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        version(&mut d)?;
        let count = count(&mut d)?;
        let mut dealers = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            dealers.push(index_after(&mut d, &mut previous)?);
        }
        d.finish()?;
        Ok(Self { dealers })
    }
}

/// R3: a dealer's published pairs for complaining recipients. Details: TC-2220
#[derive(Debug)]
pub struct DkgAnswers {
    pub(crate) answers: Vec<(MemberIndex, SharePair)>,
}

impl DkgAnswers {
    /// `01 || count:u16 || [(recipient:u16 || value:32 || blinding:32)]`. Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        encode_pairs(&self.answers)
    }
}

impl Decode for DkgAnswers {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            answers: decode_pairs(bytes)?,
        })
    }
}

/// R4: a qualified dealer's Feldman coefficients. Details: TC-2220
#[derive(Debug)]
pub struct DkgFeldman {
    pub(crate) commitments: Vec<G2>,
}

impl DkgFeldman {
    /// `01 || t:u16 || A_k:96…`. Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(VERSION);
        encode_points(&mut e, &self.commitments);
        e.finish()
    }
}

impl Decode for DkgFeldman {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        version(&mut d)?;
        let commitments = decode_points(&mut d)?;
        d.finish()?;
        Ok(Self { commitments })
    }
}

/// R5: the sender's Pedersen-valid, Feldman-invalid pairs by dealer. Details: TC-2220
#[derive(Debug)]
pub struct DkgExtractionComplaints {
    pub(crate) complaints: Vec<(MemberIndex, SharePair)>,
}

impl DkgExtractionComplaints {
    /// Same layout as R3, keyed by dealer. Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        encode_pairs(&self.complaints)
    }
}

impl Decode for DkgExtractionComplaints {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            complaints: decode_pairs(bytes)?,
        })
    }
}

/// R6: the sender's pairs for every reconstructed dealer. Details: TC-2220
#[derive(Debug)]
pub struct DkgReconstruction {
    pub(crate) values: Vec<(MemberIndex, SharePair)>,
}

impl DkgReconstruction {
    /// Same layout as R3, keyed by dealer. Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        encode_pairs(&self.values)
    }
}

impl Decode for DkgReconstruction {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            values: decode_pairs(bytes)?,
        })
    }
}

/// An unsigned member envelope for one round; the node signs `signing_preimage`. Details: TC-2220
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgMessage {
    round: u8,
    body: Vec<u8>,
}

impl DkgMessage {
    fn new(
        c: &AuthorizedCeremony,
        round: u8,
        me: MemberIndex,
        payload: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            round,
            body: ceremony_message_body(c, round, MemberCohort::Recipients, me, payload)?,
        })
    }
    /// Round number of this envelope. Details: TC-2220
    pub fn round(&self) -> u8 {
        self.round
    }
    /// Exact canonical member envelope bytes. Details: TC-2220
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// `TH(CEREMONY_MSG, body)`, signed with the member's node key. Details: TC-2220
    pub fn signing_preimage(&self) -> Vec<u8> {
        dst::tagged_hash(dst::CEREMONY_MSG, &self.body).to_vec()
    }
}

// --------------------------------------------------------------- outputs

/// Why a dealer is outside QUAL. Details: TC-2220
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisqualifyReason {
    /// No R1 message in closed R1. Details: TC-2220
    MissingDeal,
    /// R1 failed to decode or had the wrong commitment count or recipient set. Details: TC-2220
    MalformedDeal,
    /// Conflicting authenticated content in R1, R2 or R3. Details: TC-2220
    Equivocated {
        /// Round of the conflicting messages. Details: TC-2220
        round: u8,
    },
    /// At least t distinct recipients complained. Details: TC-2220
    Complaints,
    /// A required answer is absent from closed R3. Details: TC-2220
    MissingAnswer,
    /// A published answer fails the Pedersen relation. Details: TC-2220
    InvalidAnswer,
}

/// Public outcome shared by members and the transcript verifier. Details: TC-2220
#[derive(Clone, Debug)]
pub struct DkgOutput {
    /// Summed Feldman polynomial, master key and public shares. Details: TC-2220
    pub public: PublicMaterial,
    /// Qualified dealers fixed after closed R3. Details: TC-2220
    pub qual: BTreeSet<MemberIndex>,
    /// Dealers outside QUAL with the first applicable reason. Details: TC-2220
    pub disqualified: BTreeMap<MemberIndex, DisqualifyReason>,
    /// QUAL dealers whose Feldman coefficients were recovered from R6. Details: TC-2220
    pub reconstructed: BTreeSet<MemberIndex>,
    /// Transcript link after the last closed round. Details: TC-2220
    pub transcript_hash: TranscriptHash,
}

/// One owner closure and its exact ordered member statements. Details: TC-2220
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgRoundRecord {
    /// Signed owner closure. Details: TC-2220
    pub closure: SignedStatement,
    /// Member statements in owner order. Details: TC-2220
    pub messages: Vec<SignedStatement>,
}

/// Raw signed rounds R1..R5, plus R6 when reconstruction is required. Details: TC-2220
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgTranscript {
    /// Round records in order. Details: TC-2220
    pub rounds: Vec<DkgRoundRecord>,
}

// ------------------------------------------------------------ public rules

enum Sent<'a, M> {
    One(&'a RoundMessage<M>),
    Conflicting,
}
impl<M> Clone for Sent<'_, M> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<M> Copy for Sent<'_, M> {}

/// Group authenticated messages by sender; identical envelope bytes are one message.
fn by_sender<M>(round: &ClosedRound<M>) -> BTreeMap<MemberIndex, Sent<'_, M>> {
    let mut senders = BTreeMap::new();
    for message in round.messages() {
        match senders.entry(message.member()) {
            Entry::Vacant(slot) => {
                slot.insert(Sent::One(message));
            }
            Entry::Occupied(mut slot) => {
                if let Sent::One(first) = *slot.get() {
                    if first.statement().bytes != message.statement().bytes {
                        slot.insert(Sent::Conflicting);
                    }
                }
            }
        }
    }
    senders
}

fn decoded<'a, M>(sent: Option<Sent<'a, M>>) -> Option<&'a M> {
    match sent {
        Some(Sent::One(message)) => message.payload().as_ref().ok(),
        _ => None,
    }
}

fn evaluate_points(points: &[G2], x: MemberIndex) -> G2 {
    let x = Scalar::from_u64(u64::from(x.get()));
    points
        .iter()
        .rev()
        .fold(G2::identity(), |acc, point| acc.mul(&x).add(point))
}

fn pedersen_h() -> G2 {
    hash_g2(PEDERSEN_H_MESSAGE, dst::PEDERSEN_H)
}

fn commitment_hash(points: &[G2]) -> [u8; 32] {
    let mut e = Encoder::new();
    encode_points(&mut e, points);
    dst::tagged_hash(dst::COMMITMENTS, &e.finish())
}

fn times_linear(polynomial: &[Scalar], root: &Scalar) -> Vec<Scalar> {
    let zero = Scalar::from_u64(0);
    let below = core::iter::once(&zero).chain(polynomial.iter());
    let at = polynomial.iter().map(Some).chain(core::iter::once(None));
    below
        .zip(at)
        .map(|(below, at)| match at {
            Some(at) => below.sub(&at.mul(root)),
            None => below.add(&zero),
        })
        .collect()
}

/// Coefficients of the unique polynomial through the supplied distinct points.
fn interpolate(points: &[(Scalar, &Scalar)]) -> Result<Vec<Scalar>, Error> {
    let mut coefficients: Vec<Scalar> = points.iter().map(|_| Scalar::from_u64(0)).collect();
    for (m, (xm, ym)) in points.iter().enumerate() {
        let mut basis = vec![Scalar::from_u64(1)];
        let mut denominator = Scalar::from_u64(1);
        for (l, (xl, _)) in points.iter().enumerate() {
            if l != m {
                basis = times_linear(&basis, xl);
                denominator = denominator.mul(&xm.sub(xl));
            }
        }
        let scale = ym.mul(&denominator.inverse()?);
        for (coefficient, b) in coefficients.iter_mut().zip(&basis) {
            *coefficient = coefficient.add(&b.mul(&scale));
        }
    }
    Ok(coefficients)
}

/// Public ceremony state; members and the verifier apply identical rules.
struct Public {
    ceremony: AuthorizedCeremony,
    h: G2,
    previous: TranscriptHash,
    /// Valid R1 commitments of dealers not yet disqualified; QUAL after R3.
    commitments: BTreeMap<MemberIndex, Vec<G2>>,
    disqualified: BTreeMap<MemberIndex, DisqualifyReason>,
    complaints: BTreeMap<MemberIndex, BTreeSet<MemberIndex>>,
    equivocated: BTreeSet<MemberIndex>,
    feldman: BTreeMap<MemberIndex, Vec<G2>>,
    faulted: BTreeSet<MemberIndex>,
}

impl Public {
    fn new(c: &AuthorizedCeremony) -> Result<Self, Error> {
        if c.kind() != CeremonyKind::Genesis {
            return Err(Error::InvalidCeremony);
        }
        c.threshold().check_genesis_budget()?;
        Ok(Self {
            ceremony: c.clone(),
            h: pedersen_h(),
            previous: dkg_initial_transcript(c),
            commitments: BTreeMap::new(),
            disqualified: BTreeMap::new(),
            complaints: BTreeMap::new(),
            equivocated: BTreeSet::new(),
            feldman: BTreeMap::new(),
            faulted: BTreeSet::new(),
        })
    }

    fn threshold(&self) -> Threshold {
        self.ceremony.threshold()
    }

    fn t(&self) -> usize {
        usize::from(self.threshold().t())
    }

    fn members(&self) -> impl Iterator<Item = MemberIndex> + '_ {
        self.ceremony.recipients().iter().map(|r| r.index)
    }

    fn in_cohort(&self, index: MemberIndex) -> bool {
        index.get() <= self.threshold().n()
    }

    /// The closed round must belong to this ceremony, phase and exact previous link.
    fn bind<M>(&mut self, round: &ClosedRound<M>, expected: u8) -> Result<(), Error> {
        if round.ceremony_digest() != self.ceremony.digest()
            || round.round() != expected
            || round.previous_hash() != self.previous
        {
            return Err(Error::InvalidRound);
        }
        self.previous = round.transcript_hash();
        Ok(())
    }

    fn pedersen(&self, pair: &SharePair, commitments: &[G2], x: MemberIndex) -> bool {
        G2::generator()
            .mul(&pair.value)
            .add(&self.h.mul(&pair.blinding))
            == evaluate_points(commitments, x)
    }

    fn deals<'r>(
        &mut self,
        r1: &'r ClosedRound<DkgDeal>,
    ) -> Result<BTreeMap<MemberIndex, &'r DkgDeal>, Error> {
        self.bind(r1, DEAL)?;
        let senders = by_sender(r1);
        let t = self.t();
        let n = self.threshold().n();
        let mut valid = BTreeMap::new();
        for i in self.members().collect::<Vec<_>>() {
            let reason = match senders.get(&i).copied() {
                None => Some(DisqualifyReason::MissingDeal),
                Some(Sent::Conflicting) => Some(DisqualifyReason::Equivocated { round: DEAL }),
                Some(Sent::One(message)) => match message.payload() {
                    Ok(deal)
                        if deal.commitments.len() == t
                            && deal.dealings.iter().map(|(j, _)| j.get()).eq(1..=n) =>
                    {
                        self.commitments.insert(i, deal.commitments.clone());
                        valid.insert(i, deal);
                        None
                    }
                    _ => Some(DisqualifyReason::MalformedDeal),
                },
            };
            if let Some(reason) = reason {
                self.disqualified.insert(i, reason);
            }
        }
        Ok(valid)
    }

    fn complaints(&mut self, r2: &ClosedRound<DkgComplaints>) -> Result<(), Error> {
        self.bind(r2, COMPLAIN)?;
        for (j, sent) in by_sender(r2) {
            match sent {
                Sent::Conflicting => {
                    self.equivocated.insert(j);
                }
                Sent::One(message) => {
                    let Ok(list) = message.payload() else {
                        continue;
                    };
                    if !list.dealers.iter().all(|i| self.in_cohort(*i)) {
                        continue;
                    }
                    for i in list.dealers.iter().filter(|i| **i != j) {
                        self.complaints.entry(*i).or_default().insert(j);
                    }
                }
            }
        }
        Ok(())
    }

    /// Fix QUAL; return valid required answers addressed to `recipient`.
    fn answers(
        &mut self,
        r3: &ClosedRound<DkgAnswers>,
        recipient: Option<MemberIndex>,
    ) -> Result<BTreeMap<MemberIndex, SharePair>, Error> {
        self.bind(r3, ANSWER)?;
        let senders = by_sender(r3);
        let empty = BTreeSet::new();
        let mut replacements = BTreeMap::new();
        let mut removed = BTreeMap::new();
        for (i, commitments) in &self.commitments {
            let required = self.complaints.get(i).unwrap_or(&empty);
            let answers = decoded(senders.get(i).copied())
                .filter(|a| a.answers.iter().all(|(j, _)| self.in_cohort(*j)));
            let reason = if self.equivocated.contains(i) {
                Some(DisqualifyReason::Equivocated { round: COMPLAIN })
            } else if matches!(senders.get(i), Some(Sent::Conflicting)) {
                Some(DisqualifyReason::Equivocated { round: ANSWER })
            } else if required.len() >= self.t() {
                Some(DisqualifyReason::Complaints)
            } else if answers.is_some_and(|a| {
                a.answers
                    .iter()
                    .any(|(j, pair)| !self.pedersen(pair, commitments, *j))
            }) {
                Some(DisqualifyReason::InvalidAnswer)
            } else if !required
                .iter()
                .all(|j| answers.is_some_and(|a| a.answers.iter().any(|(k, _)| k == j)))
            {
                Some(DisqualifyReason::MissingAnswer)
            } else {
                None
            };
            match reason {
                Some(reason) => {
                    removed.insert(*i, reason);
                }
                None => {
                    if let (Some(me), Some(answers)) = (recipient, answers) {
                        if required.contains(&me) {
                            if let Some((_, pair)) = answers.answers.iter().find(|(j, _)| *j == me)
                            {
                                replacements.insert(*i, pair.duplicate());
                            }
                        }
                    }
                }
            }
        }
        for (i, reason) in removed {
            self.commitments.remove(&i);
            self.disqualified.insert(i, reason);
        }
        if self.commitments.len() < self.t() {
            return Err(Error::InsufficientQualified);
        }
        Ok(replacements)
    }

    fn qual(&self) -> BTreeSet<MemberIndex> {
        self.commitments.keys().copied().collect()
    }

    fn extract(&mut self, r4: &ClosedRound<DkgFeldman>) -> Result<(), Error> {
        self.bind(r4, EXTRACT)?;
        let senders = by_sender(r4);
        let t = self.t();
        for i in self.qual() {
            match decoded(senders.get(&i).copied()) {
                Some(feldman) if feldman.commitments.len() == t => {
                    self.feldman.insert(i, feldman.commitments.clone());
                }
                _ => {
                    self.faulted.insert(i);
                }
            }
        }
        Ok(())
    }

    /// Apply closed R5; return whether R6 is required.
    fn barrier(&mut self, r5: &ClosedRound<DkgExtractionComplaints>) -> Result<bool, Error> {
        self.bind(r5, EXTRACTION_COMPLAINTS)?;
        let senders = by_sender(r5);
        let mut upheld = BTreeSet::new();
        for (j, sent) in &senders {
            let Some(list) = decoded(Some(*sent)) else {
                continue;
            };
            for (i, pair) in &list.complaints {
                if i == j || self.faulted.contains(i) {
                    continue;
                }
                let (Some(commitments), Some(feldman)) =
                    (self.commitments.get(i), self.feldman.get(i))
                else {
                    continue;
                };
                if self.pedersen(pair, commitments, *j)
                    && G2::generator().mul(&pair.value) != evaluate_points(feldman, *j)
                {
                    upheld.insert(*i);
                }
            }
        }
        self.faulted.extend(upheld);
        Ok(!self.faulted.is_empty())
    }

    fn reconstruct(&mut self, r6: &ClosedRound<DkgReconstruction>) -> Result<(), Error> {
        self.bind(r6, RECONSTRUCT)?;
        let senders = by_sender(r6);
        let t = self.t();
        for i in self.faulted.clone() {
            let commitments = self.commitments.get(&i).ok_or(Error::InvalidRound)?;
            let points: Vec<(Scalar, &Scalar)> = senders
                .iter()
                .filter_map(|(m, sent)| {
                    let list = decoded(Some(*sent))?;
                    let (_, pair) = list.values.iter().find(|(k, _)| *k == i)?;
                    self.pedersen(pair, commitments, *m)
                        .then(|| (Scalar::from_u64(u64::from(m.get())), &pair.value))
                })
                .take(t)
                .collect();
            if points.len() < t {
                return Err(Error::InsufficientRecovery);
            }
            let coefficients = interpolate(&points)?;
            let recovered = coefficients
                .iter()
                .map(|a| G2::generator().mul(a))
                .collect();
            self.feldman.insert(i, recovered);
        }
        Ok(())
    }

    fn output(&self) -> Result<DkgOutput, Error> {
        let mut sums: Vec<G2> = (0..self.t()).map(|_| G2::identity()).collect();
        for i in self.commitments.keys() {
            let feldman = self.feldman.get(i).ok_or(Error::InvalidRound)?;
            for (sum, coefficient) in sums.iter_mut().zip(feldman) {
                *sum = sum.add(coefficient);
            }
        }
        Ok(DkgOutput {
            public: PublicMaterial::from_commitments(self.threshold(), sums)?,
            qual: self.qual(),
            disqualified: self.disqualified.clone(),
            reconstructed: self.faulted.clone(),
            transcript_hash: self.previous,
        })
    }
}

// ------------------------------------------------------------ member states

struct Polynomial {
    values: Vec<Scalar>,
    blinding: Vec<Scalar>,
}

impl Polynomial {
    fn at(&self, x: MemberIndex) -> SharePair {
        let x = Scalar::from_u64(u64::from(x.get()));
        SharePair {
            value: poly::evaluate(&self.values, &x),
            blinding: poly::evaluate(&self.blinding, &x),
        }
    }
}

macro_rules! redacted {
    ($($name:ident),*) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )*};
}

/// Holds this member's polynomials and recipient key until closed R1. Details: TC-2220
pub struct DkgDealt {
    public: Public,
    me: MemberIndex,
    hpke: CeremonyHpkeSecretKey,
    polynomial: Polynomial,
}

/// Holds the polynomials and private pairs until closed R2. Details: TC-2220
pub struct DkgComplained {
    public: Public,
    me: MemberIndex,
    polynomial: Polynomial,
    pairs: BTreeMap<MemberIndex, SharePair>,
}

/// Holds the polynomials and private pairs until closed R3 fixes QUAL. Details: TC-2220
pub struct DkgAnswered {
    public: Public,
    me: MemberIndex,
    polynomial: Polynomial,
    pairs: BTreeMap<MemberIndex, SharePair>,
}

/// Holds one private pair per QUAL dealer until closed R4. Details: TC-2220
pub struct DkgExtracting {
    public: Public,
    me: MemberIndex,
    pairs: BTreeMap<MemberIndex, SharePair>,
}

/// Holds the private pairs until the common closed R5. Details: TC-2220
pub struct DkgAwaitingBarrier {
    public: Public,
    me: MemberIndex,
    pairs: BTreeMap<MemberIndex, SharePair>,
}

/// Holds the private pairs until closed R6. Details: TC-2220
pub struct DkgReconstructing {
    public: Public,
    me: MemberIndex,
    pairs: BTreeMap<MemberIndex, SharePair>,
}

redacted!(
    DkgDealt,
    DkgComplained,
    DkgAnswered,
    DkgExtracting,
    DkgAwaitingBarrier,
    DkgReconstructing
);

/// The outcome of consuming the common closed R5. Details: TC-2220
#[derive(Debug)]
pub enum AfterBarrier {
    /// No extraction fault or upheld R5 complaint. Details: TC-2220
    Finished(CandidateShare, DkgOutput),
    /// R6 is required; send the message and consume closed R6. Details: TC-2220
    Reconstruct(DkgReconstructing, DkgMessage),
}

/// Validate the genesis context and local recipient key, then deal R1. Details: TC-2220
pub fn dkg_start(
    c: &AuthorizedCeremony,
    me: MemberIndex,
    hpke_sk: CeremonyHpkeSecretKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(DkgDealt, DkgMessage), Error> {
    let public = Public::new(c)?;
    let own = c
        .recipients()
        .iter()
        .find(|r| r.index == me)
        .ok_or(Error::InvalidIndex)?;
    if hpke_sk.public_key()?.encode() != own.hpke_public_key {
        return Err(Error::ContextMismatch);
    }
    let t = public.t();
    let polynomial = Polynomial {
        values: (0..t).map(|_| Scalar::random(&mut *rng, true)).collect(),
        blinding: (0..t).map(|_| Scalar::random(&mut *rng, true)).collect(),
    };
    let commitments: Vec<G2> = polynomial
        .values
        .iter()
        .zip(&polynomial.blinding)
        .map(|(a, b)| G2::generator().mul(a).add(&public.h.mul(b)))
        .collect();
    let hash = commitment_hash(&commitments);
    let mut dealings = Vec::with_capacity(c.recipients().len());
    for recipient in c.recipients() {
        let pair = polynomial.at(recipient.index);
        let value = Zeroizing::new(pair.value.to_bytes());
        let blinding = Zeroizing::new(pair.blinding.to_bytes());
        let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
        for (out, byte) in plaintext
            .iter_mut()
            .zip(value.iter().chain(blinding.iter()))
        {
            *out = *byte;
        }
        let context = DealingContext {
            ceremony_digest: c.digest(),
            round: DEAL,
            sender: me,
            recipient: recipient.index,
            commitment_hash: hash,
        };
        let key = CeremonyHpkePublicKey::decode(&recipient.hpke_public_key)?;
        dealings.push((
            recipient.index,
            seal_dealing(&key, &context, plaintext.as_slice(), &mut *rng)?,
        ));
    }
    let deal = DkgDeal {
        commitments,
        dealings,
    };
    let message = DkgMessage::new(c, DEAL, me, &deal.encode())?;
    Ok((
        DkgDealt {
            public,
            me,
            hpke: hpke_sk,
            polynomial,
        },
        message,
    ))
}

impl DkgDealt {
    fn open(&self, dealer: MemberIndex, deal: &DkgDeal) -> Result<SharePair, Error> {
        let (_, sealed) = deal
            .dealings
            .iter()
            .find(|(j, _)| *j == self.me)
            .ok_or(Error::InvalidSealedDealing)?;
        let context = DealingContext {
            ceremony_digest: self.public.ceremony.digest(),
            round: DEAL,
            sender: dealer,
            recipient: self.me,
            commitment_hash: commitment_hash(&deal.commitments),
        };
        let plaintext = open_dealing(&self.hpke, &context, sealed)?;
        if plaintext.len() != PLAINTEXT_LEN {
            return Err(Error::InvalidSealedDealing);
        }
        let (value, blinding) = plaintext.split_at(32);
        Ok(SharePair {
            value: Scalar::from_bytes(value)?,
            blinding: Scalar::from_bytes(blinding)?,
        })
    }

    /// Open and check every valid dealing; complain about failures (R2). Details: TC-2220
    pub fn complain(
        mut self,
        r1: &ClosedRound<DkgDeal>,
    ) -> Result<(DkgComplained, DkgMessage), Error> {
        let deals = self.public.deals(r1)?;
        let mut pairs = BTreeMap::new();
        let mut dealers = Vec::new();
        for (i, deal) in deals {
            match self.open(i, deal) {
                Ok(pair) if self.public.pedersen(&pair, &deal.commitments, self.me) => {
                    pairs.insert(i, pair);
                }
                _ if i != self.me => dealers.push(i),
                _ => {}
            }
        }
        let message = DkgMessage::new(
            &self.public.ceremony,
            COMPLAIN,
            self.me,
            &DkgComplaints { dealers }.encode(),
        )?;
        let Self {
            public,
            me,
            hpke,
            polynomial,
        } = self;
        drop(hpke);
        Ok((
            DkgComplained {
                public,
                me,
                polynomial,
                pairs,
            },
            message,
        ))
    }
}

impl DkgComplained {
    /// Publish this dealer's pairs for every counted complaint against it (R3). Details: TC-2220
    pub fn answer(
        mut self,
        r2: &ClosedRound<DkgComplaints>,
    ) -> Result<(DkgAnswered, DkgMessage), Error> {
        self.public.complaints(r2)?;
        let answers = match (
            self.public.commitments.contains_key(&self.me),
            self.public.complaints.get(&self.me),
        ) {
            (true, Some(required)) => required
                .iter()
                .map(|j| (*j, self.polynomial.at(*j)))
                .collect(),
            _ => Vec::new(),
        };
        let message = DkgMessage::new(
            &self.public.ceremony,
            ANSWER,
            self.me,
            &DkgAnswers { answers }.encode(),
        )?;
        Ok((
            DkgAnswered {
                public: self.public,
                me: self.me,
                polynomial: self.polynomial,
                pairs: self.pairs,
            },
            message,
        ))
    }
}

impl DkgAnswered {
    /// Fix QUAL, apply valid answers and publish Feldman coefficients (R4). Details: TC-2220
    pub fn extract(
        mut self,
        r3: &ClosedRound<DkgAnswers>,
    ) -> Result<(DkgExtracting, DkgMessage), Error> {
        let replacements = self.public.answers(r3, Some(self.me))?;
        self.pairs.extend(replacements);
        let qual = self.public.qual();
        self.pairs.retain(|i, _| qual.contains(i));
        if self.pairs.len() != qual.len() {
            return Err(Error::LocalShareUnavailable);
        }
        let feldman = DkgFeldman {
            commitments: self
                .polynomial
                .values
                .iter()
                .map(|a| G2::generator().mul(a))
                .collect(),
        };
        let message = DkgMessage::new(&self.public.ceremony, EXTRACT, self.me, &feldman.encode())?;
        Ok((
            DkgExtracting {
                public: self.public,
                me: self.me,
                pairs: self.pairs,
            },
            message,
        ))
    }
}

impl DkgExtracting {
    /// Report Feldman-invalid pairs; R5 is always sent, possibly empty. Details: TC-2220
    pub fn extraction_complaints(
        mut self,
        r4: &ClosedRound<DkgFeldman>,
    ) -> Result<(DkgAwaitingBarrier, DkgMessage), Error> {
        self.public.extract(r4)?;
        let complaints = self
            .public
            .feldman
            .iter()
            .filter(|(i, _)| **i != self.me)
            .filter_map(|(i, feldman)| {
                let pair = self.pairs.get(i)?;
                (G2::generator().mul(&pair.value) != evaluate_points(feldman, self.me))
                    .then(|| (*i, pair.duplicate()))
            })
            .collect();
        let message = DkgMessage::new(
            &self.public.ceremony,
            EXTRACTION_COMPLAINTS,
            self.me,
            &DkgExtractionComplaints { complaints }.encode(),
        )?;
        Ok((
            DkgAwaitingBarrier {
                public: self.public,
                me: self.me,
                pairs: self.pairs,
            },
            message,
        ))
    }
}

fn candidate(
    public: &Public,
    me: MemberIndex,
    pairs: &BTreeMap<MemberIndex, SharePair>,
) -> Result<(CandidateShare, DkgOutput), Error> {
    let output = public.output()?;
    let mut scalar = Scalar::from_u64(0);
    for i in &output.qual {
        let pair = pairs.get(i).ok_or(Error::LocalShareUnavailable)?;
        scalar = scalar.add(&pair.value);
    }
    Ok((
        CandidateShare {
            transcript: output.transcript_hash,
            index: me,
            scalar,
        },
        output,
    ))
}

impl DkgAwaitingBarrier {
    /// Consume the common closed R5; finish or publish R6 values. Details: TC-2220
    pub fn after_barrier(
        mut self,
        r5: &ClosedRound<DkgExtractionComplaints>,
    ) -> Result<AfterBarrier, Error> {
        if !self.public.barrier(r5)? {
            let (share, output) = candidate(&self.public, self.me, &self.pairs)?;
            return Ok(AfterBarrier::Finished(share, output));
        }
        let values = self
            .public
            .faulted
            .iter()
            .filter_map(|i| Some((*i, self.pairs.get(i)?.duplicate())))
            .collect();
        let message = DkgMessage::new(
            &self.public.ceremony,
            RECONSTRUCT,
            self.me,
            &DkgReconstruction { values }.encode(),
        )?;
        Ok(AfterBarrier::Reconstruct(
            DkgReconstructing {
                public: self.public,
                me: self.me,
                pairs: self.pairs,
            },
            message,
        ))
    }
}

impl DkgReconstructing {
    /// Recover every faulted QUAL dealer from closed R6 and finish. Details: TC-2220
    pub fn finish(
        mut self,
        r6: &ClosedRound<DkgReconstruction>,
    ) -> Result<(CandidateShare, DkgOutput), Error> {
        self.public.reconstruct(r6)?;
        candidate(&self.public, self.me, &self.pairs)
    }
}

/// Recompute the outcome from raw signed rounds; no expected output is trusted. Details: TC-2220
pub fn dkg_verify_transcript(
    c: &AuthorizedCeremony,
    t: &DkgTranscript,
    v: &impl DidSignatureVerifier,
) -> Result<DkgOutput, Error> {
    let mut size = 0usize;
    for record in &t.rounds {
        let statements = core::iter::once(&record.closure).chain(record.messages.iter());
        for statement in statements {
            size = size
                .checked_add(statement.bytes.len())
                .and_then(|s| s.checked_add(statement.signature.len()))
                .ok_or(Error::LimitExceeded)?;
            if size > TRANSCRIPT_CAP {
                return Err(Error::LimitExceeded);
            }
        }
    }
    let mut public = Public::new(c)?;
    let mut records = t.rounds.iter();
    let r1 = verified_round::<DkgDeal>(c, records.next(), DEAL, public.previous, v)?;
    public.deals(&r1)?;
    let r2 = verified_round::<DkgComplaints>(c, records.next(), COMPLAIN, public.previous, v)?;
    public.complaints(&r2)?;
    let r3 = verified_round::<DkgAnswers>(c, records.next(), ANSWER, public.previous, v)?;
    public.answers(&r3, None)?;
    let r4 = verified_round::<DkgFeldman>(c, records.next(), EXTRACT, public.previous, v)?;
    public.extract(&r4)?;
    let r5 = verified_round::<DkgExtractionComplaints>(
        c,
        records.next(),
        EXTRACTION_COMPLAINTS,
        public.previous,
        v,
    )?;
    if public.barrier(&r5)? {
        let r6 = verified_round::<DkgReconstruction>(
            c,
            records.next(),
            RECONSTRUCT,
            public.previous,
            v,
        )?;
        public.reconstruct(&r6)?;
    }
    if records.next().is_some() {
        return Err(Error::InvalidRound);
    }
    public.output()
}

fn verified_round<M: Decode>(
    c: &AuthorizedCeremony,
    record: Option<&DkgRoundRecord>,
    round: u8,
    previous: TranscriptHash,
    v: &impl DidSignatureVerifier,
) -> Result<ClosedRound<M>, Error> {
    let record = record.ok_or(Error::InvalidRound)?;
    ClosedRound::verify(c, round, &previous, &record.closure, &record.messages, v)
}

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
