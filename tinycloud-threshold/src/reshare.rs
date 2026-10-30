//! Authorized redistribution of the current master secret to a new cohort over
//! owner-closed rounds. Details: TC-2221
//!
//! Current-certificate dealers deal (R1) and answer (R3); authorized recipients
//! complain (R2). Members and `reshare_verify_transcript` apply the same public
//! rules to the authenticated round records. Liveness assumes the trusted owner
//! relay delivers every conforming member's message.

use core::fmt;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::{
    ceremony::{
        ceremony_message_body, AuthorizedCeremony, CeremonyKind, ClosedRound, Decode,
        DidSignatureVerifier, MemberCohort, RoundMessage,
    },
    cert::{CandidateShare, PublicMaterial, VerifiedCertificate},
    curve::{Scalar, G2},
    derive::KeyShare,
    dkg::{DkgComplaints, DkgDeal, DkgRoundRecord},
    dst,
    encoding::{Decoder, Encoder},
    error::Error,
    ids::{MemberIndex, Threshold, TranscriptHash},
    poly,
    seal::{
        open_dealing, seal_dealing, CeremonyHpkePublicKey, CeremonyHpkeSecretKey, DealingContext,
    },
};

/// Initial transcript link tag for reshare and refresh; not part of the frozen
/// S0.1 domain table. Details: TC-2221
pub(crate) const RESHARE_START: &[u8] = b"TC-THRESHOLD-V1-RESHARE-START";
const VERSION: u8 = 1;
const MAX_ENTRIES: u16 = 16;
const TRANSCRIPT_CAP: usize = 4_194_304;
const SCALAR_LEN: usize = 32;

const DEAL: u8 = 1;
const COMPLAIN: u8 = 2;
const ANSWER: u8 = 3;

/// `TH(RESHARE_START, authorized_ceremony_digest)`, the link preceding closed R1. Details: TC-2221
pub fn reshare_initial_transcript(c: &AuthorizedCeremony) -> TranscriptHash {
    TranscriptHash::new(dst::tagged_hash(RESHARE_START, &c.digest()))
}

// ------------------------------------------------------------------ payloads

/// R1: Feldman coefficients B_ik in the genesis R1 layout, one sealed g_i(j) per recipient. Details: TC-2221
pub type ReshareDeal = DkgDeal;

/// R2: dealers whose dealing failed for the sending recipient, in the genesis R2 layout. Details: TC-2221
pub type ReshareComplaints = DkgComplaints;

/// R3: a dealer's published g_i(j) values for complaining recipients. Details: TC-2221
#[derive(Debug)]
pub struct ReshareAnswers {
    pub(crate) answers: Vec<(MemberIndex, Scalar)>,
}

impl ReshareAnswers {
    /// `01 || count:u16 || [(recipient:u16 || value:32)]`, strictly increasing. Details: TC-2221
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(VERSION);
        e.u16(self.answers.len() as u16);
        for (index, value) in &self.answers {
            e.u16(index.get());
            e.fixed(Zeroizing::new(value.to_bytes()).as_slice());
        }
        e.finish()
    }
}

impl Decode for ReshareAnswers {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        if d.u8()? != VERSION {
            return Err(Error::InvalidEncoding);
        }
        let count = d.u16()?;
        if count > MAX_ENTRIES {
            return Err(Error::LimitExceeded);
        }
        let mut answers = Vec::with_capacity(usize::from(count));
        let mut previous: Option<MemberIndex> = None;
        for _ in 0..count {
            let index = MemberIndex::new(d.u16()?)?;
            if previous.is_some_and(|p| index <= p) {
                return Err(Error::InvalidEncoding);
            }
            previous = Some(index);
            let value = Zeroizing::new(d.fixed::<SCALAR_LEN>()?);
            answers.push((index, Scalar::from_bytes(value.as_slice())?));
        }
        d.finish()?;
        Ok(Self { answers })
    }
}

/// An unsigned member envelope for one round; the node signs `signing_preimage`. Details: TC-2221
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReshareMessage {
    round: u8,
    body: Vec<u8>,
}

impl ReshareMessage {
    fn new(
        c: &AuthorizedCeremony,
        round: u8,
        cohort: MemberCohort,
        me: MemberIndex,
        payload: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            round,
            body: ceremony_message_body(c, round, cohort, me, payload)?,
        })
    }
    /// Round number of this envelope. Details: TC-2221
    pub fn round(&self) -> u8 {
        self.round
    }
    /// Exact canonical member envelope bytes. Details: TC-2221
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// `TH(CEREMONY_MSG, body)`, signed with the member's node key. Details: TC-2221
    pub fn signing_preimage(&self) -> Vec<u8> {
        dst::tagged_hash(dst::CEREMONY_MSG, &self.body).to_vec()
    }
}

// --------------------------------------------------------------- outputs

/// Why an old dealer is not eligible for selection. Details: TC-2221
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExcludeReason {
    /// No R1 from the dealer in closed R1. Details: TC-2221
    MissingDeal,
    /// R1 failed to decode or failed a public check. Details: TC-2221
    MalformedDeal,
    /// Conflicting authenticated content in R1 or R3. Details: TC-2221
    Equivocated {
        /// Round of the conflicting messages. Details: TC-2221
        round: u8,
    },
    /// At least t′ distinct recipients complained. Details: TC-2221
    Complaints,
    /// A published answer fails the Feldman relation. Details: TC-2221
    InvalidAnswer,
    /// A required answer is absent from closed R3. Details: TC-2221
    MissingAnswer,
}

/// Public outcome shared by recipients and the transcript verifier. Details: TC-2221
#[derive(Clone, Debug)]
pub struct ReshareOutput {
    /// New Feldman polynomial, unchanged master key and new public shares. Details: TC-2221
    pub public: PublicMaterial,
    /// Selected dealers D in closed-R1 order. Details: TC-2221
    pub dealers: Vec<MemberIndex>,
    /// Excluded dealers with the first applicable reason. Details: TC-2221
    pub excluded: BTreeMap<MemberIndex, ExcludeReason>,
    /// Transcript link after closed R3. Details: TC-2221
    pub transcript_hash: TranscriptHash,
}

/// Raw signed rounds R1..R3. Details: TC-2221
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReshareTranscript {
    /// Round records in order. Details: TC-2221
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

/// Group one cohort's authenticated messages by sender; identical envelope bytes
/// are one message. Also returns each sender's first-appearance order.
fn by_sender<M>(
    round: &ClosedRound<M>,
    cohort: MemberCohort,
) -> (BTreeMap<MemberIndex, Sent<'_, M>>, Vec<MemberIndex>) {
    let mut senders = BTreeMap::new();
    let mut order = Vec::new();
    for message in round.messages().iter().filter(|m| m.cohort() == cohort) {
        match senders.entry(message.member()) {
            Entry::Vacant(slot) => {
                order.push(message.member());
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
    (senders, order)
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

fn feldman(value: &Scalar, commitments: &[G2], x: MemberIndex) -> bool {
    G2::generator().mul(value) == evaluate_points(commitments, x)
}

fn commitment_hash(points: &[G2]) -> [u8; 32] {
    let mut e = Encoder::new();
    e.u16(points.len() as u16);
    for point in points {
        e.fixed(&point.encode());
    }
    dst::tagged_hash(dst::COMMITMENTS, &e.finish())
}

fn copy(value: &Scalar) -> Scalar {
    value.add(&Scalar::from_u64(0))
}

/// Public redistribution state; recipients, dealers and the verifier apply identical rules.
struct Public {
    ceremony: AuthorizedCeremony,
    old: Threshold,
    mpk: G2,
    /// Current public shares pk_i by old dealer index.
    old_shares: BTreeMap<MemberIndex, G2>,
    previous: TranscriptHash,
    /// First-appearance order of dealer-cohort R1 senders.
    order: Vec<MemberIndex>,
    /// Publicly valid R1 commitments of dealers not yet excluded.
    commitments: BTreeMap<MemberIndex, Vec<G2>>,
    excluded: BTreeMap<MemberIndex, ExcludeReason>,
    complaints: BTreeMap<MemberIndex, BTreeSet<MemberIndex>>,
}

impl Public {
    /// Authorized reshare/refresh of exactly the supplied current certificate.
    fn new(c: &AuthorizedCeremony, current: &VerifiedCertificate) -> Result<Self, Error> {
        if !matches!(c.kind(), CeremonyKind::Reshare | CeremonyKind::Refresh) {
            return Err(Error::InvalidCeremony);
        }
        if c.statement().current != Some(current.digest()) {
            return Err(Error::ContextMismatch);
        }
        let old = current.key_context().threshold();
        if c.kind() == CeremonyKind::Refresh {
            let same_directory = c
                .recipients()
                .iter()
                .map(|r| (r.index, &r.node))
                .eq(current.body().members().iter().map(|m| (m.index, &m.node)));
            if c.threshold() != old || !same_directory {
                return Err(Error::InvalidCeremony);
            }
        }
        let keys = current.public_key_set();
        Ok(Self {
            ceremony: c.clone(),
            old,
            mpk: keys.mpk.0.clone(),
            old_shares: keys.public_shares.iter().cloned().collect(),
            previous: reshare_initial_transcript(c),
            order: Vec::new(),
            commitments: BTreeMap::new(),
            excluded: BTreeMap::new(),
            complaints: BTreeMap::new(),
        })
    }

    fn threshold(&self) -> Threshold {
        self.ceremony.threshold()
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

    fn publicly_valid(&self, deal: &ReshareDeal, pk: &G2) -> bool {
        let threshold = self.threshold();
        deal.commitments.len() == usize::from(threshold.t())
            && deal.commitments.first() == Some(pk)
            && deal.commitments.last().is_some_and(|top| !top.is_identity())
            && deal
                .dealings
                .iter()
                .map(|(j, _)| j.get())
                .eq(1..=threshold.n())
    }

    /// Apply closed R1; return the publicly valid deals.
    fn deals<'r>(
        &mut self,
        r1: &'r ClosedRound<ReshareDeal>,
    ) -> Result<BTreeMap<MemberIndex, &'r ReshareDeal>, Error> {
        self.bind(r1, DEAL)?;
        let (senders, order) = by_sender(r1, MemberCohort::Current);
        self.order = order;
        let mut valid = BTreeMap::new();
        for (i, pk) in &self.old_shares {
            let reason = match senders.get(i).copied() {
                None => Some(ExcludeReason::MissingDeal),
                Some(Sent::Conflicting) => Some(ExcludeReason::Equivocated { round: DEAL }),
                Some(Sent::One(message)) => match message.payload() {
                    Ok(deal) if self.publicly_valid(deal, pk) => {
                        valid.insert(*i, deal);
                        None
                    }
                    _ => Some(ExcludeReason::MalformedDeal),
                },
            };
            if let Some(reason) = reason {
                self.excluded.insert(*i, reason);
            }
        }
        for (i, deal) in &valid {
            self.commitments.insert(*i, deal.commitments.clone());
        }
        Ok(valid)
    }

    /// Apply closed R2: one complaint per distinct recipient and named dealer.
    fn complaints(&mut self, r2: &ClosedRound<ReshareComplaints>) -> Result<(), Error> {
        self.bind(r2, COMPLAIN)?;
        let (senders, _) = by_sender(r2, MemberCohort::Recipients);
        let n = self.old.n();
        for (j, sent) in senders {
            let Some(list) = decoded(Some(sent)) else {
                continue;
            };
            if !list.dealers.iter().all(|i| i.get() <= n) {
                continue;
            }
            for i in &list.dealers {
                self.complaints.entry(*i).or_default().insert(j);
            }
        }
        Ok(())
    }

    /// Apply closed R3 and fix the eligible dealers; return valid required
    /// answers addressed to `recipient`.
    fn answers(
        &mut self,
        r3: &ClosedRound<ReshareAnswers>,
        recipient: Option<MemberIndex>,
    ) -> Result<BTreeMap<MemberIndex, Scalar>, Error> {
        self.bind(r3, ANSWER)?;
        let (senders, _) = by_sender(r3, MemberCohort::Current);
        let t = usize::from(self.threshold().t());
        let n = self.threshold().n();
        let empty = BTreeSet::new();
        let mut replacements = BTreeMap::new();
        let mut removed = BTreeMap::new();
        for (i, commitments) in &self.commitments {
            let required = self.complaints.get(i).unwrap_or(&empty);
            let sent = senders.get(i).copied();
            let answers = decoded(sent).filter(|a| a.answers.iter().all(|(j, _)| j.get() <= n));
            let reason = if matches!(sent, Some(Sent::Conflicting)) {
                Some(ExcludeReason::Equivocated { round: ANSWER })
            } else if required.len() >= t {
                Some(ExcludeReason::Complaints)
            } else if answers.is_some_and(|a| {
                a.answers
                    .iter()
                    .any(|(j, value)| !feldman(value, commitments, *j))
            }) {
                Some(ExcludeReason::InvalidAnswer)
            } else if !required
                .iter()
                .all(|j| answers.is_some_and(|a| a.answers.iter().any(|(k, _)| k == j)))
            {
                Some(ExcludeReason::MissingAnswer)
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
                            if let Some((_, value)) = answers.answers.iter().find(|(j, _)| *j == me)
                            {
                                replacements.insert(*i, copy(value));
                            }
                        }
                    }
                }
            }
        }
        for (i, reason) in removed {
            self.commitments.remove(&i);
            self.excluded.insert(i, reason);
        }
        Ok(replacements)
    }

    /// D: the first t eligible dealers in closed-R1 order.
    fn select(&self) -> Result<Vec<MemberIndex>, Error> {
        let t = usize::from(self.old.t());
        let dealers: Vec<MemberIndex> = self
            .order
            .iter()
            .copied()
            .filter(|i| self.commitments.contains_key(i))
            .take(t)
            .collect();
        if dealers.len() < t {
            return Err(Error::InsufficientQualified);
        }
        Ok(dealers)
    }

    fn output(&self, dealers: Vec<MemberIndex>) -> Result<ReshareOutput, Error> {
        let mut sums: Vec<G2> = (0..self.threshold().t()).map(|_| G2::identity()).collect();
        for i in &dealers {
            let lambda = poly::lagrange(*i, dealers.iter().copied())?;
            let commitments = self.commitments.get(i).ok_or(Error::InvalidRound)?;
            for (sum, coefficient) in sums.iter_mut().zip(commitments) {
                *sum = sum.add(&coefficient.mul(&lambda));
            }
        }
        if sums.first() != Some(&self.mpk) {
            return Err(Error::InvalidPoint);
        }
        Ok(ReshareOutput {
            public: PublicMaterial::from_commitments(self.threshold(), sums)?,
            dealers,
            excluded: self.excluded.clone(),
            transcript_hash: self.previous,
        })
    }
}

// ------------------------------------------------------------ member states

/// Holds this dealer's polynomial g_i until it answers closed R2. Details: TC-2221
pub struct ReshareDealer {
    public: Public,
    me: MemberIndex,
    coefficients: Vec<Scalar>,
    commitments: Vec<G2>,
}

/// Holds this recipient's ceremony key until closed R1. Details: TC-2221
pub struct ReshareReceiving {
    public: Public,
    me: MemberIndex,
    hpke: CeremonyHpkeSecretKey,
}

/// Holds this recipient's opened values until closed R2 and R3. Details: TC-2221
pub struct ReshareComplained {
    public: Public,
    me: MemberIndex,
    values: BTreeMap<MemberIndex, Scalar>,
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

redacted!(ReshareDealer, ReshareReceiving, ReshareComplained);

/// Validate the authorized context and the dealer's current share, then deal R1. Details: TC-2221
pub fn reshare_deal(
    c: &AuthorizedCeremony,
    current: &VerifiedCertificate,
    share: &KeyShare,
    rng: &mut impl CryptoRngCore,
) -> Result<(ReshareDealer, ReshareMessage), Error> {
    let public = Public::new(c, current)?;
    if share.context() != &current.key_context() {
        return Err(Error::ContextMismatch);
    }
    let me = share.index();
    if !public.old_shares.contains_key(&me) {
        return Err(Error::InvalidIndex);
    }
    let t = usize::from(c.threshold().t());
    let mut coefficients = Vec::with_capacity(t);
    coefficients.push(copy(&share.scalar));
    for _ in 1..t {
        coefficients.push(Scalar::random(&mut *rng, true));
    }
    let commitments: Vec<G2> = coefficients
        .iter()
        .map(|b| G2::generator().mul(b))
        .collect();
    let hash = commitment_hash(&commitments);
    let mut dealings = Vec::with_capacity(c.recipients().len());
    for recipient in c.recipients() {
        let value = poly::evaluate(
            &coefficients,
            &Scalar::from_u64(u64::from(recipient.index.get())),
        );
        let plaintext = Zeroizing::new(value.to_bytes());
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
    let deal = ReshareDeal {
        commitments: commitments.clone(),
        dealings,
    };
    let message = ReshareMessage::new(c, DEAL, MemberCohort::Current, me, &deal.encode())?;
    Ok((
        ReshareDealer {
            public,
            me,
            coefficients,
            commitments,
        },
        message,
    ))
}

impl ReshareDealer {
    /// Publish g_i(j) for every counted complaint against this dealer (R3),
    /// unless t′ or more recipients complained. Details: TC-2221
    pub fn answer(
        mut self,
        r1: &ClosedRound<ReshareDeal>,
        r2: &ClosedRound<ReshareComplaints>,
    ) -> Result<ReshareMessage, Error> {
        self.public.deals(r1)?;
        self.public.complaints(r2)?;
        let t = usize::from(self.public.threshold().t());
        let answers = match (
            self.public.commitments.get(&self.me),
            self.public.complaints.get(&self.me),
        ) {
            (Some(published), Some(required))
                if *published == self.commitments && required.len() < t =>
            {
                required
                    .iter()
                    .map(|j| {
                        let x = Scalar::from_u64(u64::from(j.get()));
                        (*j, poly::evaluate(&self.coefficients, &x))
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        ReshareMessage::new(
            &self.public.ceremony,
            ANSWER,
            MemberCohort::Current,
            self.me,
            &ReshareAnswers { answers }.encode(),
        )
    }
}

/// Validate the authorized context and the local recipient key. Details: TC-2221
pub fn reshare_start_receiver(
    c: &AuthorizedCeremony,
    current: &VerifiedCertificate,
    me: MemberIndex,
    hpke_sk: CeremonyHpkeSecretKey,
) -> Result<ReshareReceiving, Error> {
    let public = Public::new(c, current)?;
    let own = c
        .recipients()
        .iter()
        .find(|r| r.index == me)
        .ok_or(Error::InvalidIndex)?;
    if hpke_sk.public_key()?.encode() != own.hpke_public_key {
        return Err(Error::ContextMismatch);
    }
    Ok(ReshareReceiving {
        public,
        me,
        hpke: hpke_sk,
    })
}

impl ReshareReceiving {
    fn open(&self, dealer: MemberIndex, deal: &ReshareDeal) -> Result<Scalar, Error> {
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
        if plaintext.len() != SCALAR_LEN {
            return Err(Error::InvalidSealedDealing);
        }
        Scalar::from_bytes(plaintext.as_slice())
    }

    /// Open and check every publicly valid dealing; complain about failures (R2). Details: TC-2221
    pub fn complain(
        mut self,
        r1: &ClosedRound<ReshareDeal>,
    ) -> Result<(ReshareComplained, ReshareMessage), Error> {
        let deals = self.public.deals(r1)?;
        let mut values = BTreeMap::new();
        let mut dealers = Vec::new();
        for (i, deal) in deals {
            match self.open(i, deal) {
                Ok(value) if feldman(&value, &deal.commitments, self.me) => {
                    values.insert(i, value);
                }
                _ => dealers.push(i),
            }
        }
        let message = ReshareMessage::new(
            &self.public.ceremony,
            COMPLAIN,
            MemberCohort::Recipients,
            self.me,
            &ReshareComplaints { dealers }.encode(),
        )?;
        let Self { public, me, hpke } = self;
        drop(hpke);
        Ok((ReshareComplained { public, me, values }, message))
    }
}

impl ReshareComplained {
    /// Apply closed R2 and R3, select D and return this recipient's candidate. Details: TC-2221
    pub fn finish(
        mut self,
        r2: &ClosedRound<ReshareComplaints>,
        r3: &ClosedRound<ReshareAnswers>,
    ) -> Result<(CandidateShare, ReshareOutput), Error> {
        self.public.complaints(r2)?;
        let replacements = self.public.answers(r3, Some(self.me))?;
        self.values.extend(replacements);
        let dealers = self.public.select()?;
        let mut scalar = Scalar::from_u64(0);
        for i in &dealers {
            let value = self.values.get(i).ok_or(Error::LocalShareUnavailable)?;
            let lambda = poly::lagrange(*i, dealers.iter().copied())?;
            scalar = scalar.add(&lambda.mul(value));
        }
        let output = self.public.output(dealers)?;
        Ok((
            CandidateShare {
                transcript: output.transcript_hash,
                index: self.me,
                scalar,
            },
            output,
        ))
    }
}

/// Recompute the outcome from raw signed rounds; no expected output is trusted. Details: TC-2221
pub fn reshare_verify_transcript(
    c: &AuthorizedCeremony,
    current: &VerifiedCertificate,
    t: &ReshareTranscript,
    v: &impl DidSignatureVerifier,
) -> Result<ReshareOutput, Error> {
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
    let mut public = Public::new(c, current)?;
    let mut records = t.rounds.iter();
    let r1 = verified_round::<ReshareDeal>(c, records.next(), DEAL, public.previous, v)?;
    public.deals(&r1)?;
    let r2 = verified_round::<ReshareComplaints>(c, records.next(), COMPLAIN, public.previous, v)?;
    public.complaints(&r2)?;
    let r3 = verified_round::<ReshareAnswers>(c, records.next(), ANSWER, public.previous, v)?;
    public.answers(&r3, None)?;
    if records.next().is_some() {
        return Err(Error::InvalidRound);
    }
    let dealers = public.select()?;
    public.output(dealers)
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
