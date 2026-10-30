//! Authenticated ceremony directories and owner-ordered closed rounds. Details: TC-2222

use crate::{
    cert::{CertMember, VerifiedCertificate},
    dst,
    encoding::{Decoder, Encoder},
    error::{Error, SignatureError},
    ids::*,
};

const MESSAGE_CAP: usize = 65_536;
const TRANSCRIPT_CAP: usize = 4_194_304;
const SIGNATURE_CAP: usize = 512;

/// Caller-supplied authorized owner and network. Details: TC-2222
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    /// Expected space owner. Details: TC-2222
    pub expected_owner: Did,
    /// Expected network. Details: TC-2222
    pub network: NetworkUrn,
}

/// Signature verification supplied by the integrating authentication layer. Details: TC-2222
pub trait DidSignatureVerifier {
    /// Verify exactly these bytes for the specified DID. Details: TC-2222
    fn verify(&self, signer: &Did, message: &[u8], signature: &[u8]) -> Result<(), SignatureError>;
}

/// Unauthenticated statement body and signature. Details: TC-2222
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStatement {
    /// Canonical statement body, or the activation's 32-byte preimage. Details: TC-2222
    pub bytes: Vec<u8>,
    /// Signature under the statement's resolved signer. Details: TC-2222
    pub signature: Vec<u8>,
}

/// Owner-authorized ceremony operation. Details: TC-2222
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CeremonyKind {
    /// First master key. Details: TC-2222
    Genesis = 1,
    /// Redistribution to an authorized cohort. Details: TC-2222
    Reshare = 2,
    /// Redistribution at the next epoch. Details: TC-2222
    Refresh = 3,
    /// Replacement master key. Details: TC-2222
    Rekey = 4,
}

/// Recipient identity and ceremony-scoped HPKE public key. Details: TC-2222
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeremonyRecipient {
    /// Shamir coordinate. Details: TC-2222
    pub index: MemberIndex,
    /// Recipient node identity. Details: TC-2222
    pub node: Did,
    /// Exactly 32 public-key bytes, authenticated independently of HPKE transport. Details: TC-2222
    pub hpke_public_key: [u8; 32],
}

/// Raw owner statement; authentication requires the external anchor or pinned predecessor. Details: TC-2222
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeremonyStatement {
    /// Authorized operation. Details: TC-2222
    pub kind: CeremonyKind,
    /// Fresh caller-generated ceremony identifier. Details: TC-2222
    pub id: CeremonyId,
    /// Authorized network. Details: TC-2222
    pub network: NetworkUrn,
    /// Authorizing owner. Details: TC-2222
    pub owner: Did,
    /// Pinned predecessor digest, absent only at genesis. Details: TC-2222
    pub current: Option<CertDigest>,
    /// New threshold and cohort size. Details: TC-2222
    pub threshold: Threshold,
    /// New re-key counter. Details: TC-2222
    pub rekey: RekeyCounter,
    /// New epoch. Details: TC-2222
    pub epoch: Epoch,
    /// Index-ordered recipient directory. Details: TC-2222
    pub recipients: Vec<CeremonyRecipient>,
}

impl CeremonyStatement {
    /// Encode the version-one authorization body. Details: TC-2222
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(1);
        e.u8(self.kind as u8);
        e.fixed(self.id.as_bytes());
        e.lp(self.network.as_bytes());
        e.lp(self.owner.as_bytes());
        e.u8(u8::from(self.current.is_some()));
        if let Some(current) = self.current {
            e.fixed(current.as_bytes());
        }
        e.u16(self.threshold.t());
        e.u16(self.threshold.n());
        e.u64(self.rekey.get());
        e.u64(self.epoch.get());
        e.u16(self.recipients.len() as u16);
        for r in &self.recipients {
            e.u16(r.index.get());
            e.lp(r.node.as_bytes());
            e.fixed(&r.hpke_public_key);
        }
        e.finish()
    }

    /// Decode bounded canonical fields and a complete unique recipient directory. Details: TC-2222
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        if d.u8()? != 1 {
            return Err(Error::InvalidEncoding);
        }
        let kind = match d.u8()? {
            1 => CeremonyKind::Genesis,
            2 => CeremonyKind::Reshare,
            3 => CeremonyKind::Refresh,
            4 => CeremonyKind::Rekey,
            _ => return Err(Error::InvalidEncoding),
        };
        let id = CeremonyId::new(d.fixed()?);
        let network = NetworkUrn::new(text(d.lp(1024)?)?)?;
        let owner = Did::new(text(d.lp(256)?)?)?;
        let current = match d.u8()? {
            0 => None,
            1 => Some(CertDigest::new(d.fixed()?)),
            _ => return Err(Error::InvalidEncoding),
        };
        let threshold = Threshold::new(d.u16()?, d.u16()?)?;
        let rekey = RekeyCounter::new(d.u64()?);
        let epoch = Epoch::new(d.u64()?);
        let count = d.u16()?;
        if count != threshold.n() {
            return Err(Error::InvalidCeremony);
        }
        let mut recipients: Vec<CeremonyRecipient> = Vec::with_capacity(usize::from(count));
        for expected in 1..=count {
            let index = MemberIndex::new(d.u16()?)?;
            let node = Did::new(text(d.lp(256)?)?)?;
            if index.get() != expected || recipients.iter().any(|r| r.node == node) {
                return Err(Error::InvalidCeremony);
            }
            recipients.push(CeremonyRecipient {
                index,
                node,
                hpke_public_key: d.fixed()?,
            });
        }
        d.finish()?;
        Ok(Self {
            kind,
            id,
            network,
            owner,
            current,
            threshold,
            rekey,
            epoch,
            recipients,
        })
    }

    /// Domain-separated owner signing preimage and authorized-ceremony digest. Details: TC-2222
    pub fn signing_preimage(&self) -> Vec<u8> {
        dst::tagged_hash(dst::CEREMONY_AUTH, &self.encode()).to_vec()
    }
}

pub(crate) fn text(bytes: &[u8]) -> Result<&str, Error> {
    core::str::from_utf8(bytes).map_err(|_| Error::InvalidEncoding)
}

pub(crate) fn verify_signature(
    v: &impl DidSignatureVerifier,
    signer: &Did,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if signature.is_empty() || signature.len() > SIGNATURE_CAP {
        return Err(Error::InvalidSignature);
    }
    v.verify(signer, message, signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Authenticated ceremony metadata, directory and pinned dealer identities. Details: TC-2222
#[derive(Clone, Debug)]
pub struct AuthorizedCeremony {
    body: CeremonyStatement,
    anchor: TrustAnchor,
    digest: [u8; 32],
    dealers: Vec<CertMember>,
}

impl AuthorizedCeremony {
    /// Verify genesis under the caller's expected owner and network. Details: TC-2222
    pub fn verify_genesis(
        anchor: &TrustAnchor,
        statement: &SignedStatement,
        v: &impl DidSignatureVerifier,
    ) -> Result<Self, Error> {
        let body = CeremonyStatement::decode(&statement.bytes)?;
        if body.kind != CeremonyKind::Genesis
            || body.current.is_some()
            || body.rekey.get() != 0
            || body.epoch.get() != 0
        {
            return Err(Error::InvalidCeremony);
        }
        body.threshold.check_genesis_budget()?;
        Self::authenticate(anchor, statement, body, Vec::new(), v)
    }

    /// Verify the exact successor of the certificate pinned by the caller's log head. Details: TC-2222
    pub fn verify_for(
        current: &VerifiedCertificate,
        statement: &SignedStatement,
        v: &impl DidSignatureVerifier,
    ) -> Result<Self, Error> {
        let body = CeremonyStatement::decode(&statement.bytes)?;
        let context = current.public_key_set().context();
        let epoch = context.epoch().checked_next()?;
        let rekey = if body.kind == CeremonyKind::Rekey {
            body.threshold.check_genesis_budget()?;
            context.rekey().checked_next()?
        } else {
            context.rekey()
        };
        if body.kind == CeremonyKind::Genesis
            || body.current != Some(current.digest())
            || body.epoch != epoch
            || body.rekey != rekey
        {
            return Err(Error::InvalidCeremony);
        }
        Self::authenticate(
            current.anchor(),
            statement,
            body,
            current.body().members().to_vec(),
            v,
        )
    }

    fn authenticate(
        anchor: &TrustAnchor,
        signed: &SignedStatement,
        body: CeremonyStatement,
        dealers: Vec<CertMember>,
        v: &impl DidSignatureVerifier,
    ) -> Result<Self, Error> {
        if body.owner != anchor.expected_owner || body.network != anchor.network {
            return Err(Error::ContextMismatch);
        }
        let digest = dst::tagged_hash(dst::CEREMONY_AUTH, &signed.bytes);
        verify_signature(v, &anchor.expected_owner, &digest, &signed.signature)?;
        Ok(Self {
            body,
            anchor: anchor.clone(),
            digest,
            dealers,
        })
    }

    /// Digest of the canonical owner-authorized body. Details: TC-2222
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Authenticated operation. Details: TC-2222
    pub fn kind(&self) -> CeremonyKind {
        self.body.kind
    }
    /// Authenticated threshold and cohort size. Details: TC-2222
    pub fn threshold(&self) -> Threshold {
        self.body.threshold
    }
    /// Ceremony-scoped recipient directory. Details: TC-2222
    pub fn recipients(&self) -> &[CeremonyRecipient] {
        &self.body.recipients
    }
    /// Authenticated statement fields. Details: TC-2222
    pub fn statement(&self) -> &CeremonyStatement {
        &self.body
    }
    /// External owner/network anchor retained during verification. Details: TC-2222
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }

    fn signer(&self, cohort: MemberCohort, index: MemberIndex) -> Result<&Did, Error> {
        match cohort {
            MemberCohort::Recipients => self
                .body
                .recipients
                .iter()
                .find(|r| r.index == index)
                .map(|r| &r.node)
                .ok_or(Error::InvalidRound),
            MemberCohort::Current => {
                if !matches!(self.kind(), CeremonyKind::Reshare | CeremonyKind::Refresh) {
                    return Err(Error::InvalidRound);
                }
                self.dealers
                    .iter()
                    .find(|d| d.index == index)
                    .map(|d| &d.node)
                    .ok_or(Error::InvalidRound)
            }
        }
    }
}

/// Signed sender role; a coordinate is resolved only within its named cohort. Details: TC-2222
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemberCohort {
    /// Authorized new recipient directory. Details: TC-2222
    Recipients = 1,
    /// Pinned current-certificate dealer directory. Details: TC-2222
    Current = 2,
}

/// Decoder supplied by a DKG or resharing message type. Details: TC-2222
pub trait Decode: Sized {
    /// Decode only the bounded inner payload; phase rules interpret failure. Details: TC-2222
    fn decode(bytes: &[u8]) -> Result<Self, Error>;
}

struct MessageEnvelope<'a> {
    ceremony: [u8; 32],
    round: u8,
    cohort: MemberCohort,
    member: MemberIndex,
    payload: &'a [u8],
}

fn message_envelope(bytes: &[u8]) -> Result<MessageEnvelope<'_>, Error> {
    let mut d = Decoder::new(bytes)?;
    if d.u8()? != 1 {
        return Err(Error::InvalidEncoding);
    }
    let ceremony = d.fixed()?;
    let round = d.u8()?;
    let cohort = match d.u8()? {
        1 => MemberCohort::Recipients,
        2 => MemberCohort::Current,
        _ => return Err(Error::InvalidEncoding),
    };
    let member = MemberIndex::new(d.u16()?)?;
    let payload = d.lp(MESSAGE_CAP)?;
    d.finish()?;
    Ok(MessageEnvelope {
        ceremony,
        round,
        cohort,
        member,
        payload,
    })
}

/// Encode a member payload with its authorized ceremony, round and sender role. Details: TC-2222
pub fn ceremony_message_body(
    c: &AuthorizedCeremony,
    round: u8,
    cohort: MemberCohort,
    member: MemberIndex,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    c.signer(cohort, member)?;
    if payload.len().checked_add(41).ok_or(Error::LimitExceeded)? > MESSAGE_CAP {
        return Err(Error::LimitExceeded);
    }
    let mut e = Encoder::new();
    e.u8(1);
    e.fixed(&c.digest);
    e.u8(round);
    e.u8(cohort as u8);
    e.u16(member.get());
    e.lp(payload);
    Ok(e.finish())
}

/// Member signature preimage after canonical outer-envelope decoding. Details: TC-2222
pub fn ceremony_message_preimage(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    message_envelope(bytes)?;
    Ok(dst::tagged_hash(dst::CEREMONY_MSG, bytes).to_vec())
}

fn message_list_hash(messages: &[SignedStatement]) -> Result<[u8; 32], Error> {
    let count = u16::try_from(messages.len()).map_err(|_| Error::LimitExceeded)?;
    let mut size = 2usize;
    for message in messages {
        if message.bytes.len() > MESSAGE_CAP
            || message.signature.is_empty()
            || message.signature.len() > SIGNATURE_CAP
        {
            return Err(Error::LimitExceeded);
        }
        size = size
            .checked_add(8)
            .and_then(|s| s.checked_add(message.bytes.len()))
            .and_then(|s| s.checked_add(message.signature.len()))
            .ok_or(Error::LimitExceeded)?;
        if size > TRANSCRIPT_CAP {
            return Err(Error::LimitExceeded);
        }
    }
    let mut e = Encoder::new();
    e.u16(count);
    for message in messages {
        e.lp(&message.bytes);
        e.lp(&message.signature);
    }
    Ok(dst::tagged_hash(dst::TRANSCRIPT, &e.finish()))
}

/// Encode the owner's ordered-list closure and exact preceding transcript hash. Details: TC-2222
pub fn round_closure_body(
    c: &AuthorizedCeremony,
    round: u8,
    previous: &TranscriptHash,
    messages: &[SignedStatement],
) -> Result<Vec<u8>, Error> {
    let hash = message_list_hash(messages)?;
    let mut e = Encoder::new();
    e.u8(1);
    e.fixed(&c.digest);
    e.u8(round);
    e.fixed(&hash);
    e.fixed(previous.as_bytes());
    Ok(e.finish())
}

/// Owner signing preimage after canonical closure decoding. Details: TC-2222
pub fn round_closure_preimage(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut d = Decoder::new(bytes)?;
    if d.u8()? != 1 {
        return Err(Error::InvalidEncoding);
    }
    d.fixed::<32>()?;
    d.u8()?;
    d.fixed::<32>()?;
    d.fixed::<32>()?;
    d.finish()?;
    Ok(dst::tagged_hash(dst::ROUND_CLOSE, bytes).to_vec())
}

/// Authenticated raw message and its independently decoded inner payload. Details: TC-2222
#[derive(Debug)]
pub struct RoundMessage<M> {
    statement: SignedStatement,
    member: MemberIndex,
    cohort: MemberCohort,
    payload: Result<M, Error>,
}
impl<M> RoundMessage<M> {
    /// Exact member-signed bytes and signature, retained for phase rules. Details: TC-2222
    pub fn statement(&self) -> &SignedStatement {
        &self.statement
    }
    /// Authenticated member coordinate. Details: TC-2222
    pub fn member(&self) -> MemberIndex {
        self.member
    }
    /// Authenticated sender role. Details: TC-2222
    pub fn cohort(&self) -> MemberCohort {
        self.cohort
    }
    /// Inner decoding result; authenticated malformed bytes remain in statement(). Details: TC-2222
    pub fn payload(&self) -> &Result<M, Error> {
        &self.payload
    }
}

/// Owner-closed ordered messages authenticated to one ceremony and preceding hash. Details: TC-2222
#[derive(Debug)]
pub struct ClosedRound<M> {
    closure: SignedStatement,
    messages: Vec<RoundMessage<M>>,
    ceremony: [u8; 32],
    round: u8,
    previous: TranscriptHash,
    transcript: TranscriptHash,
}
impl<M: Decode> ClosedRound<M> {
    /// Authenticate the owner closure and every member before exposing any authenticated payload. Details: TC-2222
    pub fn verify(
        c: &AuthorizedCeremony,
        round: u8,
        prev: &TranscriptHash,
        closure: &SignedStatement,
        messages: &[SignedStatement],
        v: &impl DidSignatureVerifier,
    ) -> Result<Self, Error> {
        let preimage = round_closure_preimage(&closure.bytes)?;
        let expected = round_closure_body(c, round, prev, messages)?;
        if closure.bytes != expected {
            return Err(Error::InvalidRound);
        }
        verify_signature(v, &c.anchor.expected_owner, &preimage, &closure.signature)?;
        for message in messages {
            let envelope = message_envelope(&message.bytes)?;
            if envelope.ceremony != c.digest || envelope.round != round {
                return Err(Error::InvalidRound);
            }
            let signer = c.signer(envelope.cohort, envelope.member)?;
            verify_signature(
                v,
                signer,
                &dst::tagged_hash(dst::CEREMONY_MSG, &message.bytes),
                &message.signature,
            )?;
        }
        let mut entries = Vec::with_capacity(messages.len());
        for message in messages {
            let envelope = message_envelope(&message.bytes)?;
            entries.push(RoundMessage {
                member: envelope.member,
                cohort: envelope.cohort,
                payload: M::decode(envelope.payload),
                statement: message.clone(),
            });
        }
        let mut e = Encoder::new();
        e.fixed(prev.as_bytes());
        e.lp(&closure.bytes);
        e.lp(&closure.signature);
        let transcript = TranscriptHash::new(dst::tagged_hash(dst::TRANSCRIPT, &e.finish()));
        Ok(Self {
            closure: closure.clone(),
            messages: entries,
            ceremony: c.digest,
            round,
            previous: *prev,
            transcript,
        })
    }
}
impl<M> ClosedRound<M> {
    /// Authenticated entries in owner order, including retransmissions and equivocations. Details: TC-2222
    pub fn messages(&self) -> &[RoundMessage<M>] {
        &self.messages
    }
    /// Exact owner closure and signature. Details: TC-2222
    pub fn closure(&self) -> &SignedStatement {
        &self.closure
    }
    /// Authorized ceremony digest. Details: TC-2222
    pub fn ceremony_digest(&self) -> [u8; 32] {
        self.ceremony
    }
    /// Closed round number. Details: TC-2222
    pub fn round(&self) -> u8 {
        self.round
    }
    /// Exact prior hash supplied to verification. Details: TC-2222
    pub fn previous_hash(&self) -> TranscriptHash {
        self.previous
    }
    /// Hash of the authenticated closure chained to the previous transcript. Details: TC-2222
    pub fn transcript_hash(&self) -> TranscriptHash {
        self.transcript
    }
}

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
            AuthorizedCeremony::verify_genesis(&self.anchor(), &self.statement(&body), self)
                .unwrap()
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
        fn verify(
            &self,
            signer: &Did,
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), SignatureError> {
            let key: VerifyingKey = self
                .keys
                .get(signer)
                .ok_or(SignatureError::Invalid)?
                .verifying_key();
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| SignatureError::Invalid)?;
            key.verify_strict(message, &signature)
                .map_err(|_| SignatureError::Invalid)
        }
    }

    #[test]
    fn ceremony_substitutions_require_the_owner_signature() {
        let signers = Signers::new();
        let body = signers.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
        let signed = signers.statement(&body);
        let verified =
            AuthorizedCeremony::verify_genesis(&signers.anchor(), &signed, &signers).unwrap();
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
            let forged = SignedStatement {
                bytes: changed.encode(),
                signature: signed.signature.clone(),
            };
            assert!(
                AuthorizedCeremony::verify_genesis(&signers.anchor(), &forged, &signers).is_err()
            );
        }
        let other = TrustAnchor {
            expected_owner: Signers::did(9),
            ..signers.anchor()
        };
        assert!(AuthorizedCeremony::verify_genesis(&other, &signed, &signers).is_err());
    }

    #[test]
    fn ceremony_decoding_checks_budget_directory_and_canonical_bytes() {
        let signers = Signers::new();
        let invalid_budget = signers.body(CeremonyKind::Genesis, Threshold::new(3, 4).unwrap());
        assert!(matches!(
            AuthorizedCeremony::verify_genesis(
                &signers.anchor(),
                &signers.statement(&invalid_budget),
                &signers
            ),
            Err(Error::UnsupportedFaultBudget)
        ));
        let body = signers.body(CeremonyKind::Genesis, Threshold::new(2, 3).unwrap());
        assert_eq!(
            CeremonyStatement::decode(&body.encode()).unwrap().encode(),
            body.encode()
        );
        for mutation in 0..4 {
            let mut changed = body.clone();
            match mutation {
                0 => changed.recipients.swap(0, 1),
                1 => changed.recipients[1].node = changed.recipients[0].node.clone(),
                2 => changed.recipients[1].index = changed.recipients[0].index,
                _ => {
                    changed.recipients.pop();
                }
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
    use super::tests::Signers;
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct Byte(u8);
    impl Decode for Byte {
        fn decode(bytes: &[u8]) -> Result<Self, Error> {
            match bytes {
                [byte] => Ok(Self(*byte)),
                _ => Err(Error::InvalidEncoding),
            }
        }
    }
    fn message(
        c: &AuthorizedCeremony,
        member: u16,
        payload: &[u8],
        signers: &Signers,
    ) -> SignedStatement {
        let bytes = ceremony_message_body(
            c,
            1,
            MemberCohort::Recipients,
            MemberIndex::new(member).unwrap(),
            payload,
        )
        .unwrap();
        SignedStatement {
            signature: signers.sign(
                &Signers::did(member as u8),
                &ceremony_message_preimage(&bytes).unwrap(),
            ),
            bytes,
        }
    }
    fn close(
        c: &AuthorizedCeremony,
        prev: &TranscriptHash,
        messages: &[SignedStatement],
        signers: &Signers,
    ) -> SignedStatement {
        let bytes = round_closure_body(c, 1, prev, messages).unwrap();
        SignedStatement {
            signature: signers.sign(
                &signers.anchor().expected_owner,
                &round_closure_preimage(&bytes).unwrap(),
            ),
            bytes,
        }
    }

    #[test]
    fn closure_commits_owner_order_member_signatures_ceremony_round_and_previous() {
        let signers = Signers::new();
        let ceremony = signers.genesis();
        let prev = TranscriptHash::new([0; 32]);
        let messages = vec![
            message(&ceremony, 1, &[7], &signers),
            message(&ceremony, 2, &[8], &signers),
        ];
        let closure = close(&ceremony, &prev, &messages, &signers);
        let round = ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &closure, &messages, &signers)
            .unwrap();
        assert_eq!(round.messages()[0].payload(), &Ok(Byte(7)));
        assert_ne!(round.transcript_hash(), prev);
        let mut reordered = messages.clone();
        reordered.reverse();
        assert!(
            ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &closure, &reordered, &signers)
                .is_err()
        );
        assert!(
            ClosedRound::<Byte>::verify(&ceremony, 2, &prev, &closure, &messages, &signers)
                .is_err()
        );
        assert!(ClosedRound::<Byte>::verify(
            &ceremony,
            1,
            &TranscriptHash::new([9; 32]),
            &closure,
            &messages,
            &signers
        )
        .is_err());
        let mut changed = signers.body(CeremonyKind::Genesis, ceremony.threshold());
        changed.id = CeremonyId::new([99; 32]);
        let other = AuthorizedCeremony::verify_genesis(
            &signers.anchor(),
            &signers.statement(&changed),
            &signers,
        )
        .unwrap();
        assert!(
            ClosedRound::<Byte>::verify(&other, 1, &prev, &closure, &messages, &signers).is_err()
        );
        let mut invalid = messages.clone();
        invalid[0].signature[0] ^= 1;
        let signed_invalid = close(&ceremony, &prev, &invalid, &signers);
        assert!(matches!(
            ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &signed_invalid, &invalid, &signers),
            Err(Error::InvalidSignature)
        ));
        let mut invalid_owner = closure.clone();
        invalid_owner.signature[0] ^= 1;
        assert!(matches!(
            ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &invalid_owner, &messages, &signers),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn closed_round_preserves_authenticated_equivocation_and_malformed_payloads() {
        let signers = Signers::new();
        let ceremony = signers.genesis();
        let prev = TranscriptHash::new([0; 32]);
        let one = message(&ceremony, 1, &[7], &signers);
        let messages = vec![
            one.clone(),
            one,
            message(&ceremony, 1, &[8], &signers),
            message(&ceremony, 2, &[], &signers),
        ];
        let closure = close(&ceremony, &prev, &messages, &signers);
        let round = ClosedRound::<Byte>::verify(&ceremony, 1, &prev, &closure, &messages, &signers)
            .unwrap();
        assert_eq!(round.messages()[0].payload(), &Ok(Byte(7)));
        assert_eq!(round.messages()[2].payload(), &Ok(Byte(8)));
        assert_eq!(round.messages()[3].payload(), &Err(Error::InvalidEncoding));
        assert_eq!(round.messages()[0].member(), round.messages()[2].member());
        assert!(ceremony_message_body(
            &ceremony,
            1,
            MemberCohort::Current,
            MemberIndex::new(1).unwrap(),
            &[7]
        )
        .is_err());
    }
}

#[cfg(test)]
mod cohort_tests {
    use super::tests::Signers;
    use super::*;

    struct Payload;
    impl Decode for Payload {
        fn decode(_: &[u8]) -> Result<Self, Error> {
            Ok(Self)
        }
    }

    #[test]
    fn overlapping_indices_resolve_only_in_the_signed_cohort() {
        let signers = Signers::new();
        let (current, _) = crate::cert::tests::genesis(&signers);
        let mut body = signers.body(CeremonyKind::Reshare, current.key_context().threshold());
        body.current = Some(current.digest());
        body.epoch = current.key_context().epoch().checked_next().unwrap();
        body.recipients[0].node = Signers::did(9);
        let ceremony =
            AuthorizedCeremony::verify_for(&current, &signers.statement(&body), &signers).unwrap();
        let index = MemberIndex::new(1).unwrap();
        let mut messages = Vec::new();
        for (cohort, did) in [
            (MemberCohort::Current, Signers::did(1)),
            (MemberCohort::Recipients, Signers::did(9)),
        ] {
            let bytes = ceremony_message_body(&ceremony, 1, cohort, index, &[7]).unwrap();
            messages.push(SignedStatement {
                signature: signers.sign(&did, &ceremony_message_preimage(&bytes).unwrap()),
                bytes,
            });
        }
        let prev = TranscriptHash::new([0; 32]);
        let close = |messages: &[SignedStatement]| {
            let bytes = round_closure_body(&ceremony, 1, &prev, messages).unwrap();
            SignedStatement {
                signature: signers.sign(
                    &signers.anchor().expected_owner,
                    &round_closure_preimage(&bytes).unwrap(),
                ),
                bytes,
            }
        };
        let round = ClosedRound::<Payload>::verify(
            &ceremony,
            1,
            &prev,
            &close(&messages),
            &messages,
            &signers,
        )
        .unwrap();
        assert_eq!(round.messages()[0].cohort(), MemberCohort::Current);
        assert_eq!(round.messages()[1].cohort(), MemberCohort::Recipients);
        assert_eq!(round.messages()[0].statement(), &messages[0]);
        let mut forged = messages.clone();
        forged[1].signature = signers.sign(
            &Signers::did(1),
            &ceremony_message_preimage(&forged[1].bytes).unwrap(),
        );
        assert!(matches!(
            ClosedRound::<Payload>::verify(&ceremony, 1, &prev, &close(&forged), &forged, &signers),
            Err(Error::InvalidSignature)
        ));
        let mut stale = body.clone();
        stale.current = Some(CertDigest::new([99; 32]));
        assert!(
            AuthorizedCeremony::verify_for(&current, &signers.statement(&stale), &signers).is_err()
        );
        let (rekey, _, rekey_ceremony) = crate::cert::tests::successor(
            &signers,
            &current,
            CeremonyKind::Rekey,
            current.key_context().threshold(),
            12,
        );
        assert!(
            ceremony_message_body(&rekey_ceremony, 1, MemberCohort::Current, index, &[7]).is_err()
        );
        assert!(crate::cert::verify_successor(&current, &rekey, &signers).is_ok());
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::tests::Signers;
    use super::*;

    struct Payload;
    impl Decode for Payload {
        fn decode(_: &[u8]) -> Result<Self, Error> {
            Ok(Self)
        }
    }

    #[test]
    fn round_byte_and_signature_caps_precede_authentication() {
        let signers = Signers::new();
        let c = signers.genesis();
        let index = MemberIndex::new(1).unwrap();
        assert!(
            ceremony_message_body(&c, 1, MemberCohort::Recipients, index, &vec![0; 65_536])
                .is_err()
        );
        let bytes =
            ceremony_message_body(&c, 1, MemberCohort::Recipients, index, &[0; 60_000]).unwrap();
        let message = SignedStatement {
            signature: signers.sign(
                &Signers::did(1),
                &ceremony_message_preimage(&bytes).unwrap(),
            ),
            bytes,
        };
        let prev = TranscriptHash::new([0; 32]);
        assert!(round_closure_body(&c, 1, &prev, &vec![message.clone(); 70]).is_err());
        let mut oversized = message.clone();
        oversized.signature = vec![0; 513];
        assert!(round_closure_body(&c, 1, &prev, &[oversized]).is_err());
        let mut malformed = message.clone();
        malformed.bytes.push(0);
        let mut closure = SignedStatement {
            bytes: vec![0; 98],
            signature: vec![0; 64],
        };
        assert!(
            ClosedRound::<Payload>::verify(&c, 1, &prev, &closure, &[malformed], &signers).is_err()
        );
        closure.bytes = vec![0; 65_537];
        assert!(
            ClosedRound::<Payload>::verify(&c, 1, &prev, &closure, &[message], &signers).is_err()
        );
    }
}
