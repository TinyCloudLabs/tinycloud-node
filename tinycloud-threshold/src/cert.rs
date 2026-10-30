//! Canonical anchored certificates and candidate-share binding. Details: TC-2222

use crate::{
    ceremony::{text, AuthorizedCeremony, CeremonyKind, DidSignatureVerifier, TrustAnchor},
    context::KeyContext,
    curve::{Scalar, G2},
    derive::{KeyShare, MasterPublicKey, PublicKeySet},
    dst,
    encoding::{Decoder, Encoder},
    error::{CertError, Error},
    ids::*,
};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Context-free public polynomial output shared by certificate and ceremony APIs. Details: TC-2222
#[derive(Clone, Debug)]
pub struct PublicMaterial {
    threshold: Threshold,
    mpk: MasterPublicKey,
    commitments: Vec<G2>,
    public_shares: Vec<(MemberIndex, G2)>,
}
impl PublicMaterial {
    pub(crate) fn from_commitments(
        threshold: Threshold,
        commitments: Vec<G2>,
    ) -> Result<Self, Error> {
        if commitments.len() != usize::from(threshold.t()) {
            return Err(Error::InvalidLength);
        }
        let constant = commitments.first().ok_or(Error::InvalidLength)?;
        let top = commitments.last().ok_or(Error::InvalidLength)?;
        if constant.is_identity() || top.is_identity() {
            return Err(Error::IdentityPoint);
        }
        let mut public_shares = Vec::with_capacity(usize::from(threshold.n()));
        for i in 1..=threshold.n() {
            let x = Scalar::from_u64(u64::from(i));
            let point = commitments
                .iter()
                .rev()
                .fold(G2::identity(), |sum, coefficient| {
                    sum.mul(&x).add(coefficient)
                });
            if point.is_identity() {
                return Err(Error::IdentityPoint);
            }
            public_shares.push((MemberIndex::new(i)?, point));
        }
        Ok(Self {
            threshold,
            mpk: MasterPublicKey(constant.clone()),
            commitments,
            public_shares,
        })
    }

    /// Threshold and cohort size. Details: TC-2222
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }
    /// Non-identity master public key. Details: TC-2222
    pub fn master_public_key(&self) -> &MasterPublicKey {
        &self.mpk
    }
    /// Encoded coefficients in ascending polynomial degree. Details: TC-2222
    pub fn commitments(&self) -> impl ExactSizeIterator<Item = [u8; 96]> + '_ {
        self.commitments.iter().map(G2::encode)
    }
    /// Canonical evaluated public share at the given coordinate. Details: TC-2222
    pub fn public_share(&self, index: MemberIndex) -> Result<[u8; 96], Error> {
        self.public_shares
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, point)| point.encode())
            .ok_or(Error::InvalidIndex)
    }
}

/// Ceremony output scalar awaiting transcript and certificate binding. Details: TC-2222
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CandidateShare {
    #[zeroize(skip)]
    pub(crate) transcript: TranscriptHash,
    #[zeroize(skip)]
    pub(crate) index: MemberIndex,
    pub(crate) scalar: Scalar,
}
impl CandidateShare {
    #[cfg(test)]
    pub(crate) fn new(transcript: TranscriptHash, index: MemberIndex, scalar: Scalar) -> Self {
        Self {
            transcript,
            index,
            scalar,
        }
    }
    /// Transcript from which the candidate was produced. Details: TC-2222
    pub fn transcript_hash(&self) -> TranscriptHash {
        self.transcript
    }
    /// Candidate's Shamir coordinate. Details: TC-2222
    pub fn index(&self) -> MemberIndex {
        self.index
    }
}
impl fmt::Debug for CandidateShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CandidateShare([REDACTED])")
    }
}

impl KeyShare {
    /// Bind the candidate's transcript, coordinate and scalar to the verified certificate. Details: TC-2222
    pub fn bind(mut candidate: CandidateShare, cert: &VerifiedCertificate) -> Result<Self, Error> {
        if candidate.transcript != cert.body.transcript {
            return Err(Error::CandidateMismatch);
        }
        let public_share = cert
            .public
            .public_shares
            .iter()
            .find(|(i, _)| *i == candidate.index)
            .map(|(_, point)| point)
            .ok_or(Error::CandidateMismatch)?;
        if G2::generator().mul(&candidate.scalar) != *public_share {
            return Err(Error::CandidateMismatch);
        }
        let scalar = core::mem::replace(&mut candidate.scalar, Scalar::from_u64(0));
        Ok(Self {
            context: cert.key_context(),
            index: candidate.index,
            scalar,
        })
    }
}

/// A certificate's authenticated member identity. Details: TC-2222
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertMember {
    /// Shamir coordinate. Details: TC-2222
    pub index: MemberIndex,
    /// Node identity for response and readiness signatures. Details: TC-2222
    pub node: Did,
}

/// Canonical certificate body without an owner signature or freshness assertion. Details: TC-2222
#[derive(Clone, Debug)]
pub struct CertificateBody {
    network: NetworkUrn,
    owner: Did,
    rekey: RekeyCounter,
    epoch: Epoch,
    genesis_t: u16,
    members: Vec<CertMember>,
    public: PublicMaterial,
    transcript: TranscriptHash,
    previous: Option<CertDigest>,
    previous_mpk: Option<MasterPublicKey>,
}

impl CertificateBody {
    /// Build genesis from an anchored ceremony and its public output. Details: TC-2222
    pub fn genesis(
        anchor: &TrustAnchor,
        ceremony: &AuthorizedCeremony,
        public: &PublicMaterial,
        t: &TranscriptHash,
    ) -> Result<Self, Error> {
        if ceremony.kind() != CeremonyKind::Genesis || ceremony.anchor() != anchor {
            return Err(Error::ContextMismatch);
        }
        Self::from_ceremony(ceremony, public, t, public.threshold.t(), None, None)
    }

    /// Build a successor of the exact pinned certificate authorized by the ceremony. Details: TC-2222
    pub fn successor(
        prev: &VerifiedCertificate,
        ceremony: &AuthorizedCeremony,
        public: &PublicMaterial,
        t: &TranscriptHash,
    ) -> Result<Self, Error> {
        if ceremony.anchor() != prev.anchor()
            || ceremony.statement().current != Some(prev.digest)
            || ceremony.statement().epoch != prev.body.epoch.checked_next()?
        {
            return Err(Error::ContextMismatch);
        }
        let (genesis_t, previous_mpk) = match ceremony.kind() {
            CeremonyKind::Genesis => return Err(Error::InvalidCeremony),
            CeremonyKind::Rekey => {
                if public.mpk == prev.body.public.mpk
                    || ceremony.statement().rekey != prev.body.rekey.checked_next()?
                {
                    return Err(Error::ContextMismatch);
                }
                (public.threshold.t(), Some(prev.body.public.mpk.clone()))
            }
            CeremonyKind::Reshare | CeremonyKind::Refresh => {
                if public.mpk != prev.body.public.mpk
                    || ceremony.statement().rekey != prev.body.rekey
                {
                    return Err(Error::ContextMismatch);
                }
                (prev.body.genesis_t, None)
            }
        };
        Self::from_ceremony(
            ceremony,
            public,
            t,
            genesis_t,
            Some(prev.digest),
            previous_mpk,
        )
    }

    fn from_ceremony(
        c: &AuthorizedCeremony,
        public: &PublicMaterial,
        transcript: &TranscriptHash,
        genesis_t: u16,
        previous: Option<CertDigest>,
        previous_mpk: Option<MasterPublicKey>,
    ) -> Result<Self, Error> {
        if c.threshold() != public.threshold {
            return Err(Error::ContextMismatch);
        }
        let body = Self {
            network: c.anchor().network.clone(),
            owner: c.anchor().expected_owner.clone(),
            epoch: c.statement().epoch,
            rekey: c.statement().rekey,
            genesis_t,
            members: c
                .recipients()
                .iter()
                .map(|r| CertMember {
                    index: r.index,
                    node: r.node.clone(),
                })
                .collect(),
            public: public.clone(),
            transcript: *transcript,
            previous,
            previous_mpk,
        };
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), Error> {
        let threshold = self.public.threshold;
        if self.members.len() != usize::from(threshold.n()) || !(2..=16).contains(&self.genesis_t) {
            return Err(Error::InvalidEncoding);
        }
        for (index, member) in (1..=threshold.n()).zip(&self.members) {
            if member.index.get() != index
                || self
                    .members
                    .iter()
                    .filter(|m| m.node == member.node)
                    .count()
                    != 1
            {
                return Err(Error::InvalidEncoding);
            }
        }
        if self.public.commitments.first() != Some(&self.public.mpk.0) {
            return Err(Error::InvalidPoint);
        }
        match (&self.previous, &self.previous_mpk) {
            (None, None) => {
                if self.epoch.get() != 0 || self.rekey.get() != 0 || self.genesis_t != threshold.t()
                {
                    return Err(Error::InvalidEncoding);
                }
                threshold.check_genesis_budget()?;
            }
            (Some(_), old_mpk) => {
                if self.epoch.get() == 0 || self.rekey.get() > self.epoch.get() {
                    return Err(Error::InvalidEncoding);
                }
                if let Some(old_mpk) = old_mpk {
                    if self.rekey.get() == 0
                        || old_mpk == &self.public.mpk
                        || self.genesis_t != threshold.t()
                    {
                        return Err(Error::InvalidEncoding);
                    }
                    threshold.check_genesis_budget()?;
                }
            }
            _ => return Err(Error::InvalidEncoding),
        }
        Ok(())
    }

    /// Decode bounded canonical fields and validate every evaluated public share. Details: TC-2222
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        if d.u8()? != 1 {
            return Err(Error::InvalidEncoding);
        }
        let network = NetworkUrn::new(text(d.lp(1024)?)?)?;
        let owner = Did::new(text(d.lp(256)?)?)?;
        let rekey = RekeyCounter::new(d.u64()?);
        let epoch = Epoch::new(d.u64()?);
        let genesis_t = d.u16()?;
        let threshold = Threshold::new(d.u16()?, d.u16()?)?;
        let count = d.u16()?;
        if count != threshold.n() {
            return Err(Error::InvalidLength);
        }
        let mut members = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            members.push(CertMember {
                index: MemberIndex::new(d.u16()?)?,
                node: Did::new(text(d.lp(256)?)?)?,
            });
        }
        let mpk = MasterPublicKey::decode(&d.fixed::<96>()?)?;
        let count = d.u16()?;
        if count != threshold.t() {
            return Err(Error::InvalidLength);
        }
        let mut commitments = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            commitments.push(G2::decode(&d.fixed::<96>()?, true)?);
        }
        let public = PublicMaterial::from_commitments(threshold, commitments)?;
        if public.mpk != mpk {
            return Err(Error::InvalidPoint);
        }
        let transcript = TranscriptHash::new(d.fixed()?);
        let previous = match d.u8()? {
            0 => None,
            1 => Some(CertDigest::new(d.fixed()?)),
            _ => return Err(Error::InvalidEncoding),
        };
        let previous_mpk = match d.u8()? {
            0 => None,
            1 => Some(MasterPublicKey::decode(&d.fixed::<96>()?)?),
            _ => return Err(Error::InvalidEncoding),
        };
        d.finish()?;
        let body = Self {
            network,
            owner,
            rekey,
            epoch,
            genesis_t,
            members,
            public,
            transcript,
            previous,
            previous_mpk,
        };
        body.validate()?;
        Ok(body)
    }

    /// Encode the normative fixed certificate field order. Details: TC-2222
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(1);
        e.lp(self.network.as_bytes());
        e.lp(self.owner.as_bytes());
        e.u64(self.rekey.get());
        e.u64(self.epoch.get());
        e.u16(self.genesis_t);
        e.u16(self.public.threshold.t());
        e.u16(self.public.threshold.n());
        e.u16(self.members.len() as u16);
        for member in &self.members {
            e.u16(member.index.get());
            e.lp(member.node.as_bytes());
        }
        e.fixed(&self.public.mpk.encode());
        e.u16(self.public.commitments.len() as u16);
        for commitment in &self.public.commitments {
            e.fixed(&commitment.encode());
        }
        e.fixed(self.transcript.as_bytes());
        e.u8(u8::from(self.previous.is_some()));
        if let Some(previous) = self.previous {
            e.fixed(previous.as_bytes());
        }
        e.u8(u8::from(self.previous_mpk.is_some()));
        if let Some(previous_mpk) = &self.previous_mpk {
            e.fixed(&previous_mpk.encode());
        }
        e.finish()
    }
    /// Certificate digest under its dedicated domain. Details: TC-2222
    pub fn digest(&self) -> CertDigest {
        CertDigest::new(dst::tagged_hash(dst::NETWORK_CERT, &self.encode()))
    }
    /// Exact owner signing preimage. Details: TC-2222
    pub fn owner_statement(&self) -> Vec<u8> {
        dst::tagged_hash(dst::CERT_STATEMENT, self.digest().as_bytes()).to_vec()
    }
    /// Ordered node identity directory. Details: TC-2222
    pub fn members(&self) -> &[CertMember] {
        &self.members
    }
    /// Context-free public polynomial. Details: TC-2222
    pub fn public_material(&self) -> &PublicMaterial {
        &self.public
    }
    /// Transcript committed by this certificate. Details: TC-2222
    pub fn transcript_hash(&self) -> TranscriptHash {
        self.transcript
    }
}

/// Raw owner-signed certificate. Details: TC-2222
#[derive(Clone, Debug)]
pub struct SignedCertificate {
    /// Decoded canonical body. Details: TC-2222
    pub body: CertificateBody,
    /// Owner signature over body.owner_statement(). Details: TC-2222
    pub owner_signature: Vec<u8>,
}

/// Anchored verified certificate; newest-head selection remains with the caller. Details: TC-2222
#[derive(Clone, Debug)]
pub struct VerifiedCertificate {
    body: CertificateBody,
    anchor: TrustAnchor,
    digest: CertDigest,
    public: PublicKeySet,
}

/// Validate the decoded body and owner signature under the external anchor. Details: TC-2222
pub fn verify_certificate(
    anchor: &TrustAnchor,
    signed: &SignedCertificate,
    v: &impl DidSignatureVerifier,
) -> Result<VerifiedCertificate, CertError> {
    let body = &signed.body;
    if body.owner != anchor.expected_owner || body.network != anchor.network {
        return Err(CertError::AnchorMismatch);
    }
    body.validate()?;
    let digest = body.digest();
    let owner_preimage = dst::tagged_hash(dst::CERT_STATEMENT, digest.as_bytes());
    if signed.owner_signature.is_empty()
        || signed.owner_signature.len() > 512
        || v.verify(
            &anchor.expected_owner,
            &owner_preimage,
            &signed.owner_signature,
        )
        .is_err()
    {
        return Err(CertError::InvalidSignature);
    }
    let context = KeyContext {
        network: body.network.clone(),
        rekey: body.rekey,
        epoch: body.epoch,
        certificate: digest,
        threshold: body.public.threshold,
    };
    let public = PublicKeySet {
        context,
        mpk: body.public.mpk.clone(),
        public_shares: body.public.public_shares.clone(),
    };
    Ok(VerifiedCertificate {
        body: body.clone(),
        anchor: anchor.clone(),
        digest,
        public,
    })
}

/// Verify one checked-generation transition from an externally pinned predecessor. Details: TC-2222
pub fn verify_successor(
    pinned: &VerifiedCertificate,
    next: &SignedCertificate,
    v: &impl DidSignatureVerifier,
) -> Result<VerifiedCertificate, CertError> {
    let epoch = pinned.body.epoch.checked_next()?;
    let body = &next.body;
    if body.previous != Some(pinned.digest) || body.epoch != epoch {
        return Err(CertError::InvalidLineage);
    }
    match &body.previous_mpk {
        None => {
            if body.public.mpk != pinned.body.public.mpk
                || body.rekey != pinned.body.rekey
                || body.genesis_t != pinned.body.genesis_t
            {
                return Err(CertError::InvalidLineage);
            }
        }
        Some(previous_mpk) => {
            if body.rekey != pinned.body.rekey.checked_next()?
                || previous_mpk != &pinned.body.public.mpk
                || body.public.mpk == pinned.body.public.mpk
                || body.genesis_t != body.public.threshold.t()
            {
                return Err(CertError::InvalidLineage);
            }
        }
    }
    verify_certificate(&pinned.anchor, next, v)
}

impl VerifiedCertificate {
    /// Canonical body authenticated by the owner. Details: TC-2222
    pub fn body(&self) -> &CertificateBody {
        &self.body
    }
    /// External anchor used during verification. Details: TC-2222
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }
    /// Canonical body digest. Details: TC-2222
    pub fn digest(&self) -> CertDigest {
        self.digest
    }
    /// Certificate-bound key context. Details: TC-2222
    pub fn key_context(&self) -> KeyContext {
        self.public.context.clone()
    }
    /// Certificate-bound public shares. Details: TC-2222
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public
    }
    /// Resolve the specified member in this certificate only. Details: TC-2222
    pub fn member(&self, index: MemberIndex) -> Result<&CertMember, CertError> {
        self.body
            .members
            .iter()
            .find(|m| m.index == index)
            .ok_or(CertError::InvalidMembers)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ceremony::{tests::Signers, CeremonyKind, CeremonyStatement};

    pub(crate) fn material(seed: u8, threshold: Threshold) -> (PublicMaterial, Vec<KeyShare>) {
        let context = KeyContext::test(
            Signers::new().anchor().network,
            RekeyCounter::new(0),
            Epoch::new(0),
            CertDigest::new([0; 32]),
            threshold,
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
            assert_eq!(
                pk,
                &public.public_shares.iter().find(|(j, _)| j == i).unwrap().1
            );
        }
        (material, shares)
    }
    pub(crate) fn sign(body: CertificateBody, signers: &Signers) -> SignedCertificate {
        let owner_signature = signers.sign(&body.owner, &body.owner_statement());
        SignedCertificate {
            body,
            owner_signature,
        }
    }
    pub(crate) fn genesis(signers: &Signers) -> (VerifiedCertificate, Vec<KeyShare>) {
        let (public, raw) = material(11, Threshold::new(2, 3).unwrap());
        let transcript = TranscriptHash::new([51; 32]);
        let body =
            CertificateBody::genesis(&signers.anchor(), &signers.genesis(), &public, &transcript)
                .unwrap();
        let cert = verify_certificate(&signers.anchor(), &sign(body, signers), signers).unwrap();
        let bound = raw
            .into_iter()
            .map(|mut raw| {
                let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
                KeyShare::bind(CandidateShare::new(transcript, raw.index, scalar), &cert).unwrap()
            })
            .collect();
        (cert, bound)
    }
    pub(crate) fn successor(
        signers: &Signers,
        prev: &VerifiedCertificate,
        kind: CeremonyKind,
        threshold: Threshold,
        seed: u8,
    ) -> (SignedCertificate, Vec<KeyShare>, AuthorizedCeremony) {
        let mut stmt = signers.body(kind, threshold);
        stmt.id = CeremonyId::new([52; 32]);
        stmt.current = Some(prev.digest());
        stmt.epoch = prev.body.epoch.checked_next().unwrap();
        stmt.rekey = if kind == CeremonyKind::Rekey {
            prev.body.rekey.checked_next().unwrap()
        } else {
            prev.body.rekey
        };
        let ceremony =
            AuthorizedCeremony::verify_for(prev, &signers.statement(&stmt), signers).unwrap();
        let (public, shares) = material(seed, threshold);
        let body =
            CertificateBody::successor(prev, &ceremony, &public, &TranscriptHash::new([53; 32]))
                .unwrap();
        (sign(body, signers), shares, ceremony)
    }

    #[test]
    fn dealer_certificate_chain_preserves_master_until_rekey_and_binds_candidates() {
        let signers = Signers::new();
        let (genesis, shares) = genesis(&signers);
        assert_eq!(shares[0].context(), &genesis.key_context());
        let (reshare, raw, _) = successor(
            &signers,
            &genesis,
            CeremonyKind::Reshare,
            Threshold::new(3, 4).unwrap(),
            11,
        );
        let reshare = verify_successor(&genesis, &reshare, &signers).unwrap();
        assert_eq!(
            reshare.public_key_set().master_public_key(),
            genesis.public_key_set().master_public_key()
        );
        assert_eq!(reshare.key_context().epoch().get(), 1);
        assert_eq!(
            reshare.key_context().threshold(),
            Threshold::new(3, 4).unwrap()
        );
        for mut raw in raw {
            let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
            assert!(KeyShare::bind(
                CandidateShare::new(reshare.body.transcript, raw.index, scalar),
                &reshare
            )
            .is_ok());
        }
        let (rekey, _, _) = successor(
            &signers,
            &reshare,
            CeremonyKind::Rekey,
            Threshold::new(2, 3).unwrap(),
            12,
        );
        let rekey = verify_successor(&reshare, &rekey, &signers).unwrap();
        assert_ne!(
            rekey.public_key_set().master_public_key(),
            reshare.public_key_set().master_public_key()
        );
        assert_eq!(rekey.key_context().epoch().get(), 2);
        assert_eq!(rekey.key_context().rekey().get(), 1);
        assert!(verify_successor(&rekey, &sign(genesis.body.clone(), &signers), &signers).is_err());
        assert!(KeyShare::bind(
            CandidateShare::new(
                genesis.body.transcript,
                shares[0].index,
                Scalar::from_u64(1)
            ),
            &genesis
        )
        .is_err());
        assert!(KeyShare::bind(
            CandidateShare::new(
                TranscriptHash::new([99; 32]),
                shares[0].index,
                Scalar::from_u64(1)
            ),
            &genesis
        )
        .is_err());
    }

    #[test]
    fn certificate_rejects_wrong_owner_signature() {
        let signers = Signers::new();
        let (cert, _) = genesis(&signers);
        let non_owner = Signers::did(9);
        let preimage = cert.body.owner_statement();
        let wrong_owner = SignedCertificate {
            body: cert.body.clone(),
            owner_signature: signers.sign(&non_owner, &preimage),
        };
        signers
            .verify(&non_owner, &preimage, &wrong_owner.owner_signature)
            .unwrap();
        assert!(matches!(
            verify_certificate(&signers.anchor(), &wrong_owner, &signers),
            Err(CertError::InvalidSignature)
        ));

        let mut tampered = sign(cert.body.clone(), &signers);
        tampered.owner_signature[0] ^= 1;
        assert!(matches!(
            verify_certificate(&signers.anchor(), &tampered, &signers),
            Err(CertError::InvalidSignature)
        ));
    }

    #[test]
    fn decoded_certificate_invariants_apply_before_verified_contexts_exist() {
        let signers = Signers::new();
        let (cert, _) = genesis(&signers);
        assert_eq!(
            CertificateBody::decode(&cert.body.encode())
                .unwrap()
                .encode(),
            cert.body.encode()
        );
        let threshold_offset = 1
            + 4
            + cert.body.network.as_bytes().len()
            + 4
            + cert.body.owner.as_bytes().len()
            + 8
            + 8
            + 2;
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
        let mut bytes = cert.body.encode();
        bytes.push(0);
        assert!(CertificateBody::decode(&bytes).is_err());
        for length in 0..cert.body.encode().len() {
            assert!(CertificateBody::decode(&cert.body.encode()[..length]).is_err());
        }
        let mut impostor = cert.body.clone();
        impostor.owner = Signers::did(9);
        assert!(matches!(
            verify_certificate(&signers.anchor(), &sign(impostor, &signers), &signers),
            Err(CertError::AnchorMismatch)
        ));
    }

    #[test]
    fn pinned_lineage_checks_every_generation_field_and_overflow() {
        let signers = Signers::new();
        let (prev, _) = genesis(&signers);
        let (valid, _, _) = successor(
            &signers,
            &prev,
            CeremonyKind::Reshare,
            Threshold::new(2, 3).unwrap(),
            11,
        );
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
        let (rekey, _, _) = successor(
            &signers,
            &prev,
            CeremonyKind::Rekey,
            Threshold::new(2, 3).unwrap(),
            12,
        );
        let mut missing = rekey.body.clone();
        missing.previous_mpk = None;
        assert!(verify_successor(&prev, &sign(missing, &signers), &signers).is_err());
        let mut body = valid.body.clone();
        body.epoch = Epoch::new(u64::MAX);
        let max = verify_certificate(&signers.anchor(), &sign(body, &signers), &signers).unwrap();
        assert!(matches!(
            verify_successor(&max, &valid, &signers),
            Err(CertError::Invalid(Error::CounterOverflow))
        ));
        let mut body = rekey.body.clone();
        body.epoch = Epoch::new(u64::MAX);
        body.rekey = RekeyCounter::new(u64::MAX);
        let max = verify_certificate(&signers.anchor(), &sign(body, &signers), &signers).unwrap();
        let mut stmt: CeremonyStatement =
            signers.body(CeremonyKind::Rekey, Threshold::new(2, 3).unwrap());
        stmt.current = Some(max.digest());
        assert!(matches!(
            AuthorizedCeremony::verify_for(&max, &signers.statement(&stmt), &signers),
            Err(Error::CounterOverflow)
        ));
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use crate::{
        activation::{
            activation_preimage, readiness_preimage, verify_activation, ReadinessReceipt,
            ReadyQuorum,
        },
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
            &cert.key_context(),
            crate::checkpoint::identity(&cert.key_context(), "smoke/key"),
            tsk.public_key(),
        )
        .unwrap();
        let auth = crate::checkpoint::authorize(request.clone());
        let issued: Vec<_> = shares
            .iter()
            .map(|s| issue_share(s, &auth, &mut rng).unwrap())
            .collect();
        let encrypted = combine(cert.public_key_set(), &request, &issued).unwrap();
        let derived =
            decrypt_derived_key(&encrypted, &tsk, cert.public_key_set(), &request).unwrap();
        let data = DataKey::new([0x42; 32]);
        let wrapped = wrap_key(
            cert.public_key_set().master_public_key(),
            request.identity(),
            &data,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            unwrap_key(&derived, request.identity(), &wrapped)
                .unwrap()
                .as_bytes(),
            data.as_bytes()
        );
        println!("2. PASS: certificate-bound shares issue, combine, derive and unwrap");
        let mut bad = issued[0].clone();
        bad.c3 = bad.c3.add(&crate::curve::G1::generator());
        let signature = signers.sign(&Signers::did(1), &bad.signing_preimage(&request).unwrap());
        let proof = FaultProof {
            request: request.clone(),
            share: bad,
            signature,
        };
        assert_eq!(
            verify_fault_proof(&cert, &proof, &signers),
            FaultVerdict::Fault(shares[0].index())
        );
        println!("3. PASS: genuine correctly bound signed bad response attributes its signer");
        let (reshared, raw, _) = tests::successor(
            &signers,
            &cert,
            crate::ceremony::CeremonyKind::Reshare,
            Threshold::new(3, 4).unwrap(),
            11,
        );
        let reshared = verify_successor(&cert, &reshared, &signers).unwrap();
        let bound: Vec<_> = raw
            .into_iter()
            .map(|mut raw| {
                let scalar = core::mem::replace(&mut raw.scalar, Scalar::from_u64(0));
                KeyShare::bind(
                    CandidateShare::new(reshared.body.transcript, raw.index, scalar),
                    &reshared,
                )
                .unwrap()
            })
            .collect();
        let ready: Vec<_> = bound
            .iter()
            .map(|share| ReadinessReceipt {
                index: share.index(),
                signature: signers.sign(
                    &reshared.member(share.index()).unwrap().node,
                    &readiness_preimage(reshared.body(), share.index()).unwrap(),
                ),
            })
            .collect();
        let bytes = activation_preimage(reshared.body(), &ready).unwrap();
        let activate_reshare = crate::ceremony::SignedStatement {
            signature: signers.sign(&reshared.anchor().expected_owner, &bytes),
            bytes,
        };
        verify_activation(
            &reshared,
            &ready,
            ReadyQuorum::AllHolders,
            &activate_reshare,
            &signers,
        )
        .unwrap();
        assert_eq!(
            reshared.public_key_set().master_public_key(),
            cert.public_key_set().master_public_key()
        );
        println!("3a. PASS: 2-of-3 genesis to 3-of-4 reshare; four bound candidate shares and all-holder activation");
        let (next, _, _) = tests::successor(
            &signers,
            &reshared,
            crate::ceremony::CeremonyKind::Rekey,
            cert.key_context().threshold(),
            12,
        );
        let next = verify_successor(&reshared, &next, &signers).unwrap();
        assert_eq!(
            verify_fault_proof(&next, &proof, &signers),
            FaultVerdict::NotAFault(NotAFaultReason::ContextMismatch)
        );
        println!("4. PASS: old response under re-keyed certificate is NotAFault");
        let receipts: Vec<_> = shares
            .iter()
            .map(|share| ReadinessReceipt {
                index: share.index(),
                signature: signers.sign(
                    &cert.member(share.index()).unwrap().node,
                    &readiness_preimage(cert.body(), share.index()).unwrap(),
                ),
            })
            .collect();
        let bytes = activation_preimage(cert.body(), &receipts).unwrap();
        let activation = crate::ceremony::SignedStatement {
            signature: signers.sign(&cert.anchor().expected_owner, &bytes),
            bytes,
        };
        verify_activation(
            &cert,
            &receipts,
            ReadyQuorum::AllHolders,
            &activation,
            &signers,
        )
        .unwrap();
        assert!(verify_activation(
            &cert,
            &receipts[..2],
            ReadyQuorum::AllHolders,
            &activation,
            &signers
        )
        .is_err());
        println!("5. PASS: all-holder receipts activate; under-quorum receipt set does not");
    }
}

#[cfg(test)]
mod vector_contracts {
    use super::*;
    use crate::{
        activation::{verify_activation, ReadinessReceipt, ReadyQuorum},
        ceremony::{tests::Signers, ClosedRound, Decode, SignedStatement},
        derive::{DecryptRequest, EncryptedKeyShare},
        fault::{verify_fault_proof, FaultProof, FaultVerdict, NotAFaultReason},
    };
    use serde_json::Value;

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }
    fn statement(body: &Value, signature: &Value) -> SignedStatement {
        SignedStatement {
            bytes: bytes(body),
            signature: bytes(signature),
        }
    }
    fn fixed(value: &Value) -> [u8; 32] {
        bytes(value).try_into().unwrap()
    }
    struct Payload;
    impl Decode for Payload {
        fn decode(_: &[u8]) -> Result<Self, Error> {
            Ok(Self)
        }
    }

    #[test]
    fn published_certificate_vectors_execute_the_real_verification_contracts() {
        let vectors: Value =
            serde_json::from_str(include_str!("../vectors/v1/cert-core.json")).unwrap();
        let signers = Signers::new();
        let mut certificates = Vec::<VerifiedCertificate>::new();
        for case in vectors["cases"].as_array().unwrap() {
            let inputs = &case["inputs"];
            let outputs = &case["outputs"];
            match case["operation"].as_str().unwrap() {
                "verify_certificate" => {
                    let body = CertificateBody::decode(&bytes(&inputs["body"])).unwrap();
                    let anchor = TrustAnchor {
                        expected_owner: Did::new(inputs["expected_owner"].as_str().unwrap())
                            .unwrap(),
                        network: NetworkUrn::new(inputs["network"].as_str().unwrap()).unwrap(),
                    };
                    let signed = SignedCertificate {
                        body,
                        owner_signature: bytes(&inputs["owner_signature"]),
                    };
                    let cert = if let Some(prev) = inputs["pinned_predecessor"].as_str() {
                        let pinned = certificates
                            .iter()
                            .find(|c| hex::encode(c.digest.as_bytes()) == prev)
                            .unwrap();
                        verify_successor(pinned, &signed, &signers).unwrap()
                    } else {
                        verify_certificate(&anchor, &signed, &signers).unwrap()
                    };
                    assert_eq!(cert.digest.as_bytes(), &fixed(&outputs["digest"]));
                    assert_eq!(
                        cert.body.owner_statement(),
                        bytes(&outputs["owner_statement"])
                    );
                    for share in outputs["public_shares"].as_array().unwrap() {
                        let index =
                            MemberIndex::new(share["index"].as_u64().unwrap() as u16).unwrap();
                        assert_eq!(
                            cert.body.public.public_share(index).unwrap().as_slice(),
                            bytes(&share["point"])
                        );
                    }
                    certificates.push(cert);
                }
                "decode_certificate" => {
                    let error = CertificateBody::decode(&bytes(&inputs["body"])).unwrap_err();
                    assert_eq!(format!("{error:?}"), case["error"].as_str().unwrap());
                }
                "authorize_ceremony" => {
                    let signed = statement(&inputs["body"], &inputs["signature"]);
                    let result = if let Some(prev) = inputs["pinned_predecessor"].as_str() {
                        let pinned = certificates
                            .iter()
                            .find(|c| hex::encode(c.digest.as_bytes()) == prev)
                            .unwrap();
                        AuthorizedCeremony::verify_for(pinned, &signed, &signers)
                    } else {
                        AuthorizedCeremony::verify_genesis(&signers.anchor(), &signed, &signers)
                    };
                    if let Some(error) = case["error"].as_str() {
                        assert_eq!(format!("{:?}", result.unwrap_err()), error);
                    } else {
                        assert_eq!(result.unwrap().digest(), fixed(&outputs["digest"]));
                    }
                }
                "verify_closed_round" => {
                    let ceremony = signers.genesis();
                    let previous = TranscriptHash::new(fixed(&inputs["previous"]));
                    let closure = statement(&inputs["closure"], &inputs["owner_signature"]);
                    let messages: Vec<_> = inputs["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|m| statement(&m["body"], &m["signature"]))
                        .collect();
                    let closed = ClosedRound::<Payload>::verify(
                        &ceremony,
                        inputs["round"].as_u64().unwrap() as u8,
                        &previous,
                        &closure,
                        &messages,
                        &signers,
                    )
                    .unwrap();
                    assert_eq!(
                        closed.transcript_hash().as_bytes(),
                        &fixed(&outputs["transcript_hash"])
                    );
                }
                "verify_activation" => {
                    let cert = certificates
                        .iter()
                        .find(|c| c.digest.as_bytes() == &fixed(&inputs["candidate"]))
                        .unwrap();
                    let receipts: Vec<_> = inputs["receipts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| ReadinessReceipt {
                            index: MemberIndex::new(r["index"].as_u64().unwrap() as u16).unwrap(),
                            signature: bytes(&r["signature"]),
                        })
                        .collect();
                    let preimage = if case["error"].is_string() {
                        &inputs["activation_preimage"]
                    } else {
                        &outputs["activation_preimage"]
                    };
                    let signed = statement(preimage, &inputs["owner_signature"]);
                    let q = inputs["budget"]
                        .as_u64()
                        .map(|b| ReadyQuorum::WithOutageBudget(b as u16))
                        .unwrap_or(ReadyQuorum::AllHolders);
                    let result = verify_activation(cert, &receipts, q, &signed, &signers);
                    if let Some(error) = case["error"].as_str() {
                        assert_eq!(format!("{:?}", result.unwrap_err()), error);
                    } else {
                        result.unwrap();
                    }
                }
                "verify_fault_proof" => {
                    let extra = if inputs["certificate_body"].is_string() {
                        let signed = SignedCertificate {
                            body: CertificateBody::decode(&bytes(&inputs["certificate_body"]))
                                .unwrap(),
                            owner_signature: bytes(&inputs["owner_signature"]),
                        };
                        Some(verify_certificate(&signers.anchor(), &signed, &signers).unwrap())
                    } else {
                        None
                    };
                    let cert = extra.as_ref().unwrap_or_else(|| {
                        certificates
                            .iter()
                            .find(|c| c.digest.as_bytes() == &fixed(&inputs["certificate"]))
                            .unwrap()
                    });
                    let proof = FaultProof {
                        request: DecryptRequest::decode(&bytes(&inputs["request"])).unwrap(),
                        share: EncryptedKeyShare::decode(&bytes(&inputs["share"])).unwrap(),
                        signature: bytes(&inputs["signature"]),
                    };
                    let verdict = verify_fault_proof(cert, &proof, &signers);
                    let expected = if outputs["verdict"] == "Fault" {
                        FaultVerdict::Fault(
                            MemberIndex::new(outputs["member"].as_u64().unwrap() as u16).unwrap(),
                        )
                    } else {
                        FaultVerdict::NotAFault(match outputs["reason"].as_str().unwrap() {
                            "ValidShare" => NotAFaultReason::ValidShare,
                            "ContextMismatch" => NotAFaultReason::ContextMismatch,
                            _ => panic!("unknown vector reason"),
                        })
                    };
                    assert_eq!(verdict, expected);
                }
                _ => panic!("unknown vector operation"),
            }
        }
    }
}
