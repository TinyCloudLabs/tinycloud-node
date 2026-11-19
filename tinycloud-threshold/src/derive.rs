//! Context-bound encrypted key shares (SPEC §3.6).
use crate::{
    context::{AuthorizedDerivation, KeyContext},
    curve::{hash_g1, pairing_check, Scalar, G1, G2},
    dst,
    encoding::{Decoder, Encoder},
    error::{CombineError, Error, ShareError},
    identity::IbeIdentity,
    ids::*,
};
use core::fmt;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Master public key in G2, never the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterPublicKey(pub(crate) G2);
impl MasterPublicKey {
    /// Decodes a canonical non-identity prime-order point.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(G2::decode(bytes, false)?))
    }
    /// Returns the canonical compressed point.
    pub fn encode(&self) -> [u8; 96] {
        self.0.encode()
    }
}

/// Public shares for exactly one key context; constructed by a certificate path.
#[derive(Clone, Debug)]
pub struct PublicKeySet {
    pub(crate) context: KeyContext,
    pub(crate) mpk: MasterPublicKey,
    pub(crate) public_shares: Vec<(MemberIndex, G2)>,
}
impl PublicKeySet {
    /// The exact context from which this set was constructed.
    pub fn context(&self) -> &KeyContext {
        &self.context
    }
    /// The master public key.
    pub fn master_public_key(&self) -> &MasterPublicKey {
        &self.mpk
    }
    fn public_share(&self, index: MemberIndex) -> Option<&G2> {
        self.public_shares
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, p)| p)
    }
}

/// One member's context-bound scalar, with no public S0.1 constructor.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    #[zeroize(skip)]
    pub(crate) context: KeyContext,
    #[zeroize(skip)]
    pub(crate) index: MemberIndex,
    pub(crate) scalar: Scalar,
}
impl KeyShare {
    /// Context under which this scalar may issue shares.
    pub fn context(&self) -> &KeyContext {
        &self.context
    }
    /// The Shamir x-coordinate.
    pub fn index(&self) -> MemberIndex {
        self.index
    }
}
impl fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyShare([REDACTED])")
    }
}

/// Reader transport scalar; generated from 64 CSPRNG bytes reduced modulo r.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TransportSecretKey(pub(crate) Scalar);
impl TransportSecretKey {
    /// Samples a nonzero transport scalar.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::random(rng, true))
    }
    /// Corresponding non-identity G1 point.
    pub fn public_key(&self) -> TransportPublicKey {
        TransportPublicKey(G1::generator().mul(&self.0))
    }
}
impl fmt::Debug for TransportSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportSecretKey([REDACTED])")
    }
}

/// Reader transport point in G1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportPublicKey(pub(crate) G1);
impl TransportPublicKey {
    /// Decodes and checks the transport point's non-identity field role.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(G1::decode(bytes, false)?))
    }
    /// Returns its canonical compressed bytes.
    pub fn encode(&self) -> [u8; 48] {
        self.0.encode()
    }
}

/// Raw request; possession of this type does not authorize issuing a share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptRequest {
    pub(crate) context_digest: [u8; 32],
    pub(crate) network: NetworkUrn,
    pub(crate) rekey: RekeyCounter,
    pub(crate) epoch: Epoch,
    pub(crate) certificate: CertDigest,
    pub(crate) identity: IbeIdentity,
    pub(crate) tpk: TransportPublicKey,
}
impl DecryptRequest {
    /// Builds a request for a context, requiring the identity's outer network.
    pub fn new(
        ctx: &KeyContext,
        identity: IbeIdentity,
        tpk: TransportPublicKey,
    ) -> Result<Self, Error> {
        if identity.network() != ctx.network() {
            return Err(Error::ContextMismatch);
        }
        Ok(Self {
            context_digest: ctx.digest(),
            network: ctx.network().clone(),
            rekey: ctx.rekey(),
            epoch: ctx.epoch(),
            certificate: *ctx.certificate(),
            identity,
            tpk,
        })
    }
    /// The identity to derive.
    pub fn identity(&self) -> &IbeIdentity {
        &self.identity
    }
    /// The request's canonical digest.
    pub fn digest(&self) -> RequestDigest {
        RequestDigest::new(dst::tagged_hash(dst::DECRYPT_REQUEST, &self.encode()))
    }
    /// Canonical request layout documented in SPEC.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(1);
        e.fixed(&self.context_digest);
        e.lp(self.network.as_bytes());
        e.u64(self.rekey.get());
        e.u64(self.epoch.get());
        e.fixed(self.certificate.as_bytes());
        e.lp(self.identity.as_bytes());
        e.fixed(&self.tpk.encode());
        e.finish()
    }
    /// Bounded decoding checks the identity/network relation before returning.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        if d.u8()? != 1 {
            return Err(Error::InvalidEncoding);
        }
        let context_digest = d.fixed()?;
        let network = NetworkUrn::new(
            core::str::from_utf8(d.lp(1024)?).map_err(|_| Error::InvalidEncoding)?,
        )?;
        let rekey = RekeyCounter::new(d.u64()?);
        let epoch = Epoch::new(d.u64()?);
        let certificate = CertDigest::new(d.fixed()?);
        let identity = IbeIdentity::decode(d.lp(4096)?)?;
        let tpk = TransportPublicKey::decode(&d.fixed::<48>()?)?;
        d.finish()?;
        if identity.network() != &network {
            return Err(Error::ContextMismatch);
        }
        Ok(Self {
            context_digest,
            network,
            rekey,
            epoch,
            certificate,
            identity,
            tpk,
        })
    }
    fn matches(&self, ctx: &KeyContext) -> bool {
        self.context_digest == ctx.digest()
            && self.network == *ctx.network()
            && self.rekey == ctx.rekey()
            && self.epoch == ctx.epoch()
            && self.certificate == *ctx.certificate()
            && self.identity.network() == &self.network
    }
}
impl TryFrom<&[u8]> for DecryptRequest {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Error> {
        Self::decode(v)
    }
}

/// Encrypted member share. Both context and request digest are checked first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedKeyShare {
    pub(crate) member: MemberIndex,
    pub(crate) context_digest: [u8; 32],
    pub(crate) request_digest: [u8; 32],
    pub(crate) c1: G1,
    pub(crate) c2: G2,
    pub(crate) c3: G1,
}
impl EncryptedKeyShare {
    /// The issuing member's index.
    pub fn index(&self) -> MemberIndex {
        self.member
    }
    /// Canonical layout, including the approved request-digest amendment.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(1);
        e.u16(self.member.get());
        e.fixed(&self.context_digest);
        e.fixed(&self.request_digest);
        e.fixed(&self.c1.encode());
        e.fixed(&self.c2.encode());
        e.fixed(&self.c3.encode());
        e.finish()
    }
    /// Decodes c1/c2 as non-identity and c3 with identity permitted.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        if d.u8()? != 1 {
            return Err(Error::InvalidEncoding);
        }
        let member = MemberIndex::new(d.u16()?)?;
        let context_digest = d.fixed()?;
        let request_digest = d.fixed()?;
        let c1 = G1::decode(&d.fixed::<48>()?, false)?;
        let c2 = G2::decode(&d.fixed::<96>()?, false)?;
        let c3 = G1::decode(&d.fixed::<48>()?, true)?;
        d.finish()?;
        Ok(Self {
            member,
            context_digest,
            request_digest,
            c1,
            c2,
            c3,
        })
    }
    /// Tagged 32-byte preimage for a node-key signature; request digest is explicit.
    /// Returns `ContextMismatch` if the supplied request differs from the issued request.
    pub fn signing_preimage(&self, req: &DecryptRequest) -> Result<Vec<u8>, Error> {
        let request_digest = req.digest();
        if self.request_digest != *request_digest.as_bytes() {
            return Err(Error::ContextMismatch);
        }
        let mut e = Encoder::new();
        e.fixed(request_digest.as_bytes());
        e.fixed(req.certificate.as_bytes());
        e.u16(self.member.get());
        e.fixed(&self.encode());
        Ok(dst::tagged_hash(dst::DECRYPT_SHARE, &e.finish()).to_vec())
    }
    fn matches(&self, ctx: &KeyContext, req: &DecryptRequest) -> bool {
        self.context_digest == ctx.digest()
            && self.request_digest == *req.digest().as_bytes()
            && self.member.get() <= ctx.threshold().n()
    }
}
impl TryFrom<&[u8]> for EncryptedKeyShare {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Error> {
        Self::decode(v)
    }
}

/// Issues an encrypted share only for the exact authorized request context.
pub fn issue_share(
    share: &KeyShare,
    auth: &AuthorizedDerivation,
    rng: &mut impl CryptoRngCore,
) -> Result<EncryptedKeyShare, Error> {
    let req = &auth.request;
    if !req.matches(&share.context) || share.index.get() > share.context.threshold().n() {
        return Err(Error::ContextMismatch);
    }
    let r = Scalar::random(rng, true);
    let contribution = Zeroizing::new(hash_g1(req.identity.as_bytes(), dst::H1).mul(&share.scalar));
    let mask = Zeroizing::new(req.tpk.0.mul(&r));
    Ok(EncryptedKeyShare {
        member: share.index,
        context_digest: share.context.digest(),
        request_digest: *req.digest().as_bytes(),
        c1: G1::generator().mul(&r),
        c2: G2::generator().mul(&r),
        c3: contribution.add(&mask),
    })
}

/// Checks context before separately checking both member-share equations.
pub fn verify_share(
    public: &PublicKeySet,
    req: &DecryptRequest,
    share: &EncryptedKeyShare,
) -> Result<(), ShareError> {
    if !req.matches(&public.context) || !share.matches(&public.context, req) {
        return Err(ShareError::ContextMismatch);
    }
    let pk = public
        .public_share(share.member)
        .ok_or(ShareError::ContextMismatch)?;
    let g1 = G1::generator();
    let g2 = G2::generator();
    let neg_g1 = G1::identity().sub(&g1);
    if !pairing_check(&[(&share.c1, &g2), (&neg_g1, &share.c2)]) {
        return Err(ShareError::Invalid {
            member: share.member,
        });
    }
    let h = hash_g1(req.identity.as_bytes(), dst::H1);
    let neg_h = G1::identity().sub(&h);
    let neg_tpk = G1::identity().sub(&req.tpk.0);
    if !pairing_check(&[(&share.c3, &g2), (&neg_h, pk), (&neg_tpk, &share.c2)]) {
        return Err(ShareError::Invalid {
            member: share.member,
        });
    }
    Ok(())
}

/// An aggregate for one request; identity intermediate components are permitted.
#[derive(Debug)]
pub struct EncryptedDerivedKey {
    context_digest: [u8; 32],
    request_digest: [u8; 32],
    pub(crate) c1: G1,
    // SPEC retains all three aggregate components; unmasking uses C1 and C3.
    #[allow(dead_code)]
    pub(crate) c2: G2,
    pub(crate) c3: G1,
}

/// Verifies every input, counts each member once, then uses the lowest t indices.
/// Refuses more than `2 * n` entries, including duplicates, before context checks
/// or algebra, where `n` is the validated current member count.
pub fn combine(
    public: &PublicKeySet,
    req: &DecryptRequest,
    shares: &[EncryptedKeyShare],
) -> Result<EncryptedDerivedKey, CombineError> {
    let maximum = usize::from(public.context.threshold().n()).saturating_mul(2);
    if shares.len() > maximum {
        return Err(CombineError::TooManyShares);
    }
    if !req.matches(&public.context) {
        return Err(CombineError::ContextMismatch);
    }
    // This entire pass precedes *every* pairing, including shares not selected.
    if shares.iter().any(|s| !s.matches(&public.context, req)) {
        return Err(CombineError::MixedContexts);
    }
    let mut distinct: [Option<&EncryptedKeyShare>; 16] = [None; 16];
    for s in shares {
        verify_share(public, req, s).map_err(|e| match e {
            ShareError::ContextMismatch => CombineError::MixedContexts,
            ShareError::Invalid { member } => CombineError::Invalid { member },
        })?;
        let index = usize::from(s.member.get())
            .checked_sub(1)
            .ok_or(CombineError::MixedContexts)?;
        let entry = distinct.get_mut(index).ok_or(CombineError::MixedContexts)?;
        if entry.is_none() {
            *entry = Some(s)
        }
    }
    let t = usize::from(public.context.threshold().t());
    if distinct.iter().flatten().count() < t {
        return Err(CombineError::NotEnoughShares);
    }
    let mut c1 = G1::identity();
    let mut c2 = G2::identity();
    let mut c3 = G1::identity();
    for s in distinct.iter().flatten().take(t) {
        let lambda = crate::poly::lagrange(
            s.member,
            distinct.iter().flatten().take(t).map(|s| s.member),
        )
        .map_err(|_| CombineError::MixedContexts)?;
        c1 = c1.add(&s.c1.mul(&lambda));
        c2 = c2.add(&s.c2.mul(&lambda));
        c3 = c3.add(&s.c3.mul(&lambda));
    }
    Ok(EncryptedDerivedKey {
        context_digest: public.context.digest(),
        request_digest: *req.digest().as_bytes(),
        c1,
        c2,
        c3,
    })
}

/// A derived G1 key carrying its exact identity and key-context digest.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    #[zeroize(skip)]
    pub(crate) identity: IbeIdentity,
    #[zeroize(skip)]
    context_digest: [u8; 32],
    pub(crate) key: Zeroizing<G1>,
}
impl DerivedKey {
    /// The identity associated with the key.
    pub fn identity(&self) -> &IbeIdentity {
        &self.identity
    }
    /// Context to which the derivation belongs.
    pub fn context_digest(&self) -> &[u8; 32] {
        &self.context_digest
    }
}
impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKey([REDACTED])")
    }
}

/// Removes the reader's mask and checks the resulting key against id and mpk.
pub fn decrypt_derived_key(
    ek: &EncryptedDerivedKey,
    tsk: &TransportSecretKey,
    public: &PublicKeySet,
    req: &DecryptRequest,
) -> Result<DerivedKey, Error> {
    if !req.matches(&public.context)
        || ek.context_digest != public.context.digest()
        || ek.request_digest != *req.digest().as_bytes()
        || tsk.public_key() != req.tpk
    {
        return Err(Error::ContextMismatch);
    }
    let mask = Zeroizing::new(ek.c1.mul(&tsk.0));
    let key = Zeroizing::new(ek.c3.sub(&mask));
    let g2 = G2::generator();
    let neg_h = G1::identity().sub(&hash_g1(req.identity.as_bytes(), dst::H1));
    if key.is_identity() || !pairing_check(&[(&key, &g2), (&neg_h, &public.mpk.0)]) {
        return Err(Error::InvalidDerivedKey);
    }
    Ok(DerivedKey {
        identity: req.identity.clone(),
        context_digest: public.context.digest(),
        key,
    })
}
