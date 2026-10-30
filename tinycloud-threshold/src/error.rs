//! Errors at decoding, context and algebra boundaries.
use crate::ids::MemberIndex;

/// Failure before a key or ciphertext can be returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("invalid length")]
    InvalidLength,
    #[error("input exceeds its size cap")]
    LimitExceeded,
    #[error("non-canonical scalar")]
    InvalidScalar,
    #[error("invalid curve point")]
    InvalidPoint,
    #[error("identity point is not allowed for this field")]
    IdentityPoint,
    #[error("member index outside 1..=16")]
    InvalidIndex,
    #[error("threshold must satisfy 2 <= t <= n <= 16")]
    InvalidThreshold,
    #[error("genesis requires n >= 2t-1")]
    UnsupportedFaultBudget,
    #[error("counter overflow")]
    CounterOverflow,
    #[error("key context mismatch")]
    ContextMismatch,
    #[error("identity does not match the capability check")]
    UnauthorizedIdentity,
    #[error("derived key belongs to another identity")]
    WrongIdentity,
    #[error("randomness reduced to zero")]
    DegenerateRandomness,
    #[error("invalid IBE ciphertext")]
    InvalidCiphertext,
    #[error("invalid HPKE key")]
    InvalidHpkeKey,
    #[error("invalid sealed dealing")]
    InvalidSealedDealing,
    #[error("derived key does not match the request")]
    InvalidDerivedKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid ceremony")]
    InvalidCeremony,
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid readiness receipt")]
    InvalidReadiness,
    #[error("not enough ready holders")]
    NotEnoughReady,
    #[error("candidate does not match certificate")]
    CandidateMismatch,
}

/// Verification distinguishes context selection from a member's share equation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    #[error("key context mismatch")]
    ContextMismatch,
    #[error("invalid share from {member:?}")]
    Invalid { member: MemberIndex },
}

/// Combining never interprets mixed-context inputs as member faults.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CombineError {
    #[error("request context mismatch")]
    ContextMismatch,
    #[error("mixed share contexts")]
    MixedContexts,
    #[error("invalid share from {member:?}")]
    Invalid { member: MemberIndex },
    #[error("not enough distinct shares")]
    NotEnoughShares,
}

/// Failure reported by the caller's DID signature verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("invalid signature")]
    Invalid,
}

/// Certificate validation against an external anchor and pinned predecessor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error(transparent)]
    Invalid(#[from] Error),
    #[error("certificate anchor mismatch")]
    AnchorMismatch,
    #[error("invalid certificate signature")]
    InvalidSignature,
    #[error("invalid certificate lineage")]
    InvalidLineage,
    #[error("invalid certificate members")]
    InvalidMembers,
    #[error("invalid certificate commitments")]
    InvalidCommitments,
}
