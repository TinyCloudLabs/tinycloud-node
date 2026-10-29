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
    #[error("derived key does not match the request")]
    InvalidDerivedKey,
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
    /// Raw entries exceed twice the current member count; no member is blamed.
    #[error("too many supplied share entries")]
    TooManyShares,
    #[error("request context mismatch")]
    ContextMismatch,
    #[error("mixed share contexts")]
    MixedContexts,
    #[error("invalid share from {member:?}")]
    Invalid { member: MemberIndex },
    #[error("not enough distinct shares")]
    NotEnoughShares,
}
