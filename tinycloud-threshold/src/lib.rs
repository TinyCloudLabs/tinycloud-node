//! Context-bound threshold key derivation and identity-based key wrapping.
//! The workspace does not connect this crate to the node runtime.
#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod activation;
pub mod ceremony;
pub mod cert;
pub mod context;
#[allow(unsafe_code)]
pub mod curve;
pub mod derive;
pub mod dkg;
pub mod dst;
mod encoding;
pub mod error;
pub mod fault;
pub mod ibe;
pub mod identity;
pub mod ids;
mod poly;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Crate-private dealing helpers await DKG/reshare callers."
    )
)]
pub mod seal;

pub use activation::{
    activation_preimage, readiness_preimage, verify_activation, ReadinessReceipt, ReadyQuorum,
};
pub use ceremony::{
    AuthorizedCeremony, ClosedRound, DidSignatureVerifier, SignedStatement, TrustAnchor,
};
pub use cert::{
    verify_certificate, verify_successor, CandidateShare, CertMember, CertificateBody,
    PublicMaterial, SignedCertificate, VerifiedCertificate,
};
pub use context::{AuthorizedDerivation, KeyContext};
pub use derive::*;
pub use dkg::{
    dkg_initial_transcript, dkg_start, dkg_verify_transcript, AfterBarrier, DisqualifyReason,
    DkgAnswered, DkgAnswers, DkgAwaitingBarrier, DkgComplained, DkgComplaints, DkgDeal, DkgDealt,
    DkgExtracting, DkgExtractionComplaints, DkgFeldman, DkgMessage, DkgOutput, DkgReconstructing,
    DkgReconstruction, DkgRoundRecord, DkgTranscript,
};
pub use error::{CertError, CombineError, Error, ShareError, SignatureError};
pub use fault::{verify_fault_proof, FaultProof, FaultVerdict, NotAFaultReason};
pub use ibe::*;
pub use identity::IbeIdentity;
pub use ids::*;
pub use seal::{CeremonyHpkePublicKey, CeremonyHpkeSecretKey, SealedDealing};

#[cfg(test)]
mod checkpoint;
#[cfg(test)]
mod dkg_relay;
#[cfg(test)]
mod vectors;
