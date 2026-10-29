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

pub mod context;
#[allow(unsafe_code)]
pub mod curve;
pub mod derive;
pub mod dst;
mod encoding;
pub mod error;
pub mod ibe;
pub mod identity;
pub mod ids;
mod poly;

pub use context::{AuthorizedDerivation, KeyContext};
pub use derive::*;
pub use error::{CombineError, Error, ShareError};
pub use ibe::*;
pub use identity::IbeIdentity;
pub use ids::*;

#[cfg(test)]
mod checkpoint;
#[cfg(test)]
mod vectors;
