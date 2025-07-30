use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
pub use siwe;

pub mod siwe_cacao;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CACAO<S, R>
where
    S: SignatureScheme<R>,
    R: Representation,
{
    h: R::Header,
    p: R::Payload,
    s: S::Signature,
}

impl<S, R> CACAO<S, R>
where
    S: SignatureScheme<R>,
    R: Representation,
{
    pub fn new(p: R::Payload, s: S::Signature, h: R::Header) -> Self {
        Self { h, p, s }
    }

    pub fn header(&self) -> &R::Header {
        &self.h
    }

    pub fn payload(&self) -> &R::Payload {
        &self.p
    }

    pub fn signature(&self) -> &S::Signature {
        &self.s
    }

    pub async fn verify(&self) -> Result<(), S::Err>
    where
        S: Send + Sync,
        S::Signature: Send + Sync,
        R::Payload: Send + Sync + Debug,
        R::Header: Send + Sync + Debug,
    {
        S::verify_cacao(self).await
    }
}

pub trait Representation {
    type Payload;
    type Header;
}

#[async_trait]
pub trait SignatureScheme<T>: Debug
where
    T: Representation,
{
    type Signature: Debug;
    type Err;
    async fn verify(payload: &T::Payload, sig: &Self::Signature) -> Result<(), Self::Err>;

    async fn verify_cacao(cacao: &CACAO<Self, T>) -> Result<(), Self::Err>
    where
        Self: Sized,
        Self::Signature: Send + Sync,
        T::Payload: Send + Sync,
        T::Header: Send + Sync,
    {
        Self::verify(cacao.payload(), cacao.signature()).await
    }
}
