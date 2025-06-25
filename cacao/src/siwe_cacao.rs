use super::{Representation, SignatureScheme, CACAO};
use async_trait::async_trait;
use hex::FromHex;
use http::uri::{Authority, Scheme};
use iri_string::{
    types::{UriAbsoluteString, UriString},
    validate::Error as URIStringError,
};
use libipld::{
    cbor::{DagCbor, DagCborCodec},
    codec::{Decode, Encode},
    error::Error as IpldError,
    DagCbor,
};
pub use siwe;
use siwe::{eip55, Message, TimeStamp, VerificationError as SVE, Version as SVersion};
use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use thiserror::Error;
use time::OffsetDateTime;

pub type SiweCacao = CACAO<Eip191, Eip4361>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Header;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub scheme: Option<Scheme>,
    pub domain: Authority,
    pub iss: UriAbsoluteString,
    pub statement: Option<String>,
    pub aud: UriString,
    pub version: Version,
    pub nonce: String,
    pub iat: TimeStamp,
    pub exp: Option<TimeStamp>,
    pub nbf: Option<TimeStamp>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    V1 = 1,
}

impl Payload {
    pub fn sign<S>(self, s: S::Signature) -> CACAO<S, Eip4361>
    where
        S: SignatureScheme<Eip4361>,
        S::Signature: DagCbor + Debug,
    {
        CACAO::new(self, s, None)
    }

    pub async fn verify<S>(&self, s: &S::Signature) -> Result<(), S::Err>
    where
        S: Send + Sync + SignatureScheme<Eip4361>,
        S::Signature: Send + Sync,
    {
        S::verify(self, s).await
    }

    pub fn iss(&self) -> &str {
        self.iss.as_str()
    }

    pub fn valid_at(&self, t: &OffsetDateTime) -> bool {
        self.nbf.as_ref().map(|nbf| nbf < t).unwrap_or(true)
            && self.exp.as_ref().map(|exp| exp >= t).unwrap_or(true)
    }

    pub fn valid_now(&self) -> bool {
        self.valid_at(&OffsetDateTime::now_utc())
    }
}

mod payload_ipld {
    use super::*;
    use libipld::error::Error as IpldError;
    use std::io::{Read, Seek, Write};

    #[derive(Clone, DagCbor)]
    struct TmpPayload {
        aud: String,
        #[ipld(default = None)]
        exp: Option<String>,
        iat: String,
        iss: String,
        #[ipld(default = None)]
        nbf: Option<String>,
        nonce: String,
        domain: String,
        version: String,
        resources: Vec<String>,
        #[ipld(rename = "requestId")]
        #[ipld(default = None)]
        request_id: Option<String>,
        #[ipld(default = None)]
        statement: Option<String>,
        #[ipld(default = None)]
        scheme: Option<String>,
    }

    impl From<&Payload> for TmpPayload {
        fn from(p: &Payload) -> Self {
            Self {
                scheme: p.scheme.as_ref().map(|s| s.to_string()),
                domain: p.domain.to_string(),
                iss: p.iss.to_string(),
                statement: p.statement.as_ref().map(|e| e.to_string()),
                aud: p.aud.to_string(),
                version: (p.version as u64).to_string(),
                nonce: p.nonce.to_string(),
                iat: p.iat.to_string(),
                exp: p.exp.as_ref().map(|e| e.to_string()),
                nbf: p.nbf.as_ref().map(|e| e.to_string()),
                request_id: p.request_id.clone(),
                resources: p.resources.iter().map(|r| r.to_string()).collect(),
            }
        }
    }

    impl TryFrom<TmpPayload> for Payload {
        type Error = IpldError;
        fn try_from(p: TmpPayload) -> Result<Self, Self::Error> {
            Ok(Self {
                scheme: p.scheme.map(|s| s.parse()).transpose()?,
                domain: p.domain.parse()?,
                iss: p.iss.parse()?,
                statement: p.statement,
                aud: p.aud.parse()?,
                version: Version::V1,
                nonce: p.nonce,
                iat: p.iat.parse()?,
                exp: p.exp.map(|s| s.parse()).transpose()?,
                nbf: p.nbf.map(|s| s.parse()).transpose()?,
                request_id: p.request_id,
                resources: p
                    .resources
                    .iter()
                    .map(|r| r.parse())
                    .collect::<Result<Vec<UriString>, URIStringError>>()?,
            })
        }
    }

    impl Encode<DagCborCodec> for Payload {
        fn encode<W>(&self, c: DagCborCodec, w: &mut W) -> Result<(), IpldError>
        where
            W: Write,
        {
            TmpPayload::from(self).encode(c, w)
        }
    }

    impl Decode<DagCborCodec> for Payload {
        fn decode<R>(c: DagCborCodec, r: &mut R) -> Result<Self, IpldError>
        where
            R: Read + Seek,
        {
            TmpPayload::decode(c, r).and_then(|t| t.try_into())
        }
    }

    #[derive(DagCbor)]
    struct DummyHeader {
        t: String,
    }
    impl Encode<DagCborCodec> for Header {
        fn encode<W>(&self, c: DagCborCodec, w: &mut W) -> Result<(), IpldError>
        where
            W: Write,
        {
            DummyHeader {
                t: "eip4361".to_string(),
            }
            .encode(c, w)
        }
    }

    #[derive(Error, Debug)]
    #[error("Invalid header type value")]
    struct HeaderTypeErr;

    impl Decode<DagCborCodec> for Header {
        fn decode<R>(c: DagCborCodec, r: &mut R) -> Result<Self, IpldError>
        where
            R: Read + Seek,
        {
            if DummyHeader::decode(c, r)?.t != "eip4361" {
                Err(HeaderTypeErr)?
            } else {
                Ok(Header)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Eip4361;

impl Representation for Eip4361 {
    type Payload = Payload;
    type Header = Header;
    fn header() -> Header {
        Header
    }
}

impl From<Version> for SVersion {
    fn from(s: Version) -> Self {
        match s {
            Version::V1 => Self::V1,
        }
    }
}

impl From<SVersion> for Version {
    fn from(v: SVersion) -> Self {
        match v {
            SVersion::V1 => Self::V1,
        }
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error(transparent)]
    Verification(#[from] SVE),
    #[error(transparent)]
    Serialization(#[from] SIWEPayloadConversionError),
}

#[derive(thiserror::Error, Debug)]
pub enum SIWEPayloadConversionError {
    #[error(transparent)]
    InvalidAddress(#[from] hex::FromHexError),
    #[error(transparent)]
    InvalidChainId(#[from] std::num::ParseIntError),
    #[error("Invalid DID, expected did:pkh")]
    InvalidDID,
}

impl TryInto<Message> for Payload {
    type Error = SIWEPayloadConversionError;
    fn try_into(self) -> Result<Message, Self::Error> {
        let (chain_id, address) = match &self.iss.as_str().split(':').collect::<Vec<&str>>()[..] {
            &["did", "pkh", "eip155", c, h] if h.get(..2) == Some("0x") => {
                (c.parse()?, FromHex::from_hex(&h[2..])?)
            }
            _ => return Err(Self::Error::InvalidDID),
        };
        Ok(Message {
            scheme: self.scheme,
            domain: self.domain,
            address,
            chain_id,
            statement: self.statement,
            uri: self.aud,
            version: self.version.into(),
            nonce: self.nonce,
            issued_at: self.iat,
            not_before: self.nbf,
            expiration_time: self.exp,
            request_id: self.request_id,
            resources: self.resources,
        })
    }
}

impl From<Message> for Payload {
    fn from(m: Message) -> Self {
        Self {
            scheme: m.scheme,
            domain: m.domain,
            iss: format!("did:pkh:eip155:{}:{}", m.chain_id, eip55(&m.address))
                .parse()
                .unwrap(),
            statement: m.statement,
            aud: m.uri,
            version: m.version.into(),
            nonce: m.nonce,
            iat: m.issued_at,
            nbf: m.not_before,
            exp: m.expiration_time,
            request_id: m.request_id,
            resources: m.resources,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SIWESignature([u8; 65]);

impl std::ops::Deref for SIWESignature {
    type Target = [u8; 65];
    fn deref(&self) -> &[u8; 65] {
        &self.0
    }
}

impl From<[u8; 65]> for SIWESignature {
    fn from(s: [u8; 65]) -> Self {
        Self(s)
    }
}

impl AsRef<[u8]> for SIWESignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<Vec<u8>> for SIWESignature {
    type Error = SIWESignatureDecodeError;
    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(s.try_into().map_err(SIWESignatureDecodeError::from)?))
    }
}

#[derive(Error, Debug)]
pub enum SIWESignatureDecodeError {
    #[error("Invalid length, expected 65, got {0}")]
    InvalidLength(usize),
    #[error("Invalid Type, expected 'eip191', got {0}")]
    InvalidType(String),
}

impl From<Vec<u8>> for SIWESignatureDecodeError {
    fn from(v: Vec<u8>) -> Self {
        Self::InvalidLength(v.len())
    }
}

#[derive(DagCbor)]
struct DummySig {
    s: Vec<u8>,
    t: String,
}

impl Encode<DagCborCodec> for SIWESignature {
    fn encode<W>(&self, c: DagCborCodec, w: &mut W) -> Result<(), IpldError>
    where
        W: Write,
    {
        DummySig {
            s: self.0.to_vec(),
            t: "eip191".to_string(),
        }
        .encode(c, w)
    }
}

impl Decode<DagCborCodec> for SIWESignature {
    fn decode<R>(c: DagCborCodec, r: &mut R) -> Result<Self, IpldError>
    where
        R: Read + Seek,
    {
        match DummySig::decode(c, r)? {
            d if d.t == "eip191" => Ok(d.s.try_into()?),
            d => Err(SIWESignatureDecodeError::InvalidType(d.t))?,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Eip191;

#[async_trait]
impl SignatureScheme<Eip4361> for Eip191 {
    type Signature = SIWESignature;
    type Err = VerificationError;
    async fn verify(
        payload: &<Eip4361 as Representation>::Payload,
        sig: &Self::Signature,
    ) -> Result<(), VerificationError> {
        let m: Message = payload.clone().try_into()?;
        m.verify_eip191(sig)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use siwe::Message;
    use std::str::FromStr;

    #[async_std::test]
    async fn validation() {
        // from https://github.com/blockdemy/eth_personal_sign
        let message: Payload = Message::from_str(
            r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
        )
        .unwrap()
        .into();
        // correct signature
        Eip191::verify(&message, &<Vec<u8>>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap().try_into().unwrap())
            .await
            .unwrap();

        // incorrect signature
        assert!(Eip191::verify(&message, &<Vec<u8>>::from_hex(r#"7228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap().try_into().unwrap())
            .await
            .is_err());
    }
}
