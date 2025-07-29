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
        Self {
            h,
            p,
            s,
        }
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use libipld::{
        cbor::DagCborCodec,
        codec::{assert_roundtrip, Decode},
        ipld,
    };
    use siwe_cacao::SiweCacao;
    use std::io::Cursor;
    #[test]
    fn test_ipld() {
        let cacao = SiweCacao::decode(
            DagCborCodec,
            &mut Cursor::new([
                163u8, 97u8, 104u8, 161u8, 97u8, 116u8, 103u8, 101u8, 105u8, 112u8, 52u8, 51u8,
                54u8, 49u8, 97u8, 112u8, 168u8, 99u8, 97u8, 117u8, 100u8, 120u8, 56u8, 100u8,
                105u8, 100u8, 58u8, 107u8, 101u8, 121u8, 58u8, 122u8, 54u8, 77u8, 107u8, 114u8,
                66u8, 100u8, 78u8, 100u8, 119u8, 85u8, 80u8, 110u8, 88u8, 68u8, 86u8, 68u8, 49u8,
                68u8, 67u8, 120u8, 101u8, 100u8, 122u8, 86u8, 86u8, 66u8, 112u8, 97u8, 71u8, 105u8,
                56u8, 97u8, 83u8, 109u8, 111u8, 88u8, 70u8, 65u8, 101u8, 75u8, 78u8, 103u8, 116u8,
                65u8, 101u8, 114u8, 56u8, 99u8, 105u8, 97u8, 116u8, 120u8, 24u8, 50u8, 48u8, 50u8,
                49u8, 45u8, 48u8, 57u8, 45u8, 51u8, 48u8, 84u8, 49u8, 54u8, 58u8, 50u8, 53u8, 58u8,
                50u8, 52u8, 46u8, 48u8, 48u8, 48u8, 90u8, 99u8, 105u8, 115u8, 115u8, 120u8, 59u8,
                100u8, 105u8, 100u8, 58u8, 112u8, 107u8, 104u8, 58u8, 101u8, 105u8, 112u8, 49u8,
                53u8, 53u8, 58u8, 49u8, 58u8, 48u8, 120u8, 66u8, 100u8, 57u8, 68u8, 57u8, 99u8,
                55u8, 68u8, 67u8, 51u8, 56u8, 57u8, 55u8, 49u8, 53u8, 97u8, 56u8, 57u8, 102u8,
                67u8, 56u8, 49u8, 52u8, 57u8, 69u8, 52u8, 97u8, 53u8, 66u8, 101u8, 57u8, 49u8,
                51u8, 51u8, 54u8, 66u8, 50u8, 55u8, 57u8, 54u8, 101u8, 110u8, 111u8, 110u8, 99u8,
                101u8, 104u8, 51u8, 50u8, 56u8, 57u8, 49u8, 55u8, 53u8, 55u8, 102u8, 100u8, 111u8,
                109u8, 97u8, 105u8, 110u8, 107u8, 115u8, 101u8, 114u8, 118u8, 105u8, 99u8, 101u8,
                46u8, 111u8, 114u8, 103u8, 103u8, 118u8, 101u8, 114u8, 115u8, 105u8, 111u8, 110u8,
                97u8, 49u8, 105u8, 114u8, 101u8, 115u8, 111u8, 117u8, 114u8, 99u8, 101u8, 115u8,
                130u8, 120u8, 53u8, 105u8, 112u8, 102u8, 115u8, 58u8, 47u8, 47u8, 81u8, 109u8,
                101u8, 55u8, 115u8, 115u8, 51u8, 65u8, 82u8, 86u8, 103u8, 120u8, 118u8, 54u8,
                114u8, 88u8, 113u8, 86u8, 80u8, 105u8, 105u8, 107u8, 77u8, 74u8, 56u8, 117u8, 50u8,
                78u8, 76u8, 103u8, 109u8, 103u8, 115u8, 122u8, 103u8, 49u8, 51u8, 112u8, 89u8,
                114u8, 68u8, 75u8, 69u8, 111u8, 105u8, 117u8, 120u8, 38u8, 104u8, 116u8, 116u8,
                112u8, 115u8, 58u8, 47u8, 47u8, 101u8, 120u8, 97u8, 109u8, 112u8, 108u8, 101u8,
                46u8, 99u8, 111u8, 109u8, 47u8, 109u8, 121u8, 45u8, 119u8, 101u8, 98u8, 50u8, 45u8,
                99u8, 108u8, 97u8, 105u8, 109u8, 46u8, 106u8, 115u8, 111u8, 110u8, 105u8, 115u8,
                116u8, 97u8, 116u8, 101u8, 109u8, 101u8, 110u8, 116u8, 120u8, 65u8, 73u8, 32u8,
                97u8, 99u8, 99u8, 101u8, 112u8, 116u8, 32u8, 116u8, 104u8, 101u8, 32u8, 83u8,
                101u8, 114u8, 118u8, 105u8, 99u8, 101u8, 79u8, 114u8, 103u8, 32u8, 84u8, 101u8,
                114u8, 109u8, 115u8, 32u8, 111u8, 102u8, 32u8, 83u8, 101u8, 114u8, 118u8, 105u8,
                99u8, 101u8, 58u8, 32u8, 104u8, 116u8, 116u8, 112u8, 115u8, 58u8, 47u8, 47u8,
                115u8, 101u8, 114u8, 118u8, 105u8, 99u8, 101u8, 46u8, 111u8, 114u8, 103u8, 47u8,
                116u8, 111u8, 115u8, 97u8, 115u8, 162u8, 97u8, 115u8, 152u8, 65u8, 16u8, 24u8,
                147u8, 19u8, 24u8, 231u8, 24u8, 82u8, 24u8, 93u8, 24u8, 234u8, 24u8, 85u8, 24u8,
                236u8, 24u8, 154u8, 24u8, 60u8, 24u8, 203u8, 24u8, 182u8, 24u8, 62u8, 24u8, 168u8,
                24u8, 214u8, 24u8, 132u8, 6u8, 24u8, 54u8, 24u8, 98u8, 24u8, 80u8, 24u8, 207u8,
                8u8, 24u8, 128u8, 24u8, 214u8, 24u8, 112u8, 24u8, 50u8, 24u8, 180u8, 24u8, 87u8,
                24u8, 171u8, 24u8, 51u8, 24u8, 201u8, 24u8, 38u8, 24u8, 198u8, 24u8, 127u8, 24u8,
                243u8, 24u8, 252u8, 24u8, 198u8, 24u8, 106u8, 24u8, 195u8, 24u8, 27u8, 24u8, 170u8,
                24u8, 104u8, 24u8, 104u8, 24u8, 168u8, 10u8, 18u8, 24u8, 251u8, 24u8, 230u8, 24u8,
                183u8, 24u8, 99u8, 24u8, 138u8, 24u8, 137u8, 24u8, 244u8, 24u8, 246u8, 24u8, 213u8,
                24u8, 26u8, 2u8, 24u8, 41u8, 24u8, 89u8, 12u8, 24u8, 246u8, 24u8, 103u8, 24u8,
                111u8, 24u8, 28u8, 97u8, 116u8, 102u8, 101u8, 105u8, 112u8, 49u8, 57u8, 49u8,
            ]),
        )
        .unwrap();

        let ipld = ipld!({
          "h": {
            "t": "eip4361",
          },
          "p": {
            "aud": "did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8",
            "domain": "service.org",
            "iat": "2021-09-30T16:25:24.000Z",
            "iss": "did:pkh:eip155:1:0xBd9D9c7DC389715a89fC8149E4a5Be91336B2796",
            "nonce": "32891757",
            "resources": [
              "ipfs://Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu",
              "https://example.com/my-web2-claim.json",
            ],
            "statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
            "version": "1",
          },
          "s": {
            "s": [0x10, 0x93, 0x13, 0xe7, 0x52, 0x5d, 0xea, 0x55, 0xec, 0x9a, 0x3c, 0xcb, 0xb6, 0x3e, 0xa8, 0xd6, 0x84, 0x06, 0x36, 0x62, 0x50, 0xcf, 0x08, 0x80, 0xd6, 0x70, 0x32, 0xb4, 0x57, 0xab, 0x33, 0xc9, 0x26, 0xc6, 0x7f, 0xf3, 0xfc, 0xc6, 0x6a, 0xc3, 0x1b, 0xaa, 0x68, 0x68, 0xa8, 0x0a, 0x12, 0xfb, 0xe6, 0xb7, 0x63, 0x8a, 0x89, 0xf4, 0xf6, 0xd5, 0x1a, 0x02, 0x29, 0x59, 0x0c, 0xf6, 0x67, 0x6f, 0x1c],
            "t": "eip191",
          },
        });
        assert_roundtrip(DagCborCodec, &cacao, &ipld);
    }
}
