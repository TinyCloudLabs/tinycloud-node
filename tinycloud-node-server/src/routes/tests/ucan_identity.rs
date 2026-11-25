//! A UCAN's identity does not depend on which of its valid encodings a client
//! submits: a revocation of one covers every other, at `/delegate` and at
//! `/invoke`. Each valid encoding still registers.

use super::*;
use rocket::http::{Header, Status};
use serde_json::Value;
use tinycloud_auth::{
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::hash::{hash, Hash};

/// Group order of P-256, big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Group order of secp256k1, big-endian.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `order - value`, big-endian, for `0 < value < order`.
fn negate(order: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = i16::from(order[i]) - i16::from(value[i]) - borrow;
        borrow = i16::from(digit < 0);
        if digit < 0 {
            digit += 256;
        }
        out[i] = digit as u8;
    }
    out
}

/// The two valid ECDSA encodings of `token`, `(low_s, high_s)`: the same
/// header, payload and `r`, with `s` and `order - s`.
fn encodings(token: &str, order: &[u8; 32]) -> (String, String) {
    let (signed, signature) = token.rsplit_once('.').expect("JWS");
    let signature = decode_config(signature, URL_SAFE_NO_PAD).expect("base64url signature");
    assert_eq!(signature.len(), 64, "r || s");
    let other = negate(order, &signature[32..]);
    let mut twin = signature.clone();
    twin[32..].copy_from_slice(&other);
    let encode = |bytes: &[u8]| format!("{signed}.{}", encode_config(bytes, URL_SAFE_NO_PAD));
    if signature[32..] < other[..] {
        (encode(&signature), encode(&twin))
    } else {
        (encode(&twin), encode(&signature))
    }
}

struct Issuer {
    jwk: JWK,
    vm: String,
}

impl Issuer {
    fn did(&self) -> String {
        KvSyncFixture::did_of(&self.vm)
    }
}

impl KvSyncFixture {
    /// An issuer holding `kv/sync` on `notes/` from the owner.
    async fn issuer(&self, label: &str, jwk: JWK) -> Result<(Issuer, Hash)> {
        use tinycloud_core::models::actor;
        use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set};
        let issuer = Issuer {
            vm: tc341_verification_method(&jwk)?,
            jwk,
        };
        actor::ActiveModel {
            id: Set(issuer.did()),
        }
        .insert(&self.conn)
        .await?;
        let parent = self
            .grant(
                &format!("{label}-parent"),
                &self.space.did().to_string(),
                &issuer.did(),
                &[("notes/", "tinycloud.kv/sync")],
                None,
                Some(whole_seconds_from_now(3600)),
                &[],
            )
            .await?;
        Ok((issuer, parent))
    }

    /// `issuer` delegates `kv/sync` on `notes/` to the device under `parent`.
    fn signed_sync_delegation(&self, label: &str, issuer: &Issuer, parent: Hash) -> Result<String> {
        let mut capabilities = Capabilities::new();
        capabilities.with_action(
            self.kv_resource("notes/")?.as_uri(),
            "tinycloud.kv/sync".parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        Ok(Payload {
            issuer: issuer.vm.parse::<DIDURLBuf>()?,
            audience: self.device_did().parse::<DIDBuf>()?,
            not_before: None,
            expiration: NumericDate::try_from_seconds(
                whole_seconds_from_now(3000).unix_timestamp() as f64,
            )?,
            nonce: Some(format!("urn:uuid:ucan-identity-{label}")),
            facts: Some(Vec::<Value>::new()),
            proof: vec![parent.to_cid(0x55)],
            attenuation: capabilities,
        }
        .sign(
            issuer.jwk.get_algorithm().expect("key algorithm"),
            &issuer.jwk,
        )?
        .encode()?)
    }

    async fn register(&self, token: &str) -> SyncReply {
        let response = self
            .client
            .post("/delegate")
            .header(Header::new("Authorization", token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        SyncReply { status, body, json }
    }

    /// Register `token` and return the CID the node answered, which must be
    /// the hash of the exact submitted bytes.
    async fn registered(&self, token: &str) -> Result<Hash> {
        let reply = self.register(token).await;
        anyhow::ensure!(
            reply.status == Status::Ok,
            "registration refused: {}: {}",
            reply.status,
            reply.body
        );
        let cid: Hash = reply.json["cid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no cid in {}", reply.body))?
            .parse::<tinycloud_auth::ipld_core::cid::Cid>()?
            .into();
        anyhow::ensure!(
            cid == hash(token.as_bytes()),
            "the CID is not the hash of the submitted bytes"
        );
        Ok(cid)
    }
}

#[derive(Clone, Copy, Debug)]
enum Revoked {
    LowS,
    HighS,
}

#[derive(Clone, Copy, Debug)]
enum Curve {
    P256,
    Secp256k1,
}

impl Curve {
    fn key(self) -> JWK {
        match self {
            Self::P256 => JWK::generate_p256(),
            Self::Secp256k1 => JWK::generate_secp256k1(),
        }
    }

    fn order(self) -> &'static [u8; 32] {
        match self {
            Self::P256 => &P256_ORDER,
            Self::Secp256k1 => &SECP256K1_ORDER,
        }
    }
}

/// Both encodings register and authorize; revoking either refuses both.
async fn revocation_covers_both_registered_encodings(curve: Curve, revoked: Revoked) -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let label = format!("{curve:?}-{revoked:?}-invoke");
    let (issuer, parent) = fixture.issuer(&label, curve.key()).await?;
    let token = fixture.signed_sync_delegation(&label, &issuer, parent)?;
    let (low, high) = encodings(&token, curve.order());
    let low = fixture.registered(&low).await?;
    let high = fixture.registered(&high).await?;
    assert_ne!(low, high);
    for cid in [low, high] {
        let reply = fixture.sync("notes/", cid, &[]).await?;
        assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    }
    let target = match revoked {
        Revoked::LowS => low,
        Revoked::HighS => high,
    };
    fixture.revoke(&format!("{label}-revoke"), target).await?;
    for cid in [low, high] {
        let reply = fixture.sync("notes/", cid, &[]).await?;
        assert_eq!(
            reply.status,
            Status::Unauthorized,
            "{curve:?}: revoking the {revoked:?} encoding must refuse {} too: {}",
            if cid == target { "it" } else { "the other" },
            reply.body
        );
    }
    Ok(())
}

/// After one encoding is revoked, registering the other is refused.
async fn revoked_encoding_cannot_be_registered_again(curve: Curve, revoked: Revoked) -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let label = format!("{curve:?}-{revoked:?}-delegate");
    let (issuer, parent) = fixture.issuer(&label, curve.key()).await?;
    let token = fixture.signed_sync_delegation(&label, &issuer, parent)?;
    let (low, high) = encodings(&token, curve.order());
    let (first, second) = match revoked {
        Revoked::LowS => (low, high),
        Revoked::HighS => (high, low),
    };
    let first = fixture.registered(&first).await?;
    fixture.revoke(&format!("{label}-revoke"), first).await?;
    let reply = fixture.register(&second).await;
    assert_eq!(
        reply.status,
        Status::Unauthorized,
        "{curve:?}: the other encoding of a revoked {revoked:?} delegation must be refused: {}",
        reply.body
    );
    assert_eq!(reply.json["code"], "delegation_revoked", "{}", reply.body);
    Ok(())
}

#[tokio::test]
async fn p256_revoking_the_low_s_encoding_refuses_both_at_invoke() -> Result<()> {
    revocation_covers_both_registered_encodings(Curve::P256, Revoked::LowS).await
}

#[tokio::test]
async fn p256_revoking_the_high_s_encoding_refuses_both_at_invoke() -> Result<()> {
    revocation_covers_both_registered_encodings(Curve::P256, Revoked::HighS).await
}

#[tokio::test]
async fn secp256k1_revoking_the_low_s_encoding_refuses_both_at_invoke() -> Result<()> {
    revocation_covers_both_registered_encodings(Curve::Secp256k1, Revoked::LowS).await
}

#[tokio::test]
async fn secp256k1_revoking_the_high_s_encoding_refuses_both_at_invoke() -> Result<()> {
    revocation_covers_both_registered_encodings(Curve::Secp256k1, Revoked::HighS).await
}

#[tokio::test]
async fn p256_a_revoked_low_s_delegation_cannot_be_registered_as_high_s() -> Result<()> {
    revoked_encoding_cannot_be_registered_again(Curve::P256, Revoked::LowS).await
}

#[tokio::test]
async fn p256_a_revoked_high_s_delegation_cannot_be_registered_as_low_s() -> Result<()> {
    revoked_encoding_cannot_be_registered_again(Curve::P256, Revoked::HighS).await
}

#[tokio::test]
async fn secp256k1_a_revoked_low_s_delegation_cannot_be_registered_as_high_s() -> Result<()> {
    revoked_encoding_cannot_be_registered_again(Curve::Secp256k1, Revoked::LowS).await
}

#[tokio::test]
async fn secp256k1_a_revoked_high_s_delegation_cannot_be_registered_as_low_s() -> Result<()> {
    revoked_encoding_cannot_be_registered_again(Curve::Secp256k1, Revoked::HighS).await
}

/// Ed25519 keeps its exact-bytes identity: it registers under the hash of the
/// submitted token, authorizes, and its revocation refuses it.
#[tokio::test]
async fn ed25519_identity_and_revocation_are_unchanged() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let (issuer, parent) = fixture.issuer("ed25519", JWK::generate_ed25519()?).await?;
    let token = fixture.signed_sync_delegation("ed25519", &issuer, parent)?;
    let cid = fixture.registered(&token).await?;
    let reply = fixture.sync("notes/", cid, &[]).await?;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    fixture.revoke("ed25519-revoke", cid).await?;
    let reply = fixture.sync("notes/", cid, &[]).await?;
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    Ok(())
}
