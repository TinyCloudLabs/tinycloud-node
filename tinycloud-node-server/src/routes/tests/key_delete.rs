//! Owner-signed `key.delete` credentials through real routes: they are never
//! accepted as delegations or as revocations.

use super::*;
use k256::ecdsa::SigningKey;
use rocket::http::Status;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    cacaos::{
        siwe::{encode_eip55, Message, TimeStamp, Version},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature},
    },
    siwe_recap::Capability as Recap,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::models::revocation;
use tinycloud_core::sea_orm::PaginatorTrait;

const KEY_DELETE: &str = "tinycloud.encryption/key.delete";
const KEY_CREATE: &str = "tinycloud.encryption/key.create";
const KEY_DELETE_URI_PREFIX: &str = "urn:tinycloud:encryption:key-delete:";

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        Self { key, address }
    }

    fn did(&self) -> String {
        format!("did:pkh:eip155:1:0x{}", encode_eip55(&self.address))
    }

    fn sign(&self, message: &Message) -> Signature {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        Signature::from(bytes)
    }

    /// A SIWE CACAO carrying one ReCap capability, valid for `lifetime` seconds.
    fn cacao(
        &self,
        resource: &str,
        ability: &str,
        lead: Option<String>,
        uri: &str,
        nonce: &str,
        lifetime: i64,
    ) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let stamp = |unix: i64| TimeStamp::from(OffsetDateTime::from_unix_timestamp(unix).unwrap());
        let mut recap = Recap::<Value>::default();
        recap
            .with_action_convert(resource, ability, Vec::<BTreeMap<String, Value>>::new())
            .unwrap();
        let message = recap
            .build_message(Message {
                scheme: None,
                domain: "example.com".parse().unwrap(),
                address: self.address,
                statement: lead,
                uri: uri.parse().unwrap(),
                version: Version::V1,
                chain_id: 1,
                nonce: nonce.to_string(),
                issued_at: stamp(now),
                expiration_time: Some(stamp(now + lifetime)),
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .unwrap();
        let signature = self.sign(&message);
        let cacao = CacaoPayload::from(message).sign::<Eip191>(signature);
        TinyCloudDelegation::Cacao(Box::new(cacao))
            .encode()
            .unwrap()
    }
}

fn prefix_urn(owner: &str, id: &str) -> String {
    format!("urn:tinycloud:encryption:{owner}:default/apps/{id}/")
}

fn key_urn(owner: &str, path: &str) -> String {
    format!("urn:tinycloud:encryption:{owner}:default/{path}")
}

/// A UCAN signed by the fixture owner naming `ability` on `resource`.
fn owner_ucan(
    fixture: &KvSyncFixture,
    audience: &str,
    resource: &str,
    ability: &str,
) -> Result<String> {
    let mut capabilities = Capabilities::new();
    capabilities.with_action(
        resource.parse()?,
        ability.parse::<UcanAbility>()?,
        [BTreeMap::<String, Value>::new()],
    );
    Ok(Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            OffsetDateTime::now_utc().unix_timestamp() as f64 + 200.0,
        )?,
        nonce: Some(fixture.next_nonce()),
        facts: Some(vec![json!({"type": "tinycloud.encryption.key-admin/v1"})]),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(
        fixture.owner.get_algorithm().unwrap_or_default(),
        &fixture.owner,
    )?
    .encode()?)
}

async fn fixture() -> Result<KvSyncFixture> {
    let mut config = Config::default();
    config.encryption_network.named_keys_v1 = true;
    KvSyncFixture::new_configured(config, |rocket| {
        rocket.mount("/", rocket::routes![revoke])
    })
    .await
}

async fn post(fixture: &KvSyncFixture, uri: &str, auth: String) -> (Status, String) {
    let response = fixture
        .client
        .post(uri.to_string())
        .header(rocket::http::Header::new("Authorization", auth))
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

fn owner_did(fixture: &KvSyncFixture) -> String {
    KvSyncFixture::did_of(&fixture.owner_vm)
}

#[tokio::test]
async fn delegate_refuses_key_delete_on_every_target_shape() -> Result<()> {
    let fixture = fixture().await?;
    let did_key_owner = owner_did(&fixture);
    let device = fixture.device_did();
    let wallet = Wallet::new(3);
    let wallet_did = wallet.did();

    // Positive control: the same owners can delegate key.create on the prefix,
    // so a refusal below is the refusal of key.delete.
    let control = owner_ucan(
        &fixture,
        &device,
        &prefix_urn(&did_key_owner, "foo"),
        KEY_CREATE,
    )?;
    let (status, body) = post(&fixture, "/delegate", control).await;
    assert_eq!(status, Status::Ok, "{body}");
    let control = wallet.cacao(
        &prefix_urn(&wallet_did, "foo"),
        KEY_CREATE,
        None,
        &device,
        "control0001",
        3600,
    );
    let (status, body) = post(&fixture, "/delegate", control).await;
    assert_eq!(status, Status::Ok, "{body}");

    for (label, ucan_resource, cacao_resource) in [
        (
            "app prefix",
            prefix_urn(&did_key_owner, "foo"),
            prefix_urn(&wallet_did, "foo"),
        ),
        (
            "deeper prefix",
            format!("urn:tinycloud:encryption:{did_key_owner}:default/apps/foo/x/"),
            format!("urn:tinycloud:encryption:{wallet_did}:default/apps/foo/x/"),
        ),
        (
            "exact key",
            key_urn(&did_key_owner, "apps/foo/token"),
            key_urn(&wallet_did, "apps/foo/token"),
        ),
        (
            "reserved segment prefix",
            format!("urn:tinycloud:encryption:{did_key_owner}:default/apps/"),
            format!("urn:tinycloud:encryption:{wallet_did}:default/apps/"),
        ),
        (
            "other prefix",
            format!("urn:tinycloud:encryption:{did_key_owner}:default/secrets/"),
            format!("urn:tinycloud:encryption:{wallet_did}:default/secrets/"),
        ),
    ] {
        let ucan = owner_ucan(&fixture, &device, &ucan_resource, KEY_DELETE)?;
        let (status, body) = post(&fixture, "/delegate", ucan).await;
        assert_eq!(status, Status::Unauthorized, "ucan {label}: {body}");
        assert!(
            body.contains("key-delete-not-delegable"),
            "ucan {label}: {body}"
        );

        let cacao = wallet.cacao(
            &cacao_resource,
            KEY_DELETE,
            None,
            &device,
            "nonce0001",
            3600,
        );
        let (status, body) = post(&fixture, "/delegate", cacao).await;
        assert_eq!(status, Status::Unauthorized, "cacao {label}: {body}");
        assert!(
            body.contains("key-delete-not-delegable"),
            "cacao {label}: {body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_owner_delete_credential_is_not_a_delegation() -> Result<()> {
    let fixture = fixture().await?;
    let wallet = Wallet::new(3);
    let wallet_did = wallet.did();
    let prefix = prefix_urn(&wallet_did, "foo");
    let credential = wallet.cacao(
        &prefix,
        KEY_DELETE,
        Some(format!("Delete all TinyCloud keys under {prefix}.")),
        &format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did),
        "nonce0002",
        300,
    );
    let (status, body) = post(&fixture, "/delegate", credential).await;
    assert_eq!(status, Status::Unauthorized, "{body}");
    assert!(body.contains("key-delete-not-delegable"), "{body}");
    Ok(())
}

#[tokio::test]
async fn revoke_refuses_owner_delete_credentials() -> Result<()> {
    let fixture = fixture().await?;
    let wallet = Wallet::new(3);
    let wallet_did = wallet.did();
    let prefix = prefix_urn(&wallet_did, "foo");
    let cacao = wallet.cacao(
        &prefix,
        KEY_DELETE,
        Some(format!("Delete all TinyCloud keys under {prefix}.")),
        &format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did),
        "nonce0003",
        300,
    );
    let (status, body) = post(&fixture, "/revoke", cacao).await;
    assert_eq!(status, Status::Forbidden, "cacao: {body}");

    let ucan = owner_ucan(
        &fixture,
        &fixture.node_did,
        &prefix_urn(&owner_did(&fixture), "foo"),
        KEY_DELETE,
    )?;
    let (status, body) = post(&fixture, "/revoke", ucan).await;
    assert_eq!(status, Status::Forbidden, "ucan: {body}");

    assert_eq!(
        revocation::Entity::find().count(&fixture.conn).await?,
        0,
        "no revocation is stored"
    );
    Ok(())
}
