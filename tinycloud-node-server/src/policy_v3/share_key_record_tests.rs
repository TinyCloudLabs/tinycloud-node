//! A Policy/v3 registration records the share key its content source names
//! (`<owner>:default/share/<shareId>`), in the registration's transaction, so
//! a publisher never creates the key. Only a policy owner that holds decrypt
//! on the key through the owner's own grants can record one, and the
//! network's key limit applies.

use super::named_keys_gate_tests::ShareDecrypt;
use super::test_harness::*;
use super::*;
use rocket::http::Status;
use serde_json::json;
use tinycloud_core::encryption_network::{
    keys::{KeyState, DEFAULT_KEY_CAP_PER_NETWORK},
    CreateNetworkRequest, EncryptionService, Threshold,
};
use tinycloud_core::models::encryption_network_key;
use tinycloud_core::sea_orm::PaginatorTrait;

/// A harness with named keys on, the space owner's `default` network, and a
/// policy owner the space owner granted decrypt on `<network>/share/`, as a
/// Share sign-in does.
struct Publisher {
    h: Harness,
    network: NetworkId,
    _ledger: tempfile::TempDir,
}

impl Publisher {
    async fn new(backend: Backend) -> anyhow::Result<Option<Self>> {
        let ledger = tempfile::tempdir()?;
        let Some(mut h) =
            Harness::new_with(backend, Shape::KeySession, "sharekeyrecord", |config| {
                config.encryption_network.named_keys_v1 = true;
                config.encryption_network.deletion_ledger_path =
                    Some(ledger.path().join("deletion-ledger.jsonl"));
            })
            .await?
        else {
            return Ok(None);
        };
        h.network = format!("urn:tinycloud:encryption:{}:default", h.space_owner.did());
        let network = h
            .client
            .rocket()
            .state::<EncryptionService>()
            .unwrap()
            .create_one_of_one_network(CreateNetworkRequest {
                name: "default".into(),
                owner_did: h.space_owner.did().into(),
                threshold: Threshold::one_of_one(),
            })
            .await?
            .network_id;
        let mut grants = h.owner_grants();
        grants[2].0 = format!("{}/share/", h.network);
        h.grant_owner_with(&grants, Window::until(now() + Duration::days(2)))
            .await?;
        Ok(Some(Self {
            h,
            network,
            _ledger: ledger,
        }))
    }

    fn service(&self) -> &EncryptionService {
        self.h.client.rocket().state::<EncryptionService>().unwrap()
    }

    fn location(&self, share_id: &str) -> anyhow::Result<KeyLocation> {
        Ok(KeyLocation::new(
            &self.network,
            &format!("share/{share_id}"),
        )?)
    }

    /// Registers a new policy over the share key `share/<share_id>`: each
    /// call is a distinct policy (its ciphertext digest differs).
    async fn register(&self, share_id: &str) -> anyhow::Result<(Status, String, Registered)> {
        let leaf = format!("{}/share/{share_id}", self.h.network);
        let ciphertext = hex::encode(Sha256::digest(unique("ciphertext").as_bytes()));
        self.h
            .register_with(policy_window(), |policy| {
                policy["contentSource"]["shareId"] = json!(share_id);
                policy["contentSource"]["encryptionKeyPath"] = json!(format!("share/{share_id}"));
                policy["contentSource"]["initialCiphertextDigestHex"] = json!(ciphertext);
                policy["capabilityCeiling"][1]["resource"] = json!(leaf);
            })
            .await
    }

    async fn key_rows(&self) -> anyhow::Result<u64> {
        let conn = &self
            .h
            .client
            .rocket()
            .state::<PolicyV3Runtime>()
            .unwrap()
            .conn;
        Ok(encryption_network_key::Entity::find()
            .filter(encryption_network_key::Column::NetworkId.eq(self.network.to_string()))
            .count(conn)
            .await?)
    }
}

/// The publisher encrypts to the public key and never creates the key; the
/// registration records it, active at version 1, and the recipient's session
/// decrypts. The policy owner here is a delegate: it holds decrypt on the key
/// only through the space owner's grant.
#[tokio::test]
async fn a_registration_records_its_share_key_and_the_recipient_decrypts() -> anyhow::Result<()> {
    let share = ShareDecrypt::new().await?;
    let service = share
        .h
        .client
        .rocket()
        .state::<EncryptionService>()
        .unwrap();
    let network: NetworkId = share.h.network.parse()?;
    let key = service
        .describe_key(&KeyLocation::new(&network, "share/tc-2192")?)
        .await?;
    assert_eq!(key.state, KeyState::Active);
    assert_eq!(key.key_version, 1);
    assert_eq!(key.kind, "deterministic");

    let (status, response) = share
        .invoke(&share.leaf(), &share.body(), None, Value::Null)
        .await?;
    assert_eq!(status, Status::Ok, "{response}");
    Ok(())
}

/// A recipient's policy session is not owner authority: the recipient cannot
/// register a policy over the key it may decrypt, and no key is recorded.
#[tokio::test]
async fn a_recipient_session_cannot_register_or_record_the_key() -> anyhow::Result<()> {
    let mut share = ShareDecrypt::new().await?;
    let network: NetworkId = share.h.network.parse()?;
    let loc = KeyLocation::new(&network, "share/tc-2192")?;
    // Forget the key the publisher's registration recorded, so a recipient
    // registration that succeeded would have to record it again.
    let conn = share
        .h
        .client
        .rocket()
        .state::<PolicyV3Runtime>()
        .unwrap()
        .conn
        .clone();
    encryption_network_key::Entity::delete_by_id((network.to_string(), loc.path().to_string()))
        .exec(&conn)
        .await?;

    // The recipient (who holds the minted session) signs the policy and its
    // roots as their owner.
    std::mem::swap(&mut share.h.owner, &mut share.h.holder);
    let leaf = share.leaf();
    let (status, body, registered) = share
        .h
        .register_with(policy_window(), |policy| {
            policy["contentSource"]["shareId"] = json!("tc-2192");
            policy["contentSource"]["encryptionKeyPath"] = json!("share/tc-2192");
            policy["capabilityCeiling"][1]["resource"] = json!(leaf);
        })
        .await?;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert!(body.contains("policy-owner-not-authorized"), "{body}");
    assert!(
        policy_v3_registration::Entity::find_by_id(registered.policy_cid)
            .one(&conn)
            .await?
            .is_none()
    );
    let service = share
        .h
        .client
        .rocket()
        .state::<EncryptionService>()
        .unwrap();
    assert!(matches!(
        service.describe_key(&loc).await,
        Err(EncryptionServiceError::KeyNotFound)
    ));
    Ok(())
}

/// With the network at its key limit, a registration that would record a new
/// key is refused and stores neither the registration nor the key. A key
/// that is already recorded needs no new row, so its registration succeeds.
async fn a_full_key_limit_refuses_the_registration_and_stores_nothing(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(p) = Publisher::new(backend).await? else {
        return Ok(());
    };
    let (status, body, _) = p.register("recorded").await?;
    assert_eq!(status, Status::Ok, "{body}");

    let conn =
        p.h.client
            .rocket()
            .state::<PolicyV3Runtime>()
            .unwrap()
            .conn
            .clone();
    let stamp = format_time(OffsetDateTime::now_utc());
    let filler = (1..DEFAULT_KEY_CAP_PER_NETWORK).map(|i| encryption_network_key::ActiveModel {
        network_id: Set(p.network.to_string()),
        key_path: Set(format!("docs/filler-{i}")),
        kind: Set("deterministic".into()),
        state: Set("active".into()),
        public_key: Set(vec![0; 32]),
        sealed_seed: Set(None),
        key_version: Set(1),
        created_at: Set(stamp.clone()),
        updated_at: Set(stamp.clone()),
    });
    encryption_network_key::Entity::insert_many(filler)
        .exec(&conn)
        .await?;
    assert_eq!(p.key_rows().await?, DEFAULT_KEY_CAP_PER_NETWORK);

    let (status, body, registered) = p.register("over-limit").await?;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert!(body.starts_with("key_limit_exceeded"), "{body}");
    assert!(
        policy_v3_registration::Entity::find_by_id(registered.policy_cid)
            .one(&conn)
            .await?
            .is_none()
    );
    assert_eq!(p.key_rows().await?, DEFAULT_KEY_CAP_PER_NETWORK);
    assert!(matches!(
        p.service().describe_key(&p.location("over-limit")?).await,
        Err(EncryptionServiceError::KeyNotFound)
    ));

    let (status, body, _) = p.register("recorded").await?;
    assert_eq!(status, Status::Ok, "{body}");
    Ok(())
}
on_both_backends!(a_full_key_limit_refuses_the_registration_and_stores_nothing);

/// A key that is already recorded is left as it is: a key an older client
/// created, then the owner blocked, stays blocked at its version through
/// further registrations over it.
async fn a_recorded_key_is_left_as_it_is(backend: Backend) -> anyhow::Result<()> {
    let Some(p) = Publisher::new(backend).await? else {
        return Ok(());
    };
    let loc = p.location("existing")?;
    p.service().create_key(&loc, false).await?;
    let blocked = p.service().block_key(&loc).await?;

    for _ in 0..2 {
        let (status, body, _) = p.register("existing").await?;
        assert_eq!(status, Status::Ok, "{body}");
    }
    assert_eq!(p.service().describe_key(&loc).await?, blocked);
    assert_eq!(p.key_rows().await?, 1);
    Ok(())
}
on_both_backends!(a_recorded_key_is_left_as_it_is);
