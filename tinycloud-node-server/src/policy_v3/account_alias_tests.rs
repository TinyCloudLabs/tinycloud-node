//! Actual account-owner admission boundaries over signed historical CACAO siblings.
//!
//! The generic historical-wire decoder preserves valid pre-normalization bytes.
//! This constructs disposable fixtures; it is not an f9-generated credentials
//! database, the current HTTP ingestion path, or an end-to-end mint HTTP test.

use super::*;
use k256::ecdsa::SigningKey;
use sha3::Keccak256;
use std::time::Duration as WaitDuration;
use tinycloud_auth::{
    authorization::{EncodingError, HeaderEncode, TinyCloudRevocation},
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Eip191, Payload, Signature},
    },
    resolver::DID_METHODS,
    siwe_recap::Capability,
};
use tinycloud_core::{
    db::{begin_write_transaction, DelegationStatus},
    events::Revocation,
    hash::Hash,
    sea_orm::Database,
    storage::StorageConfig as _,
};
use tokio::{sync::OwnedRwLockReadGuard, time::timeout};

const WAIT: WaitDuration = WaitDuration::from_secs(10);

/// Preserve the signed wire identity using the public generic event decoder,
/// instead of inserting inconsistent hashes or changing persisted graph rows.
struct HistoricalWire(TinyCloudDelegation);

impl HeaderEncode for HistoricalWire {
    fn encode(&self) -> Result<String, EncodingError> {
        self.0.encode()
    }

    fn decode(header: &str) -> Result<(Self, Vec<u8>), EncodingError> {
        let bytes =
            decode_config(header, base64::URL_SAFE).expect("valid historical fixture base64");
        Ok((Self(TinyCloudDelegation::from_bytes(&bytes)?), bytes))
    }
}

impl TryFrom<HistoricalWire> for DelegationInfo {
    type Error = <DelegationInfo as TryFrom<TinyCloudDelegation>>::Error;

    fn try_from(value: HistoricalWire) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

struct SignedGrant {
    id: Hash,
    bytes: Vec<u8>,
}

impl SignedGrant {
    fn from_signature(message: Message, signature: [u8; 65]) -> anyhow::Result<Self> {
        let cacao = Payload::from(message).sign::<Eip191>(Signature::from(signature));
        let header = TinyCloudDelegation::Cacao(Box::new(cacao)).encode()?;
        let bytes = decode_config(header, base64::URL_SAFE)?;
        Ok(Self {
            id: hash(&bytes),
            bytes,
        })
    }

    fn event(&self) -> anyhow::Result<Delegation> {
        Ok(Delegation::from_header_ser::<HistoricalWire>(
            &encode_config(&self.bytes, base64::URL_SAFE),
        )?)
    }
}

struct AccountAliasFixture {
    node: crate::TinyCloud,
    runtime: PolicyV3Runtime,
    key: SigningKey,
    address: [u8; 20],
    holder: String,
    owner: String,
    credentials_space: SpaceId,
    // Exactly the same payload/r/s, with raw v=0 and conventional v=27.
    aliases: [SignedGrant; 2],
    unrelated: SignedGrant,
    database_url: String,
    directory: tempfile::TempDir,
}

fn wallet_message(address: [u8; 20], audience: &str, nonce: &str) -> anyhow::Result<Message> {
    let now = OffsetDateTime::now_utc();
    Ok(Message {
        scheme: Some("https".parse()?),
        domain: "account-alias.tc1071.test".parse()?,
        address,
        statement: None,
        uri: audience.parse()?,
        version: Version::V1,
        chain_id: 1,
        nonce: nonce.into(),
        issued_at: (now - Duration::minutes(1)).into(),
        expiration_time: Some((now + Duration::hours(1)).into()),
        not_before: None,
        request_id: None,
        resources: vec![],
    })
}

fn account_message(
    address: [u8; 20],
    holder: &str,
    space: &SpaceId,
    nonce: &str,
) -> anyhow::Result<Message> {
    let mut capability = Capability::<()>::default();
    capability.with_actions_convert(format!("{space}/space"), [("tinycloud.space/host", [])])?;
    Ok(capability.build_message(wallet_message(address, holder, nonce)?)?)
}

fn sign_conventional(key: &SigningKey, message: Message) -> anyhow::Result<SignedGrant> {
    let (signature, recovery) = key.sign_prehash_recoverable(&message.eip191_hash()?)?;
    let mut bytes = [0_u8; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    bytes[64] = recovery.to_byte() + 27;
    SignedGrant::from_signature(message, bytes)
}

fn authentication_error(error: (Status, String)) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", error.0, error.1)
}

impl AccountAliasFixture {
    async fn new() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let database_url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("caps.db").display()
        );
        let conn = Database::connect(&database_url).await?;
        let storage = crate::BlockConfig::B(crate::storage::file_system::FileSystemConfig::new(
            directory.path(),
        ))
        .open()
        .await?;
        let secret = StaticSecret::new(vec![31; 32])
            .map_err(|_| anyhow::anyhow!("invalid disposable node secret"))?;
        let node = crate::TinyCloud::new(conn.clone().into(), storage, secret.clone()).await?;
        let runtime = PolicyV3Runtime::new(conn, secret.node_did(), secret)
            .with_sqlite_writer_lock(node.sqlite_writer_lock());
        let key = SigningKey::from_bytes(&[7_u8; 32].into())?;
        let point = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = Keccak256::digest(&point.as_bytes()[1..])[12..].try_into()?;
        let holder_key = JWK::generate_ed25519()?;
        let holder = DID_METHODS.generate(&holder_key, "key")?.to_string();
        let owner = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        let credentials_space: SpaceId = format!(
            "tinycloud:pkh:eip155:1:0x{}:credentials",
            encode_eip55(&address)
        )
        .parse()?;

        // Select a genuine recoverable signature whose raw recovery byte is
        // exactly zero, rather than forcing a recovery byte onto another key.
        let mut nonce = 0_u64;
        let aliases = loop {
            let message = account_message(
                address,
                &holder,
                &credentials_space,
                &format!("tc1071account{nonce}"),
            )?;
            let (signature, recovery) = key.sign_prehash_recoverable(&message.eip191_hash()?)?;
            if recovery.to_byte() == 0 {
                let mut bytes = [0_u8; 65];
                bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
                let historical = SignedGrant::from_signature(message.clone(), bytes)?;
                bytes[64] = 27;
                break [historical, SignedGrant::from_signature(message, bytes)?];
            }
            nonce = nonce
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("nonce overflow"))?;
        };
        assert_ne!(aliases[0].id, aliases[1].id);
        let unrelated = sign_conventional(
            &key,
            account_message(address, &holder, &credentials_space, "tc1071unrelated")?,
        )?;
        let fixture = Self {
            node,
            runtime,
            key,
            address,
            holder,
            owner,
            credentials_space,
            aliases,
            unrelated,
            database_url,
            directory,
        };
        for grant in fixture.aliases.iter().chain([&fixture.unrelated]) {
            fixture
                .node
                .delegate(grant.event()?)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            fixture.assert_signed_row(grant).await?;
            fixture
                .assert_status(grant.id, DelegationStatus::Active)
                .await?;
        }
        // The real signed space/host grant, not a manually inserted space row,
        // is what establishes the hosted credentials-space authority.
        assert!(
            space::Entity::find_by_id(SpaceIdWrap(fixture.credentials_space.clone()))
                .one(&fixture.runtime.conn)
                .await?
                .is_some()
        );
        Ok(fixture)
    }

    fn grant(&self, nonce: &str) -> anyhow::Result<SignedGrant> {
        sign_conventional(
            &self.key,
            account_message(self.address, &self.holder, &self.credentials_space, nonce)?,
        )
    }

    fn revocation(&self, target: Hash) -> anyhow::Result<Revocation> {
        let signed = sign_conventional(
            &self.key,
            wallet_message(
                self.address,
                &format!("ucan:{}", target.to_cid(0x55)),
                &format!("tc1071revoke{}", target.to_cid(0x55)),
            )?,
        )?;
        Ok(Revocation::from_header_ser::<TinyCloudRevocation>(
            &encode_config(signed.bytes, base64::URL_SAFE),
        )?)
    }

    async fn authenticate(&self, id: Hash) -> Result<AccountOwnerProof, (Status, String)> {
        authenticate_account_owner(
            Some(&id.to_cid(0x55).to_string()),
            Some(&self.credentials_space.to_string()),
            &self.holder,
            &self.runtime,
            &self.node,
        )
        .await
    }

    async fn assert_signed_row(&self, grant: &SignedGrant) -> anyhow::Result<()> {
        let (row, event) = self
            .node
            .load_signed_delegation(grant.id.to_cid(0x55))
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("missing signed account row"))?;
        assert_eq!(row.id, hash(&grant.bytes));
        assert_eq!(row.serialization, grant.bytes);
        assert_eq!(event.content_hash(), grant.id);
        let TinyCloudDelegation::Cacao(cacao) = event.0.delegation else {
            anyhow::bail!("account fixture is not CACAO");
        };
        cacao.verify().await?;
        Ok(())
    }

    async fn assert_status(&self, id: Hash, expected: DelegationStatus) -> anyhow::Result<()> {
        assert_eq!(
            self.node
                .delegation_status(id, &self.owner, &[])
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?,
            Some(expected),
            "core status for {}",
            id.to_cid(0x55)
        );
        Ok(())
    }

    async fn assert_active_admission(&self, id: Hash) -> anyhow::Result<()> {
        self.assert_status(id, DelegationStatus::Active).await?;
        let proof = self.authenticate(id).await.map_err(authentication_error)?;
        assert_eq!(proof.row.id, id);
        assert_eq!(proof.cid, id.to_cid(0x55));
        assert_eq!(proof.owner_did, self.owner);
        assert_eq!(proof.space, self.credentials_space);
        let transaction = begin_write_transaction(&self.runtime.conn, None).await?;
        validate_locked_account_owner(&transaction, &proof)
            .await
            .map_err(authentication_error)?;
        transaction.commit().await?;
        drop(proof);
        Ok(())
    }

    async fn assert_aliases_denied(&self) -> anyhow::Result<()> {
        for grant in &self.aliases {
            self.assert_status(grant.id, DelegationStatus::Revoked)
                .await?;
            let error = self
                .authenticate(grant.id)
                .await
                .err()
                .expect("effectively revoked account owner must not authenticate");
            assert_eq!(error.0, Status::Forbidden);
            self.assert_signed_row(grant).await?;
        }
        Ok(())
    }

    async fn independent_node(&self) -> anyhow::Result<crate::TinyCloud> {
        let conn = Database::connect(&self.database_url).await?;
        let storage = crate::BlockConfig::B(crate::storage::file_system::FileSystemConfig::new(
            self.directory.path(),
        ))
        .open()
        .await?;
        // Same disposable DB, but a new SpaceDatabase and lock registry. This
        // models a writer outside this node's in-process admission guard.
        Ok(crate::TinyCloud::new(conn.into(), storage, self.runtime.signer.clone()).await?)
    }
}

#[tokio::test]
async fn account_owner_rejects_revoked_cacao_aliases_in_both_directions() -> anyhow::Result<()> {
    for target_index in 0..2 {
        let fixture = timeout(WAIT, AccountAliasFixture::new()).await??;
        for grant in fixture.aliases.iter().chain([&fixture.unrelated]) {
            fixture.assert_active_admission(grant.id).await?;
        }
        let target = fixture.aliases[target_index].id;
        timeout(WAIT, fixture.node.revoke(fixture.revocation(target)?))
            .await?
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        fixture.assert_aliases_denied().await?;
        // Equivalent grants are revoked, not every valid grant by this wallet.
        fixture
            .assert_active_admission(fixture.unrelated.id)
            .await?;
        let rows = revocation::Entity::find()
            .all(&fixture.runtime.conn)
            .await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].revoked, target);

        // Positive revoke control, after the unrelated admission proof drops.
        timeout(
            WAIT,
            fixture
                .node
                .revoke(fixture.revocation(fixture.unrelated.id)?),
        )
        .await?
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        fixture
            .assert_status(fixture.unrelated.id, DelegationStatus::Revoked)
            .await?;
        assert_eq!(
            fixture
                .authenticate(fixture.unrelated.id)
                .await
                .err()
                .expect("revoked control")
                .0,
            Status::Forbidden
        );
    }
    Ok(())
}

#[tokio::test]
async fn locked_account_owner_recheck_rejects_committed_sibling_revocations_in_both_directions(
) -> anyhow::Result<()> {
    for target_index in 0..2 {
        let fixture = timeout(WAIT, AccountAliasFixture::new()).await??;
        let target = fixture.aliases[target_index].id;
        let proof = fixture
            .authenticate(fixture.aliases[1 - target_index].id)
            .await
            .map_err(authentication_error)?;
        let active_transaction = begin_write_transaction(&fixture.runtime.conn, None).await?;
        validate_locked_account_owner(&active_transaction, &proof)
            .await
            .map_err(authentication_error)?;
        active_transaction.commit().await?;

        let other_node = timeout(WAIT, fixture.independent_node()).await??;
        timeout(WAIT, other_node.revoke(fixture.revocation(target)?))
            .await?
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        // Confirm a durable core transition while the original proof is still
        // alive; a same-registry writer would intentionally wait for it.
        for grant in &fixture.aliases {
            assert_eq!(
                other_node
                    .delegation_status(grant.id, &fixture.owner, &[])
                    .await
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
                Some(DelegationStatus::Revoked)
            );
        }
        // No changed projection, expired proof, or removed hosted space can
        // account for the Conflict: only effective sibling revocation changed.
        assert_eq!(
            delegation_model::Entity::find_by_id(proof.row.id)
                .one(&fixture.runtime.conn)
                .await?,
            Some(proof.row.clone())
        );
        assert!(proof
            .expires_at
            .is_some_and(|expiry| expiry > OffsetDateTime::now_utc()));
        assert!(space::Entity::find_by_id(SpaceIdWrap(proof.space.clone()))
            .one(&fixture.runtime.conn)
            .await?
            .is_some());
        let transaction = begin_write_transaction(&fixture.runtime.conn, None).await?;
        let error = validate_locked_account_owner(&transaction, &proof)
            .await
            .expect_err("transactional recheck must reject a committed sibling revocation");
        assert_eq!(error.0, Status::Conflict);
        transaction.rollback().await?;
        drop(proof);
        fixture.assert_aliases_denied().await?;
        fixture
            .assert_active_admission(fixture.unrelated.id)
            .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_owner_proofs_hold_canonical_guards_through_commit_in_both_directions(
) -> anyhow::Result<()> {
    for target_index in 0..2 {
        let fixture = timeout(WAIT, AccountAliasFixture::new()).await??;
        let target = fixture.aliases[target_index].id;
        let proof = fixture
            .authenticate(fixture.aliases[1 - target_index].id)
            .await
            .map_err(authentication_error)?;
        // Both actual return values coexist: equivalent account proofs take
        // shared, not exclusive, canonical guards.
        let second_proof = timeout(WAIT, fixture.authenticate(target))
            .await?
            .map_err(authentication_error)?;
        let locks: Vec<_> = proof
            ._chain_guards
            .iter()
            .map(|guard| OwnedRwLockReadGuard::rwlock(guard).clone())
            .collect();
        let revoke_node = fixture.node.clone();
        let revocation = fixture.revocation(target)?;
        let mut revoke = tokio::spawn(async move {
            revoke_node
                .revoke(revocation)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))
        });

        // Tokio's write-preferring RwLock refuses a new reader once the real
        // revoke writer queues. Observe that state on the authentic proof's
        // lock: unlike a started-task signal or sleep, this proves contention.
        // No admission SQL transaction or writer/sequence guard exists yet.
        timeout(WAIT, async {
            loop {
                if locks.iter().any(|lock| lock.try_read().is_err()) {
                    break;
                }
                tokio::select! {
                    result = &mut revoke => panic!("revocation escaped a live account proof: {result:?}"),
                    _ = tokio::task::yield_now() => {}
                }
            }
        })
        .await?;
        for grant in &fixture.aliases {
            assert!(!revocation::is_revoked(&fixture.runtime.conn, &grant.id).await?);
        }

        // A real unrelated signed graph write commits while that writer is
        // queued. SQLite or a global writer gate cannot explain its wait.
        let write_control = fixture.grant("tc1071sqlwritecontrol")?;
        timeout(WAIT, fixture.node.delegate(write_control.event()?))
            .await?
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        fixture
            .assert_status(write_control.id, DelegationStatus::Active)
            .await?;

        let admitted = fixture.grant("tc1071guardedadmission")?;
        let sequence_guards = fixture
            .node
            .acquire_space_sequence_guards(std::slice::from_ref(&fixture.credentials_space))
            .await;
        let writer = match &fixture.runtime.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let transaction = begin_write_transaction(&fixture.runtime.conn, None).await?;
        validate_locked_account_owner(&transaction, &proof)
            .await
            .map_err(authentication_error)?;
        validate_locked_account_owner(&transaction, &second_proof)
            .await
            .map_err(authentication_error)?;
        fixture
            .node
            .delegate_batch_in_transaction(&transaction, vec![admitted.event()?])
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        transaction.commit().await?;
        drop(writer);
        drop(sequence_guards);
        fixture.assert_signed_row(&admitted).await?;
        assert!(!revoke.is_finished());
        assert!(!revocation::is_revoked(&fixture.runtime.conn, &target).await?);

        // Commit alone cannot release the proof's lifetime protection, nor
        // can dropping just one of the two concurrently held shared proofs.
        drop(proof);
        assert!(locks.iter().any(|lock| lock.try_read().is_err()));
        assert!(!revocation::is_revoked(&fixture.runtime.conn, &target).await?);
        drop(second_proof);
        timeout(WAIT, revoke).await???;
        fixture.assert_aliases_denied().await?;
        fixture
            .assert_active_admission(fixture.unrelated.id)
            .await?;
        fixture.assert_active_admission(admitted.id).await?;
    }
    Ok(())
}
