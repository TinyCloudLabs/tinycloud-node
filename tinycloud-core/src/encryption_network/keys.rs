//! Named-key rows: create, block/unblock, public-key derivation, and the
//! state-checked unwrap used by the decrypt release guard.
//!
//! Routes, wire shapes, delete, and the decrypt-path wiring that calls
//! `unwrap_named_key` after replay reservation are not implemented in this
//! module.

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbBackend, DbErr,
    EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
};

use crate::db::begin_write_transaction;
use crate::models::{encryption_network, encryption_network_key};

use super::backend::KeyBackendError;
use super::key_id::{EncryptionResource, KeyLocation};
use super::network_id::NetworkId;
use super::service::{is_unique_violation, now_rfc3339, EncryptionService, EncryptionServiceError};
use super::types::{NetworkState, ALG_X25519_AES256GCM};

pub const KEY_KIND_DETERMINISTIC: &str = "deterministic";
/// Interim hard cap per network. Counts every key row per network, deleted
/// rows included. Placeholder value pending the node-config owner.
pub const DEFAULT_KEY_CAP_PER_NETWORK: u64 = 1000;
const KEY_VERSION_INITIAL: i64 = 1;

/// Key row state. Any stored state other than `active` or `blocked` is refused
/// as a corrupt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Active,
    Blocked,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Active => "active",
            KeyState::Blocked => "blocked",
        }
    }

    fn parse(stored: &str) -> Result<Self, EncryptionServiceError> {
        match stored {
            "active" => Ok(KeyState::Active),
            "blocked" => Ok(KeyState::Blocked),
            _ => Err(EncryptionServiceError::CorruptKeyRow),
        }
    }
}

/// Full descriptor, returned by create, block/unblock and the authenticated
/// describe GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescriptor {
    pub network_id: String,
    pub key_path: String,
    pub alg: String,
    pub key_version: i64,
    pub public_encryption_key: Vec<u8>,
    pub kind: String,
    pub state: KeyState,
    pub created_at: String,
    pub updated_at: String,
}

/// Public-only view served by the unauthenticated GET. No state, kind or
/// timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPublic {
    pub network_id: String,
    pub key_path: String,
    pub alg: String,
    pub key_version: i64,
    pub public_encryption_key: Vec<u8>,
}

pub(crate) fn network_of(loc: &KeyLocation) -> Result<NetworkId, EncryptionServiceError> {
    NetworkId::new(loc.owner_did(), loc.network())
        .map_err(|e| EncryptionServiceError::InvalidBody(format!("invalid network id: {e}")))
}

pub(crate) fn canonical_key_urn(loc: &KeyLocation) -> String {
    EncryptionResource::Key(loc.clone()).to_string()
}

fn descriptor(row: encryption_network_key::Model) -> Result<KeyDescriptor, EncryptionServiceError> {
    Ok(KeyDescriptor {
        network_id: row.network_id,
        key_path: row.key_path,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: row.key_version,
        public_encryption_key: row.public_key,
        kind: row.kind,
        state: KeyState::parse(&row.state)?,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Load the network row and require it to be ACTIVE: `network_not_found`
/// (404) when absent, `network_not_active` with state `revoked` (409) when
/// revoked, and `network_not_active` with the stored state (409) otherwise.
async fn load_active_network<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
) -> Result<encryption_network::Model, EncryptionServiceError> {
    let row = encryption_network::Entity::find_by_id(network.to_string())
        .one(db)
        .await?
        .ok_or(EncryptionServiceError::NetworkNotFound)?;
    if row.state == NetworkState::Revoked.as_str() {
        return Err(EncryptionServiceError::NetworkNotActive(
            NetworkState::Revoked.as_str().to_string(),
        ));
    }
    if row.state != NetworkState::Active.as_str() {
        return Err(EncryptionServiceError::NetworkNotActive(row.state));
    }
    Ok(row)
}

async fn find_key_row<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
    key_path: &str,
) -> Result<Option<encryption_network_key::Model>, EncryptionServiceError> {
    Ok(
        encryption_network_key::Entity::find_by_id((network.to_string(), key_path.to_string()))
            .one(db)
            .await?,
    )
}

/// The answer `key.create` gives for a row that already exists: the descriptor
/// for an ACTIVE deterministic key, otherwise `key_exists`.
fn existing_create_answer(
    row: encryption_network_key::Model,
) -> Result<KeyDescriptor, EncryptionServiceError> {
    let key = descriptor(row)?;
    if key.state == KeyState::Active && key.kind == KEY_KIND_DETERMINISTIC {
        return Ok(key);
    }
    Err(EncryptionServiceError::KeyExists)
}

/// Takes the row lock that serializes `key.create` for one network on
/// PostgreSQL. On SQLite the writer transaction already serializes writers,
/// so this is a no-op there.
async fn lock_network_row<C: ConnectionTrait>(db: &C, network: &NetworkId) -> Result<(), DbErr> {
    if db.get_database_backend() == DbBackend::Postgres {
        encryption_network::Entity::find_by_id(network.to_string())
            .lock_exclusive()
            .one(db)
            .await?;
    }
    Ok(())
}

impl EncryptionService {
    /// `key.create`. Idempotent for an identical ACTIVE deterministic key
    /// (returns the existing descriptor). Any other existing row, in any state,
    /// is `key_exists`. The existence check and the insert share one
    /// transaction. On PostgreSQL the network row lock serializes concurrent
    /// creates for the same network.
    pub async fn create_key(
        &self,
        loc: &KeyLocation,
        shreddable: bool,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        if shreddable {
            return Err(EncryptionServiceError::ShreddableUnavailable);
        }
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let network = network_of(loc)?;
        let tx = begin_write_transaction(&self.db, None).await?;
        lock_network_row(&tx, &network).await?;
        let net = load_active_network(&tx, &network).await?;

        if let Some(existing) = find_key_row(&tx, &network, loc.path()).await? {
            return existing_create_answer(existing);
        }

        let count = encryption_network_key::Entity::find()
            .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
            .count(&tx)
            .await?;
        if count >= self.key_cap_per_network {
            return Err(EncryptionServiceError::KeyLimitExceeded);
        }

        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let network_secret = self.backend.open_network_secret(sealed)?;
        let public = self
            .backend
            .derive_named_public_key(&network_secret, &canonical_key_urn(loc))?;

        let now = now_rfc3339();
        let inserted = encryption_network_key::ActiveModel {
            network_id: Set(network.to_string()),
            key_path: Set(loc.path().to_string()),
            kind: Set(KEY_KIND_DETERMINISTIC.to_string()),
            state: Set(KeyState::Active.as_str().to_string()),
            public_key: Set(public),
            sealed_seed: Set(None),
            key_version: Set(KEY_VERSION_INITIAL),
            created_at: Set(now.clone()),
            updated_at: Set(now),
        }
        .insert(&tx)
        .await;
        match inserted {
            Ok(row) => {
                tx.commit().await?;
                descriptor(row)
            }
            Err(err) if is_unique_violation(&err) => {
                // Another writer committed the same key first. Roll back, then
                // answer from the committed row on the pool.
                tx.rollback().await?;
                match find_key_row(&self.db, &network, loc.path()).await? {
                    Some(existing) => existing_create_answer(existing),
                    None => Err(EncryptionServiceError::KeyExists),
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    /// `key.block`. Idempotent; returns the descriptor. Does not check the
    /// network's state.
    pub async fn block_key(
        &self,
        loc: &KeyLocation,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        self.set_key_state(loc, KeyState::Blocked).await
    }

    /// `key.unblock`. Idempotent; returns the descriptor. Does not check the
    /// network's state.
    pub async fn unblock_key(
        &self,
        loc: &KeyLocation,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        self.set_key_state(loc, KeyState::Active).await
    }

    async fn set_key_state(
        &self,
        loc: &KeyLocation,
        target: KeyState,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let network = network_of(loc)?;
        let row = find_key_row(&self.db, &network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        if KeyState::parse(&row.state)? == target {
            return descriptor(row);
        }
        let mut active: encryption_network_key::ActiveModel = row.into();
        active.state = Set(target.as_str().to_string());
        active.updated_at = Set(now_rfc3339());
        descriptor(active.update(&self.db).await?)
    }

    /// Authenticated descriptor GET. `key_not_found` is only reported here.
    /// Does not check the network's state.
    pub async fn describe_key(
        &self,
        loc: &KeyLocation,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        let network = network_of(loc)?;
        let row = find_key_row(&self.db, &network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        descriptor(row)
    }

    /// Unauthenticated public GET. Requires an ACTIVE network. Always derives
    /// from the network secret, never from the stored row, so missing, blocked
    /// and active keys return identical output. Writes nothing and never
    /// reports key state or absence.
    pub async fn public_key(&self, loc: &KeyLocation) -> Result<KeyPublic, EncryptionServiceError> {
        let network = network_of(loc)?;
        let net = load_active_network(&self.db, &network).await?;
        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let network_secret = self.backend.open_network_secret(sealed)?;
        let public = self
            .backend
            .derive_named_public_key(&network_secret, &canonical_key_urn(loc))?;
        Ok(KeyPublic {
            network_id: network.to_string(),
            key_path: loc.path().to_string(),
            alg: ALG_X25519_AES256GCM.to_string(),
            key_version: KEY_VERSION_INITIAL,
            public_encryption_key: public,
        })
    }

    /// Release-guard state read and unwrap. Order: network ACTIVE, then key row
    /// exists and is ACTIVE, then strict unwrap. Callers must invoke this after
    /// replay reservation. Any ECIES unwrap failure is `KeyUnwrapFailed`; a failure
    /// to unseal the network key is `Backend`.
    pub async fn unwrap_named_key(
        &self,
        loc: &KeyLocation,
        wrapped_key: &[u8],
    ) -> Result<(i64, Vec<u8>), EncryptionServiceError> {
        let network = network_of(loc)?;
        let net = load_active_network(&self.db, &network).await?;
        let row = find_key_row(&self.db, &network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        match KeyState::parse(&row.state)? {
            KeyState::Active => {}
            KeyState::Blocked => return Err(EncryptionServiceError::KeyBlocked),
        }
        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let network_secret = self.backend.open_network_secret(sealed)?;
        let symmetric = self
            .backend
            .unwrap_named(&network_secret, &canonical_key_urn(loc), wrapped_key)
            .map_err(EncryptionServiceError::KeyUnwrapFailed)?;
        Ok((row.key_version, symmetric))
    }
}
