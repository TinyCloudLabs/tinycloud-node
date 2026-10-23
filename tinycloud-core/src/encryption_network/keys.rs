//! Named-key rows: create, block/unblock, public-key derivation, and the
//! state-checked unwrap used by the decrypt release guard.
//!
//! Contract (CONTRACT.md v0.4): create §4 line 52, public GET line 53,
//! authenticated describe line 54, block/unblock line 55, cap line 59,
//! derivation line 62, release guard line 66, error codes line 79, state
//! ordering line 80.
//!
//! Not here (later slices): routes and wire shapes (N3), delete (N3b), the
//! decrypt-path wiring that calls `unwrap_named_key` after replay reservation
//! (N4).

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};

use crate::models::{encryption_network, encryption_network_key};

use super::backend::KeyBackendError;
use super::key_id::{EncryptionResource, KeyLocation};
use super::network_id::NetworkId;
use super::service::{now_rfc3339, EncryptionService, EncryptionServiceError};
use super::types::{NetworkState, ALG_X25519_AES256GCM};

pub const KEY_KIND_DETERMINISTIC: &str = "deterministic";
/// Interim hard cap (C7). Counts every key row per network, deleted rows
/// included. Value is a placeholder pending the node-config owner.
pub const DEFAULT_KEY_CAP_PER_NETWORK: u64 = 1000;
const KEY_VERSION_INITIAL: i64 = 1;

/// Key row state. `deleted` is not representable here: its stored name is
/// pending Sam's delete answer (CONTRACT §10 item 9), so delete lands with N3b.
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
            other => Err(EncryptionServiceError::CorruptKeyRow(format!(
                "unknown key state: {other}"
            ))),
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

/// Public-only view served by the unauthenticated GET (C8). No state, kind
/// or timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPublic {
    pub network_id: String,
    pub key_path: String,
    pub alg: String,
    pub key_version: i64,
    pub public_encryption_key: Vec<u8>,
}

fn network_of(loc: &KeyLocation) -> Result<NetworkId, EncryptionServiceError> {
    NetworkId::new(loc.owner_did(), loc.network())
        .map_err(|e| EncryptionServiceError::InvalidBody(format!("invalid network id: {e}")))
}

fn canonical_key_urn(loc: &KeyLocation) -> String {
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

impl EncryptionService {
    /// Load the network row and require it to be ACTIVE: `network_not_found`
    /// (404) when absent, `network_revoked` when revoked, `network_not_active`
    /// (409) for any other non-active state.
    async fn load_active_network(
        &self,
        network: &NetworkId,
    ) -> Result<encryption_network::Model, EncryptionServiceError> {
        let row = encryption_network::Entity::find_by_id(network.to_string())
            .one(&self.db)
            .await?
            .ok_or(EncryptionServiceError::NetworkNotFound)?;
        if row.state == NetworkState::Revoked.as_str() {
            return Err(EncryptionServiceError::NetworkRevoked);
        }
        if row.state != NetworkState::Active.as_str() {
            return Err(EncryptionServiceError::NetworkNotActive(row.state));
        }
        Ok(row)
    }

    async fn find_key_row(
        &self,
        network: &NetworkId,
        key_path: &str,
    ) -> Result<Option<encryption_network_key::Model>, EncryptionServiceError> {
        Ok(
            encryption_network_key::Entity::find_by_id((network.to_string(), key_path.to_string()))
                .one(&self.db)
                .await?,
        )
    }

    /// `key.create` (C7, §4 line 52). Idempotent for an identical ACTIVE
    /// deterministic key (returns the existing descriptor). Any other existing
    /// row, in any state, is `key_exists`.
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
        let net = self.load_active_network(&network).await?;

        if let Some(existing) = self.find_key_row(&network, loc.path()).await? {
            let key = descriptor(existing)?;
            if key.state == KeyState::Active && key.kind == KEY_KIND_DETERMINISTIC {
                return Ok(key);
            }
            return Err(EncryptionServiceError::KeyExists);
        }

        let count = encryption_network_key::Entity::find()
            .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
            .count(&self.db)
            .await?;
        if count >= self.key_cap_per_network {
            return Err(EncryptionServiceError::KeyLimitExceeded);
        }

        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let public = self
            .backend
            .derive_named_public_key(sealed, &canonical_key_urn(loc))?;

        let now = now_rfc3339();
        let row = encryption_network_key::ActiveModel {
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
        .insert(&self.db)
        .await?;
        descriptor(row)
    }

    /// `key.block` (§4 line 55). Idempotent; returns the descriptor.
    pub async fn block_key(
        &self,
        loc: &KeyLocation,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        self.set_key_state(loc, KeyState::Blocked).await
    }

    /// `key.unblock` (§4 line 55). Idempotent; returns the descriptor.
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
        let row = self
            .find_key_row(&network, loc.path())
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

    /// Authenticated descriptor GET (§4 line 54). `key_not_found` is only
    /// reported here.
    pub async fn describe_key(
        &self,
        loc: &KeyLocation,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        let network = network_of(loc)?;
        let row = self
            .find_key_row(&network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        descriptor(row)
    }

    /// Unauthenticated public GET (C8, §4 line 53). Requires an ACTIVE network.
    /// Always derives from the network secret, never from the stored row, so
    /// missing, blocked and active keys return identical output. Writes
    /// nothing and never reports key state or absence.
    pub async fn public_key(&self, loc: &KeyLocation) -> Result<KeyPublic, EncryptionServiceError> {
        let network = network_of(loc)?;
        let net = self.load_active_network(&network).await?;
        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let public = self
            .backend
            .derive_named_public_key(sealed, &canonical_key_urn(loc))?;
        Ok(KeyPublic {
            network_id: network.to_string(),
            key_path: loc.path().to_string(),
            alg: ALG_X25519_AES256GCM.to_string(),
            key_version: KEY_VERSION_INITIAL,
            public_encryption_key: public,
        })
    }

    /// Release-guard state read and unwrap (C5/C6, §4 line 66 and line 80).
    /// Order: network ACTIVE, then key row exists and is ACTIVE, then strict
    /// unwrap. Callers (N4) must invoke this after replay reservation. Any
    /// unwrap failure is `key_unwrap_failed`.
    pub async fn unwrap_named_key(
        &self,
        loc: &KeyLocation,
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, EncryptionServiceError> {
        let network = network_of(loc)?;
        let net = self.load_active_network(&network).await?;
        let row = self
            .find_key_row(&network, loc.path())
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
        self.backend
            .unwrap_named(sealed, &canonical_key_urn(loc), wrapped_key)
            .map_err(EncryptionServiceError::KeyUnwrapFailed)
    }
}
